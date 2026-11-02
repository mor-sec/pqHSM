//! The one owned byte buffer behind object values and the DEK (review M2, RULE-078).
//!
//! With `ffi` it is a C allocation, as `obj_alloc_value` made it (`src/fhsm_token.c:523-536`):
//! the secure heap for sensitive values and the DEK, `malloc` otherwise. It is released through
//! `fhsm_api_free_value`, which zeroises it, and defers the free while a reader holds the shared
//! API lock. Without `ffi` it is a heap buffer zeroised on drop.

use crate::Rv;

#[cfg(feature = "ffi")]
mod imp {
    use std::ffi::{c_int, c_void};
    use std::ptr::null_mut;

    use crate::Rv;

    unsafe extern "C" {
        fn fhsm_secure_malloc(n: usize) -> *mut c_void;
        fn fhsm_api_free_value(p: *mut c_void, len: usize, secure: c_int);
    }

    pub(crate) struct Buf {
        ptr: *mut u8,
        len: usize,
        secure: bool,
    }

    // SAFETY: the buffer is owned and mutated only through `&mut self` (`wipe`); shared reads
    // are fine.
    unsafe impl Send for Buf {}
    unsafe impl Sync for Buf {}

    impl Buf {
        pub(crate) fn new(src: &[u8], secure: bool) -> Result<Buf, Rv> {
            if src.is_empty() {
                return Ok(Buf {
                    ptr: null_mut(),
                    len: 0,
                    secure: false,
                });
            }
            // SAFETY: plain allocations of src.len() bytes, checked for NULL
            let p = unsafe {
                if secure {
                    fhsm_secure_malloc(src.len())
                } else {
                    libc::malloc(src.len())
                }
            }
            .cast::<u8>();
            if p.is_null() {
                return Err(if secure {
                    Rv::DEVICE_MEMORY
                } else {
                    Rv::HOST_MEMORY
                });
            }
            // SAFETY: p has src.len() bytes and does not overlap src
            unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), p, src.len()) };
            Ok(Buf {
                ptr: p,
                len: src.len(),
                secure,
            })
        }

        pub(crate) fn as_slice(&self) -> &[u8] {
            if self.len == 0 {
                return &[];
            }
            // SAFETY: ptr holds len initialised bytes until drop
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }

        pub(crate) fn secure(&self) -> bool {
            self.secure
        }

        /// Zeroise in place now, not when `fhsm_api_free_value` gets to it (review M-3).
        pub(crate) fn wipe(&mut self) {
            if self.len > 0 {
                // SAFETY: ptr holds len bytes until drop, and `&mut self` excludes any reader
                zeroize::Zeroize::zeroize(unsafe {
                    std::slice::from_raw_parts_mut(self.ptr, self.len)
                });
            }
        }
    }

    impl Drop for Buf {
        fn drop(&mut self) {
            // SAFETY: allocated in `new` with this length and kind; NULL is accepted
            unsafe { fhsm_api_free_value(self.ptr.cast(), self.len, self.secure as c_int) }
        }
    }
}

#[cfg(not(feature = "ffi"))]
mod imp {
    use zeroize::Zeroizing;

    use crate::Rv;

    pub(crate) struct Buf(Zeroizing<Vec<u8>>, bool);

    impl Buf {
        pub(crate) fn new(src: &[u8], secure: bool) -> Result<Buf, Rv> {
            Ok(Buf(Zeroizing::new(src.to_vec()), secure && !src.is_empty()))
        }

        pub(crate) fn as_slice(&self) -> &[u8] {
            &self.0
        }

        pub(crate) fn secure(&self) -> bool {
            self.1
        }

        pub(crate) fn wipe(&mut self) {
            zeroize::Zeroize::zeroize(self.0.as_mut_slice());
        }
    }
}

pub(crate) use imp::Buf;

/// A buffer of exactly 32 bytes in the secure heap: the DEK.
pub(crate) fn key(k: &[u8; 32]) -> Result<Buf, Rv> {
    Buf::new(k, true)
}

// With `ffi` the lib's test binary does not link the C allocator; the `ffi` integration tests
// run `wipe` at every logout.
#[cfg(all(test, not(feature = "ffi")))]
mod tests {
    use super::*;

    #[test]
    fn wipe_zeroises_in_place() {
        let mut b = key(&[0x5a; 32]).unwrap();
        b.wipe();
        assert_eq!(b.as_slice(), &[0u8; 32]);
    }
}
