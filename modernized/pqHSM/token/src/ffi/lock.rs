//! The token mutex. With `ffi` it is a `pthread_mutex_t`, as C's `t->mu` was: ThreadSanitizer
//! intercepts it, so the hybrid build's TSan run sees the token's locking (std's futex mutex is
//! invisible to it in an uninstrumented staticlib). Without `ffi`, std's `Mutex`.

#[cfg(feature = "ffi")]
mod imp {
    use std::cell::UnsafeCell;
    use std::ops::{Deref, DerefMut};

    pub(crate) struct Lock<T> {
        // Boxed: a pthread mutex must not move once used.
        m: Box<UnsafeCell<libc::pthread_mutex_t>>,
        v: UnsafeCell<T>,
    }

    // SAFETY: `v` is reached only through a guard, which holds the mutex.
    unsafe impl<T: Send> Send for Lock<T> {}
    unsafe impl<T: Send> Sync for Lock<T> {}

    impl<T> Lock<T> {
        pub(crate) fn new(v: T) -> Lock<T> {
            Lock {
                m: Box::new(UnsafeCell::new(libc::PTHREAD_MUTEX_INITIALIZER)),
                v: UnsafeCell::new(v),
            }
        }

        pub(crate) fn lock(&self) -> Guard<'_, T> {
            // SAFETY: the mutex is initialised and never moves; the token never relocks it from
            // the thread that holds it.
            unsafe { libc::pthread_mutex_lock(self.m.get()) };
            Guard(self)
        }
    }

    impl<T> Drop for Lock<T> {
        fn drop(&mut self) {
            // SAFETY: no guard can outlive the lock. As in C's fhsm_token_close, a mutex left
            // locked by a thread that did not survive fork() gets EBUSY, which is ignored.
            unsafe { libc::pthread_mutex_destroy(self.m.get()) };
        }
    }

    pub(crate) struct Guard<'a, T>(&'a Lock<T>);

    impl<T> Deref for Guard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            // SAFETY: this guard holds the mutex
            unsafe { &*self.0.v.get() }
        }
    }

    impl<T> DerefMut for Guard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            // SAFETY: this guard holds the mutex
            unsafe { &mut *self.0.v.get() }
        }
    }

    impl<T> Drop for Guard<'_, T> {
        fn drop(&mut self) {
            // SAFETY: locked by this guard's `lock`
            unsafe { libc::pthread_mutex_unlock(self.0.m.get()) };
        }
    }
}

#[cfg(not(feature = "ffi"))]
mod imp {
    use std::sync::{Mutex, MutexGuard};

    pub(crate) struct Lock<T>(Mutex<T>);

    pub(crate) type Guard<'a, T> = MutexGuard<'a, T>;

    impl<T> Lock<T> {
        pub(crate) fn new(v: T) -> Lock<T> {
            Lock(Mutex::new(v))
        }

        pub(crate) fn lock(&self) -> Guard<'_, T> {
            self.0.lock().unwrap_or_else(|e| e.into_inner())
        }
    }
}

pub(crate) use imp::{Guard, Lock};
