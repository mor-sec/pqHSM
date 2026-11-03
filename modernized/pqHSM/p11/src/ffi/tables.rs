//! `C_GetFunctionList`, `C_GetInterfaceList` and `C_GetInterface`, and the v2.40, v3.0 and
//! v3.2 tables they return (`src/fhsm_pkcs11.c:13050-13386`). The exported names are defined
//! by `p11/shim/interface.c`, which calls these.
//!
//! C filled the tables at run time under `pthread_once` (#111-prep). Here they are constants,
//! so there is nothing to race on.

use std::ffi::{CStr, c_char, c_ulong, c_void};

type Rv = c_ulong;
const OK: Rv = 0;
const FUNCTION_FAILED: Rv = 0x6;
const ARGUMENTS_BAD: Rv = 0x7;
const FUNCTION_NOT_SUPPORTED: Rv = 0x54;
const BUFFER_TOO_SMALL: Rv = 0x150;

/// One table slot. Rust only takes the entry points' addresses, never calls them, so they are
/// declared without parameters; the caller calls through its own prototypes, as with C's
/// `void *pfn[]`.
type Slot = unsafe extern "C" fn() -> Rv;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Version {
    major: u8,
    minor: u8,
}

#[repr(C)]
struct FunctionList<const N: usize> {
    version: Version,
    pfn: [Slot; N],
}

/// `CK_INTERFACE`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Interface {
    name: *const c_char,
    list: *const c_void,
    flags: c_ulong,
}

/// The two records `C_GetInterface` returns; constant, so sharing them is sound.
struct Shared(Interface);
// SAFETY: both pointers are to immutable statics.
unsafe impl Sync for Shared {}

/// Every slot this module does not implement (`fhsm_not_supported`).
extern "C" fn not_supported() -> Rv {
    FUNCTION_NOT_SUPPORTED
}

macro_rules! v2_40 {
    ($($slot:literal $name:ident)*) => {
        unsafe extern "C" {
            $(fn $name() -> Rv;)*
            fn C_GetInterfaceList() -> Rv;
            fn C_GetInterface() -> Rv;
            fn C_EncapsulateKey() -> Rv;
            fn C_DecapsulateKey() -> Rv;
        }
        /// PKCS#11 v2.40 §C.6 order (`src/fhsm_pkcs11.c:13088-13162`).
        const V2_40: [Slot; 68] = {
            let mut t = [not_supported as Slot; 68];
            $(t[$slot] = $name;)*
            t
        };
    };
}

v2_40! {
    0 C_Initialize 1 C_Finalize 2 C_GetInfo 3 C_GetFunctionList 4 C_GetSlotList
    5 C_GetSlotInfo 6 C_GetTokenInfo 7 C_GetMechanismList 8 C_GetMechanismInfo 9 C_InitToken
    10 C_InitPIN 11 C_SetPIN 12 C_OpenSession 13 C_CloseSession 14 C_CloseAllSessions
    15 C_GetSessionInfo 18 C_Login 19 C_Logout 20 C_CreateObject 21 C_CopyObject
    22 C_DestroyObject 23 C_GetObjectSize 24 C_GetAttributeValue 25 C_SetAttributeValue
    26 C_FindObjectsInit 27 C_FindObjects 28 C_FindObjectsFinal 29 C_EncryptInit 30 C_Encrypt
    31 C_EncryptUpdate 32 C_EncryptFinal 33 C_DecryptInit 34 C_Decrypt 35 C_DecryptUpdate
    36 C_DecryptFinal 37 C_DigestInit 38 C_Digest 39 C_DigestUpdate 40 C_DigestKey
    41 C_DigestFinal 42 C_SignInit 43 C_Sign 44 C_SignUpdate 45 C_SignFinal 48 C_VerifyInit
    49 C_Verify 50 C_VerifyUpdate 51 C_VerifyFinal 58 C_GenerateKey 59 C_GenerateKeyPair
    60 C_WrapKey 61 C_UnwrapKey 62 C_DeriveKey 63 C_SeedRandom 64 C_GenerateRandom
    65 C_GetFunctionStatus 66 C_CancelFunction 67 C_WaitForSlotEvent
}

/// `base` followed by not-supported slots.
const fn extend<const N: usize, const M: usize>(base: [Slot; N]) -> [Slot; M] {
    let mut t = [not_supported as Slot; M];
    let mut i = 0;
    while i < N {
        t[i] = base[i];
        i += 1;
    }
    t
}

/// v3.0: slots 68 and 69 are the interface calls; 70-91 (C_LoginUser, C_SessionCancel, the
/// message family) are not implemented (`:13199-13231`).
const V3_0: [Slot; 92] = {
    let mut t = extend::<68, 92>(V2_40);
    t[68] = C_GetInterfaceList;
    t[69] = C_GetInterface;
    t
};

/// v3.2: the KEM pair at 92 and 93; the other ten v3.2 slots are not implemented (`:13267-13292`).
const V3_2: [Slot; 104] = {
    let mut t = extend::<92, 104>(V3_0);
    t[92] = C_EncapsulateKey;
    t[93] = C_DecapsulateKey;
    t
};

static LIST_2_40: FunctionList<68> = FunctionList {
    version: Version {
        major: 2,
        minor: 40,
    },
    pfn: V2_40,
};
static LIST_3_0: FunctionList<92> = FunctionList {
    version: Version { major: 3, minor: 0 },
    pfn: V3_0,
};
static LIST_3_2: FunctionList<104> = FunctionList {
    version: Version { major: 3, minor: 2 },
    pfn: V3_2,
};

const NAME: &CStr = c"PKCS 11";
static IFACE_3_0: Shared = Shared(Interface {
    name: NAME.as_ptr(),
    list: (&raw const LIST_3_0).cast(),
    flags: 0,
});
static IFACE_3_2: Shared = Shared(Interface {
    name: NAME.as_ptr(),
    list: (&raw const LIST_3_2).cast(),
    flags: 0,
});

/// `C_GetFunctionList` (`:13165`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_p11_get_function_list(out: *mut *const c_void) -> Rv {
    if out.is_null() {
        return ARGUMENTS_BAD;
    }
    // SAFETY: non-NULL; the caller provides a writable pointer, as the C did.
    unsafe { out.write((&raw const LIST_2_40).cast()) };
    OK
}

/// `C_GetInterfaceList` (`:13350`): v3.2 first, so a caller taking the first entry gets the
/// richer one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_p11_get_interface_list(
    list: *mut Interface,
    count: *mut c_ulong,
) -> Rv {
    if count.is_null() {
        return ARGUMENTS_BAD;
    }
    // SAFETY: `count` is non-NULL; `list`, when given, holds `*count` records.
    unsafe {
        let have = *count;
        *count = 2;
        if list.is_null() {
            return OK;
        }
        if have < 2 {
            return BUFFER_TOO_SMALL;
        }
        list.write(IFACE_3_2.0);
        list.add(1).write(IFACE_3_0.0);
    }
    OK
}

/// `C_GetInterface` (`:13366`). A NULL version is v3.0, the default C kept; any version not
/// published is refused rather than answered with a table of another shape. `flags` is
/// ignored, as in C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_p11_get_interface(
    name: *const c_char,
    version: *const Version,
    out: *mut *const Interface,
    _flags: c_ulong,
) -> Rv {
    if out.is_null() {
        return ARGUMENTS_BAD;
    }
    // SAFETY: a non-NULL name is a C string and a non-NULL version two bytes, per PKCS#11.
    if !name.is_null() && unsafe { CStr::from_ptr(name) } != NAME {
        return FUNCTION_FAILED;
    }
    let v = if version.is_null() {
        Version { major: 3, minor: 0 }
    } else {
        unsafe { *version }
    };
    let iface = match (v.major, v.minor) {
        (3, 2) => &IFACE_3_2,
        (3, 0) => &IFACE_3_0,
        _ => return FUNCTION_FAILED,
    };
    // SAFETY: non-NULL; the records are statics, so the pointer stays valid and unchanged.
    unsafe { out.write(&iface.0) };
    OK
}
