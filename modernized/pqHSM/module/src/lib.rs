//! libpqhsm.so (PHASE6_PLAN.md §8.2, slice 5a), and the staticlib the hybrid build links.
//! It bundles the C ABI of every ported crate, so the module carries one copy of std; naming
//! each crate keeps its `#[no_mangle]` symbols linked (review L1).
//!
//! The cdylib links with `--exclude-libs,ALL` (build.rs), which keeps every symbol of the
//! dependency rlibs out of the dynamic table, so its exports are exactly the functions defined
//! here: the 62 `C_*` and `fhsm_kat_results` (`testdata/abi/libpqhsm.txt`). Each forwards to
//! the Rust entry point under its crate's name, as the C shims did (p11/shim/interface.c,
//! crypto/shim/kat_results.c), with their C-level types: pointers as `void *`, `CK_ULONG` and
//! `CK_RV` as `unsigned long`.
#![allow(non_snake_case, clippy::missing_safety_doc, clippy::too_many_arguments)]

extern crate pqhsm_audit;
extern crate pqhsm_crypto;
extern crate pqhsm_p11;
extern crate pqhsm_pki;
extern crate pqhsm_selftest;
extern crate pqhsm_token;

use std::ffi::{c_ulong, c_void};

type Rv = c_ulong;
type Ul = c_ulong;
type P = *mut c_void;

/// `name = target(args);`: `name` exported, forwarding to `target`.
macro_rules! exports {
    ($($name:ident = $target:ident($($a:ident: $t:ty),*);)*) => {
        unsafe extern "C" {
            $(fn $target($($a: $t),*) -> Rv;)*
        }
        $(
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $name($($a: $t),*) -> Rv {
                // SAFETY: the caller's arguments, passed on unchanged
                unsafe { $target($($a),*) }
            }
        )*
    };
}

exports! {
    C_GetFunctionList = pqhsm_p11_get_function_list(out: P);
    C_GetInterfaceList = pqhsm_p11_get_interface_list(list: P, count: P);
    C_GetInterface = pqhsm_p11_get_interface(name: P, version: P, out: P, flags: Ul);
    C_Initialize = pqhsm_C_Initialize(a: P);
    C_Finalize = pqhsm_C_Finalize(a: P);
    C_GetInfo = pqhsm_C_GetInfo(a: P);
    C_GetSlotList = pqhsm_C_GetSlotList(p: u8, l: P, n: P);
    C_GetSlotInfo = pqhsm_C_GetSlotInfo(s: Ul, i: P);
    C_GetTokenInfo = pqhsm_C_GetTokenInfo(s: Ul, i: P);
    C_InitToken = pqhsm_C_InitToken(s: Ul, p: P, n: Ul, l: P);
    C_OpenSession = pqhsm_C_OpenSession(s: Ul, f: Ul, a: P, c: P, h: P);
    C_CloseSession = pqhsm_C_CloseSession(h: Ul);
    C_CloseAllSessions = pqhsm_C_CloseAllSessions(s: Ul);
    C_GetSessionInfo = pqhsm_C_GetSessionInfo(h: Ul, i: P);
    C_Login = pqhsm_C_Login(h: Ul, u: Ul, p: P, n: Ul);
    C_Logout = pqhsm_C_Logout(h: Ul);
    C_InitPIN = pqhsm_C_InitPIN(h: Ul, p: P, n: Ul);
    C_SetPIN = pqhsm_C_SetPIN(h: Ul, o: P, on: Ul, p: P, pn: Ul);
    C_FindObjectsInit = pqhsm_C_FindObjectsInit(h: Ul, t: P, n: Ul);
    C_FindObjects = pqhsm_C_FindObjects(h: Ul, o: P, m: Ul, n: P);
    C_FindObjectsFinal = pqhsm_C_FindObjectsFinal(h: Ul);
    C_GetObjectSize = pqhsm_C_GetObjectSize(h: Ul, o: Ul, s: P);
    C_DestroyObject = pqhsm_C_DestroyObject(h: Ul, o: Ul);
    C_GetAttributeValue = pqhsm_C_GetAttributeValue(h: Ul, o: Ul, t: P, n: Ul);
    C_SetAttributeValue = pqhsm_C_SetAttributeValue(h: Ul, o: Ul, t: P, n: Ul);
    C_CopyObject = pqhsm_C_CopyObject(h: Ul, o: Ul, t: P, n: Ul, no: P);
    C_DigestInit = pqhsm_C_DigestInit(h: Ul, m: P);
    C_Digest = pqhsm_C_Digest(h: Ul, d: P, dn: Ul, o: P, on: P);
    C_DigestUpdate = pqhsm_C_DigestUpdate(h: Ul, d: P, dn: Ul);
    C_DigestKey = pqhsm_C_DigestKey(h: Ul, k: Ul);
    C_DigestFinal = pqhsm_C_DigestFinal(h: Ul, o: P, on: P);
    C_EncryptInit = pqhsm_C_EncryptInit(h: Ul, m: P, k: Ul);
    C_Encrypt = pqhsm_C_Encrypt(h: Ul, d: P, dn: Ul, e: P, en: P);
    C_EncryptUpdate = pqhsm_C_EncryptUpdate(h: Ul, d: P, dn: Ul, e: P, en: P);
    C_EncryptFinal = pqhsm_C_EncryptFinal(h: Ul, e: P, en: P);
    C_DecryptInit = pqhsm_C_DecryptInit(h: Ul, m: P, k: Ul);
    C_Decrypt = pqhsm_C_Decrypt(h: Ul, e: P, en: Ul, d: P, dn: P);
    C_DecryptUpdate = pqhsm_C_DecryptUpdate(h: Ul, e: P, en: Ul, d: P, dn: P);
    C_DecryptFinal = pqhsm_C_DecryptFinal(h: Ul, d: P, dn: P);
    C_SignInit = pqhsm_C_SignInit(h: Ul, m: P, k: Ul);
    C_Sign = pqhsm_C_Sign(h: Ul, d: P, dn: Ul, s: P, sn: P);
    C_SignUpdate = pqhsm_C_SignUpdate(h: Ul, d: P, dn: Ul);
    C_SignFinal = pqhsm_C_SignFinal(h: Ul, s: P, sn: P);
    C_VerifyInit = pqhsm_C_VerifyInit(h: Ul, m: P, k: Ul);
    C_Verify = pqhsm_C_Verify(h: Ul, d: P, dn: Ul, s: P, sn: Ul);
    C_VerifyUpdate = pqhsm_C_VerifyUpdate(h: Ul, d: P, dn: Ul);
    C_VerifyFinal = pqhsm_C_VerifyFinal(h: Ul, s: P, sn: Ul);
    C_GetMechanismList = pqhsm_C_GetMechanismList(s: Ul, l: P, n: P);
    C_GetMechanismInfo = pqhsm_C_GetMechanismInfo(s: Ul, t: Ul, i: P);
    C_WaitForSlotEvent = pqhsm_C_WaitForSlotEvent(f: Ul, s: P, r: P);
    C_GetFunctionStatus = pqhsm_C_GetFunctionStatus(h: Ul);
    C_CancelFunction = pqhsm_C_CancelFunction(h: Ul);
    C_SeedRandom = pqhsm_C_SeedRandom(h: Ul, p: P, n: Ul);
    C_GenerateRandom = pqhsm_C_GenerateRandom(h: Ul, p: P, n: Ul);
    C_CreateObject = pqhsm_C_CreateObject(h: Ul, t: P, n: Ul, o: P);
    C_GenerateKey = pqhsm_C_GenerateKey(h: Ul, m: P, t: P, n: Ul, k: P);
    C_GenerateKeyPair = pqhsm_C_GenerateKeyPair(h: Ul, m: P, pu: P, npu: Ul, pr: P, npr: Ul, hpu: P, hpr: P);
    C_WrapKey = pqhsm_C_WrapKey(h: Ul, m: P, wk: Ul, k: Ul, o: P, on: P);
    C_UnwrapKey = pqhsm_C_UnwrapKey(h: Ul, m: P, uk: Ul, w: P, wn: Ul, t: P, n: Ul, k: P);
    C_DeriveKey = pqhsm_C_DeriveKey(h: Ul, m: P, b: Ul, t: P, n: Ul, k: P);
    C_EncapsulateKey = pqhsm_C_EncapsulateKey(h: Ul, m: P, k: Ul, t: P, n: Ul, c: P, cn: P, nk: P);
    C_DecapsulateKey = pqhsm_C_DecapsulateKey(h: Ul, m: P, k: Ul, t: P, n: Ul, c: P, cn: Ul, nk: P);
}

unsafe extern "C" {
    fn pqhsm_kat_results(count: *mut usize) -> *const c_void;
}

/// The module's one export beyond PKCS#11: the power-on KAT results (`include/fhsm_crypto.h`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_kat_results(count: *mut usize) -> *const c_void {
    // SAFETY: the caller's argument, passed on unchanged
    unsafe { pqhsm_kat_results(count) }
}
