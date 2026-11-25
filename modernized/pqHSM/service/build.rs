//! The binary's link (Phase 6 slice 5b). pqhsm-pkiops reaches the module in the same process
//! with dlopen(NULL), so the binary exports C_GetFunctionList, and nothing else, as the C link
//! did (`-Wl,--export-dynamic-symbol`). Its unwinder comes from libgcc_eh.a, as with the C
//! link's -static-libgcc, so NEEDED has no libgcc_s.so.1 (see module/build.rs).
fn main() {
    println!("cargo:rustc-link-arg-bins=-Wl,--export-dynamic-symbol=C_GetFunctionList");
    // and kept: a link without it fails, not the first in-process pkiops call (review L2)
    println!("cargo:rustc-link-arg-bins=-Wl,--undefined=C_GetFunctionList");
    println!("cargo:rustc-link-arg-bins=-Wl,--whole-archive,-lgcc_eh,--no-whole-archive");
}
