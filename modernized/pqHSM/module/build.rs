//! The cdylib's link (PHASE6_PLAN.md §8.2, slice 5a): soname libpqhsm.so, and no symbol of the
//! dependency rlibs in the dynamic table, so the exports are src/lib.rs's alone, as hybrid.mk's
//! `--exclude-libs,ALL` kept them to the C shims'. scripts/abi_report.sh checks the result.
fn main() {
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libpqhsm.so");
    println!("cargo:rustc-cdylib-link-arg=-Wl,--exclude-libs,ALL");
    // hybrid.mk's -static-libgcc: std's unwinder from libgcc_eh.a, so NEEDED stays C's (no
    // libgcc_s.so.1). rustc names -lgcc_s itself; lld takes the archive's definitions over the
    // shared ones, and --as-needed then drops libgcc_s.
    println!("cargo:rustc-cdylib-link-arg=-Wl,--whole-archive,-lgcc_eh,--no-whole-archive");
    // An unresolved symbol fails the link, not the first dlopen (review L3).
    println!("cargo:rustc-cdylib-link-arg=-Wl,-z,defs");
}
