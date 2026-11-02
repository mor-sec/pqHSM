//! A whole `slotN.tok` as read from disk: the 317-byte header, the blob framing, and the
//! PIN-free public view. Seeded from `testdata/*.tok` and the store goldens' token files.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqhsm_token::header::Header;
use pqhsm_token::store;

fuzz_target!(|file: &[u8]| {
    if let Ok(h) = Header::parse(file) {
        // Writing normalises (user_initialized to 0/1, throttle bytes to zero), so the check is
        // that what is written parses back to the same header.
        assert_eq!(Header::parse(&h.to_bytes()), Ok(h));
    }
    let _ = store::split_blob(file);
    let _ = store::read_public_view(file);
});
