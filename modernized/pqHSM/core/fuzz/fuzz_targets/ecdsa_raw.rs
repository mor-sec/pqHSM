//! `ecdsa::der_to_raw` and `raw_to_der` with `fuzz/fuzz_ecdsa_raw.c`'s paths: any DER, the raw
//! round trip bit for bit, and the DER one byte short.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqhsm_core::ecdsa::{der_to_raw, raw_to_der};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    let nlen = [32, 48, 66][usize::from(sel % 3)];
    if let Some(raw) = der_to_raw(body, nlen) {
        assert_eq!(raw.len(), 2 * nlen);
    }
    if let Some(raw) = body.get(..2 * nlen) {
        let der = raw_to_der(raw, nlen).expect("2 * nlen bytes always encode");
        assert_eq!(der_to_raw(&der, nlen).as_deref(), Some(raw));
    }
    if let Some((_, short)) = body.split_last() {
        let _ = der_to_raw(short, nlen);
    }
});
