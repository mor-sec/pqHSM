//! A decrypted object store, as `Token::login` hands it to the parser after GCM. Seeded from the
//! C-written plaintexts in `tests/golden/store/pt/`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqhsm_token::store;

fuzz_target!(|pt: &[u8]| {
    if let Ok(s) = store::parse(pt) {
        // A store that parses must survive its own write and read back the same.
        let again = store::parse(&store::serialize(&s, false)).expect("re-parse");
        assert_eq!(store::serialize(&again, false), store::serialize(&s, false));
        let _ = store::public_section(&s);
    }
});
