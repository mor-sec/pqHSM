//! The pure DER reader that finds a CMS structure's signed attributes (`tlv_at`, and the walk
//! ContentInfo -> SignedData -> SignerInfo -> [0]). Seeded from the CMS structures in the
//! x509 goldens.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqhsm_pki::x509::{cms_signed_attrs_of, tlv_at};

fuzz_target!(|der: &[u8]| {
    if let Some((_, value, whole)) = tlv_at(der) {
        assert!(whole.len() <= der.len() && whole.ends_with(value));
    }
    if let Some(attrs) = cms_signed_attrs_of(der) {
        assert!(attrs.len() <= der.len() && attrs[0] == 0x31);
    }
});
