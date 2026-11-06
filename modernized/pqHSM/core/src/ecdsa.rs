//! `src/fhsm_ecdsa_raw.c`: PKCS#11's raw `r || s` ECDSA signature and OpenSSL's DER
//! Ecdsa-Sig-Value, each way. Pure Rust: C went through `ECDSA_SIG` and BIGNUMs, whose
//! answers on these inputs this reproduces (the DER side only ever comes from OpenSSL).

/// `fhsm_mech_is_ecdsa`: CKM_ECDSA and CKM_ECDSA_SHA256, _SHA384, _SHA512.
pub fn is_ecdsa(mech: u64) -> bool {
    matches!(mech, 0x1041 | 0x1044 | 0x1045 | 0x1046)
}

/// One DER element at the front of `b`: its tag, contents and the rest.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&l, b) = b.split_first()?;
    let (len, b) = match l {
        0..=0x7F => (l as usize, b),
        0x81 => {
            let (&n, b) = b.split_first()?;
            (n as usize, b)
        }
        _ => return None,
    };
    (b.len() >= len).then(|| (tag, &b[..len], &b[len..]))
}

/// `fhsm_ecdsa_der_to_raw`: r and s, each left-padded to `nlen` bytes; `None` where C
/// returned 0 (unparsable, or a half longer than `nlen`).
pub fn der_to_raw(der: &[u8], nlen: usize) -> Option<Vec<u8>> {
    let (0x30, seq, _) = tlv(der)? else {
        return None;
    };
    let (0x02, r, rest) = tlv(seq)? else {
        return None;
    };
    let (0x02, s, _) = tlv(rest)? else {
        return None;
    };
    let mut out = vec![0u8; 2 * nlen];
    for (i, v) in [r, s].into_iter().enumerate() {
        // A negative INTEGER is not a signature OpenSSL makes; as BN_num_bytes, its magnitude
        // is what counts, so it is refused only by length, as C.
        let v = &v[v.iter().take_while(|&&x| x == 0).count()..];
        if v.len() > nlen {
            return None;
        }
        out[i * nlen + nlen - v.len()..(i + 1) * nlen].copy_from_slice(v);
    }
    Some(out)
}

/// `fhsm_ecdsa_raw_to_der`: two minimal non-negative INTEGERs; `None` unless `raw` is
/// `2 * nlen` bytes.
pub fn raw_to_der(raw: &[u8], nlen: usize) -> Option<Vec<u8>> {
    if raw.len() != 2 * nlen {
        return None;
    }
    let int = |b: &[u8]| {
        let b = &b[b.iter().take_while(|&&x| x == 0).count()..];
        let mut v = vec![0x02];
        let pad = b.first().is_none_or(|x| x & 0x80 != 0);
        len(&mut v, b.len() + pad as usize);
        if pad {
            v.push(0);
        }
        v.extend_from_slice(b);
        v
    };
    let (r, s) = raw.split_at(nlen);
    let body = [int(r), int(s)].concat();
    let mut v = vec![0x30];
    len(&mut v, body.len());
    v.extend(body);
    Some(v)
}

fn len(v: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        v.push(n as u8);
    } else {
        v.extend([0x81, n as u8]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_and_der_round_trip_with_c_s_padding_and_refusals() {
        // r = 0x00 0x80 (a leading zero to strip, then a sign byte to add), s = 0x01
        let raw = [0x00, 0x80, 0x00, 0x01];
        let der = raw_to_der(&raw, 2).unwrap();
        assert_eq!(der, [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01]);
        assert_eq!(der_to_raw(&der, 2).unwrap(), raw);
        assert_eq!(raw_to_der(&[0, 0], 1).unwrap(), [0x30, 6, 2, 1, 0, 2, 1, 0]);
        assert!(raw_to_der(&raw, 1).is_none());
        // a half longer than nlen, and garbage
        assert!(der_to_raw(&der, 0).is_none());
        assert!(der_to_raw(&[0x30, 0x03, 0x02, 0x01], 2).is_none());
        // P-521: 66-byte halves and a long-form SEQUENCE length
        let big = [0xFFu8; 132];
        let d = raw_to_der(&big, 66).unwrap();
        assert_eq!(&d[..3], &[0x30, 0x81, 138]);
        assert_eq!(der_to_raw(&d, 66).unwrap(), big);
        assert!(is_ecdsa(0x1041) && is_ecdsa(0x1046) && !is_ecdsa(0x1042) && !is_ecdsa(0x1057));
    }
}
