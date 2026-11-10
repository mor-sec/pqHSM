//! Files encrypted as CMS AuthEnvelopedData for a key on the token or for a certificate's
//! holder, and decrypted with the key the file names (`tools/pkiops.c`, docs/fhsm-crypt-plan.md
//! stages 2 and 3; PHASE5_PLAN.md slice 3). The structure is [`crate::cms_env`]'s. OpenSSL does
//! the AES-GCM over the content and the RSA-OAEP encryption to a public key; the token wraps
//! and unwraps the content key (AES key wrap) and does the OAEP decryption, so its keys never
//! leave it.
//!
//! Nothing is written over an existing file and nothing is left behind on failure: output goes
//! to a temporary file beside its destination (mkstemp's, mode 0600), renamed into place only
//! once complete; for decryption only once the GCM tag has verified.

use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;

use openssl::bn::BigNum;
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::md::Md;
use openssl::pkey::{Id, PKey, Public};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::{Padding, Rsa};
use openssl::x509::X509;
use zeroize::Zeroizing;

use crate::cms_env::{self, Rid, der_tlv};
use crate::ffi::{
    CK_MECHANISM, CK_ULONG, has, w_decrypt, w_decrypt_init, w_encrypt, w_encrypt_init,
};
use crate::keys::{CKK_AES, CKK_RSA};
use crate::objects::{CKA_VALUE_LEN, CKM_RSA_PKCS_OAEP, ObjClass, objects};
use crate::ops::{
    CKA_ALLOWED_MECHANISMS, CKA_KEY_TYPE, CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKG_MGF1_SHA256,
    CKM_SHA256, CKO_PUBLIC_KEY, CKO_SECRET_KEY, Handle, err, find_one, get_attr, get_ulong, text,
};
use crate::{Error, strerror};

const CKM_AES_KEY_WRAP: CK_ULONG = 0x2109;
const CKZ_DATA_SPECIFIED: CK_ULONG = 1;
const CHUNK: usize = 65536;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// A path as C's `%s` prints it.
fn p(path: &Path) -> &[u8] {
    path.as_os_str().as_bytes()
}

fn mech(mechanism: CK_ULONG) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism,
        p_parameter: null_mut(),
        parameter_len: 0,
    }
}

/// `env_key`: the secret AES key labelled `label`, and its size in bits.
fn env_key(s: Handle, label: &[u8]) -> Result<(Handle, u32), Error> {
    let h = find_one(s, CKO_SECRET_KEY, label)?;
    if get_ulong(s, h, CKA_KEY_TYPE)? != CKK_AES {
        return Err(err(
            3,
            &[b"the secret key \"", label, b"\" is not an AES key\n"],
        ));
    }
    let vl = get_ulong(s, h, CKA_VALUE_LEN)?;
    if !matches!(vl, 16 | 24 | 32) {
        return Err(err(
            3,
            &[
                b"the AES key \"",
                label,
                format!("\" is {vl} bytes long\n").as_bytes(),
            ],
        ));
    }
    Ok((h, vl as u32 * 8))
}

/// `token_wrap`: the content key wrapped by the token key with AES key wrap (RFC 3394).
fn token_wrap(s: Handle, h: Handle, cek: &[u8; 32]) -> Result<Vec<u8>, Error> {
    if !has("EncryptInit") || !has("Encrypt") {
        return Err(Error::new(2, "the module does not implement C_Encrypt\n"));
    }
    let mut m = mech(CKM_AES_KEY_WRAP);
    // SAFETY: a mechanism without parameters; plain handles.
    let rv = unsafe { w_encrypt_init(s, &mut m, h) };
    if rv != 0 {
        return Err(Error::new(
            2,
            format!("C_EncryptInit(CKM_AES_KEY_WRAP) failed (0x{rv:x})\n"),
        ));
    }
    let (mut out, mut ol) = ([0u8; 48], 48 as CK_ULONG);
    // SAFETY: 32 readable bytes in, 48 writable out, ol writable.
    let rv = unsafe { w_encrypt(s, cek.as_ptr().cast_mut(), 32, out.as_mut_ptr(), &mut ol) };
    if rv != 0 {
        return Err(Error::new(
            2,
            format!("C_Encrypt(CKM_AES_KEY_WRAP) failed (0x{rv:x})\n"),
        ));
    }
    if ol != 40 {
        return Err(Error::new(
            2,
            format!("AES key wrap returned {ol} bytes for 32\n"),
        ));
    }
    Ok(out[..40].to_vec())
}

/// `token_unwrap`: the content key, `want` bytes, unwrapped by the token key. AES key wrap
/// carries its own integrity check: a wrong key fails here, before a byte of content.
fn token_unwrap(
    s: Handle,
    h: Handle,
    ekey: &[u8],
    want: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !has("DecryptInit") || !has("Decrypt") {
        return Err(Error::new(2, "the module does not implement C_Decrypt\n"));
    }
    let mut m = mech(CKM_AES_KEY_WRAP);
    // SAFETY: as token_wrap.
    let rv = unsafe { w_decrypt_init(s, &mut m, h) };
    if rv != 0 {
        return Err(Error::new(
            2,
            format!("C_DecryptInit(CKM_AES_KEY_WRAP) failed (0x{rv:x})\n"),
        ));
    }
    let (mut buf, mut ol) = (Zeroizing::new([0u8; 64]), 64 as CK_ULONG);
    // SAFETY: ekey readable for its length, 64 writable bytes out, ol writable.
    let rv = unsafe {
        w_decrypt(
            s,
            ekey.as_ptr().cast_mut(),
            ekey.len() as CK_ULONG,
            buf.as_mut_ptr(),
            &mut ol,
        )
    };
    if rv != 0 {
        return Err(Error::new(
            4,
            format!(
                "the content key does not unwrap with this key (0x{rv:x}): the file was not made for it, or was altered\n"
            ),
        ));
    }
    if ol as usize != want {
        return Err(Error::new(
            4,
            format!(
                "the content key is {ol} bytes; AES-{}-GCM needs {want}\n",
                want * 8
            ),
        ));
    }
    Ok(Zeroizing::new(buf[..want].to_vec()))
}

/// `temp_beside`: a new file beside `path` (mkstemp's `path.XXXXXX`, mode 0600), and its name.
fn temp_beside(path: &Path) -> Result<(File, Vec<u8>), Error> {
    let mut t = [p(path), b".XXXXXX\0"].concat();
    // SAFETY: a NUL-terminated template mkstemp may rewrite in place.
    let fd = unsafe { libc::mkstemp(t.as_mut_ptr().cast()) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return Err(err(
            2,
            &[
                b"cannot create a file beside ",
                p(path),
                b": ",
                strerror(&e).as_bytes(),
                b"\n",
            ],
        ));
    }
    t.pop();
    // SAFETY: a descriptor mkstemp just opened, owned from here on.
    Ok((unsafe { File::from_raw_fd(fd) }, t))
}

/// `temp_finish`: renamed into place when `ok`, removed otherwise.
fn temp_finish(f: File, tmp: &[u8], path: &Path, mut ok: bool) -> Result<(), Error> {
    let failed =
        |what: &[u8], e: &io::Error| err(2, &[what, p(path), b": ", strerror(e).as_bytes(), b"\n"]);
    let mut r = Ok(());
    if ok && let Err(e) = f.sync_all() {
        r = Err(failed(b"cannot write ", &e));
        ok = false;
    }
    // close's own result, which dropping a File discards.
    // SAFETY: the descriptor into_raw_fd hands over, closed once.
    if unsafe { libc::close(f.into_raw_fd()) } != 0 && ok {
        r = Err(failed(b"cannot write ", &io::Error::last_os_error()));
        ok = false;
    }
    let tmp = Path::new(std::ffi::OsStr::from_bytes(tmp));
    if ok && let Err(e) = std::fs::rename(tmp, path) {
        r = Err(failed(b"cannot rename onto ", &e));
        ok = false;
    }
    if !ok {
        let _ = std::fs::remove_file(tmp);
    }
    r
}

fn refuse_existing(path: &Path) -> Result<(), Error> {
    if std::fs::metadata(path).is_ok() {
        return Err(err(1, &[p(path), b" exists; nothing is written over it\n"]));
    }
    Ok(())
}

fn gcm_name(bits: u32) -> &'static str {
    match bits {
        128 => "AES-128-GCM",
        192 => "AES-192-GCM",
        _ => "AES-256-GCM",
    }
}

/// `fopen` and `fstat` of the file to read, refused unless regular; and its size.
fn open_regular(path: &Path) -> Result<(File, u64), Error> {
    let f = File::open(path).map_err(|e| {
        err(
            2,
            &[
                b"cannot read ",
                p(path),
                b": ",
                strerror(&e).as_bytes(),
                b"\n",
            ],
        )
    })?;
    match f.metadata() {
        Ok(m) if m.is_file() => Ok((f, m.len())),
        _ => Err(err(2, &[p(path), b" is not a regular file\n"])),
    }
}

/// `fread(buf, 1, buf.len(), f)`: as much as there is, up to the buffer; an error after a
/// short read is an error.
fn read_full(f: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

// --- RSA-OAEP recipients ------------------------------------------------------------------------

/// `rsa_pkey_of`: an RSA public key from CKA_MODULUS and CKA_PUBLIC_EXPONENT, which a private
/// key answers too.
fn rsa_pkey_of(s: Handle, h: Handle) -> Option<PKey<Public>> {
    let n = get_attr(s, h, CKA_MODULUS).ok()?;
    let e = get_attr(s, h, CKA_PUBLIC_EXPONENT).ok()?;
    let rsa =
        Rsa::from_public_components(BigNum::from_slice(&n).ok()?, BigNum::from_slice(&e).ok()?)
            .ok()?;
    PKey::from_rsa(rsa).ok()
}

/// `ski_of`: subjectKeyIdentifier, RFC 5280 method 1: SHA-1 over the subjectPublicKey BIT
/// STRING's bits (what `X509_PUBKEY_get0_param` gives: its value less the unused-bits byte).
fn ski_of(k: &PKey<Public>) -> Option<[u8; 20]> {
    let spki = k.public_key_to_der().ok()?;
    let (0x30, body, _) = der_tlv(&spki)? else {
        return None;
    };
    let (0x30, _, rest) = der_tlv(body)? else {
        return None;
    };
    let (0x03, bits, _) = der_tlv(rest)? else {
        return None;
    };
    let (_, bits) = bits.split_first()?;
    (!bits.is_empty()).then(|| openssl::sha::sha1(bits))
}

/// `oaep_allowed`: CKA_ALLOWED_MECHANISMS absent, empty, or naming CKM_RSA_PKCS_OAEP.
fn oaep_allowed(s: Handle, h: Handle) -> bool {
    let Ok(v) = get_attr(s, h, CKA_ALLOWED_MECHANISMS) else {
        return true;
    };
    v.is_empty()
        || v.as_chunks::<{ size_of::<CK_ULONG>() }>()
            .0
            .iter()
            .any(|m| CK_ULONG::from_ne_bytes(*m) == CKM_RSA_PKCS_OAEP)
}

/// `oaep_encrypt`: the content key to `k`, RSAES-OAEP with SHA-256 and MGF1-SHA-256, in
/// software: a public operation, which needs neither the token nor a login.
fn oaep_encrypt(k: &PKey<Public>, cek: &[u8]) -> Result<Vec<u8>, Error> {
    let run = || -> Result<Vec<u8>, openssl::error::ErrorStack> {
        let mut c = PkeyCtx::new(k)?;
        c.encrypt_init()?;
        c.set_rsa_padding(Padding::PKCS1_OAEP)?;
        c.set_rsa_oaep_md(Md::sha256())?;
        c.set_rsa_mgf1_md(Md::sha256())?;
        let mut out = Vec::new();
        c.encrypt_to_vec(cek, &mut out)?;
        Ok(out)
    };
    run().map_err(|_| Error::new(2, "RSA-OAEP encryption of the content key failed\n"))
}

/// `CK_RSA_PKCS_OAEP_PARAMS`.
#[repr(C)]
struct OaepParams {
    hash_alg: CK_ULONG,
    mgf: CK_ULONG,
    source: CK_ULONG,
    p_source_data: *mut c_void,
    source_data_len: CK_ULONG,
}

/// `token_oaep_decrypt`: the token's half, C_Decrypt with CKM_RSA_PKCS_OAEP, SHA-256,
/// MGF1-SHA-256. Any failure is None: trying a key that is not the recipient's costs a
/// refusal and reveals nothing.
fn token_oaep_decrypt(
    s: Handle,
    h: Handle,
    ekey: &[u8],
    want: usize,
) -> Option<Zeroizing<Vec<u8>>> {
    if !has("DecryptInit") || !has("Decrypt") {
        return None;
    }
    let mut prm = OaepParams {
        hash_alg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        source: CKZ_DATA_SPECIFIED,
        p_source_data: null_mut(),
        source_data_len: 0,
    };
    let mut m = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_OAEP,
        p_parameter: (&raw mut prm).cast(),
        parameter_len: size_of::<OaepParams>() as CK_ULONG,
    };
    // SAFETY: the parameters outlive the call; plain handles.
    if unsafe { w_decrypt_init(s, &mut m, h) } != 0 {
        return None;
    }
    let (mut buf, mut ol) = (Zeroizing::new([0u8; 512]), 512 as CK_ULONG);
    // SAFETY: ekey readable for its length, 512 writable bytes out, ol writable.
    let rv = unsafe {
        w_decrypt(
            s,
            ekey.as_ptr().cast_mut(),
            ekey.len() as CK_ULONG,
            buf.as_mut_ptr(),
            &mut ol,
        )
    };
    (rv == 0 && ol as usize == want).then(|| Zeroizing::new(buf[..want].to_vec()))
}

/// The serial number's whole TLV, from a certificate's DER: what `i2d_ASN1_INTEGER` of the
/// parsed serial gives, since OpenSSL takes only a minimal encoding.
fn serial_tlv(der: &[u8]) -> Option<&[u8]> {
    let (0x30, cert, _) = der_tlv(der)? else {
        return None;
    };
    let (0x30, mut tbs, _) = der_tlv(cert)? else {
        return None;
    };
    if let Some((0xA0, _, after)) = der_tlv(tbs) {
        tbs = after; // [0] version
    }
    let (0x02, _, after) = der_tlv(tbs)? else {
        return None;
    };
    Some(&tbs[..tbs.len() - after.len()])
}

/// IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber CertificateSerialNumber }.
fn issuer_and_serial(cert: &X509) -> Option<Vec<u8>> {
    let iss = cert.issuer_name().to_der().ok()?;
    let der = cert.to_der().ok()?;
    let ser = serial_tlv(&der)?;
    let n = iss.len() + ser.len();
    if iss.is_empty() || ser.is_empty() || n >= 0x10000 {
        return None;
    }
    let mut ias = vec![0x30];
    match n {
        0..0x80 => ias.push(n as u8),
        0x80..0x100 => ias.extend([0x81, n as u8]),
        _ => ias.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    ias.extend(iss);
    ias.extend(ser);
    Some(ias)
}

/// `ktri_for`: a KeyTransRecipientInfo for `k`: by the certificate's subjectKeyIdentifier, by
/// the key's own when there is no certificate, by issuer and serial when the certificate has
/// none.
fn ktri_for(k: &PKey<Public>, cert: Option<&X509>, cek: &[u8]) -> Result<Vec<u8>, Error> {
    if k.size() > 1024 {
        return Err(Error::new(1, "the RSA key is larger than this handles\n"));
    }
    let ek = oaep_encrypt(k, cek)?;
    let ri = match (cert, cert.and_then(|c| c.subject_key_id())) {
        (_, Some(id)) => Some(cms_env::ktri_oaep(Rid::Ski(id.as_slice()), &ek)),
        (None, None) => {
            let md =
                ski_of(k).ok_or_else(|| Error::new(2, "cannot compute the key's identifier\n"))?;
            Some(cms_env::ktri_oaep(Rid::Ski(&md), &ek))
        }
        (Some(c), None) => issuer_and_serial(c).map(|ias| cms_env::ktri_oaep(Rid::Ias(&ias), &ek)),
    };
    ri.ok_or_else(|| Error::new(2, "cannot encode the recipient\n"))
}

// --- writing and reading ------------------------------------------------------------------------

/// `env_write`: `in_path` streamed into `out_path` under `cek`, for the recipient `ri`.
fn env_write(in_path: &Path, out_path: &Path, cek: &[u8; 32], ri: &[u8]) -> Result<(), Error> {
    let (mut inp, size) = open_regular(in_path)?;
    let mut nonce = [0u8; NONCE_LEN];
    if openssl::rand::rand_bytes(&mut nonce).is_err() {
        return Err(Error::new(2, "no random bytes for the nonce\n"));
    }
    let (mut out, tmp) = temp_beside(out_path)?;
    let mut write = || -> Result<(), Error> {
        let head = cms_env::head(ri, 256, &nonce, size, TAG_LEN);
        if head.is_none_or(|h| out.write_all(&h).is_err()) {
            return Err(err(2, &[b"cannot write ", p(out_path), b"\n"]));
        }
        let unavailable = || Error::new(2, "AES-256-GCM is not available\n");
        let cipher = Cipher::fetch(None, "AES-256-GCM", None).map_err(|_| unavailable())?;
        let mut ctx = CipherCtx::new().map_err(|_| unavailable())?;
        ctx.encrypt_init(Some(&cipher), Some(cek), Some(&nonce))
            .map_err(|_| unavailable())?;
        let mut ib = Zeroizing::new(vec![0u8; CHUNK]);
        let mut ob = Zeroizing::new(vec![0u8; CHUNK + 32]);
        let (mut seen, mut read_failed) = (0u64, false);
        loop {
            let got = match read_full(&mut inp, &mut ib) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => {
                    read_failed = true;
                    break;
                }
            };
            let w = ctx.cipher_update(&ib[..got], Some(&mut ob));
            if w.is_err() || out.write_all(&ob[..*w.as_ref().unwrap_or(&0)]).is_err() {
                return Err(err(2, &[b"cannot encrypt into ", p(out_path), b"\n"]));
            }
            seen += got as u64;
        }
        // The head promised `size` bytes; a file that changed while it was read would make the
        // structure lie about its own length.
        if read_failed || seen != size {
            return Err(err(2, &[p(in_path), b" changed while it was read\n"]));
        }
        let mut tag = [0u8; TAG_LEN];
        if ctx.cipher_final(&mut ob).is_err()
            || ctx.tag(&mut tag).is_err()
            || out.write_all(&cms_env::tail(&tag)).is_err()
        {
            return Err(err(2, &[b"cannot finish ", p(out_path), b"\n"]));
        }
        Ok(())
    };
    let r = write();
    let fin = temp_finish(out, &tmp, out_path, r.is_ok());
    r.and(fin)
}

/// `pkiops_encrypt_file`: for `label`. An AES key wraps the content key (a KEK recipient named
/// by the label); an RSA-OAEP pair's public half encrypts it (a key-transport recipient named
/// by its subjectKeyIdentifier). Codes: 1 an output that exists, 2 the module or the file
/// system, 3 no such key.
pub fn encrypt_file(s: Handle, label: &[u8], in_path: &Path, out_path: &Path) -> Result<(), Error> {
    refuse_existing(out_path)?;
    let mut cek = Zeroizing::new([0u8; 32]);
    if openssl::rand::rand_priv_bytes(&mut cek[..]).is_err() {
        return Err(Error::new(2, "no random bytes for the content key\n"));
    }
    let ri = if find_one(s, CKO_SECRET_KEY, label).is_ok() {
        // A secret key under the label: it wraps the content key itself.
        let (h, kbits) = env_key(s, label)?;
        let ekey = token_wrap(s, h, &cek)?;
        cms_env::kekri(label, kbits, &ekey)
    } else if let Ok(h) = find_one(s, CKO_PUBLIC_KEY, label) {
        // An RSA key pair: the content key goes to its public half.
        if get_ulong(s, h, CKA_KEY_TYPE)? != CKK_RSA || !oaep_allowed(s, h) {
            return Err(err(
                3,
                &[
                    b"the key \"",
                    label,
                    b"\" is neither an AES key nor an RSA key that may encrypt with OAEP\n",
                ],
            ));
        }
        let k = rsa_pkey_of(s, h)
            .ok_or_else(|| err(2, &[b"cannot read the public key \"", label, b"\"\n"]))?;
        Some(ktri_for(&k, None, &cek[..])?)
    } else {
        return Err(err(
            3,
            &[
                b"no AES key and no RSA encryption key labelled \"",
                label,
                b"\"\n",
            ],
        ));
    };
    let ri = ri.ok_or_else(|| Error::new(2, "cannot encode the recipient\n"))?;
    env_write(in_path, out_path, &cek, &ri)
}

/// `read_cert`: the certificate in `path`, PEM or DER.
fn read_cert(path: &Path) -> Result<X509, Error> {
    let mut f = File::open(path).map_err(|e| {
        err(
            2,
            &[
                b"cannot read ",
                p(path),
                b": ",
                strerror(&e).as_bytes(),
                b"\n",
            ],
        )
    })?;
    // As BIO_new_file: once open, a read that fails (a directory) is a file that does not
    // parse, code 1, not an I/O error.
    let mut data = Vec::new();
    let _ = f.read_to_end(&mut data);
    X509::from_pem(&data)
        .or_else(|_| X509::from_der(&data))
        .map_err(|_| err(1, &[p(path), b" is not a certificate, PEM or DER\n"]))
}

/// `pkiops_encrypt_file_for_cert`: for the holder of the certificate in `cert_path`, an RSA
/// key. No token and no login: encrypting for someone needs only their public key.
pub fn encrypt_file_for_cert(
    cert_path: &Path,
    in_path: &Path,
    out_path: &Path,
) -> Result<(), Error> {
    refuse_existing(out_path)?;
    let x = read_cert(cert_path)?;
    let k = x.public_key().ok().filter(|k| k.id() == Id::RSA).ok_or_else(|| {
        err(
            1,
            &[
                p(cert_path),
                b" does not certify an RSA key: only RSA-OAEP recipients are encrypted for, for now\n",
            ],
        )
    })?;
    let mut cek = Zeroizing::new([0u8; 32]);
    if openssl::rand::rand_priv_bytes(&mut cek[..]).is_err() {
        return Err(Error::new(2, "no random bytes\n"));
    }
    let ri = ktri_for(&k, Some(&x), &cek[..])?;
    env_write(in_path, out_path, &cek, &ri)
}

/// `pkiops_decrypt_file`: the key is found from the file, the first recipient this token can
/// open: a KEK recipient naming one of its AES keys, then an RSA-OAEP recipient one of its RSA
/// keys opens. The label of the key used goes into `used` once the key is found, as C's does,
/// whatever follows. Codes as [`encrypt_file`], and 4 a file that does not open with the key:
/// altered, or made for another.
pub fn decrypt_file(
    s: Handle,
    in_path: &Path,
    out_path: &Path,
    used: &mut Option<Vec<u8>>,
) -> Result<(), Error> {
    refuse_existing(out_path)?;
    let (mut inp, size) = open_regular(in_path)?;
    let mut head = vec![0u8; cms_env::HEAD_MAX];
    // An error reading is a short head, which the parse then refuses, as C's unchecked fread.
    let hn = read_full(&mut inp, &mut head).unwrap_or(0);
    let hd = cms_env::parse_head(&head[..hn])
        .map_err(|why| err(1, &[p(in_path), b": ", why.as_bytes(), b"\n"]))?;
    let mut tail = [0u8; 256];
    let after = hd.content_off.checked_add(hd.content_len);
    let Some(tn) = after
        .filter(|&a| hd.content_off <= size && a <= size)
        .map(|a| size - a)
        .filter(|&t| t <= tail.len() as u64)
    else {
        return Err(err(
            1,
            &[
                p(in_path),
                b": its length does not match the structure it declares\n",
            ],
        ));
    };
    let tn = tn as usize;
    let read_tail = inp
        .seek(SeekFrom::Start(hd.content_off + hd.content_len))
        .and_then(|_| inp.read_exact(&mut tail[..tn]));
    let tag = match read_tail {
        Err(_) => Err("cannot read its end"),
        Ok(()) => cms_env::parse_tail(&tail[..tn], &hd),
    }
    .map_err(|why| err(1, &[p(in_path), b": ", why.as_bytes(), b"\n"]))?;

    // The first recipient this token can open: a KEK recipient naming one of its AES keys,
    // then an RSA-OAEP recipient one of its RSA keys opens.
    let want = hd.gcm_bits as usize / 8;
    let mut found: Option<(Zeroizing<Vec<u8>>, Vec<u8>)> = None;
    let (mut names, mut nl) = (Vec::new(), 0);
    for k in &hd.kek {
        if found.is_some() {
            break;
        }
        let label = k.id;
        if label.is_empty() || label.len() >= 65 || label.contains(&0) {
            continue;
        }
        let piece = [if nl > 0 { &b", "[..] } else { b"" }, b"\"", label, b"\""].concat();
        crate::objects::append_capped(&mut names, &mut nl, 200, &piece);
        let Ok((h, kbits)) = env_key(s, label) else {
            continue;
        };
        if kbits != k.wrap_bits {
            return Err(err(
                4,
                &[
                    b"the key \"",
                    label,
                    format!(
                        "\" is AES-{kbits}; the file wraps its content key with AES-{}\n",
                        k.wrap_bits
                    )
                    .as_bytes(),
                ],
            ));
        }
        found = Some((token_unwrap(s, h, k.ekey, want)?, label.to_vec()));
    }
    let refused = hd.ktri.iter().rev().find_map(|t| t.refused);
    let openable = hd.ktri.iter().filter(|t| t.refused.is_none()).count();
    if found.is_none()
        && openable > 0
        && let Ok(v) = objects(s, 1 << ObjClass::Private as u32)
    {
        // The token's RSA private keys, each with the identifier its public key would have:
        // Some(Some(ski)), Some(None) when it has no computable one, None when unreadable.
        let skis: Vec<Option<Option<[u8; 20]>>> = v
            .iter()
            .map(|o| {
                if o.key_type != CKK_RSA {
                    return Some(None);
                }
                rsa_pkey_of(s, o.handle).map(|k| ski_of(&k))
            })
            .collect();
        // Pass 0: keys whose identifier the recipient names. Pass 1: the rest, for a recipient
        // named by issuer and serial, or by an identifier computed some other way.
        'passes: for pass in 0..2 {
            for t in hd.ktri.iter().filter(|t| t.refused.is_none()) {
                for (o, ski) in v.iter().zip(&skis) {
                    let Some(ski) = ski else { continue };
                    if o.key_type != CKK_RSA {
                        continue;
                    }
                    let matches = t.ski.is_some_and(|r| ski.is_some_and(|k| r == k));
                    if (pass == 0) != matches {
                        continue;
                    }
                    if let Some(cek) = token_oaep_decrypt(s, o.handle, t.ekey, want) {
                        found = Some((cek, text(&o.label).to_vec()));
                        break 'passes;
                    }
                }
            }
        }
    }
    let Some((cek, label)) = found else {
        let msg = if let (Some(why), 0, true) = (refused, openable, hd.kek.is_empty()) {
            err(1, &[p(in_path), b": ", why.as_bytes(), b"\n"])
        } else if !hd.kek.is_empty() && hd.ktri.is_empty() {
            err(
                3,
                &[
                    b"no AES key on this token is named by the file's recipients",
                    if nl > 0 { b": " } else { b"" },
                    &names,
                    b"\n",
                ],
            )
        } else {
            let tail: &[u8] = match (openable > 0, nl > 0) {
                (false, _) => b"",
                (true, true) => b", and an RSA key none of these is",
                (true, false) => b": no RSA key here is the recipient's",
            };
            err(
                3,
                &[
                    b"no key on this token opens the file",
                    if nl > 0 { b": it names " } else { b"" },
                    &names,
                    tail,
                    b"\n",
                ],
            )
        };
        return Err(msg);
    };
    *used = Some(label);

    if inp.seek(SeekFrom::Start(hd.content_off)).is_err() {
        return Err(err(2, &[b"cannot read ", p(in_path), b"\n"]));
    }
    let (mut out, tmp) = temp_beside(out_path)?;
    let mut write = || -> Result<(), Error> {
        let name = gcm_name(hd.gcm_bits);
        let unavailable = || Error::new(2, format!("{name} is not available\n"));
        let cipher = Cipher::fetch(None, name, None).map_err(|_| unavailable())?;
        let mut ctx = CipherCtx::new().map_err(|_| unavailable())?;
        ctx.decrypt_init(Some(&cipher), None, None)
            .and_then(|()| ctx.set_iv_length(hd.nonce.len()))
            .and_then(|()| ctx.decrypt_init(None, Some(&cek), Some(hd.nonce)))
            .map_err(|_| unavailable())?;
        let mut ib = Zeroizing::new(vec![0u8; CHUNK]);
        let mut ob = Zeroizing::new(vec![0u8; CHUNK + 32]);
        let mut left = hd.content_len;
        while left > 0 {
            let chunk = left.min(CHUNK as u64) as usize;
            let ok = inp.read_exact(&mut ib[..chunk]).is_ok()
                && ctx
                    .cipher_update(&ib[..chunk], Some(&mut ob))
                    .is_ok_and(|w| out.write_all(&ob[..w]).is_ok());
            if !ok {
                return Err(err(2, &[b"cannot decrypt ", p(in_path), b"\n"]));
            }
            left -= chunk as u64;
        }
        if ctx.set_tag(tag).is_err() || ctx.cipher_final(&mut ob).is_err() {
            return Err(err(
                4,
                &[
                    p(in_path),
                    b" does not authenticate: it was altered after it was made. Nothing was written.\n",
                ],
            ));
        }
        Ok(())
    };
    let r = write();
    let fin = temp_finish(out, &tmp, out_path, r.is_ok());
    r.and(fin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_as_openssl() {
        // A self-signed RSA certificate without subjectKeyIdentifier: its issuer and serial,
        // and its key's identifier as OpenSSL computes it (X509_PUBKEY_get0_param's bits).
        let rsa = Rsa::generate(2048).unwrap();
        let k = PKey::from_rsa(rsa).unwrap();
        let mut b = openssl::x509::X509Builder::new().unwrap();
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "ias").unwrap();
        let name = name.build();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        let serial = BigNum::from_hex_str("80ff").unwrap(); // a leading 0x00 in DER
        b.set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        b.set_pubkey(&k).unwrap();
        b.sign(&k, openssl::hash::MessageDigest::sha256()).unwrap();
        let x = b.build();
        assert!(x.subject_key_id().is_none());
        assert_eq!(
            serial_tlv(&x.to_der().unwrap()),
            Some(&[0x02, 0x03, 0x00, 0x80, 0xff][..])
        );
        let ias = issuer_and_serial(&x).unwrap();
        let iss = name.to_der().unwrap();
        assert_eq!(ias[0], 0x30);
        assert!(ias.ends_with(&[&iss[..], &[0x02, 0x03, 0x00, 0x80, 0xff]].concat()));
        let pk = PKey::public_key_from_der(&k.public_key_to_der().unwrap()).unwrap();
        let ski = ski_of(&pk).unwrap();
        let n = pk.rsa().unwrap().n().to_vec();
        let bits = pk.public_key_to_der().unwrap();
        // The bits end with the RSAPublicKey, whose modulus is the key's.
        assert!(bits.windows(n.len()).any(|w| w == n));
        assert_eq!(ski.len(), 20);
    }
}
