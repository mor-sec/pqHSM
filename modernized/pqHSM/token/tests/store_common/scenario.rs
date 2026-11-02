//! The Rust interpreter of `store_scenarios.txt`. It is gen_store.c's `run_op` line for line:
//! the same ops and the same output fields in the same format, so a step's Rust output is
//! compared with C's as a plain string. Where gen_store.c masks (the random serial, the
//! throttle rounded up to C's ladder, provenance instead of salts and nonces), this does the
//! same. See `golden/store/steps.tsv` for C's side.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pqhsm_token::Rv;
use pqhsm_token::store::PolicyAttr;
use pqhsm_token::token::{Meta, Platform, Role, Tmpl, Token};
use pqhsm_token::tpm::{Cli, Tpm};

use super::*;

/// One Rust step: its output, and the token file after it.
pub struct Done {
    pub step: usize,
    pub line: String,
    pub out: String,
    pub file: Option<Vec<u8>>,
}

pub struct Outcome {
    pub steps: Vec<Done>,
    /// Decrypted blob plaintext and public-section bytes at each `snap` that found them.
    pub pt: BTreeMap<usize, Vec<u8>>,
    pub public: BTreeMap<usize, Vec<u8>>,
}

struct Run {
    _dir: tempfile::TempDir,
    tokdir: PathBuf,
    ctl: PathBuf,
    path: PathBuf,
    device: PathBuf,
    rec: Arc<Recorder>,
    sealing: bool,
    toks: [Option<Token>; 2],
    ref_hdr: Vec<u8>,
    ref_blob: Option<Vec<u8>>,
    nosave: bool,
}

fn put32(f: &mut [u8], off: usize, v: u32) {
    f[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn get32(f: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(f[off..off + 4].try_into().unwrap())
}

/// Remaining throttle rounded up to the next rung of C's ladder (gen_store.c `ladder`).
pub fn ladder(ms: u64) -> u64 {
    if ms == 0 {
        return 0;
    }
    let mut d = 500;
    while d < ms && d < 60_000 {
        d = (d * 2).min(60_000);
    }
    d
}

fn prov(now: &[u8], r: &[u8]) -> &'static str {
    if now.iter().all(|&b| b == 0) {
        "zero"
    } else if now != r {
        "new"
    } else {
        "same"
    }
}

fn serial_fmt(s: &[u8]) -> bool {
    s.len() >= 21
        && s.starts_with(b"FHSM-")
        && s[5..21]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
        && s[21..].iter().all(|&b| b == 0)
}

fn attr_text(a: &PolicyAttr) -> String {
    format!("0x{:x}:{}:{}:{}", a.type_, a.kind, a.len, hex(&a.value))
}

fn tmpl_parse(s: &str) -> Vec<PolicyAttr> {
    if s == "empty" {
        return Vec::new();
    }
    s.split(',')
        .map(|e| {
            let f: Vec<&str> = e.split(':').collect();
            let mut a = PolicyAttr {
                type_: num(f[0]) as u32,
                kind: num(f[1]) as u8,
                len: num(f[2]) as u8,
                ..Default::default()
            };
            if let Some(v) = f.get(3) {
                for (i, b) in unhex(v).into_iter().take(48).enumerate() {
                    a.value[i] = b;
                }
            }
            a
        })
        .collect()
}

fn meta_of(n: u64) -> Meta {
    match n {
        0 => Meta::StartDate,
        1 => Meta::EndDate,
        _ => Meta::Application,
    }
}

fn tmpl_of(n: u64) -> Tmpl {
    match n {
        0 => Tmpl::Wrap,
        1 => Tmpl::Unwrap,
        _ => Tmpl::Derive,
    }
}

impl Run {
    fn platform(&self) -> Arc<Platform> {
        Arc::new(Platform {
            tpm: Arc::new(self.tpm()),
            sealing_required: self.sealing,
            audit: Box::new(Rec(self.rec.clone())),
        })
    }

    fn tpm(&self) -> Tpm {
        let c = self.ctl.display();
        let cmd = format!(
            "sh '{c}/pre.sh'; FHSM_TPM_FAKE_PCR=$(cat '{c}/pcr') FHSM_TPM_FAKE_FAIL=$(cat '{c}/fail') sh '{}'",
            tpm_stub().display()
        );
        Tpm::new(&self.device, Cli::Shell(cmd))
    }

    fn set_ctl(&self, name: &str, text: &str) {
        fs::write(self.ctl.join(name), text).unwrap();
    }

    fn set_ref_from_file(&mut self) {
        let f = fs::read(&self.path).unwrap_or_default();
        self.ref_hdr = vec![0; HDR];
        let n = f.len().min(HDR);
        self.ref_hdr[..n].copy_from_slice(&f[..n]);
        self.ref_blob = None;
        if f.len() > HDR + 4 {
            let ct = get32(&f, HDR) as u64;
            if HDR as u64 + 16 + ct + 16 <= f.len() as u64 {
                let len = 12 + ct as usize + 16;
                self.ref_blob = Some(f[HDR + 4..HDR + 4 + len].to_vec());
            }
        }
    }

    fn snap(
        &mut self,
        kv: &BTreeMap<String, String>,
        o: &mut String,
        pt: &mut Option<Vec<u8>>,
        public: &mut Option<Vec<u8>>,
    ) {
        let Ok(f) = fs::read(&self.path) else {
            o.push_str("\tsize=absent");
            return;
        };
        let n = f.len();
        o.push_str(&format!("\tsize={n}"));
        if n < HDR {
            return;
        }
        let r = &self.ref_hdr;
        let label_len = f[8..72].iter().position(|&b| b == 0).unwrap_or(64);
        o.push_str(&format!(
            "\tmagic={}\tver={}\tlabel={}",
            hex(&f[0..4]),
            get32(&f, 4),
            hex(&f[8..8 + label_len])
        ));
        o.push_str(&format!(
            "\tserial={}\tserial_fmt={}\titer={}",
            prov(&f[72..136], &r[72..136]),
            if serial_fmt(&f[72..136]) { "ok" } else { "bad" },
            get32(&f, 136)
        ));
        o.push_str(&format!(
            "\tsalt_so={}\tso_nonce={}\tso_ct={}",
            prov(&f[140..156], &r[140..156]),
            prov(&f[156..168], &r[156..168]),
            prov(&f[168..216], &r[168..216])
        ));
        o.push_str(&format!(
            "\tsalt_user={}\tuser_nonce={}\tuser_ct={}",
            prov(&f[216..232], &r[216..232]),
            prov(&f[232..244], &r[232..244]),
            prov(&f[244..292], &r[244..292])
        ));
        o.push_str(&format!(
            "\tuinit={}\tfso={}\tfuser={}\tthr={}",
            f[292],
            get32(&f, 293),
            get32(&f, 297),
            hex(&f[301..317])
        ));
        o.push_str(&format!(
            "\tsalts_differ={}",
            (f[140..156] != f[216..232]) as u8
        ));
        let mut blob: Option<(usize, usize)> = None; // (start of nonce, ct_len)
        let mut end = n;
        if n == HDR {
            o.push_str("\tblob=none");
        } else if n < HDR + 16 {
            o.push_str("\tblob=bad");
        } else {
            let ct = get32(&f, HDR) as u64;
            if ct == 0 || ct > BLOB_MAX || HDR as u64 + 16 + ct + 16 > n as u64 {
                o.push_str(&format!("\tblob=bad\tctlen={ct}"));
            } else {
                let ct = ct as usize;
                let b = &f[HDR + 4..HDR + 4 + 12 + ct + 16];
                let same = self.ref_blob.as_deref() == Some(b);
                let nonce = match &self.ref_blob {
                    Some(rb) => prov(&b[..12], &rb[..12.min(rb.len())]),
                    None => "new",
                };
                o.push_str(&format!(
                    "\tblob={}\tctlen={ct}\tnonce={nonce}",
                    if same { "same" } else { "new" }
                ));
                end = HDR + 16 + ct + 16;
                blob = Some((HDR + 4, ct));
            }
        }
        if blob.is_some() && end < n {
            *public = Some(f[end..].to_vec());
            o.push_str(&format!("\tpub=file:{}", n - end));
        } else if blob.is_some() {
            o.push_str("\tpub=none");
        }
        if let Some(rs) = kv.get("role") {
            let pin = pin_of(&kv["pin"]);
            match (unwrap_dek(&f, role_of(rs), &pin), blob) {
                (None, _) => o.push_str("\tpt=nodek"),
                (Some(_), None) => o.push_str("\tpt=none"),
                (Some(dek), Some((at, ct))) => {
                    let mut tag: [u8; 16] = f[at + 12 + ct..at + 12 + ct + 16].try_into().unwrap();
                    let (nonce, c, aad) =
                        (&f[at..at + 12], &f[at + 12..at + 12 + ct], serial_aad(&f));
                    let got = gcm(false, &dek, nonce, aad, c, &mut tag)
                        .map(|p| ("ok", p))
                        .or_else(|| {
                            gcm(false, &[0u8; 32], nonce, aad, c, &mut tag).map(|p| ("zero", p))
                        });
                    match got {
                        None => o.push_str("\tpt=fail"),
                        Some((how, p)) => {
                            o.push_str(&format!("\tpt={how}:{ct}"));
                            *pt = Some(p);
                        }
                    }
                }
            }
        }
        self.set_ref_from_file();
    }

    fn files(&self, o: &mut String) {
        let mut names: Vec<String> = fs::read_dir(&self.tokdir)
            .map(|d| {
                d.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.retain(|n| !n.starts_with('.'));
        names.sort();
        let list: Vec<String> = names
            .iter()
            .map(|n| {
                let m = fs::symlink_metadata(self.tokdir.join(n)).unwrap();
                format!(
                    "{n}{}:{:o}",
                    if m.is_dir() { "/" } else { "" },
                    m.mode() & 0o777
                )
            })
            .collect();
        o.push_str(&format!("\tfiles={}", list.join(",")));
    }

    fn dump(t: &Token, o: &mut String) {
        let r = t.object_find(None, None, 2048);
        let (hs, cnt) = r.clone().unwrap_or_default();
        o.push_str(&format!("\trv={}\tn={cnt}", rv_hex(rv_of(&r))));
        for h in hs {
            let (v, c, k) = t.object_get(h).unwrap_or_default();
            let f1 = t.object_get_flags(h).unwrap_or(0);
            let f2 = t.object_get_flags2(h).unwrap_or(0);
            let f3 = t.object_get_flags3(h).unwrap_or(0);
            let us = t.object_get_usage(h).unwrap_or(0);
            let tk = t.object_is_token(h).unwrap_or(false) as u8;
            o.push_str(&format!(
                "\n\tobj h={h} class={c} kt={k} flags=0x{f1:02x} flags2=0x{f2:02x} flags3=0x{f3:02x} usage=0x{us:02x} tok={tk} label={}",
                hex(&t.object_get_label(h).unwrap_or_default())
            ));
            o.push_str(&format!(
                " id={} value={}",
                hex(&t.object_get_id(h).unwrap_or_default()),
                hex(&v)
            ));
            for (w, name) in [
                (Meta::StartDate, "start"),
                (Meta::EndDate, "end"),
                (Meta::Application, "app"),
            ] {
                o.push_str(&format!(
                    " {name}={}",
                    hex(&t.object_get_meta(h, w).unwrap_or_default())
                ));
            }
            let c4 = t.object_policy_counts(h).unwrap_or([0; 4]);
            o.push_str(&format!(
                " counts={},{},{},{} mechs=",
                c4[0], c4[1], c4[2], c4[3]
            ));
            if let Ok(m) = t.object_get_allowed_mechs(h) {
                o.push_str(
                    &m.iter()
                        .map(|x| format!("0x{x:x}"))
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            for (w, name) in [
                (Tmpl::Wrap, "wrap"),
                (Tmpl::Unwrap, "unwrap"),
                (Tmpl::Derive, "derive"),
            ] {
                o.push_str(&format!(" {name}="));
                if let Ok(a) = t.object_get_tmpl(h, w) {
                    o.push_str(&a.iter().map(attr_text).collect::<Vec<_>>().join(","));
                }
            }
        }
    }

    fn token_op(t: &Token, op: &str, kv: &BTreeMap<String, String>, o: &mut String) -> bool {
        let h = kv.get("h").map_or(0, |v| num(v) as u32);
        let a = |k: &str| {
            kv.get(k)
                .map(String::as_str)
                .unwrap_or_else(|| panic!("`{op}` needs {k}="))
        };
        let rv = |o: &mut String, r: Rv| o.push_str(&format!("\trv={}", rv_hex(r)));
        // RV(): the rv, then the value only when it is OK.
        macro_rules! rv_then {
            ($r:expr, |$v:ident| $body:expr) => {{
                let r = $r;
                rv(o, rv_of(&r));
                if let Ok($v) = r {
                    o.push_str(&$body);
                }
            }};
        }
        match op {
            "login" | "verify" => {
                let (role, pin) = (role_of(a("role")), pin_of(a("pin")));
                let r = if op == "login" {
                    t.login(role, &pin)
                } else {
                    t.verify_pin(role, &pin)
                };
                rv(o, rv_of(&r));
            }
            "logout" => {
                t.logout();
                o.push_str("\t-");
            }
            "role" => o.push_str(&format!("\trole={}", t.current_role() as u8)),
            "set_pin" => rv(
                o,
                rv_of(&t.set_pin(role_of(a("role")), &pin_of(a("old")), &pin_of(a("new")))),
            ),
            "init_user_pin" => rv(o, rv_of(&t.init_user_pin(&pin_of(a("pin"))))),
            "reinit" => rv(
                o,
                rv_of(&t.reinit(&pin_of(a("so")), &bytes_of(a("label")).unwrap_or_default())),
            ),
            "info" => {
                let (l, s) = (t.label(), t.serial());
                o.push_str(&format!("\tlabel={}", hex(&l[..l.len().min(64)])));
                if l.len() > 64 {
                    if l[64..] == s[..] {
                        o.push_str("+overrun:serial");
                    } else {
                        o.push_str(&format!("+overrun:{}", hex(&l[64..])));
                    }
                }
                let sok = s.len() == 21 && serial_fmt(&[s.clone(), vec![0; 43]].concat());
                o.push_str(&format!(
                    "\tserial={}\tfso={}\tfuser={}\tuinit={}\tlso={}\tluser={}\ttso={}\ttuser={}\trole={}",
                    if sok { "ok" } else { "bad" },
                    t.failed_count(Role::So),
                    t.failed_count(Role::User),
                    t.user_initialized() as u8,
                    t.is_locked(Role::So) as u8,
                    t.is_locked(Role::User) as u8,
                    ladder(t.throttle_remaining_ms(Role::So)),
                    ladder(t.throttle_remaining_ms(Role::User)),
                    t.current_role() as u8
                ));
            }
            "add" => {
                let label = bytes_of(a("label"));
                let r = t.object_add(
                    num(a("class")) as u32,
                    num(a("kt")) as u32,
                    label.as_deref(),
                    &bytes_of(a("value")).unwrap_or_default(),
                    &bytes_of(a("id")).unwrap_or_default(),
                    num(a("flags")) as u8,
                );
                rv(o, rv_of(&r));
                if let Ok(h) = r {
                    o.push_str(&format!("\th={h}"));
                }
            }
            "get" => rv_then!(t.object_get(h), |v| format!(
                "\tclass={}\tkt={}\tvalue={}",
                v.1,
                v.2,
                hex(&v.0)
            )),
            "find" => {
                let cap = kv.get("cap").map_or(2048, |c| num(c) as usize);
                let class = kv.get("class").map(|c| num(c) as u32);
                let label = kv.get("label").and_then(|l| bytes_of(l));
                let r = t.object_find(class, label.as_deref(), cap);
                let (hs, n) = r.clone().unwrap_or_default();
                let list: Vec<String> = hs.iter().take(cap).map(|h| h.to_string()).collect();
                o.push_str(&format!(
                    "\trv={}\tn={n}\ths={}",
                    rv_hex(rv_of(&r)),
                    list.join(",")
                ));
            }
            "get_label" => rv_then!(t.object_get_label(h), |v| format!("\tv={}", hex(&v))),
            "get_id" => rv_then!(t.object_get_id(h), |v| format!("\tv={}", hex(&v))),
            "get_meta" => rv_then!(t.object_get_meta(h, meta_of(num(a("which")))), |v| format!(
                "\tv={}",
                hex(&v)
            )),
            "get_flags" => rv_then!(t.object_get_flags(h), |v| format!("\tv=0x{v:02x}")),
            "get_flags2" => rv_then!(t.object_get_flags2(h), |v| format!("\tv=0x{v:02x}")),
            "get_flags3" => rv_then!(t.object_get_flags3(h), |v| format!("\tv=0x{v:02x}")),
            "get_usage" => rv_then!(t.object_get_usage(h), |v| format!("\tv=0x{v:02x}")),
            "is_token" => rv_then!(t.object_is_token(h), |v| format!("\tv={}", v as u8)),
            "policy" => rv_then!(t.object_policy_counts(h), |c| format!(
                "\tcounts={},{},{},{}",
                c[0], c[1], c[2], c[3]
            )),
            "get_mechs" => rv_then!(t.object_get_allowed_mechs(h), |m| format!(
                "\tn={}\tv={}",
                m.len(),
                m.iter()
                    .map(|x| format!("0x{x:x}"))
                    .collect::<Vec<_>>()
                    .join(",")
            )),
            "get_tmpl" => rv_then!(t.object_get_tmpl(h, tmpl_of(num(a("which")))), |v| format!(
                "\tn={}\tv={}",
                v.len(),
                v.iter().map(attr_text).collect::<Vec<_>>().join(",")
            )),
            "mech_allowed" => rv(o, rv_of(&t.object_mech_allowed(h, num(a("mech")) as u32))),
            "set_label" => rv(
                o,
                rv_of(&t.object_set_label(h, &bytes_of(a("label")).unwrap_or_default())),
            ),
            "set_id" => rv(
                o,
                rv_of(&t.object_set_id(h, &bytes_of(a("id")).unwrap_or_default())),
            ),
            "set_flags" => rv(o, rv_of(&t.object_set_flags(h, num(a("v")) as u8))),
            "set_flags2" => rv(o, rv_of(&t.object_set_flags2(h, num(a("v")) as u8))),
            "set_flags3" => rv(o, rv_of(&t.object_set_flags3(h, num(a("v")) as u8))),
            "set_usage" => rv(o, rv_of(&t.object_set_usage(h, num(a("v")) as u8))),
            "set_meta" => {
                let (s, e, ap) = (bytes_of(a("start")), bytes_of(a("end")), bytes_of(a("app")));
                rv(
                    o,
                    rv_of(&t.object_set_meta(h, s.as_deref(), e.as_deref(), ap.as_deref())),
                );
            }
            "set_mechs" => {
                let l = a("list");
                let m: Vec<u32> = if l == "empty" {
                    Vec::new()
                } else {
                    l.split(',').map(|x| num(x) as u32).collect()
                };
                rv(o, rv_of(&t.object_set_allowed_mechs(h, &m)));
            }
            "set_tmpl" => rv(
                o,
                rv_of(&t.object_set_tmpl(h, tmpl_of(num(a("which"))), &tmpl_parse(a("e")))),
            ),
            "mark_session" => rv(o, rv_of(&t.object_mark_session(h, num(a("owner")) as u32))),
            "destroy" => rv(o, rv_of(&t.object_destroy(h))),
            "destroy_session" => rv(o, rv_of(&t.destroy_session_objects(num(a("owner")) as u32))),
            "dump" => Self::dump(t, o),
            _ => return false,
        }
        true
    }

    fn op(&mut self, line: &str, pt: &mut Option<Vec<u8>>, public: &mut Option<Vec<u8>>) -> String {
        let (op, kv) = args(line);
        let ti = usize::from(kv.get("t").map(String::as_str) == Some("B"));
        let a = |k: &str| {
            kv.get(k)
                .cloned()
                .unwrap_or_else(|| panic!("`{op}` needs {k}="))
        };
        let mut o = String::new();
        let dash = "\t-";
        match op.as_str() {
            "init" => {
                self.toks[ti] = None;
                let r = Token::init(
                    &self.path,
                    &pin_of(&a("so")),
                    &bytes_of(&a("label")).unwrap_or_default(),
                    self.platform(),
                );
                o.push_str(&format!("\trv={}", rv_hex(rv_of(&r))));
                self.toks[ti] = r.ok();
            }
            "load" => {
                self.toks[ti] = None;
                let r = Token::load(&self.path, self.platform());
                o.push_str(&format!("\trv={}", rv_hex(rv_of(&r))));
                self.toks[ti] = r.ok();
            }
            "close" => match self.toks[ti].take() {
                Some(t) => {
                    t.close();
                    o.push_str(dash);
                }
                None => o.push_str("\tnotoken"),
            },
            "snap" => self.snap(&kv, &mut o, pt, public),
            "files" => self.files(&mut o),
            "poke" => {
                let mut f = fs::read(&self.path).unwrap();
                let off = num(&a("off")) as usize;
                if let Some(v) = kv.get("u32") {
                    put32(&mut f, off, num(v) as u32);
                } else if let Some(v) = kv.get("u8") {
                    f[off] = num(v) as u8;
                } else {
                    let b = unhex(&a("hex"));
                    f[off..off + b.len()].copy_from_slice(&b);
                }
                fs::write(&self.path, f).unwrap();
                o.push_str(dash);
            }
            "truncate" => {
                fs::OpenOptions::new()
                    .write(true)
                    .open(&self.path)
                    .unwrap()
                    .set_len(num(&a("len")))
                    .unwrap();
                o.push_str(dash);
            }
            "append" => {
                let mut f = fs::read(&self.path).unwrap();
                f.extend(bytes_of(&a("b")).unwrap_or_default());
                fs::write(&self.path, f).unwrap();
                o.push_str(dash);
            }
            "pubsec" => {
                let mut f = fs::read(&self.path).unwrap();
                let end = if f.len() < HDR + 4 {
                    f.len()
                } else {
                    HDR + 16 + get32(&f, HDR) as usize + 16
                };
                if kv.contains_key("drop") {
                    f.truncate(end);
                } else if let Some(s) = kv.get("set") {
                    let b = read_golden(&format!("in/{s}.bin"));
                    f.truncate(end);
                    f.extend(pqhsm_token::store::PUB_MAGIC.to_le_bytes());
                    f.extend((b.len() as u32).to_le_bytes());
                    f.extend(b);
                } else if let Some(m) = kv.get("magic") {
                    put32(&mut f, end, num(m) as u32);
                } else if let Some(b) = kv.get("byte") {
                    f.push(num(b) as u8);
                }
                fs::write(&self.path, f).unwrap();
                o.push_str(dash);
            }
            "reblob" => {
                let f = fs::read(&self.path).unwrap();
                let pt_in = read_golden(&format!("in/{}.bin", a("pt")));
                let Some(dek) = unwrap_dek(&f, role_of(&a("role")), &pin_of(&a("pin"))) else {
                    o.push_str("\terr");
                    return o;
                };
                let mut nonce = [0u8; 12];
                openssl::rand::rand_bytes(&mut nonce).unwrap();
                let mut tag = [0u8; 16];
                let ct = gcm(true, &dek, &nonce, serial_aad(&f), &pt_in, &mut tag).unwrap();
                if kv.get("tag").map(String::as_str) == Some("bad") {
                    tag[0] ^= 1;
                }
                let mut img = f[..HDR].to_vec();
                img.extend((pt_in.len() as u32).to_le_bytes());
                img.extend(nonce);
                img.extend(ct);
                img.extend(tag);
                if a("pub") != "none" {
                    let b = read_golden(&format!("in/{}.bin", a("pub")));
                    img.extend(pqhsm_token::store::PUB_MAGIC.to_le_bytes());
                    img.extend((b.len() as u32).to_le_bytes());
                    img.extend(b);
                }
                fs::write(&self.path, img).unwrap();
                o.push_str(dash);
            }
            "rodir" | "rwdir" => {
                let mode = if op == "rodir" { 0o555 } else { 0o755 };
                fs::set_permissions(&self.tokdir, fs::Permissions::from_mode(mode)).unwrap();
                o.push_str(dash);
            }
            "tokdir" => {
                fs::DirBuilder::new()
                    .mode(0o755)
                    .create(&self.path)
                    .unwrap();
                o.push_str(dash);
            }
            "tpm" => {
                self.sealing = num(&a("seal")) != 0;
                o.push_str(dash);
            }
            "pcr" => {
                self.set_ctl("pcr", &a("v"));
                o.push_str(dash);
            }
            "tpmfail" => {
                let v = a("v");
                self.set_ctl("fail", if v == "-" { "" } else { &v });
                o.push_str(dash);
            }
            "tpmprefix" => {
                let pre = format!("chmod 0555 '{}'\n", self.tokdir.display());
                self.set_ctl("pre.sh", if a("v") == "rodir" { &pre } else { "" });
                o.push_str(dash);
            }
            "reseal_tpm" => {
                let d: [u8; 32] = bytes_of(&a("dek")).unwrap().try_into().unwrap();
                let r = self.tpm().seal_companion(&self.path, &d);
                o.push_str(&format!("\trv={}", rv_hex(rv_of(&r))));
            }
            "audit" => {
                self.rec.set_fail(true);
                o.push_str(dash);
            }
            "nosave" => {
                self.nosave = true;
                o.push_str(dash);
            }
            _ => match &self.toks[ti] {
                None => o.push_str("\tnotoken"),
                Some(t) => {
                    if !Self::token_op(t, &op, &kv, &mut o) {
                        panic!("unknown op `{op}`");
                    }
                }
            },
        }
        o
    }
}

/// Run scenario `name` of the golden copy of store_scenarios.txt against the Rust token.
pub fn run(name: &str) -> Outcome {
    let text = String::from_utf8(read_golden("store_scenarios.txt")).unwrap();
    let (_, from, lines) = script(&text)
        .into_iter()
        .find(|s| s.0 == name)
        .unwrap_or_else(|| panic!("no scenario {name}"));
    let dir = tempfile::tempdir().unwrap();
    let (tokdir, ctl) = (dir.path().join("tok"), dir.path().join("ctl"));
    fs::create_dir(&tokdir).unwrap();
    fs::create_dir(&ctl).unwrap();
    let device = dir.path().join("fake_tpmrm0");
    fs::write(&device, b"").unwrap();
    let path = tokdir.join("slot0.tok");
    if let Some(from) = &from {
        let src = match from.split_once(':') {
            Some(("tok", s)) => store_golden(&format!("tok/{s}.tok")),
            Some(("corpus", s)) => corpus(s),
            _ => panic!("bad from= {from}"),
        };
        copy_0600(&src, &path);
        let tpm = PathBuf::from(format!("{}.tpm", src.display()));
        if tpm.exists() {
            copy_0600(&tpm, &PathBuf::from(format!("{}.tpm", path.display())));
        }
    }
    let mut r = Run {
        _dir: dir,
        tokdir,
        ctl,
        path,
        device,
        rec: Arc::new(Recorder::default()),
        sealing: false,
        toks: [None, None],
        ref_hdr: Vec::new(),
        ref_blob: None,
        nosave: false,
    };
    r.set_ctl("pcr", "golden-pcr");
    r.set_ctl("fail", "");
    r.set_ctl("pre.sh", "");
    r.set_ref_from_file();
    let mut out = Outcome {
        steps: Vec::new(),
        pt: BTreeMap::new(),
        public: BTreeMap::new(),
    };
    for (i, line) in lines.iter().enumerate() {
        let (mut pt, mut public) = (None, None);
        let mut o = r.op(line, &mut pt, &mut public);
        for l in r.rec.take() {
            o.push_str(&format!("\taudit={l}"));
        }
        if let Some(p) = pt {
            out.pt.insert(i + 1, p);
        }
        if let Some(p) = public {
            out.public.insert(i + 1, p);
        }
        out.steps.push(Done {
            step: i + 1,
            line: line.clone(),
            out: o,
            file: file_or_none(&r.path),
        });
    }
    // Let the directory be removed even if a scenario left it read-only.
    let _ = fs::set_permissions(&r.tokdir, fs::Permissions::from_mode(0o755));
    out
}

fn copy_0600(from: &Path, to: &Path) {
    fs::copy(from, to).unwrap_or_else(|e| panic!("{}: {e}", from.display()));
    fs::set_permissions(to, fs::Permissions::from_mode(0o600)).unwrap();
}

/// An approved divergence (or plan amendment) at one step: C's output must match `c` (pinned
/// first), Rust's must match `rust` (see [`matches`]; or, written `C~OLD~>NEW`, must be C's
/// output with OLD replaced by NEW, exactly), and with `same_file_as` > 0 the token
/// file after this step must be byte-identical to the one after that step.
#[derive(Clone, Copy, Debug)]
pub struct Div {
    pub scenario: &'static str,
    pub step: usize,
    pub div: &'static str,
    pub c: &'static str,
    pub rust: &'static str,
    pub same_file_as: usize,
}

/// Compare a Rust run with C's steps, step by step. Returns every mismatch.
pub fn compare(name: &str, rust: &Outcome, divs: &[Div]) -> Vec<String> {
    let c = steps_of(name);
    let mut bad = Vec::new();
    if c.len() != rust.steps.len() {
        bad.push(format!(
            "{name}: C has {} steps, the script {}",
            c.len(),
            rust.steps.len()
        ));
    }
    for (cs, rs) in c.iter().zip(&rust.steps) {
        let at = format!("{name} step {} `{}`", cs.step, cs.line);
        if cs.line != rs.line {
            bad.push(format!("{at}: golden is stale (script says `{}`)", rs.line));
            continue;
        }
        if let Some(d) = divs
            .iter()
            .find(|d| d.scenario == name && d.step == cs.step)
        {
            if !matches(d.c, &cs.out) {
                bad.push(format!("{at} [{}]: C's golden\n    {:?}\n  no longer matches the pinned C value\n    {:?}", d.div, cs.out, d.c));
            }
            let rust_ok = match d.rust.strip_prefix("C~").and_then(|r| r.split_once("~>")) {
                Some((old, new)) => rs.out == cs.out.replace(old, new),
                None => matches(d.rust, &rs.out),
            };
            if !rust_ok {
                bad.push(format!(
                    "{at} [{}]: Rust gave\n    {:?}\n  expected\n    {:?}",
                    d.div, rs.out, d.rust
                ));
            }
            if d.same_file_as > 0 && rust.steps[d.same_file_as - 1].file != rs.file {
                bad.push(format!(
                    "{at} [{}]: the token file changed since step {}",
                    d.div, d.same_file_as
                ));
            }
            continue;
        }
        if cs.out != rs.out {
            bad.push(format!(
                "{at}:\n    C    {:?}\n    Rust {:?}",
                cs.out, rs.out
            ));
            continue;
        }
        if cs.out.contains("\tpt=ok:") || cs.out.contains("\tpt=zero:") {
            let want = read_golden(&format!("pt/{name}.{}.bin", cs.step));
            if rust.pt.get(&cs.step) != Some(&want) {
                bad.push(format!(
                    "{at}: the decrypted blob differs from C's pt/{name}.{}.bin",
                    cs.step
                ));
            }
        }
        if cs.out.contains("\tpub=file:") {
            let want = read_golden(&format!("pub/{name}.{}.bin", cs.step));
            if rust.public.get(&cs.step) != Some(&want) {
                bad.push(format!(
                    "{at}: the public section differs from C's pub/{name}.{}.bin",
                    cs.step
                ));
            }
        }
    }
    bad
}

/// Run and compare; panic with every mismatch.
pub fn check(name: &str, divs: &[Div]) {
    let out = run(name);
    let bad = compare(name, &out, divs);
    assert!(
        bad.is_empty(),
        "{} mismatch(es):\n{}",
        bad.len(),
        bad.join("\n")
    );
}
