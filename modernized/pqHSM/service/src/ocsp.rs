//! The OCSP responder on the public listener (`service/fhsm_service.c:858-940`, `:1816-1939`):
//! the revocation database re-read when the file changes, and each POST answered by
//! `pqhsm_pki::revocation::answer`, signed with the composite key `--ocsp-label` names
//! (RULE-023, RULE-024, RULE-054). A serial of this CA not in the database is "good", and so
//! is every serial while the file is missing (Q20, decided: kept as C, as RFC 6960 allows a
//! CA that keeps no issuance record).

use std::ffi::c_int;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::sync::{PoisonError, RwLock};

use pqhsm_pki::ffi::x509::{Signer, ocsp_for};
use pqhsm_pki::revocation::{self as rev, Db, Query, Tbs};
use pqhsm_pkiops::keys::CKM_COMPOSITE;
use pqhsm_pkiops::ops::{self, CKO_PRIVATE_KEY};

use crate::http::{respond, respond_bytes};
use crate::svc;

// RFC 6960 4.2.1 OCSPResponseStatus.
const MALFORMED: i32 = 1;
const INTERNAL: i32 = 2;
const TRY_LATER: i32 = 3;

/// The database in force, and the file's stamp (inode, mtime to the nanosecond, size; DIV-082)
/// when it was last read.
#[derive(Default)]
struct Rev {
    db: Db,
    ok: bool,
    stamp: [i64; 4],
}

pub struct Ocsp {
    pub label: Vec<u8>,
    path: PathBuf,
    days: i32,
    /// `--responder-cert`, or none: the CA signs its own responses.
    responder: Option<Vec<u8>>,
    rev: RwLock<Rev>,
}

impl Ocsp {
    pub fn new(label: Vec<u8>, path: PathBuf, days: i32, responder: Option<Vec<u8>>) -> Ocsp {
        Ocsp {
            label,
            path,
            days,
            responder,
            rev: RwLock::new(Rev::default()),
        }
    }

    /// `rev_db_refresh`: whether a usable database is in force. Re-read only when the file's
    /// stamp changed (C: whole-second mtime and size; DIV-082); a missing file is an empty database; a file that does not parse
    /// is reported once and the previous database kept, if there was one.
    pub fn refresh(&self) -> bool {
        let stamp = match std::fs::metadata(&self.path) {
            Ok(m) => [m.ino() as i64, m.mtime(), m.mtime_nsec(), m.size() as i64],
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => [0; 4],
            Err(_) => return false,
        };
        {
            let r = self.rev.read().unwrap_or_else(PoisonError::into_inner);
            if r.ok && r.stamp == stamp {
                return true;
            }
        }
        let loaded = Db::load(&self.path);
        if let Err(e) = &loaded {
            // before the lock, as C: a stalled stderr must not hold every reader
            errw!("pqhsm-service: {}", e.msg);
        }
        let mut r = self.rev.write().unwrap_or_else(PoisonError::into_inner);
        match loaded {
            Ok(db) => {
                *r = Rev {
                    db,
                    ok: true,
                    stamp,
                }
            }
            // not the same broken file again on every request
            Err(_) => r.stamp = stamp,
        }
        r.ok
    }

    /// `do_ocsp`: one request body, answered with an OCSPResponse (a status-only one when
    /// there is nothing to sign).
    pub fn answer(&self, fd: c_int, body: &[u8], ca: &[u8]) {
        if body.is_empty() {
            return status(fd, MALFORMED);
        }
        if !self.refresh() {
            // nothing about the request is wrong: ask again later
            return status(fd, TRY_LATER);
        }
        let s = svc();
        let sess = s.pool.acquire();
        let Some(key) = ops::find_first(sess, CKO_PRIVATE_KEY, &self.label) else {
            s.pool.release(sess);
            return status(fd, INTERNAL);
        };
        let mut encode = |t: &Tbs<'_>| {
            let mut sign = |tbs: &[u8], sig: &mut [u8]| -> Result<usize, u32> {
                let out = ops::sign_once(sess, CKM_COMPOSITE, key, tbs, sig.len());
                let out = out.map_err(|_| 6u32)?; // FHSM_RV_FUNCTION_FAILED, as C's callback
                sig[..out.len()].copy_from_slice(&out);
                Ok(out.len())
            };
            let algid = &pqhsm_pki::x509::ALGID_COMPOSITE[..];
            ocsp_for(
                &mut Signer {
                    algid,
                    sign: &mut sign,
                },
                t,
            )
        };
        let answered = {
            // held across the signature, so a re-read cannot free the database under it
            let r = self.rev.read().unwrap_or_else(PoisonError::into_inner);
            let q = Query {
                req: body,
                ca,
                responder: self.responder.as_deref().unwrap_or(ca),
                db: &r.db,
                days: self.days,
                label: None,
                // SAFETY: time(NULL)
                now: unsafe { libc::time(null_mut()) },
            };
            rev::answer(&q, &mut encode)
        };
        s.pool.release(sess);
        match answered {
            Ok((der, _)) => respond_bytes(fd, "application/ocsp-response", "", &der),
            // a request that does not parse is the caller's; anything else is ours
            Err(e) if e.code == rev::EPARSE => status(fd, MALFORMED),
            Err(_) => status(fd, INTERNAL),
        }
    }
}

/// `respond_ocsp` with no body: a status-only OCSPResponse.
fn status(fd: c_int, st: i32) {
    match rev::status_response(st) {
        Some(der) => respond_bytes(fd, "application/ocsp-response", "", &der),
        None => respond(fd, 500, "internal error\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_database_is_reread_on_change_and_a_broken_one_keeps_the_last_good() {
        let d = std::env::temp_dir().join(format!("pqhsm-ocsp-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("rev.db");
        let has = |o: &Ocsp, serial: u8| o.rev.read().unwrap().db.find(&[serial]).is_some();
        let o = Ocsp::new(b"ca".to_vec(), p.clone(), 7, None);
        assert!(o.refresh() && !has(&o, 0x0A), "missing: an empty database");
        std::fs::write(&p, "0A 20260101000000Z keyCompromise\n").unwrap();
        assert!(o.refresh() && has(&o, 0x0A), "created: read");
        std::fs::write(
            &p,
            "0A 20260101000000Z keyCompromise\n0B 20260102000000Z -\n",
        )
        .unwrap();
        assert!(o.refresh() && has(&o, 0x0B), "changed: read again");
        std::fs::write(&p, "garbage\n").unwrap();
        assert!(o.refresh(), "a broken file keeps the last good database");
        assert!(has(&o, 0x0B));
        // DIV-082: a fix of the same size within the same second is still read
        let put = |text: &str| {
            std::fs::write(d.join("t"), text).unwrap();
            std::fs::rename(d.join("t"), &p).unwrap();
        };
        put("xxxxxxxxxxxxxxxxxxxx\n");
        assert!(o.refresh() && !has(&o, 0x0C));
        put("0C 20260103000000Z -\n");
        assert!(o.refresh() && has(&o, 0x0C), "the fix, same size, read");
        put("garbage\n");
        let first = Ocsp::new(b"ca".to_vec(), p.clone(), 7, None);
        assert!(
            !first.refresh(),
            "with none before it, a broken file is no database"
        );
        std::fs::write(&p, "# fixed\n").unwrap();
        assert!(first.refresh());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
