//! One request on each listener (`service/fhsm_service.c:1352-1745`, `:1941-2035`): the peer
//! (RULE-067), then the request, the identity, the budget and the fairness cap (RULE-068),
//! then the route: signing and verifying under the policy (RULE-066). Every refusal is
//! audited and answered "refused" once; an answer whose record cannot be written is not
//! given (DIV-001).

use std::ffi::c_int;

use pqhsm_pkiops::keys::CKM_COMPOSITE;
use pqhsm_pkiops::ops::{self, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY};

use crate::audit::{self, EV_IDENTITY_RESUMED, EV_REQUEST_ACCEPTED, EV_REQUEST_REFUSED};
use crate::http::{self, OK, Request, Verdict, refuse, respond, respond_with};
use crate::state::Note;
use crate::svc;

/// The peer's uid through SO_PEERCRED, `None` if the kernel will not say.
fn peer_uid(fd: c_int) -> Option<u32> {
    let mut cr = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cr and len are writable and sized for SO_PEERCRED.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cr).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some(cr.uid)
}

/// `serve`: the private listener.
pub fn serve(fd: c_int) {
    let s = svc();
    let mut r = Request::default();
    let mut v = match peer_uid(fd) {
        None => refuse(403, "peercred_unavailable"),
        Some(uid) if uid != s.proxy_uid => refuse(403, "peer_not_proxy"),
        Some(_) => http::read_request(fd, &mut r),
    };
    // The actor only once an identity is established: a refusal before it has a blank one.
    let subject = r.subject.clone().unwrap_or_default();
    if v == OK {
        if r.subject_repeated {
            v = refuse(400, "subject_repeated");
        } else if r.subject.is_none() {
            v = refuse(403, "no_identity");
        } else {
            audit::set_actor(Some(&subject));
        }
    }
    let mut retry_after = 0;
    if v == OK {
        retry_after = s.budget.retry_after(&subject);
        if retry_after > 0 {
            v = refuse(429, "refusal_budget");
        }
    }
    let mut note = Note::default();
    let mut counted = false;
    if v == OK {
        match s.idents.enter(&subject, &mut note) {
            Ok(()) => counted = true,
            Err(e) => v = e,
        }
    }
    if note.log_resume {
        audit::event(
            EV_IDENTITY_RESUMED,
            -1,
            -1,
            audit::ROLE_NONE,
            audit::RV_OK,
            &[
                ("suppressed", note.suppressed.to_string().as_bytes()),
                ("window_s", note.window_s.to_string().as_bytes()),
            ],
        );
    }
    if v == OK {
        v = route(fd, &r, &subject);
    }
    // An authorisation refusal, and only that, is what the budget counts.
    if v.reason == Some("not_authorised")
        && let Some((n, delay)) = s.budget.charge(&subject)
    {
        audit::event(
            audit::EV_IDENTITY_LIMITED,
            -1,
            -1,
            audit::ROLE_NONE,
            audit::RV_FUNCTION_FAILED,
            &[
                ("refusals", n.to_string().as_bytes()),
                ("delay_s", delay.to_string().as_bytes()),
            ],
        );
    }
    if v != OK {
        refused(fd, &r, v, retry_after, &note);
    }
    if counted {
        s.idents.leave(&subject, v == OK);
    }
    audit::set_actor(None);
}

/// The refusal for an answer whose record could not be written (DIV-001).
const AUDIT_FAILED: Verdict = refuse(500, "audit_failed");

/// The private routes. `OK` means the route answered.
fn route(fd: c_int, r: &Request, subject: &[u8]) -> Verdict {
    let accepted = |slot: c_int, session: c_int, role: c_int, route: &[u8]| {
        audit::event(
            EV_REQUEST_ACCEPTED,
            slot,
            session,
            role,
            audit::RV_OK,
            &[("route", route)],
        )
    };
    if r.is(b"GET", b"/health") {
        if !accepted(-1, -1, audit::ROLE_NONE, b"/health") {
            return AUDIT_FAILED;
        }
        respond(fd, 200, "ok\n");
        return OK;
    }
    if r.is(b"GET", b"/token") {
        // The one read-only route through the pool: the token's public description.
        let s = svc();
        let sess = s.pool.acquire();
        let ti = pqhsm_pkiops::ops::token_info(s.pool.slot);
        s.pool.release(sess);
        let Ok(ti) = ti else {
            return refuse(503, "token_unavailable");
        };
        let text = pqhsm_pkiops::ops::text;
        let body = [
            b"label=",
            text(&ti.label),
            b"\nserial=",
            text(&ti.serial),
            b"\n",
        ]
        .concat();
        if !accepted(
            s.pool.slot.0 as c_int,
            sess.0 as c_int,
            audit::ROLE_USER,
            b"/token",
        ) {
            return AUDIT_FAILED;
        }
        respond(fd, 200, &body);
        return OK;
    }
    if r.is(b"POST", b"/sign") {
        return sign(fd, r, subject);
    }
    if r.is(b"POST", b"/verify") {
        return verify(fd, r, subject);
    }
    match &r.target[..] {
        b"/sign" | b"/verify" => refuse(405, "wrong_method"),
        b"/certificates" | b"/ocsp" => {
            respond_with(
                fd,
                404,
                "not here; see the public listener\n",
                "Link: </certificates>; rel=\"alternate\"\r\n",
            );
            OK
        }
        _ => refuse(404, "unknown_route"),
    }
}

/// The key the policy lets `subject` use, of class `cls`, in a pooled session: `Err` is
/// 403 not_authorised whether the rule or the key is missing (C looks the key up either way).
fn permitted_key(
    subject: &[u8],
    label: &[u8],
    cls: std::ffi::c_ulong,
) -> Result<(ops::Session, ops::ObjHandle), Verdict> {
    let s = svc();
    let sess = s.pool.acquire();
    let permitted = s.policy.permits(subject, label);
    match ops::find_first(sess, cls, label) {
        Some(k) if permitted => Ok((sess, k)),
        _ => {
            s.pool.release(sess);
            Err(refuse(403, "not_authorised"))
        }
    }
}

/// The EV_SIGN or EV_VERIFY record of `key` in `sess`.
fn record(ev: c_int, sess: ops::Session, rv: u32, params: &[(&str, &[u8])]) -> bool {
    let slot = svc().pool.slot.0 as c_int;
    audit::event(ev, slot, sess.0 as c_int, audit::ROLE_USER, rv, params)
}

/// `do_sign`: the body signed with the composite key labelled X-FHSM-Key.
fn sign(fd: c_int, r: &Request, subject: &[u8]) -> Verdict {
    let Some(key) = r.key.as_deref() else {
        return refuse(400, "no_key_header");
    };
    if r.key_repeated {
        return refuse(400, "key_repeated");
    }
    if r.body.is_empty() {
        return refuse(400, "empty_body");
    }
    let (sess, k) = match permitted_key(subject, key, CKO_PRIVATE_KEY) {
        Ok(found) => found,
        Err(v) => return v,
    };
    // C's 8192-byte buffer, no size query: a longer signature is a failure
    let sig = ops::sign_once(sess, CKM_COMPOSITE, k, &r.body, 8192);
    svc().pool.release(sess);
    let Ok(sig) = sig else {
        record(
            audit::EV_SIGN,
            sess,
            audit::RV_FUNCTION_FAILED,
            &[("key", key)],
        );
        return refuse(500, "sign_failed");
    };
    if !record(audit::EV_SIGN, sess, audit::RV_OK, &[("key", key)]) {
        return AUDIT_FAILED;
    }
    http::respond_bytes(fd, "application/octet-stream", "", &sig);
    OK
}

/// `do_verify`: the body is the signature (X-FHSM-Signature-Length bytes), then the message.
fn verify(fd: c_int, r: &Request, subject: &[u8]) -> Verdict {
    let Some(key) = r.key.as_deref() else {
        return refuse(400, "no_key_header");
    };
    if r.key_repeated {
        return refuse(400, "key_repeated");
    }
    let Some(siglen) = r.siglen else {
        return refuse(400, "no_signature_length");
    };
    if r.siglen_repeated {
        return refuse(400, "signature_length_repeated");
    }
    if r.body.is_empty() {
        return refuse(400, "empty_body");
    }
    if siglen >= r.body.len() {
        return refuse(400, "signature_length_covers_body");
    }
    let (sess, k) = match permitted_key(subject, key, CKO_PUBLIC_KEY) {
        Ok(found) => found,
        Err(v) => return v,
    };
    let (sig, msg) = r.body.split_at(siglen);
    let rv = ops::verify_once(sess, CKM_COMPOSITE, k, msg, sig);
    svc().pool.release(sess);
    // CKR_SIGNATURE_INVALID is an answer, not a failure of the request. The whole CK_ULONG is
    // compared: cut to 32 bits, 0x1_0000_0000 would read as valid.
    let valid = rv == 0;
    if !valid && rv != std::ffi::c_ulong::from(audit::RV_SIGNATURE_INVALID) {
        record(
            audit::EV_VERIFY,
            sess,
            audit::RV_FUNCTION_FAILED,
            &[("key", key)],
        );
        return refuse(500, "verify_failed");
    }
    let (result, rv): (&[u8], u32) = if valid {
        (b"valid", audit::RV_OK)
    } else {
        (b"invalid", audit::RV_SIGNATURE_INVALID)
    };
    if !record(
        audit::EV_VERIFY,
        sess,
        rv,
        &[("key", key), ("result", result)],
    ) {
        return AUDIT_FAILED;
    }
    let (status, text) = if valid {
        (200, "valid\n")
    } else {
        (422, "invalid\n")
    };
    respond(fd, status, text);
    OK
}

/// The refusal: audited unless it is inside a throttled burst, then answered, with
/// Retry-After on a 429 (the budget's interval, or one second from the fairness cap).
fn refused(fd: c_int, r: &Request, v: Verdict, retry_after: i64, note: &Note) {
    if v.status != 429 || note.log_refusal {
        let route = if r.target.is_empty() {
            &b"-"[..]
        } else {
            &r.target
        };
        audit::event(
            EV_REQUEST_REFUSED,
            -1,
            -1,
            audit::ROLE_NONE,
            audit::RV_FUNCTION_FAILED,
            &[
                ("reason", v.reason.unwrap_or_default().as_bytes()),
                ("route", route),
            ],
        );
    }
    let extra = if v.status == 429 {
        format!(
            "Retry-After: {}\r\n",
            if retry_after > 0 { retry_after } else { 1 }
        )
    } else {
        String::new()
    };
    respond_with(fd, v.status, "refused\n", &extra);
}

/// `serve_public`: no identity, no policy, no budget, no audit line per request.
pub fn serve_public(fd: c_int) {
    let s = svc();
    if peer_uid(fd) != Some(s.proxy_uid) {
        respond(fd, 403, "refused\n");
        return;
    }
    let mut r = Request::default();
    let v = http::read_request(fd, &mut r);
    if v != OK {
        respond(fd, v.status, "refused\n");
    } else if r.is(b"GET", b"/health") {
        respond(fd, 200, "ok\n");
    } else if r.is(b"GET", b"/certificates") {
        if s.ca_cert.is_empty() {
            respond(fd, 404, "no certificate configured\n");
        } else {
            let cc = "Cache-Control: public, max-age=86400\r\n";
            http::respond_bytes(fd, "application/pkix-cert", cc, &s.ca_cert);
        }
    } else if r.target == b"/ocsp" {
        let Some(o) = &s.ocsp else {
            respond(fd, 404, "no responder configured\n");
            return;
        };
        if r.method != b"POST" {
            respond_with(
                fd,
                405,
                "POST only; RFC 6960 A.1 GET is not served\n",
                "Allow: POST\r\n",
            );
        } else {
            o.answer(fd, &r.body, &s.ca_cert);
        }
    } else {
        respond(fd, 404, "refused\n");
    }
}
