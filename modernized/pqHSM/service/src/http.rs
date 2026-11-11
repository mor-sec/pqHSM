//! The request reader and the response writer (`service/fhsm_service.c:955-1335`, RULE-068's
//! limits): one request per connection, read to CRLFCRLF within 8 KiB and then to exactly
//! Content-Length, every field bounded, answered once with `Connection: close`.

use std::ffi::c_int;
use std::time::{Duration, Instant};

pub const MAX_HEADER_BYTES: usize = 8192;
const MAX_REQUEST_LINE: usize = 1024;
const MAX_HEADERS: usize = 32;
const MAX_TARGET: usize = 256;
pub const MAX_BODY: usize = 65536;
/// CKA_LABEL is 64 in the token store; a key label is shorter.
pub const MAX_KEY_LABEL: usize = 64;
/// `FHSM_AUDIT_ACTOR_MAX`: a subject is shorter.
pub const ACTOR_MAX: usize = 128;
pub const FIRST_BYTE_DEADLINE: Duration = Duration::from_millis(1000);
pub const REQUEST_DEADLINE: Duration = Duration::from_millis(10000);

/// A refusal: the status to send and the audit token. `reason: None` is a request to serve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub status: u16,
    pub reason: Option<&'static str>,
}

pub const OK: Verdict = Verdict {
    status: 200,
    reason: None,
};

pub const fn refuse(status: u16, reason: &'static str) -> Verdict {
    Verdict {
        status,
        reason: Some(reason),
    }
}

/// What the reader kept of a request.
#[derive(Default, Debug)]
pub struct Request {
    pub method: Vec<u8>,
    pub target: Vec<u8>,
    pub subject: Option<Vec<u8>>,
    pub subject_repeated: bool,
    pub key: Option<Vec<u8>>,
    pub key_repeated: bool,
    pub siglen: Option<usize>,
    pub siglen_repeated: bool,
    pub body: Vec<u8>,
}

impl Request {
    pub fn is(&self, method: &[u8], target: &[u8]) -> bool {
        self.method == method && self.target == target
    }
}

/// 1 readable, 0 the deadline passed, -1 the connection failed (`wait_readable`).
fn wait_readable(fd: c_int, deadline: Instant) -> i32 {
    loop {
        let ms = deadline
            .saturating_duration_since(Instant::now())
            .as_millis();
        if ms == 0 {
            return 0;
        }
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one pollfd.
        let n = unsafe { libc::poll(&mut p, 1, ms.min(i32::MAX as u128) as c_int) };
        if n > 0 {
            return 1;
        }
        if n == 0 {
            return 0;
        }
        if errno() == libc::EINTR {
            continue;
        }
        return -1;
    }
}

pub fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// read(2) into `buf`: bytes read, 0 at the end, -1 on error (EINTR included, as C's loop
/// tells it apart).
fn read_fd(fd: c_int, buf: &mut [u8]) -> isize {
    // SAFETY: buf is writable for its length.
    unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) }
}

/// C's strings end at a NUL: what `strstr` and `strlen` see of `b`.
fn c_str(b: &[u8]) -> &[u8] {
    b.split(|&c| c == 0).next().unwrap_or_default()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// `strtol(v, &tail, 10)` with errno, as the signature-length header is read: the value, or
/// `None` if it overflowed or anything follows the number. `v` is non-empty and NUL-free.
fn strtol_whole(v: &[u8]) -> Option<i64> {
    let (n, end, overflow) = pqhsm_pkiops::strtol(v);
    (!overflow && end == v.len()).then_some(n)
}

/// `read_request`: the request on `fd`, or the refusal.
pub fn read_request(fd: c_int, r: &mut Request) -> Verdict {
    let start = Instant::now();
    let deadline = start + REQUEST_DEADLINE;
    let first = start + FIRST_BYTE_DEADLINE;
    let mut had_a_byte = false;
    let mut buf = vec![0u8; MAX_HEADER_BYTES];
    let mut used = 0usize;
    let mut end = None;
    while used < MAX_HEADER_BYTES {
        match wait_readable(fd, if had_a_byte { deadline } else { first }) {
            0 => return refuse(408, "request_timeout"),
            w if w < 0 => return refuse(400, "read_failed"),
            _ => {}
        }
        had_a_byte = true;
        let n = read_fd(fd, &mut buf[used..]);
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return refuse(400, "read_failed");
        }
        if n == 0 {
            return refuse(400, "closed_early");
        }
        used += n as usize;
        end = find(c_str(&buf[..used]), b"\r\n\r\n");
        if end.is_some() {
            break;
        }
    }
    let Some(end) = end else {
        return refuse(400, "headers_too_large");
    };
    let text = &buf[..end + 2]; // through the last header's CRLF

    // --- the request line
    let Some(eol) = find(text, b"\r\n") else {
        return refuse(400, "request_line");
    };
    if eol > MAX_REQUEST_LINE {
        return refuse(400, "request_line");
    }
    let line = &text[..eol];
    let Some(sp1) = line.iter().position(|&c| c == b' ') else {
        return refuse(400, "request_line");
    };
    if sp1 == 0 || sp1 >= 8 {
        return refuse(400, "method");
    }
    r.method = line[..sp1].to_vec();
    if r.method != b"GET" && r.method != b"POST" {
        return refuse(400, "method");
    }
    let rest = &line[sp1 + 1..];
    let Some(sp2) = rest.iter().position(|&c| c == b' ') else {
        return refuse(400, "request_line");
    };
    let target = &rest[..sp2];
    if target.is_empty() || target.len() >= MAX_TARGET || target[0] != b'/' {
        return refuse(400, "target");
    }
    if target.iter().any(|&c| !(0x21..=0x7e).contains(&c)) {
        return refuse(400, "target");
    }
    r.target = target.to_vec();
    if &rest[sp2 + 1..] != b"HTTP/1.1" {
        return refuse(400, "version");
    }

    // --- the headers
    let mut content_length: Option<usize> = None;
    let mut saw_transfer_encoding = false;
    let mut count = 0;
    let mut p = eol + 2;
    while p < end {
        let Some(n) = find(&text[p..], b"\r\n") else {
            return refuse(400, "header_line");
        };
        let h = &text[p..p + n];
        p += n + 2;
        count += 1;
        if count > MAX_HEADERS {
            return refuse(400, "header_count");
        }
        let Some(colon) = h.iter().position(|&c| c == b':') else {
            return refuse(400, "header_line");
        };
        if colon == 0 || colon > 64 {
            return refuse(400, "header_name");
        }
        let name = h[..colon].to_ascii_lowercase();
        let blank = |c: &u8| *c == b' ' || *c == b'\t';
        let v = &h[colon + 1..];
        let v = &v[v.iter().take_while(|c| blank(c)).count()..];
        let v = &v[..v.len() - v.iter().rev().take_while(|c| blank(c)).count()];
        if v.len() > 256 {
            return refuse(400, "header_value");
        }
        if v.iter().any(|&c| c < 0x20 || c == 0x7f) {
            return refuse(400, "header_value");
        }
        match &name[..] {
            // Repeated is refused later, not resolved: any choice is one to plan around.
            b"x-fhsm-client-subject" => {
                if r.subject.is_some() {
                    r.subject_repeated = true;
                } else if v.is_empty() || v.len() >= ACTOR_MAX {
                    return refuse(400, "subject_length");
                } else {
                    r.subject = Some(v.to_vec());
                }
            }
            b"x-fhsm-signature-length" => {
                if r.siglen.is_some() {
                    r.siglen_repeated = true;
                }
                if v.is_empty() || v.len() >= 32 {
                    return refuse(400, "bad_signature_length");
                }
                match strtol_whole(v) {
                    Some(n) if n > 0 && n <= MAX_BODY as i64 => r.siglen = Some(n as usize),
                    _ => return refuse(400, "bad_signature_length"),
                }
            }
            b"x-fhsm-key" => {
                if r.key.is_some() {
                    r.key_repeated = true;
                } else if v.is_empty() || v.len() >= MAX_KEY_LABEL {
                    return refuse(400, "key_length");
                } else {
                    r.key = Some(v.to_vec());
                }
            }
            b"content-length" => {
                if content_length.is_some() || v.is_empty() || v.len() > 9 {
                    return refuse(400, "content_length");
                }
                if !v.iter().all(u8::is_ascii_digit) {
                    return refuse(400, "content_length");
                }
                let cl = v.iter().fold(0usize, |a, c| a * 10 + usize::from(c - b'0'));
                if cl > MAX_BODY {
                    return refuse(413, "body_too_large");
                }
                content_length = Some(cl);
            }
            // Refused, not handled too: a body framed two ways is how a proxy and a backend
            // come to disagree about where a request ends.
            b"transfer-encoding" => saw_transfer_encoding = true,
            _ => {}
        }
    }
    if saw_transfer_encoding {
        return refuse(400, "transfer_encoding");
    }

    // --- the body: what came with the headers, then exactly the rest of Content-Length
    let cl = content_length.unwrap_or(0);
    if cl > 0 {
        let have = &buf[end + 4..used];
        let mut got = have.len().min(cl);
        r.body = vec![0u8; cl];
        r.body[..got].copy_from_slice(&have[..got]);
        while got < cl {
            match wait_readable(fd, deadline) {
                0 => return refuse(408, "request_timeout"),
                w if w < 0 => return refuse(400, "body_read"),
                _ => {}
            }
            let n = read_fd(fd, &mut r.body[got..]);
            if n < 0 {
                if errno() == libc::EINTR {
                    continue;
                }
                return refuse(400, "body_read");
            }
            if n == 0 {
                return refuse(400, "body_short");
            }
            got += n as usize;
        }
    }
    OK
}

fn phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// One write(2), its result ignored, as C's: not a loop, so not for large bodies as is.
pub fn write_once(fd: c_int, b: &[u8]) {
    // SAFETY: b is readable for its length.
    let _ = unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) };
}

/// The response head and text, as C formats it into 512 bytes: anything longer is not sent.
fn text_response(status: u16, phrase: &str, text: &[u8], extra: &str) -> Option<Vec<u8>> {
    let head = format!(
        "HTTP/1.1 {status} {phrase}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
        text.len()
    );
    let s = [head.as_bytes(), text].concat();
    (s.len() < 512).then_some(s)
}

/// `respond_with`: `extra` is zero or more whole header lines.
pub fn respond_with(fd: c_int, status: u16, text: impl AsRef<[u8]>, extra: &str) {
    if let Some(b) = text_response(status, phrase(status), text.as_ref(), extra) {
        write_once(fd, &b);
    }
}

pub fn respond(fd: c_int, status: u16, text: impl AsRef<[u8]>) {
    respond_with(fd, status, text, "");
}

/// `refuse_now`: the acceptor's 408 and 503, on a non-blocking descriptor, never retried.
pub fn refuse_now(fd: c_int, status: u16, text: &str, extra: &str) {
    let phrase = if status == 408 {
        "Request Timeout"
    } else {
        "Service Unavailable"
    };
    if let Some(b) = text_response(status, phrase, text.as_bytes(), extra) {
        write_once(fd, &b);
    }
}

/// A 200 with a binary body (`/sign`, `/certificates`, `/ocsp`): the head, then the body.
pub fn respond_bytes(fd: c_int, content_type: &str, extra: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
        body.len()
    );
    if head.len() < 256 {
        write_once(fd, head.as_bytes());
        write_once(fd, body);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    fn read(req: &[u8]) -> (Verdict, Request) {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(req).unwrap();
        drop(a.shutdown(std::net::Shutdown::Write));
        let mut r = Request::default();
        (read_request(b.as_raw_fd(), &mut r), r)
    }

    #[test]
    fn the_reader_keeps_what_it_needs_and_refuses_the_rest() {
        let (v, r) =
            read(b"POST /sign HTTP/1.1\r\nx-fhsm-key:  k \r\nContent-Length: 3\r\n\r\nabcdef");
        assert_eq!(v, OK);
        assert_eq!(
            (r.key.as_deref(), &r.body[..]),
            (Some(&b"k"[..]), &b"abc"[..])
        );
        for (req, why) in [
            (&b"GET /x HTTP/1.1\r\n"[..], "closed_early"),
            (b"GET /x HTTP/1.0\r\n\r\n", "version"),
            (b"PUT /x HTTP/1.1\r\n\r\n", "method"),
            (b"GET x HTTP/1.1\r\n\r\n", "target"),
            (b"GET /x HTTP/1.1\r\nA\r\n\r\n", "header_line"),
            (
                b"GET /x HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nab",
                "content_length",
            ),
            (
                b"GET /x HTTP/1.1\r\nTransfer-Encoding: x\r\n\r\n",
                "transfer_encoding",
            ),
            (
                b"GET /x HTTP/1.1\r\nX-FHSM-Signature-Length: +0\r\n\r\n",
                "bad_signature_length",
            ),
            (
                b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nab",
                "body_short",
            ),
            // strstr stops at a NUL: the blank line after it is never found
            (b"GET /x HTTP/1.1\r\nA: \x00\r\n\r\n", "closed_early"),
        ] {
            assert_eq!(
                read(req).0.reason,
                Some(why),
                "{}",
                String::from_utf8_lossy(req)
            );
        }
        assert_eq!(
            read(b"GET /x HTTP/1.1\r\nContent-Length: 65537\r\n\r\n").0,
            refuse(413, "body_too_large")
        );
        let (_, r) = read(b"GET /x HTTP/1.1\r\nX-FHSM-Signature-Length: +7\r\n\r\n");
        assert_eq!(r.siglen, Some(7));
    }
}
