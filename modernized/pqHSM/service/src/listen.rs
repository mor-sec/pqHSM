//! The acceptor and its workers (`service/fhsm_service.c:2036-2324`). One acceptor per
//! listener holds every connection that has not yet spoken, never blocking: it lets a silent
//! one go after the first-byte deadline (408), refuses past `--queue-depth` (503), and counts
//! hang-ups and queue-full refusals as bursts, one audit line to open and one to close. A
//! connection that spoke goes to a worker.

use std::collections::VecDeque;
use std::ffi::c_int;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Instant;

use crate::audit::{self, EV_REQUEST_REFUSED};
use crate::http::{self, FIRST_BYTE_DEADLINE, REQUEST_DEADLINE};
use crate::state::BURST_COOLDOWN_S;

/// Set by SIGTERM and SIGINT, with a byte written to the stop pipe.
pub static STOP: AtomicBool = AtomicBool::new(false);
/// The stop pipe's ends: every acceptor polls the read end.
pub static STOP_READ: AtomicI32 = AtomicI32::new(-1);
pub static STOP_WRITE: AtomicI32 = AtomicI32::new(-1);

/// Wake every acceptor to stop; async-signal-safe.
pub fn wake_all() {
    let fd = STOP_WRITE.load(Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: write(2) of one byte from a local.
        unsafe { libc::write(fd, [1u8].as_ptr().cast(), 1) };
    }
}

const QUEUE_FULL: usize = 0;
const HANGUP: usize = 1;
const BURST_OPEN: [&str; 2] = ["queue_full", "hung_up_early"];
const BURST_CLOSE: [&str; 2] = ["queue_full_over", "hung_up_early_over"];

pub struct Listener {
    lfd: c_int,
    public: bool,
    depth: usize,
    ready: Mutex<(VecDeque<c_int>, bool)>,
    cv: Condvar,
}

#[derive(Default)]
struct Burst {
    count: u64,
    since: i64,
    last: i64,
    open: bool,
}

fn wall_now() -> i64 {
    // SAFETY: NULL is allowed.
    unsafe { libc::time(std::ptr::null_mut()) }
}

fn refused_line(params: &[(&str, &[u8])]) {
    audit::event(
        EV_REQUEST_REFUSED,
        -1,
        -1,
        audit::ROLE_NONE,
        audit::RV_FUNCTION_FAILED,
        params,
    );
}

fn close(fd: c_int) {
    // SAFETY: a descriptor this listener owns.
    unsafe { libc::close(fd) };
}

fn set_nonblocking(fd: c_int, on: bool) {
    // SAFETY: plain fcntl on a descriptor we own.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL, 0);
        if fl >= 0 {
            let fl = if on {
                fl | libc::O_NONBLOCK
            } else {
                fl & !libc::O_NONBLOCK
            };
            libc::fcntl(fd, libc::F_SETFL, fl);
        }
    }
}

impl Listener {
    pub fn new(lfd: c_int, public: bool, depth: usize) -> Listener {
        Listener {
            lfd,
            public,
            depth,
            ready: Mutex::new((VecDeque::with_capacity(depth), false)),
            cv: Condvar::new(),
        }
    }

    /// Wake every worker to leave once the queue is empty.
    pub fn stop(&self) {
        self.ready.lock().unwrap_or_else(PoisonError::into_inner).1 = true;
        self.cv.notify_all();
    }

    fn push(&self, fd: c_int) {
        let mut q = self.ready.lock().unwrap_or_else(PoisonError::into_inner);
        // Cannot overflow (a descriptor is waiting or ready, never both); checked anyway.
        if q.0.len() < self.depth {
            q.0.push_back(fd);
            self.cv.notify_one();
        } else {
            drop(q);
            close(fd);
        }
    }

    /// A worker: take a connection, serve it with blocking reads and a send timeout, close.
    pub fn worker(&self) {
        loop {
            let fd = {
                let mut q = self.ready.lock().unwrap_or_else(PoisonError::into_inner);
                while q.0.is_empty() && !q.1 {
                    q = self.cv.wait(q).unwrap_or_else(PoisonError::into_inner);
                }
                match q.0.pop_front() {
                    Some(fd) => fd,
                    None => return,
                }
            };
            set_nonblocking(fd, false);
            let tv = libc::timeval {
                tv_sec: REQUEST_DEADLINE.as_secs() as libc::time_t,
                tv_usec: 0,
            };
            // SAFETY: tv is a timeval, sized as passed.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDTIMEO,
                    (&raw const tv).cast(),
                    size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if self.public {
                crate::serve::serve_public(fd);
            } else {
                crate::serve::serve(fd);
            }
            close(fd);
        }
    }

    /// The acceptor: returns when asked to stop, having closed whatever was still waiting.
    pub fn acceptor(&self) {
        let mut wait: Vec<(c_int, Instant)> = Vec::with_capacity(self.depth);
        let mut burst = [Burst::default(), Burst::default()];
        let note = |b: &mut Burst, kind: usize, now: i64| {
            if !b.open {
                refused_line(&[("reason", BURST_OPEN[kind].as_bytes()), ("route", b"-")]);
                *b = Burst {
                    count: 0,
                    since: now,
                    last: now,
                    open: true,
                };
            }
            b.count += 1;
            b.last = now;
        };
        let flush = |burst: &mut [Burst; 2], now: i64, force: bool| {
            for (k, b) in burst.iter_mut().enumerate() {
                if b.open && (force || now - b.last >= BURST_COOLDOWN_S) {
                    refused_line(&[
                        ("reason", BURST_CLOSE[k].as_bytes()),
                        ("refused", b.count.to_string().as_bytes()),
                        ("window_s", (b.last - b.since).to_string().as_bytes()),
                    ]);
                    (b.open, b.count) = (false, 0);
                }
            }
        };
        let ms_left = |d: Instant| d.saturating_duration_since(Instant::now()).as_millis() as i64;
        let mut pfds: Vec<libc::pollfd> = Vec::with_capacity(self.depth + 2);
        loop {
            pfds.clear();
            for fd in [self.lfd, STOP_READ.load(Ordering::Relaxed)]
                .into_iter()
                .chain(wait.iter().map(|w| w.0))
            {
                pfds.push(libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            // No longer than the nearest deadline; an open burst wakes the loop to close it.
            let mut timeout: i64 = if burst.iter().any(|b| b.open) {
                BURST_COOLDOWN_S * 1000
            } else {
                -1
            };
            for w in &wait {
                let ms = ms_left(w.1);
                if timeout < 0 || ms < timeout {
                    timeout = ms;
                }
            }
            // SAFETY: pfds holds pfds.len() entries.
            let r = unsafe {
                libc::poll(
                    pfds.as_mut_ptr(),
                    pfds.len() as libc::nfds_t,
                    timeout as c_int,
                )
            };
            // errno before the flush, whose audit write may change it (C reads it after: DIV-076)
            let e = http::errno();
            flush(&mut burst, wall_now(), false);
            if r < 0 && e != libc::EINTR {
                break;
            }
            if STOP.load(Ordering::Relaxed) || pfds[1].revents != 0 {
                break;
            }
            let spoke =
                |revents: i16| revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;

            // Expired first, so the slot is free for the accept below.
            let mut i = 0;
            while i < wait.len() {
                let readable = pfds
                    .get(2 + i)
                    .is_some_and(|p| p.fd == wait[i].0 && spoke(p.revents));
                if !readable && ms_left(wait[i].1) <= 0 {
                    http::refuse_now(wait[i].0, 408, "no request within the deadline\n", "");
                    refused_line(&[("reason", b"request_timeout"), ("route", b"-")]);
                    close(wait[i].0);
                    // the moved entry is looked at again; its pfds slot is stale, so not
                    // readable this round, as C's
                    wait.swap_remove(i);
                    continue;
                }
                i += 1;
            }
            // Then those that spoke, matched by descriptor after the compaction above.
            for p in &pfds[2..] {
                if !spoke(p.revents) {
                    continue;
                }
                let mut peek = 0u8;
                // SAFETY: one writable byte.
                let pk = unsafe {
                    libc::recv(
                        p.fd,
                        (&raw mut peek).cast(),
                        1,
                        libc::MSG_PEEK | libc::MSG_DONTWAIT,
                    )
                };
                if pk < 0 && http::errno() == libc::EAGAIN {
                    continue;
                }
                if let Some(k) = wait.iter().position(|w| w.0 == p.fd) {
                    wait.swap_remove(k);
                    if pk == 0 {
                        // Gone before saying anything: counted, not narrated.
                        note(&mut burst[HANGUP], HANGUP, wall_now());
                        close(p.fd);
                    } else {
                        self.push(p.fd);
                    }
                }
            }
            if pfds[0].revents & libc::POLLIN == 0 {
                continue;
            }
            loop {
                // SAFETY: no address wanted.
                let cfd =
                    unsafe { libc::accept(self.lfd, std::ptr::null_mut(), std::ptr::null_mut()) };
                if cfd < 0 {
                    break;
                }
                set_nonblocking(cfd, true);
                if wait.len() >= self.depth {
                    http::refuse_now(cfd, 503, "queue full\n", "Retry-After: 1\r\n");
                    note(&mut burst[QUEUE_FULL], QUEUE_FULL, wall_now());
                    close(cfd);
                    continue;
                }
                wait.push((cfd, Instant::now() + FIRST_BYTE_DEADLINE));
            }
        }
        // An acceptor that failed takes the other with it, rather than leaving one listener
        // dead and the main thread joining an acceptor that never stops (DIV-076).
        wake_all();
        self.stop();
        flush(&mut burst, wall_now(), true);
        for (fd, _) in wait {
            close(fd);
        }
    }
}
