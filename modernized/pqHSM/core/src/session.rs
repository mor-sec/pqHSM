//! The session table (`src/fhsm_session.c`). Each entry holds a slot id, the open flags, a role
//! and the slot's token; the token itself belongs to the slot registry, so the table only
//! names it (`T`). Login state is the token's (PKCS#11 v3.2 §5.6): `role` and `info` read the
//! token's role, and fall back to the entry's own only while no token is attached.
//!
//! Kept from C, in C's order: handle 0 and handles from [`MAX`] up are invalid without a
//! lock; handles are issued lowest first from 1; closing the last session on a token logs the
//! token out, under the table lock (lock order: table, then token); `login` does not hold the
//! table across the token's login, which runs PBKDF2, so a read-only session opened in that
//! window is not seen (C's comment says so too).

use std::ffi::{c_int, c_ulong};
use std::sync::{Mutex, MutexGuard};

/// `FHSM_MAX_SESSIONS`: handles run from 1 to `MAX - 1`. No build sets `-DFHSM_MAX_SESSIONS`,
/// so it is fixed here, as the store's cap is.
pub const MAX: usize = 128;

pub const OK: u32 = 0;
pub const HOST_MEMORY: u32 = 0x2;
pub const SESSION_HANDLE_INVALID: u32 = 0xB3;
pub const SESSION_READ_ONLY_EXISTS: u32 = 0xB7;
pub const TOKEN_NOT_PRESENT: u32 = 0xE0;
pub const USER_ALREADY_LOGGED_IN: u32 = 0x100;
pub const USER_NOT_LOGGED_IN: u32 = 0x101;

/// `FHSM_ROLE_NONE` and `FHSM_ROLE_SO`. Roles pass through as C's `int`: the token, not the
/// table, refuses a role that is neither (DIV-028).
pub const ROLE_NONE: c_int = 0;
pub const ROLE_SO: c_int = 1;

/// `CKF_RW_SESSION`.
pub const RW_SESSION: c_ulong = 0x2;

/// The token calls the table makes. `Pin` is handed to the token untouched: the C ABI passes
/// C's pointer and length, so the token, not the table, decides what a NULL PIN means.
pub trait Token: Copy + Eq {
    type Pin;
    fn login(self, role: c_int, pin: Self::Pin) -> u32;
    fn logout(self);
    fn role(self) -> c_int;
}

#[derive(Clone, Copy)]
struct Entry<T> {
    in_use: bool,
    slot: c_ulong,
    flags: c_ulong,
    role: c_int,
    token: Option<T>,
}

impl<T> Entry<T> {
    const FREE: Self = Entry {
        in_use: false,
        slot: 0,
        flags: 0,
        role: ROLE_NONE,
        token: None,
    };
}

pub struct Table<T> {
    entries: Mutex<[Entry<T>; MAX]>,
}

impl<T: Token> Default for Table<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Token> Table<T> {
    pub const fn new() -> Self {
        Table {
            entries: Mutex::new([Entry::FREE; MAX]),
        }
    }

    fn lock(&self) -> MutexGuard<'_, [Entry<T>; MAX]> {
        // A panic aborts the module (panic = "abort"), so a poisoned lock is only seen in tests.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn index(h: c_ulong) -> Option<usize> {
        usize::try_from(h).ok().filter(|&i| i != 0 && i < MAX)
    }

    /// The live entry `h` names, under the lock.
    fn with<R>(&self, h: c_ulong, f: impl FnOnce(&mut Entry<T>) -> R) -> Result<R, u32> {
        let i = Self::index(h).ok_or(SESSION_HANDLE_INVALID)?;
        let mut t = self.lock();
        let e = &mut t[i];
        if e.in_use {
            Ok(f(e))
        } else {
            Err(SESSION_HANDLE_INVALID)
        }
    }

    /// `fhsm_session_open`: the lowest free handle, or `HOST_MEMORY`.
    pub fn open(&self, slot: c_ulong, flags: c_ulong) -> Result<c_ulong, u32> {
        let mut t = self.lock();
        let i = (1..MAX).find(|&i| !t[i].in_use).ok_or(HOST_MEMORY)?;
        t[i] = Entry {
            in_use: true,
            slot,
            flags,
            role: ROLE_NONE,
            token: None,
        };
        Ok(i as c_ulong)
    }

    /// `fhsm_session_close`. The last session on a token logs the token out.
    pub fn close(&self, h: c_ulong) -> u32 {
        let Some(i) = Self::index(h) else {
            return SESSION_HANDLE_INVALID;
        };
        let mut t = self.lock();
        if !t[i].in_use {
            return SESSION_HANDLE_INVALID;
        }
        let tok = t[i].token;
        t[i] = Entry::FREE;
        if let Some(tok) = tok
            && !t.iter().any(|e| e.in_use && e.token == Some(tok))
        {
            tok.logout();
        }
        OK
    }

    /// `fhsm_session_exists_on_slot`, whether or not a token is attached.
    pub fn exists_on_slot(&self, slot: c_ulong) -> bool {
        self.lock()[1..].iter().any(|e| e.in_use && e.slot == slot)
    }

    /// `fhsm_session_ro_exists`. `None` matches sessions with no token attached, as C's NULL.
    pub fn ro_exists(&self, tok: Option<T>) -> bool {
        self.lock()[1..]
            .iter()
            .any(|e| e.in_use && e.token == tok && e.flags & RW_SESSION == 0)
    }

    /// `fhsm_session_login`. An SO login is refused while a read-only session is open on the
    /// token. The entry takes the role when the token reports it logged in, now or already.
    pub fn login(&self, h: c_ulong, role: c_int, pin: T::Pin) -> u32 {
        let tok = match self.with(h, |e| e.token) {
            Ok(Some(tok)) => tok,
            Ok(None) => return TOKEN_NOT_PRESENT,
            Err(rv) => return rv,
        };
        if role == ROLE_SO && self.ro_exists(Some(tok)) {
            return SESSION_READ_ONLY_EXISTS;
        }
        let rv = tok.login(role, pin);
        // RULE-035 (review M4): a read-only session may have opened during the PIN check
        if rv == OK && role == ROLE_SO && self.ro_exists(Some(tok)) {
            tok.logout();
            return SESSION_READ_ONLY_EXISTS;
        }
        if rv == OK || rv == USER_ALREADY_LOGGED_IN {
            // The handle may have been closed meanwhile; a closed entry is left alone.
            let _ = self.with(h, |e| e.role = role);
        }
        rv
    }

    /// `fhsm_session_logout`: `USER_NOT_LOGGED_IN` unless the TOKEN is logged in (§5.6.8). The
    /// entry's role is cleared either way.
    pub fn logout(&self, h: c_ulong) -> u32 {
        self.with(h, |e| {
            let rv = match e.token {
                Some(tok) if tok.role() != ROLE_NONE => {
                    tok.logout();
                    OK
                }
                _ => USER_NOT_LOGGED_IN,
            };
            e.role = ROLE_NONE;
            rv
        })
        .unwrap_or_else(|rv| rv)
    }

    /// `fhsm_session_attach_token`. `None` detaches, as C's NULL.
    pub fn attach(&self, h: c_ulong, tok: Option<T>) -> u32 {
        self.with(h, |e| e.token = tok)
            .map_or_else(|rv| rv, |()| OK)
    }

    /// `fhsm_session_token`.
    pub fn token(&self, h: c_ulong) -> Option<T> {
        self.with(h, |e| e.token).ok().flatten()
    }

    /// `fhsm_session_reset_all`, the post-fork reset: every entry dropped, no token touched.
    pub fn reset_all(&self) {
        *self.lock() = [Entry::FREE; MAX];
    }

    /// `fhsm_session_role`: the token's role, or the entry's own with no token attached.
    pub fn role(&self, h: c_ulong) -> c_int {
        self.with(h, |e| e.token.map_or(e.role, T::role))
            .unwrap_or(ROLE_NONE)
    }

    /// `fhsm_session_info`: slot, flags and role (as [`Self::role`]).
    pub fn info(&self, h: c_ulong) -> Result<(c_ulong, c_ulong, c_int), u32> {
        self.with(h, |e| (e.slot, e.flags, e.token.map_or(e.role, T::role)))
    }
}
