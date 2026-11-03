//! The module state machine (`src/fhsm_state.c`, FIPS 140-3 §7.4.2): one state under one lock,
//! a whitelist of transitions, and an ERROR latch that only a restart clears. The audit events
//! are the caller's to emit, outside the lock, as C emitted them: [`State::set`] returns the
//! state it left and [`State::latch`] whether it latched.
//!
//! Not carried over: C's `g_error_reason`, a copy of the latch reason that nothing read.

use std::ffi::c_int;
use std::sync::{Mutex, MutexGuard};

pub const POWER_OFF: c_int = 0;
pub const INITIALIZING: c_int = 1;
pub const INITIALIZED: c_int = 2;
pub const AUTHENTICATED: c_int = 3;
pub const ERROR: c_int = 4;

const FUNCTION_FAILED: u32 = 0x6;

/// `g_valid_transitions`, in C's order. ERROR is reached only through [`State::latch`].
const VALID: [(c_int, c_int); 6] = [
    (POWER_OFF, INITIALIZING),
    (INITIALIZING, INITIALIZED),
    (INITIALIZED, AUTHENTICATED),
    (AUTHENTICATED, INITIALIZED),
    (INITIALIZED, POWER_OFF),
    (AUTHENTICATED, POWER_OFF),
];

pub struct State(Mutex<c_int>);

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub const fn new() -> Self {
        State(Mutex::new(POWER_OFF))
    }

    fn lock(&self) -> MutexGuard<'_, c_int> {
        // A panic aborts the module (panic = "abort"), so a poisoned lock is only seen in tests.
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `fhsm_state_get`.
    pub fn get(&self) -> c_int {
        *self.lock()
    }

    /// `fhsm_state_set`: the state left, or `FUNCTION_FAILED` when latched or not whitelisted.
    pub fn set(&self, to: c_int) -> Result<c_int, u32> {
        let mut s = self.lock();
        if *s == ERROR || !VALID.contains(&(*s, to)) {
            return Err(FUNCTION_FAILED);
        }
        Ok(std::mem::replace(&mut *s, to))
    }

    /// `fhsm_state_reset_after_fork`: POWER_OFF, except that ERROR survives a fork.
    pub fn reset_after_fork(&self) {
        let mut s = self.lock();
        if *s != ERROR {
            *s = POWER_OFF;
        }
    }

    /// `fhsm_state_latch_error`: true only on the call that latched.
    pub fn latch(&self) -> bool {
        std::mem::replace(&mut *self.lock(), ERROR) != ERROR
    }
}
