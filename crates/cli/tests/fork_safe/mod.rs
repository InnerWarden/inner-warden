//! Copying the binary under test and then running the copy is racy on Linux.
//! This is the shared guard that closes the race, for every integration test in
//! this crate that does it.
//!
//! # The race
//!
//! The tests in one integration binary run as threads of one process, and
//! several of them copy `CARGO_BIN_EXE_innerwarden` into a layout and then
//! execute the copy. `std::fs::copy` holds a write descriptor to the
//! destination until it returns.
//!
//! On Linux `fork` duplicates every open descriptor into the child, and the
//! kernel counts those duplicates when it decides whether an image is open for
//! writing. So a `Command` spawned by ANOTHER test, in the instant between its
//! `fork` and its `execve`, is enough for this test's `execve` to be refused
//! with `ETXTBSY` ("Text file busy"), even though the two tests copy different
//! files into different tempdirs. Nothing about the product is involved.
//!
//! macOS does not raise `ETXTBSY` here, so the gate on the Mac cannot see it.
//! It surfaced as a failed Linux build of a release run, which is the worst
//! place to find it.
//!
//! # The guard
//!
//! Copying takes the lock exclusively, forking shares it. The shared side is
//! released as soon as the child exists rather than being held across the whole
//! run, so a slow child never blocks another test's copy and the tests stay
//! concurrent. They just never fork across an open write descriptor.
//!
//! Each integration binary is a separate process and compiles its own copy of
//! the static, which is exactly right: a fork in another process cannot inherit
//! this process's descriptors, so the lock only ever needs to cover its own.

use std::path::Path;
use std::process::{Child, Command};
use std::sync::RwLock;

static NO_FORK_WHILE_WRITING: RwLock<()> = RwLock::new(());

/// Copy the binary under test to `to`, with no fork running concurrently.
///
/// `copy` carries the mode across on Unix, so the copy stays executable.
pub fn copy_the_binary(from: &Path, to: &Path) {
    let _writing = NO_FORK_WHILE_WRITING
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::fs::copy(from, to).expect("copy the binary");
}

/// Spawn `cmd`, holding the shared side of the guard across the fork only.
///
/// Callers wait on the returned child themselves, outside the guard.
pub fn spawn_without_racing_a_copy(cmd: &mut Command) -> Child {
    let _forking = NO_FORK_WHILE_WRITING
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cmd.spawn().expect("spawn the binary under test")
}
