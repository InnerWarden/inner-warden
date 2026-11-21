//! Who launched the hook that keeps a prompt: the proof that the record of
//! what the person asked was written by the agent's runtime, not by the
//! agent.
//!
//! # Why
//!
//! An agent with a shell on the person's account can run `innerwarden hook`
//! with a `UserPromptSubmit` payload it made up, and the record then says
//! the person asked for whatever the agent wrote
//! ([`crate::user_prompt`]). The rule that stops an agent running the
//! guard's own hook reads the command's text, and a copy of the program, a
//! variable or a script file gets past it (measured 2026-11-21).
//!
//! # The proof
//!
//! The runtime that runs a hook (Claude Code) reads what the hook prints:
//! the hook's stdout is a pipe whose reading end the runtime alone holds,
//! open until the hook ends. A command the agent runs is not handed such a
//! pipe: Claude Code 2.1.329 starts each command of its Bash tool as
//! `/bin/bash -c`, a child of its own binary, with stdin `/dev/null` and
//! stdout and stderr on a file (measured 2026-11-21 on Linux). So the hook
//! asks, before it keeps a prompt:
//!
//! - is its stdin a pipe, and its stdout a pipe;
//! - does exactly one process hold the reading end of that stdout pipe;
//! - is that process its parent or the parent of its parent (the runtime,
//!   or the runtime through the `sh -c` that runs the hook line)?
//!
//! When all three hold, the record keeps that process, its id and its start
//! time ([`Writer`]). A process that reads the record (the MCP proxy, which
//! the same runtime starts) counts a prompt as proven only when that writer
//! is itself or one of its own ancestors ([`is_self_or_ancestor`]). A
//! script, a shell line or a Python `subprocess` the agent runs to feed the
//! hook reads the hook's stdout itself (or leaves it on the file the
//! runtime gave the command): its writer is the agent's process, never an
//! ancestor of the proxy, and its prompt is not proven.
//!
//! # What it does not prove
//!
//! - A process of the same account can open another process's pipe through
//!   `/proc/<pid>/fd` (Linux: `ptrace_scope` 1 guards attaching, not this
//!   read) and hand it to the hook as its stdout. The proof then names the
//!   runtime.
//! - A runtime that hands the commands of its agent a stdout pipe it reads
//!   itself gives that agent's own hook run the same proof as a hook's. Claude
//!   Code 2.1.329 does not (a file, measured).
//! - The record is a file of the person's account: an agent that writes it
//!   directly writes what it likes, proof included. The guard refuses an
//!   agent's writes to the folder by the command's text, as before.
//! - Linux reads `/proc`; macOS reads libproc (`proc_pidinfo`,
//!   `proc_pidfdinfo`), compiled and not measured on a Mac. Anywhere else
//!   there is no proof, and a prompt is kept unproven, as before.
//!
//! No root is needed: a process reads its own account's processes. Nothing
//! here lowers a refusal; it says which prompts a runtime wrote.

use serde::{Deserialize, Serialize};

/// The process that ran the hook a prompt was kept by: its id and its
/// start time, so a later process with the same id is not taken for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Writer {
    pub pid: u32,
    /// When it started, in the platform's own unit (Linux: clock ticks
    /// since boot; macOS: microseconds since the epoch).
    pub start: u64,
}

/// How many ancestors are walked, at most.
const MAX_DEPTH: usize = 64;

/// The process that alone reads this process's stdout, when stdin and
/// stdout are pipes and that process is the parent or the grandparent:
/// the runtime that ran the hook. `None` for anything else, and where the
/// platform gives no way to tell.
pub fn hook_writer() -> Option<Writer> {
    let me = std::process::id();
    if !sys::fd_is_pipe(0) || !sys::fd_is_pipe(1) {
        return None;
    }
    let readers = sys::stdout_readers(me)?;
    let [reader] = readers.as_slice() else {
        return None;
    };
    let (parent, _) = sys::parent_and_start(me)?;
    let near = if *reader == parent {
        true
    } else {
        sys::parent_and_start(parent).is_some_and(|(grand, _)| grand == *reader && grand > 1)
    };
    if !near || *reader <= 1 {
        return None;
    }
    let (_, start) = sys::parent_and_start(*reader)?;
    Some(Writer {
        pid: *reader,
        start,
    })
}

/// Whether `writer` is this process or one of its ancestors, the same
/// process (id and start time) still running.
pub fn is_self_or_ancestor(writer: &Writer) -> bool {
    let mut pid = std::process::id();
    for _ in 0..MAX_DEPTH {
        let Some((parent, start)) = sys::parent_and_start(pid) else {
            return false;
        };
        if pid == writer.pid {
            return start == writer.start;
        }
        if parent == 0 || parent == pid {
            return false;
        }
        pid = parent;
    }
    false
}

#[cfg(target_os = "linux")]
mod sys {
    use std::fs;

    /// The parent and the start time of `pid`, from `/proc/<pid>/stat`.
    pub(super) fn parent_and_start(pid: u32) -> Option<(u32, u64)> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // The name is in parentheses and may hold anything: the fields are
        // read after its last `)`.
        let rest = &stat[stat.rfind(')')? + 1..];
        let fields: Vec<&str> = rest.split_whitespace().collect();
        // After the name: state (3), ppid (4), ... starttime (22).
        let parent = fields.get(1)?.parse().ok()?;
        let start = fields.get(19)?.parse().ok()?;
        Some((parent, start))
    }

    fn link(pid: &str, fd: &str) -> Option<String> {
        fs::read_link(format!("/proc/{pid}/fd/{fd}"))
            .ok()
            .map(|target| target.to_string_lossy().into_owned())
    }

    pub(super) fn fd_is_pipe(fd: u32) -> bool {
        link("self", &fd.to_string()).is_some_and(|target| target.starts_with("pipe:"))
    }

    /// Every other process that holds the pipe on `me`'s stdout open for
    /// reading. `None` when stdout is no pipe or `/proc` cannot be listed.
    pub(super) fn stdout_readers(me: u32) -> Option<Vec<u32>> {
        let pipe = link("self", "1").filter(|target| target.starts_with("pipe:"))?;
        let mut readers = Vec::new();
        for entry in fs::read_dir("/proc").ok()?.flatten() {
            let name = entry.file_name();
            let Some(pid) = name
                .to_str()
                .filter(|n| n.bytes().all(|b| b.is_ascii_digit()))
            else {
                continue;
            };
            let Ok(pid_number) = pid.parse::<u32>() else {
                continue;
            };
            if pid_number == me {
                continue;
            }
            let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                let fd = fd.file_name();
                let Some(fd) = fd.to_str() else {
                    continue;
                };
                if link(pid, fd).as_deref() != Some(pipe.as_str()) {
                    continue;
                }
                // The access mode of the descriptor: a reader opened it
                // read-only or read-write.
                let reads = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}"))
                    .ok()
                    .and_then(|info| {
                        info.lines()
                            .find_map(|line| line.strip_prefix("flags:"))
                            .and_then(|flags| u32::from_str_radix(flags.trim(), 8).ok())
                    })
                    .is_some_and(|flags| flags & 3 != 1);
                if reads && !readers.contains(&pid_number) {
                    readers.push(pid_number);
                }
            }
        }
        Some(readers)
    }
}

#[cfg(target_os = "macos")]
mod sys {
    use std::os::raw::{c_int, c_void};

    /// `PROC_PIDFDPIPEINFO` of `<sys/proc_info.h>`.
    const PROC_PIDFDPIPEINFO: c_int = 6;

    /// `struct proc_fileinfo` of `<sys/proc_info.h>`.
    #[repr(C)]
    struct ProcFileinfo {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: i64,
        fi_type: i32,
        fi_guardflags: u32,
    }

    /// `struct pipe_info` of `<sys/proc_info.h>`.
    #[repr(C)]
    struct PipeInfo {
        pipe_stat: libc::vinfo_stat,
        pipe_handle: u64,
        pipe_peerhandle: u64,
        pipe_status: c_int,
        rfu_1: c_int,
    }

    /// `struct pipe_fdinfo` of `<sys/proc_info.h>`.
    #[repr(C)]
    struct PipeFdinfo {
        pfi: ProcFileinfo,
        pipeinfo: PipeInfo,
    }

    pub(super) fn parent_and_start(pid: u32) -> Option<(u32, u64)> {
        // SAFETY: proc_bsdinfo is plain data; proc_pidinfo writes at most
        // the size handed in and returns how much it wrote.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as c_int;
        let wrote = unsafe {
            libc::proc_pidinfo(
                pid as c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut c_void,
                size,
            )
        };
        if wrote != size {
            return None;
        }
        let start = info
            .pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec);
        Some((info.pbi_ppid, start))
    }

    fn pipe_of(pid: u32, fd: c_int) -> Option<PipeFdinfo> {
        // SAFETY: as above, for pipe_fdinfo.
        let mut info: PipeFdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<PipeFdinfo>() as c_int;
        let wrote = unsafe {
            libc::proc_pidfdinfo(
                pid as c_int,
                fd,
                PROC_PIDFDPIPEINFO,
                &mut info as *mut _ as *mut c_void,
                size,
            )
        };
        (wrote == size).then_some(info)
    }

    pub(super) fn fd_is_pipe(fd: u32) -> bool {
        pipe_of(std::process::id(), fd as c_int).is_some()
    }

    fn all_pids() -> Option<Vec<u32>> {
        // SAFETY: a null buffer asks for the count; the second call writes
        // at most the size handed in.
        let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        if count <= 0 {
            return None;
        }
        let mut pids = vec![0 as c_int; count as usize + 64];
        let size = (pids.len() * std::mem::size_of::<c_int>()) as c_int;
        let wrote = unsafe { libc::proc_listallpids(pids.as_mut_ptr() as *mut c_void, size) };
        if wrote <= 0 {
            return None;
        }
        pids.truncate(wrote as usize);
        Some(
            pids.into_iter()
                .filter(|p| *p > 0)
                .map(|p| p as u32)
                .collect(),
        )
    }

    fn fds_of(pid: u32) -> Vec<libc::proc_fdinfo> {
        let one = std::mem::size_of::<libc::proc_fdinfo>();
        // SAFETY: a null buffer asks for the size; the second call writes at
        // most the size handed in.
        let need = unsafe {
            libc::proc_pidinfo(
                pid as c_int,
                libc::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        if need <= 0 {
            return Vec::new();
        }
        let mut fds: Vec<libc::proc_fdinfo> = Vec::with_capacity(need as usize / one + 16);
        let size = (fds.capacity() * one) as c_int;
        let wrote = unsafe {
            libc::proc_pidinfo(
                pid as c_int,
                libc::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr() as *mut c_void,
                size,
            )
        };
        if wrote <= 0 {
            return Vec::new();
        }
        // SAFETY: proc_pidinfo wrote `wrote` bytes of whole entries.
        unsafe { fds.set_len(wrote as usize / one) };
        fds
    }

    /// Every other process that holds the reading end of the pipe on
    /// `me`'s stdout: the end whose handle is the peer of stdout's.
    pub(super) fn stdout_readers(me: u32) -> Option<Vec<u32>> {
        let mine = pipe_of(me, 1)?;
        let reading_end = mine.pipeinfo.pipe_peerhandle;
        if reading_end == 0 {
            return None;
        }
        let mut readers = Vec::new();
        for pid in all_pids()? {
            if pid == me {
                continue;
            }
            let holds = fds_of(pid).iter().any(|fd| {
                fd.proc_fdtype == libc::PROX_FDTYPE_PIPE as u32
                    && pipe_of(pid, fd.proc_fd)
                        .is_some_and(|pipe| pipe.pipeinfo.pipe_handle == reading_end)
            });
            if holds {
                readers.push(pid);
            }
        }
        Some(readers)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod sys {
    pub(super) fn parent_and_start(_pid: u32) -> Option<(u32, u64)> {
        None
    }
    pub(super) fn fd_is_pipe(_fd: u32) -> bool {
        false
    }
    pub(super) fn stdout_readers(_me: u32) -> Option<Vec<u32>> {
        None
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

    /// A test process reads its own chain: itself counts, a process that is
    /// no ancestor does not, nor itself with another start time.
    #[test]
    fn self_and_ancestors_are_known_by_id_and_start() {
        let me = std::process::id();
        let (parent, start) = sys::parent_and_start(me).expect("own stat");
        assert!(is_self_or_ancestor(&Writer { pid: me, start }));
        let (_, parent_start) = sys::parent_and_start(parent).expect("parent stat");
        assert!(is_self_or_ancestor(&Writer {
            pid: parent,
            start: parent_start
        }));
        assert!(!is_self_or_ancestor(&Writer {
            pid: me,
            start: start + 1
        }));
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("a child");
        let (_, child_start) = sys::parent_and_start(child.id()).expect("child stat");
        assert!(!is_self_or_ancestor(&Writer {
            pid: child.id(),
            start: child_start
        }));
        let _ = child.kill();
        let _ = child.wait();
    }
}
