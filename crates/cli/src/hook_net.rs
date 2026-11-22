//! The net under the hook: a screening that ends without an answer.
//!
//! An agent blocks a tool call only when its hook exits 2. A hook that dies
//! on a signal, or that the agent kills at its own hook timeout, reads as
//! "show stderr, carry on": the call runs, unscreened and unrecorded. The
//! panic guard in `main.rs` covers a panic. This covers the two ends a panic
//! guard never sees.
//!
//! **A fault.** A stack overflow is not a panic: the process ends on a
//! signal. On unix the signals a fault raises get a handler that runs on its
//! own stack (an overflow leaves none to run on), says what happened and
//! exits.
//!
//! **No answer in time.** A line that costs more to read than the agent
//! waits, a caller that never closes stdin, a wait that never ends. A
//! watchdog thread ends the hook once it has spent [`DEADLINE`] on the
//! screening, or [`WALL_CAP`] on the clock, well inside the wait of the
//! agents this hook is wired to. Time the screening thread spent ready to run
//! while the CPUs ran something else (a `cargo build` beside it) is not the
//! screening's: on Linux it is read from the kernel (`run_delay` in the
//! thread's `schedstat`) and left out of [`DEADLINE`], never out of
//! [`WALL_CAP`]. A wait the hook makes on purpose and bounds itself (the
//! second opinion of a model) moves both by its bound with [`allow_wait`].
//!
//! Both end as a call the hook could not read does: 2 in enforce (the call
//! is refused), 1 in monitor (it never blocks, and says the call went
//! unscreened).
//!
//! Not closed here: `SIGKILL`, which no process can answer, and a fault on
//! Windows, where only the deadline is armed.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How long the hook has to answer. Reading a line takes milliseconds, and
/// every wait the hook makes on the way is bounded well under a second (the
/// record's locks, the host's answer, a notification), so ten seconds is a
/// hook that is not going to answer. An agent waits 60 s or more for a hook
/// unless its operator set less.
pub const DEADLINE: Duration = Duration::from_secs(10);

/// The most the hook takes on the clock, waiting for a CPU included, before
/// it ends itself. Under [`hook::HOOK_TIMEOUT_SECS`], the wait `install`
/// writes for Claude Code, with room for a second opinion's bound
/// ([`hook::HOOK_LONGEST_SECS`]).
///
/// [`hook::HOOK_TIMEOUT_SECS`]: innerwarden_agent_guard::hook::HOOK_TIMEOUT_SECS
/// [`hook::HOOK_LONGEST_SECS`]: innerwarden_agent_guard::hook::HOOK_LONGEST_SECS
pub const WALL_CAP: Duration = Duration::from_secs(25);

// The screening's deadline comes before the limit on the clock.
const _: () = assert!(DEADLINE.as_millis() < WALL_CAP.as_millis());

/// Lowers [`DEADLINE`], in milliseconds, for an operator whose agent waits
/// less for a hook than the default. It never raises it: a value above the
/// default, zero, or anything that is not a number leaves the default.
pub const DEADLINE_ENV: &str = "INNERWARDEN_HOOK_DEADLINE_MS";

/// Raises [`DEADLINE`], in milliseconds, in a DEBUG build only: the test
/// suites run the debug binary beside every other test binary, and on a
/// loaded machine a screening that is not about the deadline at all ran past
/// ten seconds and was refused by it (`hook_profiles.rs`, 2026-11-18). A
/// release build does not read it. [`DEADLINE_ENV`], when set, wins: the
/// tests of the deadline itself lower it.
#[cfg(debug_assertions)]
pub const TEST_DEADLINE_ENV: &str = "IW_TEST_HOOK_DEADLINE_MS";

/// Names a file, in a DEBUG build only, that each phase of the hook appends
/// one line to ([`mark`]): where the time of a hook run goes, measured by
/// the test suite. A release build does not read it.
#[cfg(debug_assertions)]
pub const TEST_PHASES_ENV: &str = "IW_TEST_HOOK_PHASES";

/// When the net was armed, and the run queue of the thread that screens:
/// what the watchdog and [`mark`] measure from.
static ARMED: std::sync::OnceLock<(Instant, RunQueue)> = std::sync::OnceLock::new();

static MONITOR: AtomicBool = AtomicBool::new(false);

/// No answer yet: [`ANSWER`] holds this until [`answered`].
const NO_ANSWER: u16 = u16::MAX;

/// The exit code the hook answered with, once it has ([`answered`]), and
/// [`NO_ANSWER`] before.
static ANSWER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(NO_ANSWER);

/// Work that decides nothing (writing the record, alerting, bringing the
/// wiring up to date), kept for after the answer by [`after_answer`].
type Deferred = Box<dyn FnOnce() + Send>;
static AFTER_ANSWER: std::sync::Mutex<Vec<Deferred>> = std::sync::Mutex::new(Vec::new());

/// Work kept by [`after_answer_last`]: run after all of [`AFTER_ANSWER`].
static AFTER_ANSWER_LAST: std::sync::Mutex<Vec<Deferred>> = std::sync::Mutex::new(Vec::new());

/// The most [`allow_wait`] adds in one run, all waits together: one answer
/// of a model ([`crate::second_opinion_io::LLM_ANSWER_BOUND`]). Each line of
/// a call asked its own and added 20 s, so with two lines the limit on the
/// clock (65 s) passed the 50 s Claude Code waits for its hook.
pub const MAX_ALLOWED_WAIT: Duration = crate::second_opinion_io::LLM_ANSWER_BOUND;
const _: () = assert!(
    WALL_CAP.as_millis() + MAX_ALLOWED_WAIT.as_millis()
        <= (innerwarden_agent_guard::hook::HOOK_LONGEST_SECS as u128) * 1000
);

/// Milliseconds [`allow_wait`] has added in this run.
static ALLOWED_MS: AtomicU64 = AtomicU64::new(0);

/// Set for a run on the person's prompt: every end is 0 and silent.
static QUIET: AtomicBool = AtomicBool::new(false);

/// Set for an agent that reads its hook's answer as JSON on stdout only (the
/// Antigravity CLI): every end of the net writes [`JSON_DENY`] (or, in
/// monitor mode, [`JSON_ALLOW`]) there and exits 0.
static JSON_ANSWER: AtomicBool = AtomicBool::new(false);

/// The refusal an end of the net writes on stdout in JSON mode, in the
/// Antigravity CLI's shape (`innerwarden_agent_guard::antigravity_hook::deny`).
const JSON_DENY: &str = "{\"decision\":\"deny\",\"reason\":\"InnerWarden hook: the screening of \
this tool call did not finish (it ran out of time, or a fault or an internal error stopped it); \
refusing it rather than letting it run unscreened.\"}\n";

/// What an end of the net writes on stdout in JSON mode while monitoring:
/// the call runs, as monitor mode never refuses.
const JSON_ALLOW: &str = "{\"decision\":\"allow\"}\n";

/// Milliseconds of screening after [`arm`] at which the watchdog ends the
/// hook. Zero while no deadline is armed.
static DEADLINE_MS: AtomicU64 = AtomicU64::new(0);

/// Milliseconds on the clock after [`arm`] at which the watchdog ends the
/// hook whatever the screening spent. Zero while no deadline is armed.
static WALL_MS: AtomicU64 = AtomicU64::new(0);

const OUT_OF_TIME_ENFORCE: &str =
    "InnerWarden hook: the screening of this tool call did not finish in time; refusing it \
     rather than letting it run unscreened.\n  If the command line is very long, write it \
     shorter, as separate commands, or with the long value in a file.\n";
const OUT_OF_TIME_MONITOR: &str =
    "InnerWarden hook: the screening of this tool call did not finish in time; it was NOT \
     screened (monitor mode never blocks).\n";
#[cfg(unix)]
const FAULT_ENFORCE: &str =
    "InnerWarden hook: a fault stopped the screening of this tool call; refusing it rather \
     than letting it run unscreened.\n";
#[cfg(unix)]
const FAULT_MONITOR: &str =
    "InnerWarden hook: a fault stopped the screening of this tool call; it was NOT screened \
     (monitor mode never blocks).\n";

/// The deadline the hook runs under: [`DEADLINE`], or the lower one the
/// environment names.
fn deadline_from(named: Option<&str>) -> Duration {
    named
        .and_then(|text| text.trim().parse::<u64>().ok())
        .filter(|&ms| ms > 0)
        .map(Duration::from_millis)
        .filter(|&lower| lower < DEADLINE)
        .unwrap_or(DEADLINE)
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Arm the net for this hook run: the fault handlers on the calling thread
/// (the one that screens) and the deadline. An error is a net that could not
/// be set; the caller refuses the call as one it could not read.
pub fn arm(monitor: bool) -> Result<(), &'static str> {
    let named = std::env::var(DEADLINE_ENV).ok();
    #[cfg(debug_assertions)]
    if named.is_none() {
        let raised = std::env::var(TEST_DEADLINE_ENV).ok();
        if let Some(deadline) = test_deadline_from(raised.as_deref()) {
            // A raise for a loaded test suite raises the limit on the clock
            // with it: the clock is what a loaded suite runs out of.
            return arm_with_cap(monitor, deadline, deadline.max(WALL_CAP));
        }
    }
    arm_with(monitor, deadline_from(named.as_deref()))
}

/// The deadline [`TEST_DEADLINE_ENV`] names, debug builds only: any positive
/// number of milliseconds, `None` for anything else.
#[cfg(debug_assertions)]
fn test_deadline_from(named: Option<&str>) -> Option<Duration> {
    named
        .and_then(|text| text.trim().parse::<u64>().ok())
        .filter(|&ms| ms > 0)
        .map(Duration::from_millis)
}

/// The limit on the clock for a deadline: [`WALL_CAP`], or the deadline
/// itself where the environment lowered it (the agent waits that long on the
/// clock, not on the screening).
fn wall_cap_for(deadline: Duration) -> Duration {
    if deadline < DEADLINE {
        deadline
    } else {
        WALL_CAP
    }
}

fn arm_with(monitor: bool, deadline: Duration) -> Result<(), &'static str> {
    arm_with_cap(monitor, deadline, wall_cap_for(deadline))
}

fn arm_with_cap(monitor: bool, deadline: Duration, cap: Duration) -> Result<(), &'static str> {
    MONITOR.store(monitor, Ordering::SeqCst);
    #[cfg(unix)]
    fault::install()?;
    // Opened here, on the thread that screens: the file is that thread's.
    let (armed, queue) = ARMED.get_or_init(|| (Instant::now(), RunQueue::of_this_thread()));
    DEADLINE_MS.store(millis(deadline).max(1), Ordering::SeqCst);
    WALL_MS.store(millis(cap).max(1), Ordering::SeqCst);
    std::thread::Builder::new()
        .name("hook-deadline".into())
        .spawn(move || watch(*armed, queue))
        .map(|_| ())
        .map_err(|_| "no screening deadline could be set")
}

/// Run `work` after the hook has answered, outside the deadline, when the
/// net is armed (a hook run); at once otherwise (`innerwarden check`, the
/// OpenClaw guard). For work whose outcome no answer waits on: the record,
/// the alert. Written to the record late or not at all, a call keeps the
/// answer it was given; refused by the deadline, it would lose an answer it
/// already had because a busy disk held the record (2026-11-20, four
/// calls of a lab machine refused during a build).
pub fn after_answer(work: impl FnOnce() + Send + 'static) {
    if ARMED.get().is_none() || answer().is_some() {
        return work();
    }
    match AFTER_ANSWER.lock() {
        Ok(mut queue) => queue.push(Box::new(work)),
        Err(_) => work(),
    }
}

/// The hook has its answer, `code`, and has written whatever it says on
/// stdout and stderr: from here on the deadline is behind it. Then the work
/// [`after_answer`] kept runs, still under [`WALL_CAP`]; past it, and on a
/// fault or a panic, the hook ends with `code` and not with a refusal.
pub fn answered(code: u8) {
    ANSWER.store(u16::from(code), Ordering::SeqCst);
    let take = |queue: &std::sync::Mutex<Vec<Deferred>>| {
        queue
            .lock()
            .map(|mut queue| std::mem::take(&mut *queue))
            .unwrap_or_default()
    };
    let kept: Vec<Deferred> = take(&AFTER_ANSWER)
        .into_iter()
        .chain(take(&AFTER_ANSWER_LAST))
        .collect();
    if kept.is_empty() {
        return;
    }
    // A mark beside the record while the work runs (`record_pending`): an
    // end at the limit on the clock leaves it, and the next hook or the
    // status says the record was cut. Marks an earlier hook left are swept
    // first.
    let graph = crate::graph_io::graph_path();
    if let Some(graph) = &graph {
        crate::record_pending::sweep(graph);
        let _ = PENDING_GRAPH.set(graph.clone());
    }
    let mark = graph.as_deref().and_then(crate::record_pending::begin);
    for work in kept {
        work();
    }
    if let Some(mark) = mark {
        crate::record_pending::finish(&mark);
    }
}

/// The record the work after the answer writes: what an end at the limit
/// on the clock cleans the temporaries of ([`watch`]).
static PENDING_GRAPH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// [`after_answer`] for work that must come after every other kept work:
/// bringing the wiring up to date, which decides nothing about this call
/// and must not hold back its record and alert.
pub fn after_answer_last(work: impl FnOnce() + Send + 'static) {
    if ARMED.get().is_none() || answer().is_some() {
        return work();
    }
    match AFTER_ANSWER_LAST.lock() {
        Ok(mut queue) => queue.push(Box::new(work)),
        Err(_) => work(),
    }
}

/// The exit code the hook answered with, `None` before [`answered`].
pub fn answer() -> Option<u8> {
    u8::try_from(ANSWER.load(Ordering::SeqCst)).ok()
}

/// What an end of the net that comes after the answer says.
const AFTER_ANSWER_LATE: &str =
    "InnerWarden hook: this call was answered, but its record was not written in time; the \
     answer stands.\n";
#[cfg(unix)]
const AFTER_ANSWER_FAULT: &str =
    "InnerWarden hook: this call was answered, but a fault stopped writing its record; the \
     answer stands.\n";

/// Holds the record back, in milliseconds, in a DEBUG build only: a disk
/// that a build keeps busy, for the tests that prove a slow record does not
/// cost a call its answer. A release build does not read it.
#[cfg(debug_assertions)]
pub const TEST_RECORD_DELAY_ENV: &str = "IW_TEST_HOOK_RECORD_DELAY_MS";

/// Debug builds: wait as long as [`TEST_RECORD_DELAY_ENV`] says, before the
/// record is written. Nothing in a release build.
pub fn test_record_delay() {
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var(TEST_RECORD_DELAY_ENV)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
    {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

/// Debug builds, with [`TEST_PHASES_ENV`] set, append one line for `phase`:
/// the time since [`arm`] on the clock, the part of it the screening
/// thread waited for a CPU, and the rest, which is what the deadline counts.
/// Nothing anywhere else, nor before the net is armed.
pub fn mark(phase: &str) {
    #[cfg(debug_assertions)]
    {
        let Some(path) = std::env::var_os(TEST_PHASES_ENV) else {
            return;
        };
        let Some((armed, queue)) = ARMED.get() else {
            return;
        };
        let wall = armed.elapsed();
        let queued = queue.since_armed();
        let line = format!(
            "{phase} wall_ms={} queued_ms={} screening_ms={}\n",
            millis(wall),
            millis(queued),
            millis(wall.saturating_sub(queued))
        );
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| std::io::Write::write_all(&mut file, line.as_bytes()));
    }
    #[cfg(not(debug_assertions))]
    let _ = phase;
}

/// From here on every end of the net (the deadline, a fault) is 0 and
/// silent, and so is the panic guard's: for a run on the person's prompt,
/// where any other end shows an error, and 2 drops what the person typed.
/// `false` puts the ends back, for a tool call that came on a prompt line.
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::SeqCst);
}

/// Whether the run ends quietly ([`set_quiet`]).
pub fn is_quiet() -> bool {
    QUIET.load(Ordering::SeqCst)
}

/// From here on every end of the net, and the panic guard's, answers on
/// stdout as JSON with exit 0 ([`json_answer`]), for an agent that reads
/// nothing else. `monitor` is the run's mode, kept for an end that comes
/// before [`arm`].
pub fn set_json_answer(on: bool, monitor: bool) {
    JSON_ANSWER.store(on, Ordering::SeqCst);
    if on {
        MONITOR.store(monitor, Ordering::SeqCst);
    }
}

/// The JSON an end of the net writes on stdout: a refusal, or in monitor
/// mode a pass. `None` unless [`set_json_answer`] turned it on.
pub fn json_answer() -> Option<&'static str> {
    JSON_ANSWER.load(Ordering::SeqCst).then(|| {
        if MONITOR.load(Ordering::SeqCst) {
            JSON_ALLOW
        } else {
            JSON_DENY
        }
    })
}

/// The hook is about to make a wait it bounds itself by `bound`: move the
/// deadline and the limit on the clock by as much. Nothing to move when no
/// deadline is armed (the same code runs under `innerwarden check`).
///
/// All waits of a run together move them by at most [`MAX_ALLOWED_WAIT`].
/// `false` when this wait would go past it: the caller then does not make
/// the wait (a second opinion keeps its review), since the deadline would
/// refuse the call while it waited.
pub fn allow_wait(bound: Duration) -> bool {
    if DEADLINE_MS.load(Ordering::SeqCst) == 0 {
        return true;
    }
    let granted = ALLOWED_MS
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |added| {
            let after = added.saturating_add(millis(bound));
            (after <= millis(MAX_ALLOWED_WAIT)).then_some(after)
        })
        .is_ok();
    if !granted {
        return false;
    }
    for limit in [&DEADLINE_MS, &WALL_MS] {
        let _ = limit.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |armed| {
            (armed != 0).then(|| armed.saturating_add(millis(bound)))
        });
    }
    true
}

/// How long the screening thread has waited, ready to run, for a CPU since
/// the net was armed: `run_delay`, the second field of the thread's
/// `/proc/thread-self/schedstat`, in nanoseconds. Zero where it cannot be
/// read (not Linux, no `/proc`), which is the clock alone, as before.
struct RunQueue {
    #[cfg(target_os = "linux")]
    file: Option<std::fs::File>,
    at_arm: Duration,
}

impl RunQueue {
    fn of_this_thread() -> Self {
        #[cfg(target_os = "linux")]
        {
            let file = std::fs::File::open("/proc/thread-self/schedstat").ok();
            let mut queue = RunQueue {
                file,
                at_arm: Duration::ZERO,
            };
            queue.at_arm = queue.total();
            queue
        }
        #[cfg(not(target_os = "linux"))]
        RunQueue {
            at_arm: Duration::ZERO,
        }
    }

    #[cfg(target_os = "linux")]
    fn total(&self) -> Duration {
        use std::os::unix::fs::FileExt;
        let Some(file) = &self.file else {
            return Duration::ZERO;
        };
        let mut buf = [0u8; 96];
        let Ok(read) = file.read_at(&mut buf, 0) else {
            return Duration::ZERO;
        };
        std::str::from_utf8(&buf[..read])
            .ok()
            .and_then(|text| text.split_whitespace().nth(1))
            .and_then(|field| field.parse::<u64>().ok())
            .map_or(Duration::ZERO, Duration::from_nanos)
    }

    #[cfg(not(target_os = "linux"))]
    fn total(&self) -> Duration {
        Duration::ZERO
    }

    fn since_armed(&self) -> Duration {
        self.total().saturating_sub(self.at_arm)
    }
}

/// PURE: what is left before the hook is out of time, or `None` once it
/// is: the screening is `wall` less what it spent `queued` for a CPU, held
/// to `deadline`; the clock is held to `cap` whatever was queued. Once the
/// hook has `answered`, the screening is over and only the clock counts.
fn time_left(
    wall: Duration,
    queued: Duration,
    deadline: Duration,
    cap: Duration,
    answered: bool,
) -> Option<Duration> {
    let on_the_clock = cap.checked_sub(wall)?;
    let left = if answered {
        on_the_clock
    } else {
        let screening = wall.saturating_sub(queued);
        deadline.checked_sub(screening)?.min(on_the_clock)
    };
    (!left.is_zero()).then_some(left)
}

/// Sleep to the deadline, read it again (a wait may have moved it, time
/// spent waiting for a CPU puts it later), end the hook once it is behind.
fn watch(armed: Instant, queue: &RunQueue) -> ! {
    loop {
        let deadline = Duration::from_millis(DEADLINE_MS.load(Ordering::SeqCst));
        let cap = Duration::from_millis(WALL_MS.load(Ordering::SeqCst));
        let answer = answer();
        match time_left(
            armed.elapsed(),
            queue.since_armed(),
            deadline,
            cap,
            answer.is_some(),
        ) {
            Some(left) => std::thread::sleep(left.max(Duration::from_millis(1))),
            None => {
                if QUIET.load(Ordering::SeqCst) {
                    end("", 0)
                } else if let Some(code) = answer {
                    // Answered already, on stdout too in JSON mode: only the
                    // exit is left, with the answer's own code. The writer's
                    // temporaries go; the mark stays, for the next hook or
                    // the status to say the record was cut.
                    if let Some(graph) = PENDING_GRAPH.get() {
                        crate::record_pending::clean_own_temporaries(graph);
                    }
                    end(AFTER_ANSWER_LATE, code)
                } else if let Some(answer) = json_answer() {
                    let said = if MONITOR.load(Ordering::SeqCst) {
                        OUT_OF_TIME_MONITOR
                    } else {
                        OUT_OF_TIME_ENFORCE
                    };
                    end_answering(said, answer)
                } else if MONITOR.load(Ordering::SeqCst) {
                    end(OUT_OF_TIME_MONITOR, crate::unreadable_exit_code(true))
                } else {
                    end(OUT_OF_TIME_ENFORCE, crate::unreadable_exit_code(false))
                }
            }
        }
    }
}

/// Say `message` and end the process with `code`, from a thread that is not
/// the one screening, or from a signal handler.
///
/// On unix this is `write` and `_exit` and nothing else: both may be called
/// from a signal handler, neither takes a lock the stopped thread may hold
/// (the lock on stderr), and `_exit` runs no exit handler beside a thread
/// that is still running.
#[cfg(unix)]
fn end(message: &'static str, code: u8) -> ! {
    // SAFETY: `message` is a live buffer of `message.len()` bytes; `write`
    // and `_exit` are async-signal-safe and `_exit` does not return.
    unsafe {
        libc::write(2, message.as_ptr().cast(), message.len());
        libc::_exit(i32::from(code))
    }
}

/// Where there is no `_exit`: say it and end the process.
#[cfg(not(unix))]
fn end(message: &'static str, code: u8) -> ! {
    let _ = std::io::Write::write_all(&mut std::io::stderr(), message.as_bytes());
    std::process::exit(i32::from(code))
}

/// [`end`] for JSON mode: `message` on stderr, `answer` on stdout, exit 0.
/// The same two calls and nothing else, so it may run in a signal handler.
#[cfg(unix)]
fn end_answering(message: &'static str, answer: &'static str) -> ! {
    // SAFETY: both are live buffers of their own length; `write` and
    // `_exit` are async-signal-safe and `_exit` does not return.
    unsafe {
        libc::write(2, message.as_ptr().cast(), message.len());
        libc::write(1, answer.as_ptr().cast(), answer.len());
        libc::_exit(0)
    }
}

/// Where there is no `_exit`: say it, answer, and end the process.
#[cfg(not(unix))]
fn end_answering(message: &'static str, answer: &'static str) -> ! {
    let _ = std::io::Write::write_all(&mut std::io::stderr(), message.as_bytes());
    let _ = std::io::Write::write_all(&mut std::io::stdout(), answer.as_bytes());
    let _ = std::io::Write::flush(&mut std::io::stdout());
    std::process::exit(0)
}

#[cfg(unix)]
mod fault {
    use std::sync::atomic::Ordering;

    /// What a fault of the process itself raises: an abort (a stack overflow
    /// reported by the runtime, an allocation that failed), a bad access (a
    /// stack overflow, by signal), an illegal or trap instruction (an abort
    /// compiled in line), an arithmetic fault, a refused system call.
    const SIGNALS: [libc::c_int; 7] = [
        libc::SIGABRT,
        libc::SIGSEGV,
        libc::SIGBUS,
        libc::SIGILL,
        libc::SIGFPE,
        libc::SIGTRAP,
        libc::SIGSYS,
    ];

    /// Room for the handler when the thread's own stack is gone.
    const HANDLER_STACK: usize = 1 << 16;

    extern "C" fn on_fault(_signal: libc::c_int) {
        // Only what a signal handler may do: read an atomic, `write`, `_exit`.
        if super::QUIET.load(Ordering::SeqCst) {
            super::end("", 0)
        } else if let Some(code) = super::answer() {
            super::end(super::AFTER_ANSWER_FAULT, code)
        } else if let Some(answer) = super::json_answer() {
            let said = if super::MONITOR.load(Ordering::SeqCst) {
                super::FAULT_MONITOR
            } else {
                super::FAULT_ENFORCE
            };
            super::end_answering(said, answer)
        } else if super::MONITOR.load(Ordering::SeqCst) {
            super::end(super::FAULT_MONITOR, crate::unreadable_exit_code(true))
        } else {
            super::end(super::FAULT_ENFORCE, crate::unreadable_exit_code(false))
        }
    }

    /// Give the calling thread a stack for the handler and point the fault
    /// signals at it.
    pub fn install() -> Result<(), &'static str> {
        const REFUSED: &str = "no fault handler could be set";
        let size = HANDLER_STACK.max(libc::SIGSTKSZ);
        // Never freed: the handler may need it until the process ends.
        let stack = Box::leak(vec![0u8; size].into_boxed_slice());
        let alternate = libc::stack_t {
            ss_sp: stack.as_mut_ptr().cast(),
            ss_flags: 0,
            ss_size: size,
        };
        // SAFETY: `alternate` describes a live, leaked buffer of `size` bytes.
        if unsafe { libc::sigaltstack(&alternate, std::ptr::null_mut()) } != 0 {
            return Err(REFUSED);
        }
        for signal in SIGNALS {
            // SAFETY: a zeroed `sigaction` is a valid value to fill in; the
            // handler has the one-argument signature that the flags (no
            // `SA_SIGINFO`) ask for.
            let installed = unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = on_fault as extern "C" fn(libc::c_int) as usize;
                action.sa_flags = libc::SA_ONSTACK;
                libc::sigemptyset(&mut action.sa_mask);
                libc::sigaction(signal, &action, std::ptr::null_mut())
            };
            if installed != 0 {
                return Err(REFUSED);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    /// What `agents connect` tells the person about the guard's own deadline
    /// is this deadline, and both stay well inside the wait it writes for
    /// Codex and Gemini, so the guard answers (or refuses) before the agent
    /// gives up on it and runs the tool.
    ///
    /// FAILS ON REVERT: change either number alone.
    #[test]
    fn the_deadline_connect_states_is_this_one_and_inside_the_agents_wait() {
        use innerwarden_agent_guard::agent_hooks::{
            ANTIGRAVITY, CODEX, GEMINI, GUARD_DEADLINE_SECS,
        };
        assert_eq!(DEADLINE, Duration::from_secs(GUARD_DEADLINE_SECS));
        let second_opinion = crate::second_opinion_io::LLM_ANSWER_BOUND;
        for spec in [&CODEX, &GEMINI, &ANTIGRAVITY] {
            assert!(DEADLINE + second_opinion < spec.wait(), "{}", spec.agent);
        }
    }

    /// The default holds unless the environment names a LOWER bound.
    ///
    /// FAILS ON REVERT: take the named value as it comes and a large one
    /// puts the deadline past the agent's own wait, where it never fires.
    #[test]
    fn the_environment_lowers_the_deadline_and_never_raises_it() {
        assert_eq!(deadline_from(None), DEADLINE);
        assert_eq!(deadline_from(Some("300")), Duration::from_millis(300));
        assert_eq!(deadline_from(Some(" 9999 ")), Duration::from_millis(9999));
        for kept in [
            "10000",
            "600000",
            "0",
            "",
            "abc",
            "-5",
            "1.5",
            "18446744073709551616",
        ] {
            assert_eq!(deadline_from(Some(kept)), DEADLINE, "{kept:?}");
        }
    }

    /// The test suites' raise reads only in a debug build, takes a positive
    /// number of milliseconds, and nothing else. The release build has no
    /// such variable (it is not compiled in), which is what keeps the test
    /// above true for what ships.
    #[cfg(debug_assertions)]
    #[test]
    fn the_test_raise_takes_only_a_positive_number() {
        assert_eq!(
            test_deadline_from(Some("120000")),
            Some(Duration::from_secs(120))
        );
        for ignored in [None, Some("0"), Some(""), Some("abc"), Some("-5")] {
            assert_eq!(test_deadline_from(ignored), None, "{ignored:?}");
        }
    }

    /// Never returns: each call keeps a frame the next one needs.
    #[allow(unconditional_recursion)]
    fn overflow_the_stack(depth: u64) -> u64 {
        let frame = std::hint::black_box([depth; 64]);
        overflow_the_stack(depth + 1) + frame[0]
    }

    const CHILD: &str = "INNERWARDEN_TEST_HOOK_NET_CHILD";
    /// Far past any end the net gives: a child still alive here was not ended.
    const GIVE_UP: Duration = Duration::from_secs(30);

    /// What the child does once the parent names an end.
    fn act_as_child(test: &str) {
        let Ok(asked) = std::env::var(CHILD) else {
            return;
        };
        let (mode, end) = asked.split_once(':').expect("mode:end");
        let monitor = mode == "monitor";
        match end {
            "overflow" => {
                arm_with(monitor, DEADLINE).expect("arm");
                std::hint::black_box(overflow_the_stack(0));
            }
            "abort" => {
                arm_with(monitor, DEADLINE).expect("arm");
                std::process::abort();
            }
            "stall" => {
                arm_with(monitor, Duration::from_millis(200)).expect("arm");
                loop {
                    std::hint::black_box(0u8);
                }
            }
            "queued-work" => {
                queued_work_as_child();
            }
            "json-stall" => {
                set_json_answer(true, monitor);
                arm_with(monitor, Duration::from_millis(200)).expect("arm");
                loop {
                    std::hint::black_box(0u8);
                }
            }
            "json-abort" => {
                set_json_answer(true, monitor);
                arm_with(monitor, DEADLINE).expect("arm");
                std::process::abort();
            }
            "allowed-wait" => {
                arm_with(monitor, Duration::from_millis(200)).expect("arm");
                allow_wait(Duration::from_secs(3));
                loop {
                    std::hint::black_box(0u8);
                }
            }
            "order" => {
                // The record of this child goes where its parent said
                // (`child_in`), a folder of its own.
                let dir = crate::graph_io::graph_path()
                    .and_then(|graph| graph.parent().map(std::path::Path::to_path_buf))
                    .expect("a record folder");
                arm_with(monitor, DEADLINE).expect("arm");
                after_answer_last(|| eprintln!("ran=rewire"));
                after_answer(|| eprintln!("ran=record"));
                after_answer(|| eprintln!("ran=alert"));
                answered(0);
                let marks = std::fs::read_dir(&dir)
                    .map(|entries| {
                        entries
                            .flatten()
                            .filter(|e| {
                                e.file_name()
                                    .to_string_lossy()
                                    .starts_with(".hook-pending.")
                            })
                            .count()
                    })
                    .unwrap_or(0);
                eprintln!("marks_left={marks}");
                std::process::exit(0)
            }
            "two-waits" => {
                arm_with(monitor, Duration::from_millis(200)).expect("arm");
                let first = allow_wait(crate::second_opinion_io::LLM_ANSWER_BOUND);
                let second = allow_wait(crate::second_opinion_io::LLM_ANSWER_BOUND);
                let small = allow_wait(Duration::from_millis(1));
                eprintln!(
                    "granted={first},{second},{small} wall_ms={}",
                    WALL_MS.load(Ordering::SeqCst)
                );
                std::process::exit(0)
            }
            other => panic!("{test}: unknown end {other}"),
        }
    }

    /// Pin this thread to one CPU, start four threads that spin on the same
    /// CPU, arm a 400 ms deadline with a 20 s limit on the clock, and do
    /// 150 ms of the screening thread's own CPU work. Most of the clock goes
    /// to waiting for that CPU. Says how long it took on the clock, and ends
    /// with 0 if the net let it finish.
    #[cfg(target_os = "linux")]
    fn queued_work_as_child() -> ! {
        // SAFETY: a zeroed cpu_set_t is an empty set; CPU_SET writes inside
        // it; sched_setaffinity(0, ..) pins the calling thread, and threads
        // started after it inherit the mask.
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(0, &mut set);
            assert_eq!(
                libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set),
                0
            );
        }
        for _ in 0..4 {
            std::thread::spawn(|| loop {
                std::hint::black_box(0u8);
            });
        }
        let cpu = || {
            // SAFETY: clock_gettime writes the timespec it is given.
            let mut now: libc::timespec = unsafe { std::mem::zeroed() };
            unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut now) };
            Duration::new(now.tv_sec as u64, now.tv_nsec as u32)
        };
        let started = Instant::now();
        arm_with_cap(false, Duration::from_millis(400), Duration::from_secs(20)).expect("arm");
        let at_arm = cpu();
        while cpu() - at_arm < Duration::from_millis(150) {
            std::hint::black_box(0u8);
        }
        eprintln!("wall_ms={}", started.elapsed().as_millis());
        std::process::exit(0)
    }

    #[cfg(not(target_os = "linux"))]
    fn queued_work_as_child() -> ! {
        std::process::exit(0)
    }

    /// Run this test again as a child told to end one way; its exit code,
    /// what it said, and how long it took.
    fn child(test: &str, asked: &str) -> (Option<i32>, String, Duration) {
        child_with(test, asked, None)
    }

    /// [`child`] with its record at `graph`.
    fn child_in(
        test: &str,
        asked: &str,
        graph: &std::path::Path,
    ) -> (Option<i32>, String, Duration) {
        child_with(test, asked, Some(graph))
    }

    fn child_with(
        test: &str,
        asked: &str,
        graph: Option<&std::path::Path>,
    ) -> (Option<i32>, String, Duration) {
        let started = Instant::now();
        let mut command = Command::new(std::env::current_exe().expect("test binary"));
        if let Some(graph) = graph {
            command.env("IW_GRAPH_FILE", graph);
        }
        let mut child = command
            .args([
                "--exact",
                &format!("hook_net::tests::{test}"),
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, asked)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run the child");
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait") {
                break status;
            }
            if started.elapsed() > GIVE_UP {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{asked}: the child was still running after {GIVE_UP:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let took = started.elapsed();
        let mut said = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = std::io::Read::read_to_string(&mut stderr, &mut said);
        }
        (status.code(), said, took)
    }

    /// [`child`], with what the child wrote on stdout as well.
    fn child_with_stdout(test: &str, asked: &str) -> (Option<i32>, String, String) {
        let out = tempfile::NamedTempFile::new().expect("a file for stdout");
        let mut child = Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                &format!("hook_net::tests::{test}"),
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, asked)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out.reopen().expect("reopen")))
            .stderr(Stdio::piped())
            .spawn()
            .expect("run the child");
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait") {
                break status;
            }
            if started.elapsed() > GIVE_UP {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{asked}: the child was still running after {GIVE_UP:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut said = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = std::io::Read::read_to_string(&mut stderr, &mut said);
        }
        let stdout = std::fs::read_to_string(out.path()).unwrap_or_default();
        (status.code(), stdout, said)
    }

    /// For an agent that reads only JSON on stdout (Antigravity), the
    /// deadline and a fault answer there, with exit 0: a deny in enforce, an
    /// allow in monitor, in the shape Antigravity reads.
    ///
    /// FAILS ON REVERT: take the `json_answer` arm out of `watch`, and the
    /// enforcing child ends with 2 and no decision on stdout.
    #[test]
    fn json_mode_answers_every_end_of_the_net_on_stdout() {
        const TEST: &str = "json_mode_answers_every_end_of_the_net_on_stdout";
        act_as_child(TEST);
        let mut ends = vec!["json-stall"];
        if cfg!(unix) {
            ends.push("json-abort");
        }
        for end in ends {
            for (mode, decision) in [("enforce", "deny"), ("monitor", "allow")] {
                let (code, stdout, said) = child_with_stdout(TEST, &format!("{mode}:{end}"));
                assert_eq!(code, Some(0), "{mode}:{end}: {said}");
                // The test harness names the test on stdout before the child's
                // answer, on the same line.
                let line = stdout
                    .lines()
                    .find_map(|line| line.find("{\"decision\"").map(|at| &line[at..]))
                    .unwrap_or_else(|| panic!("{mode}:{end}: no decision on stdout: {stdout:?}"));
                let answer: serde_json::Value = serde_json::from_str(line).expect("JSON");
                assert_eq!(answer["decision"], decision, "{mode}:{end}");
                assert!(!said.trim().is_empty(), "{mode}:{end}: stderr says why");
            }
        }
        let deny: serde_json::Value = serde_json::from_str(JSON_DENY.trim()).unwrap();
        assert!(deny["reason"]
            .as_str()
            .is_some_and(|r| r.contains("refusing it")));
    }

    /// A stack overflow and an abort while screening refuse the call (2) in
    /// enforce and are loud (1) in monitor. Proven in a child process that
    /// arms the net and then overflows its stack for real, or aborts.
    ///
    /// FAILS ON REVERT: without the handlers, or with a handler that has no
    /// stack of its own, the child ends on a signal and has no exit code.
    #[cfg(unix)]
    #[test]
    fn a_fault_while_screening_refuses_the_call() {
        const TEST: &str = "a_fault_while_screening_refuses_the_call";
        act_as_child(TEST);
        for end in ["overflow", "abort"] {
            for (mode, expected, says) in [
                (
                    "enforce",
                    2,
                    "refusing it rather than letting it run unscreened",
                ),
                ("monitor", 1, "it was NOT screened"),
            ] {
                let (code, said, _) = child(TEST, &format!("{mode}:{end}"));
                assert_eq!(code, Some(expected), "{mode}:{end}: {said}");
                assert!(
                    said.contains("a fault stopped the screening"),
                    "{mode}:{end}: {said}"
                );
                assert!(said.contains(says), "{mode}:{end}: {said}");
            }
        }
    }

    /// A screening still busy at the deadline refuses the call (2) in enforce
    /// and is loud (1) in monitor.
    ///
    /// FAILS ON REVERT: without the watchdog the child spins until this test
    /// gives up on it.
    #[test]
    fn a_screening_past_its_deadline_refuses_the_call() {
        const TEST: &str = "a_screening_past_its_deadline_refuses_the_call";
        act_as_child(TEST);
        for (mode, expected, says) in [
            (
                "enforce",
                2,
                "refusing it rather than letting it run unscreened",
            ),
            ("monitor", 1, "it was NOT screened"),
        ] {
            let (code, said, _) = child(TEST, &format!("{mode}:stall"));
            assert_eq!(code, Some(expected), "{mode}: {said}");
            assert!(said.contains("did not finish in time"), "{mode}: {said}");
            assert!(said.contains(says), "{mode}: {said}");
        }
    }

    /// Time the screening thread spent waiting for a CPU is not screening:
    /// a 400 ms deadline lets 150 ms of work finish though the CPU it runs on
    /// is shared with four spinning threads and the clock passes 400 ms.
    ///
    /// FAILS ON REVERT: count the clock alone (`since_armed` always zero)
    /// and the call is refused (2) at 400 ms on the clock.
    #[cfg(target_os = "linux")]
    #[test]
    fn time_spent_waiting_for_a_cpu_is_not_the_screenings() {
        const TEST: &str = "time_spent_waiting_for_a_cpu_is_not_the_screenings";
        act_as_child(TEST);
        let (code, said, _) = child(TEST, "enforce:queued-work");
        assert_eq!(code, Some(0), "{said}");
        let wall: u64 = said
            .lines()
            .find_map(|line| line.strip_prefix("wall_ms="))
            .and_then(|ms| ms.trim().parse().ok())
            .expect("the child says how long it took");
        assert!(
            wall > 400,
            "the work never waited for its CPU ({wall} ms), so this proves nothing"
        );
    }

    /// The pure rule: screening is the clock less the time queued, held to
    /// the deadline; the clock is held to its limit whatever was queued.
    #[test]
    fn the_deadline_is_the_screenings_and_the_clock_has_its_own_limit() {
        let ms = Duration::from_millis;
        let (deadline, cap) = (ms(1000), ms(5000));
        assert_eq!(
            time_left(ms(400), ms(0), deadline, cap, false),
            Some(ms(600))
        );
        // 3 s on the clock, 2.5 s of it queued: 500 ms of screening.
        assert_eq!(
            time_left(ms(3000), ms(2500), deadline, cap, false),
            Some(ms(500))
        );
        assert_eq!(time_left(ms(1000), ms(0), deadline, cap, false), None);
        // Queued or not, the clock's limit holds.
        assert_eq!(time_left(ms(5000), ms(4900), deadline, cap, false), None);
        assert_eq!(
            time_left(ms(4800), ms(4500), deadline, cap, false),
            Some(ms(200))
        );
        // Once answered, the screening is over: only the clock's limit holds.
        assert_eq!(
            time_left(ms(3000), ms(0), deadline, cap, true),
            Some(ms(2000))
        );
        assert_eq!(time_left(ms(5000), ms(0), deadline, cap, true), None);
        // A lowered deadline is also the clock's limit.
        assert_eq!(wall_cap_for(ms(300)), ms(300));
        assert_eq!(wall_cap_for(DEADLINE), WALL_CAP);
        // The limit on the clock and a second opinion's bound stay under the
        // wait `install` writes for Claude Code.
        use innerwarden_agent_guard::hook::HOOK_LONGEST_SECS;
        assert_eq!(
            WALL_CAP + crate::second_opinion_io::LLM_ANSWER_BOUND,
            Duration::from_secs(HOOK_LONGEST_SECS)
        );
    }

    /// A wait the hook bounds itself moves the deadline by its bound, and
    /// the call is still refused once that is behind too. With no deadline
    /// armed there is nothing to move.
    ///
    /// FAILS ON REVERT: with `allow_wait` doing nothing the child ends at
    /// its 200 ms and not after the 3 s it was allowed.
    /// Review of the hook deadline change, item d: the work kept for after
    /// the answer runs the record and the alert first, in the order they
    /// were kept, and bringing the wiring up to date last, though it was
    /// kept first; the mark beside the record is gone once all of it ran.
    ///
    /// FAILS ON REVERT of `after_answer_last` (the rewire kept in the same
    /// queue, first) and of taking the mark away (`record_pending::finish`).
    #[test]
    fn the_rewire_runs_after_the_record_and_the_alert() {
        const TEST: &str = "the_rewire_runs_after_the_record_and_the_alert";
        act_as_child(TEST);
        let dir = tempfile::tempdir().expect("folder");
        let (code, said, _) = child_in(TEST, "enforce:order", &dir.path().join("graph.json"));
        assert_eq!(code, Some(0), "{said}");
        let ran: Vec<&str> = said
            .lines()
            .filter_map(|line| line.strip_prefix("ran="))
            .collect();
        assert_eq!(ran, ["record", "alert", "rewire"], "{said}");
        assert!(said.contains("marks_left=0"), "{said}");
    }

    /// Review of the hook deadline change, item h: the waits of one run
    /// move the limits by one model's answer in all. A second line asking
    /// for another is refused (and keeps its review), so the limit on the
    /// clock stays under the 50 s Claude Code waits.
    ///
    /// FAILS ON REVERT of `MAX_ALLOWED_WAIT` in `allow_wait`: the second wait
    /// is granted and the limit on the clock is 40 s past the deadline.
    #[test]
    fn the_waits_of_one_run_move_the_limits_by_one_answer_in_all() {
        const TEST: &str = "the_waits_of_one_run_move_the_limits_by_one_answer_in_all";
        act_as_child(TEST);
        let (code, said, _) = child(TEST, "enforce:two-waits");
        assert_eq!(code, Some(0), "{said}");
        let expected = 200 + millis(crate::second_opinion_io::LLM_ANSWER_BOUND);
        assert!(
            said.contains(&format!("granted=true,false,false wall_ms={expected}")),
            "{said}"
        );
    }

    #[test]
    fn a_wait_the_hook_bounds_moves_the_deadline_by_its_bound() {
        const TEST: &str = "a_wait_the_hook_bounds_moves_the_deadline_by_its_bound";
        act_as_child(TEST);
        let (code, said, took) = child(TEST, "enforce:allowed-wait");
        assert_eq!(code, Some(2), "{said}");
        assert!(said.contains("did not finish in time"), "{said}");
        assert!(took >= Duration::from_secs(3), "ended after {took:?}");

        // This process never arms (only the children do): nothing to move.
        allow_wait(Duration::from_secs(3));
        assert_eq!(DEADLINE_MS.load(Ordering::SeqCst), 0);
    }

    /// Codex and Gemini run the tool when their hook does not answer in the
    /// time they were told to wait. The longest this hook takes to answer is
    /// its deadline plus the one wait it is allowed on top, the model's
    /// answer, so the time written into each agent's file is longer than
    /// that, in the agent's own unit.
    ///
    /// FAILS ON REVERT: write 10 for Codex (seconds) or 10000 for Gemini
    /// (milliseconds) and the agent gives up at the same moment as the
    /// deadline, before the refusal is out. Write Gemini's 60 in seconds'
    /// worth of digits and it waits 60 ms.
    #[test]
    fn each_agent_waits_longer_for_the_hook_than_the_hook_takes_to_refuse() {
        use innerwarden_agent_guard::agent_hooks::{CODEX, GEMINI};

        let longest = DEADLINE + crate::second_opinion_io::LLM_ANSWER_BOUND;
        assert_eq!(longest, Duration::from_secs(30));
        assert_eq!(CODEX.wait(), Duration::from_secs(60));
        assert_eq!(GEMINI.wait(), Duration::from_secs(60));
        for agent in [&CODEX, &GEMINI] {
            assert!(agent.wait() > longest, "{}", agent.agent);
        }
    }
}
