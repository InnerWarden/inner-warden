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

static MONITOR: AtomicBool = AtomicBool::new(false);

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
    let queue = RunQueue::of_this_thread();
    let armed = Instant::now();
    DEADLINE_MS.store(millis(deadline).max(1), Ordering::SeqCst);
    WALL_MS.store(millis(cap).max(1), Ordering::SeqCst);
    std::thread::Builder::new()
        .name("hook-deadline".into())
        .spawn(move || watch(armed, &queue))
        .map(|_| ())
        .map_err(|_| "no screening deadline could be set")
}

/// The hook is about to make a wait it bounds itself by `bound`: move the
/// deadline and the limit on the clock by as much. Nothing to move when no
/// deadline is armed (the same code runs under `innerwarden check`).
/// From here on the net ends the run as monitor does, never with a
/// refusal: for a run that turned out to carry no tool call (the person's
/// prompt), where a refusal would drop what the person typed.
pub fn never_refuse() {
    MONITOR.store(true, Ordering::SeqCst);
}

pub fn allow_wait(bound: Duration) {
    for limit in [&DEADLINE_MS, &WALL_MS] {
        let _ = limit.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |armed| {
            (armed != 0).then(|| armed.saturating_add(millis(bound)))
        });
    }
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
/// to `deadline`; the clock is held to `cap` whatever was queued.
fn time_left(
    wall: Duration,
    queued: Duration,
    deadline: Duration,
    cap: Duration,
) -> Option<Duration> {
    let screening = wall.saturating_sub(queued);
    let left = deadline.checked_sub(screening)?.min(cap.checked_sub(wall)?);
    (!left.is_zero()).then_some(left)
}

/// Sleep to the deadline, read it again (a wait may have moved it, time
/// spent waiting for a CPU puts it later), end the hook once it is behind.
fn watch(armed: Instant, queue: &RunQueue) -> ! {
    loop {
        let deadline = Duration::from_millis(DEADLINE_MS.load(Ordering::SeqCst));
        let cap = Duration::from_millis(WALL_MS.load(Ordering::SeqCst));
        match time_left(armed.elapsed(), queue.since_armed(), deadline, cap) {
            Some(left) => std::thread::sleep(left.max(Duration::from_millis(1))),
            None => {
                if MONITOR.load(Ordering::SeqCst) {
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
        if super::MONITOR.load(Ordering::SeqCst) {
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
        use innerwarden_agent_guard::agent_hooks::{CODEX, GEMINI, GUARD_DEADLINE_SECS};
        assert_eq!(DEADLINE, Duration::from_secs(GUARD_DEADLINE_SECS));
        let second_opinion = crate::second_opinion_io::LLM_ANSWER_BOUND;
        for spec in [&CODEX, &GEMINI] {
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
            "allowed-wait" => {
                arm_with(monitor, Duration::from_millis(200)).expect("arm");
                allow_wait(Duration::from_secs(3));
                loop {
                    std::hint::black_box(0u8);
                }
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
        let started = Instant::now();
        let mut child = Command::new(std::env::current_exe().expect("test binary"))
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
        assert_eq!(time_left(ms(400), ms(0), deadline, cap), Some(ms(600)));
        // 3 s on the clock, 2.5 s of it queued: 500 ms of screening.
        assert_eq!(time_left(ms(3000), ms(2500), deadline, cap), Some(ms(500)));
        assert_eq!(time_left(ms(1000), ms(0), deadline, cap), None);
        // Queued or not, the clock's limit holds.
        assert_eq!(time_left(ms(5000), ms(4900), deadline, cap), None);
        assert_eq!(time_left(ms(4800), ms(4500), deadline, cap), Some(ms(200)));
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
