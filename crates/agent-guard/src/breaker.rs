//! Identical-call loop breaker for the MCP proxy.
//!
//! A hijacked or looping agent can re-issue the same tool call in a tight retry
//! storm: the same sub-goal re-planned every iteration, each iteration another
//! call against a real system. This breaker counts identical tool calls (same
//! tool, same arguments) in a sliding window and trips on a repeat once that
//! exact call was already made `max_identical_calls` times in the last
//! `window_secs` seconds. The proxy turns a trip into a finding on that call;
//! its mode decides whether the call is refused (guard) or only flagged
//! (advisory).
//!
//! It was first written as a per-run object with a lifetime count and a sticky,
//! global trip, but the proxy keeps one breaker for its whole life. One loop of
//! four identical calls then tripped every later call, whatever it was, until
//! the proxy restarted, and every distinct call it had ever seen stayed in
//! memory with its full arguments. So the breaker is now:
//!
//! * **Windowed.** Only calls inside the window count, and a trip covers the
//!   call it was raised on and nothing after it. A tripped repeat does not fill
//!   the window itself, so a call is accepted again at most `window_secs` after
//!   the oldest of the calls that filled it.
//! * **Per call.** A loop on one call never trips a different call.
//! * **Bounded.** A call is remembered by a keyed 64-bit hash, never by its
//!   arguments; each holds at most `max_identical_calls` timestamps; at most
//!   `max_tracked_calls` are tracked, the least recently seen forgotten first.
//!
//! Pure: no I/O, and the caller hands in the clock, so every rule above is
//! unit-tested without waiting.
//!
//! It sees tool calls, not model spend. A spend ceiling belongs where the spend
//! is metered (the model gateway), not in a pipe that cannot price a call.
//!
//! OWASP mapping: loop amplification is ASI02 (Tool Misuse & Exploitation) and
//! ASI08 (Cascading Failures), see `OWASP-AGENTIC-TOP-10.md`. The finding the
//! proxy raises keeps its original id, `AG-ASI09-BREAKER`, because recorded
//! decisions, and any alert rule written against them, already carry it. The
//! finding itself names ASI02 and ASI08 (`crate::asi::LOOP_BREAKER_ASI`), so
//! the record and the case classify a loop by what it is, not by its id.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;

/// Limits for one breaker. The defaults are the product's policy.
#[derive(Debug, Clone)]
pub struct BreakerConfig {
    /// How many identical calls the window accepts. The next identical call
    /// inside the window trips.
    pub max_identical_calls: u32,
    /// The sliding window, in seconds.
    pub window_secs: u64,
    /// The most distinct calls tracked at once. Past it, the least recently
    /// seen call is forgotten. Bounds memory for a long-lived proxy.
    pub max_tracked_calls: usize,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            max_identical_calls: 3,
            window_secs: 60,
            max_tracked_calls: 1024,
        }
    }
}

/// The breaker's decision for one call.
#[derive(Debug, Clone, PartialEq)]
pub enum BreakerVerdict {
    /// Not a fast repeat.
    Ok,
    /// A fast repeat of a call already made the maximum number of times inside
    /// the window. `reason` is the plain-words cause.
    Tripped { reason: String },
}

impl BreakerVerdict {
    pub fn is_tripped(&self) -> bool {
        matches!(self, BreakerVerdict::Tripped { .. })
    }
}

/// What the breaker remembers about one call.
#[derive(Debug, Clone, Default)]
struct Recent {
    /// When the call was made and not tripped, oldest first. Never longer than
    /// `max_identical_calls`.
    accepted: VecDeque<u64>,
    /// When the call was last seen at all, tripped or not, as a position in
    /// the breaker's own sequence of calls (unique, so forgetting is
    /// deterministic even when many calls share a second).
    last_touch: u64,
}

/// Windowed loop guard. One instance per proxy session.
#[derive(Debug, Clone)]
pub struct Breaker {
    config: BreakerConfig,
    /// Keys the call hashes with a per-breaker random key, so the hash cannot
    /// be steered from outside to make two different calls collide.
    hasher: RandomState,
    calls: HashMap<u64, Recent>,
    /// Calls recorded so far; orders `Recent::last_touch`.
    touches: u64,
}

impl Breaker {
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            hasher: RandomState::new(),
            calls: HashMap::new(),
            touches: 0,
        }
    }

    /// Record one call: its signature (tool name plus arguments, so an identical
    /// re-plan collides and a different call does not) and `now_secs`, a
    /// monotonic clock in seconds. Returns the verdict for THIS call only.
    pub fn record(&mut self, call_signature: &str, now_secs: u64) -> BreakerVerdict {
        let key = self.hasher.hash_one(call_signature);
        if !self.calls.contains_key(&key) {
            self.make_room(now_secs);
        }
        let window = self.config.window_secs;
        let limit = self.config.max_identical_calls as usize;
        self.touches += 1;
        let recent = self.calls.entry(key).or_default();
        recent.last_touch = self.touches;
        recent.accepted.retain(|&at| is_live(at, now_secs, window));
        if recent.accepted.len() >= limit {
            // When the oldest accepted call leaves the window, one more of
            // these is accepted. Said in the reason, because an agent told only
            // that its call was refused reads the refusal as permanent and
            // gives up on a job a retry half a minute later would finish.
            let accepted_again_in = recent
                .accepted
                .front()
                .map_or(window, |&oldest| (oldest + window).saturating_sub(now_secs))
                .max(1);
            return BreakerVerdict::Tripped {
                reason: format!(
                    "identical tool call (same tool, same arguments) already made {limit} times \
                     in the last {window} s, the pattern of a runaway loop; the breaker accepts \
                     this same call again in {accepted_again_in} s, and does not hold back any \
                     other call"
                ),
            };
        }
        recent.accepted.push_back(now_secs);
        BreakerVerdict::Ok
    }

    /// Before tracking a new call at the cap: drop every call with nothing left
    /// inside the window (it holds no state), and if the table is still full,
    /// forget the call seen least recently. A call that keeps being repeated
    /// keeps its place, so forgetting it takes a flood of distinct calls, and
    /// distinct calls already pass the breaker by design.
    fn make_room(&mut self, now_secs: u64) {
        let cap = self.config.max_tracked_calls.max(1);
        if self.calls.len() < cap {
            return;
        }
        let window = self.config.window_secs;
        // One pass: drop the expired, and note the least recently seen of the
        // rest in case dropping the expired was not enough.
        let mut least_recent: Option<(u64, u64)> = None;
        self.calls.retain(|&key, recent| {
            let live = recent
                .accepted
                .iter()
                .any(|&at| is_live(at, now_secs, window));
            if live && least_recent.is_none_or(|(touch, _)| recent.last_touch < touch) {
                least_recent = Some((recent.last_touch, key));
            }
            live
        });
        if self.calls.len() >= cap {
            if let Some((_, key)) = least_recent {
                self.calls.remove(&key);
            }
        }
    }
}

/// A call made at `at` still counts at `now`. A clock that reads earlier than
/// a recorded call keeps it counting: a wrong clock never releases a loop.
fn is_live(at: u64, now: u64, window: u64) -> bool {
    now.saturating_sub(at) < window
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breaker(max_identical_calls: u32, max_tracked_calls: usize) -> Breaker {
        Breaker::new(BreakerConfig {
            max_identical_calls,
            window_secs: 60,
            max_tracked_calls,
        })
    }

    fn reason(verdict: BreakerVerdict) -> String {
        match verdict {
            BreakerVerdict::Tripped { reason } => reason,
            BreakerVerdict::Ok => panic!("expected a trip, got Ok"),
        }
    }

    #[test]
    fn the_default_policy_is_three_calls_a_minute() {
        let config = BreakerConfig::default();
        assert_eq!(config.max_identical_calls, 3);
        assert_eq!(config.window_secs, 60);
        assert_eq!(config.max_tracked_calls, 1024);
    }

    #[test]
    fn a_loop_trips_inside_the_window_and_releases_after_it() {
        let mut b = Breaker::new(BreakerConfig::default());
        for t in 0..3 {
            assert_eq!(b.record("search(same)", t), BreakerVerdict::Ok, "t={t}");
        }
        let why = reason(b.record("search(same)", 3));
        assert!(
            why.contains("already made 3 times in the last 60 s"),
            "the reason must say what was counted: {why}"
        );
        // ...and when the same call is accepted again: the oldest accepted
        // call (t=0) leaves the window at t=60, 57 s after this trip.
        assert!(
            why.contains("accepts this same call again in 57 s"),
            "the reason must say when it ends: {why}"
        );
        // The first accepted call (t=0) is a full window old at t=60, so one
        // repeat is accepted again; the trip at t=3 did not hold it shut.
        assert_eq!(b.record("search(same)", 60), BreakerVerdict::Ok);
        assert_eq!(b.record("search(same)", 64), BreakerVerdict::Ok);
    }

    #[test]
    fn a_trip_never_trips_a_different_call() {
        let mut b = Breaker::new(BreakerConfig::default());
        for t in 0..3 {
            assert_eq!(b.record("read(a)", t), BreakerVerdict::Ok);
        }
        assert!(b.record("read(a)", 3).is_tripped());
        assert_eq!(b.record("read(b)", 4), BreakerVerdict::Ok);
        assert_eq!(b.record("list()", 4), BreakerVerdict::Ok);
    }

    #[test]
    fn three_identical_calls_a_minute_apart_never_trip() {
        let mut b = Breaker::new(BreakerConfig::default());
        for t in [0, 61, 122, 183, 244, 305] {
            assert_eq!(b.record("status()", t), BreakerVerdict::Ok, "t={t}");
        }
    }

    #[test]
    fn a_tight_loop_keeps_tripping_while_it_loops() {
        // The attacker form: ten identical calls in ten seconds. The window lets
        // three through and trips every repeat after them; tripped repeats are
        // not let through later in the same window.
        let mut b = Breaker::new(BreakerConfig::default());
        let verdicts: Vec<bool> = (0..10)
            .map(|t| b.record("transfer(acct=1)", t).is_tripped())
            .collect();
        assert_eq!(
            verdicts,
            [false, false, false, true, true, true, true, true, true, true]
        );
        // Still looping at t=59: still tripped.
        assert!(b.record("transfer(acct=1)", 59).is_tripped());
    }

    #[test]
    fn a_steady_loop_gets_at_most_the_window_through() {
        // One identical call every 5 s for 10 minutes: never more than three
        // accepted in any 60 s, and never shut for good.
        let mut b = Breaker::new(BreakerConfig::default());
        let accepted: Vec<u64> = (0..120)
            .map(|i| i * 5)
            .filter(|&t| !b.record("poll()", t).is_tripped())
            .collect();
        for (i, &t) in accepted.iter().enumerate() {
            let in_window = accepted[i..].iter().take_while(|&&u| u < t + 60).count();
            assert!(
                in_window <= 3,
                "more than 3 accepted from t={t}: {accepted:?}"
            );
        }
        assert_eq!(
            accepted.len(),
            30,
            "three a minute, every minute: {accepted:?}"
        );
    }

    #[test]
    fn the_tracked_calls_are_bounded() {
        // The worst case: a flood of distinct calls (a write_file per file)
        // all inside one window, so nothing expires and only the cap holds.
        let mut b = Breaker::new(BreakerConfig::default());
        for i in 0..20_000u64 {
            let sig = format!("write_file({{\"path\":\"/tmp/{i}\",\"content\":\"{i}\"}})");
            assert_eq!(b.record(&sig, i / 1000), BreakerVerdict::Ok);
            assert!(
                b.calls.len() <= 1024,
                "{} tracked at call {i}",
                b.calls.len()
            );
        }
        for recent in b.calls.values() {
            assert!(recent.accepted.len() <= 3);
        }
    }

    #[test]
    fn a_call_with_nothing_left_in_the_window_is_dropped_first() {
        let mut b = breaker(3, 2);
        assert_eq!(b.record("old()", 0), BreakerVerdict::Ok);
        for t in [100, 101, 102] {
            assert_eq!(b.record("busy()", t), BreakerVerdict::Ok);
        }
        // Full table; old() expired long ago, so it goes, not busy().
        assert_eq!(b.record("new()", 103), BreakerVerdict::Ok);
        assert!(b.record("busy()", 104).is_tripped());
    }

    #[test]
    fn a_call_being_repeated_is_the_last_to_be_forgotten() {
        // x() was accepted first, but it is the one still being repeated; the
        // table must forget y() rather than x(), or a loop would be released by
        // a single unrelated call.
        let mut b = breaker(1, 2);
        assert_eq!(b.record("x()", 0), BreakerVerdict::Ok);
        assert_eq!(b.record("y()", 1), BreakerVerdict::Ok);
        assert!(b.record("x()", 2).is_tripped());
        assert_eq!(b.record("z()", 3), BreakerVerdict::Ok);
        assert!(
            b.record("x()", 4).is_tripped(),
            "the repeated call was forgotten"
        );
        // y() was forgotten, so it starts fresh.
        assert_eq!(b.record("y()", 5), BreakerVerdict::Ok);
    }

    /// D4: the breaker is never permanent, so its refusal must not read as
    /// permanent either. An agent polling a job every 10 s is told when its
    /// poll is accepted again, and that time is when it is.
    ///
    /// FAILS ON REVERT: drop the time from the reason and the agent is told
    /// only that its call was refused.
    #[test]
    fn a_trip_says_when_the_same_call_is_accepted_again() {
        let mut b = Breaker::new(BreakerConfig::default());
        for t in [0, 10, 20] {
            assert_eq!(
                b.record("get_job_status({\"id\":7})", t),
                BreakerVerdict::Ok
            );
        }
        let why = reason(b.record("get_job_status({\"id\":7})", 30));
        assert!(why.contains("again in 30 s"), "{why}");
        assert!(why.contains("does not hold back any other call"), "{why}");
        let why = reason(b.record("get_job_status({\"id\":7})", 59));
        assert!(why.contains("again in 1 s"), "{why}");
        // And it is: at t=60 the call at t=0 has left the window.
        assert_eq!(
            b.record("get_job_status({\"id\":7})", 60),
            BreakerVerdict::Ok
        );
        // A clock that reads earlier than the calls never says "now".
        let why = reason(b.record("get_job_status({\"id\":7})", 5));
        assert!(why.contains("again in 65 s"), "{why}");
    }

    #[test]
    fn a_clock_that_reads_earlier_never_releases_a_loop() {
        let mut b = Breaker::new(BreakerConfig::default());
        for t in [100, 101, 102] {
            assert_eq!(b.record("same()", t), BreakerVerdict::Ok);
        }
        assert!(b.record("same()", 50).is_tripped());
    }
}
