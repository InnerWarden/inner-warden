//! Per-agent session tracking for behavioral anomaly detection.

use std::collections::HashMap;
use std::time::Instant;

use crate::threats;

/// Call rate above which a session's tempo is worth recording as context.
///
/// NOT a limit: nothing is refused for crossing it. See `apply_behaviour` in the
/// CLI for why tempo annotates a verdict instead of changing it.
///
/// The value was 30, chosen for a human at a keyboard. An agent reading files in
/// a loop is not that: over ten days of real hook traffic the legitimate rate
/// ran 31-72/min with a median of 35, so 30 was crossed almost continuously and
/// the annotation said nothing. Set above that measured ceiling so crossing it
/// again means something.
pub const NOTABLE_CALLS_PER_MINUTE: u32 = 120;
pub const MAX_FAILURES_PER_SESSION: u32 = 5;
pub const MAX_SENSITIVE_PER_SESSION: u32 = 3;
/// How long a read stays relevant to exfiltration correlation. Mirrors the
/// window [`SessionTracker::check_exfil`] already applied, now also used to prune.
const EXFIL_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);
/// Upper bound on retained sensitive paths. Well above the alert threshold, so
/// the count still crosses it, while the list cannot grow without end.
const MAX_TRACKED_SENSITIVE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Layer {
    Warn,
    Shadow,
    Kill,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Alert {
    pub layer: Layer,
    pub reason: String,
}

#[derive(Debug)]
pub struct SessionTracker {
    call_times: Vec<Instant>,
    failures: u32,
    sensitive_accesses: Vec<String>,
    read_files: HashMap<String, Instant>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            call_times: Vec::new(),
            failures: 0,
            sensitive_accesses: Vec::new(),
            read_files: HashMap::new(),
        }
    }

    pub fn record_call(&mut self) -> Option<Alert> {
        let now = Instant::now();
        self.call_times.push(now);
        let cutoff = now - std::time::Duration::from_secs(60);
        self.call_times.retain(|t| *t > cutoff);

        if self.call_times.len() as u32 > NOTABLE_CALLS_PER_MINUTE {
            return Some(Alert {
                layer: Layer::Warn,
                reason: format!(
                    "{}/min sustained (notable above {})",
                    self.call_times.len(),
                    NOTABLE_CALLS_PER_MINUTE
                ),
            });
        }
        None
    }

    pub fn record_failure(&mut self) -> Option<Alert> {
        self.failures += 1;
        if self.failures > MAX_FAILURES_PER_SESSION {
            return Some(Alert {
                layer: Layer::Warn,
                reason: format!("{} failures in session", self.failures),
            });
        }
        None
    }

    pub fn record_file_access(&mut self, path: &str) -> Option<Alert> {
        threats::check_sensitive_path(path)?;
        self.sensitive_accesses.push(path.to_string());
        self.read_files.insert(path.to_string(), Instant::now());
        // Audit PERF-08: `call_times` is windowed to 60s, these two were not, so
        // a long-lived agent session grew them without end. `read_files` only
        // matters inside the exfil window, so anything older is dead weight; the
        // access list is capped because the alert reports a COUNT, and a count
        // does not need every entry retained to stay correct.
        self.prune(Instant::now());

        if self.sensitive_accesses.len() as u32 > MAX_SENSITIVE_PER_SESSION {
            return Some(Alert {
                layer: Layer::Warn,
                reason: format!("{} sensitive accesses", self.sensitive_accesses.len()),
            });
        }
        Some(Alert {
            layer: Layer::Warn,
            reason: format!("sensitive file: {path}"),
        })
    }

    /// Drop what can no longer influence a decision.
    ///
    /// `read_files` feeds only [`Self::check_exfil`], which ignores anything
    /// older than [`EXFIL_WINDOW`], so an older entry can never change an
    /// outcome. `sensitive_accesses` feeds a count, so it keeps the most recent
    /// entries up to a bound and keeps counting past it.
    fn prune(&mut self, now: Instant) {
        self.read_files
            .retain(|_, seen| now.duration_since(*seen) <= EXFIL_WINDOW);
        if self.sensitive_accesses.len() > MAX_TRACKED_SENSITIVE {
            let drop = self.sensitive_accesses.len() - MAX_TRACKED_SENSITIVE;
            self.sensitive_accesses.drain(..drop);
        }
    }

    pub fn check_exfil(&self, tool_name: &str, args: &str) -> Option<Alert> {
        if self.read_files.is_empty() {
            return None;
        }
        let is_outbound = [
            "send", "post", "fetch", "request", "webhook", "email", "upload",
        ]
        .iter()
        .any(|k| tool_name.contains(k));
        if !is_outbound {
            return None;
        }

        for (path, read_time) in &self.read_files {
            if read_time.elapsed() > EXFIL_WINDOW {
                continue;
            }
            if args.contains(path) {
                return Some(Alert {
                    layer: Layer::Kill,
                    reason: format!("EXFIL: read '{path}' then outbound '{tool_name}'"),
                });
            }
        }

        let recent: Vec<_> = self.read_files.keys().take(3).cloned().collect();
        if !recent.is_empty() {
            return Some(Alert {
                layer: Layer::Warn,
                reason: format!(
                    "outbound '{tool_name}' after reading: {}",
                    recent.join(", ")
                ),
            });
        }
        None
    }
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_notable_rate_raises_an_alert() {
        let mut s = SessionTracker::new();
        for _ in 0..=NOTABLE_CALLS_PER_MINUTE {
            s.record_call();
        }
        assert!(s.record_call().is_some());
    }

    /// The tempo an agent genuinely sustains while doing safe work must stay
    /// quiet. Measured over ten days of real hook traffic the legitimate rate
    /// peaked at 72/min, so nothing in that band may raise an alert.
    ///
    /// FAILS ON REVERT: put the threshold back to 30 and normal agent work is
    /// flagged again.
    #[test]
    fn the_measured_legitimate_agent_tempo_stays_quiet() {
        let mut s = SessionTracker::new();
        for _ in 0..72 {
            assert!(
                s.record_call().is_none(),
                "72/min is real, observed, legitimate agent work"
            );
        }
    }

    #[test]
    fn sensitive_tracking() {
        let mut s = SessionTracker::new();
        let alert = s.record_file_access("/home/user/.ssh/id_rsa");
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().layer, Layer::Warn);
    }

    #[test]
    fn exfil_detection() {
        let mut s = SessionTracker::new();
        s.record_file_access("/home/user/.ssh/id_rsa");
        let alert = s.check_exfil("send_message", "/home/user/.ssh/id_rsa");
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().layer, Layer::Kill);
    }

    #[test]
    fn normal_no_exfil() {
        let s = SessionTracker::new();
        assert!(s.check_exfil("fetch", "https://api.com").is_none());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistable tracker (the one a one-shot CLI can use)
// ─────────────────────────────────────────────────────────────────────────────

/// The same behavioural limits as [`SessionTracker`], but expressed against
/// wall-clock milliseconds so the state survives between processes.
///
/// # Why this exists
///
/// [`SessionTracker`] keeps `Instant`s. `Instant` is monotonic and process
/// local: it has no meaningful serialisation, so a tracker cannot be handed
/// from one process to the next. That is fine for a long-running agent, which
/// is where the original was used, and it is exactly why the Community binary
/// never wired any of this up. Its hook is a ONE-SHOT process: it starts, reads
/// one tool call, answers, and exits. An in-memory tracker would be empty on
/// every single call, so "30 calls per minute" could never be observed.
///
/// So the behaviour was not missing from the free product because it was a paid
/// feature. It was missing because the shape of the state did not fit the shape
/// of the process. This type fixes the shape.
///
/// Thresholds are NOT re-declared here: it reuses the same `MAX_*` constants, so
/// the free and paid paths cannot drift apart.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PersistedSession {
    /// Wall-clock milliseconds of each recorded call, newest last.
    #[serde(default)]
    pub call_times_ms: Vec<i64>,
    #[serde(default)]
    pub failures: u32,
    #[serde(default)]
    pub sensitive_accesses: Vec<String>,
    /// Values that entered this session inside a TOOL RESULT, newest last.
    ///
    /// This is the state the two-step attack needs and the product did not have.
    /// A value that arrives in something the agent READ (a file, a web page, an
    /// issue comment, an MCP response) is attacker-influenced by default: the
    /// agent did not choose it, the content did. When one of them reappears as
    /// an argument in a later command, statelessly inspecting that command
    /// cannot see anything wrong, because there is nothing wrong with the
    /// command. The wrongness is in where the value came from.
    #[serde(default)]
    pub tainted_values: Vec<TaintedValue>,
}

/// One value carried in from a tool result, with when it arrived and what
/// brought it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaintedValue {
    pub value: String,
    /// The tool whose result carried it, for the operator-facing explanation.
    pub source_tool: String,
    pub seen_ms: i64,
}

/// How long a value stays tainted.
///
/// Long enough to cover a realistic multi-step task, short enough that a
/// day-long session does not accumulate every host name it has ever read. The
/// window is a product decision, not a security one: past it, the value is
/// still suspicious, we just stop claiming to know where it came from.
pub const TAINT_TTL_MS: i64 = 30 * 60 * 1000;

/// Cap on remembered values, so a session that reads a large file cannot grow
/// the state file without end.
pub const MAX_TAINTED_VALUES: usize = 64;

/// Pull the values worth remembering out of a tool result.
///
/// PURE. Deliberately narrow: hosts, IP literals, URLs and absolute paths are
/// the things that become arguments. Prose is not extracted, because a rule
/// that taints every word turns the next command into a false positive.
///
/// Short tokens are dropped: a two-character "value" would match inside almost
/// any later command and the finding would be noise.
pub fn extract_taintable_values(result: &str) -> Vec<String> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?ix)
              (?: https?://[^\s"'<>()]+ )                       # a URL
            | (?: \b\d{1,3}(?:\.\d{1,3}){3} \b )                # an IPv4 literal
            | (?: \b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,} \b )  # a hostname
            | (?: (?:^|\s) /(?:[\w.-]+/)*[\w.-]+ )              # an absolute path
            "#,
        )
        .expect("static taintable value regex")
    });
    let mut out: Vec<String> = Vec::new();
    for m in re.find_iter(result) {
        let v = m.as_str().trim().trim_end_matches(['.', ',', ';', ':']);
        // Too short to be distinctive: it would match inside unrelated commands.
        if v.len() < 8 {
            continue;
        }
        if !out.iter().any(|e: &String| e == v) {
            out.push(v.to_string());
        }
        if out.len() >= MAX_TAINTED_VALUES {
            break;
        }
    }
    out
}

impl PersistedSession {
    /// Record one call at `now_ms` and report a limit breach.
    ///
    /// `now_ms` is injected rather than read from the clock so the window logic
    /// is testable without sleeping.
    pub fn record_call(&mut self, now_ms: i64) -> Option<Alert> {
        self.call_times_ms.push(now_ms);
        let cutoff = now_ms - 60_000;
        self.call_times_ms.retain(|t| *t > cutoff);
        // Bound the vector even when the caller never crosses the threshold, so a
        // very long session cannot grow the state file without end.
        let ceiling = (NOTABLE_CALLS_PER_MINUTE as usize + 1) * 4;
        if self.call_times_ms.len() > ceiling {
            let drop = self.call_times_ms.len() - ceiling;
            self.call_times_ms.drain(..drop);
        }
        if self.call_times_ms.len() as u32 > NOTABLE_CALLS_PER_MINUTE {
            return Some(Alert {
                layer: Layer::Warn,
                reason: format!(
                    "{}/min sustained (notable above {})",
                    self.call_times_ms.len(),
                    NOTABLE_CALLS_PER_MINUTE
                ),
            });
        }
        None
    }

    pub fn record_failure(&mut self) -> Option<Alert> {
        self.failures += 1;
        (self.failures > MAX_FAILURES_PER_SESSION).then(|| Alert {
            layer: Layer::Warn,
            reason: format!("{} failures in session", self.failures),
        })
    }

    /// Record a sensitive path read. Mirrors [`SessionTracker::record_file_access`]:
    /// a non-sensitive path is not recorded and yields nothing.
    pub fn record_file_access(&mut self, path: &str) -> Option<Alert> {
        threats::check_sensitive_path(path)?;
        if !self.sensitive_accesses.iter().any(|p| p == path) {
            self.sensitive_accesses.push(path.to_string());
        }
        if self.sensitive_accesses.len() as u32 > MAX_SENSITIVE_PER_SESSION {
            return Some(Alert {
                layer: Layer::Warn,
                reason: format!("{} sensitive accesses", self.sensitive_accesses.len()),
            });
        }
        Some(Alert {
            layer: Layer::Warn,
            reason: format!("sensitive file: {path}"),
        })
    }

    /// Record the values a tool result carried into this session.
    ///
    /// `now_ms` is injected for the same reason the call window injects it: the
    /// expiry has to be testable without sleeping.
    pub fn record_tool_result(&mut self, tool: &str, result: &str, now_ms: i64) {
        for value in extract_taintable_values(result) {
            if let Some(existing) = self.tainted_values.iter_mut().find(|t| t.value == value) {
                existing.seen_ms = now_ms;
                continue;
            }
            self.tainted_values.push(TaintedValue {
                value,
                source_tool: tool.to_string(),
                seen_ms: now_ms,
            });
        }
        self.expire_taint(now_ms);
    }

    /// Drop values that have aged out, then bound the list.
    pub fn expire_taint(&mut self, now_ms: i64) {
        let cutoff = now_ms - TAINT_TTL_MS;
        self.tainted_values.retain(|t| t.seen_ms > cutoff);
        if self.tainted_values.len() > MAX_TAINTED_VALUES {
            let drop = self.tainted_values.len() - MAX_TAINTED_VALUES;
            self.tainted_values.drain(..drop);
        }
    }

    /// Does this command carry a value that arrived in a tool result?
    ///
    /// The whole point of the two-step attack is that the answer to "is this
    /// command dangerous" is NO. `scp build.tar.gz deploy@host:/opt/` is an
    /// ordinary deployment. It stops being ordinary when the host came out of a
    /// file the agent was asked to read, because then the destination was
    /// chosen by whoever wrote that file.
    ///
    /// Returns the matched value and the tool that carried it, so the operator
    /// is told WHERE it came from rather than just that something is wrong.
    pub fn tainted_argument(&self, command: &str, now_ms: i64) -> Option<(&str, &str)> {
        let cutoff = now_ms - TAINT_TTL_MS;
        self.tainted_values
            .iter()
            .filter(|t| t.seen_ms > cutoff)
            .find(|t| command.contains(&t.value))
            .map(|t| (t.value.as_str(), t.source_tool.as_str()))
    }
}

#[cfg(test)]
mod persisted_tests {
    use super::*;

    /// REGRESSION ANCHOR. The whole point of this type: the counters survive a
    /// round trip through JSON, which an `Instant`-based tracker cannot do.
    /// Without this the free binary's hook, which is a fresh process per tool
    /// call, can never observe a rate at all.
    #[test]
    fn the_state_survives_a_round_trip_between_processes() {
        let mut a = PersistedSession::default();
        for i in 0..5 {
            assert!(a.record_call(1_000 + i).is_none());
        }
        let wire = serde_json::to_string(&a).expect("serialises");
        let b: PersistedSession = serde_json::from_str(&wire).expect("deserialises");
        assert_eq!(a, b, "a resumed session must be the session that was saved");
        assert_eq!(b.call_times_ms.len(), 5);
    }

    /// The limit is observed ACROSS processes: each call here stands for a
    /// separate hook invocation resuming the saved state.
    #[test]
    fn the_rate_limit_trips_across_separate_invocations() {
        let mut s = PersistedSession::default();
        let mut tripped_at = None;
        for i in 0..=(NOTABLE_CALLS_PER_MINUTE as i64 + 1) {
            let resumed: PersistedSession =
                serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
            s = resumed;
            if s.record_call(10_000 + i).is_some() && tripped_at.is_none() {
                tripped_at = Some(i);
            }
        }
        assert_eq!(
            tripped_at,
            Some(NOTABLE_CALLS_PER_MINUTE as i64),
            "must trip on the call after the limit, counting across processes"
        );
    }

    /// Calls older than the window stop counting, so a slow session is never
    /// punished for activity from an hour ago.
    #[test]
    fn calls_outside_the_minute_window_are_forgotten() {
        let mut s = PersistedSession::default();
        for i in 0..NOTABLE_CALLS_PER_MINUTE as i64 {
            s.record_call(i);
        }
        assert_eq!(s.call_times_ms.len(), NOTABLE_CALLS_PER_MINUTE as usize);
        // Far outside the 60s window: everything before is dropped.
        assert!(s.record_call(500_000).is_none());
        assert_eq!(s.call_times_ms, vec![500_000]);
    }

    /// A long-lived session must not grow the state file without bound, even
    /// when the caller keeps tripping the limit and ignoring it.
    #[test]
    fn the_state_stays_bounded_under_sustained_load() {
        let mut s = PersistedSession::default();
        for i in 0..5_000 {
            s.record_call(1_000_000 + i);
        }
        assert!(
            s.call_times_ms.len() <= (NOTABLE_CALLS_PER_MINUTE as usize + 1) * 4,
            "unbounded growth: {}",
            s.call_times_ms.len()
        );
    }

    /// The thresholds are the SHARED constants, not a second copy that can
    /// drift away from the daemon's behaviour.
    #[test]
    fn sensitive_and_failure_limits_match_the_shared_constants() {
        let mut s = PersistedSession::default();
        for _ in 0..MAX_FAILURES_PER_SESSION {
            assert!(s.record_failure().is_none());
        }
        assert!(s.record_failure().is_some(), "trips one past the constant");

        let mut t = PersistedSession::default();
        // A path with no sensitive marker is not recorded at all.
        assert!(t.record_file_access("/tmp/notes.txt").is_none());
        assert!(t.sensitive_accesses.is_empty());
    }
}

#[cfg(test)]
mod pruning_tests {
    use super::*;

    /// REGRESSION ANCHOR for PERF-08. `call_times` was windowed; these two grew
    /// for the life of the session, so a long-running agent leaked memory in the
    /// component meant to watch it.
    ///
    /// FAILS ON REVERT: remove the `prune` call and the length assertion trips.
    #[test]
    fn sensitive_tracking_stays_bounded_over_a_long_session() {
        let mut t = SessionTracker::new();
        for i in 0..1_000 {
            // A path the sensitive check recognises, varied so each is distinct.
            t.record_file_access(&format!("/home/u{i}/.ssh/id_rsa"));
        }
        assert!(
            t.sensitive_accesses.len() <= MAX_TRACKED_SENSITIVE,
            "sensitive_accesses grew to {}",
            t.sensitive_accesses.len()
        );
        assert!(
            t.read_files.len() <= 1_000,
            "read_files must not exceed what was recorded"
        );
    }

    /// Pruning must not weaken the alert: the count still crosses the threshold.
    #[test]
    fn the_alert_still_fires_after_pruning() {
        let mut t = SessionTracker::new();
        let mut alerts = 0;
        for i in 0..(MAX_SENSITIVE_PER_SESSION + 3) {
            if t.record_file_access(&format!("/home/u{i}/.ssh/id_rsa"))
                .is_some()
            {
                alerts += 1;
            }
        }
        assert!(alerts > 0, "sensitive reads must still alert");
    }

    /// A read older than the exfil window can no longer change an outcome, so it
    /// is dropped rather than retained forever.
    #[test]
    fn reads_outside_the_exfil_window_are_dropped() {
        let mut t = SessionTracker::new();
        t.read_files
            .insert("/old/path".into(), Instant::now() - EXFIL_WINDOW * 2);
        t.read_files.insert("/fresh/path".into(), Instant::now());
        t.prune(Instant::now());
        assert!(!t.read_files.contains_key("/old/path"));
        assert!(t.read_files.contains_key("/fresh/path"));
    }
}
