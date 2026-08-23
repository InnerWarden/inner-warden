//! The one place this CLI builds an HTTP client.
//!
//! ureq 3 moved timeouts off the request builder and onto the agent, so
//! `ureq::get(url).timeout(d)` no longer exists. Every call site here had its own
//! timeout for a stated reason (400ms because it runs inside the command a
//! beginner reaches for when something already feels wrong; 700ms for a liveness
//! probe; 20s for an LLM round trip), so the migration keeps each one rather than
//! collapsing them to a single default.
//!
//! It also centralises the thing that is easy to get wrong twice: ureq 3 turns
//! 4xx/5xx into `Error::StatusCode` by default, and the old code matched
//! `Error::Status(code, _)` / `Error::Transport(_)` as an exhaustive pair. The
//! new enum has ten variants, so "everything that is not a status" has to be a
//! catch-all or a future ureq release silently changes behaviour at a `match`
//! that still compiles.

use std::time::Duration;

/// An agent whose every request is bounded by `timeout`.
///
/// `timeout_global` covers the whole request including connect, TLS, headers and
/// body, which is what each of these call sites actually wanted: the old
/// `.timeout()` on the request builder was the same total bound.
pub fn agent_with_timeout(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .build()
        .into()
}

/// Did the server answer at all, whatever it answered?
///
/// A 4xx or 5xx is still an answer: something is listening and speaking HTTP.
/// Only a transport failure means nobody is there. ureq 2 expressed this as a
/// two-variant match; in ureq 3 the status case is one variant and everything
/// else is a transport-ish failure, so the question is asked directly instead of
/// being spelled out as a list that will rot.
pub fn is_an_answer<T>(result: &Result<T, ureq::Error>) -> bool {
    matches!(result, Ok(_) | Err(ureq::Error::StatusCode(_)))
}

/// The HTTP status a failed call carried, if it carried one.
pub fn status_of(err: &ureq::Error) -> Option<u16> {
    match err {
        ureq::Error::StatusCode(code) => Some(*code),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The distinction the liveness probes are built on: a status error means
    /// somebody answered. Folding it in with transport errors would report a
    /// live-but-unhappy dashboard as absent, which is what the probe exists to
    /// tell apart.
    #[test]
    fn a_status_error_is_an_answer_and_a_transport_error_is_not() {
        let status: Result<(), ureq::Error> = Err(ureq::Error::StatusCode(503));
        let gone: Result<(), ureq::Error> = Err(ureq::Error::HostNotFound);
        let ok: Result<(), ureq::Error> = Ok(());

        assert!(is_an_answer(&ok));
        assert!(
            is_an_answer(&status),
            "a 503 means something is listening and speaking HTTP"
        );
        assert!(
            !is_an_answer(&gone),
            "an unresolvable host means nobody answered"
        );
    }

    /// `status_of` must not invent a code for errors that never had one. The
    /// caller prints it to the operator, and "returned HTTP 0" is worse than
    /// saying the transport failed.
    #[test]
    fn only_a_status_error_carries_a_status() {
        assert_eq!(status_of(&ureq::Error::StatusCode(404)), Some(404));
        assert_eq!(status_of(&ureq::Error::HostNotFound), None);
        assert_eq!(status_of(&ureq::Error::RedirectFailed), None);
    }

    /// The agent is the only thing carrying the bound now, so a builder that
    /// silently dropped it would leave every probe unbounded. Reading the
    /// config back is the only way to see that from a test.
    #[test]
    fn the_agent_actually_carries_the_timeout_it_was_given() {
        let agent = agent_with_timeout(Duration::from_millis(400));
        assert_eq!(
            agent.config().timeouts().global,
            Some(Duration::from_millis(400)),
            "ureq 3 holds the bound on the agent; a dropped one is an unbounded probe"
        );
    }
}
