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

/// An agent for a listener on this host (InnerWarden Pro's agent, the
/// dashboard, `serve`), bounded by `timeout`, that never goes through a
/// proxy. ureq takes `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` from the
/// environment by default, and the MCP proxy, the OpenClaw guard and
/// `contain` run with the AI agent's: a proxy it named received every
/// refusal report and every command sent to Pro, and could drop or change
/// Pro's answer. A request to this host has no reason to leave it.
/// `status_as_error` as ureq reads it; `own_certificate` relaxes TLS
/// verification for a loopback listener that answers with a certificate of
/// its own (Pro's agent): a caller sets it only for a loopback url.
pub fn loopback_agent(
    timeout: Duration,
    status_as_error: bool,
    own_certificate: bool,
) -> ureq::Agent {
    let mut config = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(status_as_error)
        .proxy(None);
    if own_certificate {
        config = config.tls_config(
            ureq::tls::TlsConfig::builder()
                .disable_verification(true)
                .build(),
        );
    }
    config.build().into()
}

/// An agent for a request that carries what the guard read off this
/// machine (the second opinion, an alert), bounded by `timeout`, that goes
/// through `proxy` (from the account's own config) or straight to the
/// address, and never through a proxy the environment names. ureq takes
/// `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` from the environment by
/// default, and a hook runs with the AI agent's: a proxy it named received
/// the account's bearer key inside the CONNECT tunnel of an `http://` url.
/// `Err` with why when `proxy` is not a proxy url: then nothing is sent,
/// rather than sent around the proxy the person configured.
pub fn account_agent(timeout: Duration, proxy: Option<&str>) -> Result<ureq::Agent, String> {
    account_agent_with(timeout, proxy, true)
}

/// [`account_agent`] that hands back every status as a response instead of
/// an error, for a caller that reads the status itself (the second opinion
/// tells a busy 429 apart, with its Retry-After headers).
pub fn account_agent_reading_status(
    timeout: Duration,
    proxy: Option<&str>,
) -> Result<ureq::Agent, String> {
    account_agent_with(timeout, proxy, false)
}

fn account_agent_with(
    timeout: Duration,
    proxy: Option<&str>,
    status_as_error: bool,
) -> Result<ureq::Agent, String> {
    let proxy = match proxy.map(str::trim).filter(|proxy| !proxy.is_empty()) {
        None => None,
        Some(url) => Some(
            ureq::Proxy::new(url)
                .map_err(|e| format!("the configured proxy is not a proxy url ({e})"))?,
        ),
    };
    Ok(ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(status_as_error)
        .proxy(proxy)
        .build()
        .into())
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

    /// The agent that carries what the guard read takes no proxy from the
    /// environment, only the one it is given.
    #[test]
    fn the_account_agent_takes_its_proxy_only_from_the_config() {
        let direct = account_agent(Duration::from_millis(400), None).unwrap();
        assert!(direct.config().proxy().is_none());
        assert_eq!(
            direct.config().timeouts().global,
            Some(Duration::from_millis(400))
        );
        let configured =
            account_agent(Duration::from_millis(400), Some("http://127.0.0.1:3128")).unwrap();
        assert!(configured.config().proxy().is_some());
        assert!(account_agent(Duration::from_millis(400), Some("::not a url::")).is_err());
        assert!(direct.config().http_status_as_error());
        let reading = account_agent_reading_status(Duration::from_millis(400), None).unwrap();
        assert!(reading.config().proxy().is_none());
        assert!(!reading.config().http_status_as_error());
        assert!(
            account_agent_reading_status(Duration::from_millis(400), Some("::not a url::"))
                .is_err()
        );
    }

    /// The agent for this host's own listeners takes no proxy at all, and
    /// relaxes TLS only when asked to.
    #[test]
    fn the_loopback_agent_takes_no_proxy() {
        for (status_as_error, own_certificate) in
            [(true, false), (false, false), (false, true), (true, true)]
        {
            let agent =
                loopback_agent(Duration::from_millis(700), status_as_error, own_certificate);
            assert!(agent.config().proxy().is_none());
            assert_eq!(agent.config().http_status_as_error(), status_as_error);
            assert_eq!(
                agent.config().timeouts().global,
                Some(Duration::from_millis(700))
            );
            assert_eq!(
                agent.config().tls_config().disable_verification(),
                own_certificate
            );
        }
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
