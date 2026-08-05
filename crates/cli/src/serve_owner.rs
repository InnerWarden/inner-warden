//! Who owns the check-command contract on this machine.
//!
//! # Why a bind failure needs an explanation
//!
//! `POST /api/agent/check-command` is a CONTRACT, not a feature of one product.
//! The Community `serve` answers it on `127.0.0.1:8787`, and an Active Defence
//! agent answers the same route on `0.0.0.0:8787`. Since `0.0.0.0` includes the
//! loopback, the two do not share the port: whichever starts first takes it.
//!
//! On a machine that has both, `serve` failed with a bare "address already in
//! use", which reads like a stray process to kill. It is not. It is the paid
//! agent already serving the contract, with MORE context than this process
//! could, and the right move is to leave it alone.
//!
//! So a bind failure on the contract port asks the obvious question before
//! reporting an error: is something already answering the contract? If yes, say
//! so and stand down. If no, report the ordinary failure.

/// The port the check-command contract lives on, whichever product serves it.
pub const CONTRACT_PORT: u16 = 8787;

/// What a bind failure on the contract port means.
#[derive(Debug, PartialEq, Eq)]
pub enum BindFailure {
    /// Something is already answering the contract here. Not an error to fix.
    ContractAlreadyServed,
    /// An ordinary bind failure: a stray process, a permission problem.
    Unavailable,
}

/// Is `bind` the contract port, on any local address?
///
/// Pure so the rule is testable without a socket.
pub fn is_contract_port(bind: &str) -> bool {
    bind.rsplit(':')
        .next()
        .and_then(|p| p.trim().parse::<u16>().ok())
        .map(|p| p == CONTRACT_PORT)
        .unwrap_or(false)
}

/// Classify a bind failure, given whether the contract answered a probe.
///
/// Separated from the probe itself so the decision is unit-testable and the I/O
/// stays a thin shell.
pub fn classify(bind: &str, contract_answered: bool) -> BindFailure {
    if is_contract_port(bind) && contract_answered {
        BindFailure::ContractAlreadyServed
    } else {
        BindFailure::Unavailable
    }
}

/// Probe the contract endpoint to see whether something already answers it.
///
/// Any response at all counts, including an auth challenge: a 401 from the paid
/// agent means the contract IS served, by something that wants a credential this
/// process does not have. Treating that as "nothing there" is how two servers
/// end up fighting over one port.
pub fn contract_answers(bind: &str) -> bool {
    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{bind}/api/agent/check-command");
        match ureq::post(&url)
            .timeout(std::time::Duration::from_millis(700))
            .send_json(serde_json::json!({"command": ""}))
        {
            Ok(_) => return true,
            // A status error is still an answer: something is listening.
            Err(ureq::Error::Status(_, _)) => return true,
            Err(_) => continue,
        }
    }
    false
}

/// The message for an operator whose `serve` could not take the port.
pub fn explain(failure: &BindFailure, bind: &str, io_error: &str) -> String {
    match failure {
        BindFailure::ContractAlreadyServed => format!(
            "innerwarden: {bind} is already serving /api/agent/check-command.\n  \
             That is InnerWarden Active Defence, which answers the same contract with host \
             context this process does not have. Nothing to fix, and nothing to start.\n  \
             To run a second, separate screener anyway:  innerwarden serve --bind 127.0.0.1:8790"
        ),
        BindFailure::Unavailable => {
            format!("innerwarden: failed to bind {bind}: {io_error}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_contract_port_is_recognised_on_any_local_address() {
        assert!(is_contract_port("127.0.0.1:8787"));
        assert!(is_contract_port("0.0.0.0:8787"));
        assert!(is_contract_port("[::1]:8787"));
        assert!(!is_contract_port("127.0.0.1:8788"));
        assert!(!is_contract_port("127.0.0.1"));
        assert!(!is_contract_port(""));
    }

    /// REGRESSION ANCHOR. On a machine with Active Defence, `serve` reported a
    /// bare "address already in use", which reads as a stray process to kill.
    /// The paid agent serving the same contract is not a fault.
    ///
    /// FAILS ON REVERT: classify every failure as `Unavailable` and this trips.
    #[test]
    fn a_served_contract_is_not_reported_as_a_fault() {
        let f = classify("127.0.0.1:8787", true);
        assert_eq!(f, BindFailure::ContractAlreadyServed);
        let msg = explain(&f, "127.0.0.1:8787", "address in use");
        assert!(msg.contains("already serving"));
        assert!(msg.contains("Active Defence"), "must name what owns it");
        assert!(msg.contains("Nothing to fix"));
        assert!(
            msg.contains("--bind"),
            "must offer the way to run a second one anyway"
        );
    }

    /// A bind failure with nothing answering is an ordinary failure and must
    /// keep its original message, not be explained away as a healthy machine.
    #[test]
    fn an_unanswered_port_stays_an_ordinary_failure() {
        let f = classify("127.0.0.1:8787", false);
        assert_eq!(f, BindFailure::Unavailable);
        let msg = explain(&f, "127.0.0.1:8787", "permission denied");
        assert!(msg.contains("failed to bind"));
        assert!(msg.contains("permission denied"), "keeps the real cause");
    }

    /// A different port is never the contract, even if something answers there.
    #[test]
    fn another_port_is_never_the_contract() {
        assert_eq!(
            classify("127.0.0.1:9999", true),
            BindFailure::Unavailable,
            "only the contract port gets the contract explanation"
        );
    }
}
