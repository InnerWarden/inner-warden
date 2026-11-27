//! The proxy asks its server to stop with SIGTERM (see the transport's
//! "Lifetime"), so the server must be able to receive it, whatever the
//! process that started the proxy set SIGTERM to.
//!
//! A disposition of "ignored" is kept across exec, and a shell cannot trap a
//! signal that was ignored when it started. A proxy started with SIGTERM
//! ignored handed that to its server: the request to stop did nothing, and
//! the server lived until the SIGKILL after the grace, its own shutdown never
//! run. On the macOS runner this is what the transport test that proves the
//! request is sent saw twice: the server's trap never wrote (grace of 5 s),
//! and its `sleep 60` outlived a grace of an hour.
//!
//! This binary holds this one test, because it sets SIGTERM to ignored for
//! its whole process. Proved without a clock: the server sends itself
//! SIGTERM, and a server that can receive it never writes that it survived.

#![cfg(unix)]

use innerwarden_agent_guard::mcp_proxy::enforce::ProxyMode;
use innerwarden_agent_guard::mcp_proxy::router::ProxyDecision;
use innerwarden_agent_guard::mcp_proxy::transport::{run_proxy_with_io, ProxyConfig};

/// FAILS ON REVERT: drop the reset of SIGTERM in the server's spawn and the
/// server writes that it survived its own SIGTERM.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_can_receive_the_stop_request_when_the_proxy_ignores_sigterm() {
    // SAFETY: only reads and sets this process's SIGTERM disposition; no
    // other test runs in this binary.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
        let mut current: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut current);
        assert_eq!(current.sa_sigaction, libc::SIG_IGN, "the setup holds");
    }
    let dir = tempfile::tempdir().unwrap();
    let started = dir.path().join("started");
    let survived = dir.path().join("survived");
    let script = r#"echo yes > "$1"; kill -TERM $$; echo yes > "$2""#;
    let (_to_proxy, proxy_in) = tokio::io::duplex(16384);
    let (proxy_out, _from_proxy) = tokio::io::duplex(16384);
    let ended = run_proxy_with_io(
        proxy_in,
        proxy_out,
        ProxyConfig {
            server_cmd: vec![
                "sh".into(),
                "-c".into(),
                script.into(),
                "sh".into(),
                started.display().to_string(),
                survived.display().to_string(),
            ],
            mode: ProxyMode::Advisory,
            as_protocol_error: false,
        },
        None,
        |_d: &ProxyDecision| {},
    )
    .await;
    assert!(ended.is_ok(), "{ended:?}");
    assert!(started.exists(), "the server ran");
    assert!(
        !survived.exists(),
        "the server survived its own SIGTERM: it inherited the proxy's ignored SIGTERM, \
         so the proxy's request to stop could not reach it"
    );
}
