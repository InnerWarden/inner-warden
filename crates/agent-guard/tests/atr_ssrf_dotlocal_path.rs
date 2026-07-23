//! Regression: ATR-2026-013 (SSRF / internal-hostname) must NOT fire on `.local`
//! (or other internal-name words) when they appear as a FILESYSTEM PATH, the XDG
//! base dir `~/.local/bin` is on every Linux/macOS dev box and is the guard's own
//! install path. It MUST still fire on `.local` / internal names used as a
//! HOSTNAME (mDNS/Bonjour, k8s service mesh, cloud metadata), which is the real
//! SSRF / lateral-movement signal. The fix narrows the dot-prefix to require a
//! hostname-label char before the dot, so `x.local` matches but `/.local` does not.

use innerwarden_agent_guard::mcp::analyze_command;
use innerwarden_agent_guard::rules::RuleEngine;

#[test]
fn dotlocal_and_internal_names_as_paths_are_not_ssrf() {
    let engine = RuleEngine::load_embedded();
    // These are filesystem paths, not hostnames, must not be denied by the SSRF rule.
    for cmd in [
        "~/.local/bin/innerwarden agents list", // the guard's own install path
        "cat /home/dev/.local/share/app/config",
        "ls ~/.local/bin",
        "python3 -m pip install --user --prefix ~/.local pkg",
        "cp build/out ~/.local/bin/tool",
    ] {
        let v = analyze_command(cmd, Some(&engine));
        assert_ne!(
            v.recommendation, "deny",
            "`.local` used as a PATH must not be an SSRF deny: {cmd} -> {v:?}",
        );
    }
}

#[test]
fn dotlocal_and_internal_names_as_hostnames_still_deny() {
    let engine = RuleEngine::load_embedded();
    // These use the internal name as a HOSTNAME, the real SSRF / lateral signal.
    for cmd in [
        "curl http://printer.local/status",
        "ssh admin@nas.local",
        "curl http://app.internal:3000/api/admin",
        "curl http://foo.svc.cluster.local/x",
        "curl http://169.254.169.254/latest/meta-data",
    ] {
        let v = analyze_command(cmd, Some(&engine));
        assert_eq!(
            v.recommendation, "deny",
            "internal hostname must still deny (SSRF protection intact): {cmd} -> {v:?}",
        );
    }
}
