//! The I/O half of `innerwarden demo` (the rules are in `demo`): which
//! agents are wired, running each one's hook as its settings write it, and
//! asking the MCP proxy's own code about each call.

use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use innerwarden_agent_guard::agents::{AgentStatus, GuardMode};
use innerwarden_agent_guard::mcp_proxy::enforce::{apply_layers, ProxyAction, ProxyMode};
use innerwarden_agent_guard::mcp_proxy::jsonrpc::JsonRpcEnvelope;
use innerwarden_agent_guard::mcp_proxy::router::{route_message, Direction};
use innerwarden_agent_guard::profiles::ProxyProfile;
use innerwarden_agent_guard::rules::RuleEngine;
use innerwarden_agent_guard::{agents_ops, hook};

use crate::demo::{self, AgentDemo, CallResult, DemoCall, Outcome, Via};

/// How long one hook, or its program's `--version`, gets to answer. A hook
/// answers in well under a second; this only bounds one that hangs, so the
/// demo itself never does.
const HOOK_WAIT: Duration = Duration::from_secs(20);

/// A fresh nonce for this run: 128 bits from two independently, randomly
/// keyed std hashers (the OS seeds each `RandomState`), mixed with the
/// clock and the pid, as 32 hex digits.
pub(crate) fn new_nonce() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let salt = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let half = || {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u128(salt);
        hasher.write_u32(std::process::id());
        hasher.finish()
    };
    format!("{:016x}{:016x}", half(), half())
}

pub(crate) fn cmd(rest: &[String]) -> ExitCode {
    let mut as_json = false;
    for arg in rest {
        match arg.as_str() {
            "--json" => as_json = true,
            other => {
                eprintln!(
                    "innerwarden demo: unexpected argument `{other}` (see innerwarden demo --help)"
                );
                return ExitCode::from(demo::EXIT_USAGE);
            }
        }
    }
    let home = match hook::home_dir() {
        Ok(home) => home,
        Err(why) => {
            eprintln!("innerwarden demo: could not find your home directory ({why}), so no agent's wiring could be read");
            return ExitCode::from(demo::EXIT_NOTHING_CONNECTED);
        }
    };
    let rows = agents_ops::rows(&home);
    let calls = demo::calls(&home);
    let nonce = new_nonce();
    let agents = gather(&home, &rows, &calls, &nonce);
    // "Running" only from the process scan (a row's pids), never from an
    // agent's config dir or binary merely being here; unknown where the scan
    // cannot look. Shared with `status`.
    let running = agents_ops::any_agent_running(&rows);
    let none =
        (!agents.iter().any(|a| a.wired)).then(|| crate::status::nothing_wired_finding(running));
    if as_json {
        println!("{}", demo::to_json(&agents, none.as_ref()));
    } else {
        print!("{}", demo::render(&agents, none.as_ref(), calls.len()));
    }
    ExitCode::from(demo::exit_code(&agents))
}

/// Every agent here that can be wired, with what each connected one answered.
fn gather(home: &Path, rows: &[AgentStatus], calls: &[DemoCall], nonce: &str) -> Vec<AgentDemo> {
    let wiring = crate::status_wiring(Some(home), rows);
    let mut engine: Option<RuleEngine> = None;
    // The agent profiles, read as the proxy reads them when it starts.
    let mut profiles: Option<crate::agent_profiles::ProfilesState> = None;
    let mut out = Vec::new();
    for row in rows {
        let via = if row.hookable { Via::Hook } else { Via::Proxy };
        let mode = row.mode.map(|m| m.label().to_string());
        if let Some(trouble) = wiring.hook_trouble.iter().find(|t| t.agent == row.name) {
            if let Some(finding) = crate::status::trouble_finding(trouble) {
                out.push(AgentDemo {
                    agent: row.name.clone(),
                    via,
                    wired: true,
                    connected: false,
                    mode,
                    finding,
                    calls: Vec::new(),
                });
                continue;
            }
        }
        if !wiring.wired_agents.contains(&row.name) {
            let wirable = row.hookable
                || row.mcp_json.is_some()
                || row.mcp_toml.is_some()
                || row.mcp_yaml.is_some();
            if wirable {
                let next = if row.hookable {
                    agents_ops::hook_repair_command(home, row)
                } else {
                    format!("innerwarden agents connect {}", row.name)
                };
                out.push(AgentDemo {
                    agent: row.name.clone(),
                    via,
                    wired: false,
                    connected: false,
                    mode: None,
                    finding: demo::not_connected_finding(&row.name, next),
                    calls: Vec::new(),
                });
            }
            continue;
        }
        let finding = match wiring
            .partly_unscreened
            .iter()
            .find(|p| p.agent == row.name)
        {
            Some(partly) => crate::status::Finding::NotWorking {
                what: crate::status::partly_unscreened_words(&partly.agent, &partly.sentence),
                next: partly.next.clone(),
            },
            None => demo::connected_finding(&row.name, via, mode.as_deref()),
        };
        let results = match via {
            Via::Hook => through_hooks(home, calls, nonce),
            Via::Proxy => {
                let engine = engine.get_or_insert_with(RuleEngine::load_embedded);
                let state = profiles.get_or_insert_with(crate::agent_profiles_io::load);
                // The wiring passes the agent's name as `--agent`; the demo
                // runs outside the agent, so no instance identity is read.
                let profile = crate::agent_profiles::proxy_profile(state, Some(&row.name), None);
                through_proxy(calls, row.mode, engine, profile.as_ref())
            }
        };
        out.push(AgentDemo {
            agent: row.name.clone(),
            via,
            wired: true,
            connected: true,
            mode,
            finding,
            calls: results,
        });
    }
    out
}

/// Each call, sent to every InnerWarden hook Claude Code would run for its
/// tool, as the settings write it: the same program, the same flags, the
/// payload on stdin. Claude Code's settings are the ones every hook agent
/// is wired in (`agents_ops::hook_program` reads the same file).
fn through_hooks(home: &Path, calls: &[DemoCall], nonce: &str) -> Vec<CallResult> {
    let settings = std::fs::read_to_string(home.join(".claude/settings.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .unwrap_or_default();
    let mut versions: Vec<(String, Result<(), String>)> = Vec::new();
    calls
        .iter()
        .enumerate()
        .map(|(index, call)| {
            let hooks = hook::iwguard_hook_commands_for_tool(&settings, call.tool);
            let results = hooks
                .iter()
                .map(|words| {
                    let program = &words[0];
                    let speaks = match versions.iter().find(|(p, _)| p == program) {
                        Some((_, known)) => known.clone(),
                        None => {
                            let known = speaks_demo(program, HOOK_WAIT);
                            versions.push((program.clone(), known.clone()));
                            known
                        }
                    };
                    if let Err(why) = speaks {
                        let mut result = CallResult::new(call, Outcome::NotSent);
                        result.why = Some(why);
                        return result;
                    }
                    let payload = demo::hook_payload(call, home, index, nonce);
                    let (exit, stdout, stderr) = run_bounded(
                        words,
                        Some(home),
                        Some((demo::DEMO_NONCE_ENV, nonce)),
                        Some(&payload),
                        HOOK_WAIT,
                    );
                    let (outcome, recommendation, why) = demo::hook_outcome(exit, &stdout, &stderr);
                    CallResult {
                        recommendation,
                        why,
                        ..CallResult::new(call, outcome)
                    }
                })
                .collect();
            demo::strictest(results).unwrap_or_else(|| {
                let mut result = CallResult::new(call, Outcome::NotScreened);
                result.why = Some(format!(
                    "no InnerWarden hook is wired for the {} tool",
                    call.tool
                ));
                result
            })
        })
        .collect()
}

/// Whether the hook's program is this same version: an older one has no idea
/// what the demo marker means and would record the calls, and alert on them,
/// as an agent's. `Err` says why the call was not sent. Bounded by `wait`,
/// like the hook itself.
fn speaks_demo(program: &str, wait: Duration) -> Result<(), String> {
    let ours = env!("CARGO_PKG_VERSION");
    let words = [program.to_string(), "--version".to_string()];
    let (exit, stdout, stderr) = run_bounded(&words, None, None, None, wait);
    match exit {
        None => {
            return Err(format!(
            "its hook runs {program}, whose --version did not answer in {}s, so it was not sent",
            wait.as_secs()
        ))
        }
        Some(-1) if stdout.is_empty() => {
            return Err(format!(
                "its hook runs {program}, which could not be started: {stderr}"
            ))
        }
        Some(_) => {}
    }
    let text = stdout;
    let theirs = text.split_whitespace().nth(1).unwrap_or("").to_string();
    if theirs == ours {
        Ok(())
    } else {
        Err(format!(
            "its hook runs {program}, version {}, and this is {ours}; an older hook would record the \
             call as your agent's, so it was not sent. Rewire the hook to this binary first",
            if theirs.is_empty() { "unknown" } else { &theirs }
        ))
    }
}

/// Run `words` with `stdin` (or none), in `dir` when given, with `env`
/// added: exit code (`None` when it did not finish in `wait` and was
/// stopped; `Some(-1)` when it could not be started), stdout and stderr.
fn run_bounded(
    words: &[String],
    dir: Option<&Path>,
    env: Option<(&str, &str)>,
    stdin: Option<&str>,
    wait: Duration,
) -> (Option<i32>, String, String) {
    let mut command = Command::new(&words[0]);
    command
        .args(&words[1..])
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    if let Some((key, value)) = env {
        command.env(key, value);
    }
    let child = command.spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(e) => {
            return (
                Some(-1),
                String::new(),
                format!("could not start {}: {e}", words[0]),
            )
        }
    };
    if let (Some(mut pipe), Some(text)) = (child.stdin.take(), stdin) {
        let _ = pipe.write_all(text.as_bytes());
    }
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < wait => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return (None, String::new(), String::new());
            }
        }
    }
    match child.wait_with_output() {
        Ok(out) => (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ),
        Err(e) => (Some(-1), String::new(), e.to_string()),
    }
}

/// Each call, as a `tools/call` the proxy wrapping this agent's servers would
/// receive, judged by the proxy's own router, the agent profiles it applies
/// (`profile`, built as the proxy builds it) and its mode. The wrapper is
/// not started, so neither is any server behind it.
fn through_proxy(
    calls: &[DemoCall],
    mode: Option<GuardMode>,
    engine: &RuleEngine,
    profile: Option<&ProxyProfile>,
) -> Vec<CallResult> {
    // A mixed or unreadable wiring has servers that only record: the demo
    // shows the weaker of the two, which is what part of the calls get.
    let proxy_mode = match mode {
        Some(GuardMode::Enforce) => ProxyMode::Guard,
        _ => ProxyMode::Advisory,
    };
    calls
        .iter()
        .enumerate()
        .map(|(index, call)| {
            let line = demo::mcp_line(call, index);
            let Ok(envelope) = serde_json::from_str::<JsonRpcEnvelope>(&line) else {
                let mut result = CallResult::new(call, Outcome::Failed);
                result.why = Some("the call could not be read back as JSON-RPC".into());
                return result;
            };
            let mut decision = route_message(
                &envelope,
                Direction::ClientToServer,
                None,
                Some(engine),
                None,
            );
            let action = apply_layers(
                &mut decision,
                &envelope,
                profile,
                Some(engine),
                proxy_mode,
                false,
            );
            let why = decision
                .verdict
                .alerts
                .iter()
                .find(|a| a.block)
                .or(decision.verdict.alerts.first())
                .map(|a| a.detail.clone());
            let outcome = match action {
                ProxyAction::Block { .. } | ProxyAction::Kill { .. } => Outcome::Refused,
                _ if !decision.verdict.allowed => Outcome::WouldRefuse,
                _ => Outcome::Allowed,
            };
            CallResult {
                recommendation: Some(
                    if decision.verdict.allowed {
                        "allow"
                    } else {
                        "deny"
                    }
                    .into(),
                ),
                why,
                ..CallResult::new(call, outcome)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The MCP half: the proxy's own router refuses the calls in enforce
    /// (`guard`), and in monitor the same calls are only alerted on.
    ///
    /// FAILS ON REVERT: map enforce to anything but `guard` and nothing is
    /// refused; drop the `allowed` check and monitor reads as let through.
    #[test]
    fn the_proxy_refuses_in_enforce_and_only_flags_in_monitor() {
        let engine = RuleEngine::load_embedded();
        let calls = demo::calls(Path::new("/home/someone"));
        let enforce = through_proxy(&calls, Some(GuardMode::Enforce), &engine, None);
        let monitor = through_proxy(&calls, Some(GuardMode::Monitor), &engine, None);
        for id in ["download-to-shell", "read-ssh-key"] {
            let e = enforce.iter().find(|r| r.id == id).unwrap();
            assert_eq!(e.outcome, Outcome::Refused, "{id}: {e:?}");
            assert_eq!(e.recommendation.as_deref(), Some("deny"));
            let m = monitor.iter().find(|r| r.id == id).unwrap();
            assert_eq!(m.outcome, Outcome::WouldRefuse, "{id}: {m:?}");
        }
        // A mixed or unreadable wiring shows what its recording half does.
        let mixed = through_proxy(&calls, Some(GuardMode::Mixed), &engine, None);
        assert!(mixed.iter().all(|r| r.outcome != Outcome::Refused));
    }

    /// The MCP half applies the agent profiles the proxy applies: a profile
    /// that denies a tool refuses its call in enforce, and an unusable
    /// profiles file refuses every call, as the proxy does. Each is built
    /// by `agent_profiles::proxy_profile`, the proxy's own builder.
    ///
    /// FAILS ON REVERT of `apply_layers` (back to `apply_mode`): the
    /// profile is not read and the reasons below are not given.
    #[test]
    fn the_proxy_half_applies_the_agent_profiles_the_proxy_applies() {
        use crate::agent_profiles::{proxy_profile, ProfilesState};
        let engine = RuleEngine::load_embedded();
        // The four calls are refused by the rules alone, so a profile only
        // shows on a call the rules let through: a weather lookup.
        let weather = DemoCall {
            id: "weather",
            tool: "weather",
            shown: "weather NYC".into(),
            hook_input: serde_json::json!({}),
            mcp_tool: "weather",
            mcp_args: serde_json::json!({ "location": "NYC" }),
        };
        let mut calls = demo::calls(Path::new("/home/someone"));
        calls.push(weather);
        let plain = through_proxy(&calls, Some(GuardMode::Enforce), &engine, None);
        assert_eq!(plain[4].outcome, Outcome::Allowed, "{:?}", plain[4]);

        let invalid = proxy_profile(
            &ProfilesState::Invalid("agents.toml: line 3 is not a profile".into()),
            Some("cursor"),
            None,
        );
        let refused = through_proxy(&calls, Some(GuardMode::Enforce), &engine, invalid.as_ref());
        assert!(
            refused.iter().all(|r| r.outcome == Outcome::Refused),
            "{refused:?}"
        );
        let why = refused[4].why.clone().unwrap_or_default();
        assert!(why.contains("agent profiles file"), "{why}");

        let profiles = innerwarden_agent_guard::profiles::parse(
            b"schema_version = 1\n[profile.cursor]\nmcp_tools_deny = [\"weather\"]\n",
        )
        .expect("profiles");
        let state = ProfilesState::On(profiles);
        let denying = proxy_profile(&state, Some("cursor"), None);
        let results = through_proxy(&calls, Some(GuardMode::Enforce), &engine, denying.as_ref());
        assert_eq!(results[4].outcome, Outcome::Refused, "{:?}", results[4]);
        // In monitor the proxy only records what the profile refuses.
        let monitor = through_proxy(&calls, Some(GuardMode::Monitor), &engine, denying.as_ref());
        assert_eq!(monitor[4].outcome, Outcome::WouldRefuse, "{:?}", monitor[4]);
        // Another agent's profile is not this one's.
        let codex = proxy_profile(&state, Some("codex"), None);
        let other = through_proxy(&calls, Some(GuardMode::Enforce), &engine, codex.as_ref());
        assert_eq!(other[4].outcome, Outcome::Allowed, "{:?}", other[4]);
        // Another agent's type does not apply to this one.
        assert_eq!(
            proxy_profile(&state, Some("codex"), None),
            Some(ProxyProfile::Active {
                agent_type: Some("codex".into()),
                profile: None,
                trust: innerwarden_agent_guard::identity::Trust::Declared,
                revoked: None,
            })
        );
        assert_eq!(
            proxy_profile(&ProfilesState::Off, Some("cursor"), None),
            None
        );
    }

    /// A hook program whose `--version` hangs is stopped at the wait, and
    /// the call is not sent, so the demo itself never hangs.
    ///
    /// FAILS ON REVERT: run `--version` with no bound and this waits out the
    /// program's sleep.
    #[cfg(unix)]
    #[test]
    fn a_version_check_that_hangs_is_stopped() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let program = dir.path().join("innerwarden");
        std::fs::write(&program, "#!/bin/sh\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let started = Instant::now();
        let got = speaks_demo(program.to_str().unwrap(), Duration::from_millis(300));
        assert!(started.elapsed() < Duration::from_secs(10));
        let why = got.unwrap_err();
        assert!(why.contains("did not answer"), "{why}");
    }

    /// Two runs never share a nonce, and each is long enough to count.
    #[test]
    fn each_run_has_its_own_nonce() {
        let (a, b) = (new_nonce(), new_nonce());
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
    }
}
