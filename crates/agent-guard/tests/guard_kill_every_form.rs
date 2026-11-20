//! Every form of kill or stop against every process of the guard, read by
//! the processes it reaches.
//!
//! Measured 2026-11-20 on main with `analyze_command`: `pgrep <guard> |
//! xargs kill` and `pidof <guard> | xargs kill -9` were allowed for each
//! of the guard's programs; every form against the CLI's `iw-guard` was
//! allowed (pkill, killall, kill $(pgrep), kill $(pidof), xargs kill,
//! systemctl kill); `pkill -f` by a word of the guard's command lines
//! (sensor, dashboard, bin, agent) was allowed; `lsof -ti:8787 | xargs
//! kill`, `fuser -k 8787/tcp`, `ps aux | grep innerwarden | awk ... |
//! xargs kill -9` and `sudo service innerwarden-agent stop` were allowed;
//! and a kill whose processes the line does not name (`kill $PID`, `kill
//! $(cat app.pid)`, `xargs kill < pids.txt`) was allowed. One rule now: a
//! target that resolves to a process of the guard is refused, one the line
//! does not resolve is held for review, and one that resolves elsewhere is
//! allowed.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

/// FAILS ON REVERT: take `kill_targets::kill_reach` out of
/// `security_tamper_as_written` and the xargs, iw-guard and word forms are
/// allowed.
#[test]
fn every_form_of_kill_against_every_guard_process_is_refused() {
    for line in [
        r##"pkill innerwarden"##,
        r##"pkill -9 innerwarden"##,
        r##"pkill -f innerwarden"##,
        r##"killall innerwarden"##,
        r##"killall -9 innerwarden"##,
        r##"kill $(pgrep innerwarden)"##,
        r##"kill $(pgrep -f innerwarden)"##,
        r##"kill -9 $(pidof innerwarden)"##,
        r##"kill `pgrep innerwarden`"##,
        r##"pgrep innerwarden | xargs kill"##,
        r##"pidof innerwarden | xargs kill -9"##,
        r##"pgrep -f innerwarden | xargs -r kill -9"##,
        r##"systemctl kill innerwarden"##,
        r##"sudo systemctl kill -s KILL innerwarden.service"##,
        r##"sudo kill -9 $(pidof innerwarden)"##,
        r##"pkill innerwarden-agent"##,
        r##"pkill -9 innerwarden-agent"##,
        r##"pkill -f innerwarden-agent"##,
        r##"killall innerwarden-agent"##,
        r##"killall -9 innerwarden-agent"##,
        r##"kill $(pgrep innerwarden-agent)"##,
        r##"kill $(pgrep -f innerwarden-agent)"##,
        r##"kill -9 $(pidof innerwarden-agent)"##,
        r##"kill `pgrep innerwarden-agent`"##,
        r##"pgrep innerwarden-agent | xargs kill"##,
        r##"pidof innerwarden-agent | xargs kill -9"##,
        r##"pgrep -f innerwarden-agent | xargs -r kill -9"##,
        r##"systemctl kill innerwarden-agent"##,
        r##"sudo systemctl kill -s KILL innerwarden-agent.service"##,
        r##"sudo kill -9 $(pidof innerwarden-agent)"##,
        r##"pkill innerwarden-sensor"##,
        r##"pkill -9 innerwarden-sensor"##,
        r##"pkill -f innerwarden-sensor"##,
        r##"killall innerwarden-sensor"##,
        r##"killall -9 innerwarden-sensor"##,
        r##"kill $(pgrep innerwarden-sensor)"##,
        r##"kill $(pgrep -f innerwarden-sensor)"##,
        r##"kill -9 $(pidof innerwarden-sensor)"##,
        r##"kill `pgrep innerwarden-sensor`"##,
        r##"pgrep innerwarden-sensor | xargs kill"##,
        r##"pidof innerwarden-sensor | xargs kill -9"##,
        r##"pgrep -f innerwarden-sensor | xargs -r kill -9"##,
        r##"systemctl kill innerwarden-sensor"##,
        r##"sudo systemctl kill -s KILL innerwarden-sensor.service"##,
        r##"sudo kill -9 $(pidof innerwarden-sensor)"##,
        r##"pkill innerwarden-watchdog"##,
        r##"pkill -9 innerwarden-watchdog"##,
        r##"pkill -f innerwarden-watchdog"##,
        r##"killall innerwarden-watchdog"##,
        r##"killall -9 innerwarden-watchdog"##,
        r##"kill $(pgrep innerwarden-watchdog)"##,
        r##"kill $(pgrep -f innerwarden-watchdog)"##,
        r##"kill -9 $(pidof innerwarden-watchdog)"##,
        r##"kill `pgrep innerwarden-watchdog`"##,
        r##"pgrep innerwarden-watchdog | xargs kill"##,
        r##"pidof innerwarden-watchdog | xargs kill -9"##,
        r##"pgrep -f innerwarden-watchdog | xargs -r kill -9"##,
        r##"systemctl kill innerwarden-watchdog"##,
        r##"sudo systemctl kill -s KILL innerwarden-watchdog.service"##,
        r##"sudo kill -9 $(pidof innerwarden-watchdog)"##,
        r##"pkill innerwarden-dns-guard"##,
        r##"pkill -9 innerwarden-dns-guard"##,
        r##"pkill -f innerwarden-dns-guard"##,
        r##"killall innerwarden-dns-guard"##,
        r##"killall -9 innerwarden-dns-guard"##,
        r##"kill $(pgrep innerwarden-dns-guard)"##,
        r##"kill $(pgrep -f innerwarden-dns-guard)"##,
        r##"kill -9 $(pidof innerwarden-dns-guard)"##,
        r##"kill `pgrep innerwarden-dns-guard`"##,
        r##"pgrep innerwarden-dns-guard | xargs kill"##,
        r##"pidof innerwarden-dns-guard | xargs kill -9"##,
        r##"pgrep -f innerwarden-dns-guard | xargs -r kill -9"##,
        r##"systemctl kill innerwarden-dns-guard"##,
        r##"sudo systemctl kill -s KILL innerwarden-dns-guard.service"##,
        r##"sudo kill -9 $(pidof innerwarden-dns-guard)"##,
        r##"pkill iw-guard"##,
        r##"pkill -9 iw-guard"##,
        r##"pkill -f iw-guard"##,
        r##"killall iw-guard"##,
        r##"killall -9 iw-guard"##,
        r##"kill $(pgrep iw-guard)"##,
        r##"kill $(pgrep -f iw-guard)"##,
        r##"kill -9 $(pidof iw-guard)"##,
        r##"kill `pgrep iw-guard`"##,
        r##"pgrep iw-guard | xargs kill"##,
        r##"pidof iw-guard | xargs kill -9"##,
        r##"pgrep -f iw-guard | xargs -r kill -9"##,
        r##"systemctl kill iw-guard"##,
        r##"sudo systemctl kill -s KILL iw-guard.service"##,
        r##"sudo kill -9 $(pidof iw-guard)"##,
        r##"lsof -ti:8787 | xargs kill"##,
        r##"fuser -k 8787/tcp"##,
        r##"sudo service innerwarden-agent stop"##,
        r##"ps aux | grep innerwarden | awk '{print $2}' | xargs kill -9"##,
        r##"kill -9 $(ps -C innerwarden-agent -o pid=)"##,
        r##"pkill -f config.toml"##,
        r##"killall -r 'inner.*'"##,
        r##"pkill warden"##,
        r##"kill $(pgrep -f 'innerwarden hook')"##,
        r##"pgrep -f iw-guard | sudo xargs kill"##,
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// A `pkill -f` pattern, or a pgrep feeding a kill, that matches the
/// guard's command lines by a word of them, not its name, still reaches
/// it.
///
/// FAILS ON REVERT: match the pattern against the name only and each is
/// allowed, as on main.
#[test]
fn a_pattern_that_matches_the_guards_command_line_by_any_word_is_refused() {
    for line in [
        r##"pkill -f sensor"##,
        r##"kill $(pgrep -f sensor)"##,
        r##"pgrep -f sensor | xargs kill"##,
        r##"pkill -f dashboard"##,
        r##"kill $(pgrep -f dashboard)"##,
        r##"pgrep -f dashboard | xargs kill"##,
        r##"pkill -f bin"##,
        r##"kill $(pgrep -f bin)"##,
        r##"pgrep -f bin | xargs kill"##,
        r##"pkill -f agent"##,
        r##"kill $(pgrep -f agent)"##,
        r##"pgrep -f agent | xargs kill"##,
        r##"pkill -f watchdog"##,
        r##"kill $(pgrep -f watchdog)"##,
        r##"pgrep -f watchdog | xargs kill"##,
        r##"pkill -f dns-guard"##,
        r##"kill $(pgrep -f dns-guard)"##,
        r##"pgrep -f dns-guard | xargs kill"##,
        r##"pkill -f local/bin"##,
        r##"kill $(pgrep -f local/bin)"##,
        r##"pgrep -f local/bin | xargs kill"##,
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// A kill whose processes the line does not resolve may be the guard's.
///
/// FAILS ON REVERT: drop `KILL_TARGET_UNREAD` from `check_security_tamper`
/// and each is allowed, as on main.
#[test]
fn a_kill_whose_target_the_line_does_not_resolve_is_held_for_review() {
    for line in [
        r##"kill $(cat app.pid)"##,
        r##"kill $PID"##,
        r##"kill -9 $PID"##,
        r##"xargs kill < pids.txt"##,
        r##"cat pids | xargs kill -9"##,
        r##"kill $(pgrep "$N")"##,
        r##"kill -9 $(pidof $P)"##,
    ] {
        assert_eq!(verdict(line), "review", "{line}");
    }
}

/// The other side: the same forms against processes that are not the
/// guard's, and the kills of a working day, are not refused; those whose
/// numbers a substitution prints are held for review by the rule for a
/// part the guard does not read, as on main.
#[test]
fn every_form_of_kill_against_other_processes_is_allowed() {
    for line in [
        r##"pkill vite"##,
        r##"pkill -9 vite"##,
        r##"pkill -f vite"##,
        r##"killall vite"##,
        r##"killall -9 vite"##,
        r##"kill $(pgrep vite)"##,
        r##"kill $(pgrep -f vite)"##,
        r##"kill -9 $(pidof vite)"##,
        r##"kill `pgrep vite`"##,
        r##"pgrep vite | xargs kill"##,
        r##"pidof vite | xargs kill -9"##,
        r##"pgrep -f vite | xargs -r kill -9"##,
        r##"systemctl kill vite"##,
        r##"sudo systemctl kill -s KILL vite.service"##,
        r##"sudo kill -9 $(pidof vite)"##,
        r##"pkill node"##,
        r##"pkill -9 node"##,
        r##"pkill -f node"##,
        r##"killall node"##,
        r##"killall -9 node"##,
        r##"kill $(pgrep node)"##,
        r##"kill $(pgrep -f node)"##,
        r##"kill -9 $(pidof node)"##,
        r##"kill `pgrep node`"##,
        r##"pgrep node | xargs kill"##,
        r##"pidof node | xargs kill -9"##,
        r##"pgrep -f node | xargs -r kill -9"##,
        r##"systemctl kill node"##,
        r##"sudo systemctl kill -s KILL node.service"##,
        r##"sudo kill -9 $(pidof node)"##,
        r##"pkill nginx"##,
        r##"pkill -9 nginx"##,
        r##"pkill -f nginx"##,
        r##"killall nginx"##,
        r##"killall -9 nginx"##,
        r##"kill $(pgrep nginx)"##,
        r##"kill $(pgrep -f nginx)"##,
        r##"kill -9 $(pidof nginx)"##,
        r##"kill `pgrep nginx`"##,
        r##"pgrep nginx | xargs kill"##,
        r##"pidof nginx | xargs kill -9"##,
        r##"pgrep -f nginx | xargs -r kill -9"##,
        r##"systemctl kill nginx"##,
        r##"sudo systemctl kill -s KILL nginx.service"##,
        r##"sudo kill -9 $(pidof nginx)"##,
        r##"pkill python3"##,
        r##"pkill -9 python3"##,
        r##"pkill -f python3"##,
        r##"killall python3"##,
        r##"killall -9 python3"##,
        r##"kill $(pgrep python3)"##,
        r##"kill $(pgrep -f python3)"##,
        r##"kill -9 $(pidof python3)"##,
        r##"kill `pgrep python3`"##,
        r##"pgrep python3 | xargs kill"##,
        r##"pidof python3 | xargs kill -9"##,
        r##"pgrep -f python3 | xargs -r kill -9"##,
        r##"systemctl kill python3"##,
        r##"sudo systemctl kill -s KILL python3.service"##,
        r##"sudo kill -9 $(pidof python3)"##,
        r##"pkill cargo"##,
        r##"pkill -9 cargo"##,
        r##"pkill -f cargo"##,
        r##"killall cargo"##,
        r##"killall -9 cargo"##,
        r##"kill $(pgrep cargo)"##,
        r##"kill $(pgrep -f cargo)"##,
        r##"kill -9 $(pidof cargo)"##,
        r##"kill `pgrep cargo`"##,
        r##"pgrep cargo | xargs kill"##,
        r##"pidof cargo | xargs kill -9"##,
        r##"pgrep -f cargo | xargs -r kill -9"##,
        r##"systemctl kill cargo"##,
        r##"sudo systemctl kill -s KILL cargo.service"##,
        r##"sudo kill -9 $(pidof cargo)"##,
        r##"kill -9 $(lsof -t -i:3000)"##,
        r##"lsof -ti:5173 | xargs kill -9"##,
        r##"kill $(lsof -t -i :8080)"##,
        r##"fuser -k 3000/tcp"##,
        r##"pkill -f "next dev""##,
        r##"pkill -f uvicorn"##,
        r##"pkill -f 'python -m http.server'"##,
        r##"ps aux | grep vite | grep -v grep | awk '{print $2}' | xargs kill"##,
        r##"pgrep -f gunicorn | xargs kill -HUP"##,
        r##"pkill -f "cargo watch""##,
        r##"pkill -f webpack"##,
        r##"killall node"##,
        r##"pkill -f jest"##,
        r##"pkill -f esbuild"##,
        r##"pkill -f "npm run dev""##,
        r##"pkill -f chrome"##,
        r##"pkill -f tsc"##,
        r##"kill -9 $(pgrep -f "node server.js")"##,
        r##"pkill -f npx"##,
        r##"pkill -f claude"##,
        r##"pkill -f server"##,
        r##"pkill -f 'target/debug/myapp'"##,
        r##"kill %1"##,
        r##"sudo systemctl kill nginx"##,
        r##"lsof -ti tcp:4000 | xargs -r kill"##,
        r##"kill -9 $(ps aux | grep '[r]edis' | awk '{print $2}')"##,
        r##"pkill -INT -f "ruby app.rb""##,
        r##"pkill -f flask"##,
        r##"pkill -f hugo"##,
        r##"pkill -f "go run""##,
        r##"pkill -f postgres"##,
        r##"service nginx stop"##,
        r##"pkill -f playwright"##,
        r##"pkill -f vitest"##,
        r##"pkill -f "rails s""##,
        r##"pkill -f docker-compose"##,
        r##"kill -0 $(cat app.pid)"##,
        r##"npm run dev & sleep 3; curl -s localhost:3000; kill $!"##,
    ] {
        // A substitution in a kill's place is a part of the line the guard
        // does not read (unread_parts.rs): held for review there, never
        // refused here.
        let expected = if line.contains("$(") || line.contains('`') {
            "review"
        } else {
            "allow"
        };
        assert_eq!(verdict(line), expected, "{line}");
    }
}
