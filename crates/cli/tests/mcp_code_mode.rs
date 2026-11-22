//! MCP servers in code mode (Cloudflare's: two tools, `search` and `execute`) take a
//! TypeScript script that runs in the server's sandbox. The calls to the API
//! inside it are what the call does: the hook (PreToolUse of the MCP tool)
//! and the proxy read the script and judge those calls.
//!
//! Drives the REAL binary over a disposable HOME, with a fake code-mode
//! server written into a tempdir: nothing real is called.

#![cfg(unix)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// A code-mode server: `search` and `execute`, each tool call answered with
/// what it was handed, so a call that reached it comes back.
const FAKE_SERVER: &str = r#"
import json, sys
TOOLS = [
    {"name": "search", "description": "Search the API spec.",
     "inputSchema": {"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"]}},
    {"name": "execute", "description": "Run JavaScript against the API in a sandbox.",
     "inputSchema": {"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"]}},
]
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake-code-mode", "version": "0"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "ran " + msg["params"]["name"]}], "echo": msg["id"]}
    else:
        result = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
"#;

struct Host {
    dir: tempfile::TempDir,
}

/// What the hook answered: exit code, stdout, stderr.
#[derive(Debug)]
struct HookAnswer {
    code: Option<i32>,
    stdout: String,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        std::fs::create_dir_all(dir.path().join("home/proj")).expect("project");
        std::fs::write(dir.path().join("server.py"), FAKE_SERVER).expect("server");
        Self { dir }
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn hook(&self, flags: &[&str], tool: &str, code: &str) -> HookAnswer {
        let payload = serde_json::json!({
            "session_id": "s-code-mode",
            "hook_event_name": "PreToolUse",
            "cwd": self.home().join("proj"),
            "tool_name": tool,
            "tool_input": { "code": code },
        })
        .to_string();
        let mut child = Command::new(env!("CARGO_BIN_EXE_innerwarden"))
            .arg("hook")
            .args(flags)
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("IW_SESSION_FILE", self.dir.path().join("sessions.json"))
            .env_remove("IW_GUARD_SESSION")
            .env("INNERWARDEN_AGENT_URL", "off")
            .env("IW_TEST_HOOK_DEADLINE_MS", "30000")
            .current_dir(self.home().join("proj"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run innerwarden hook");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(payload.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        HookAnswer {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        }
    }

    /// The proxy in `mode` around the fake server: initialize, list the
    /// tools, then one `execute` call with `code`. What reached the client.
    fn proxy(&self, mode: &str, code: &str) -> String {
        let lines = [
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
            serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute","arguments":{"code": code}}}),
        ];
        let mut child = Command::new(env!("CARGO_BIN_EXE_innerwarden"))
            .args(["proxy", "--mode", mode, "--label", "code-mode", "--"])
            .arg("python3")
            .arg("-u")
            .arg(self.dir.path().join("server.py"))
            .env("HOME", self.home())
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("INNERWARDEN_AGENT_URL", "off")
            .env("IW_TEST_ACCOUNT_HOME", self.home())
            .env("IW_TEST_GUARD_CONFIG", self.home().join("no-guard.toml"))
            .env_remove("IW_GUARD_SESSION")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run innerwarden proxy");
        let mut stdin = child.stdin.take().unwrap();
        for line in lines {
            stdin.write_all(line.to_string().as_bytes()).unwrap();
            stdin.write_all(b"\n").unwrap();
            stdin.flush().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
        drop(stdin);
        let out = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

/// The hook's verdict as an agent reads it: 2 refuses, 0 with `ask` asks.
fn hook_verdict(answer: &HookAnswer) -> &'static str {
    match answer.code {
        Some(2) => "deny",
        Some(0) if answer.stdout.contains("\"ask\"") => "review",
        Some(0) => "allow",
        _ => "other",
    }
}

/// The proxy's verdict on call 3: never forwarded is a refusal, forwarded
/// with a finding beside it is a review, forwarded clean is allowed.
fn proxy_verdict(out: &str) -> &'static str {
    let reply = out
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|v| v["id"] == 3);
    match reply {
        Some(v) if v["result"]["echo"] == 3 => "forwarded",
        Some(v) if v["result"]["isError"] == true || v.get("error").is_some() => "refused",
        _ => "no-answer",
    }
}

const ZONE: &str = "023e105f4ecef8ad9ca31a8372d0c353";

/// The five scripts the card measures: delete a zone, purge the cache,
/// create a token, publish a worker, list the zones.
fn measured_scripts() -> Vec<(&'static str, String)> {
    vec![
        (
            "delete zone",
            format!("async () => {{\n  await cloudflare.zones.delete({{ zone_id: \"{ZONE}\" }});\n  return \"ok\";\n}}"),
        ),
        (
            "purge cache",
            format!("async () => cloudflare.cache.purge({{ zone_id: \"{ZONE}\", purge_everything: true }})"),
        ),
        (
            "create token",
            "async () => {\n  const t = await cloudflare.user.tokens.create({ name: \"ci\", policies: [] });\n  return t.value;\n}".to_string(),
        ),
        (
            "publish worker",
            "async () => cloudflare.workers.scripts.update(\"edge\", { account_id: \"a1\", metadata: { main_module: \"w.js\" } })".to_string(),
        ),
        (
            "list zones",
            "async () => {\n  const zones = await cloudflare.zones.list();\n  return zones.result.map((z) => z.name);\n}".to_string(),
        ),
    ]
}

/// Ten scripts that only read: allowed by the hook, under `--block-review`
/// too, and forwarded by the proxy, in strict mode too.
const READS: &[&str] = &[
    "async () => {\n  const zones = await cloudflare.zones.list();\n  return zones.result.map((z) => z.name);\n}",
    "async () => cloudflare.request({ method: \"GET\", path: \"/zones/\" + zoneId + \"/dns_records\" })",
    "async () => {\n  const r = await cloudflare.dns.records.list({ zone_id: \"z1\" });\n  return r.result.filter((x) => x.type === \"A\").length;\n}",
    "async () => (await cloudflare.workers.scripts.get(\"edge\", { account_id: \"a1\" })).etag",
    "async () => { const { result } = await cloudflare.accounts.list(); return result[0]?.id; }",
    "async () => cloudflare.request({ path: \"/user/tokens/verify\" })",
    "async () => {\n  const out = [];\n  for await (const z of cloudflare.zones.list({ per_page: 50 })) out.push(z.id);\n  return JSON.stringify(out);\n}",
    "const res = await octokit.request(\"GET /repos/{owner}/{repo}/issues\", { owner: \"o\", repo: \"r\" });\nreturn res.data.map(i => i.title);",
    "async () => { const seen = new Map(); seen.set(\"a\", 1); const s = new Set([1]); s.add(2); return [...seen.keys(), s.size]; }",
    "// list the analytics, no change\nasync () => (await cloudflare.analytics.query({ zone: \"z\", since: -60 })).totals.requests.all / 2",
];

const TOOL: &str = "mcp__cloudflare__execute";

impl Host {
    fn record(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("graph.json")).unwrap_or_default()
    }
}

/// The card's measure: a script that deletes a zone, purges the cache,
/// creates a token or publishes a worker is a review (the hook asks, the
/// proxy's guard mode forwards it with the alert) and a refusal under
/// `--block-review` and the proxy's strict mode; the one that lists the
/// zones runs everywhere.
///
/// FAILS ON REVERT: before, all five ran in every mode (the hook read no
/// field of the call, the proxy read the script as a shell line).
#[test]
fn code_mode_scripts_are_judged_by_their_api_calls() {
    for (label, code) in measured_scripts() {
        let host = Host::new();
        let enforce = host.hook(&["--agent", "claude-code"], TOOL, &code);
        let strict = host.hook(&["--agent", "claude-code", "--block-review"], TOOL, &code);
        let guard = host.proxy("guard", &code);
        let guard_record = host.record();
        let strict_proxy = host.proxy("strict", &code);
        if label == "list zones" {
            assert_eq!(hook_verdict(&enforce), "allow", "{label}: {enforce:?}");
            assert_eq!(hook_verdict(&strict), "allow", "{label}: {strict:?}");
            assert_eq!(proxy_verdict(&guard), "forwarded", "{label}: {guard}");
            assert_eq!(
                proxy_verdict(&strict_proxy),
                "forwarded",
                "{label}: {strict_proxy}"
            );
            assert!(!host.record().contains("AG-CODE-MODE"), "{label}");
            continue;
        }
        assert_eq!(hook_verdict(&enforce), "review", "{label}: {enforce:?}");
        assert!(
            enforce.stdout.contains("code-mode script"),
            "{label}: {enforce:?}"
        );
        assert_eq!(hook_verdict(&strict), "deny", "{label}: {strict:?}");
        assert_eq!(proxy_verdict(&guard), "forwarded", "{label}: {guard}");
        assert!(
            guard_record.contains("AG-CODE-MODE"),
            "{label}: {guard_record}"
        );
        assert_eq!(
            proxy_verdict(&strict_proxy),
            "refused",
            "{label}: {strict_proxy}"
        );
        assert!(
            strict_proxy.contains("AG-CODE-MODE"),
            "{label}: {strict_proxy}"
        );
    }
}

/// Ten scripts that only read are allowed by the hook, under
/// `--block-review` too, and the proxy finds nothing in them, in strict mode
/// too. (Some are refused by the proxy for an ATR rule that reads their
/// arguments, as before: not this reader's.)
#[test]
fn code_mode_reads_still_run() {
    let host = Host::new();
    for code in READS {
        let strict = host.hook(&["--agent", "claude-code", "--block-review"], TOOL, code);
        assert_eq!(hook_verdict(&strict), "allow", "{code}: {strict:?}");
        for mode in ["guard", "strict"] {
            let proxied = host.proxy(mode, code);
            assert!(!proxied.contains("AG-CODE-MODE"), "{code}: {proxied}");
            let rule = proxied
                .lines()
                .find(|line| line.contains("\"id\":3") && line.contains("blocked"))
                .and_then(|line| line.split("call, ").nth(1))
                .and_then(|rest| rest.split(':').next())
                .unwrap_or("-");
            println!(
                "READ {mode:6} {:9} {rule} | {}",
                proxy_verdict(&proxied),
                code.replace('\n', " ")
            );
        }
    }
    assert!(!host.record().contains("AG-CODE-MODE"));
}

/// Hermes Agent's `execute_code` runs Python, and its hook judges it as a
/// `python3 -c` line. Three ordinary scripts: allowed by the hook, under
/// `--block-review` too, as on main (the round before read them as
/// JavaScript: unreadable, a reset, a change).
#[test]
fn hermes_python_is_not_read_as_javascript() {
    let host = Host::new();
    for code in [
        "import json\n# list what's there\nprint(json.dumps(sorted(os.listdir('.'))))",
        "import pandas as pd\ndf = pd.DataFrame({'a': [1, 2]}).reset_index()\nprint(df.head())",
        "d = {}\nd.update(a=1)\nprint(d)",
    ] {
        for flags in [
            &["--agent", "hermes"][..],
            &["--agent", "hermes", "--block-review"][..],
        ] {
            let answer = host.hook(flags, "execute_code", code);
            assert_eq!(answer.code, Some(0), "{flags:?} {code}: {answer:?}");
            assert!(
                !answer.stdout.contains("block") && !answer.stdout.contains("approve"),
                "{flags:?} {code}: {answer:?}"
            );
        }
    }
}

/// The round's cases through the real hook: a request method in lower case
/// or by shorthand, a template with substitutions, an escape, code built at
/// run time and a call hidden behind a `/` are each a review (a refusal
/// under `--block-review`); methods of the script's own values run.
#[test]
fn round_one_cases_through_the_hook() {
    let host = Host::new();
    for code in [
        "const method = \"delete\"; await fetch(u, { method })",
        "await fetch(u, { \"method\": \"delete\" })",
        "await octokit.request(`DELETE /repos/${o}/${r}`)",
        "await octokit.request(\"\\x44ELETE /repos/o/r\")",
        "(0, eval)(s)",
        "Reflect.get(cloudflare.zones, \"delete\").call(cloudflare.zones, {})",
        "await env.DB.exec(\"SELECT 1; DROP TABLE users\")",
        "let a = 0; a++ /cloudflare.zones.delete({ zone_id: 'z' })/ 1",
        "{} /\"/; await cloudflare.zones.delete({ zone_id: 'z' }); //\"",
        "// x\rawait cloudflare.zones.delete({ zone_id: 'z' })",
    ] {
        let enforce = host.hook(&["--agent", "claude-code"], TOOL, code);
        assert_eq!(hook_verdict(&enforce), "review", "{code}: {enforce:?}");
        let strict = host.hook(&["--agent", "claude-code", "--block-review"], TOOL, code);
        assert_eq!(hook_verdict(&strict), "deny", "{code}: {strict:?}");
    }
    for code in [
        "const m = new Map(); m.set(\"a\", 1); m.delete(\"a\"); return m.size;",
        "const q = new URLSearchParams(s); q.delete(\"a\"); return q.toString();",
        "return crypto.createHash(\"sha256\").update(body).digest(\"hex\");",
    ] {
        let strict = host.hook(&["--agent", "claude-code", "--block-review"], TOOL, code);
        assert_eq!(hook_verdict(&strict), "allow", "{code}: {strict:?}");
    }
}

/// A shell script handed to `execute` with no language named is not read as
/// JavaScript: the proxy's strict mode finds no `AG-CODE-MODE` in it.
#[test]
fn a_shell_script_is_not_read_as_javascript_by_the_proxy() {
    let host = Host::new();
    let code = "# show the build\nls -la build && echo it's there";
    let proxied = host.proxy("strict", code);
    assert!(!proxied.contains("AG-CODE-MODE"), "{proxied}");
}

/// The second round's cases through the real hook and proxy: a script that
/// names its method through many names answers in time (it took past the
/// hook's 10 s), the items of a page's elements and Node's hashes run, and
/// a shell line handed to `execute` keeps the reading it had before.
#[test]
fn round_two_cases_through_the_hook_and_proxy() {
    let host = Host::new();
    let v = 100;
    let named = format!(
        "{}{}{}{}{}",
        "method=b;".repeat(v),
        "b=c;".repeat(v),
        "c=d;".repeat(v),
        "d=e;".repeat(v),
        "f({method});".repeat(v)
    );
    let started = std::time::Instant::now();
    let strict = host.hook(&["--agent", "claude-code", "--block-review"], TOOL, &named);
    assert_eq!(hook_verdict(&strict), "deny", "{strict:?}");
    let proxied = host.proxy("strict", &named);
    assert_eq!(proxy_verdict(&proxied), "refused", "{proxied}");
    let took = started.elapsed();
    assert!(took < std::time::Duration::from_secs(8), "{took:?}");
    for code in [
        "document.querySelectorAll(\".ad\").forEach((e) => e.remove())",
        "for (const el of document.querySelectorAll(\".ad\")) el.remove();",
        "const { createHash } = require(\"node:crypto\"); return createHash(\"sha256\").update(s).digest(\"hex\");",
        "const c = require(\"crypto\"); return c.createHash(\"sha256\").update(s).digest(\"hex\");",
    ] {
        let strict = host.hook(&["--agent", "claude-code", "--block-review"], TOOL, code);
        assert_eq!(hook_verdict(&strict), "allow", "{code}: {strict:?}");
    }
    let shell = "ls -la build && echo it's there";
    let enforce = host.hook(&["--agent", "claude-code"], "mcp__sh__execute", shell);
    assert_eq!(hook_verdict(&enforce), "allow", "{enforce:?}");
    let strict = host.hook(
        &["--agent", "claude-code", "--block-review"],
        "mcp__sh__execute",
        shell,
    );
    assert_eq!(hook_verdict(&strict), "allow", "{strict:?}");
    let proxied = host.proxy("strict", shell);
    assert!(!proxied.contains("AG-CODE-MODE"), "{proxied}");
}
