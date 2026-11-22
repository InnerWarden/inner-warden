//! End-to-end: `agents connect` leaves a server the agent signs in to by
//! itself (OAuth) as it is, so the agent keeps signing in to it, and says
//! that the agent's hook judges its calls instead.
//!
//! Through the proxy's stdio wrapper such a server lost its sign-in: the
//! client signs in only to a server it reaches by URL, so every call came
//! back 401 and the proxy asked for a token in the headers. Codex is asked
//! which servers it signs in to (`codex mcp list --json`, which names each
//! server's `auth_status` and never a token); here a stand-in prints the
//! listing Codex prints, and no real sign-in is run. Cursor runs the OAuth
//! sign-in by itself for a server it reaches by URL alone.
//!
//! Drives the REAL binary over a disposable HOME.

#![cfg(unix)]

use std::process::Command;

/// The suite's PATH less every folder that holds a `codex`.
fn path_without_codex() -> std::ffi::OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let kept = std::env::split_paths(&path)
        .filter(|dir| !dir.join("codex").exists() && !dir.join("codex.exe").exists());
    std::env::join_paths(kept).expect("folders split from PATH join back")
}

/// `linear`: reached by URL alone, Codex signed in to it with `codex mcp
/// login` (nothing in the file says so). `plain`: by URL alone, no
/// sign-in. `docs`: by URL with its token in a variable, which the proxy
/// carries. `local`: a local server.
const CODEX_CONFIG: &str = "[mcp_servers.linear]\nurl = \"https://mcp.linear.example/mcp\"\n\n\
[mcp_servers.plain]\nurl = \"https://plain.example/mcp\"\n\n\
[mcp_servers.docs]\nurl = \"https://docs.example/mcp\"\nbearer_token_env_var = \"DOCS_TOKEN\"\n\n\
[mcp_servers.local]\ncommand = \"fs-server\"\n";

/// What `codex mcp list --json` prints for [`CODEX_CONFIG`] (Codex CLI's
/// `mcp list`: one object per server, `auth_status` in snake case).
const CODEX_LIST: &str = r#"[{"name":"docs","enabled":true,"transport":{"type":"streamable_http","url":"https://docs.example/mcp","bearer_token_env_var":"DOCS_TOKEN"},"auth_status":"bearer_token"},{"name":"linear","enabled":true,"transport":{"type":"streamable_http","url":"https://mcp.linear.example/mcp"},"auth_status":"o_auth"},{"name":"local","enabled":true,"transport":{"type":"stdio","command":"fs-server","args":[]},"auth_status":"unsupported"},{"name":"plain","enabled":true,"transport":{"type":"streamable_http","url":"https://plain.example/mcp"},"auth_status":"unsupported"}]"#;

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("home/.codex")).unwrap();
        std::fs::create_dir_all(dir.path().join("bin")).unwrap();
        Self { dir }
    }

    fn home(&self) -> std::path::PathBuf {
        self.dir.path().join("home")
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.home().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn read(&self, relative: &str) -> String {
        std::fs::read_to_string(self.home().join(relative)).unwrap()
    }

    /// A `codex` on PATH that prints [`CODEX_LIST`] for `mcp list
    /// --json` and fails at anything else (the trust a connect asks for).
    fn with_codex(&self) {
        use std::os::unix::fs::PermissionsExt;
        let script = self.dir.path().join("bin/codex");
        std::fs::write(&script, "").unwrap();
        std::fs::write(self.dir.path().join("list.json"), CODEX_LIST).unwrap();
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nif [ \"$1 $2 $3\" = \"mcp list --json\" ]; then cat '{}'; exit 0; fi\nexit 1\n",
                self.dir.path().join("list.json").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn connect(&self, agent: &str) -> String {
        let mut path = vec![self.dir.path().join("bin")];
        path.extend(std::env::split_paths(&path_without_codex()));
        let mut command = Command::new(env!("CARGO_BIN_EXE_innerwarden"));
        command
            .args(["agents", "connect", agent])
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("PATH", std::env::join_paths(path).unwrap())
            .env_remove("CODEX_HOME");
        for marker in [
            "CLAUDECODE",
            "CLAUDE_CODE_ENTRYPOINT",
            "CODEX_SANDBOX",
            "CODEX_SANDBOX_NETWORK_DISABLED",
            "GEMINI_CLI",
            "OPENCLAW_SHELL",
        ] {
            command.env_remove(marker);
        }
        let out = command.output().expect("run innerwarden");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }
}

/// The table of one server in a Codex config, as text.
fn table(config: &str, name: &str) -> String {
    let doc: toml::Table = toml::from_str(config).expect("the config still parses");
    doc["mcp_servers"][name].to_string()
}

fn wrapped(config: &str, name: &str) -> bool {
    table(config, name).contains("proxy")
}

/// FAILS ON REVERT: wrap every server reached by URL in
/// `connect_by_one_mechanism` again (`wrap_toml`) and `linear` becomes a
/// stdio wrapper Codex no longer signs in to.
#[test]
fn a_server_codex_signs_in_to_is_left_as_it_is() {
    let host = Host::new();
    host.write(".codex/config.toml", CODEX_CONFIG);
    host.with_codex();
    let out = host.connect("codex");
    let config = host.read(".codex/config.toml");
    assert_eq!(
        table(&config, "linear"),
        table(CODEX_CONFIG, "linear"),
        "{out}\n{config}"
    );
    for carried in ["plain", "docs", "local"] {
        assert!(
            wrapped(&config, carried),
            "{carried} not wrapped:\n{out}\n{config}"
        );
    }
    assert!(
        out.contains("left as they are, Codex signs in to them itself: linear; the Codex hook"),
        "{out}"
    );
}

/// With no Codex to ask, a server reached by URL alone may be one Codex
/// signs in to: it is left as it is, and the line says why. A server whose
/// token the proxy sends is carried as before.
#[test]
fn with_no_codex_to_ask_a_server_reached_by_url_alone_is_left() {
    let host = Host::new();
    host.write(".codex/config.toml", CODEX_CONFIG);
    let out = host.connect("codex");
    let config = host.read(".codex/config.toml");
    for left in ["linear", "plain"] {
        assert_eq!(
            table(&config, left),
            table(CODEX_CONFIG, left),
            "{out}\n{config}"
        );
    }
    for carried in ["docs", "local"] {
        assert!(
            wrapped(&config, carried),
            "{carried} not wrapped:\n{out}\n{config}"
        );
    }
    assert!(out.contains("Codex could not be asked"), "{out}");
    assert!(out.contains(": linear, plain;"), "{out}");
}

/// A config whose only server Codex signs in to has nothing for the proxy:
/// the connect says so, and names the server and the hook that judges it.
#[test]
fn a_config_of_servers_codex_signs_in_to_only_has_nothing_to_route() {
    let host = Host::new();
    let only = "[mcp_servers.linear]\nurl = \"https://mcp.linear.example/mcp\"\n";
    host.write(".codex/config.toml", only);
    host.with_codex();
    let out = host.connect("codex");
    assert_eq!(host.read(".codex/config.toml"), only);
    assert!(
        out.contains("no local MCP servers to route through the guard proxy; left as they are, Codex signs in to them itself: linear"),
        "{out}"
    );
}

/// Cursor signs in by itself to a server it reaches by URL alone: left as
/// it is. One with headers (a token the person wrote) and a local one go
/// through the proxy.
///
/// FAILS ON REVERT: `mcp_wire::wrap` for Cursor again and `linear`
/// becomes a stdio wrapper.
#[test]
fn a_cursor_server_reached_by_url_alone_is_left_as_it_is() {
    let host = Host::new();
    let config = serde_json::json!({"mcpServers": {
        "linear": {"url": "https://mcp.linear.example/mcp"},
        "docs": {"url": "https://docs.example/mcp", "headers": {"Authorization": "Bearer ${env:DOCS_TOKEN}"}},
        "local": {"command": "fs-server"}
    }});
    host.write(".cursor/mcp.json", &config.to_string());
    let out = host.connect("cursor");
    let after: serde_json::Value = serde_json::from_str(&host.read(".cursor/mcp.json")).unwrap();
    assert_eq!(
        after["mcpServers"]["linear"], config["mcpServers"]["linear"],
        "{out}"
    );
    for carried in ["docs", "local"] {
        assert!(
            after["mcpServers"][carried].to_string().contains("proxy"),
            "{carried} not wrapped:\n{out}\n{after}"
        );
    }
    assert!(
        out.contains("cursor signs in to them itself: linear"),
        "{out}"
    );
}
