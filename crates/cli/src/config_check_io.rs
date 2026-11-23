//! The I/O half of the config check: read each agent file that is there,
//! hand it to the pure `config_check`, and print what it says. Reads only;
//! never writes, and never prints the value of a secret it found.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::config_check::{self, Dir, Layout, Report, Unread};

/// A file bigger than this is not read (`~/.claude.json` grows with the
/// projects Claude Code has opened, but stays far below it).
const MAX_BYTES: u64 = 32 * 1024 * 1024;

/// Read every file the check knows, under `home` or the folders
/// `CLAUDE_CONFIG_DIR` and `CODEX_HOME` name, and say what is set there.
pub fn check(home: &Path) -> Report {
    let var = |name: &str| std::env::var(name).ok();
    check_in(
        home,
        config_check::moved_dir(var(config_check::CLAUDE_DIR_ENV).as_deref()),
        config_check::moved_dir(var(config_check::CODEX_DIR_ENV).as_deref()),
    )
}

/// The file as the person knows it: `~/...` under the home, else the path.
fn shown(home: &Path, path: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => path.display().to_string(),
    }
    .chars()
    .filter(|c| !c.is_control())
    .collect()
}

/// Read every file the check knows, Claude Code's in `claude_dir` and
/// Codex's in `codex_dir` when they are given, else under `home`.
/// A file that is not there is skipped; one that is there and cannot be
/// read or parsed is named, never taken for "nothing found".
pub fn check_in(home: &Path, claude_dir: Option<PathBuf>, codex_dir: Option<PathBuf>) -> Report {
    let mut report = Report::default();
    for (agent, dir, in_dir, rel, layout) in config_check::FILES {
        let moved = match dir {
            Dir::Home => None,
            Dir::Claude => claude_dir.as_deref(),
            Dir::Codex => codex_dir.as_deref(),
        };
        let path = match moved {
            Some(folder) => folder.join(in_dir),
            None => home.join(rel),
        };
        let shown = shown(home, &path);
        let meta = match std::fs::metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                report.unread.push(Unread {
                    file: shown,
                    why: error.to_string(),
                });
                continue;
            }
        };
        if !meta.is_file() {
            continue;
        }
        let too_big = || Unread {
            file: shown.clone(),
            why: format!("larger than {} MiB", MAX_BYTES / (1024 * 1024)),
        };
        if meta.len() > MAX_BYTES {
            report.unread.push(too_big());
            continue;
        }
        // The size is held while reading too: the file can grow after the
        // metadata was taken.
        let text = match read_at_most(&path, MAX_BYTES) {
            Ok(Some(text)) => text,
            Ok(None) => {
                report.unread.push(too_big());
                continue;
            }
            Err(error) => {
                report.unread.push(Unread {
                    file: shown,
                    why: error.to_string(),
                });
                continue;
            }
        };
        match parse(&text, *layout) {
            Ok(root) => {
                report
                    .findings
                    .extend(config_check::check_file(agent, &shown, *layout, &root));
                report.read.push(shown);
            }
            Err(why) => report.unread.push(Unread { file: shown, why }),
        }
    }
    report
}

/// The file's text, or `None` when it holds more than `max` bytes.
fn read_at_most(path: &Path, max: u64) -> std::io::Result<Option<String>> {
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(max + 1)
        .read_to_string(&mut text)?;
    Ok((text.len() as u64 <= max).then_some(text))
}

/// The file's content as JSON values. The reason given on a parse error
/// names the format and the place, never the text around it: the text may be
/// a secret.
fn parse(text: &str, layout: Layout) -> Result<serde_json::Value, String> {
    if text.trim().is_empty() {
        return Ok(serde_json::Value::Null);
    }
    match layout {
        Layout::CodexConfig => toml::from_str::<toml::Value>(text)
            .map_err(|error| match error.span() {
                Some(span) => format!("not valid TOML (at byte {})", span.start),
                None => "not valid TOML".to_string(),
            })
            .and_then(|value| {
                serde_json::to_value(value).map_err(|_| "not valid TOML".to_string())
            }),
        _ => serde_json::from_str(text).map_err(|error| {
            format!(
                "not valid JSON (line {}, column {})",
                error.line(),
                error.column()
            )
        }),
    }
}

/// The lines `setup` and `status --config` print for this home.
pub fn lines(home: &Path, indent: &str) -> Vec<String> {
    config_check::render(&check(home), indent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use config_check::Kind;

    /// A fake token of each shape the check names, and one under a name that
    /// says it is a secret. None of them is real.
    /// Put together from pieces so that no token shape sits whole in the
    /// source for a secret scanner to match.
    const FAKE_GITHUB: &str = concat!("gh", "p_", "FAKEfake0123456789FAKEfake0123456789");
    const FAKE_ANTHROPIC: &str = "sk-ant-FAKEfake0123456789FAKEfake";
    const FAKE_PLAIN: &str = "hunter2-FAKE-not-a-real-password";
    const FAKE_AWS: &str = "AKIAFAKEFAKEFAKE1234";

    fn home_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        for (rel, body) in files {
            let path = home.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        home
    }

    fn kinds(report: &Report, file: &str) -> Vec<Kind> {
        report
            .findings
            .iter()
            .filter(|f| f.file == file)
            .map(|f| f.kind)
            .collect()
    }

    /// What the check says about this home alone: never the folders the
    /// variables of whoever runs the tests name.
    fn said_at(home: &Path) -> Vec<String> {
        config_check::render(&check_in(home, None, None), "")
    }

    fn sample_home() -> tempfile::TempDir {
        let claude_settings = format!(
            r#"{{
  "permissions": {{"allow": ["Bash(git status)", "mcp__github", "mcp__fs__read_file", "mcp__slack__*"], "defaultMode": "bypassPermissions"}},
  "enableAllProjectMcpServers": true,
  "env": {{"ANTHROPIC_API_KEY": "{FAKE_ANTHROPIC}", "DEBUG": "1", "GITHUB_TOKEN": "${{GITHUB_TOKEN}}"}},
  "hooks": {{"PreToolUse": [
    {{"matcher": "Bash", "hooks": [{{"type": "command", "command": "/home/u/.local/bin/innerwarden hook"}}]}},
    {{"matcher": "*", "hooks": [{{"type": "command", "command": "OTHER_KEY={FAKE_PLAIN} /opt/otherguard/bin/otherguard check --token {FAKE_GITHUB}"}}]}}
  ]}}
}}"#
        );
        let claude_state = format!(
            r#"{{"mcpServers": {{"github": {{"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {{"GITHUB_PERSONAL_ACCESS_TOKEN": "{FAKE_GITHUB}"}}}}}},
  "projects": {{"/home/u/app": {{"mcpServers": {{"pinned": {{"command": "npx", "args": ["-y", "@scope/tool@1.4.2"]}}}}}}}}}}"#
        );
        let cursor_mcp = format!(
            r#"{{"mcpServers": {{
  "fs": {{"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@latest", "/home/u"], "autoApprove": ["read_file", "list_directory"]}},
  "remote": {{"url": "https://mcp.example.com/sse?api_key={FAKE_PLAIN}"}},
  "wrapped": {{"command": "/home/u/.local/bin/innerwarden", "args": ["proxy", "--monitor", "--", "uvx", "mcp-server-fetch"]}}
}}}}"#
        );
        let cursor_hooks = r#"{"version": 1, "hooks": {"beforeShellExecution": [{"command": "/home/u/.local/bin/innerwarden hook --cursor"}, {"command": "./hooks/audit.sh"}]}}"#;
        let codex = format!(
            r#"approval_policy = "never"

[profiles.ci]
approval_policy = "never"

[mcp_servers.search]
command = "uvx"
args = ["mcp-server-search==0.6.1"]

[mcp_servers.db]
command = "uvx"
args = ["--from", "mcp-db>=1.0", "mcp-db", "--password", "{FAKE_PLAIN}"]
env = {{ AWS_ACCESS_KEY_ID = "{FAKE_AWS}" }}
"#
        );
        let gemini = format!(
            r#"{{"mcpServers": {{"trusted": {{"command": "bunx", "args": ["some-mcp"], "trust": true, "env": {{"API_TOKEN": "{FAKE_PLAIN}", "OTHER": "$OTHER"}}}}}},
  "hooks": {{"BeforeTool": [{{"matcher": ".*", "hooks": [{{"type": "command", "command": "python3 /home/u/guard.py"}}]}}]}}}}"#
        );
        home_with(&[
            (".claude/settings.json", &claude_settings),
            (".claude.json", &claude_state),
            (".cursor/mcp.json", &cursor_mcp),
            (".cursor/hooks.json", cursor_hooks),
            (".codex/config.toml", &codex),
            (".gemini/settings.json", &gemini),
        ])
    }

    /// Each of the four agents' sample files gives the findings its content
    /// holds, and nothing for what is fine: a pinned package, a variable
    /// reference, a single tool allowed by name, InnerWarden's own hook.
    ///
    /// FAILS ON REVERT: drop a layout's arm in `check_file`, or take a
    /// pinned `@1.4.2` / `==0.6.1` for unpinned, and its list changes.
    #[test]
    fn each_agent_file_says_what_is_set_in_it() {
        let home = sample_home();
        let report = check_in(home.path(), None, None);
        assert!(report.unread.is_empty(), "{:?}", report.unread);
        assert_eq!(report.read.len(), 6, "{:?}", report.read);

        use Kind::*;
        assert_eq!(
            kinds(&report, "~/.claude/settings.json"),
            vec![
                AutoApprove,
                AutoApprove,
                AutoApprove,
                AutoApprove,
                Secret,
                OtherHook
            ],
            "{:#?}",
            report.findings
        );
        assert_eq!(
            kinds(&report, "~/.claude.json"),
            vec![Unpinned, Secret],
            "{:#?}",
            report.findings
        );
        assert_eq!(
            kinds(&report, "~/.cursor/mcp.json"),
            vec![Unpinned, Secret, Unpinned],
            "{:#?}",
            report.findings
        );
        assert_eq!(kinds(&report, "~/.cursor/hooks.json"), vec![OtherHook]);
        assert_eq!(
            kinds(&report, "~/.codex/config.toml"),
            vec![AutoApprove, AutoApprove, Unpinned, Secret, Secret],
            "{:#?}",
            report.findings
        );
        assert_eq!(
            kinds(&report, "~/.gemini/settings.json"),
            vec![AutoApprove, Unpinned, Secret, OtherHook],
            "{:#?}",
            report.findings
        );

        let said = config_check::render(&report, "").join("\n");
        // What to do, with the InnerWarden command where there is one.
        for expected in [
            "innerwarden agents connect cursor",
            "innerwarden agents connect codex",
            "innerwarden agents connect gemini",
            "innerwarden mcp list",
            "`@modelcontextprotocol/server-filesystem@<version>`",
            "`uvx mcp-db==<version>`",
            "`GITHUB_PERSONAL_ACCESS_TOKEN` to a value written in the file (GitHub token)",
            "once `innerwarden agents connect codex` puts the proxy in front of it",
            "`AWS_ACCESS_KEY_ID` to a value written in the file (AWS access key)",
            "its URL carries a value in its `api_key` parameter (secret)",
            "`otherguard`",
            "`audit.sh`",
            "`python3`",
            "nothing was changed",
        ] {
            assert!(said.contains(expected), "missing {expected}:\n{said}");
        }
        // Claude Code's MCP servers are not put behind the proxy by connect,
        // so their line promises no pinning of tool definitions.
        let claude_unpinned = report
            .findings
            .iter()
            .find(|f| f.file == "~/.claude.json" && f.kind == Unpinned)
            .unwrap();
        assert!(
            !claude_unpinned.next.contains("proxy"),
            "{}",
            claude_unpinned.next
        );
        // A proxied server is read past the wrapper and known to be proxied.
        assert!(
            said.contains("`mcp-server-fetch`") && said.contains("the proxy already holds"),
            "{said}"
        );
    }

    /// The value of a secret never appears in what the check says, wherever
    /// it was written: an env table, a URL, an argument, a hook's command
    /// line.
    ///
    /// FAILS ON REVERT: put the value in a finding (for example
    /// `format!("... {value}")` in `secrets_in_server`) and this sees it.
    #[test]
    fn the_value_of_a_secret_is_never_said() {
        let home = sample_home();
        let report = check_in(home.path(), None, None);
        let said = format!(
            "{}\n{:?}",
            config_check::render(&report, "  ").join("\n"),
            report
        );
        for fake in [FAKE_GITHUB, FAKE_ANTHROPIC, FAKE_PLAIN, FAKE_AWS] {
            assert!(!said.contains(fake), "the value {fake} was said:\n{said}");
            assert!(
                !said.contains(&fake[4..16]),
                "a piece of {fake} was said:\n{said}"
            );
        }
        let secrets = report
            .findings
            .iter()
            .filter(|f| f.kind == Kind::Secret)
            .count();
        assert_eq!(secrets, 6, "{:#?}", report.findings);
    }

    /// A file that is there and cannot be parsed is named as not read,
    /// never as clean, and the reason does not quote the file's text.
    ///
    /// FAILS ON REVERT: skip a file that does not parse and the report says
    /// "Nothing to point out" about a file nobody read.
    #[test]
    fn a_file_that_cannot_be_read_is_never_called_clean() {
        let broken = format!(r#"{{"env": {{"TOKEN": "{FAKE_GITHUB}"#);
        let home = home_with(&[
            (".cursor/mcp.json", &broken),
            (".codex/config.toml", "x = = 1"),
        ]);
        let report = check_in(home.path(), None, None);
        assert!(report.findings.is_empty() && report.read.is_empty());
        assert_eq!(report.unread.len(), 2, "{:?}", report.unread);
        let said = config_check::render(&report, "").join("\n");
        assert!(!said.contains("Nothing to point out"), "{said}");
        assert!(
            said.contains("could not read ~/.cursor/mcp.json: not valid JSON"),
            "{said}"
        );
        assert!(
            said.contains("could not read ~/.codex/config.toml: not valid TOML"),
            "{said}"
        );
        assert!(!said.contains(FAKE_GITHUB), "{said}");

        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            said_at(empty.path()),
            vec!["No config of Claude Code, Codex, Gemini CLI or Cursor here to check."]
        );
        let clean = home_with(&[(
            ".cursor/mcp.json",
            r#"{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21"], "env": {"TOKEN": "${env:TOKEN}"}}}}"#,
        )]);
        assert_eq!(
            said_at(clean.path()),
            vec!["Nothing to point out in ~/.cursor/mcp.json (auto-approve, unpinned packages, keys in the file, other hooks)."]
        );
    }

    /// Which runners and versions count as fixed.
    #[test]
    fn a_version_is_fixed_only_when_nothing_is_left_open() {
        let run = |command: &str, args: &[&str]| {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            config_check::unpinned(command, &args).is_some()
        };
        assert!(run("npx", &["-y", "pkg"]));
        assert!(run("npx", &["pkg@latest"]));
        assert!(run("npx", &["pkg@^1.2.0"]));
        assert!(run("npx", &["pkg@1.x"]));
        assert!(run("npx", &["@scope/pkg"]));
        assert!(run("/usr/local/bin/npx.cmd", &["--yes", "@scope/pkg@~2.0"]));
        assert!(run("npx", &["-p", "pkg", "pkg-bin"]));
        assert!(run("pnpm", &["dlx", "pkg"]));
        assert!(run("bunx", &["pkg"]));
        assert!(run("uvx", &["mcp-server-fetch"]));
        assert!(run("uvx", &["--python", "3.12", "pkg>=1"]));
        assert!(run("uv", &["tool", "run", "pkg"]));

        assert!(!run("npx", &["-y", "pkg@1.2.3"]));
        assert!(!run("npx", &["@scope/pkg@0.6.0-beta.1"]));
        assert!(!run("npx", &["--package=pkg@1.0.0", "pkg-bin"]));
        assert!(!run("uvx", &["pkg==0.4.1"]));
        assert!(!run("uvx", &["pkg@0.4.1"]));
        assert!(!run("uvx", &["--from", "pkg==1.0", "pkg-cli"]));
        assert!(!run("npx", &["./local-server"]));
        assert!(!run("npx", &["github:owner/repo"]));
        assert!(!run("node", &["server.js"]));
        assert!(!run("pnpm", &["install"]));
        assert!(!run("npx", &[]));
    }

    /// A value is a secret by its shape or the name it is under; a variable
    /// reference, a plain flag value or a number is not.
    #[test]
    fn a_secret_is_told_apart_from_a_reference_or_a_plain_value() {
        use config_check::secret_kind;
        assert_eq!(secret_kind("X", FAKE_GITHUB), Some("GitHub token"));
        assert_eq!(
            secret_kind("Authorization", &format!("Bearer {FAKE_ANTHROPIC}")),
            Some("Anthropic API key")
        );
        assert_eq!(secret_kind("API_TOKEN", FAKE_PLAIN), Some("secret"));
        assert_eq!(secret_kind("API_TOKEN", "${API_TOKEN}"), None);
        assert_eq!(secret_kind("API_TOKEN", "$API_TOKEN"), None);
        assert_eq!(secret_kind("API_TOKEN", "${env:API_TOKEN}"), None);
        assert_eq!(secret_kind("API_TOKEN", "short"), None);
        assert_eq!(secret_kind("MAX_TOKENS", "4096"), None);
        assert_eq!(secret_kind("USE_AUTH", "true"), None);
        assert_eq!(
            secret_kind("TOKEN_FILE", "/home/u/.config/token-file"),
            None
        );
        assert_eq!(secret_kind("LOG_LEVEL", FAKE_PLAIN), None);
        assert_eq!(secret_kind("MODEL", "sk-short"), None);
    }

    fn findings_of(agent: &'static str, layout: Layout, body: &str) -> Vec<config_check::Finding> {
        let root: serde_json::Value = serde_json::from_str(body).unwrap();
        config_check::check_file(agent, "~/f", layout, &root)
    }

    /// Only an approval field the agent's own docs name is counted: Gemini's
    /// `trust`. `autoApprove`, `alwaysAllow` and `auto_approve` are read by
    /// none of the four agents, so they are not said, wherever they are.
    ///
    /// FAILS ON REVERT: count those keys again and the other agents' files
    /// say "runs without asking" about a field the agent never reads.
    #[test]
    fn only_an_approval_field_the_agent_documents_is_counted() {
        let foreign = r#"{"mcpServers": {"s": {"command": "node", "args": ["s.js"],
            "autoApprove": ["*"], "alwaysAllow": true, "auto_approve": true}}}"#;
        for (agent, layout) in [
            ("claude-code", Layout::ClaudeState),
            ("cursor", Layout::CursorMcp),
            ("gemini", Layout::GeminiSettings),
        ] {
            let found = findings_of(agent, layout, foreign);
            assert!(found.is_empty(), "{agent}: {found:?}");
        }
        let codex: serde_json::Value = serde_json::to_value(
            toml::from_str::<toml::Value>(
                "[mcp_servers.s]\ncommand = \"node\"\nauto_approve = true\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(config_check::check_file("codex", "~/f", Layout::CodexConfig, &codex).is_empty());

        let trusted = r#"{"mcpServers": {"s": {"command": "node", "trust": true}}}"#;
        let found = findings_of("gemini", Layout::GeminiSettings, trusted);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].kind, Kind::AutoApprove);
        assert!(found[0].what.contains("`trust` is on"), "{}", found[0].what);
        // `trust` is Gemini's: another agent's file with it says nothing.
        assert!(findings_of("cursor", Layout::CursorMcp, trusted).is_empty());
    }

    /// `npx -c` / `--call` run a shell string: it is not a package, so it is
    /// not said back, and a token in it is named but never printed.
    ///
    /// FAILS ON REVERT: without the `no_package` flags the whole string is
    /// taken for the package and said twice, token included.
    #[test]
    fn a_shell_string_given_to_npx_is_never_said_back() {
        let shell = format!("mcp-server --token {FAKE_GITHUB}");
        for args in [
            vec!["-c".to_string(), shell.clone()],
            vec!["--call".to_string(), shell.clone()],
            vec![format!("--call={shell}")],
            vec!["-y".to_string(), shell.clone()],
            // A one-word shell string is still not a package.
            vec!["-c".to_string(), "mcp-tool".to_string()],
            vec!["--call=mcp-tool".to_string()],
        ] {
            assert_eq!(config_check::unpinned("npx", &args), None, "{args:?}");
        }
        let body =
            serde_json::json!({"mcpServers": {"x": {"command": "npx", "args": ["-c", shell]}}})
                .to_string();
        for agent in ["claude-code", "cursor", "gemini"] {
            let found = findings_of(agent, Layout::CursorMcp, &body);
            let said = format!("{found:?}");
            assert!(!said.contains(FAKE_GITHUB), "{said}");
            assert!(!said.contains(&FAKE_GITHUB[4..16]), "{said}");
            assert_eq!(
                found.iter().map(|f| f.kind).collect::<Vec<_>>(),
                vec![Kind::Secret],
                "{said}"
            );
        }
    }

    /// A path, a URL with no password, or a name with `auth` inside a word
    /// is not a secret; `auth` as a whole word and a URL with a password are.
    ///
    /// FAILS ON REVERT: the old name match took `AUTHOR` and `OAUTH` for
    /// `auth`, and any long value under `CREDENTIALS` for a secret.
    #[test]
    fn a_path_an_address_or_an_author_is_not_a_secret() {
        use config_check::secret_kind;
        for (key, value) in [
            (
                "GOOGLE_APPLICATION_CREDENTIALS",
                "/home/u/.config/gcloud/key.json",
            ),
            (
                "GOOGLE_APPLICATION_CREDENTIALS",
                "~/keys/service-account.json",
            ),
            (
                "GOOGLE_APPLICATION_CREDENTIALS",
                "./keys/service-account.json",
            ),
            ("GOOGLE_APPLICATION_CREDENTIALS", "C:\\Users\\u\\key.json"),
            ("GOOGLE_APPLICATION_CREDENTIALS", "D:/keys/key.json"),
            ("GIT_AUTHOR_EMAIL", "me@example.com"),
            ("GIT_AUTHOR_NAME", "Someone Else"),
            ("OAUTH_REDIRECT_URI", "http://localhost:3000/cb"),
            ("AUTH_SERVER", "https://login.example.com/oauth2"),
        ] {
            assert_eq!(secret_kind(key, value), None, "{key}={value}");
        }
        assert_eq!(secret_kind("AUTH_HEADER", FAKE_PLAIN), Some("secret"));
        assert_eq!(secret_kind("X_AUTH", FAKE_PLAIN), Some("secret"));
        assert_eq!(
            secret_kind(
                "DATABASE_PASSWORD",
                "postgres://u:hunter2-FAKE@db.example.com/app"
            ),
            Some("secret")
        );
        assert_eq!(
            secret_kind(
                "WEBHOOK_TOKEN",
                &format!("https://h.example.com/x?api_key={FAKE_PLAIN}")
            ),
            Some("secret")
        );
    }

    /// A pre-release such as `2.0.0-next.3` is fixed: `x` is a wildcard
    /// only as a whole part between dots.
    ///
    /// FAILS ON REVERT: the old check saw the `x` in `next` and called the
    /// version open.
    #[test]
    fn a_prerelease_is_a_fixed_version() {
        let run = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            config_check::unpinned("npx", &args).is_some()
        };
        assert!(!run(&["-y", "@scope/tool@2.0.0-next.3"]));
        assert!(!run(&["tool@1.0.0-rc.x1"]));
        assert!(!run(&["tool@3.1.4-beta.1+exp.sha.5114f85"]));
        assert!(run(&["tool@1.x"]));
        assert!(run(&["tool@1.2.X"]));
        assert!(run(&["tool@1.*"]));
    }

    /// uvx flags that take a value do not have that value read as the
    /// package.
    ///
    /// FAILS ON REVERT: without them `only-managed` (and the rest) is said
    /// to be the package, unpinned.
    #[test]
    fn a_uvx_flag_value_is_not_the_package() {
        let run = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            config_check::unpinned("uvx", &args)
        };
        for flag in [
            "--python-preference",
            "--index-strategy",
            "--env-file",
            "--prefix",
        ] {
            assert_eq!(run(&[flag, "some-value", "mcp-x==1.0"]), None, "{flag}");
            let found = run(&[flag, "some-value", "mcp-x"]).expect(flag);
            assert_eq!(found.said, "`uvx` runs `mcp-x`", "{flag}");
        }
    }

    /// A hook behind `sudo -u bob` or `env -u VAR` is named by its program.
    ///
    /// FAILS ON REVERT: the old pick took `-u` for the program.
    #[test]
    fn a_hook_is_named_by_its_program_past_sudo_and_its_flags() {
        for (command, program) in [
            ("sudo -u bob /opt/g", "`g`"),
            ("sudo -n -u bob -- /opt/g --check", "`g`"),
            ("env -u HOME A=1 /usr/bin/other-guard", "`other-guard`"),
            ("exec -a name /opt/h", "`h`"),
        ] {
            let body =
                serde_json::json!({"hooks": {"beforeShellExecution": [{"command": command}]}})
                    .to_string();
            let found = findings_of("cursor", Layout::CursorHooks, &body);
            assert_eq!(found.len(), 1, "{command}: {found:?}");
            assert!(
                found[0]
                    .what
                    .contains(&format!("another program, {program},")),
                "{command}: {}",
                found[0].what
            );
        }
    }

    /// `CLAUDE_CONFIG_DIR` and `CODEX_HOME` move where the files are read;
    /// unset, or not an absolute path, the home is read.
    ///
    /// FAILS ON REVERT: the old check read only `~/.claude` and `~/.codex`
    /// and said nothing about the folder the agent really uses.
    #[test]
    fn the_folders_the_variables_name_are_read() {
        let home = home_with(&[(".claude/settings.json", "{}"), (".codex/config.toml", "")]);
        let moved = home_with(&[
            (
                "claude/settings.json",
                r#"{"permissions": {"defaultMode": "bypassPermissions"}}"#,
            ),
            (
                "claude/.claude.json",
                r#"{"mcpServers": {"s": {"command": "npx", "args": ["s"]}}}"#,
            ),
            ("codex/config.toml", "approval_policy = \"never\"\n"),
        ]);
        let claude_dir = moved.path().join("claude");
        let codex_dir = moved.path().join("codex");
        let report = check_in(
            home.path(),
            Some(claude_dir.clone()),
            Some(codex_dir.clone()),
        );
        let files: Vec<&str> = report.findings.iter().map(|f| f.file.as_str()).collect();
        let settings = claude_dir.join("settings.json").display().to_string();
        let state = claude_dir.join(".claude.json").display().to_string();
        let codex = codex_dir.join("config.toml").display().to_string();
        assert_eq!(
            files,
            vec![settings.as_str(), state.as_str(), codex.as_str()],
            "{report:#?}"
        );
        assert!(
            !report
                .read
                .iter()
                .any(|f| f.starts_with("~/.claude") || f.starts_with("~/.codex")),
            "{:?}",
            report.read
        );

        let at_home = check_in(home.path(), None, None);
        assert_eq!(
            at_home.read,
            vec!["~/.claude/settings.json", "~/.codex/config.toml"]
        );
        assert!(at_home.findings.is_empty());

        use config_check::moved_dir;
        assert_eq!(moved_dir(None), None);
        assert_eq!(moved_dir(Some("relative/dir")), None);
        assert_eq!(moved_dir(Some("/a/../b")), None);
        assert_eq!(
            moved_dir(Some("/opt/claude")),
            Some(PathBuf::from("/opt/claude"))
        );
    }

    /// The tests read only the home they make. Run again with
    /// `CLAUDE_CONFIG_DIR` and `CODEX_HOME` naming folders that hold
    /// findings, as on the machine of someone who has set them, they still
    /// pass.
    ///
    /// FAILS ON REVERT: call `check()` (which reads the variables) in those
    /// tests and the run with the variables set fails.
    ///
    /// It runs the test binary again itself, straight, with libtest's own
    /// arguments (`<name> --exact --test-threads=1`): a run through a
    /// wrapper (`cross`, qemu, any `CARGO_TARGET_<triple>_RUNNER`) would
    /// start a binary built for another machine with no wrapper, so where
    /// such a runner is set in the environment it says so and checks
    /// nothing. A runner set only in `.cargo/config.toml` is not seen here.
    #[test]
    fn the_tests_read_only_the_home_they_make() {
        const CHILD: &str = "IW_CONFIG_CHECK_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            return;
        }
        if let Some((runner, _)) = std::env::vars_os().find(|(name, _)| {
            name.to_str()
                .is_some_and(|n| n.starts_with("CARGO_TARGET_") && n.ends_with("_RUNNER"))
        }) {
            eprintln!(
                "skipped: {} is set, and this test runs its own binary with no runner",
                runner.to_string_lossy()
            );
            return;
        }
        let other = home_with(&[
            (
                "claude/settings.json",
                r#"{"permissions": {"defaultMode": "bypassPermissions"}}"#,
            ),
            ("codex/config.toml", "approval_policy = \"never\"\n"),
        ]);
        let exe = std::env::current_exe().unwrap();
        for test in [
            "each_agent_file_says_what_is_set_in_it",
            "the_value_of_a_secret_is_never_said",
            "a_file_that_cannot_be_read_is_never_called_clean",
        ] {
            let name = format!("config_check_io::tests::{test}");
            let out = std::process::Command::new(&exe)
                .args([name.as_str(), "--exact", "--test-threads=1"])
                .env(CHILD, "1")
                .env(config_check::CLAUDE_DIR_ENV, other.path().join("claude"))
                .env(config_check::CODEX_DIR_ENV, other.path().join("codex"))
                .output()
                .unwrap();
            let said = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success() && said.contains("1 passed"),
                "{test} with the variables set:\n{said}{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    fn found(report: &Report) -> Vec<String> {
        report.findings.iter().map(|f| f.what.clone()).collect()
    }

    /// Claude Code's `permissions.allow`: an empty server name is no
    /// finding, `mcp__*` is said as a possibility, a server whose tools are
    /// denied in `permissions.deny` names them, a server denied whole is
    /// no finding.
    ///
    /// FAILS ON REVERT: the old loop said "every tool of that MCP server
    /// runs without asking" for `mcp__`, `mcp____*`, `mcp__*` and the
    /// denied server, and never named a denied tool.
    #[test]
    fn claude_allow_rules_say_only_what_they_allow() {
        let home = home_with(&[(
            ".claude/settings.json",
            r#"{"permissions": {
  "allow": ["mcp__", "mcp____*", "mcp__*", "mcp__gh", "mcp__fs__*", "mcp__db", "mcp__one__read"],
  "deny": ["mcp__fs__write_file", "mcp__fs__delete", "mcp__db__*", "mcp__", "Bash(rm:*)"]
}}"#,
        )]);
        let report = check_in(home.path(), None, None);
        assert_eq!(
            found(&report),
            vec![
                "`permissions.allow` has `mcp__*`: it may allow every MCP server's tools without asking (the permissions docs name only `mcp__<server>` and `mcp__<server>__*`)",
                "`permissions.allow` has `mcp__gh`: every tool of that MCP server runs without asking",
                "`permissions.allow` has `mcp__fs__*`: every tool of that MCP server runs without asking except `write_file`, `delete`, denied in `permissions.deny`",
            ],
            "{report:#?}"
        );
        assert!(report.findings.iter().all(|f| f.kind == Kind::AutoApprove));
    }

    /// Codex's `approval_mode = "approve"` runs a tool without asking, for
    /// the whole server (`default_tools_approval_mode`, a tool's own mode
    /// left out) or for one tool; `auto`, the default, is not said.
    ///
    /// FAILS ON REVERT: `auto_approved` read nothing in Codex's servers.
    #[test]
    fn codex_approve_mode_is_said() {
        let home = home_with(&[(
            ".codex/config.toml",
            r#"[mcp_servers.a]
command = "a-server"
default_tools_approval_mode = "approve"

[mcp_servers.a.tools.danger]
approval_mode = "prompt"

[mcp_servers.a.tools.also]
approval_mode = "approve"

[mcp_servers.b]
command = "b-server"

[mcp_servers.b.tools.read]
approval_mode = "approve"

[mcp_servers.b.tools.write]
approval_mode = "auto"

[mcp_servers.c]
command = "c-server"
default_tools_approval_mode = "auto"
"#,
        )]);
        let report = check_in(home.path(), None, None);
        assert_eq!(
            found(&report),
            vec![
                "MCP server `a`: `default_tools_approval_mode = \"approve\"`: every tool of that server runs without asking except `danger`, which set their own `approval_mode`",
                "MCP server `b`: tool `read` has `approval_mode = \"approve\"`: it runs without asking",
            ],
            "{report:#?}"
        );
        assert!(report
            .findings
            .iter()
            .all(|f| f.kind == Kind::AutoApprove
                && f.next.contains("innerwarden agents connect codex")));
    }

    /// What a Codex finding of `approve` says to do: set `prompt`, since a
    /// server with the field removed takes `auto`, which still runs the
    /// tools that call themselves read-only without asking. Gemini's `trust`
    /// is still to be removed.
    ///
    /// FAILS ON REVERT: Codex told "Remove it so the agent asks before each
    /// call".
    #[test]
    fn a_codex_approve_finding_says_to_set_prompt() {
        let home = home_with(&[
            (
                ".codex/config.toml",
                "[mcp_servers.a]\ncommand = \"a-server\"\ndefault_tools_approval_mode = \"approve\"\n",
            ),
            (
                ".gemini/settings.json",
                r#"{"mcpServers": {"g": {"command": "g-server", "trust": true}}}"#,
            ),
        ]);
        let report = check_in(home.path(), None, None);
        let codex: Vec<&str> = report
            .findings
            .iter()
            .filter(|f| f.kind == Kind::AutoApprove && f.what.contains("approval_mode"))
            .map(|f| f.next.as_str())
            .collect();
        assert_eq!(codex.len(), 1, "{report:#?}");
        assert!(
            codex[0].contains("`\"prompt\"`") && !codex[0].contains("Remove it"),
            "{}",
            codex[0]
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.what.contains("`trust`") && f.next.starts_with("Remove it")),
            "{report:#?}"
        );
    }

    /// A file that grows past the limit while it is read is not taken whole.
    #[test]
    fn a_file_past_the_limit_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, "0123456789").unwrap();
        assert_eq!(
            read_at_most(&path, 10).unwrap().as_deref(),
            Some("0123456789")
        );
        assert_eq!(read_at_most(&path, 9).unwrap(), None);
    }
}
