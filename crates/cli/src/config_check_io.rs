//! The I/O half of the config check: read each agent file that is there,
//! hand it to the pure `config_check`, and print what it says. Reads only;
//! never writes, and never prints the value of a secret it found.

use std::path::Path;

use crate::config_check::{self, Layout, Report, Unread};

/// A file bigger than this is not read (`~/.claude.json` grows with the
/// projects Claude Code has opened, but stays far below it).
const MAX_BYTES: u64 = 32 * 1024 * 1024;

/// Read every file the check knows under `home` and say what is set there.
/// A file that is not there is skipped; one that is there and cannot be
/// read or parsed is named, never taken for "nothing found".
pub fn check(home: &Path) -> Report {
    let mut report = Report::default();
    for (agent, rel, layout) in config_check::FILES {
        let path = home.join(rel);
        let shown = format!("~/{rel}");
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
        if meta.len() > MAX_BYTES {
            report.unread.push(Unread {
                file: shown,
                why: format!("larger than {} MiB", MAX_BYTES / (1024 * 1024)),
            });
            continue;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
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
    const FAKE_GITHUB: &str = "ghp_FAKEfake0123456789FAKEfake0123456789";
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
        let report = check(home.path());
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
            vec![AutoApprove, Unpinned, Secret, Unpinned],
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
        let report = check(home.path());
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
        let report = check(home.path());
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
            lines(empty.path(), ""),
            vec!["No config of Claude Code, Codex, Gemini CLI or Cursor here to check."]
        );
        let clean = home_with(&[(
            ".cursor/mcp.json",
            r#"{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21"], "env": {"TOKEN": "${env:TOKEN}"}}}}"#,
        )]);
        assert_eq!(
            lines(clean.path(), ""),
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
}
