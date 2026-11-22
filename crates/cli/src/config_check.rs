//! What is already set in the AI agents' own config, read and never changed:
//! the PURE half of the config check that `setup` and `status --config`
//! print. The files are read in `config_check_io.rs`.
//!
//! Four things are looked for, in Claude Code, Codex, Gemini CLI and Cursor:
//!
//! * tool calls that run without the agent asking first: an MCP server
//!   marked trusted or auto-approved, a whole server allowed in Claude Code's
//!   permissions, Claude Code's bypass mode, Codex's `approval_policy = "never"`;
//! * an MCP server started by `npx`, `uvx` and the like with no version
//!   fixed, so the next release of the package runs on its own;
//! * a key or token written into the agent's file: only the file, the place
//!   in it and the kind of secret are said, never the value;
//! * a hook of some other program that runs before tool calls.
//!
//! Each finding comes with one line of what to do, and the InnerWarden
//! command when there is one. Nothing here writes, and no finding is a
//! verdict on the server or the hook: it is what the file says.

use serde_json::Value;

/// What kind of thing was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Tool calls that run without the agent asking first.
    AutoApprove,
    /// A package runner with no version fixed.
    Unpinned,
    /// A key or token written in the file.
    Secret,
    /// Another program's hook before tool calls.
    OtherHook,
}

/// One thing found in an agent's file, with what to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub agent: &'static str,
    /// The file as the person knows it (`~/.cursor/mcp.json`).
    pub file: String,
    pub kind: Kind,
    /// What the file says. Never holds the value of a secret.
    pub what: String,
    /// What to do, with the InnerWarden command when there is one.
    pub next: String,
}

/// A file that is there but could not be read, so nothing was checked in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unread {
    pub file: String,
    pub why: String,
}

/// Everything the check has to say.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub unread: Vec<Unread>,
    /// The files that were read, with findings or not.
    pub read: Vec<String>,
}

/// How a file's content is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `~/.claude/settings.json`: permissions, env and hooks.
    ClaudeSettings,
    /// `~/.claude.json`: MCP servers, at the top and per project.
    ClaudeState,
    /// `~/.cursor/mcp.json`.
    CursorMcp,
    /// `~/.cursor/hooks.json`.
    CursorHooks,
    /// `~/.codex/config.toml`, read into JSON values.
    CodexConfig,
    /// `~/.codex/hooks.json`.
    CodexHooks,
    /// `~/.gemini/settings.json`: MCP servers and hooks.
    GeminiSettings,
}

/// The folder a file is in: the home, or the folder a variable moves an
/// agent's config to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Home,
    /// `CLAUDE_CONFIG_DIR`: Claude Code reads `settings.json` and
    /// `.claude.json` there instead of `~/.claude/` and `~/.claude.json`.
    Claude,
    /// `CODEX_HOME`: Codex reads its files there instead of `~/.codex/`.
    Codex,
}

/// The variable that moves Claude Code's config folder.
pub const CLAUDE_DIR_ENV: &str = "CLAUDE_CONFIG_DIR";
/// The variable that moves Codex's config folder.
pub const CODEX_DIR_ENV: &str = "CODEX_HOME";

/// The files the check reads, with their agent: the folder a variable can
/// move it to, its name there, and its `$HOME`-relative place otherwise.
pub const FILES: &[(&str, Dir, &str, &str, Layout)] = &[
    (
        "claude-code",
        Dir::Claude,
        "settings.json",
        ".claude/settings.json",
        Layout::ClaudeSettings,
    ),
    (
        "claude-code",
        Dir::Claude,
        ".claude.json",
        ".claude.json",
        Layout::ClaudeState,
    ),
    (
        "cursor",
        Dir::Home,
        "",
        ".cursor/mcp.json",
        Layout::CursorMcp,
    ),
    (
        "cursor",
        Dir::Home,
        "",
        ".cursor/hooks.json",
        Layout::CursorHooks,
    ),
    (
        "codex",
        Dir::Codex,
        "config.toml",
        ".codex/config.toml",
        Layout::CodexConfig,
    ),
    (
        "codex",
        Dir::Codex,
        "hooks.json",
        ".codex/hooks.json",
        Layout::CodexHooks,
    ),
    (
        "gemini",
        Dir::Home,
        "",
        ".gemini/settings.json",
        Layout::GeminiSettings,
    ),
];

/// PURE. The folder a variable names, when it is set to an absolute path
/// with no `.` or `..` step; anything else falls back to the home.
pub fn moved_dir(value: Option<&str>) -> Option<std::path::PathBuf> {
    let path = std::path::Path::new(value?);
    let plain = path.is_absolute()
        && path.components().all(|c| {
            !matches!(
                c,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        });
    plain.then(|| path.to_path_buf())
}

/// What to do about a key written in the file, in the agent's own way of
/// naming a variable instead.
fn secret_next(agent: &str) -> String {
    let instead = match agent {
        "codex" => "export it in your shell and list its name in `env_vars`",
        "cursor" => "set it in your shell and write `${env:NAME}` in its place",
        "gemini" => "set it in your shell and write `$NAME` in its place",
        _ => "set it in your shell and write `${NAME}` in its place",
    };
    format!(
        "Take it out of the file: {instead}; rotate it if this file was ever shared or committed."
    )
}

/// PURE. What one file says, from its parsed content.
pub fn check_file(agent: &'static str, file: &str, layout: Layout, root: &Value) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut push = |kind: Kind, what: String, next: String| {
        out.push(Finding {
            agent,
            file: file.to_string(),
            kind,
            what,
            next,
        })
    };
    match layout {
        Layout::ClaudeSettings => {
            claude_permissions(root, &mut push);
            if let Some(env) = root.get("env").and_then(Value::as_object) {
                for (key, value) in env {
                    if let Some(kind) = value.as_str().and_then(|v| secret_kind(key, v)) {
                        push(
                            Kind::Secret,
                            format!("`env` sets {} to a value written in the file ({kind})", name(key)),
                            "Take it out of the file and set it in your shell or a secret manager instead; rotate it if this file was ever shared or committed.".to_string(),
                        );
                    }
                }
            }
            nested_hooks(root, "PreToolUse", &mut push);
        }
        Layout::ClaudeState => {
            servers(agent, root.get("mcpServers"), None, &mut push);
            if let Some(projects) = root.get("projects").and_then(Value::as_object) {
                for (project, entry) in projects {
                    servers(agent, entry.get("mcpServers"), Some(project), &mut push);
                }
            }
        }
        Layout::CursorMcp => servers(agent, root.get("mcpServers"), None, &mut push),
        Layout::GeminiSettings => {
            servers(agent, root.get("mcpServers"), None, &mut push);
            nested_hooks(root, "BeforeTool", &mut push);
        }
        Layout::CodexConfig => {
            if root.get("approval_policy").and_then(Value::as_str) == Some("never") {
                push(
                    Kind::AutoApprove,
                    "`approval_policy = \"never\"`: Codex runs every command and tool call without asking".to_string(),
                    "Set `approval_policy = \"on-request\"` (or `untrusted`) so Codex asks again; `innerwarden agents connect codex` puts the guard in front of its calls either way.".to_string(),
                );
            }
            if let Some(profiles) = root.get("profiles").and_then(Value::as_object) {
                for (profile, entry) in profiles {
                    if entry.get("approval_policy").and_then(Value::as_str) == Some("never") {
                        push(
                            Kind::AutoApprove,
                            format!("profile {}: `approval_policy = \"never\"`, Codex runs every call without asking", name(profile)),
                            "Set `approval_policy = \"on-request\"` in that profile; `innerwarden agents connect codex` puts the guard in front of its calls either way.".to_string(),
                        );
                    }
                }
            }
            servers(agent, root.get("mcp_servers"), None, &mut push);
        }
        Layout::CursorHooks => {
            if let Some(events) = root.get("hooks").and_then(Value::as_object) {
                for (event, entries) in events {
                    for entry in entries.as_array().into_iter().flatten() {
                        if let Some(command) = entry.get("command").and_then(Value::as_str) {
                            other_hook(event, command, &mut push);
                        }
                    }
                }
            }
        }
        Layout::CodexHooks => nested_hooks(root, "PreToolUse", &mut push),
    }
    out
}

/// A name from the file, as said back: short and on one line. A key or
/// server name is not the secret, but the file is not ours, so a long name
/// is cut and control characters are dropped.
fn name(raw: &str) -> String {
    let clean: String = raw.chars().filter(|c| !c.is_control()).take(60).collect();
    format!("`{clean}`")
}

/// Claude Code's permissions: bypass mode, a whole MCP server allowed, and
/// every project server started.
fn claude_permissions(root: &Value, push: &mut impl FnMut(Kind, String, String)) {
    let permissions = root.get("permissions");
    if permissions
        .and_then(|p| p.get("defaultMode"))
        .and_then(Value::as_str)
        == Some("bypassPermissions")
    {
        push(
            Kind::AutoApprove,
            "`permissions.defaultMode` is `bypassPermissions`: Claude Code runs every tool call without asking".to_string(),
            "Remove it (or set `default`) so Claude Code asks again; `innerwarden status` says what its hook still judges.".to_string(),
        );
    }
    for rule in permissions
        .and_then(|p| p.get("allow"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        let Some(rest) = rule.strip_prefix("mcp__") else {
            continue;
        };
        // `mcp__server` and `mcp__server__*` allow every tool of the server;
        // `mcp__server__tool` allows one, chosen by name.
        let whole = match rest.split_once("__") {
            None => true,
            Some((_, tool)) => tool == "*",
        };
        if whole {
            push(
                Kind::AutoApprove,
                format!("`permissions.allow` has {}: every tool of that MCP server runs without asking", name(rule)),
                "Allow only the tools you need by name (`mcp__<server>__<tool>`), so Claude Code asks before the rest.".to_string(),
            );
        }
    }
    if root
        .get("enableAllProjectMcpServers")
        .and_then(Value::as_bool)
        == Some(true)
    {
        push(
            Kind::AutoApprove,
            "`enableAllProjectMcpServers` is on: every MCP server a project's `.mcp.json` names starts without asking".to_string(),
            "Turn it off so Claude Code asks before it starts a project's server.".to_string(),
        );
    }
}

/// The MCP servers of a table (`mcpServers`, or Codex's `mcp_servers`).
fn servers(
    agent: &str,
    table: Option<&Value>,
    project: Option<&str>,
    push: &mut impl FnMut(Kind, String, String),
) {
    let Some(table) = table.and_then(Value::as_object) else {
        return;
    };
    for (server_name, server) in table {
        let label = match project {
            Some(project) => format!(
                "MCP server {} (project {})",
                name(server_name),
                name(project)
            ),
            None => format!("MCP server {}", name(server_name)),
        };
        let (command, args, wrapped) = launch(server);
        if let Some(why) = auto_approved(agent, server) {
            let next = match agent {
                "cursor" | "gemini" | "codex" if !wrapped => format!(
                    "Remove it so the agent asks before each call; `innerwarden agents connect {agent}` puts the guard in front of this server's calls."
                ),
                _ => "Remove it so the agent asks before each call.".to_string(),
            };
            push(Kind::AutoApprove, format!("{label}: {why}"), next);
        }
        if let Some(found) = command.as_deref().and_then(|c| unpinned(c, &args)) {
            let pins = match agent {
                _ if wrapped => "; the proxy already holds its tool definitions to the ones it first listed (`innerwarden mcp list`).".to_string(),
                "cursor" | "gemini" | "codex" => format!("; once `innerwarden agents connect {agent}` puts the proxy in front of it, the proxy also holds its tool definitions to the ones it first listed (`innerwarden mcp list`)."),
                _ => ".".to_string(),
            };
            push(
                Kind::Unpinned,
                format!("{label}: {} with no version fixed, so the version is whatever the registry serves when it is next fetched", found.said),
                format!("Fix the version ({}){pins}", found.fix),
            );
        }
        for place in secrets_in_server(server, &args) {
            push(
                Kind::Secret,
                format!("{label}: {place}"),
                secret_next(agent),
            );
        }
    }
}

/// The program and arguments a server runs, looking past InnerWarden's own
/// proxy wrapper (`innerwarden proxy ... -- <command> <args>`), and whether
/// it was wrapped.
fn launch(server: &Value) -> (Option<String>, Vec<String>, bool) {
    let command = server
        .get("command")
        .and_then(Value::as_str)
        .map(str::to_string);
    let args: Vec<String> = server
        .get("args")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    if command.as_deref().is_some_and(is_innerwarden) {
        if let Some(separator) = args.iter().position(|a| a == "--") {
            let mut inner = args[separator + 1..].to_vec();
            if !inner.is_empty() {
                let program = inner.remove(0);
                return (Some(program), inner, true);
            }
        }
    }
    (command, args, false)
}

/// The basename of a program, without a Windows suffix, in lower case.
fn stem(program: &str) -> String {
    let base = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase();
    [".exe", ".cmd", ".bat"]
        .iter()
        .find_map(|suffix| base.strip_suffix(suffix).map(str::to_string))
        .unwrap_or(base)
}

fn is_innerwarden(program: &str) -> bool {
    stem(program) == "innerwarden"
}

/// Why a server's calls run without asking, or `None`. Cursor documents no
/// per-server approval field in `mcp.json` (its approval follows the Run
/// Mode set in the app, https://cursor.com/docs/context/mcp), so an
/// `autoApprove` or `alwaysAllow` there changes nothing and is not said.
fn auto_approved(agent: &str, server: &Value) -> Option<String> {
    if agent == "cursor" {
        return None;
    }
    // Gemini CLI: `trust: true` skips every confirmation for the server.
    if server.get("trust").and_then(Value::as_bool) == Some(true) {
        return Some("`trust` is on, so every tool call runs without asking".to_string());
    }
    // `autoApprove` / `alwaysAllow`: a list of tools, or `true` for all.
    for key in ["autoApprove", "alwaysAllow", "auto_approve"] {
        match server.get(key) {
            Some(Value::Bool(true)) => {
                return Some(format!(
                    "`{key}` is on, so every tool call runs without asking"
                ))
            }
            Some(Value::Array(tools)) if !tools.is_empty() => {
                return Some(if tools.iter().any(|t| t.as_str() == Some("*")) {
                    format!("`{key}` lists `*`, so every tool call runs without asking")
                } else {
                    format!(
                        "`{key}` lists {} tool{} that run without asking",
                        tools.len(),
                        if tools.len() == 1 { "" } else { "s" }
                    )
                });
            }
            _ => {}
        }
    }
    None
}

/// A package runner with no version fixed: what to say and how to fix it.
#[derive(Debug, PartialEq, Eq)]
pub struct Unpinned {
    pub said: String,
    pub fix: String,
}

/// PURE. `npx`, `bunx`, `pnpx`, `pnpm dlx`, `yarn dlx`, `uvx` and
/// `uv tool run` with a registry package whose version is not fixed. A local
/// path, a URL or a git source is not judged.
pub fn unpinned(command: &str, args: &[String]) -> Option<Unpinned> {
    let program = stem(command);
    let (runner, rest): (&str, &[String]) = match program.as_str() {
        "npx" | "bunx" | "pnpx" => (program.as_str(), args),
        "pnpm" | "yarn" if args.first().map(String::as_str) == Some("dlx") => {
            (program.as_str(), &args[1..])
        }
        "uvx" => ("uvx", args),
        "uv" if args.len() >= 2 && args[0] == "tool" && args[1] == "run" => {
            ("uv tool run", &args[2..])
        }
        _ => return None,
    };
    let python = matches!(runner, "uvx" | "uv tool run");
    let package = if python {
        package_arg(
            rest,
            &["--from"],
            &[
                "--python",
                "-p",
                "--with",
                "--with-requirements",
                "--index",
                "--index-url",
                "--extra-index-url",
                "--default-index",
                "--find-links",
                "-f",
                "--python-preference",
                "--index-strategy",
                "--keyring-provider",
                "--resolution",
                "--prerelease",
                "--env-file",
                "--prefix",
                "--constraints",
                "-c",
                "--overrides",
                "--build-constraints",
                "-b",
                "--cache-dir",
                "--config-file",
                "--directory",
                "--project",
                "--exclude-newer",
                "--link-mode",
                "--refresh-package",
                "--reinstall-package",
                "--upgrade-package",
                "--color",
            ],
            &[],
        )?
    } else {
        // `-c` / `--call` run a shell string, not a package: nothing to
        // judge, and the string may carry a token.
        package_arg(
            rest,
            &["--package", "-p"],
            &[
                "--registry",
                "--cache",
                "--userconfig",
                "--node-options",
                "--prefix",
            ],
            &["-c", "--call"],
        )?
    };
    // A registry package has no space in its name: a word with one is a
    // command line, and saying it back could say a token in it.
    if package.contains(char::is_whitespace) {
        return None;
    }
    if is_not_registry(&package) {
        return None;
    }
    let (bare, pinned) = if python {
        python_pinned(&package)
    } else {
        npm_pinned(&package)
    };
    if pinned {
        return None;
    }
    let said = format!("`{runner}` runs {}", name(&bare));
    let bare: String = bare.chars().filter(|c| !c.is_control()).take(60).collect();
    Some(Unpinned {
        said,
        fix: if python {
            format!("`{runner} {bare}==<version>`")
        } else {
            format!("`{bare}@<version>`, the version from `npm view {bare} version`")
        },
    })
}

/// The package a runner starts: the value of one of `package_flags`, or else
/// the first word that is not a flag (a flag in `value_flags` takes the next
/// word with it). `None` when a flag in `no_package` is there.
fn package_arg(
    args: &[String],
    package_flags: &[&str],
    value_flags: &[&str],
    no_package: &[&str],
) -> Option<String> {
    let mut words = args.iter();
    let mut first = None;
    while let Some(word) = words.next() {
        if word == "--" {
            break;
        }
        let flag = word.split_once('=').map_or(word.as_str(), |(flag, _)| flag);
        if no_package.contains(&flag) {
            return None;
        }
        if let Some((flag, value)) = word.split_once('=') {
            if package_flags.contains(&flag) {
                return Some(value.to_string());
            }
            if flag.starts_with('-') {
                continue;
            }
        }
        if package_flags.contains(&word.as_str()) {
            return words.next().cloned();
        }
        if value_flags.contains(&word.as_str()) {
            words.next();
            continue;
        }
        if word.starts_with('-') {
            continue;
        }
        if first.is_none() {
            first = Some(word.clone());
        }
    }
    first
}

fn is_not_registry(package: &str) -> bool {
    package.starts_with(['.', '/', '~'])
        || package.contains(':')
        || package.ends_with(".tgz")
        || package.ends_with(".whl")
        || package.ends_with(".tar.gz")
        || (!package.starts_with('@') && package.contains('/'))
}

/// PURE. `name@1.2.3` and `@scope/name@1.2.3` are fixed; no version, a tag
/// (`latest`) or a range (`^1`, `~1.2`, `1.x`, `>=1`) is not.
fn npm_pinned(package: &str) -> (String, bool) {
    let after_scope = usize::from(package.starts_with('@'));
    match package[after_scope..].find('@') {
        None => (package.to_string(), false),
        Some(at) => {
            let at = at + after_scope;
            (package[..at].to_string(), exact_version(&package[at + 1..]))
        }
    }
}

/// PURE. `name==1.2.3` and `name@1.2.3` are fixed; anything else is not.
fn python_pinned(package: &str) -> (String, bool) {
    if let Some((bare, version)) = package.split_once("==") {
        return (bare.to_string(), exact_version(version));
    }
    if let Some((bare, version)) = package.split_once('@') {
        return (bare.trim().to_string(), exact_version(version.trim()));
    }
    let bare: String = package
        .chars()
        .take_while(|c| !matches!(c, '>' | '<' | '~' | '!' | '=' | ';' | ' '))
        .collect();
    (bare, false)
}

/// A version with nothing left open: it starts with a digit, has no range
/// in it, and no part between dots is a wildcard (`x`, `X`, `*`), so
/// `2.0.0-next.3` is fixed and `1.x` is not.
fn exact_version(version: &str) -> bool {
    version.starts_with(|c: char| c.is_ascii_digit())
        && !version
            .chars()
            .any(|c| matches!(c, '^' | '~' | '*' | '>' | '<' | '|' | ' ' | ','))
        && !version.split('.').any(|part| matches!(part, "x" | "X"))
}

/// Where a server's entry holds a secret written out, said without its value.
fn secrets_in_server(server: &Value, args: &[String]) -> Vec<String> {
    let mut places = Vec::new();
    for table in ["env", "headers", "http_headers"] {
        if let Some(map) = server.get(table).and_then(Value::as_object) {
            for (key, value) in map {
                if let Some(kind) = value.as_str().and_then(|v| secret_kind(key, v)) {
                    places.push(format!(
                        "`{table}` sets {} to a value written in the file ({kind})",
                        name(key)
                    ));
                }
            }
        }
    }
    if let Some(kind) = server
        .get("bearer_token")
        .and_then(Value::as_str)
        .and_then(|v| secret_kind("bearer_token", v))
    {
        places.push(format!(
            "`bearer_token` holds a value written in the file ({kind})"
        ));
    }
    if let Some(what) = ["url", "httpUrl", "serverUrl"]
        .iter()
        .find_map(|key| server.get(*key).and_then(Value::as_str))
        .and_then(url_secret)
    {
        places.push(format!("its URL carries {what}"));
    }
    let mut words = args.iter().enumerate().peekable();
    while let Some((i, word)) = words.next() {
        if let Some((flag, value)) = word.split_once('=') {
            if flag.starts_with('-') {
                if let Some(kind) = secret_kind(flag.trim_start_matches('-'), value) {
                    places.push(format!(
                        "argument {} holds a value written in the file ({kind})",
                        name(flag)
                    ));
                }
                continue;
            }
        }
        if word.starts_with('-') && secret_name(word.trim_start_matches('-')) {
            let kind = words
                .peek()
                .and_then(|(_, value)| secret_kind(word.trim_start_matches('-'), value));
            if let Some(kind) = kind {
                places.push(format!(
                    "the argument after {} holds a value written in the file ({kind})",
                    name(word)
                ));
                words.next();
            }
            continue;
        }
        if let Some(kind) = word.split_whitespace().find_map(known_prefix) {
            places.push(format!(
                "argument {} holds a value written in the file ({kind})",
                i + 1
            ));
        }
    }
    places
}

/// What a URL carries that is a secret, or `None`.
fn url_secret(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    if let Some((user_info, _)) = authority.rsplit_once('@') {
        if user_info.contains(':') {
            return Some("a password".to_string());
        }
    }
    let query = url.split_once('?').map(|(_, q)| q)?;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        let kind = secret_kind(key, value)?;
        Some(format!("a value in its {} parameter ({kind})", name(key)))
    })
}

/// PURE. The kind of secret a value is, from its own shape or the name it is
/// written under; `None` for a value that refers to one kept elsewhere
/// (`${VAR}`, `$VAR`, `${env:VAR}`) or that is too short or plain to be one.
pub fn secret_kind(key: &str, value: &str) -> Option<&'static str> {
    let value = value.trim();
    let value = ["Bearer ", "bearer ", "Basic ", "token "]
        .iter()
        .find_map(|scheme| value.strip_prefix(scheme))
        .unwrap_or(value)
        .trim();
    if value.is_empty() || refers_elsewhere(value) {
        return None;
    }
    if let Some(kind) = known_prefix(value) {
        return Some(kind);
    }
    // A path names where a secret is kept, not the secret.
    if is_path(value) {
        return None;
    }
    // A URL is a secret only for what it carries: a password, or a secret
    // in its query.
    if value.contains("://") {
        return url_secret(value).map(|_| "secret");
    }
    let plain = matches!(
        value.to_ascii_lowercase().as_str(),
        "true" | "false" | "null" | "none" | "yes" | "no"
    ) || value.chars().all(|c| c.is_ascii_digit() || c == '.');
    (secret_name(key) && value.len() >= 8 && !plain && !value.contains(char::is_whitespace))
        .then_some("secret")
}

/// A file path: `/`, `~`, `./`, `../` or a drive letter (`C:\` or `C:/`).
fn is_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.starts_with(['/', '~'])
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with(".\\")
        || value.starts_with("..\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'))
}

fn refers_elsewhere(value: &str) -> bool {
    value.starts_with('$')
        || value.contains("${")
        || value.starts_with("{env:")
        || value.starts_with("env:")
        || value.starts_with("op://")
        || value.starts_with('<')
}

/// The shapes that name their issuer.
fn known_prefix(value: &str) -> Option<&'static str> {
    const PREFIXES: &[(&str, &str)] = &[
        ("github_pat_", "GitHub token"),
        ("ghp_", "GitHub token"),
        ("gho_", "GitHub token"),
        ("ghu_", "GitHub token"),
        ("ghs_", "GitHub token"),
        ("ghr_", "GitHub token"),
        ("glpat-", "GitLab token"),
        ("sk-ant-", "Anthropic API key"),
        ("sk-proj-", "OpenAI API key"),
        ("xoxb-", "Slack token"),
        ("xoxp-", "Slack token"),
        ("xoxa-", "Slack token"),
        ("xapp-", "Slack token"),
        ("npm_", "npm token"),
        ("hf_", "Hugging Face token"),
        ("AIza", "Google API key"),
        ("AKIA", "AWS access key"),
        ("ASIA", "AWS access key"),
        ("sk_live_", "Stripe key"),
        ("rk_live_", "Stripe key"),
        ("sk-", "API key"),
    ];
    PREFIXES
        .iter()
        .find(|(prefix, _)| {
            value.len() >= prefix.len() + 12
                && value.starts_with(prefix)
                && value[prefix.len()..]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        })
        .map(|(_, kind)| *kind)
}

/// A setting whose name says it holds a secret. `auth` counts only as a
/// whole word between `_` (`AUTH_HEADER`), not inside one (`AUTHOR`,
/// `OAUTH`).
fn secret_name(key: &str) -> bool {
    let key = key.to_ascii_lowercase().replace('-', "_");
    let auth = key.split('_').any(|word| word == "auth");
    (auth
        || [
            "token",
            "secret",
            "password",
            "passwd",
            "api_key",
            "apikey",
            "access_key",
            "private_key",
            "authorization",
            "credential",
        ]
        .iter()
        .any(|word| key.contains(word)))
        && !["_url", "_file", "_path", "_env", "_var", "_vars", "_helper"]
            .iter()
            .any(|tail| key.ends_with(tail))
}

/// Claude Code, Codex and Gemini hooks: `hooks.<event>[].hooks[].command`.
fn nested_hooks(root: &Value, event: &str, push: &mut impl FnMut(Kind, String, String)) {
    for group in root
        .get("hooks")
        .and_then(|h| h.get(event))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for hook in group
            .get("hooks")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(command) = hook.get("command").and_then(Value::as_str) {
                other_hook(event, command, push);
            }
        }
    }
}

/// A hook whose command is not InnerWarden's, named by its program alone so
/// that a token on its command line is never said.
fn other_hook(event: &str, command: &str, push: &mut impl FnMut(Kind, String, String)) {
    let words: Vec<&str> = command
        .split_whitespace()
        .map(|w| w.trim_matches(['"', '\'']))
        .collect();
    if words.iter().any(|word| is_innerwarden(word)) {
        return;
    }
    // Past `env`, `exec` and `sudo`, their flags (and the value of the ones
    // that take one, as in `sudo -u bob`) and variable settings.
    const VALUE_FLAGS: &[&str] = &[
        "-u",
        "-g",
        "-C",
        "-D",
        "-p",
        "-r",
        "-t",
        "-U",
        "-T",
        "-S",
        "-a",
        "--user",
        "--group",
        "--chdir",
        "--unset",
        "--split-string",
    ];
    let mut rest = words.iter();
    let mut program = None;
    while let Some(word) = rest.next() {
        if VALUE_FLAGS.contains(word) {
            rest.next();
            continue;
        }
        if word.starts_with('-') || word.contains('=') || matches!(*word, "env" | "exec" | "sudo") {
            continue;
        }
        program = Some(stem(word));
        break;
    }
    let Some(program) = program else {
        return;
    };
    push(
        Kind::OtherHook,
        format!(
            "another program, {}, runs as a `{event}` hook before tool calls",
            name(&program)
        ),
        "If it is another guard, both answer each call and either can refuse it; keep it only if you set it up. `innerwarden status` says what InnerWarden's own hook judges.".to_string(),
    );
}

/// PURE. The lines the check prints, under `indent`. Says plainly when
/// nothing was found, and names every file it could not read: "could not
/// read" is never "nothing found".
pub fn render(report: &Report, indent: &str) -> Vec<String> {
    let mut lines = Vec::new();
    if report.read.is_empty() && report.unread.is_empty() {
        lines.push(format!(
            "{indent}No config of Claude Code, Codex, Gemini CLI or Cursor here to check."
        ));
        return lines;
    }
    if report.findings.is_empty() {
        if !report.read.is_empty() {
            lines.push(format!(
                "{indent}Nothing to point out in {} (auto-approve, unpinned packages, keys in the file, other hooks).",
                report.read.join(", ")
            ));
        }
    } else {
        lines.push(format!(
            "{indent}What is already set in your agents' config (read only, nothing was changed):"
        ));
        for finding in &report.findings {
            lines.push(format!(
                "{indent}  ! {} {}: {}",
                finding.file,
                tag(finding.kind),
                finding.what
            ));
            lines.push(format!("{indent}      {}", finding.next));
        }
    }
    for unread in &report.unread {
        lines.push(format!(
            "{indent}  ? could not read {}: {}; nothing in it was checked",
            unread.file, unread.why
        ));
    }
    lines
}

fn tag(kind: Kind) -> &'static str {
    match kind {
        Kind::AutoApprove => "[auto-approve]",
        Kind::Unpinned => "[unpinned]",
        Kind::Secret => "[key in file]",
        Kind::OtherHook => "[other hook]",
    }
}
