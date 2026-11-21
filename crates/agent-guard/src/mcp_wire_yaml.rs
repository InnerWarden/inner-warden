//! Guard **Goose**, whose MCP servers live in `~/.config/goose/config.yaml`
//! under `extensions:` (YAML, `type: stdio` with `cmd`/`args`) rather than a
//! JSON `mcpServers` table. Same idea as [`crate::mcp_wire`]: each stdio
//! server is rewritten to launch THROUGH `innerwarden proxy`, so Goose's MCP
//! tool calls are screened by the same engine as `check`.
//!
//! The servers are read as the JSON clients' table ([`YamlDoc::view`]), so
//! every decision (what is wrapped, in which mode, which agent a wrapper
//! names, what is remote) is [`crate::mcp_wire`]'s, made once for every
//! client. Only the write is YAML's own, and it is LINE-PRESERVING: the
//! `cmd` and `args` lines of each server that changes are replaced, and every
//! other line of the person's file (comments, key order, blank lines, the
//! other settings and extensions) is left byte for byte. The edited text is
//! parsed again and must equal the original document with only those
//! servers' `cmd` and `args` changed; any other outcome (a shape this editor
//! cannot place, a server written inline) is an error and nothing is
//! written. Built-in and remote extensions have no local command: they are
//! counted as remote, since the proxy never sees their calls.
//!
//! All logic here is pure; the file read/write is the I/O layer's job.

use serde_json::{Map, Value};
use serde_yaml::Value as Yaml;

/// The table of the view, as [`crate::mcp_wire`] reads a JSON client's.
const SERVERS: &str = "mcpServers";

/// A Goose configuration: the text as the person wrote it and what it parses
/// to.
#[derive(Debug, Clone, PartialEq)]
pub struct YamlDoc {
    text: String,
    value: Yaml,
}

impl YamlDoc {
    /// Parse a configuration. An empty file is an empty mapping; any other
    /// document that is not a mapping is refused.
    pub fn parse(text: &str) -> Result<Self, String> {
        let value: Yaml =
            serde_yaml::from_str(text).map_err(|error| format!("not valid YAML: {error}"))?;
        let value = match value {
            Yaml::Null => Yaml::Mapping(serde_yaml::Mapping::new()),
            Yaml::Mapping(_) => value,
            _ => return Err("not a YAML mapping".to_string()),
        };
        Ok(Self {
            text: text.to_string(),
            value,
        })
    }

    /// The text to write back.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The extensions as a JSON client's `{"mcpServers": {...}}`: a stdio
    /// extension as its `command` (Goose's `cmd`) and `args`, any other
    /// extension (built-in, remote) as its `type` alone, which has no local
    /// command and so is counted remote. An entry that is not a mapping
    /// stays what it is, so the strict shape check refuses it. Pure.
    pub fn view(&self) -> Value {
        let mut servers = Map::new();
        if let Some(extensions) = extensions(&self.value) {
            for (name, extension) in extensions {
                let Some(name) = name.as_str() else {
                    continue;
                };
                let server = if !extension.is_mapping() {
                    to_json(extension)
                } else if is_stdio(extension) {
                    let mut server = Map::new();
                    if let Some(command) = extension.get("cmd") {
                        server.insert("command".to_string(), to_json(command));
                    }
                    if let Some(args) = extension.get("args") {
                        server.insert("args".to_string(), to_json(args));
                    }
                    Value::Object(server)
                } else {
                    let mut server = Map::new();
                    server.insert(
                        "type".to_string(),
                        extension.get("type").map(to_json).unwrap_or(Value::Null),
                    );
                    Value::Object(server)
                };
                servers.insert(name.to_string(), server);
            }
        }
        let mut root = Map::new();
        root.insert(SERVERS.to_string(), Value::Object(servers));
        Value::Object(root)
    }

    /// Make the file say what `wanted` (a [`Self::view`] changed by
    /// [`crate::mcp_wire::wrap`] or [`crate::mcp_wire::unwrap`]) says: each
    /// server whose `command` or `args` differ gets its `cmd` and `args`
    /// lines rewritten, and nothing else changes. Returns how many servers
    /// changed. On any error the document is left as it was.
    pub fn apply(&mut self, wanted: &Value) -> Result<usize, String> {
        let current = self.view();
        let have = current
            .get(SERVERS)
            .and_then(Value::as_object)
            .ok_or("the servers could not be read")?;
        let want = wanted
            .get(SERVERS)
            .and_then(Value::as_object)
            .ok_or("the new servers could not be read")?;
        if have.len() != want.len() || want.keys().any(|name| !have.contains_key(name)) {
            return Err("the edit would add or remove an extension".to_string());
        }
        let mut text = self.text.clone();
        let mut expected = self.value.clone();
        let mut changed = 0;
        for (name, server) in want {
            let before = &have[name];
            if before == server {
                continue;
            }
            let beside = |server: &Value| {
                server.as_object().map(|object| {
                    object
                        .iter()
                        .filter(|(key, _)| *key != "command" && *key != "args")
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect::<Vec<_>>()
                })
            };
            if beside(before) != beside(server) {
                return Err(format!(
                    "the edit would change more of extension `{name}` than its command"
                ));
            }
            let command = server
                .get("command")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("extension `{name}` would have no command"))?;
            let args: Vec<String> = match server.get("args") {
                None => Vec::new(),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|item| item.as_str().map(str::to_string))
                    .collect::<Option<_>>()
                    .ok_or_else(|| format!("extension `{name}` has arguments that are not text"))?,
                Some(_) => {
                    return Err(format!(
                        "extension `{name}` has arguments that are not a list"
                    ))
                }
            };
            text = patch_extension(&text, name, command, &args)?;
            let extension = expected
                .get_mut("extensions")
                .and_then(|extensions| extensions.get_mut(name.as_str()))
                .and_then(Yaml::as_mapping_mut)
                .ok_or_else(|| format!("extension `{name}` could not be found"))?;
            extension.insert(Yaml::from("cmd"), Yaml::from(command));
            extension.insert(
                Yaml::from("args"),
                Yaml::Sequence(args.iter().map(|arg| Yaml::from(arg.as_str())).collect()),
            );
            changed += 1;
        }
        if changed == 0 {
            return Ok(0);
        }
        let reparsed: Yaml = serde_yaml::from_str(&text)
            .map_err(|error| format!("the edited file would not be valid YAML: {error}"))?;
        if reparsed != expected {
            return Err(
                "the edit would change more than the servers' commands; nothing was written"
                    .to_string(),
            );
        }
        self.text = text;
        self.value = reparsed;
        Ok(changed)
    }
}

/// The view of a configuration's bytes ([`YamlDoc::view`]), `None` when they
/// are not a YAML mapping. Pure.
pub fn view_of_bytes(bytes: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(bytes).ok()?;
    YamlDoc::parse(text).ok().map(|doc| doc.view())
}

fn extensions(value: &Yaml) -> Option<&serde_yaml::Mapping> {
    value.get("extensions")?.as_mapping()
}

/// Goose runs a local command only for an extension of `type: stdio`.
fn is_stdio(extension: &Yaml) -> bool {
    extension.get("type").and_then(Yaml::as_str) == Some("stdio")
}

fn to_json(value: &Yaml) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// One line of the file as the editor reads it.
struct Line<'a> {
    indent: usize,
    /// The line without its indentation, ending and trailing spaces.
    rest: &'a str,
}

impl<'a> Line<'a> {
    /// `None` for a blank line or a comment, which belong to no field.
    fn read(line: &'a str) -> Option<Self> {
        let body = line.trim_end_matches(['\n', '\r']);
        let rest = body.trim_start_matches(' ');
        let rest = rest.trim_end();
        if rest.is_empty() || rest.starts_with('#') {
            return None;
        }
        Some(Self {
            indent: body.len() - body.trim_start_matches(' ').len(),
            rest,
        })
    }

    fn is_item(&self) -> bool {
        self.rest == "-" || self.rest.starts_with("- ")
    }

    /// The key this line opens and what follows its colon (a comment taken
    /// off), `None` for a line that opens no plain or simply quoted key.
    fn key(&self) -> Option<(&'a str, &'a str)> {
        if self.is_item() {
            return None;
        }
        let rest = self.rest;
        let (key, after) = match rest.chars().next()? {
            quote @ ('"' | '\'') => {
                let close = rest[1..].find(quote)? + 1;
                let key = &rest[1..close];
                if key.contains('\\') || key.contains(quote) {
                    return None;
                }
                (key, rest[close + 1..].strip_prefix(':')?)
            }
            _ => {
                let colon = rest
                    .match_indices(':')
                    .map(|(at, _)| at)
                    .find(|at| rest[at + 1..].is_empty() || rest[at + 1..].starts_with(' '))?;
                (rest[..colon].trim_end(), &rest[colon + 1..])
            }
        };
        if !(after.is_empty() || after.starts_with(' ')) {
            return None;
        }
        let value = after.trim();
        let value = if value.starts_with('#') { "" } else { value };
        Some((key, value))
    }
}

/// The line index after the last line of the field opened at `start`: the
/// lines indented past `field`, and list items at `field` (Goose writes
/// `args:` and its items at one indentation).
fn field_end(lines: &[&str], start: usize, end: usize, field: usize) -> usize {
    let mut last = start;
    for (at, line) in lines.iter().enumerate().take(end).skip(start + 1) {
        match Line::read(line) {
            None => continue,
            Some(line) if line.indent > field || (line.indent == field && line.is_item()) => {
                last = at
            }
            Some(_) => break,
        }
    }
    last + 1
}

/// A YAML scalar for `text`: plain where it reads back as that text in a
/// list item, double-quoted (JSON's escapes, which YAML reads the same)
/// otherwise.
fn scalar(text: &str) -> String {
    let plain = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./+=~-".contains(c))
        && serde_yaml::from_str::<Yaml>(&format!("- {text}")).ok()
            == Some(Yaml::Sequence(vec![Yaml::from(text)]));
    if plain {
        text.to_string()
    } else {
        serde_json::to_string(text).unwrap_or_else(|_| format!("{text:?}"))
    }
}

/// Rewrite the `cmd` and `args` lines of extension `name` in `text`, every
/// other line kept as it was. An error for a shape the lines cannot be
/// placed in: no block `extensions:` at the top level, the extension
/// written inline, no `cmd` line.
fn patch_extension(
    text: &str,
    name: &str,
    command: &str,
    args: &[String],
) -> Result<String, String> {
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let cannot = |why: &str| format!("extension `{name}` cannot be edited in place: {why}");
    let top = lines
        .iter()
        .position(|line| {
            Line::read(line)
                .is_some_and(|line| line.indent == 0 && line.key() == Some(("extensions", "")))
        })
        .ok_or_else(|| cannot("no `extensions:` block at the top level"))?;
    let block_end = (top + 1..lines.len())
        .find(|at| Line::read(lines[*at]).is_some_and(|line| line.indent == 0))
        .unwrap_or(lines.len());
    let child = (top + 1..block_end)
        .find_map(|at| Line::read(lines[at]))
        .map(|line| line.indent)
        .ok_or_else(|| cannot("the `extensions:` block is empty"))?;
    let entry = (top + 1..block_end)
        .find(|at| {
            Line::read(lines[*at]).is_some_and(|line| {
                line.indent == child && line.key().is_some_and(|(key, _)| key == name)
            })
        })
        .ok_or_else(|| cannot("its key was not found"))?;
    if Line::read(lines[entry])
        .and_then(|line| line.key())
        .is_some_and(|(_, value)| !value.is_empty())
    {
        return Err(cannot("it is written on one line"));
    }
    let entry_end = (entry + 1..block_end)
        .find(|at| Line::read(lines[*at]).is_some_and(|line| line.indent <= child))
        .unwrap_or(block_end);
    let field = (entry + 1..entry_end)
        .find_map(|at| Line::read(lines[at]))
        .map(|line| line.indent)
        .filter(|indent| *indent > child)
        .ok_or_else(|| cannot("it has no fields"))?;
    let find = |wanted: &str| {
        (entry + 1..entry_end).find(|at| {
            Line::read(lines[*at]).is_some_and(|line| {
                line.indent == field && line.key().is_some_and(|(key, _)| key == wanted)
            })
        })
    };
    let cmd_at = find("cmd").ok_or_else(|| cannot("it has no `cmd` line"))?;
    let cmd_span = (cmd_at, field_end(&lines, cmd_at, entry_end, field));
    let args_span = find("args").map(|at| (at, field_end(&lines, at, entry_end, field)));
    let pad = " ".repeat(field);
    let item_pad = args_span
        .and_then(|(start, end)| {
            (start + 1..end)
                .find_map(|at| Line::read(lines[at]).filter(Line::is_item))
                .map(|line| line.indent)
        })
        .unwrap_or(field);
    let cmd_text = format!("{pad}cmd: {}{newline}", scalar(command));
    let args_text = if args.is_empty() {
        format!("{pad}args: []{newline}")
    } else {
        let mut out = format!("{pad}args:{newline}");
        for arg in args {
            out.push_str(&format!(
                "{}- {}{newline}",
                " ".repeat(item_pad),
                scalar(arg)
            ));
        }
        out
    };
    let mut out = String::with_capacity(text.len() + 256);
    let mut at = 0;
    while at < lines.len() {
        if at == cmd_span.0 {
            out.push_str(&cmd_text);
            if args_span.is_none() {
                out.push_str(&args_text);
            }
            at = cmd_span.1;
            continue;
        }
        if let Some((start, end)) = args_span {
            if at == start {
                out.push_str(&args_text);
                at = end;
                continue;
            }
        }
        // A last line with no ending that now has a line after it.
        let line = lines[at];
        out.push_str(line);
        if !line.ends_with('\n') && at + 1 < lines.len() {
            out.push_str(newline);
        }
        at += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_wire;

    const BIN: &str = "/usr/local/bin/innerwarden";

    /// A Goose configuration as Goose writes it (`goose configure`, then
    /// `goose info`), with what a person adds by hand: comments, a server in
    /// flow style, a disabled server, a remote one and a setting after the
    /// block.
    const GOOSE: &str = "# Goose settings, edited by hand
GOOSE_PROVIDER: anthropic
GOOSE_MODEL: claude-sonnet-4
extensions:
  developer:
    bundled: true
    display_name: Developer
    enabled: true
    name: developer
    timeout: 300
    type: builtin
  # the GitHub server, added by hand
  github:
    args:
    - -y
    - '@modelcontextprotocol/server-github'
    bundled: null
    cmd: npx
    description: GitHub
    enabled: true
    env_keys:
    - GITHUB_PERSONAL_ACCESS_TOKEN
    envs: {}
    name: github
    timeout: 300
    type: stdio
  fetch:
    args: [mcp-server-fetch]   # flow style
    cmd: uvx
    enabled: false
    envs: {}
    name: fetch
    timeout: 300
    type: stdio
  remote:
    enabled: true
    name: remote
    type: streamable_http
    uri: https://example.test/mcp
GOOSE_MODE: smart_approve
";

    fn wrap(doc: &mut YamlDoc, monitor: bool) -> usize {
        let (wrapped, n) = mcp_wire::wrap(doc.view(), BIN, monitor, "goose");
        let applied = doc.apply(&wrapped).expect("apply");
        assert_eq!(applied, n);
        n
    }

    fn unwrap(doc: &mut YamlDoc) -> usize {
        let (restored, n) = mcp_wire::unwrap(doc.view());
        let applied = doc.apply(&restored).expect("apply");
        assert_eq!(applied, n);
        n
    }

    /// The lines that are no server's `cmd` or `args`.
    fn kept_lines(text: &str) -> Vec<&str> {
        let mut kept = Vec::new();
        let mut in_args = false;
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("cmd:") {
                in_args = false;
                continue;
            }
            if trimmed.starts_with("args:") {
                in_args = true;
                continue;
            }
            if in_args && trimmed.starts_with("- ") && line.starts_with("    -") {
                continue;
            }
            in_args = false;
            kept.push(line);
        }
        kept
    }

    /// Every stdio server is routed through the proxy, naming Goose, in the
    /// mode asked; built-in and remote extensions are counted remote; and
    /// every other line of the file is left as it was, comments included.
    ///
    /// FAILS ON REVERT of the line editor (`patch_extension`).
    #[test]
    fn a_real_goose_config_is_wrapped_with_only_its_server_lines_changed() {
        let mut doc = YamlDoc::parse(GOOSE).unwrap();
        assert_eq!(
            mcp_wire::server_counts(&doc.view()),
            mcp_wire::ServerCounts {
                stdio: 2,
                wrapped: 0,
                remote: 2
            }
        );
        assert_eq!(wrap(&mut doc, false), 2);
        let view = doc.view();
        assert!(mcp_wire::is_guarded(&view), "{}", doc.text());
        assert_eq!(
            mcp_wire::guarded_mode(&view),
            Some(mcp_wire::WiringMode::Enforce)
        );
        assert_eq!(kept_lines(doc.text()), kept_lines(GOOSE));
        assert!(doc.text().contains("# the GitHub server, added by hand\n"));
        assert!(doc.text().contains("GOOSE_MODE: smart_approve\n"));
        let github = &view["mcpServers"]["github"];
        assert_eq!(github["command"], BIN);
        let args: Vec<&str> = github["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        assert!(
            args.windows(2).any(|w| w == ["--agent", "goose"]),
            "{args:?}"
        );
        assert!(
            args.ends_with(&["--", "npx", "-y", "@modelcontextprotocol/server-github"]),
            "{args:?}"
        );
        // Goose reads it back: the same document, only cmd and args changed.
        let reread: Yaml = serde_yaml::from_str(doc.text()).unwrap();
        assert_eq!(
            reread["extensions"]["github"]["env_keys"][0],
            "GITHUB_PERSONAL_ACCESS_TOKEN"
        );
        assert_eq!(reread["extensions"]["fetch"]["enabled"], false);
        assert_eq!(
            reread["extensions"]["remote"]["uri"],
            "https://example.test/mcp"
        );
    }

    /// A second connect changes nothing; a mode switch rewrites the mode
    /// alone; a disconnect takes out only what connect put in, and Goose
    /// reads back the document it had.
    ///
    /// FAILS ON REVERT of `YamlDoc::apply` writing only changed servers.
    #[test]
    fn connect_twice_switch_mode_and_disconnect_leave_the_person_s_file() {
        let mut doc = YamlDoc::parse(GOOSE).unwrap();
        wrap(&mut doc, false);
        let once = doc.text().to_string();
        assert_eq!(wrap(&mut doc, false), 0);
        assert_eq!(doc.text(), once);

        assert_eq!(wrap(&mut doc, true), 2);
        assert_eq!(
            mcp_wire::guarded_mode(&doc.view()),
            Some(mcp_wire::WiringMode::Monitor)
        );

        assert_eq!(unwrap(&mut doc), 2);
        let original: Yaml = serde_yaml::from_str(GOOSE).unwrap();
        let restored: Yaml = serde_yaml::from_str(doc.text()).unwrap();
        assert_eq!(restored, original);
        assert_eq!(kept_lines(doc.text()), kept_lines(GOOSE));
        assert!(!mcp_wire::has_guard_wiring(&doc.view()));
        assert_eq!(unwrap(&mut doc), 0);
    }

    /// A server the lines cannot be placed in is refused, and the document
    /// is left as it was: nothing is written blind.
    ///
    /// FAILS ON REVERT of the refusal of an inline entry.
    #[test]
    fn a_server_written_inline_is_refused_and_the_file_left_alone() {
        for text in [
            "extensions:\n  github: {cmd: npx, args: [x], type: stdio}\n",
            "extensions: {github: {cmd: npx, args: [x], type: stdio}}\n",
        ] {
            let mut doc = YamlDoc::parse(text).unwrap();
            let (wrapped, n) = mcp_wire::wrap(doc.view(), BIN, false, "goose");
            assert_eq!(n, 1);
            assert!(doc.apply(&wrapped).is_err(), "{text}");
            assert_eq!(doc.text(), text);
        }
    }

    /// A server with no `args` line gains one after its `cmd`; a file with
    /// Windows line endings keeps them; a path with a space is quoted.
    #[test]
    fn a_server_without_args_and_a_crlf_file_are_wrapped() {
        let text = "extensions:\r\n  local:\r\n    cmd: /opt/my tools/server\r\n    type: stdio\r\n    enabled: true\r\n";
        let mut doc = YamlDoc::parse(text).unwrap();
        assert_eq!(wrap(&mut doc, false), 1);
        assert!(
            !doc.text().replace("\r\n", "").contains('\n'),
            "{:?}",
            doc.text()
        );
        let view = doc.view();
        assert!(mcp_wire::is_guarded(&view));
        assert!(view["mcpServers"]["local"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == "/opt/my tools/server"));
        assert_eq!(unwrap(&mut doc), 1);
        let restored: Yaml = serde_yaml::from_str(doc.text()).unwrap();
        assert_eq!(
            restored["extensions"]["local"]["cmd"],
            "/opt/my tools/server"
        );
    }

    /// A config with no stdio extension has nothing to wrap, and an empty
    /// file is an empty configuration, not an error.
    #[test]
    fn built_in_only_and_empty_configs_have_nothing_to_wrap() {
        let builtin = "extensions:\n  developer:\n    enabled: true\n    type: builtin\n";
        for text in [builtin, "", "GOOSE_MODEL: x\n"] {
            let doc = YamlDoc::parse(text).unwrap();
            assert!(!mcp_wire::is_guardable(&doc.view()), "{text:?}");
        }
        assert!(YamlDoc::parse("- a\n").is_err());
    }
}
