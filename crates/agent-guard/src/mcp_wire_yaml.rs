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
//! written. Built-in extensions have no local command: they are counted as
//! remote, since the proxy never sees their calls.
//!
//! A remote extension (`type: streamable_http` or `sse`, an http(s) `uri`)
//! goes through the same proxy, which talks HTTP(S) to it
//! ([`crate::mcp_proxy::remote`]): its `type` line becomes `stdio` and
//! `cmd` and `args` lines marked as connect's own follow it, while its
//! `uri` and `headers` lines stay as they were (Goose does not read them
//! for a stdio extension). The proxy reads those headers there
//! (`--goose-headers <name>`), `$VAR` filled from the variables Goose hands
//! its servers, so no header value is copied. Disconnect puts the `type`
//! back and takes the marked lines out. An extension Goose signs in to by
//! itself (`client_id`), one reached through a `socket`, or one whose
//! `uri` Goose fills from a variable is left as it was and counted remote.
//!
//! All logic here is pure; the file read/write is the I/O layer's job.

use serde_json::{Map, Value};
use serde_yaml::Value as Yaml;

/// The table of the view, as [`crate::mcp_wire`] reads a JSON client's.
const SERVERS: &str = "mcpServers";

/// The comment on an `args` line connect wrote where the server had none:
/// disconnect takes the line out again, so the file is as it was.
const ARGS_ADDED: &str = "# added by innerwarden connect; disconnect removes it";

/// The extension types whose servers Goose runs itself (`builtin`,
/// `platform`) or that are local commands the proxy wraps (`stdio`). Any
/// other type (`streamable_http`, `sse`, ...) is a server the proxy never
/// sees: [`YamlDoc::unscreened`] names each.
const OWN_OR_WRAPPED_TYPES: &[&str] = &["stdio", "builtin", "platform"];

/// A Goose configuration: the text as the person wrote it and what it parses
/// to.
#[derive(Debug, Clone, PartialEq)]
pub struct YamlDoc {
    text: String,
    value: Yaml,
    /// Where this configuration is read from, when the caller said: a remote
    /// extension's wrapper names it (`--goose-config`) so its proxy finds the
    /// headers without `HOME`.
    path: Option<String>,
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
        // A merge key (`<<: *base`) in the extensions: Goose (1.60, serde_yaml
        // 0.9) does not apply it, so what such an extension runs, or whether
        // Goose loads it at all, is not what the merged text says. Read
        // without it, a stdio server whose `type` came from the merge was
        // counted remote and left unwrapped without a word. The file is
        // refused instead: nothing is written and the status says it could
        // not be read.
        if let Some(extensions) = value.get("extensions") {
            if let Some(name) = extension_with_merge_key(extensions) {
                return Err(format!(
                    "a YAML merge key (`<<`) in extension `{name}`, which Goose does not apply; \
                     write that extension's fields out in full"
                ));
            }
        }
        Ok(Self {
            text: text.to_string(),
            value,
            path: None,
        })
    }

    /// Say where this configuration is read from: a remote extension wrapped
    /// from here on names the file (`--goose-config`), so its proxy reads the
    /// headers there and not under `HOME`, which a Goose started without it
    /// does not have.
    pub fn set_path(&mut self, path: &std::path::Path) {
        self.path = Some(path.to_string_lossy().into_owned());
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
                } else if let Some((uri, kind)) = carried_remote(extension) {
                    // A remote server the proxy carries, as a JSON client's
                    // `{"url", "type"}`: [`crate::mcp_wire`] wraps it.
                    let mut server = Map::new();
                    server.insert("url".to_string(), Value::String(uri));
                    server.insert("type".to_string(), Value::String(kind));
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

    /// The extensions the proxy does not screen and Goose does not run
    /// itself: each by its name and its type (`streamable_http`, `sse`, a
    /// missing type as `unknown`), in file order. Pure.
    pub fn unscreened(&self) -> Vec<(String, String)> {
        let Some(extensions) = extensions(&self.value) else {
            return Vec::new();
        };
        extensions
            .iter()
            .filter_map(|(name, extension)| {
                let name = name.as_str()?;
                let kind = extension
                    .get("type")
                    .and_then(Yaml::as_str)
                    .unwrap_or("unknown");
                (!OWN_OR_WRAPPED_TYPES.contains(&kind))
                    .then(|| (name.to_string(), kind.to_string()))
            })
            .collect()
    }

    /// The extensions that run code inside Goose and are no server at all
    /// (`inline_python`, `frontend`, a type this reader does not know, no
    /// type): no proxy sees what they do, so a config that holds one is never
    /// fully guarded. Remote servers (`streamable_http`, `sse`) and Goose's
    /// own (`builtin`, `platform`) are not among them. Pure.
    pub fn runs_inside(&self) -> Vec<(String, String)> {
        self.unscreened()
            .into_iter()
            .filter(|(_, kind)| !matches!(kind.as_str(), "streamable_http" | "sse"))
            .collect()
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
            if before.get("url").is_some() || server.get("url").is_some() {
                text = self.apply_remote(&text, &mut expected, name, before, server)?;
                changed += 1;
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
            let (patched, has_args) = patch_extension(&text, name, command, &args)?;
            text = patched;
            let extension = expected
                .get_mut("extensions")
                .and_then(|extensions| extensions.get_mut(name.as_str()))
                .and_then(Yaml::as_mapping_mut)
                .ok_or_else(|| format!("extension `{name}` could not be found"))?;
            extension.insert(Yaml::from("cmd"), Yaml::from(command));
            if has_args {
                extension.insert(
                    Yaml::from("args"),
                    Yaml::Sequence(args.iter().map(|arg| Yaml::from(arg.as_str())).collect()),
                );
            } else {
                extension.remove("args");
            }
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

impl YamlDoc {
    /// The edit of one remote extension: wrapped (its `type` becomes
    /// `stdio`, and `cmd` and `args` lines connect marks as its own come
    /// after it) or given back (its `type` as it was, those lines out).
    /// Its `uri` and `headers` lines stay where they were: Goose does not
    /// read them for a stdio extension, and the proxy reads the headers there
    /// (`--goose-headers`, [`crate::mcp_proxy::remote`]), filled from the
    /// variables Goose hands its servers, so no header value is copied
    /// anywhere.
    fn apply_remote(
        &self,
        text: &str,
        expected: &mut Yaml,
        name: &str,
        before: &Value,
        server: &Value,
    ) -> Result<String, String> {
        let extension = expected
            .get_mut("extensions")
            .and_then(|extensions| extensions.get_mut(name))
            .and_then(Yaml::as_mapping_mut)
            .ok_or_else(|| format!("extension `{name}` could not be found"))?;
        let only = |server: &Value, keys: &[&str]| {
            server
                .as_object()
                .is_some_and(|object| object.keys().all(|key| keys.contains(&key.as_str())))
        };
        if before.get("url").is_some() {
            // Connect: `{"url", "type"}` becomes a wrapper.
            if !only(server, &["command", "args", "type"])
                || server.get("type").and_then(Value::as_str) != Some("stdio")
            {
                return Err(format!(
                    "the edit would change more of extension `{name}` than its command"
                ));
            }
            let command = server
                .get("command")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("extension `{name}` would have no command"))?;
            let mut args: Vec<String> = server
                .get("args")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or(Some(Vec::new()))
                .ok_or_else(|| format!("extension `{name}` has arguments that are not text"))?;
            if extension.contains_key("headers") {
                if let Some(path) = &self.path {
                    args.push("--goose-config".to_string());
                    args.push(path.clone());
                }
                args.push("--goose-headers".to_string());
                args.push(name.to_string());
            }
            let patched = patch_remote_extension(text, name, Some((command, &args)), "stdio")?;
            extension.insert(Yaml::from("type"), Yaml::from("stdio"));
            extension.insert(Yaml::from("cmd"), Yaml::from(command));
            extension.insert(
                Yaml::from("args"),
                Yaml::Sequence(args.iter().map(|arg| Yaml::from(arg.as_str())).collect()),
            );
            Ok(patched)
        } else {
            // Disconnect: a wrapper goes back to the remote server it was.
            let url = server.get("url").and_then(Value::as_str);
            let kind = server.get("type").and_then(Value::as_str);
            let (Some(url), Some(kind)) = (url, kind) else {
                return Err(format!("extension `{name}` cannot be given back"));
            };
            if !only(server, &["url", "type"])
                || !REMOTE_KINDS.contains(&kind)
                || extension.get("uri").and_then(Yaml::as_str) != Some(url)
            {
                return Err(format!(
                    "extension `{name}` cannot be given back: its `uri` is not the address its proxy names"
                ));
            }
            let patched = patch_remote_extension(text, name, None, kind)?;
            extension.insert(Yaml::from("type"), Yaml::from(kind));
            extension.remove("cmd");
            extension.remove("args");
            Ok(patched)
        }
    }
}

/// The remote extension types the proxy carries.
const REMOTE_KINDS: &[&str] = &["streamable_http", "sse"];

/// Keys of a remote extension the proxy cannot stand in for: a sign-in
/// Goose does itself (`client_id`, `client_secret_key`, `scopes`), a
/// Unix socket the connection goes through (`socket`), and the keys of a
/// local server (a wrapper would write them twice).
const NOT_CARRIED_KEYS: &[&str] = &[
    "client_id",
    "client_secret_key",
    "scopes",
    "socket",
    "cmd",
    "args",
];

/// The address and type of a remote extension the proxy can carry: type
/// `streamable_http` or `sse`, an http(s) `uri` with no `$` (Goose
/// fills those from its variables, the proxy would not), `headers` of text
/// if any, and nothing of [`NOT_CARRIED_KEYS`]. Pure.
fn carried_remote(extension: &Yaml) -> Option<(String, String)> {
    let map = extension.as_mapping()?;
    let kind = extension.get("type")?.as_str()?;
    if !REMOTE_KINDS.contains(&kind) {
        return None;
    }
    if NOT_CARRIED_KEYS
        .iter()
        .any(|key| map.contains_key(Yaml::from(*key)))
    {
        return None;
    }
    let uri = extension.get("uri")?.as_str()?;
    if uri.contains('$') || !crate::mcp_proxy::remote::is_remote_url(uri) {
        return None;
    }
    match extension.get("headers") {
        None | Some(Yaml::Null) => {}
        Some(Yaml::Mapping(headers)) => {
            for (key, value) in headers {
                let (Some(key), Some(value)) = (key.as_str(), value.as_str()) else {
                    return None;
                };
                if !crate::mcp_proxy::remote::is_header_name(key.trim())
                    || value.contains(['\r', '\n', '\0'])
                {
                    return None;
                }
            }
        }
        Some(_) => return None,
    }
    Some((uri.to_string(), kind.to_string()))
}

/// The view of a configuration's bytes ([`YamlDoc::view`]), `None` when they
/// are not a YAML mapping. Pure.
pub fn view_of_bytes(bytes: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(bytes).ok()?;
    YamlDoc::parse(text).ok().map(|doc| doc.view())
}

/// The name of an extension that holds a merge key (`<<`) at any depth, or
/// `""` for one on the `extensions` mapping itself.
fn extension_with_merge_key(extensions: &Yaml) -> Option<String> {
    fn holds_merge_key(value: &Yaml) -> bool {
        match value {
            Yaml::Mapping(map) => map
                .iter()
                .any(|(key, value)| key.as_str() == Some("<<") || holds_merge_key(value)),
            Yaml::Sequence(items) => items.iter().any(holds_merge_key),
            Yaml::Tagged(tagged) => holds_merge_key(&tagged.value),
            _ => false,
        }
    }
    let map = extensions.as_mapping()?;
    if map.keys().any(|key| key.as_str() == Some("<<")) {
        return Some(String::new());
    }
    map.iter()
        .find(|(_, extension)| holds_merge_key(extension))
        .map(|(name, _)| name.as_str().unwrap_or("?").to_string())
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
/// other line kept as it was, and say whether the extension still has an
/// `args` field. An `args` line written where the server had none carries
/// [`ARGS_ADDED`]; when the arguments go back to none, that line is taken
/// out, so a server connect and disconnect pass over is as it was. An error
/// for a shape the lines cannot be placed in: no block `extensions:` at the
/// top level, the extension written inline, no `cmd` line.
fn patch_extension(
    text: &str,
    name: &str,
    command: &str,
    args: &[String],
) -> Result<(String, bool), String> {
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
    // Connect's own `args` line: written where there was none, or one it
    // wrote before.
    let added = args_span.is_none_or(|(start, _)| lines[start].contains(ARGS_ADDED));
    let has_args = !(args.is_empty() && added);
    let args_text = if !has_args {
        String::new()
    } else if args.is_empty() {
        format!("{pad}args: []{newline}")
    } else {
        let mut out = if added {
            format!("{pad}args: {ARGS_ADDED}{newline}")
        } else {
            format!("{pad}args:{newline}")
        };
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
    Ok((out, has_args))
}

/// Rewrite a remote extension's `type` line to `kind`, and put `cmd`
/// and `args` lines after it (`wrapper`, each marked as connect's own) or
/// take them out (`None`). Every other line is kept as it was. An error
/// for a shape the lines cannot be placed in.
fn patch_remote_extension(
    text: &str,
    name: &str,
    wrapper: Option<(&str, &[String])>,
    kind: &str,
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
    let type_at = find("type").ok_or_else(|| cannot("it has no `type` line"))?;
    let type_end = field_end(&lines, type_at, entry_end, field);
    if type_end != type_at + 1 {
        return Err(cannot("its `type` is not written on one line"));
    }
    let pad = " ".repeat(field);
    let mut drop: Vec<(usize, usize)> = Vec::new();
    let mut added = String::new();
    match wrapper {
        Some((command, args)) => {
            if find("cmd").is_some() || find("args").is_some() {
                return Err(cannot("it already has a `cmd` or `args` line"));
            }
            added.push_str(&format!(
                "{pad}cmd: {} {ARGS_ADDED}{newline}",
                scalar(command)
            ));
            added.push_str(&format!("{pad}args: {ARGS_ADDED}{newline}"));
            for arg in args {
                added.push_str(&format!("{pad}- {}{newline}", scalar(arg)));
            }
        }
        None => {
            for key in ["cmd", "args"] {
                let at =
                    find(key).ok_or_else(|| cannot("its wrapper has no `cmd` or `args` line"))?;
                drop.push((at, field_end(&lines, at, entry_end, field)));
            }
        }
    }
    // The `type` line keeps whatever comment it had after its value.
    let type_line = lines[type_at];
    let body = type_line.trim_end_matches(['\n', '\r']);
    let comment = body.find(" #").map(|at| &body[at..]).unwrap_or_default();
    let type_text = format!("{pad}type: {}{comment}{newline}", scalar(kind));
    let mut out = String::with_capacity(text.len() + 512);
    for (at, line) in lines.iter().enumerate() {
        if drop.iter().any(|(start, end)| (*start..*end).contains(&at)) {
            continue;
        }
        if at == type_at {
            out.push_str(&type_text);
            out.push_str(&added);
            continue;
        }
        out.push_str(line);
        if !line.ends_with('\n') && at + 1 < lines.len() {
            out.push_str(newline);
        }
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
        // The built-in extension is Goose's own; the remote one is carried.
        assert_eq!(
            mcp_wire::server_counts(&doc.view()),
            mcp_wire::ServerCounts {
                stdio: 3,
                wrapped: 0,
                remote: 1
            }
        );
        assert_eq!(wrap(&mut doc, false), 3);
        let view = doc.view();
        assert!(mcp_wire::is_guarded(&view), "{}", doc.text());
        assert_eq!(
            mcp_wire::guarded_mode(&view),
            Some(mcp_wire::WiringMode::Enforce)
        );
        // Besides the cmd and args lines, only the remote one's type changed.
        assert_eq!(
            kept_lines(doc.text()),
            kept_lines(&GOOSE.replace("    type: streamable_http\n", "    type: stdio\n"))
        );
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

        assert_eq!(wrap(&mut doc, true), 3);
        assert_eq!(
            mcp_wire::guarded_mode(&doc.view()),
            Some(mcp_wire::WiringMode::Monitor)
        );

        assert_eq!(unwrap(&mut doc), 3);
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

    /// The extensions block Goose 1.60.2 documents as its "common extension
    /// shapes" (documentation/docs/guides/config-files.md at tag v1.60.2,
    /// commit fb55b5a6d7f5b5df96c8f817f1cde6a81880d9f1), verbatim, with the
    /// settings it documents above it. Goose writes the same fields; the
    /// file is copied from Goose's own page, not from a running Goose.
    const GOOSE_1_60_2: &str = "# Security Configuration
SECURITY_PROMPT_ENABLED: true

extensions:
  developer:
    type: builtin
    name: developer
    enabled: true
    bundled: true
    timeout: 300

  computercontroller:
    type: platform
    name: computercontroller
    display_name: Computer Controller
    enabled: true
    bundled: true

  filesystem:
    type: stdio
    name: filesystem
    enabled: true
    cmd: npx
    args: [\"-y\", \"@modelcontextprotocol/server-filesystem\", \"/tmp\"]
    env_keys: []
    envs: {}
    timeout: 300

  remote-tools:
    type: streamable_http
    name: remote-tools
    enabled: true
    uri: \"https://example.com/mcp\"
    headers: {}
    env_keys: []
    envs: {}
    timeout: 300
";

    /// Goose 1.60.2's own sample: its stdio server and its remote one are
    /// wrapped (the remote one was named as a server the proxy does not see
    /// until the proxy carried it), the built-in and platform ones are
    /// Goose's, and a disconnect gives back the same bytes.
    #[test]
    fn goose_1_60_2_sample_is_wrapped_with_its_remote_server() {
        let mut doc = YamlDoc::parse(GOOSE_1_60_2).unwrap();
        assert_eq!(
            doc.unscreened(),
            vec![("remote-tools".to_string(), "streamable_http".to_string())]
        );
        assert_eq!(wrap(&mut doc, false), 2);
        assert!(mcp_wire::is_guarded(&doc.view()), "{}", doc.text());
        assert!(doc.unscreened().is_empty(), "{}", doc.text());
        assert_eq!(unwrap(&mut doc), 2);
        // The remote extension comes back byte for byte (the stdio one's
        // flow-style args come back in block style, as before).
        let remote = |text: &str| text[text.find("  remote-tools:").unwrap()..].to_string();
        assert_eq!(remote(doc.text()), remote(GOOSE_1_60_2));
        let restored: Yaml = serde_yaml::from_str(doc.text()).unwrap();
        let original: Yaml = serde_yaml::from_str(GOOSE_1_60_2).unwrap();
        assert_eq!(restored, original);
    }

    /// FAILS ON REVERT of the merge key refusal in `YamlDoc::parse`: the
    /// stdio server whose `type` comes from `<<: *base` is read as remote
    /// and left unwrapped, and connect says nothing of it.
    #[test]
    fn an_extension_with_a_merge_key_refuses_the_file() {
        let with_merge = GOOSE_1_60_2.replace(
            "extensions:\n",
            "stdio_base: &stdio_base\n  type: stdio\n  enabled: true\n  timeout: 300\n\nextensions:\n  github:\n    <<: *stdio_base\n    name: github\n    cmd: npx\n    args:\n    - -y\n    - '@modelcontextprotocol/server-github'\n",
        );
        let error = YamlDoc::parse(&with_merge).unwrap_err();
        assert!(
            error.contains("merge key") && error.contains("github"),
            "{error}"
        );
        assert!(view_of_bytes(with_merge.as_bytes()).is_none());
        // An anchor and an alias with no merge key are plain YAML Goose reads
        // as written: such a file is read.
        let anchors = GOOSE_1_60_2
            .replace(
                "    env_keys: []\n    envs: {}\n    timeout: 300\n\n  remote-tools:",
                "    env_keys: &none []\n    envs: {}\n    timeout: 300\n\n  remote-tools:",
            )
            .replace(
                "    headers: {}\n    env_keys: []",
                "    headers: {}\n    env_keys: *none",
            );
        let doc = YamlDoc::parse(&anchors).unwrap();
        // The stdio server and the remote one the proxy carries.
        assert_eq!(mcp_wire::server_counts(&doc.view()).stdio, 2);
    }

    /// Review of #369, item 7: a key written twice in an extension (a second
    /// `type:` or `cmd:`), or an extension named twice, is refused by the
    /// parser (serde_yaml 0.9, Goose's too), so the file is not read and
    /// nothing is written.
    #[test]
    fn a_key_written_twice_refuses_the_file() {
        for text in [
            "extensions:\n  gh:\n    type: builtin\n    cmd: npx\n    type: stdio\n",
            "extensions:\n  gh:\n    type: stdio\n    cmd: npx\n    cmd: /tmp/evil\n",
            "extensions:\n  gh:\n    type: stdio\n    cmd: npx\n  gh:\n    type: sse\n",
        ] {
            let error = YamlDoc::parse(text).unwrap_err();
            assert!(error.contains("duplicate"), "{error}");
        }
    }

    /// Review of #369, item 5: code that runs inside Goose (`inline_python`,
    /// `frontend`, an unknown or missing type) is named apart from the remote
    /// servers: no proxy sees it, so the config is never fully guarded.
    #[test]
    fn code_that_runs_inside_goose_is_named_apart() {
        let text = "extensions:\n  a:\n    type: sse\n  b:\n    type: inline_python\n  c:\n    type: frontend\n  d:\n    name: d\n  e:\n    type: builtin\n";
        let doc = YamlDoc::parse(text).unwrap();
        let inside: Vec<String> = doc.runs_inside().into_iter().map(|(n, _)| n).collect();
        assert_eq!(inside, ["b", "c", "d"]);
    }

    /// A file of more than one document is not read: the parser Goose uses
    /// refuses it too, and nothing here says what it runs.
    #[test]
    fn a_file_of_several_documents_is_not_read() {
        let multi = format!("{GOOSE_1_60_2}---\nGOOSE_MODE: auto\n");
        assert!(YamlDoc::parse(&multi).is_err());
        assert!(view_of_bytes(multi.as_bytes()).is_none());
    }

    /// FAILS ON REVERT of `ARGS_ADDED` in `patch_extension`: a server with
    /// no `args` line kept an `args: []` after connect and disconnect.
    #[test]
    fn disconnect_gives_back_a_server_without_args_as_it_was() {
        let text = "extensions:\n  local:\n    type: stdio\n    name: local\n    enabled: true\n    cmd: /opt/tools/server\n    timeout: 300\n";
        let mut doc = YamlDoc::parse(text).unwrap();
        assert_eq!(wrap(&mut doc, false), 1);
        assert!(doc.text().contains(ARGS_ADDED), "{}", doc.text());
        // A mode switch keeps the line connect's own.
        assert_eq!(wrap(&mut doc, true), 1);
        assert!(doc.text().contains(ARGS_ADDED), "{}", doc.text());
        assert_eq!(unwrap(&mut doc), 1);
        assert_eq!(doc.text(), text);
        // A server that had `args: []` keeps it.
        let empty = text.replace("    timeout: 300\n", "    args: []\n    timeout: 300\n");
        let mut doc = YamlDoc::parse(&empty).unwrap();
        wrap(&mut doc, false);
        unwrap(&mut doc);
        let restored: Yaml = serde_yaml::from_str(doc.text()).unwrap();
        assert_eq!(restored, serde_yaml::from_str::<Yaml>(&empty).unwrap());
    }

    /// Every extension the proxy does not see is named with its type: a
    /// remote one of either kind, one of a type this reader does not know,
    /// one with no type.
    #[test]
    fn extensions_the_proxy_does_not_see_are_named() {
        let text = "extensions:\n  a:\n    type: sse\n    uri: http://x\n  b:\n    type: streamable_http\n    uri: http://y\n  c:\n    type: inline_python\n  d:\n    name: d\n  e:\n    type: builtin\n  f:\n    type: stdio\n    cmd: x\n";
        let doc = YamlDoc::parse(text).unwrap();
        let names: Vec<(String, String)> = doc.unscreened();
        let want: Vec<(String, String)> = [
            ("a", "sse"),
            ("b", "streamable_http"),
            ("c", "inline_python"),
            ("d", "unknown"),
        ]
        .iter()
        .map(|(n, t)| (n.to_string(), t.to_string()))
        .collect();
        assert_eq!(names, want);
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

#[cfg(test)]
mod remote_wiring_tests {
    use super::*;
    use crate::mcp_wire;

    const BIN: &str = "/usr/local/bin/innerwarden";

    /// A remote extension the proxy cannot stand in for is left as it is
    /// and named: a sign-in Goose does itself, a Unix socket, an address
    /// Goose fills from a variable, a header that is not text.
    #[test]
    fn a_remote_extension_the_proxy_cannot_carry_is_left_alone() {
        for extra in [
            "    client_id: registered-client.example\n",
            "    socket: /run/mcp.sock\n",
            "    headers:\n      A: 1\n",
        ] {
            let text = format!(
                "extensions:\n  r:\n    name: r\n    type: streamable_http\n    uri: https://x.example/mcp\n{extra}"
            );
            let doc = YamlDoc::parse(&text).unwrap();
            assert!(!mcp_wire::is_guardable(&doc.view()), "{text}");
            assert_eq!(doc.unscreened().len(), 1, "{text}");
        }
        let filled = "extensions:\n  r:\n    name: r\n    type: sse\n    uri: https://x.example/mcp?key=$KEY\n";
        assert!(!mcp_wire::is_guardable(
            &YamlDoc::parse(filled).unwrap().view()
        ));
    }

    /// A remote extension with headers names Goose's extension for the
    /// proxy (`--goose-headers`), keeps its `uri` and `headers` lines,
    /// and comes back byte for byte after a mode switch. A wrapper whose
    /// `uri` line is gone is not given back blind. FAILS ON REVERT of
    /// `patch_remote_extension`.
    #[test]
    fn a_remote_extension_with_headers_is_wired_and_comes_back() {
        let text = "extensions:\n  remote:\n    enabled: true\n    envs: {}\n    env_keys:\n    - API_TOKEN\n    headers:\n      Authorization: Bearer ${API_TOKEN}\n    name: remote\n    timeout: 300\n    type: sse # the old transport\n    uri: https://example.test/sse\n";
        let mut doc = YamlDoc::parse(text).unwrap();
        let (wrapped, n) = mcp_wire::wrap(doc.view(), BIN, false, "goose");
        assert_eq!(n, 1);
        assert_eq!(doc.apply(&wrapped).unwrap(), 1);
        assert!(
            doc.text().contains("    type: stdio # the old transport\n"),
            "{}",
            doc.text()
        );
        assert!(doc
            .text()
            .contains("      Authorization: Bearer ${API_TOKEN}\n"));
        let view = doc.view();
        let args: Vec<&str> = view["mcpServers"]["remote"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        assert!(
            args.ends_with(&[
                "--",
                "https://example.test/sse",
                "--type",
                "sse",
                "--goose-headers",
                "remote"
            ]),
            "{args:?}"
        );
        let (monitor, n) = mcp_wire::wrap(view, BIN, true, "goose");
        assert_eq!(n, 1);
        assert_eq!(doc.apply(&monitor).unwrap(), 1);
        let (restored, n) = mcp_wire::unwrap(doc.view());
        assert_eq!(n, 1);
        assert_eq!(doc.apply(&restored).unwrap(), 1);
        assert_eq!(doc.text(), text);

        let mut doc = YamlDoc::parse(text).unwrap();
        let (wrapped, _) = mcp_wire::wrap(doc.view(), BIN, false, "goose");
        doc.apply(&wrapped).unwrap();
        let moved = doc
            .text()
            .replace("    uri: https://example.test/sse\n", "");
        let mut moved = YamlDoc::parse(&moved).unwrap();
        let (restored, _) = mcp_wire::unwrap(moved.view());
        let before = moved.text().to_string();
        assert!(moved.apply(&restored).is_err());
        assert_eq!(moved.text(), before);
    }

    /// Connect names Goose's configuration in the wrapper
    /// (`--goose-config`), so the proxy reads the headers there when Goose
    /// starts it with no `HOME`; disconnect still gives the file back byte
    /// for byte. FAILS ON REVERT: leave the path out of the wrapper, and the
    /// proxy started without `HOME` refuses to start.
    #[test]
    fn the_wrapper_names_gooses_configuration() {
        let text = "extensions:\n  remote:\n    headers:\n      X-Team: blue\n    name: remote\n    type: streamable_http\n    uri: https://example.test/mcp\n";
        let mut doc = YamlDoc::parse(text).unwrap();
        doc.set_path(std::path::Path::new("/cfg/goose/config.yaml"));
        let (wrapped, n) = mcp_wire::wrap(doc.view(), BIN, false, "goose");
        assert_eq!(n, 1);
        assert_eq!(doc.apply(&wrapped).unwrap(), 1);
        let view = doc.view();
        let args: Vec<String> = view["mcpServers"]["remote"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().to_string())
            .collect();
        let at = args.iter().position(|a| a == "--").unwrap();
        let words = args[at + 1..].to_vec();
        assert!(
            words.ends_with(&[
                "--goose-config".to_string(),
                "/cfg/goose/config.yaml".to_string(),
                "--goose-headers".to_string(),
                "remote".to_string()
            ]),
            "{words:?}"
        );
        let spec = crate::mcp_proxy::remote::RemoteSpec::from_cmd_reading(
            &words,
            |_| None,
            |path| {
                (path == std::path::Path::new("/cfg/goose/config.yaml")).then(|| text.to_string())
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(spec.headers, [("X-Team".to_string(), "blue".to_string())]);
        let (restored, n) = mcp_wire::unwrap(doc.view());
        assert_eq!(n, 1);
        assert_eq!(doc.apply(&restored).unwrap(), 1);
        assert_eq!(doc.text(), text);
    }
}
