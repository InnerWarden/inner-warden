//! Guard **Codex**, whose MCP servers live in `~/.codex/config.toml` under
//! `[mcp_servers.NAME]` (TOML, `command`/`args`/`env`) rather than a JSON
//! `mcp.json`. Same idea as `mcp_wire`: rewrite each stdio server so it launches
//! THROUGH `innerwarden proxy` instead of directly, so Codex's MCP tool calls are
//! screened by the same engine as `check`. Monitor mode records findings;
//! enforcement may block dangerous calls. Reversible (`unwrap_toml`) and
//! idempotent (`wrap_toml` twice = wrapped once).
//!
//! Edits are FORMAT-PRESERVING (`toml_edit`): the user's comments, key order, and
//! unrelated config in `config.toml` are left untouched, only `command`/`args`
//! of each MCP server change. All logic here is pure/tested (operates on a parsed
//! `DocumentMut`; the file read/write is the I/O layer's job).

use toml_edit::{value, Array, DocumentMut, Item, Table, Value};

/// The basename of a command path, cross-platform (`/` and `\`), lowercased.
fn basename(cmd: &str) -> String {
    cmd.rsplit(['/', '\\'])
        .next()
        .unwrap_or(cmd)
        .trim_end_matches(".exe")
        .to_ascii_lowercase()
}

/// Effective enforcement of MCP servers wired through the local proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WiringMode {
    Monitor,
    Enforce,
    Mixed,
}

fn has_proxy_prefix(server: &Table) -> bool {
    let is_guard = server
        .get("command")
        .and_then(Item::as_str)
        .map(|c| {
            let b = basename(c);
            b.starts_with("innerwarden") || b == "iw" || b == "innerwarden"
        })
        .unwrap_or(false);
    if !is_guard {
        return false;
    }
    server
        .get("args")
        .and_then(Item::as_array)
        .and_then(|args| args.get(0))
        .and_then(Value::as_str)
        == Some("proxy")
}

/// Locate the proxy's `--` separator for both legacy `proxy --` wrappers and the
/// explicit `proxy --mode M --` layout written by current versions.
fn wrapper_separator(server: &Table) -> Option<usize> {
    if !has_proxy_prefix(server) {
        return None;
    }
    let args = server.get("args").and_then(Item::as_array)?;
    args.iter().position(|v| v.as_str() == Some("--"))
}

fn server_mode(server: &Table) -> Option<WiringMode> {
    let separator = wrapper_separator(server)?;
    let args = server.get("args").and_then(Item::as_array)?;
    if args
        .get(separator + 1)
        .and_then(Value::as_str)
        .is_none_or(|command| command.trim().is_empty())
    {
        return None;
    }
    let values: Vec<&Value> = args.iter().collect();
    let mut mode: Option<&str> = None;
    let mut i = 1usize;
    while i < separator {
        let arg = values[i].as_str()?;
        if arg == "--mode" {
            mode = Some(values.get(i + 1)?.as_str()?);
            i += 2;
        } else if let Some(value) = arg.strip_prefix("--mode=") {
            mode = Some(value);
            i += 1;
        } else {
            i += 1;
        }
    }
    match mode {
        // Legacy Community wrappers were written as `proxy -- <child>`; the
        // Community CLI's historical default is guard, so they enforce.
        None | Some("guard" | "kill") => Some(WiringMode::Enforce),
        Some("advisory" | "warn") => Some(WiringMode::Monitor),
        Some(_) => None,
    }
}

/// True when a server table is already routed through the guard proxy: its command
/// is the guard binary and its args contain the proxy command separator.
fn is_wrapped_server(server: &Table) -> bool {
    server_mode(server).is_some()
}

fn proxy_prefix_without_mode(args: &[Value], separator: usize) -> Vec<Value> {
    let mut prefix = Vec::with_capacity(separator + 2);
    prefix.push(Value::from("proxy"));
    let mut i = 1usize;
    while i < separator {
        let is_mode = args[i].as_str() == Some("--mode");
        let is_inline_mode = args[i]
            .as_str()
            .is_some_and(|arg| arg.starts_with("--mode="));
        if is_mode {
            i = (i + 2).min(separator);
        } else if is_inline_mode {
            i += 1;
        } else {
            prefix.push(args[i].clone());
            i += 1;
        }
    }
    prefix
}

/// A stdio server has a non-empty local `command` (not a remote `url`-only server).
fn is_stdio_server(server: &Table) -> bool {
    server
        .get("command")
        .and_then(Item::as_str)
        .map(|c| !c.trim().is_empty())
        .unwrap_or(false)
}

/// The `[mcp_servers]` table, mutable, if present.
fn servers_mut(doc: &mut DocumentMut) -> Option<&mut Table> {
    doc.get_mut("mcp_servers").and_then(Item::as_table_mut)
}

fn wrap_server(server: &mut Table, guard_bin: &str, monitor: bool) -> bool {
    if !is_stdio_server(server) {
        return false;
    }
    let current_command = server
        .get("command")
        .and_then(Item::as_str)
        .unwrap_or_default()
        .to_string();
    let current_args: Vec<Value> = server
        .get("args")
        .and_then(Item::as_array)
        .map(|a| a.iter().cloned().collect())
        .unwrap_or_default();
    let current_args_text = server
        .get("args")
        .and_then(Item::as_array)
        .map(ToString::to_string)
        .unwrap_or_default();
    let separator = wrapper_separator(server);
    if separator.is_none() && has_proxy_prefix(server) {
        return false;
    }
    let (orig_cmd, orig_args, mut proxy_prefix) = if let Some(separator) = separator {
        if current_args.len() <= separator + 1 {
            return false;
        }
        (
            current_args[separator + 1]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            current_args[separator + 2..].to_vec(),
            proxy_prefix_without_mode(&current_args, separator),
        )
    } else {
        (
            current_command.clone(),
            current_args.clone(),
            vec![Value::from("proxy")],
        )
    };
    if orig_cmd.is_empty() {
        return false;
    }

    let mut new_args = Array::new();
    for arg in proxy_prefix.drain(..) {
        new_args.push_formatted(arg);
    }
    new_args.push("--mode");
    new_args.push(if monitor { "advisory" } else { "guard" });
    new_args.push("--");
    new_args.push(orig_cmd);
    for a in orig_args {
        new_args.push_formatted(a);
    }
    if current_command == guard_bin && current_args_text == new_args.to_string() {
        return false;
    }
    server.insert("command", value(guard_bin));
    server.insert("args", value(new_args));
    true
}

fn unwrap_server(server: &mut Table) -> bool {
    let Some(separator) = wrapper_separator(server) else {
        return false;
    };
    let args: Vec<Value> = server
        .get("args")
        .and_then(Item::as_array)
        .map(|a| a.iter().cloned().collect())
        .unwrap_or_default();
    if args.len() <= separator + 1 {
        return false;
    }
    let orig_cmd = args[separator + 1].as_str().unwrap_or_default().to_string();
    let mut orig_args = Array::new();
    for a in &args[separator + 2..] {
        orig_args.push_formatted(a.clone());
    }
    server.insert("command", value(orig_cmd));
    if orig_args.is_empty() {
        server.remove("args");
    } else {
        server.insert("args", value(orig_args));
    }
    true
}

fn for_each_server(doc: &mut DocumentMut, mut f: impl FnMut(&mut Table) -> bool) -> usize {
    let mut n = 0;
    if let Some(servers) = servers_mut(doc) {
        for (_name, item) in servers.iter_mut() {
            if let Some(t) = item.as_table_mut() {
                if f(t) {
                    n += 1;
                }
            }
        }
    }
    n
}

fn counts(doc: &DocumentMut) -> (usize, usize) {
    let mut stdio = 0;
    let mut wrapped = 0;
    if let Some(servers) = doc.get("mcp_servers").and_then(Item::as_table) {
        for (_name, item) in servers.iter() {
            if let Some(t) = item.as_table() {
                if is_stdio_server(t) {
                    stdio += 1;
                    if is_wrapped_server(t) {
                        wrapped += 1;
                    }
                }
            }
        }
    }
    (stdio, wrapped)
}

/// Route every stdio MCP server through `guard_bin proxy` in explicit advisory
/// (`monitor=true`) or guard mode. Existing wrappers are reconfigured without
/// nesting. Returns how many entries changed. Idempotent, format-preserving.
pub fn wrap_toml(doc: &mut DocumentMut, guard_bin: &str, monitor: bool) -> usize {
    for_each_server(doc, |s| wrap_server(s, guard_bin, monitor))
}

/// Undo `wrap_toml`. Returns how many servers were unwrapped.
pub fn unwrap_toml(doc: &mut DocumentMut) -> usize {
    for_each_server(doc, unwrap_server)
}

/// Every stdio server is routed through the proxy (and there is at least one).
/// Is there at least one stdio server not yet routed through the proxy?
/// See [`super::mcp_wire::has_unguarded_stdio_server`] for why this is distinct
/// from "has any wiring".
pub fn has_unguarded_stdio_server_toml(doc: &DocumentMut) -> bool {
    let (stdio, wrapped) = counts(doc);
    stdio > wrapped
}

pub fn is_guarded_toml(doc: &DocumentMut) -> bool {
    let (stdio, wrapped) = counts(doc);
    stdio > 0 && stdio == wrapped
}

/// Whether at least one server still points at an InnerWarden proxy wrapper,
/// including legacy or malformed wiring that a reconnect can repair.
pub fn has_guard_wiring_toml(doc: &DocumentMut) -> bool {
    doc.get("mcp_servers")
        .and_then(Item::as_table)
        .is_some_and(|servers| {
            servers
                .iter()
                .any(|(_, item)| item.as_table().is_some_and(has_proxy_prefix))
        })
}

/// Effective mode across every guarded stdio server. `None` means there is no
/// fully guarded local server; differing modes are reported as `Mixed`.
pub fn guarded_mode_toml(doc: &DocumentMut) -> Option<WiringMode> {
    let mut found: Option<WiringMode> = None;
    let servers = doc.get("mcp_servers").and_then(Item::as_table)?;
    for (_name, item) in servers.iter() {
        let Some(server) = item
            .as_table()
            .filter(|server| wrapper_separator(server).is_some())
        else {
            continue;
        };
        let mode = server_mode(server)?;
        found = Some(match found {
            None => mode,
            Some(existing) if existing == mode => existing,
            Some(_) => WiringMode::Mixed,
        });
    }
    found
}

/// There is at least one stdio server the guard can wrap.
pub fn is_guardable_toml(doc: &DocumentMut) -> bool {
    counts(doc).0 > 0
}

/// Strict shape required by background setup. It must be possible to preserve
/// every existing argument exactly; explicit/manual connect remains the repair
/// path for malformed TOML.
pub fn is_automatic_wrap_safe_toml(doc: &DocumentMut) -> bool {
    let Some(servers) = doc.get("mcp_servers").and_then(Item::as_table) else {
        return false;
    };
    for (_name, item) in servers.iter() {
        let Some(server) = item.as_table() else {
            return false;
        };
        if is_stdio_server(server)
            && server.get("args").is_some_and(|args| {
                !args
                    .as_array()
                    .is_some_and(|args| args.iter().all(|value| value.as_str().is_some()))
            })
        {
            return false;
        }
    }
    is_guardable_toml(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> DocumentMut {
        r#"
# a comment the wrap must preserve
model = "gpt-5"

[mcp_servers.icm]
command = "npx"
args = ["-y", "some-server"]

[mcp_servers.node_repl]
command = "node"
args = ["repl.js"]
[mcp_servers.node_repl.env]
FOO = "bar"

[mcp_servers.remote_only]
url = "https://example.com/mcp"
"#
        .parse::<DocumentMut>()
        .unwrap()
    }

    #[test]
    fn wraps_stdio_servers_preserves_comments_and_leaves_remote_alone() {
        let mut d = doc();
        assert!(is_guardable_toml(&d));
        assert!(!is_guarded_toml(&d));
        let n = wrap_toml(&mut d, "innerwarden", false);
        assert_eq!(n, 2, "two stdio servers wrapped, remote_only left alone");
        // command rewritten, original preserved inside args
        let icm = d["mcp_servers"]["icm"].as_table().unwrap();
        assert_eq!(icm["command"].as_str(), Some("innerwarden"));
        let args: Vec<&str> = icm["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            args,
            vec!["proxy", "--mode", "guard", "--", "npx", "-y", "some-server"]
        );
        // unrelated config + comment preserved
        let out = d.to_string();
        assert!(out.contains("a comment the wrap must preserve"));
        assert!(out.contains("model = \"gpt-5\""));
        assert!(out.contains("FOO = \"bar\""), "env sub-table preserved");
        assert!(is_guarded_toml(&d));
        assert_eq!(guarded_mode_toml(&d), Some(WiringMode::Enforce));
    }

    #[test]
    fn automatic_wrap_rejects_non_string_or_non_array_args() {
        assert!(is_automatic_wrap_safe_toml(&doc()));
        let absent = "[mcp_servers.local]\ncommand = \"npx\"\n"
            .parse::<DocumentMut>()
            .unwrap();
        assert!(is_automatic_wrap_safe_toml(&absent));
        let scalar = "[mcp_servers.local]\ncommand = \"npx\"\nargs = \"--foo\"\n"
            .parse::<DocumentMut>()
            .unwrap();
        assert!(!is_automatic_wrap_safe_toml(&scalar));
        let mixed = "[mcp_servers.local]\ncommand = \"npx\"\nargs = [\"ok\", 1]\n"
            .parse::<DocumentMut>()
            .unwrap();
        assert!(!is_automatic_wrap_safe_toml(&mixed));
    }

    #[test]
    fn wrap_is_idempotent() {
        let mut d = doc();
        assert_eq!(wrap_toml(&mut d, "innerwarden", false), 2);
        assert_eq!(
            wrap_toml(&mut d, "innerwarden", false),
            0,
            "second wrap is a no-op"
        );
    }

    #[test]
    fn unwrap_restores_the_original() {
        let mut d = doc();
        wrap_toml(&mut d, "innerwarden", false);
        let n = unwrap_toml(&mut d);
        assert_eq!(n, 2);
        let icm = d["mcp_servers"]["icm"].as_table().unwrap();
        assert_eq!(icm["command"].as_str(), Some("npx"));
        let args: Vec<&str> = icm["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(args, vec!["-y", "some-server"]);
        assert!(!is_guarded_toml(&d));
    }

    #[test]
    fn recognizes_install_name_variants_as_wrapped() {
        let mut d = "[mcp_servers.x]\ncommand = \"/opt/innerwarden-ctl\"\nargs = [\"proxy\", \"--\", \"npx\"]\n"
            .parse::<DocumentMut>()
            .unwrap();
        assert!(is_guarded_toml(&d));
        assert_eq!(guarded_mode_toml(&d), Some(WiringMode::Enforce));
        assert_eq!(wrap_toml(&mut d, "innerwarden", false), 1);
        assert_eq!(wrap_toml(&mut d, "innerwarden", false), 0);
    }

    #[test]
    fn switching_monitor_and_enforce_rewrites_without_nesting() {
        let original = doc();
        let mut d = original.clone();
        assert_eq!(wrap_toml(&mut d, "innerwarden", true), 2);
        assert_eq!(guarded_mode_toml(&d), Some(WiringMode::Monitor));
        let first = d["mcp_servers"]["icm"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            first,
            vec![
                "proxy",
                "--mode",
                "advisory",
                "--",
                "npx",
                "-y",
                "some-server"
            ]
        );

        assert_eq!(wrap_toml(&mut d, "innerwarden", false), 2);
        assert_eq!(guarded_mode_toml(&d), Some(WiringMode::Enforce));
        assert_eq!(unwrap_toml(&mut d), 2);
        assert_eq!(d.to_string(), original.to_string());
    }

    #[test]
    fn mode_switch_preserves_existing_proxy_options() {
        let mut d = r#"
[mcp_servers.x]
command = "innerwarden"
args = ["proxy", "--label", "codex-main", "--error-response", "--mode", "guard", "--", "npx", "srv"]
"#
        .parse::<DocumentMut>()
        .unwrap();
        assert_eq!(wrap_toml(&mut d, "innerwarden", true), 1);
        let args = d["mcp_servers"]["x"]["args"].as_array().unwrap();
        let values: Vec<&str> = args.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(
            values,
            vec![
                "proxy",
                "--label",
                "codex-main",
                "--error-response",
                "--mode",
                "advisory",
                "--",
                "npx",
                "srv"
            ]
        );
        assert_eq!(wrap_toml(&mut d, "innerwarden", false), 1);
        assert_eq!(guarded_mode_toml(&d), Some(WiringMode::Enforce));
    }

    #[test]
    fn partial_and_invalid_wiring_are_reported_conservatively() {
        let mut partial = doc();
        // Wrap two, then add a new local server that is not wrapped yet.
        wrap_toml(&mut partial, "innerwarden", false);
        partial["mcp_servers"]["late"] = Item::Table({
            let mut table = Table::new();
            table.insert("command", value("python"));
            table
        });
        assert!(has_guard_wiring_toml(&partial));
        assert!(!is_guarded_toml(&partial));
        assert_eq!(guarded_mode_toml(&partial), Some(WiringMode::Enforce));

        for source in [
            "[mcp_servers.x]\ncommand = \"innerwarden\"\nargs = [\"proxy\", \"--mode\", \"bogus\", \"--\", \"npx\"]\n",
            "[mcp_servers.x]\ncommand = \"innerwarden\"\nargs = [\"proxy\", \"--mode\", \"guard\", \"--\"]\n",
            "[mcp_servers.x]\ncommand = \"innerwarden\"\nargs = [\"proxy\", \"--mode\", \"guard\", \"npx\"]\n",
        ] {
            let invalid = source.parse::<DocumentMut>().unwrap();
            assert!(has_guard_wiring_toml(&invalid));
            assert!(!is_guarded_toml(&invalid));
            assert_eq!(guarded_mode_toml(&invalid), None);
        }

        let mut broken = "[mcp_servers.x]\ncommand = \"innerwarden\"\nargs = [\"proxy\", \"--mode\", \"guard\", \"npx\"]\n"
            .parse::<DocumentMut>()
            .unwrap();
        let before = broken.to_string();
        assert_eq!(wrap_toml(&mut broken, "innerwarden", true), 0);
        assert_eq!(
            broken.to_string(),
            before,
            "a broken proxy must not be nested"
        );
    }

    #[test]
    fn no_servers_is_not_guardable() {
        let d = "model = \"x\"\n".parse::<DocumentMut>().unwrap();
        assert!(!is_guardable_toml(&d));
        assert!(!is_guarded_toml(&d));
    }
}
