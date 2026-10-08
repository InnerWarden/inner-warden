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
//!
//! Every wrapper names the agent whose configuration it is in, exactly as
//! [`crate::mcp_wire::naming`] describes for the JSON clients.

use toml_edit::{value, Array, DocumentMut, Item, Table, Value};

use crate::mcp_wire::{is_guard_command, is_wrapper_name, naming, proxy_agent, wrapper_blocks};

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
        .is_some_and(is_guard_command);
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

/// The mode this server's proxy runs in, read from its own wrapper the way
/// `innerwarden proxy` reads it ([`wrapper_blocks`]); `None` for a server that
/// is not a complete wrapper.
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
    let options = wrapper_options(server)?;
    Some(if wrapper_blocks(&options)? {
        WiringMode::Enforce
    } else {
        WiringMode::Monitor
    })
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

/// An args array as its words, formatting aside. An array read from a file
/// keeps the spacing it was written with and one built here has none, so
/// comparing their text called every wrapper on disk changed: each connect
/// rewrote the file and reported a change it had not made.
fn words<'a>(values: impl Iterator<Item = &'a Value>) -> Vec<String> {
    values
        .map(|value| {
            let mut value = value.clone();
            value.decor_mut().clear();
            value.to_string()
        })
        .collect()
}

fn wrap_server(server: &mut Table, guard_bin: &str, monitor: bool, agent: Option<&str>) -> bool {
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
    let current_words = server
        .get("args")
        .and_then(Item::as_array)
        .map(|args| words(args.iter()))
        .unwrap_or_default();
    let separator = wrapper_separator(server);
    if separator.is_none() && has_proxy_prefix(server) {
        return false;
    }
    let (orig_cmd, orig_args, proxy_prefix) = if let Some(separator) = separator {
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

    // `proxy_prefix[0]` is `proxy`; the options follow it.
    let options: Vec<Option<&str>> = proxy_prefix[1..].iter().map(Value::as_str).collect();
    let naming = naming(&options, agent);
    let mut new_args = Array::new();
    for (i, arg) in proxy_prefix.iter().enumerate() {
        if i == 0 || !naming.drop.contains(&(i - 1)) {
            new_args.push_formatted(arg.clone());
        }
    }
    for word in naming.add {
        new_args.push(word);
    }
    new_args.push("--mode");
    new_args.push(if monitor { "advisory" } else { "guard" });
    new_args.push("--");
    new_args.push(orig_cmd);
    for a in orig_args {
        new_args.push_formatted(a);
    }
    if current_command == guard_bin && current_words == words(new_args.iter()) {
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
/// (`monitor=true`) or guard mode, each wrapper naming `agent`, the agent whose
/// configuration this is. Existing wrappers are reconfigured without nesting,
/// and one written before wrappers named their agent gains the name. Returns
/// how many entries changed. Idempotent, format-preserving.
pub fn wrap_toml(doc: &mut DocumentMut, guard_bin: &str, monitor: bool, agent: &str) -> usize {
    wrap_toml_naming(doc, guard_bin, monitor, Some(agent))
}

fn wrap_toml_naming(
    doc: &mut DocumentMut,
    guard_bin: &str,
    monitor: bool,
    agent: Option<&str>,
) -> usize {
    for_each_server(doc, |s| wrap_server(s, guard_bin, monitor, agent))
}

/// The TOML twin of [`crate::mcp_wire::unnamed_reconnect_flag`]: when some
/// wrapper's proxy records no agent or another one, the mode flag a reconnect
/// by hand with `guard_bin` needs so that it adds `agent`'s name and changes
/// nothing else; `None` when every proxy records `agent` already or the
/// reconnect would change more. Pure.
pub fn unnamed_reconnect_flag_toml(
    doc: &DocumentMut,
    guard_bin: &str,
    agent: &str,
) -> Option<&'static str> {
    if !is_wrapper_name(agent) || !is_guarded_toml(doc) {
        return None;
    }
    let monitor = match guarded_mode_toml(doc)? {
        WiringMode::Monitor => true,
        WiringMode::Enforce => false,
        WiringMode::Mixed => return None,
    };
    let unnamed = doc
        .get("mcp_servers")
        .and_then(Item::as_table)
        .into_iter()
        .flat_map(Table::iter)
        .filter_map(|(_, item)| item.as_table())
        .filter_map(wrapper_options)
        .any(|options| proxy_agent(&options) != Some(agent));
    let beyond_the_name = wrap_toml_naming(&mut doc.clone(), guard_bin, monitor, None);
    (unnamed && beyond_the_name == 0).then_some(if monitor { " --monitor" } else { "" })
}

/// The proxy options of a wrapper (the words between `proxy` and its `--`),
/// or `None` for a server that is not one.
fn wrapper_options(server: &Table) -> Option<Vec<Option<&str>>> {
    let separator = wrapper_separator(server)?;
    let args = server.get("args").and_then(Item::as_array)?;
    Some(
        args.iter()
            .skip(1)
            .take(separator - 1)
            .map(Value::as_str)
            .collect(),
    )
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

/// The program each InnerWarden proxy wrapper in this config runs, as
/// written, in file order (see `mcp_wire::guard_wrapper_commands`).
pub fn guard_wrapper_commands_toml(doc: &DocumentMut) -> Vec<String> {
    doc.get("mcp_servers")
        .and_then(Item::as_table)
        .map(|servers| {
            servers
                .iter()
                .filter_map(|(_, item)| item.as_table())
                .filter(|server| has_proxy_prefix(server))
                .filter_map(|server| server.get("command").and_then(Item::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
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
        let n = wrap_toml(&mut d, "innerwarden", false, "codex");
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
            vec![
                "proxy",
                "--label",
                "codex",
                "--agent",
                "codex",
                "--mode",
                "guard",
                "--",
                "npx",
                "-y",
                "some-server"
            ]
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
        assert_eq!(wrap_toml(&mut d, "innerwarden", false, "codex"), 2);
        assert_eq!(
            wrap_toml(&mut d, "innerwarden", false, "codex"),
            0,
            "second wrap is a no-op"
        );
    }

    #[test]
    fn unwrap_restores_the_original() {
        let mut d = doc();
        wrap_toml(&mut d, "innerwarden", false, "codex");
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
        let mut d =
            "[mcp_servers.x]\ncommand = \"/opt/iw-guard\"\nargs = [\"proxy\", \"--\", \"npx\"]\n"
                .parse::<DocumentMut>()
                .unwrap();
        assert!(is_guarded_toml(&d));
        assert_eq!(guarded_mode_toml(&d), Some(WiringMode::Enforce));
        assert_eq!(wrap_toml(&mut d, "innerwarden", false, "codex"), 1);
        assert_eq!(wrap_toml(&mut d, "innerwarden", false, "codex"), 0);
    }

    /// A command that only begins with the guard's name is not the guard
    /// (see `mcp_wire::is_guard_command`): a shim written as
    /// `innerwarden-shim` is a server like any other, and connecting the
    /// agent wraps it in the real proxy.
    #[test]
    fn a_command_that_only_begins_with_the_guards_name_is_not_the_guard() {
        let mut d = "[mcp_servers.x]\ncommand = \"/home/u/.local/bin/innerwarden-shim\"\nargs = [\"proxy\", \"--mode\", \"guard\", \"--\", \"npx\"]\n"
            .parse::<DocumentMut>()
            .unwrap();
        assert!(!is_guarded_toml(&d));
        assert_eq!(guarded_mode_toml(&d), None);
        assert_eq!(wrap_toml(&mut d, "/abs/innerwarden", false, "codex"), 1);
        assert_eq!(guarded_mode_toml(&d), Some(WiringMode::Enforce));
    }

    #[test]
    fn switching_monitor_and_enforce_rewrites_without_nesting() {
        let original = doc();
        let mut d = original.clone();
        assert_eq!(wrap_toml(&mut d, "innerwarden", true, "codex"), 2);
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
                "--label",
                "codex",
                "--agent",
                "codex",
                "--mode",
                "advisory",
                "--",
                "npx",
                "-y",
                "some-server"
            ]
        );

        assert_eq!(wrap_toml(&mut d, "innerwarden", false, "codex"), 2);
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
        assert_eq!(wrap_toml(&mut d, "innerwarden", true, "codex"), 1);
        let args = d["mcp_servers"]["x"]["args"].as_array().unwrap();
        let values: Vec<&str> = args.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(
            values,
            vec![
                "proxy",
                "--label",
                "codex-main",
                "--error-response",
                "--agent",
                "codex",
                "--mode",
                "advisory",
                "--",
                "npx",
                "srv"
            ]
        );
        assert_eq!(wrap_toml(&mut d, "innerwarden", false, "codex"), 1);
        assert_eq!(guarded_mode_toml(&d), Some(WiringMode::Enforce));
    }

    #[test]
    fn partial_and_invalid_wiring_are_reported_conservatively() {
        let mut partial = doc();
        // Wrap two, then add a new local server that is not wrapped yet.
        wrap_toml(&mut partial, "innerwarden", false, "codex");
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
        assert_eq!(wrap_toml(&mut broken, "innerwarden", true, "codex"), 0);
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

#[cfg(test)]
mod agent_naming_tests {
    use super::*;

    const BIN: &str = "/home/u/.local/bin/innerwarden";

    fn parse(source: &str) -> DocumentMut {
        source.parse::<DocumentMut>().unwrap()
    }

    fn args_of(doc: &DocumentMut, name: &str) -> Vec<String> {
        doc["mcp_servers"][name]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap().to_string())
            .collect()
    }

    fn wrapper(command: &str, args: &str) -> DocumentMut {
        parse(&format!(
            "# the user's own note\nmodel = \"gpt-5\"\n\n[mcp_servers.icm]\ncommand = \"{command}\"\nargs = {args}\n[mcp_servers.icm.env]\nFOO = \"bar\"\n"
        ))
    }

    /// REGRESSION ANCHOR, the Codex twin of
    /// `mcp_wire::agent_naming_tests::wrap_names_the_agent_on_the_proxy`.
    ///
    /// FAILS ON REVERT: drop the naming from `wrap_server` and the args read
    /// `proxy --mode advisory -- npx ...`.
    #[test]
    fn wrap_names_the_agent_on_the_proxy() {
        let mut d = wrapper("npx", "[\"-y\", \"some-server\"]");
        assert_eq!(wrap_toml(&mut d, BIN, true, "codex"), 1);
        assert_eq!(
            args_of(&d, "icm"),
            [
                "proxy",
                "--label",
                "codex",
                "--agent",
                "codex",
                "--mode",
                "advisory",
                "--",
                "npx",
                "-y",
                "some-server"
            ]
        );
        assert_eq!(guarded_mode_toml(&d), Some(WiringMode::Monitor));
        assert!(d.to_string().contains("# the user's own note"));
    }

    /// An operator's label is kept in either spelling; only the agent is
    /// added beside it.
    #[test]
    fn an_operator_label_is_kept() {
        for (options, expected) in [
            (
                "\"--label\", \"prod\"",
                vec![
                    "proxy", "--label", "prod", "--agent", "codex", "--mode", "guard", "--", "icm",
                ],
            ),
            (
                "\"--label=prod\"",
                vec![
                    "proxy",
                    "--label=prod",
                    "--agent",
                    "codex",
                    "--mode",
                    "guard",
                    "--",
                    "icm",
                ],
            ),
        ] {
            let mut d = wrapper(
                BIN,
                &format!("[\"proxy\", {options}, \"--mode\", \"guard\", \"--\", \"icm\"]"),
            );
            assert_eq!(wrap_toml(&mut d, BIN, false, "codex"), 1, "{options}");
            assert_eq!(args_of(&d, "icm"), expected, "{options}");
        }
    }

    /// A wrapper an earlier release wrote gains the name and nothing else: the
    /// mode, its other options, the server's own command line, the comment and
    /// every other key stay as they were, and unwrapping still gives back the
    /// server exactly as the user had it.
    #[test]
    fn a_wrapper_written_before_wrappers_named_their_agent_gains_the_name_and_nothing_else() {
        let original = wrapper("npx", "[\"-y\", \"some-server\", \"--root\", \"/srv/a b\"]");
        let mut before = original.clone();
        // What 1.5.1 wrote: no label, no agent.
        assert_eq!(wrap_toml_naming(&mut before, BIN, true, None), 1);
        assert_eq!(
            args_of(&before, "icm"),
            [
                "proxy",
                "--mode",
                "advisory",
                "--",
                "npx",
                "-y",
                "some-server",
                "--root",
                "/srv/a b"
            ]
        );

        let mut after = before.clone();
        assert_eq!(wrap_toml(&mut after, BIN, true, "codex"), 1);
        assert_eq!(
            args_of(&after, "icm"),
            [
                "proxy",
                "--label",
                "codex",
                "--agent",
                "codex",
                "--mode",
                "advisory",
                "--",
                "npx",
                "-y",
                "some-server",
                "--root",
                "/srv/a b"
            ]
        );
        assert_eq!(after["mcp_servers"]["icm"]["command"].as_str(), Some(BIN));
        assert_eq!(guarded_mode_toml(&after), guarded_mode_toml(&before));
        assert_eq!(
            after["mcp_servers"]["icm"]["env"].to_string(),
            before["mcp_servers"]["icm"]["env"].to_string()
        );
        assert_eq!(wrap_toml(&mut after.clone(), BIN, true, "codex"), 0);
        assert_eq!(unwrap_toml(&mut after), 1);
        assert_eq!(after.to_string(), original.to_string());
    }

    #[test]
    fn server_mode_reads_through_label_and_agent() {
        for (args, mode) in [
            (
                "[\"proxy\", \"--label\", \"codex\", \"--agent\", \"codex\", \"--mode\", \"advisory\", \"--\", \"icm\"]",
                WiringMode::Monitor,
            ),
            (
                "[\"proxy\", \"--agent=codex\", \"--label=x\", \"--mode=guard\", \"--\", \"icm\"]",
                WiringMode::Enforce,
            ),
            (
                "[\"proxy\", \"--label\", \"codex\", \"--agent\", \"codex\", \"--\", \"icm\"]",
                WiringMode::Enforce,
            ),
        ] {
            let d = wrapper(BIN, args);
            assert!(is_guarded_toml(&d), "{args}");
            assert_eq!(guarded_mode_toml(&d), Some(mode), "{args}");
        }
    }

    /// The TOML twin of the JSON reader's
    /// [`crate::mcp_wire`] `a_flag_value_is_never_read_as_the_mode` and
    /// `a_flag_that_takes_the_separator_leaves_no_mode_to_report`: a Codex
    /// wrapper's mode is read the way `innerwarden proxy` reads it.
    ///
    /// FAILS ON REVERT: step over every option one word at a time in this
    /// module's `server_mode` again; the first case reads `Some(Enforce)` and
    /// the last reads guarded.
    #[test]
    fn the_mode_is_read_the_way_the_proxy_reads_its_options() {
        for (args, mode) in [
            (
                "[\"proxy\", \"--mode\", \"advisory\", \"--label\", \"--mode=guard\", \"--\", \"icm\"]",
                Some(WiringMode::Monitor),
            ),
            (
                "[\"proxy\", \"--label\", \"--mode\", \"--\", \"icm\"]",
                Some(WiringMode::Enforce),
            ),
            (
                "[\"proxy\", \"--mode\", \"guard\", \"--label\", \"--\", \"--mode\", \"advisory\", \"--\", \"icm\"]",
                None,
            ),
        ] {
            let d = wrapper(BIN, args);
            assert_eq!(is_guarded_toml(&d), mode.is_some(), "{args}");
            assert_eq!(guarded_mode_toml(&d), mode, "{args}");
        }
    }

    #[test]
    fn a_name_that_is_not_a_plain_id_is_never_written() {
        for agent in ["", "Codex", "my.app", "x; rm -rf /", "--mode"] {
            let mut d = wrapper("npx", "[\"srv\"]");
            wrap_toml(&mut d, BIN, false, agent);
            assert_eq!(
                args_of(&d, "icm"),
                ["proxy", "--mode", "guard", "--", "npx", "srv"],
                "{agent:?}"
            );
        }
    }

    #[test]
    fn an_unnamed_wiring_is_offered_the_reconnect_that_names_it_in_its_own_mode() {
        let mut monitor = wrapper("npx", "[\"srv\"]");
        wrap_toml_naming(&mut monitor, BIN, true, None);
        assert_eq!(
            unnamed_reconnect_flag_toml(&monitor, BIN, "codex"),
            Some(" --monitor")
        );
        let mut enforce = wrapper("npx", "[\"srv\"]");
        wrap_toml_naming(&mut enforce, BIN, false, None);
        assert_eq!(
            unnamed_reconnect_flag_toml(&enforce, BIN, "codex"),
            Some("")
        );
        let borrowed = wrapper(
            BIN,
            "[\"proxy\", \"--label\", \"cursor\", \"--agent\", \"cursor\", \"--mode\", \"guard\", \"--\", \"icm\"]",
        );
        assert_eq!(
            unnamed_reconnect_flag_toml(&borrowed, BIN, "codex"),
            Some("")
        );

        for (mut d, monitor) in [(monitor, true), (enforce, false), (borrowed, false)] {
            let mode = guarded_mode_toml(&d);
            assert_eq!(wrap_toml(&mut d, BIN, monitor, "codex"), 1);
            assert_eq!(unnamed_reconnect_flag_toml(&d, BIN, "codex"), None);
            assert_eq!(guarded_mode_toml(&d), mode);
        }
    }

    #[test]
    fn no_reconnect_is_offered_where_it_would_change_more_than_the_name() {
        for args in [
            // Named already, or its proxy records the agent already.
            "[\"proxy\", \"--label\", \"codex\", \"--agent\", \"codex\", \"--mode\", \"guard\", \"--\", \"icm\"]",
            "[\"proxy\", \"--agent\", \"codex\", \"--mode\", \"guard\", \"--\", \"icm\"]",
            "[\"proxy\", \"--label\", \"prod\", \"--agent=codex\", \"--mode\", \"guard\", \"--\", \"icm\"]",
            // The oldest layout: a reconnect would write a `--mode`.
            "[\"proxy\", \"--\", \"icm\"]",
        ] {
            let d = wrapper(BIN, args);
            assert_eq!(unnamed_reconnect_flag_toml(&d, BIN, "codex"), None, "{args}");
        }
        // Another copy of the CLI: the reconnect would move the wrapper to this one.
        let elsewhere = wrapper(
            "/opt/pinned/innerwarden",
            "[\"proxy\", \"--mode\", \"guard\", \"--\", \"icm\"]",
        );
        assert_eq!(unnamed_reconnect_flag_toml(&elsewhere, BIN, "codex"), None);
        // Two modes, or a server still open.
        let mixed = parse(&format!(
            "[mcp_servers.a]\ncommand = \"{BIN}\"\nargs = [\"proxy\", \"--mode\", \"advisory\", \"--\", \"a\"]\n\n[mcp_servers.b]\ncommand = \"{BIN}\"\nargs = [\"proxy\", \"--mode\", \"guard\", \"--\", \"b\"]\n"
        ));
        assert_eq!(guarded_mode_toml(&mixed), Some(WiringMode::Mixed));
        assert_eq!(unnamed_reconnect_flag_toml(&mixed, BIN, "codex"), None);
        let partial = parse(&format!(
            "[mcp_servers.a]\ncommand = \"{BIN}\"\nargs = [\"proxy\", \"--mode\", \"guard\", \"--\", \"a\"]\n\n[mcp_servers.b]\ncommand = \"b\"\n"
        ));
        assert_eq!(unnamed_reconnect_flag_toml(&partial, BIN, "codex"), None);
        // No plain id, no name to add.
        let mut unnamed = wrapper("npx", "[\"srv\"]");
        wrap_toml_naming(&mut unnamed, BIN, false, None);
        assert_eq!(unnamed_reconnect_flag_toml(&unnamed, BIN, "my.app"), None);
    }
}
