//! Guard **Codex**, whose MCP servers live in `~/.codex/config.toml` under
//! `[mcp_servers.NAME]` (TOML, `command`/`args`/`env`) rather than a JSON
//! `mcp.json`. Same idea as `mcp_wire`: rewrite each stdio server so it launches
//! THROUGH `innerwarden proxy` instead of directly, so Codex's MCP tool calls are
//! screened by the same engine as `check`. Monitor mode records findings;
//! enforcement may block dangerous calls. Reversible (`unwrap_toml`) and
//! idempotent (`wrap_toml` twice = wrapped once).
//!
//! A server reached by URL (`url`, its token named by
//! `bearer_token_env_var`, headers in `http_headers` and
//! `env_http_headers`) goes through the same proxy, which talks HTTP(S) to
//! it ([`crate::mcp_proxy::remote`]): its table becomes a wrapper whose
//! server is the address. Codex refuses those keys on a local server, so
//! each gives way where it was: `url` to `command`/`args`, the variables
//! to `env_vars` (Codex then hands them to the proxy; the token is never
//! written anywhere), `http_headers` to `env`. The words after the address
//! (`--bearer-env`, `--header-env`, `--headers`, `--env-headers`) say
//! what the table had, so disconnect writes it back where it was. A table
//! the proxy cannot carry is left alone and counted remote: a token written
//! in the file, a sign-in Codex does itself, a header helper program, a
//! server Codex runs elsewhere.
//!
//! Edits are FORMAT-PRESERVING (`toml_edit`): the user's comments, key order, and
//! unrelated config in `config.toml` are left untouched, only `command`/`args`
//! of each MCP server change. All logic here is pure/tested (operates on a parsed
//! `DocumentMut`; the file read/write is the I/O layer's job).
//!
//! Every wrapper names the agent whose configuration it is in, exactly as
//! [`crate::mcp_wire::naming`] describes for the JSON clients.

use toml_edit::{value, Array, DocumentMut, Item, Table, Value};

use crate::mcp_proxy::remote::{
    is_env_name, is_header_name, is_remote_url, HEADER_ENV_PREFIX, MAX_HEADERS,
};
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

/// Every server under `mcp_servers` with its table, in file order. A server
/// written as an inline table (`[mcp_servers]` then `linear = { url = ... }`,
/// or `mcp_servers = { linear = { ... } }` whole) is read as the table it
/// stands for, as Codex reads it. Copies, for reading only.
fn server_tables(doc: &DocumentMut) -> Vec<(String, Table)> {
    let Some(servers) = doc.get("mcp_servers").and_then(Item::as_table_like) else {
        return Vec::new();
    };
    servers
        .iter()
        .filter_map(|(name, item)| Some((name.to_string(), as_server_table(item)?)))
        .collect()
}

/// A server's entry as a table: a table, or an inline one read as a table.
fn as_server_table(item: &Item) -> Option<Table> {
    match item {
        Item::Table(table) => Some(table.clone()),
        Item::Value(Value::InlineTable(inline)) => Some(inline.clone().into_table()),
        _ => None,
    }
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
        let Some(remote) = remote_entry(server) else {
            return false;
        };
        let mut local = server.clone();
        remote_as_local(&mut local, &remote);
        let command = decors(&local, "command");
        if !wrap_server(&mut local, guard_bin, monitor, agent) {
            return false;
        }
        set_decors(&mut local, "command", command);
        *server = local;
        return true;
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
    // A comment after the command stays where it was.
    let command = decors(server, "command");
    server.insert("command", value(guard_bin));
    set_decors(server, "command", command);
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
    // A remote server goes back to the address and keys it had.
    if is_remote_url(&orig_cmd) {
        let command = decors(server, "command");
        let mut restored = server.clone();
        set_decors(&mut restored, "command", command);
        if restore_remote(&mut restored, &orig_cmd, &args[separator + 2..]) {
            *server = restored;
            return true;
        }
    }
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

/// A Codex server reached by URL that the proxy can carry, as its table
/// says it (see [`remote_entry`]).
struct RemoteEntry {
    url: String,
    /// The table's remote keys, in the order it has them.
    keys: Vec<RemoteKey>,
}

enum RemoteKey {
    /// `bearer_token_env_var`: the variable Codex reads the token from.
    Bearer(String),
    /// `http_headers`: headers written in the file.
    Headers(Vec<(String, String)>),
    /// `env_http_headers`: each header's name and the variable its value
    /// is read from.
    EnvHeaders(Vec<(String, String)>),
}

/// Keys that say the server is reached some other way than the proxy can
/// carry: a token written in the file (`bearer_token`, which Codex refuses
/// anyway), a sign-in Codex does itself (`oauth`, `oauth_resource`,
/// `scopes`, `auth`), a program that makes the headers
/// (`http_headers_helper`), a server Codex runs elsewhere
/// (`environment_id`), or the keys of a local server.
const NOT_CARRIED_KEYS: &[&str] = &[
    "bearer_token",
    "oauth",
    "oauth_resource",
    "scopes",
    "auth",
    "http_headers_helper",
    "environment_id",
    "command",
    "args",
    "env",
    "env_vars",
    "cwd",
];

/// The text pairs of a header table, inline or not; `None` when one is not
/// text.
fn text_pairs(item: &Item) -> Option<Vec<(String, String)>> {
    match item {
        Item::Table(table) => table
            .iter()
            .map(|(key, value)| Some((key.to_string(), value.as_str()?.to_string())))
            .collect(),
        Item::Value(Value::InlineTable(table)) => table
            .iter()
            .map(|(key, value)| Some((key.to_string(), value.as_str()?.to_string())))
            .collect(),
        _ => None,
    }
}

/// The remote server a Codex table names, when the proxy can carry it:
/// an http(s) `url`, its token named by `bearer_token_env_var`, headers
/// in `http_headers` and `env_http_headers` (inline), and nothing of
/// [`NOT_CARRIED_KEYS`]. `None` for every other table, which is left as
/// it is and counted remote.
fn remote_entry(server: &Table) -> Option<RemoteEntry> {
    if NOT_CARRIED_KEYS.iter().any(|key| server.contains_key(key)) {
        return None;
    }
    let url = server.get("url")?.as_str()?;
    if !is_remote_url(url) {
        return None;
    }
    let mut keys = Vec::new();
    for (key, item) in server.iter() {
        match key {
            "bearer_token_env_var" => {
                let var = item.as_str()?;
                if !is_env_name(var) {
                    return None;
                }
                keys.push(RemoteKey::Bearer(var.to_string()));
            }
            "http_headers" => {
                let pairs = text_pairs(item)?;
                if pairs.iter().any(|(name, value)| {
                    !is_header_name(name) || value.contains(['\r', '\n', '\0'])
                }) {
                    return None;
                }
                keys.push(RemoteKey::Headers(pairs));
            }
            "env_http_headers" => {
                if !matches!(item, Item::Value(Value::InlineTable(_))) {
                    return None;
                }
                let pairs = text_pairs(item)?;
                if pairs
                    .iter()
                    .any(|(name, var)| !is_header_name(name) || !is_env_name(var))
                {
                    return None;
                }
                keys.push(RemoteKey::EnvHeaders(pairs));
            }
            _ => {}
        }
    }
    // The proxy sends at most MAX_HEADERS headers: a table with more is left
    // as it was, never carried with some of its headers dropped.
    if header_count(&keys) > MAX_HEADERS {
        return None;
    }
    Some(RemoteEntry {
        url: url.to_string(),
        keys,
    })
}

/// How many headers the keys of a remote table send: the token is one.
fn header_count(keys: &[RemoteKey]) -> usize {
    keys.iter()
        .map(|key| match key {
            RemoteKey::Bearer(_) => 1,
            RemoteKey::Headers(pairs) | RemoteKey::EnvHeaders(pairs) => pairs.len(),
        })
        .sum()
}

/// Why the proxy does not carry a server reached by URL, in a word a person
/// finds in the table: the first key of [`NOT_CARRIED_KEYS`] it holds, or
/// what else [`remote_entry`] refused. Names and keys only, never a value.
fn not_carried_because(server: &Table) -> String {
    if let Some(key) = NOT_CARRIED_KEYS.iter().find(|key| server.contains_key(key)) {
        return (*key).to_string();
    }
    match server.get("url").and_then(Item::as_str) {
        Some(url) if !is_remote_url(url) => return "url".to_string(),
        None => return "url".to_string(),
        _ => {}
    }
    let count: usize = ["http_headers", "env_http_headers"]
        .iter()
        .filter_map(|key| server.get(key).and_then(text_pairs))
        .map(|pairs| pairs.len())
        .sum::<usize>()
        + usize::from(server.contains_key("bearer_token_env_var"));
    if count > MAX_HEADERS {
        return format!("more than {MAX_HEADERS} headers");
    }
    for key in ["bearer_token_env_var", "http_headers", "env_http_headers"] {
        if server.contains_key(key) {
            return key.to_string();
        }
    }
    "url".to_string()
}

/// The servers of a Codex config reached by URL that the proxy does not
/// carry, each as `name (key)`: the key that keeps it out
/// ([`not_carried_because`]). For the line `agents connect` prints, as Goose's
/// names its own. Pure.
pub fn unscreened_remote_toml(doc: &DocumentMut) -> Vec<String> {
    server_tables(doc)
        .into_iter()
        .filter(|(_, table)| table.contains_key("url") && !is_proxyable_server(table))
        .map(|(name, table)| format!("{name} ({})", not_carried_because(&table)))
        .collect()
}

/// Every server of a Codex config as the hook reads it
/// ([`crate::mcp_unproxied`]): its name, whether the proxy stands in front
/// of it (a wrapper), and whether it is reached by URL. An inline table
/// counts as the table it stands for. Names only, never a value. Pure.
pub fn server_entries_toml(doc: &DocumentMut) -> Vec<crate::mcp_unproxied::ServerEntry> {
    server_tables(doc)
        .into_iter()
        .map(|(name, table)| crate::mcp_unproxied::ServerEntry {
            behind_proxy: is_wrapped_server(&table),
            remote: !is_stdio_server(&table) && table.contains_key("url"),
            name,
        })
        .collect()
}

/// A table that runs a local command, or a remote server the proxy carries.
fn is_proxyable_server(server: &Table) -> bool {
    is_stdio_server(server) || remote_entry(server).is_some()
}

/// The decor of a key and of its value, so a key that takes another's place
/// keeps its comments and spacing.
fn decors(server: &Table, key: &str) -> (Option<toml_edit::Decor>, Option<toml_edit::Decor>) {
    (
        server.key(key).map(|key| key.leaf_decor().clone()),
        server
            .get(key)
            .and_then(Item::as_value)
            .map(|value| value.decor().clone()),
    )
}

fn set_decors(
    server: &mut Table,
    key: &str,
    decor: (Option<toml_edit::Decor>, Option<toml_edit::Decor>),
) {
    if let (Some(decor), Some(mut key)) = (decor.0, server.key_mut(key)) {
        *key.leaf_decor_mut() = decor;
    }
    if let (Some(decor), Some(value)) = (decor.1, server.get_mut(key).and_then(Item::as_value_mut))
    {
        *value.decor_mut() = decor;
    }
}

/// An item of the kind `like` is (a table of its own, or inline), holding
/// `pairs`.
fn table_like(like: &Item, pairs: &[(String, String)]) -> Item {
    match like {
        Item::Table(original) => {
            let mut table = Table::new();
            table.set_position(original.position());
            *table.decor_mut() = original.decor().clone();
            for (name, value) in pairs {
                table.insert(name, toml_edit::value(value.as_str()));
            }
            Item::Table(table)
        }
        _ => {
            let mut table = toml_edit::InlineTable::new();
            for (name, value) in pairs {
                table.insert(name, Value::from(value.as_str()));
            }
            let mut value = Value::InlineTable(table);
            if let Some(original) = like.as_value() {
                *value.decor_mut() = original.decor().clone();
            }
            Item::Value(value)
        }
    }
}

/// A remote table rewritten as a local one whose command is its address,
/// the shape [`wrap_server`] then wraps like any other. Each remote key
/// gives way where it was: `url` to `command` and `args` (the words
/// that say what the table had, in its order), `bearer_token_env_var` and
/// `env_http_headers` to `env_vars` (the variables Codex then hands the
/// proxy, the token never written), `http_headers` to `env` (each
/// header as `INNERWARDEN_MCP_HEADER_<n>`, read by the proxy as a JSON
/// client's are).
fn remote_as_local(server: &mut Table, remote: &RemoteEntry) {
    let mut words = Array::new();
    let mut vars: Vec<String> = Vec::new();
    let mut headers: Vec<(String, String)> = Vec::new();
    for key in &remote.keys {
        match key {
            RemoteKey::Bearer(var) => {
                words.push("--bearer-env");
                words.push(var.as_str());
                vars.push(var.clone());
            }
            RemoteKey::Headers(pairs) => {
                words.push("--headers");
                for (n, (name, value)) in pairs.iter().enumerate() {
                    headers.push((
                        format!("{HEADER_ENV_PREFIX}{}", n + 1),
                        format!("{name}: {value}"),
                    ));
                }
            }
            RemoteKey::EnvHeaders(pairs) => {
                words.push("--env-headers");
                for (name, var) in pairs {
                    words.push("--header-env");
                    words.push(name.as_str());
                    words.push(var.as_str());
                    vars.push(var.clone());
                }
            }
        }
    }
    let mut unique = Vec::new();
    for var in vars {
        if !unique.contains(&var) {
            unique.push(var);
        }
    }
    let entries: Vec<(toml_edit::Key, Item)> = server
        .iter()
        .filter_map(|(key, item)| Some((server.key(key)?.clone(), item.clone())))
        .collect();
    server.clear();
    let mut vars_placed = false;
    for (key, item) in entries {
        match key.get() {
            "url" => {
                let mut command = Value::from(remote.url.as_str());
                if let Some(value) = item.as_value() {
                    *command.decor_mut() = value.decor().clone();
                }
                server.insert_formatted(
                    &toml_edit::Key::new("command").with_leaf_decor(key.leaf_decor().clone()),
                    Item::Value(command),
                );
                server.insert("args", value(words.clone()));
            }
            "bearer_token_env_var" | "env_http_headers" => {
                // Placed even when it names no variable (`env_http_headers
                // = {}`): disconnect reads `--env-headers` as a key that
                // stands where `env_vars` is.
                if vars_placed {
                    continue;
                }
                vars_placed = true;
                let mut list = Value::Array(unique.iter().map(String::as_str).collect());
                if let Some(value) = item.as_value() {
                    *list.decor_mut() = value.decor().clone();
                }
                server.insert_formatted(
                    &toml_edit::Key::new("env_vars").with_leaf_decor(key.leaf_decor().clone()),
                    Item::Value(list),
                );
            }
            "http_headers" => {
                server.insert_formatted(
                    &toml_edit::Key::new("env").with_leaf_decor(key.leaf_decor().clone()),
                    table_like(&item, &headers),
                );
            }
            _ => {
                server.insert_formatted(&key, item);
            }
        }
    }
}

/// Write a wrapped remote table back as it was: `url` where `command` is,
/// `bearer_token_env_var` and `env_http_headers` where `env_vars` is, in
/// the order the words name them, and `http_headers` where `env` is.
/// `false`, touching nothing, when the words after the address are not the
/// ones [`remote_as_local`] writes.
fn restore_remote(server: &mut Table, url: &str, words: &[Value]) -> bool {
    let mut keys: Vec<RemoteKey> = Vec::new();
    let mut it = words.iter().map(Value::as_str);
    while let Some(word) = it.next() {
        match word {
            Some("--bearer-env") => match it.next().flatten() {
                Some(var) if is_env_name(var) => keys.push(RemoteKey::Bearer(var.to_string())),
                _ => return false,
            },
            Some("--headers") => keys.push(RemoteKey::Headers(Vec::new())),
            Some("--env-headers") => keys.push(RemoteKey::EnvHeaders(Vec::new())),
            Some("--header-env") => {
                match (it.next().flatten(), it.next().flatten(), keys.last_mut()) {
                    (Some(name), Some(var), Some(RemoteKey::EnvHeaders(pairs))) => {
                        pairs.push((name.to_string(), var.to_string()))
                    }
                    _ => return false,
                }
            }
            _ => return false,
        }
    }
    let has_headers = keys.iter().any(|key| matches!(key, RemoteKey::Headers(_)));
    let has_vars = keys.iter().any(|key| !matches!(key, RemoteKey::Headers(_)));
    // What connect wrote, and only that: `env` of headers alone, `env_vars`
    // of the variables the words name.
    let env_ok = match server.get("env") {
        None => !has_headers,
        Some(item) => {
            has_headers
                && text_pairs(item).is_some_and(|pairs| {
                    pairs
                        .iter()
                        .all(|(name, _)| name.starts_with(HEADER_ENV_PREFIX))
                })
        }
    };
    if !env_ok || server.contains_key("env_vars") != has_vars {
        return false;
    }
    let mut headers = Vec::new();
    if let Some(pairs) = server.get("env").and_then(text_pairs) {
        let mut n = 1;
        while let Some((_, line)) = pairs
            .iter()
            .find(|(name, _)| *name == format!("{HEADER_ENV_PREFIX}{n}"))
        {
            let Some((name, value)) = line.split_once(':') else {
                return false;
            };
            headers.push((
                name.to_string(),
                value.strip_prefix(' ').unwrap_or(value).to_string(),
            ));
            n += 1;
        }
    }
    // Where `env_vars` stands, the variable keys that came before the
    // headers are written; those after the headers follow `http_headers`
    // where `env` stands, so the keys come back in their order.
    let headers_at = keys
        .iter()
        .position(|key| matches!(key, RemoteKey::Headers(_)));
    let first_var = keys
        .iter()
        .position(|key| !matches!(key, RemoteKey::Headers(_)));
    let vars_before_headers = match (headers_at, first_var) {
        (Some(h), Some(f)) if f < h => h,
        _ => keys.len(),
    };
    let entries: Vec<(toml_edit::Key, Item)> = server
        .iter()
        .filter_map(|(key, item)| Some((server.key(key)?.clone(), item.clone())))
        .collect();
    server.clear();
    for (key, item) in entries {
        let value_decor = item.as_value().map(|value| value.decor().clone());
        let with_decor = |mut value: Value, first: bool| {
            if let (true, Some(decor)) = (first, &value_decor) {
                *value.decor_mut() = decor.clone();
            }
            value
        };
        match key.get() {
            "command" => {
                server.insert_formatted(
                    &toml_edit::Key::new("url").with_leaf_decor(key.leaf_decor().clone()),
                    Item::Value(with_decor(Value::from(url), true)),
                );
            }
            "args" => {}
            "env_vars" => {
                let mut first = true;
                for remote in keys.iter().take(vars_before_headers) {
                    let (name, value) = match remote {
                        RemoteKey::Bearer(var) => {
                            ("bearer_token_env_var", Value::from(var.as_str()))
                        }
                        RemoteKey::EnvHeaders(pairs) => {
                            let mut table = toml_edit::InlineTable::new();
                            for (header, var) in pairs {
                                table.insert(header, Value::from(var.as_str()));
                            }
                            ("env_http_headers", Value::InlineTable(table))
                        }
                        RemoteKey::Headers(_) => continue,
                    };
                    let key = if first {
                        toml_edit::Key::new(name).with_leaf_decor(key.leaf_decor().clone())
                    } else {
                        toml_edit::Key::new(name)
                    };
                    server.insert_formatted(&key, Item::Value(with_decor(value, first)));
                    first = false;
                }
            }
            "env" => {
                server.insert_formatted(
                    &toml_edit::Key::new("http_headers").with_leaf_decor(key.leaf_decor().clone()),
                    table_like(&item, &headers),
                );
                // The variable keys that came after the headers in the table
                // follow them again.
                for remote in keys.iter().skip(vars_before_headers) {
                    let (name, value) = match remote {
                        RemoteKey::Bearer(var) => {
                            ("bearer_token_env_var", Value::from(var.as_str()))
                        }
                        RemoteKey::EnvHeaders(pairs) => {
                            let mut table = toml_edit::InlineTable::new();
                            for (header, var) in pairs {
                                table.insert(header, Value::from(var.as_str()));
                            }
                            ("env_http_headers", Value::InlineTable(table))
                        }
                        RemoteKey::Headers(_) => continue,
                    };
                    server.insert_formatted(&toml_edit::Key::new(name), Item::Value(value));
                }
            }
            _ => {
                server.insert_formatted(&key, item);
            }
        }
    }
    true
}

fn for_each_server(doc: &mut DocumentMut, mut f: impl FnMut(&mut Table) -> bool) -> usize {
    let mut n = 0;
    match doc.get_mut("mcp_servers") {
        Some(Item::Table(servers)) => {
            for (_name, item) in servers.iter_mut() {
                match item {
                    Item::Table(t) => n += usize::from(f(t)),
                    Item::Value(value) => n += usize::from(change_inline(value, &mut f)),
                    _ => {}
                }
            }
        }
        Some(Item::Value(Value::InlineTable(servers))) => {
            for (_name, value) in servers.iter_mut() {
                n += usize::from(change_inline(value, &mut f));
            }
        }
        _ => {}
    }
    n
}

/// Apply `f` to a server written as an inline table, read as the table it
/// stands for, and write it back inline (its spacing kept) when `f`
/// changed it. Anything else is left alone.
fn change_inline(value: &mut Value, f: &mut impl FnMut(&mut Table) -> bool) -> bool {
    let Value::InlineTable(inline) = value else {
        return false;
    };
    let mut table = inline.clone().into_table();
    if !f(&mut table) {
        return false;
    }
    let mut changed = table.into_inline_table();
    *changed.decor_mut() = inline.decor().clone();
    *inline = changed;
    true
}

/// The TOML twin of [`crate::mcp_wire::server_counts`]: the servers under
/// `[mcp_servers]`, counted by how the proxy can reach them. A server
/// reached by URL that the proxy carries ([`remote_entry`]) counts with the
/// local ones; every other server with no local command is remote, whatever
/// names its address: the proxy never sees its calls. Pure.
pub fn server_counts_toml(doc: &DocumentMut) -> crate::mcp_wire::ServerCounts {
    let (stdio, wrapped) = counts(doc);
    let remote = server_tables(doc)
        .iter()
        .filter(|(_, t)| !is_proxyable_server(t))
        .count();
    crate::mcp_wire::ServerCounts {
        stdio,
        wrapped,
        remote,
    }
}

fn counts(doc: &DocumentMut) -> (usize, usize) {
    let mut stdio = 0;
    let mut wrapped = 0;
    for (_name, t) in server_tables(doc) {
        if is_proxyable_server(&t) {
            stdio += 1;
            if is_wrapped_server(&t) {
                wrapped += 1;
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
    let unnamed = server_tables(doc)
        .iter()
        .filter_map(|(_, table)| wrapper_options(table))
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

/// [`wrap_toml`] for automatic setup: only the servers that run a local
/// command. A server reached by URL goes through the proxy only on a connect
/// a person runs (as [`crate::mcp_wire::wrap_local`] says for the JSON
/// clients): one Codex signs in to with `codex mcp login` names no key
/// that says so, and through the proxy it would stop working.
pub fn wrap_toml_local(
    doc: &mut DocumentMut,
    guard_bin: &str,
    monitor: bool,
    agent: &str,
) -> usize {
    for_each_server(doc, |s| {
        is_stdio_server(s) && wrap_server(s, guard_bin, monitor, Some(agent))
    })
}

/// Whether every server that runs a local command goes through the proxy,
/// and there is one: what [`wrap_toml_local`] guarantees.
pub fn local_servers_guarded_toml(doc: &DocumentMut) -> bool {
    let servers = server_tables(doc);
    let local: Vec<&Table> = servers
        .iter()
        .map(|(_, t)| t)
        .filter(|t| is_stdio_server(t))
        .collect();
    !local.is_empty() && local.iter().all(|t| is_wrapped_server(t))
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
    server_tables(doc)
        .iter()
        .any(|(_, table)| has_proxy_prefix(table))
}

/// The program each InnerWarden proxy wrapper in this config runs, as
/// written, in file order (see `mcp_wire::guard_wrapper_commands`).
pub fn guard_wrapper_commands_toml(doc: &DocumentMut) -> Vec<String> {
    server_tables(doc)
        .iter()
        .filter(|(_, server)| has_proxy_prefix(server))
        .filter_map(|(_, server)| server.get("command").and_then(Item::as_str))
        .map(str::to_string)
        .collect()
}

/// Effective mode across every guarded stdio server. `None` means there is no
/// fully guarded local server; differing modes are reported as `Mixed`.
pub fn guarded_mode_toml(doc: &DocumentMut) -> Option<WiringMode> {
    let mut found: Option<WiringMode> = None;
    for (_name, server) in server_tables(doc) {
        if wrapper_separator(&server).is_none() {
            continue;
        }
        let mode = server_mode(&server)?;
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
    // Automatic setup wraps only local servers ([`wrap_toml_local`]).
    servers
        .iter()
        .filter_map(|(_, item)| item.as_table())
        .any(is_stdio_server)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server written as an inline table, under `[mcp_servers]` or in an
    /// inline `mcp_servers`, is wrapped as a table is, stays inline, counts
    /// as guarded, and unwraps back. FAILS ON REVERT of the inline reading
    /// in `for_each_server` and `server_tables`: nothing is wrapped.
    #[test]
    fn an_inline_server_is_wrapped_and_counted() {
        for text in [
            "[mcp_servers]\nicm = { command = \"icm\", args = [\"serve\"] }\n",
            "mcp_servers = { icm = { command = \"icm\", args = [\"serve\"] } }\n",
        ] {
            let mut doc: DocumentMut = text.parse().unwrap();
            assert_eq!(
                wrap_toml(&mut doc, "/abs/innerwarden", false, "codex"),
                1,
                "{text}"
            );
            let wrapped = doc.to_string();
            assert!(wrapped.contains("icm = {"), "stays inline: {wrapped}");
            assert!(wrapped.contains("\"proxy\""), "{wrapped}");
            assert!(is_guarded_toml(&doc), "{wrapped}");
            assert_eq!(guarded_mode_toml(&doc), Some(WiringMode::Enforce));
            assert_eq!(wrap_toml(&mut doc, "/abs/innerwarden", false, "codex"), 0);
            let entries = server_entries_toml(&doc);
            assert!(entries[0].behind_proxy, "{entries:?}");
            assert_eq!(unwrap_toml(&mut doc), 1);
            let back: DocumentMut = doc.to_string().parse().unwrap();
            assert!(!is_guarded_toml(&back), "{back}");
            assert!(back.to_string().contains("command = \"icm\""), "{back}");
        }
    }

    /// The same servers, written as Codex's TOML and as a JSON client's
    /// `mcpServers`, count the same before and after a wrap. FAILS ON REVERT
    /// of the remote count in either reader.
    #[test]
    fn server_counts_toml_agrees_with_json() {
        let toml_text = r#"
[mcp_servers.icm]
command = "npx"
args = ["-y", "some-server"]

[mcp_servers.node_repl]
command = "node"
args = ["repl.js"]

[mcp_servers.py]
command = "uvx"
args = ["a-server"]

[mcp_servers.docs]
url = "https://example.com/mcp"

[mcp_servers.streamed]
httpUrl = "https://example.com/stream"
"#;
        let json_cfg = serde_json::json!({"mcpServers": {
            "icm": {"command": "npx", "args": ["-y", "some-server"]},
            "node_repl": {"command": "node", "args": ["repl.js"]},
            "py": {"command": "uvx", "args": ["a-server"]},
            "docs": {"url": "https://example.com/mcp"},
            "streamed": {"httpUrl": "https://example.com/stream"}
        }});
        let mut doc: DocumentMut = toml_text.parse().expect("toml");
        // Three local, one `url` server the proxy carries, and one under
        // `httpUrl`, a key Codex does not read, counted remote: a count that
        // took one kind for the other reads differently (nightly mutant
        // 2026-10-24: with two of each, a reader that counted the local
        // servers as remote read the same).
        let expected = crate::mcp_wire::ServerCounts {
            stdio: 4,
            wrapped: 0,
            remote: 1,
        };
        assert_eq!(server_counts_toml(&doc), expected);
        // The JSON wiring carries both remote servers through the proxy
        // (`mcp_proxy::remote`); Codex's TOML carries its `url` one.
        let json_expected = crate::mcp_wire::ServerCounts {
            stdio: 5,
            wrapped: 0,
            remote: 0,
        };
        assert_eq!(crate::mcp_wire::server_counts(&json_cfg), json_expected);
        wrap_toml(&mut doc, "/abs/innerwarden", true, "codex");
        let (wrapped_json, _) = crate::mcp_wire::wrap(json_cfg, "/abs/innerwarden", true, "codex");
        let after = crate::mcp_wire::ServerCounts {
            wrapped: 4,
            ..expected
        };
        assert_eq!(server_counts_toml(&doc), after);
        assert_eq!(
            crate::mcp_wire::server_counts(&wrapped_json),
            crate::mcp_wire::ServerCounts {
                wrapped: 5,
                ..json_expected
            }
        );
        let empty: DocumentMut = "model = \"x\"\n".parse().expect("toml");
        assert_eq!(
            server_counts_toml(&empty),
            crate::mcp_wire::ServerCounts::default()
        );
    }

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
    fn wraps_stdio_and_remote_servers_preserving_comments() {
        let mut d = doc();
        assert!(is_guardable_toml(&d));
        assert!(!is_guarded_toml(&d));
        let n = wrap_toml(&mut d, "innerwarden", false, "codex");
        assert_eq!(n, 3, "two stdio servers and the url server wrapped");
        // The url server's proxy talks to its address.
        let remote = d["mcp_servers"]["remote_only"].as_table().unwrap();
        assert_eq!(remote["command"].as_str(), Some("innerwarden"));
        assert!(remote.get("url").is_none());
        assert_eq!(
            remote["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "proxy",
                "--label",
                "codex",
                "--agent",
                "codex",
                "--mode",
                "guard",
                "--",
                "https://example.com/mcp"
            ]
        );
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
        assert_eq!(wrap_toml(&mut d, "innerwarden", false, "codex"), 3);
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
        assert_eq!(n, 3);
        assert_eq!(d.to_string(), doc().to_string(), "the file as it was");
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
        assert_eq!(wrap_toml(&mut d, "innerwarden", true, "codex"), 3);
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

        assert_eq!(wrap_toml(&mut d, "innerwarden", false, "codex"), 3);
        assert_eq!(guarded_mode_toml(&d), Some(WiringMode::Enforce));
        assert_eq!(unwrap_toml(&mut d), 3);
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

#[cfg(test)]
mod remote_wiring_tests {
    use super::*;

    const BIN: &str = "/abs/innerwarden";

    /// A Codex config as `codex mcp add` writes it and a person edits it:
    /// a server with its token's variable, one with headers of each kind
    /// and a comment, one with its headers in a table of their own, one
    /// Codex signs in to, and a local one.
    const CODEX: &str = r#"# my Codex settings
model = "gpt-5"

[mcp_servers.docs]
url = "https://docs.example/mcp"
bearer_token_env_var = "DOCS_TOKEN"
startup_timeout_sec = 20

[mcp_servers.team]
url = "https://team.example/mcp" # the team server
http_headers = { X-Team = "blue", X-Env = "prod" }
env_http_headers = { X-Org = "ORG_ID" }
enabled = true

[mcp_servers.sub]
url = "http://127.0.0.1:9000/mcp"

[mcp_servers.sub.http_headers]
X-A = "1"

[mcp_servers.signin]
url = "https://x.example/mcp"
scopes = ["read"]

[mcp_servers.local]
command = "npx"
args = ["-y", "srv"]
"#;

    fn args_of(doc: &DocumentMut, name: &str) -> Vec<String> {
        doc["mcp_servers"][name]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().to_string())
            .collect()
    }

    /// Every remote server the proxy can carry becomes a wrapper Codex
    /// accepts as a local server (none of the keys it refuses there), the
    /// variables go to `env_vars` and never a value, and disconnect gives
    /// back the file byte for byte, after a mode switch too. FAILS ON REVERT
    /// of `remote_as_local` (nothing wrapped) or `restore_remote` (the
    /// table comes back as a command named after its address).
    #[test]
    fn codex_remote_servers_are_wired_and_come_back_byte_for_byte() {
        let mut doc: DocumentMut = CODEX.parse().unwrap();
        assert_eq!(
            server_counts_toml(&doc),
            crate::mcp_wire::ServerCounts {
                stdio: 4,
                wrapped: 0,
                remote: 1
            }
        );
        assert_eq!(wrap_toml(&mut doc, BIN, false, "codex"), 4);
        assert!(is_guarded_toml(&doc));
        assert_eq!(server_counts_toml(&doc).remote, 1, "signin stays as it was");
        for name in ["docs", "team", "sub"] {
            let server = doc["mcp_servers"][name].as_table().unwrap();
            for key in [
                "url",
                "bearer_token_env_var",
                "http_headers",
                "env_http_headers",
            ] {
                assert!(server.get(key).is_none(), "{name}.{key}: {doc}");
            }
            assert_eq!(server["command"].as_str(), Some(BIN));
        }
        let docs = args_of(&doc, "docs");
        assert_eq!(
            docs[docs.iter().position(|a| a == "--").unwrap()..],
            [
                "--",
                "https://docs.example/mcp",
                "--bearer-env",
                "DOCS_TOKEN"
            ]
        );
        let env_vars: Vec<&str> = doc["mcp_servers"]["docs"]["env_vars"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(env_vars, ["DOCS_TOKEN"]);
        let team = args_of(&doc, "team");
        assert_eq!(
            team[team.iter().position(|a| a == "--").unwrap()..],
            [
                "--",
                "https://team.example/mcp",
                "--headers",
                "--env-headers",
                "--header-env",
                "X-Org",
                "ORG_ID"
            ]
        );
        let text = doc.to_string();
        assert!(text.contains("# the team server"), "{text}");
        assert!(
            text.contains("INNERWARDEN_MCP_HEADER_1 = \"X-Team: blue\""),
            "{text}"
        );
        assert!(text.contains("[mcp_servers.sub.env]"), "{text}");

        // What the proxy reads from the team wrapper: the headers in `env`
        // and the one whose value Codex hands it in `ORG_ID`.
        let env = doc["mcp_servers"]["team"]["env"]
            .as_inline_table()
            .unwrap()
            .clone();
        let words = team[team.iter().position(|a| a == "--").unwrap() + 1..].to_vec();
        let spec = crate::mcp_proxy::remote::RemoteSpec::from_cmd(&words, |name| {
            if name == "ORG_ID" {
                return Some("org-7".to_string());
            }
            env.get(name).and_then(Value::as_str).map(str::to_string)
        })
        .unwrap()
        .unwrap();
        assert_eq!(
            spec.headers,
            [
                ("X-Team".to_string(), "blue".to_string()),
                ("X-Env".to_string(), "prod".to_string()),
                ("X-Org".to_string(), "org-7".to_string())
            ]
        );

        assert_eq!(wrap_toml(&mut doc, BIN, false, "codex"), 0, "idempotent");
        assert_eq!(wrap_toml(&mut doc, BIN, true, "codex"), 4);
        assert_eq!(guarded_mode_toml(&doc), Some(WiringMode::Monitor));
        assert_eq!(unwrap_toml(&mut doc), 4);
        assert_eq!(doc.to_string(), CODEX);
    }

    /// Automatic setup wraps only the local server: a server reached by URL
    /// may be one Codex signs in to with `codex mcp login`, which no key
    /// says. FAILS ON REVERT of `wrap_toml_local` taking the remote ones.
    #[test]
    fn automatic_setup_wraps_only_local_servers() {
        let mut doc: DocumentMut = CODEX.parse().unwrap();
        assert!(is_automatic_wrap_safe_toml(&doc));
        assert_eq!(wrap_toml_local(&mut doc, BIN, false, "codex"), 1);
        assert!(local_servers_guarded_toml(&doc));
        assert!(!is_guarded_toml(&doc), "the remote ones are still direct");
        assert_eq!(
            doc["mcp_servers"]["docs"]["url"].as_str(),
            Some("https://docs.example/mcp")
        );
        let remote_only: DocumentMut = "[mcp_servers.docs]\nurl = \"https://docs.example/mcp\"\n"
            .parse()
            .unwrap();
        assert!(is_guardable_toml(&remote_only));
        assert!(!is_automatic_wrap_safe_toml(&remote_only));
    }

    /// `env_http_headers = {}` names no variable: the wrapper still has
    /// `env_vars` where it stood, so disconnect gives the table back byte for
    /// byte. FAILS ON REVERT: skip `env_vars` when no variable is named, and
    /// the table comes back as `command = "https://..."`, which Codex does
    /// not load.
    #[test]
    fn an_empty_env_http_headers_comes_back_byte_for_byte() {
        for text in [
            "[mcp_servers.x]\nurl = \"https://x.example/mcp\"\nenv_http_headers = {}\n",
            "[mcp_servers.x]\nurl = \"https://x.example/mcp\"\nhttp_headers = { A = \"1\" }\nenv_http_headers = {}\n",
        ] {
            let mut doc: DocumentMut = text.parse().unwrap();
            assert_eq!(wrap_toml(&mut doc, BIN, false, "codex"), 1, "{text}");
            assert!(
                doc["mcp_servers"]["x"]["env_vars"].as_array().is_some(),
                "{doc}"
            );
            assert_eq!(unwrap_toml(&mut doc), 1, "{doc}");
            assert_eq!(doc.to_string(), text);
        }
    }

    /// More headers than the proxy sends: the table is left as it was, never
    /// carried with some of them dropped, and named with why.
    #[test]
    fn a_table_with_more_headers_than_the_proxy_sends_is_left_alone() {
        let headers: Vec<String> = (0..=MAX_HEADERS)
            .map(|n| format!("X-H{n} = \"v\""))
            .collect();
        let text = format!(
            "[mcp_servers.many]\nurl = \"https://x.example/mcp\"\nhttp_headers = {{ {} }}\n",
            headers.join(", ")
        );
        let mut doc: DocumentMut = text.parse().unwrap();
        assert_eq!(wrap_toml(&mut doc, BIN, false, "codex"), 0);
        assert_eq!(doc.to_string(), text);
        assert_eq!(
            unscreened_remote_toml(&doc),
            [format!("many (more than {MAX_HEADERS} headers)")]
        );
        let at_the_cap: Vec<String> = (1..=MAX_HEADERS)
            .map(|n| format!("X-H{n} = \"v\""))
            .collect();
        let text = format!(
            "[mcp_servers.many]\nurl = \"https://x.example/mcp\"\nhttp_headers = {{ {} }}\n",
            at_the_cap.join(", ")
        );
        let mut doc: DocumentMut = text.parse().unwrap();
        assert_eq!(wrap_toml(&mut doc, BIN, false, "codex"), 1);
    }

    /// Each server reached by URL the proxy does not carry is named with the
    /// key that keeps it out, and a carried or local one is not.
    #[test]
    fn the_servers_left_out_are_named_with_their_key() {
        let mut doc: DocumentMut = CODEX.parse().unwrap();
        assert_eq!(unscreened_remote_toml(&doc), ["signin (scopes)"]);
        wrap_toml(&mut doc, BIN, false, "codex");
        assert_eq!(unscreened_remote_toml(&doc), ["signin (scopes)"]);
        let text = "[mcp_servers.a]\nurl = \"https://x.example/mcp\"\nbearer_token = \"t\"\n\n[mcp_servers.b]\nurl = \"https://x.example/mcp\"\nhttp_headers_helper = \"/bin/mint\"\n\n[mcp_servers.c]\nurl = \"https://x.example/mcp\"\nenvironment_id = \"e\"\n";
        let doc: DocumentMut = text.parse().unwrap();
        let named = unscreened_remote_toml(&doc);
        assert_eq!(
            named,
            [
                "a (bearer_token)",
                "b (http_headers_helper)",
                "c (environment_id)"
            ]
        );
        assert!(named.iter().all(|line| !line.contains("\"t\"")));
    }

    /// A table the proxy cannot carry is left exactly as it was and counted
    /// remote: a token written in the file, a sign-in Codex does itself, a
    /// header program, a server run elsewhere, an address that is not
    /// http(s), a header that is not text, `env_http_headers` in a table
    /// of its own.
    #[test]
    fn a_table_the_proxy_cannot_carry_is_left_alone() {
        for server in [
            "url = \"https://x.example/mcp\"\nbearer_token = \"abc\"\n",
            "url = \"https://x.example/mcp\"\noauth_resource = \"https://x.example\"\n",
            "url = \"https://x.example/mcp\"\nscopes = [\"a\"]\n",
            "url = \"https://x.example/mcp\"\nhttp_headers_helper = \"/bin/mint\"\n",
            "url = \"https://x.example/mcp\"\nenvironment_id = \"remote\"\n",
            "url = \"ftp://x.example/mcp\"\n",
            "url = \"https://x.example/mcp\"\nhttp_headers = { A = 1 }\n",
            "url = \"https://x.example/mcp\"\nbearer_token_env_var = \"NOT A NAME\"\n",
            "url = \"https://x.example/mcp\"\n\n[mcp_servers.x.env_http_headers]\nA = \"B\"\n",
        ] {
            let text = format!("[mcp_servers.x]\n{server}");
            let mut doc: DocumentMut = text.parse().unwrap();
            assert_eq!(wrap_toml(&mut doc, BIN, false, "codex"), 0, "{text}");
            assert_eq!(doc.to_string(), text);
            assert_eq!(server_counts_toml(&doc).remote, 1, "{text}");
            assert!(!is_guardable_toml(&doc), "{text}");
        }
    }
}
