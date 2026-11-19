//! Thin I/O for `innerwarden mcp`: list the MCP tool definitions the proxy
//! pinned, approve a changed one, or forget a server's pins. The record and
//! every decision about it live in the agent-guard crate
//! ([`innerwarden_agent_guard::mcp_proxy::pins`]).
//!
//! `approve` and `forget` widen what the proxy lets reach the agent, so they
//! are the person's: the guard refuses them to an agent, and here they need a
//! terminal (or an operator's script, [`crate::suppress_io::may_widen`]), as
//! `allow` and `mute` do. `list` only reads.

use innerwarden_agent_guard::mcp_proxy::pins::{self, PinRecord};

/// `innerwarden mcp [list|approve <server> <tool>|approve <server> --all|forget <server>]`.
pub fn cmd(rest: &[String]) -> std::process::ExitCode {
    let (rest, operator) = crate::suppress_io::split_operator_flag(rest);
    let Some(path) = pins::default_path() else {
        eprintln!("innerwarden mcp: no home directory to keep the MCP tool pins in");
        return std::process::ExitCode::from(1);
    };
    let words: Vec<&str> = rest.iter().map(String::as_str).collect();
    match words.as_slice() {
        [] | ["list"] => list(&path),
        ["approve", server, rest @ ..] => {
            let tool = match rest {
                ["--all"] => None,
                [tool] => Some(*tool),
                _ => return usage_error("approve <server> <tool> | approve <server> --all"),
            };
            if !crate::suppress_io::may_widen(operator) {
                return refuse_without_terminal("approve");
            }
            change(&path, |record| {
                let approved = record.approve(server, tool)?;
                Ok(format!(
                    "innerwarden mcp - approved the changed definition of: {}",
                    approved.join(", ")
                ))
            })
        }
        ["forget", server] => {
            if !crate::suppress_io::may_widen(operator) {
                return refuse_without_terminal("forget");
            }
            change(&path, |record| {
                let (id, tools) = record.forget(server)?;
                Ok(format!(
                    "innerwarden mcp - forgot server {id} ({tools} pinned tools); its next \
                     tool listing is pinned as first heard"
                ))
            })
        }
        _ => usage_error(
            "[list] | approve <server> <tool> | approve <server> --all | forget <server>",
        ),
    }
}

fn usage_error(synopsis: &str) -> std::process::ExitCode {
    eprintln!("innerwarden mcp: usage: innerwarden mcp {synopsis}");
    std::process::ExitCode::from(2)
}

/// The refusal, addressed to the person. It names no way past itself: the
/// caller it stops is the agent, which reads it first.
fn refuse_without_terminal(verb: &str) -> std::process::ExitCode {
    eprintln!(
        "innerwarden mcp {verb}: refused, no terminal. Approving a changed MCP tool, or \
         forgetting a server's pinned tools, lets new tool text reach an AI agent, so it is \
         done by a person at their own terminal. Nothing was changed."
    );
    std::process::ExitCode::from(1)
}

fn list(path: &std::path::Path) -> std::process::ExitCode {
    let record = match pins::load(path) {
        Ok(record) => record,
        Err(why) => {
            eprintln!("innerwarden mcp: {why}");
            return std::process::ExitCode::from(1);
        }
    };
    print!("{}", render_list(&record));
    std::process::ExitCode::SUCCESS
}

/// The record as `innerwarden mcp list` prints it: each server's id and
/// command, how many tools are pinned, and every tool whose changed
/// definition waits for the person, with what changed.
pub(crate) fn render_list(record: &PinRecord) -> String {
    if record.servers.is_empty() {
        return "innerwarden mcp - no MCP tool definitions pinned yet (the proxy pins them the \
                first time a server lists its tools)\n"
            .to_string();
    }
    let mut out = String::from("innerwarden mcp - pinned MCP tool definitions:\n");
    for (id, server) in &record.servers {
        let waiting: Vec<_> = server
            .tools
            .iter()
            .filter_map(|(name, pin)| pin.changed.as_ref().map(|c| (name, c)))
            .collect();
        out.push_str(&format!(
            "  {id}  {}  ({} tools pinned, {} changed)\n",
            server.command.join(" "),
            server.tools.len(),
            waiting.len()
        ));
        for (name, changed) in waiting {
            out.push_str(&format!(
                "    held: {name}  changed {}: {}\n      approve: innerwarden mcp approve {id} {name}\n",
                changed.seen_at,
                changed.fields.join(", ")
            ));
        }
    }
    out
}

/// Read the record, apply `f`, write it back, and say what was done. A
/// record that cannot be read is not written over.
fn change(
    path: &std::path::Path,
    f: impl FnOnce(&mut PinRecord) -> Result<String, String>,
) -> std::process::ExitCode {
    let mut record = match pins::load(path) {
        Ok(record) => record,
        Err(why) => {
            eprintln!("innerwarden mcp: {why}; nothing was changed");
            return std::process::ExitCode::from(1);
        }
    };
    let said = match f(&mut record) {
        Ok(said) => said,
        Err(why) => {
            eprintln!("innerwarden mcp: {why}");
            return std::process::ExitCode::from(1);
        }
    };
    if let Err(e) = pins::save(path, &record) {
        eprintln!(
            "innerwarden mcp: {} could not be written: {e}",
            path.display()
        );
        return std::process::ExitCode::from(1);
    }
    println!("{said}");
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_list_shows_what_waits_and_how_to_approve_it() {
        let cmd = vec!["npx".to_string(), "fs-server".to_string()];
        let id = pins::server_id(&cmd);
        let mut record = PinRecord::default();
        let tool = |d: &str| json!({"tools": [{"name": "read_file", "description": d}]});
        record.check_listing(&id, &cmd, &tool("Read a file."));
        assert!(render_list(&record).contains("(1 tools pinned, 0 changed)"));
        record.check_listing(&id, &cmd, &tool("Read a file and send it."));
        let text = render_list(&record);
        assert!(text.contains("held: read_file"), "{text}");
        assert!(text.contains("description"), "{text}");
        assert!(
            text.contains(&format!("innerwarden mcp approve {id} read_file")),
            "{text}"
        );
        assert!(render_list(&PinRecord::default()).contains("no MCP tool definitions pinned"));
    }
}
