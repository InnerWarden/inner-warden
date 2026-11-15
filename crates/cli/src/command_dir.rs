//! The folder a shell call names for its command.
//!
//! Gemini CLI's `run_shell_command` takes, beside the command, the folder to
//! run it in: `tool_input.dir_path` (`directory` in older versions), which
//! Gemini joins to the folder it works in. Hermes Agent's `terminal` takes
//! one too, `tool_input.workdir` (v0.23.1, `tools/terminal_tool.py`). A command judged without it is
//! judged in the wrong place: `rm settings.json` says nothing of the file it
//! removes until the folder is `.gemini`.
//!
//! Pure: what the payload says, joined to a base the caller gives. The hook
//! (`classify_hook_input` and `hook_cwd` in `main.rs`) judges the command as
//! the line [`in_folder`] writes, and judges and records it in the folder
//! [`of`] returns.

/// The tools whose input names a folder for their command, and the fields
/// that name it: Gemini CLI's today, then the one it had before; Hermes
/// Agent's.
const TOOLS: &[(&str, &[&str])] = &[
    ("run_shell_command", &["dir_path", "directory"]),
    ("terminal", &["workdir"]),
];

/// The longest folder read, in bytes: the longest path most systems take.
const MAX_FOLDER_BYTES: usize = 4096;

/// The folder a shell call names for its command.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommandDir {
    /// The call names none: the command runs where the agent is.
    Unnamed,
    /// The folder the command runs in, absolute.
    Named(String),
    /// The call names a folder that cannot be read. A command judged
    /// without it would be judged in the wrong place.
    Unreadable(&'static str),
}

/// The folder the command of `payload` runs in, when the call names one.
/// A relative folder is joined to the payload's `cwd`, and to `own_dir()`
/// (the hook's own directory, where the agent starts it) when the payload
/// has none.
pub(crate) fn of(
    payload: &serde_json::Value,
    own_dir: impl FnOnce() -> Option<String>,
) -> CommandDir {
    let dir = match named(payload) {
        Ok(Some(dir)) => dir,
        Ok(None) => return CommandDir::Unnamed,
        Err(why) => return CommandDir::Unreadable(why),
    };
    let base = payload
        .get("cwd")
        .and_then(|cwd| cwd.as_str())
        .filter(|cwd| !cwd.trim().is_empty())
        .map(str::to_string)
        .or_else(own_dir);
    match joined(dir, base.as_deref()) {
        Some(folder) if folder.len() <= MAX_FOLDER_BYTES => CommandDir::Named(folder),
        Some(_) => CommandDir::Unreadable("a folder for the command that is too long to read"),
        None => {
            CommandDir::Unreadable("a relative folder for the command and no folder to join it to")
        }
    }
}

/// The folder as the call writes it. The empty string is no folder, as it is
/// to Gemini CLI.
fn named(payload: &serde_json::Value) -> Result<Option<&str>, &'static str> {
    let tool = payload
        .get("tool_name")
        .or_else(|| payload.get("tool"))
        .and_then(|tool| tool.as_str())
        .unwrap_or("");
    let Some((_, fields)) = TOOLS
        .iter()
        .find(|(name, _)| tool.eq_ignore_ascii_case(name))
    else {
        return Ok(None);
    };
    let Some(input) = payload.get("tool_input") else {
        return Ok(None);
    };
    let mut found: Option<&str> = None;
    for field in *fields {
        let Some(value) = input.get(field) else {
            continue;
        };
        let Some(dir) = value.as_str() else {
            return Err("a folder for the command that is not a string");
        };
        if dir.is_empty() {
            continue;
        }
        if dir.chars().any(char::is_control) {
            return Err("a folder for the command with a control character in it");
        }
        // Which of the two a given Gemini reads depends on its version.
        if found.is_some_and(|first| first != dir) {
            return Err("two different folders for the command");
        }
        found = Some(dir);
    }
    Ok(found)
}

/// `dir` made absolute the way Gemini CLI does it: joined to `base` when it
/// is relative, `.` and `..` resolved by name alone. `None` when it is
/// relative and there is no absolute base.
fn joined(dir: &str, base: Option<&str>) -> Option<String> {
    if dir.starts_with('/') {
        return Some(collapsed(dir));
    }
    if windows_absolute(dir) {
        return Some(dir.to_string());
    }
    let base = base?;
    if base.starts_with('/') {
        return Some(collapsed(&format!("{base}/{dir}")));
    }
    windows_absolute(base).then(|| format!("{}\\{dir}", base.trim_end_matches(['\\', '/'])))
}

/// A path that starts at a drive (`C:\`, `C:/`) or at a share (`\\host`).
fn windows_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with("\\\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'))
}

/// An absolute path without its `.`, `..` and empty parts.
fn collapsed(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

/// The command as it is judged: after a change of directory to `folder`,
/// which is quoted whole so no character of it is read as shell. The rules
/// that follow a `cd` on the line then read a relative target in the folder
/// the command runs in.
pub(crate) fn in_folder(command: &str, folder: &str) -> String {
    format!("cd -- '{}' && {command}", folder.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(tool: &str, input: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"cwd": "/work/app", "tool_name": tool, "tool_input": input})
    }

    fn no_own_dir() -> Option<String> {
        None
    }

    /// Gemini's shell call names the folder its command runs in, under
    /// either name, and the folder is joined to the payload's `cwd`.
    ///
    /// FAILS ON REVERT: take `"directory"` out of `TOOLS` and the second
    /// call names no folder; return `Ok(None)` at the top of `named` and
    /// neither does.
    #[test]
    fn geminis_shell_call_names_the_folder_its_command_runs_in() {
        for field in ["dir_path", "directory"] {
            let payload = call(
                "run_shell_command",
                serde_json::json!({"command": "ls", field: "../.gemini"}),
            );
            assert_eq!(
                of(&payload, no_own_dir),
                CommandDir::Named("/work/.gemini".to_string()),
                "{field}"
            );
        }
        // The same folder under both names is one folder.
        let both = call(
            "run_shell_command",
            serde_json::json!({"command": "ls", "dir_path": "src", "directory": "src"}),
        );
        assert_eq!(
            of(&both, no_own_dir),
            CommandDir::Named("/work/app/src".to_string())
        );
    }

    /// Hermes Agent's `terminal` names the folder its command runs in as
    /// `workdir` (v0.23.1), and a Gemini field in its input is not read.
    ///
    /// FAILS ON REVERT: take the `terminal` row out of `TOOLS` and the call
    /// names no folder, so `rm config.yaml` there is judged where Hermes was
    /// started.
    #[test]
    fn hermes_terminal_call_names_the_folder_its_command_runs_in() {
        let payload = call(
            "terminal",
            serde_json::json!({"command": "rm config.yaml", "workdir": "/home/u/.hermes"}),
        );
        assert_eq!(
            of(&payload, no_own_dir),
            CommandDir::Named("/home/u/.hermes".to_string())
        );
        let other = call(
            "terminal",
            serde_json::json!({"command": "ls", "dir_path": "/home/u/.hermes"}),
        );
        assert_eq!(of(&other, no_own_dir), CommandDir::Unnamed);
    }

    /// No folder, the empty one, and a folder in the input of another tool
    /// leave the command where the agent is.
    ///
    /// FAILS ON REVERT: drop the `dir.is_empty()` test in `named` and the
    /// empty folder is named as the `cwd` itself; drop the tool test and
    /// Claude Code's `Bash` call is read for a field it does not have.
    #[test]
    fn a_call_that_names_no_folder_is_left_where_the_agent_is() {
        for payload in [
            call("run_shell_command", serde_json::json!({"command": "ls"})),
            call(
                "run_shell_command",
                serde_json::json!({"command": "ls", "dir_path": ""}),
            ),
            call(
                "Bash",
                serde_json::json!({"command": "ls", "dir_path": ".gemini"}),
            ),
            serde_json::json!({"tool_name": "run_shell_command"}),
        ] {
            assert_eq!(of(&payload, no_own_dir), CommandDir::Unnamed, "{payload}");
        }
    }

    /// A folder that is there and cannot be read is said to be unreadable,
    /// never taken for none.
    ///
    /// FAILS ON REVERT: turn the `Err` for a value that is not a string into
    /// `continue` in `named` and the first four are `Unnamed`; drop the test
    /// of the two names and the fifth is the first folder alone; drop the
    /// control character test and the sixth is named.
    #[test]
    fn a_folder_that_cannot_be_read_is_unreadable() {
        for input in [
            serde_json::json!({"command": "ls", "dir_path": 7}),
            serde_json::json!({"command": "ls", "dir_path": null}),
            serde_json::json!({"command": "ls", "dir_path": [".gemini"]}),
            serde_json::json!({"command": "ls", "directory": {"path": ".gemini"}}),
            serde_json::json!({"command": "ls", "dir_path": "src", "directory": "../.gemini"}),
            serde_json::json!({"command": "ls", "dir_path": "src\n.gemini"}),
        ] {
            let payload = call("run_shell_command", input);
            assert!(
                matches!(of(&payload, no_own_dir), CommandDir::Unreadable(_)),
                "{payload}"
            );
        }
    }

    /// The join is Gemini's: an absolute folder stands alone, a relative one
    /// is read from the base, and `..` is resolved by name.
    ///
    /// FAILS ON REVERT: drop the `..` arm of `collapsed` and the third and
    /// fourth folders keep their `..`; drop the `windows_absolute(base)` test
    /// that ends `joined` and the last line is a folder.
    #[test]
    fn a_folder_is_joined_the_way_gemini_joins_it() {
        assert_eq!(joined("/srv/x", Some("/work")), Some("/srv/x".to_string()));
        assert_eq!(joined("src", Some("/work/")), Some("/work/src".to_string()));
        assert_eq!(
            joined("./a/../../.gemini/.", Some("/work/app")),
            Some("/work/.gemini".to_string())
        );
        assert_eq!(joined("../../..", Some("/work")), Some("/".to_string()));
        assert_eq!(
            joined("src", Some("C:\\work\\")),
            Some("C:\\work\\src".to_string())
        );
        assert_eq!(joined("D:/x", None), Some("D:/x".to_string()));
        assert_eq!(joined("src", None), None);
        assert_eq!(joined("src", Some("work")), None);
    }

    /// With no `cwd` in the payload the hook's own directory is the base,
    /// and a relative folder with neither is unreadable.
    ///
    /// FAILS ON REVERT: drop `.or_else(own_dir)` in `of` and the first is
    /// unreadable.
    #[test]
    fn a_payload_without_a_cwd_is_joined_to_the_hooks_own_directory() {
        let payload = serde_json::json!({
            "tool_name": "run_shell_command",
            "tool_input": {"command": "ls", "dir_path": ".gemini"},
        });
        assert_eq!(
            of(&payload, || Some("/home/dev".to_string())),
            CommandDir::Named("/home/dev/.gemini".to_string())
        );
        assert!(matches!(
            of(&payload, no_own_dir),
            CommandDir::Unreadable(_)
        ));
    }

    /// A folder longer than a path can be is unreadable.
    ///
    /// FAILS ON REVERT: drop the length guard in `of` and it is named.
    #[test]
    fn a_folder_too_long_to_be_a_path_is_unreadable() {
        let payload = call(
            "run_shell_command",
            serde_json::json!({"command": "ls", "dir_path": "a/".repeat(3000)}),
        );
        assert!(matches!(
            of(&payload, no_own_dir),
            CommandDir::Unreadable(_)
        ));
    }

    /// The judged line changes directory first and quotes the folder whole.
    ///
    /// FAILS ON REVERT: drop the `replace` in `in_folder` and the quote in
    /// the folder's name ends the quoted word.
    #[test]
    fn the_judged_line_changes_directory_first_and_quotes_the_folder() {
        assert_eq!(
            in_folder("rm settings.json", "/work/.gemini"),
            "cd -- '/work/.gemini' && rm settings.json"
        );
        assert_eq!(
            in_folder("ls", "/work/it's; here"),
            "cd -- '/work/it'\\''s; here' && ls"
        );
    }
}
