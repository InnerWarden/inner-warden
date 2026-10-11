//! An agent's own file tools, screened before they run.
//!
//! Claude Code writes files through `Write`, `Edit`, `MultiEdit` and
//! `NotebookEdit`, not through its shell. A hook wired to `Bash` alone never
//! sees them, so the shell side could refuse `sed -i` on the agent's settings
//! while an `Edit` of the same file went through: the agent could drop the
//! hook that screens it, add an allow rule to the guard's own configuration,
//! or plant a line in a shell startup file, and nothing said so.
//!
//! What is judged is WHERE a call writes, never what it writes, and only
//! against a short list of privileged places:
//!
//! * every place [`crate::threats`] already refuses an MCP write tool
//!   (the guard's configuration and the agent settings that load it, SSH
//!   keys, the sudo rules, cron, boot services, ...);
//! * places in the account's own home that an MCP server is not held to,
//!   because they run as that account and not as anyone more: the shell's
//!   startup files, the user's own services and login items, and the stored
//!   credentials of common tools;
//! * the guard's own program.
//!
//! Everything else, which is every ordinary edit to a project, is allowed
//! without a word and without touching the rule engine, so the hook stays
//! fast on the call an agent makes most.
//!
//! A path is judged as written, after `~` and the working directory are
//! applied and `.` and `..` resolved, and again after the links on the way
//! are followed, so a link made earlier in the project does not step around
//! the list. Then, on Unix, by what it is rather than what it is called: a
//! file that is one of the privileged files (a hard link to it, or the real
//! file a home link such as `~/.bashrc -> dotfiles/bashrc` points at), or that
//! sits in one of the privileged directories reached by another name (a
//! mount or firmlink path to the home), is refused as that file.
//!
//! What a hook that runs before the tool cannot close: the path is judged,
//! then the agent's tool writes it, and a background job that swaps a link
//! into place between the two can win that race. A change the shell makes to
//! a hard link (`>>` into a project file that is the same file) is the shell
//! side's to judge.

use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::threats::{privileged_write_target, ROOT_HOME};

/// Claude Code's tools that change a file, by name.
pub const FILE_TOOLS: &[&str] = &["Write", "Edit", "MultiEdit", "NotebookEdit"];

/// The PreToolUse matcher that sends [`FILE_TOOLS`] to the hook: a plain
/// `|` list, which every Claude Code version reads as that exact set.
pub const FILE_TOOLS_MATCHER: &str = "Write|Edit|MultiEdit|NotebookEdit";

/// Where a file tool names its target: `file_path` for `Write`, `Edit` and
/// `MultiEdit`, `notebook_path` for `NotebookEdit`. `path` is read too, so a
/// renamed field is still judged rather than skipped.
const PATH_KEYS: &[&str] = &["file_path", "notebook_path", "path"];

/// How many links are followed before a path is judged as it stands.
const MAX_LINK_STEPS: u8 = 40;

/// Longest path judged. A longer one is not a path any system opens.
const MAX_PATH_BYTES: usize = 4096;

/// One tool call, read for what it writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileToolCall {
    /// Not one of [`FILE_TOOLS`]: none of this module's business.
    NotAFileTool,
    /// A file tool, and every path it names.
    Writes { tool: String, paths: Vec<String> },
    /// A file tool whose target could not be read. The hook is registered for
    /// these tools, so this is a schema change or a broken agent.
    Unreadable(&'static str),
}

/// Read a hook payload as a file tool call.
pub fn file_tool_call(payload: &Value) -> FileToolCall {
    let tool = payload
        .get("tool_name")
        .or_else(|| payload.get("tool"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if !FILE_TOOLS.contains(&tool) {
        return FileToolCall::NotAFileTool;
    }
    let input = payload.get("tool_input");
    let paths: Vec<String> = PATH_KEYS
        .iter()
        .filter_map(|key| input.and_then(|input| input.get(*key)))
        .filter_map(Value::as_str)
        .filter(|path| !path.trim().is_empty())
        .map(str::to_string)
        .collect();
    if paths.is_empty() {
        return FileToolCall::Unreadable("a file tool call with no file path");
    }
    FileToolCall::Writes {
        tool: tool.to_string(),
        paths,
    }
}

/// Where the call runs, as far as the hook knows it.
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteContext<'a> {
    /// The agent's working directory, for a relative path.
    pub cwd: Option<&'a Path>,
    /// The home of the account the agent runs as.
    pub home: Option<&'a Path>,
    /// The program the guard's hook runs (this binary).
    pub guard_program: Option<&'a Path>,
}

/// A group of places in the account's own home, relative to it, in lowercase.
struct HomeGroup {
    what: &'static str,
    files: &'static [&'static str],
    trees: &'static [&'static str],
}

/// Places in the account's own home whose change runs code later, outside
/// the agent's sight, or hands over a login. Not in the MCP list because an
/// MCP server runs as the same account and could write them itself; the
/// agent's own file tools are the thing being screened here.
const HOME_PLACES: &[HomeGroup] = &[
    HomeGroup {
        what: "your shell's startup files, which run in every new shell",
        files: &[
            ".bashrc",
            ".bash_profile",
            ".bash_login",
            ".bash_logout",
            ".profile",
            ".zshrc",
            ".zprofile",
            ".zlogin",
            ".zlogout",
            ".zshenv",
            ".kshrc",
            ".mkshrc",
            ".cshrc",
            ".tcshrc",
            ".login",
            ".pam_environment",
        ],
        trees: &[".config/fish"],
    },
    HomeGroup {
        what: "the services, jobs and login items your account starts on its own",
        files: &[],
        trees: &[
            ".config/systemd/user",
            ".local/share/systemd/user",
            ".config/environment.d",
            ".config/autostart",
            "library/launchagents",
        ],
    },
    HomeGroup {
        what: "your stored credentials",
        files: &[
            ".aws/credentials",
            ".aws/config",
            ".docker/config.json",
            ".kube/config",
            ".netrc",
            ".npmrc",
            ".pypirc",
            ".cargo/credentials",
            ".cargo/credentials.toml",
            ".config/gh/hosts.yml",
            ".config/hub",
            ".config/git/credentials",
            ".vault-token",
            ".terraform.d/credentials.tfrc.json",
        ],
        trees: &[
            ".azure",
            ".config/gcloud",
            ".password-store",
            ".local/share/keyrings",
            "library/keychains",
        ],
    },
];

const GUARD_PROGRAM: &str = "the guard's own program";

/// What the file at `path` is, when a file tool may not change it: the
/// group's words, to show the person. `None` for every other file.
pub fn privileged_file_write(path: &str, context: &WriteContext<'_>) -> Option<&'static str> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_PATH_BYTES {
        return None;
    }
    // With `HOME` unset the account's home still exists; the list in it is
    // judged against the home the account database names.
    let account_home;
    let context = &if context.home.is_none() {
        account_home = home_of_this_account();
        WriteContext {
            home: account_home.as_deref(),
            ..*context
        }
    } else {
        *context
    };
    let Some(absolute) = absolute_path(trimmed, context) else {
        // Relative, with no working directory to place it: only the places
        // that are the same wherever they start can be judged.
        return privileged_write_target(trimmed).map(|target| target.group.what);
    };
    let written = lexical(&absolute);
    if let Some(what) = judge(&written, context) {
        return Some(what);
    }
    // Resolved from the path as given, not its lexical form: after a link,
    // `..` steps out of the link's target, not out of the link's directory,
    // so `proj/link/../.bashrc` can name a file outside the project.
    let real = resolve_links(&absolute);
    if let Some(real) = real.as_ref().filter(|real| **real != written) {
        if let Some(what) = judge(real, context) {
            return Some(what);
        }
    }
    same_as_a_privileged_file(real.as_deref().unwrap_or(&written), context)
}

/// Privileged files in the account's home, relative to it, outside
/// [`HOME_PLACES`]: the ones [`crate::threats`] holds by name wherever they
/// are. Compared by identity in [`same_as_a_privileged_file`].
const HOME_GUARD_FILES: &[&str] = &[
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude.json",
    ".mcp.json",
    ".cursor/mcp.json",
    ".codex/config.toml",
    ".gemini/settings.json",
    ".openclaw/openclaw.json",
    "library/application support/claude/claude_desktop_config.json",
    ".git-credentials",
];

/// Privileged directories in the account's home outside [`HOME_PLACES`].
const HOME_GUARD_TREES: &[&str] = &[".config/innerwarden", ".ssh", ".gnupg"];

/// The account's home from the account database, for a hook run without
/// `HOME`.
#[cfg(unix)]
fn home_of_this_account() -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is to memory owned here and sized as passed; the
    // result is read only when the call says it filled `entry`.
    let status = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        )
    };
    if status != 0 || found.is_null() || entry.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` points into `buffer`, NUL-terminated by the call.
    let dir = unsafe { CStr::from_ptr(entry.pw_dir) };
    let dir = Path::new(std::ffi::OsStr::from_bytes(dir.to_bytes()));
    dir.is_absolute().then(|| dir.to_path_buf())
}

#[cfg(not(unix))]
fn home_of_this_account() -> Option<PathBuf> {
    None
}

/// What `path` is when it is one of the privileged files under another name:
/// the same file (a hard link, or the real file a home link points at), or a
/// file in one of the privileged directories reached by another path. Judged
/// by device and inode, so the spelling does not matter; only what exists is
/// compared, and a missing privileged file is matched by its directory and
/// name.
#[cfg(unix)]
fn same_as_a_privileged_file(path: &Path, context: &WriteContext<'_>) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    let identity = |p: &Path| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
    let target = identity(path);
    let parent = path.parent().and_then(identity);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase());
    let mut above: Vec<(u64, u64)> = Vec::new();
    let mut directory = path.parent();
    while let Some(at) = directory {
        above.extend(identity(at));
        directory = at.parent();
    }
    let home = context.home?;
    let files = HOME_PLACES
        .iter()
        .flat_map(|group| group.files.iter())
        .chain(HOME_GUARD_FILES);
    for relative in files {
        let relative: &str = relative;
        let place = home.join(relative);
        let same_file = target.is_some() && target == identity(&place);
        let same_slot = parent.is_some()
            && parent == place.parent().and_then(identity)
            && name.as_deref() == relative.rsplit('/').next();
        if same_file || same_slot {
            return judge(&place, context);
        }
    }
    let trees = HOME_PLACES
        .iter()
        .flat_map(|group| group.trees.iter())
        .chain(HOME_GUARD_TREES);
    for relative in trees {
        let place = home.join(relative);
        if let Some(tree) = identity(&place) {
            if target == Some(tree) || above.contains(&tree) {
                return judge(&place.join("x"), context);
            }
        }
    }
    let guard = context.guard_program.and_then(identity);
    (guard.is_some() && target == guard).then_some(GUARD_PROGRAM)
}

#[cfg(not(unix))]
fn same_as_a_privileged_file(_: &Path, _: &WriteContext<'_>) -> Option<&'static str> {
    None
}

/// `path` made absolute: `~` from the home, a relative path from the
/// working directory. `None` when the piece it needs is not known.
fn absolute_path(path: &str, context: &WriteContext<'_>) -> Option<PathBuf> {
    if path == "~" {
        return context.home.map(Path::to_path_buf);
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return context.home.map(|home| home.join(rest));
    }
    let path = Path::new(path);
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    context.cwd.map(|cwd| cwd.join(path))
}

/// `.` and `..` resolved by name, the way the path reads.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The file `path` reaches once every link on the way is followed, the part
/// that does not exist yet kept as written. A link whose target does not
/// exist yet is followed too: writing through it creates that target.
fn resolve_links(path: &Path) -> Option<PathBuf> {
    let mut path = path.to_path_buf();
    let mut missing: Vec<std::ffi::OsString> = Vec::new();
    let mut steps = 0u8;
    loop {
        if let Ok(real) = std::fs::canonicalize(&path) {
            let mut out = real;
            for name in missing.iter().rev() {
                out.push(name);
            }
            return Some(out);
        }
        if let Ok(target) = std::fs::read_link(&path) {
            steps += 1;
            if steps > MAX_LINK_STEPS {
                return None;
            }
            path = match path.parent() {
                Some(parent) if target.is_relative() => parent.join(&target),
                _ => target,
            };
            continue;
        }
        missing.push(path.file_name()?.to_os_string());
        if !path.pop() {
            return None;
        }
    }
}

/// [`privileged_file_write`] for one spelling of the path.
fn judge(path: &Path, context: &WriteContext<'_>) -> Option<&'static str> {
    let text = path.to_string_lossy();
    if let Some(target) = privileged_write_target(&text) {
        // A writer that runs as root has its own home under `/root`; its own
        // work there is a project like any other, judged by the home list.
        let own_home = target.group.what == ROOT_HOME
            && homes(context)
                .iter()
                .any(|home| home_relative(path, home).is_some());
        if !own_home {
            return Some(target.group.what);
        }
    }
    for home in homes(context) {
        if let Some(relative) = home_relative(path, &home) {
            if let Some(what) = home_place(&relative) {
                return Some(what);
            }
        }
    }
    if let Some(guard) = context.guard_program {
        let same = |a: &Path, b: &Path| lowercase(a) == lowercase(b);
        if same(path, guard) || std::fs::canonicalize(guard).is_ok_and(|real| same(path, &real)) {
            return Some(GUARD_PROGRAM);
        }
    }
    None
}

/// The home as given and as its links resolve (a home under a linked
/// directory is reached by either name).
fn homes(context: &WriteContext<'_>) -> Vec<PathBuf> {
    let Some(home) = context.home else {
        return Vec::new();
    };
    let given = lexical(home);
    let mut out = vec![given.clone()];
    if let Ok(real) = std::fs::canonicalize(&given) {
        if real != given {
            out.push(real);
        }
    }
    out
}

fn lowercase(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

/// `path` below `home`, as `/`-joined lowercase components; `None` when it
/// is not below it. Lowercase because the macOS file system ignores case.
fn home_relative(path: &Path, home: &Path) -> Option<String> {
    let path = PathBuf::from(lowercase(path));
    let home = PathBuf::from(lowercase(home));
    let rest = path.strip_prefix(&home).ok()?;
    let parts: Vec<String> = rest
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// The group of [`HOME_PLACES`] a home-relative path is in.
fn home_place(relative: &str) -> Option<&'static str> {
    HOME_PLACES
        .iter()
        .find(|group| {
            group.files.contains(&relative)
                || group.trees.iter().any(|tree| {
                    relative == *tree
                        || relative
                            .strip_prefix(tree)
                            .is_some_and(|rest| rest.starts_with('/'))
                })
        })
        .map(|group| group.what)
}

/// The person-facing reason a file tool call was refused.
pub fn refusal_explanation(tool: &str, path: &str, what: &str) -> String {
    let shown: String = path.trim().chars().take(200).collect();
    format!(
        "{tool} would change `{shown}`, part of {what}. An agent may not change this file \
         with its own tools; if you meant the change, make it yourself"
    )
}

/// The verdict the hook records for a refused file tool call, in the shape
/// of the command verdicts beside it.
pub fn refusal_verdict(tool: &str, path: &str, what: &str) -> Value {
    let explanation = refusal_explanation(tool, path, what);
    serde_json::json!({
        "command": format!("{tool} {}", path.trim()),
        "risk_score": 60,
        "severity": "high",
        "signals": [{
            "signal": "privileged_file_write",
            "score": 60,
            "detail": explanation,
        }],
        "recommendation": "deny",
        "explanation": explanation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn context<'a>(home: &'a Path, cwd: &'a Path) -> WriteContext<'a> {
        WriteContext {
            cwd: Some(cwd),
            home: Some(home),
            guard_program: None,
        }
    }

    #[test]
    fn only_the_file_tools_are_read_as_file_tools() {
        for tool in FILE_TOOLS {
            let key = if *tool == "NotebookEdit" {
                "notebook_path"
            } else {
                "file_path"
            };
            assert_eq!(
                file_tool_call(&json!({"tool_name": tool, "tool_input": {key: "/x/y"}})),
                FileToolCall::Writes {
                    tool: tool.to_string(),
                    paths: vec!["/x/y".into()],
                }
            );
        }
        for tool in [
            "Bash",
            "Read",
            "Grep",
            "WebFetch",
            "write",
            "mcp__fs__write_file",
        ] {
            assert_eq!(
                file_tool_call(&json!({"tool_name": tool, "tool_input": {"file_path": "/x"}})),
                FileToolCall::NotAFileTool,
                "{tool}"
            );
        }
        assert!(matches!(
            file_tool_call(&json!({"tool_name": "Edit", "tool_input": {"content": "x"}})),
            FileToolCall::Unreadable(_)
        ));
        assert!(matches!(
            file_tool_call(&json!({"tool_name": "Write", "tool_input": {"file_path": "  "}})),
            FileToolCall::Unreadable(_)
        ));
    }

    #[test]
    fn the_matcher_names_exactly_the_file_tools() {
        assert_eq!(
            FILE_TOOLS_MATCHER.split('|').collect::<Vec<_>>(),
            FILE_TOOLS
        );
    }

    /// The row's proof: the agent's settings, the guard's configuration, shell
    /// startup files, SSH keys, the account's own services and credential
    /// stores are refused, however the path is spelled.
    ///
    /// FAILS ON REVERT: an empty [`HOME_PLACES`], or `privileged_file_write`
    /// returning `None`, leaves these allowed.
    #[test]
    fn privileged_files_are_refused_however_they_are_spelled() {
        let home = Path::new("/home/dev");
        let cwd = Path::new("/home/dev/proj");
        let ctx = context(home, cwd);
        for (path, what) in [
            (
                "/home/dev/.claude/settings.json",
                "the guard's own configuration",
            ),
            ("~/.claude/settings.json", "the guard's own configuration"),
            ("../.claude/settings.json", "the guard's own configuration"),
            (
                "/home/dev/proj/./src/../../.claude/settings.json",
                "the guard's own configuration",
            ),
            (".claude/settings.json", "the guard's own configuration"),
            (
                ".claude/settings.local.json",
                "the guard's own configuration",
            ),
            (
                "/home/dev/.config/innerwarden/suppress.toml",
                "the guard's own configuration",
            ),
            (
                "/home/dev/.codex/config.toml",
                "the guard's own configuration",
            ),
            ("/home/dev/.ssh/authorized_keys", "SSH"),
            ("/home/dev/.bashrc", "startup files"),
            ("~/.zshrc", "startup files"),
            ("/HOME/DEV/.ZSHRC", "startup files"),
            ("/home/dev/.config/fish/config.fish", "startup files"),
            (
                "/home/dev/.config/systemd/user/x.service",
                "your account starts",
            ),
            (
                "/home/dev/Library/LaunchAgents/com.x.plist",
                "your account starts",
            ),
            ("/home/dev/.aws/credentials", "credentials"),
            ("/home/dev/.docker/config.json", "credentials"),
            ("/home/dev/.npmrc", "credentials"),
            ("/home/dev/.git-credentials", "git credentials"),
            ("/etc/cron.d/job", "schedule"),
            ("/var/spool/cron/crontabs/dev", "schedule"),
            ("/etc/sudoers.d/dev", "sudo"),
        ] {
            let found = privileged_file_write(path, &ctx)
                .unwrap_or_else(|| panic!("{path} must be refused"));
            assert!(found.contains(what), "{path}: {found}");
        }
    }

    /// The guard rule of the row: ordinary project edits are never refused,
    /// including files that share a name with a privileged one but sit in a
    /// project, and the work of an agent that runs as root in its own home.
    #[test]
    fn project_edits_are_never_refused() {
        let home = Path::new("/home/dev");
        let cwd = Path::new("/home/dev/proj");
        let ctx = context(home, cwd);
        for path in [
            "/home/dev/proj/src/main.rs",
            "src/main.rs",
            "./README.md",
            "/home/dev/proj/.npmrc",
            "/home/dev/proj/.profile.example",
            "/home/dev/proj/config/.bashrc",
            "/home/dev/proj/.claude/agents/reviewer.md",
            "/home/dev/proj/.claude/commands/x.md",
            "/home/dev/proj/CLAUDE.md",
            "/home/dev/proj/.env",
            "/home/dev/notes.md",
            "/home/dev/.config/systemd-like/x",
            "/tmp/scratch.txt",
        ] {
            assert_eq!(privileged_file_write(path, &ctx), None, "{path}");
        }
        let root = context(Path::new("/root"), Path::new("/root/proj"));
        assert_eq!(privileged_file_write("/root/proj/src/main.rs", &root), None);
        assert!(privileged_file_write("/root/.bashrc", &root).is_some());
        assert!(privileged_file_write("/root/.claude/settings.json", &root).is_some());
        // Root's home is still root's to an agent that is not root.
        assert_eq!(privileged_file_write("/root/proj/x", &ctx), Some(ROOT_HOME));
    }

    #[test]
    fn the_guards_own_program_is_refused() {
        let ctx = WriteContext {
            cwd: Some(Path::new("/w")),
            home: Some(Path::new("/home/dev")),
            guard_program: Some(Path::new("/opt/tools/innerwarden")),
        };
        assert_eq!(
            privileged_file_write("/opt/tools/innerwarden", &ctx),
            Some(GUARD_PROGRAM)
        );
        assert_eq!(privileged_file_write("/opt/tools/other", &ctx), None);
    }

    /// A link made in the project earlier does not step around the list,
    /// including one whose target does not exist yet.
    ///
    /// FAILS ON REVERT: judge only the path as written and both links pass.
    #[cfg(unix)]
    #[test]
    fn a_link_in_the_project_is_followed_to_what_it_writes() {
        let dir = tempfile::TempDir::new().unwrap();
        let home = dir.path().join("home");
        let proj = home.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(home.join(".claude/settings.json"), "{}").unwrap();
        std::os::unix::fs::symlink(home.join(".claude/settings.json"), proj.join("cfg.json"))
            .unwrap();
        std::os::unix::fs::symlink(home.join(".claude"), proj.join("dot")).unwrap();
        // Dangling: the unit does not exist yet, and writing creates it.
        std::os::unix::fs::symlink(
            home.join(".config/systemd/user/x.service"),
            proj.join("unit"),
        )
        .unwrap();
        // `..` after a link steps out of the link's target: `cfgdir/..` is
        // the home, not the project.
        std::fs::create_dir_all(home.join(".config")).unwrap();
        std::os::unix::fs::symlink(home.join(".config"), proj.join("cfgdir")).unwrap();
        let ctx = context(&home, &proj);
        for path in ["cfg.json", "dot/settings.json", "unit", "cfgdir/../.bashrc"] {
            assert!(
                privileged_file_write(path, &ctx).is_some(),
                "{path} must be judged where it writes"
            );
        }
        std::fs::write(proj.join("plain.txt"), "x").unwrap();
        assert_eq!(privileged_file_write("plain.txt", &ctx), None);
    }

    /// The same file under another name is the same file: a hard link made
    /// in the project, the real file a home link points at (dotfiles kept in
    /// a repository), a new file in a privileged directory reached that way,
    /// and a hard link to the guard's own program.
    ///
    /// FAILS ON REVERT: drop `same_as_a_privileged_file` from
    /// `privileged_file_write` and every path here is allowed.
    #[cfg(unix)]
    #[test]
    fn the_same_file_under_another_name_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let home = dir.path().join("home");
        let proj = home.join("proj");
        let dotfiles = home.join("dotfiles");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(dotfiles.join("fish")).unwrap();
        std::fs::create_dir_all(home.join(".config")).unwrap();
        std::fs::write(home.join(".claude/settings.json"), "{}").unwrap();
        std::fs::hard_link(home.join(".claude/settings.json"), proj.join("notes.json")).unwrap();
        std::fs::write(dotfiles.join("bashrc"), "").unwrap();
        std::os::unix::fs::symlink(dotfiles.join("bashrc"), home.join(".bashrc")).unwrap();
        std::os::unix::fs::symlink(dotfiles.join("fish"), home.join(".config/fish")).unwrap();
        let tools = dir.path().join("tools");
        std::fs::create_dir_all(&tools).unwrap();
        std::fs::write(tools.join("innerwarden"), "").unwrap();
        std::fs::hard_link(tools.join("innerwarden"), proj.join("helper")).unwrap();
        let guard = tools.join("innerwarden");
        let ctx = WriteContext {
            cwd: Some(&proj),
            home: Some(&home),
            guard_program: Some(&guard),
        };
        for (path, what) in [
            ("notes.json", "the guard's own configuration"),
            ("../dotfiles/bashrc", "startup files"),
            ("../dotfiles/fish/conf.d/new.fish", "startup files"),
            ("helper", GUARD_PROGRAM),
        ] {
            let found = privileged_file_write(path, &ctx)
                .unwrap_or_else(|| panic!("{path} is a privileged file under another name"));
            assert!(found.contains(what), "{path}: {found}");
        }
        // A plain file beside them, and a dotfile that is no link, are not.
        std::fs::write(dotfiles.join("README.md"), "").unwrap();
        std::fs::write(proj.join("plain.json"), "{}").unwrap();
        for path in ["plain.json", "../dotfiles/README.md", "new.txt"] {
            assert_eq!(privileged_file_write(path, &ctx), None, "{path}");
        }
    }

    /// A hook run without `HOME` still knows the account's home, from the
    /// account database, so the home list does not fall away.
    ///
    /// FAILS ON REVERT: without `home_of_this_account` the path below is
    /// judged as an unknown home (allowed) or as root's home, not as a
    /// startup file.
    #[cfg(unix)]
    #[test]
    fn with_no_home_set_the_accounts_own_home_is_used() {
        let Some(home) = home_of_this_account() else {
            return;
        };
        let ctx = WriteContext {
            cwd: Some(Path::new("/")),
            home: None,
            guard_program: None,
        };
        let path = home.join(".bashrc");
        let found = privileged_file_write(&path.to_string_lossy(), &ctx)
            .unwrap_or_else(|| panic!("{} must be refused with HOME unset", path.display()));
        assert!(found.contains("startup files"), "{found}");
    }

    #[test]
    fn a_relative_path_with_no_working_directory_is_judged_as_far_as_it_can_be() {
        let ctx = WriteContext::default();
        assert!(privileged_file_write(".claude/settings.json", &ctx).is_some());
        assert_eq!(privileged_file_write("src/main.rs", &ctx), None);
    }

    #[test]
    fn the_refusal_says_what_and_who_may_change_it() {
        let verdict = refusal_verdict("Edit", "/h/.claude/settings.json", "the x");
        assert_eq!(verdict["recommendation"], "deny");
        assert_eq!(verdict["signals"][0]["signal"], "privileged_file_write");
        let text = verdict["explanation"].as_str().unwrap();
        assert!(text.contains("Edit would change `/h/.claude/settings.json`"));
        assert!(text.contains("make it yourself"));
    }
}
