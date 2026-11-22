//! The shared `agents` orchestration: discover the AI agents on this machine and
//! wire the guard into them (Claude Code hook, the Codex and Gemini hook beside
//! their MCP proxy, or MCP-proxy wrap of an agent's reviewed agent-specific
//! config). This is the ONE implementation both InnerWarden Community
//! (`innerwarden`) and Active Defence (`innerwarden` ctl) drive, so the command
//! behaves identically in both products. The pure decision logic lives in
//! `agents` / `mcp_wire` / `hook`; this module is the I/O (the /proc scan, the
//! config-dir stat, the file read/write)
//! and returns the lines to print, so each CLI is a thin `println` wrapper.

use std::ffi::OsStr;
use std::path::Path;

use serde_json::Value;

use crate::agent_hooks::{self, HookSpec, HookState};
use crate::agents::{
    canonical, connect_targets, summarize_discovered, AgentStatus, ConfigFormat, DiscoveryEvidence,
    GuardMode, KnownDiscovery, ProfileConfig, KNOWN,
};
use crate::signatures::SignatureIndex;
use crate::{detect, hermes_hook, hook, mcp_wire, mcp_wire_toml, mcp_wire_yaml};

const MAX_GENERIC_MCP_CONFIGS: usize = 256;
const MAX_GENERIC_DIRECTORY_ENTRIES: usize = 4_096;
const MAX_GENERIC_MCP_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PROFILE_DIRECTORY_ENTRIES: usize = 4_096;

#[derive(Debug, Default)]
struct HomeMcpDiscovery {
    paths: Vec<String>,
    limited: bool,
}

/// Running agents from the signature process scan (`/proc` on Linux, the
/// kernel's process table on macOS), as (name, pid). Empty where neither can
/// be read (Windows): the config-dir pass still finds installed agents there.
fn scan_running() -> Vec<(String, u32)> {
    let index = SignatureIndex::new();
    // Config discovery happens once below against this user's home. A dashboard
    // poll for running state must not also walk every system home directory.
    detect::scan_processes(&index)
        .into_iter()
        .map(|a| (a.name, a.pid))
        .collect()
}

/// Check exact executable basenames through filesystem metadata only. Agent
/// binaries are never launched (including with `--version`) during discovery.
fn executable_on_path(names: &[&str], path_env: Option<&OsStr>) -> bool {
    find_on_path(names, path_env).is_some()
}

/// The first executable file a `PATH` walk finds for any of `names`,
/// metadata only, never run.
fn find_on_path(names: &[&str], path_env: Option<&OsStr>) -> Option<std::path::PathBuf> {
    let path_env = path_env?;
    std::env::split_paths(path_env)
        .filter(|directory| !directory.as_os_str().is_empty())
        .find_map(|directory| {
            names.iter().find_map(|name| {
                let direct = directory.join(name);
                if executable_file(&direct) {
                    return Some(direct);
                }
                #[cfg(windows)]
                {
                    ["exe", "cmd", "bat", "com"].iter().find_map(|extension| {
                        let candidate = directory.join(format!("{name}.{extension}"));
                        executable_file(&candidate).then_some(candidate)
                    })
                }
                #[cfg(not(windows))]
                None
            })
        })
}

fn executable_file(path: &Path) -> bool {
    path_fact(path) == hook::ProgramFact::Executable
}

/// What a failed metadata lookup says about a path. The path, or a directory
/// on the way to it, not existing is `Missing`. Anything else (permission
/// denied, an I/O error) means the look itself failed: `Unreadable`, which is
/// never reported as a broken hook. Split out of [`path_fact`] so the answer
/// for each error is tested without a filesystem that denies anything, which
/// a test running as root would never see.
fn failed_lookup_fact(kind: std::io::ErrorKind) -> hook::ProgramFact {
    match kind {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => {
            hook::ProgramFact::Missing
        }
        _ => hook::ProgramFact::Unreadable,
    }
}

/// What is at `path`, from metadata alone. Nothing is ever executed.
///
/// "Not there" and "could not look" are different answers: only the first may
/// be reported as a broken hook.
fn path_fact(path: &Path) -> hook::ProgramFact {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return failed_lookup_fact(error.kind()),
    };
    if !metadata.is_file() {
        return hook::ProgramFact::NotExecutable;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return hook::ProgramFact::NotExecutable;
        }
    }
    hook::ProgramFact::Executable
}

/// Look for the program a hook runs, WITHOUT running it: file metadata for a
/// path, and the same metadata-only `PATH` walk discovery uses for a bare name.
/// A path relative to a directory is not looked up at all, because it is
/// relative to wherever the agent starts; [`hook::judge_hook_program`] says so.
pub fn program_fact(program: &str, path_env: Option<&OsStr>) -> hook::ProgramFact {
    if !program.contains(['/', '\\']) {
        return if executable_on_path(&[program], path_env) {
            hook::ProgramFact::Executable
        } else {
            hook::ProgramFact::Missing
        };
    }
    if !Path::new(program).is_absolute() {
        return hook::ProgramFact::Unreadable;
    }
    path_fact(Path::new(program))
}

/// The one answer to "does Claude Code's hook screen Bash right now": a
/// recognised hook under a matcher that covers Bash, whose program is there to
/// start. A hook that could not be checked still counts, because "could not
/// tell" is never "off"; one whose program is gone does not, because it
/// screens nothing.
fn claude_hook_screens(settings: &Value, path_env: Option<&OsStr>) -> bool {
    let places = usual_bin_dirs();
    matches!(
        hook::judge_iwguard_hooks(settings, |program| {
            hook_program_fact(program, path_env, &places)
        }),
        Some(hook::HookProgram::Runs | hook::HookProgram::Unknown { .. })
    )
}

/// How long this agent waits for the InnerWarden hook that screens its Bash
/// calls ([`hook::iwguard_bash_hook_timeout`]): `None` for an agent guarded
/// some other way, with no such hook, or whose settings could not be read.
pub fn hook_timeout(home: &Path, agent: &AgentStatus) -> Option<Option<u64>> {
    if !agent.hookable {
        return None;
    }
    hook::iwguard_bash_hook_timeout(&read_json(&home.join(".claude/settings.json"))?)
}

/// Whether the hook this agent is wired with runs a program that is there.
/// `None` for an agent guarded some other way, or with no InnerWarden hook that
/// screens Bash. Shared by `status`, `agents` and the dashboard so all three
/// give the same answer.
pub fn hook_program(home: &Path, agent: &AgentStatus) -> Option<hook::HookProgram> {
    if !agent.hookable {
        return None;
    }
    let settings = read_json(&home.join(".claude/settings.json"))?;
    let path_env = std::env::var_os("PATH");
    hook_program_with(&settings, path_env.as_deref(), &usual_bin_dirs())
}

fn hook_program_with(
    settings: &Value,
    path_env: Option<&OsStr>,
    places: &[std::path::PathBuf],
) -> Option<hook::HookProgram> {
    let verdict = hook::judge_iwguard_hooks(settings, |program| {
        hook_program_fact(program, path_env, places)
    })?;
    Some(with_bare_name_clue(verdict, path_env, places))
}

/// Where a guard installed under a bare name usually lives, beyond `PATH`:
/// a shell that runs a hook may have a PATH this process lacks, and these are
/// the directories installers write to.
fn usual_bin_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(home) = hook::home_dir() {
        dirs.push(home.join(".local/bin"));
    }
    for dir in ["/usr/local/bin", "/usr/bin", "/opt/homebrew/bin"] {
        dirs.push(std::path::PathBuf::from(dir));
    }
    dirs
}

/// A bare name found here: on this process's `PATH`, else in one of
/// `places`. Metadata only, never run.
fn find_bare_name(
    program: &str,
    path_env: Option<&OsStr>,
    places: &[std::path::PathBuf],
) -> Option<std::path::PathBuf> {
    find_on_path(&[program], path_env).or_else(|| {
        places
            .iter()
            .map(|dir| dir.join(program))
            .find(|candidate| executable_file(candidate))
    })
}

/// [`program_fact`] for a hook's program: a bare name is looked for on this
/// PATH AND in the usual places, so "found nowhere" (off) is only said when
/// the agent will likely not find it either.
fn hook_program_fact(
    program: &str,
    path_env: Option<&OsStr>,
    places: &[std::path::PathBuf],
) -> hook::ProgramFact {
    if program.contains(['/', '\\']) {
        return program_fact(program, path_env);
    }
    if find_bare_name(program, path_env, places).is_some() {
        hook::ProgramFact::Executable
    } else {
        hook::ProgramFact::Missing
    }
}

/// A bare name's "could not tell", with where it was found here as a clue.
/// Any other verdict as it is.
fn with_bare_name_clue(
    verdict: hook::HookProgram,
    path_env: Option<&OsStr>,
    places: &[std::path::PathBuf],
) -> hook::HookProgram {
    match verdict {
        hook::HookProgram::Unknown { program, why }
            if !program.contains(['/', '\\']) && why.starts_with(hook::BARE_NAME) =>
        {
            let found = find_bare_name(&program, path_env, places);
            let why = format!("{why}{}", hook::bare_name_clue(found.as_deref()));
            hook::HookProgram::Unknown { program, why }
        }
        other => other,
    }
}

/// Each hook line in this agent's settings that names the guard but is not
/// the guard's own line ([`hook::WrappedHook`]), with its verdict. Empty for
/// an agent guarded some other way. `status` names every one, so a line
/// written by hand never vanishes from the report.
pub fn wrapped_hooks(
    home: &Path,
    agent: &AgentStatus,
) -> Vec<(hook::WrappedHook, hook::HookProgram)> {
    if !agent.hookable {
        return Vec::new();
    }
    let Some(settings) = read_json(&home.join(".claude/settings.json")) else {
        return Vec::new();
    };
    let path_env = std::env::var_os("PATH");
    wrapped_hooks_with(&settings, path_env.as_deref())
}

fn wrapped_hooks_with(
    settings: &Value,
    path_env: Option<&OsStr>,
) -> Vec<(hook::WrappedHook, hook::HookProgram)> {
    hook::wrapped_iwguard_hooks(settings)
        .into_iter()
        .map(|wrapped| {
            let verdict =
                hook::judge_wrapped_hook(&wrapped, program_fact(&wrapped.program, path_env));
            (wrapped, verdict)
        })
        .collect()
}

/// Whether any known agent is running, from the process scan alone (a row's
/// pids), never from an agent being installed or having a config dir.
/// `None` where the scan cannot look (no `/proc` on Linux, no process table
/// read on macOS, Windows): "none running" would be
/// a claim nothing measured.
pub fn any_agent_running(rows: &[AgentStatus]) -> Option<bool> {
    any_agent_running_with(rows, detect::process_scan_can_look())
}

/// PURE: [`any_agent_running`] with whether the process scan could look.
pub fn any_agent_running_with(rows: &[AgentStatus], scan_could_look: bool) -> Option<bool> {
    scan_could_look.then(|| rows.iter().any(|row| !row.pids.is_empty()))
}

/// The tools a wired agent's hooks leave unscreened while its Bash hook runs:
/// a file-tool, read-tool or result hook whose program is gone. Empty when the
/// Bash hook itself does not run (that is [`hook_program`]'s answer, and the
/// whole agent is off) or for an agent guarded some other way. Shared by
/// `status` and `agents` so the two give the same answer.
pub fn unscreened_hooks(home: &Path, agent: &AgentStatus) -> Vec<hook::UnscreenedHooks> {
    if !agent.hookable {
        return Vec::new();
    }
    let Some(settings) = read_json(&home.join(".claude/settings.json")) else {
        return Vec::new();
    };
    let path_env = std::env::var_os("PATH");
    let places = usual_bin_dirs();
    let fact = |program: &str| hook_program_fact(program, path_env.as_deref(), &places);
    match hook::judge_iwguard_hooks(&settings, fact) {
        Some(hook::HookProgram::Runs) => hook::unscreened_iwguard_hooks(&settings, fact),
        _ => Vec::new(),
    }
}

/// PURE: judge one MCP proxy wrapper's program from what the caller found
/// when it looked. The same facts and the same rule as a hook's program
/// ([`hook::judge_hook_program`]), worded for what goes wrong: an MCP client
/// that cannot start the wrapper cannot start the server behind it.
///
/// A bare name is found on the PATH of the MCP client that starts the
/// wrapper, which is not this process's: found here, it is "could not tell"
/// (the client may resolve another, or none); found nowhere here, off.
pub fn judge_proxy_program(program: &str, fact: hook::ProgramFact) -> hook::HookProgram {
    use hook::{HookProgram, ProgramFact};
    let bare = !program.contains(['/', '\\']);
    if bare {
        return match fact {
            ProgramFact::Missing | ProgramFact::NotExecutable => HookProgram::Broken {
                program: program.to_string(),
                problem: format!(
                    "its MCP proxy runs `{program}`, which is not on PATH: {}",
                    hook::BARE_NOT_FOUND
                ),
            },
            ProgramFact::Executable | ProgramFact::Unreadable => HookProgram::Unknown {
                program: program.to_string(),
                why: format!("{}: its MCP proxy runs `{program}`", hook::BARE_NAME),
            },
        };
    }
    if !bare && !Path::new(program).is_absolute() {
        return HookProgram::Unknown {
            program: program.to_string(),
            why: format!(
                "its MCP proxy runs {program}, a path relative to wherever the agent starts, \
                 so I cannot check it from here"
            ),
        };
    }
    let what = match fact {
        ProgramFact::Executable => return HookProgram::Runs,
        ProgramFact::Unreadable => {
            return HookProgram::Unknown {
                program: program.to_string(),
                why: format!(
                    "its MCP proxy runs {program}, and I could not look to see if it is there"
                ),
            }
        }
        ProgramFact::Missing => format!("{program}, which does not exist"),
        ProgramFact::NotExecutable => format!("{program}, which is not an executable file"),
    };
    HookProgram::Broken {
        program: program.to_string(),
        problem: format!("its MCP proxy runs {what}"),
    }
}

/// PURE: across every wrapper in one config, as for hooks: one that runs is
/// enough, short of that one that could not be checked makes it unknown
/// ("could not tell" is never "off"), and only then is it broken. `None` when
/// the config has no wrapper.
fn judge_proxy_programs(
    programs: &[String],
    fact: impl Fn(&str) -> hook::ProgramFact,
) -> Option<hook::HookProgram> {
    let verdicts: Vec<hook::HookProgram> = programs
        .iter()
        .map(|program| judge_proxy_program(program, fact(program)))
        .collect();
    if verdicts.contains(&hook::HookProgram::Runs) {
        return Some(hook::HookProgram::Runs);
    }
    verdicts
        .iter()
        .find(|verdict| matches!(verdict, hook::HookProgram::Unknown { .. }))
        .or_else(|| verdicts.first())
        .cloned()
}

/// The proxy wrappers' programs in one MCP config, read as written.
fn mcp_wrapper_programs(
    home: &Path,
    mcp_json: Option<&str>,
    mcp_toml: Option<&str>,
    mcp_yaml: Option<&str>,
) -> Vec<String> {
    if let Some(relative) = mcp_json {
        return read_json(&home.join(relative))
            .map(|config| mcp_wire::guard_wrapper_commands(&config))
            .unwrap_or_default();
    }
    if let Some(relative) = mcp_yaml {
        return read_yaml(&home.join(relative))
            .map(|config| mcp_wire::guard_wrapper_commands(&config))
            .unwrap_or_default();
    }
    if let Some(relative) = mcp_toml {
        return read_toml(&home.join(relative))
            .map(|document| mcp_wire_toml::guard_wrapper_commands_toml(&document))
            .unwrap_or_default();
    }
    Vec::new()
}

/// Whether the proxy an MCP agent's servers are wrapped in is there to start.
/// `None` for a hook agent, or one with no InnerWarden wrapper.
///
/// A wrapper is only text, like a hook. Its binary removed (an uninstalled
/// or moved CLI), the agent's MCP servers fail to start: closed, not open,
/// but the row went on reading "guarded" because only the text was judged.
pub fn mcp_proxy_program(home: &Path, agent: &AgentStatus) -> Option<hook::HookProgram> {
    if agent.hookable {
        return None;
    }
    let path_env = std::env::var_os("PATH");
    mcp_proxy_program_with(home, agent, path_env.as_deref(), &usual_bin_dirs())
}

fn mcp_proxy_program_with(
    home: &Path,
    agent: &AgentStatus,
    path_env: Option<&OsStr>,
    places: &[std::path::PathBuf],
) -> Option<hook::HookProgram> {
    let programs = mcp_wrapper_programs(
        home,
        agent.mcp_json.as_deref(),
        agent.mcp_toml.as_deref(),
        agent.mcp_yaml.as_deref(),
    );
    let verdict = judge_proxy_programs(&programs, |program| {
        hook_program_fact(program, path_env, places)
    })?;
    Some(with_bare_name_clue(verdict, path_env, places))
}

/// Whether wrappers that are all known to be unable to start leave this
/// config's guard broken. Unknown and runs are not broken. A bare name is
/// looked for here as a hook's is ([`hook_program_fact`]): off only when it
/// is found nowhere.
fn proxy_is_broken(programs: &[String], path_env: Option<&OsStr>) -> bool {
    let places = usual_bin_dirs();
    matches!(
        judge_proxy_programs(programs, |program| {
            hook_program_fact(program, path_env, &places)
        }),
        Some(hook::HookProgram::Broken { .. })
    )
}

/// The command that rewrites an MCP agent's wrappers to the binary the user
/// runs it with, in the mode they already have. Never an unwrap: removing
/// the wrappers because their binary is gone would silently take the guard
/// off servers that now fail closed.
pub fn proxy_repair_command(home: &Path, agent: &AgentStatus) -> String {
    let monitor = match (agent.mcp_json.as_deref(), agent.mcp_toml.as_deref()) {
        (Some(relative), _) => read_json(&home.join(relative))
            .and_then(|config| mcp_wire::guarded_mode(&config))
            .is_some_and(|mode| mode == mcp_wire::WiringMode::Monitor),
        (None, Some(relative)) => read_toml(&home.join(relative))
            .and_then(|document| mcp_wire_toml::guarded_mode_toml(&document))
            .is_some_and(|mode| mode == mcp_wire_toml::WiringMode::Monitor),
        (None, None) => agent
            .mcp_yaml
            .as_deref()
            .and_then(|relative| read_yaml(&home.join(relative)))
            .and_then(|config| mcp_wire::guarded_mode(&config))
            .is_some_and(|mode| mode == mcp_wire::WiringMode::Monitor),
    };
    let flag = if monitor { " --monitor" } else { "" };
    format!("innerwarden agents connect {}{flag}", agent.name)
}

/// The command that rewrites this agent's hook to point at the binary the user
/// runs it with, in the mode the hook already has. It is the per-agent
/// `install` command the CLI names everywhere else, never a second spelling.
pub fn hook_repair_command(home: &Path, agent: &AgentStatus) -> String {
    let install = crate::hook_targets::by_id(&agent.name)
        .map(crate::hook_targets::guidance)
        .unwrap_or_else(|| format!("innerwarden install {}", agent.name));
    let flag = read_json(&home.join(".claude/settings.json"))
        .map(|settings| hook::install_mode_flag(&settings))
        .unwrap_or("");
    format!("{install}{flag}")
}

fn marker_exists_without_following_symlinks(home: &Path, relative: &str) -> bool {
    std::fs::symlink_metadata(home.join(relative))
        .map(|metadata| {
            !metadata.file_type().is_symlink() && (metadata.is_dir() || metadata.is_file())
        })
        .unwrap_or(false)
}

fn valid_config_file(home: &Path, relative: &str, format: ConfigFormat) -> bool {
    let path = home.join(relative);
    let Ok(Some(bytes)) = crate::file_update::read_config_no_symlinks(home, &path) else {
        return false;
    };
    match format {
        ConfigFormat::JsonObject => serde_json::from_slice::<Value>(&bytes)
            .ok()
            .is_some_and(|value| value.is_object()),
        ConfigFormat::Json5Object => json5_object_has_balanced_shape(&bytes),
        ConfigFormat::Toml => std::str::from_utf8(&bytes)
            .ok()
            .and_then(|body| body.parse::<toml_edit::DocumentMut>().ok())
            .is_some(),
        ConfigFormat::YamlMapping => serde_yaml::from_slice::<serde_yaml::Value>(&bytes)
            .ok()
            .is_some_and(|value| value.is_mapping()),
    }
}

/// Conservative JSON5 container validation without normalizing or rewriting the
/// file. OpenClaw accepts JSON5, so strict `serde_json` would reject valid
/// comments/trailing commas; this scanner only establishes a balanced top-level
/// object and rejects truncated strings/comments/brackets.
fn json5_object_has_balanced_shape(bytes: &[u8]) -> bool {
    if std::str::from_utf8(bytes).is_err() {
        return false;
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Normal,
        SingleQuoted,
        DoubleQuoted,
        LineComment,
        BlockComment,
    }

    let mut state = State::Normal;
    let mut escaped = false;
    let mut delimiters = Vec::new();
    let mut started = false;
    let mut finished = false;
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            State::SingleQuoted | State::DoubleQuoted => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if (state == State::SingleQuoted && byte == b'\'')
                    || (state == State::DoubleQuoted && byte == b'"')
                {
                    state = State::Normal;
                }
            }
            State::LineComment => {
                if byte == b'\n' || byte == b'\r' {
                    state = State::Normal;
                }
            }
            State::BlockComment => {
                if byte == b'*' && next == Some(b'/') {
                    state = State::Normal;
                    index += 1;
                }
            }
            State::Normal => {
                if byte == b'/' && next == Some(b'/') {
                    state = State::LineComment;
                    index += 1;
                } else if byte == b'/' && next == Some(b'*') {
                    state = State::BlockComment;
                    index += 1;
                } else if byte.is_ascii_whitespace()
                    || (!started && bytes[index..].starts_with(&[0xEF, 0xBB, 0xBF]))
                {
                    if !started && bytes[index..].starts_with(&[0xEF, 0xBB, 0xBF]) {
                        index += 2;
                    }
                } else if !started {
                    if byte != b'{' {
                        return false;
                    }
                    started = true;
                    delimiters.push(b'{');
                } else if finished {
                    return false;
                } else {
                    match byte {
                        b'\'' => state = State::SingleQuoted,
                        b'"' => state = State::DoubleQuoted,
                        b'{' => delimiters.push(b'{'),
                        b'}' => {
                            if delimiters.pop() != Some(b'{') {
                                return false;
                            }
                            if delimiters.is_empty() {
                                finished = true;
                            }
                        }
                        b'[' => delimiters.push(b'['),
                        b']' if delimiters.pop() != Some(b'[') => return false,
                        b']' => {}
                        _ => {}
                    }
                }
            }
        }
        index += 1;
    }
    started
        && finished
        && delimiters.is_empty()
        && matches!(state, State::Normal | State::LineComment)
}

fn profile_configuration_found(home: &Path, profile: ProfileConfig) -> (bool, bool) {
    let Ok(entries) = std::fs::read_dir(home) else {
        return (false, false);
    };
    let mut limited = false;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_PROFILE_DIRECTORY_ENTRIES {
            limited = true;
            break;
        }
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(profile_name) = name.strip_prefix(profile.directory_prefix) else {
            continue;
        };
        if profile_name.is_empty() {
            continue;
        }
        let relative = format!("{name}/{}", profile.file_name);
        if valid_config_file(home, &relative, profile.format) {
            return (true, limited);
        }
    }
    (false, limited)
}

fn discover_known(home: &Path, path_env: Option<&OsStr>) -> (Vec<KnownDiscovery>, bool) {
    let mut discoveries = Vec::new();
    let mut limited = false;
    for known in KNOWN {
        let mut evidence = Vec::new();
        if executable_on_path(known.executables, path_env) {
            evidence.push(DiscoveryEvidence::ExecutableOnPath);
        }
        let direct_config = known
            .config_files
            .iter()
            .any(|(relative, format)| valid_config_file(home, relative, *format));
        let profile_config = known.profile_config.is_some_and(|profile| {
            let (found, profile_limited) = profile_configuration_found(home, profile);
            limited |= profile_limited;
            found
        });
        if direct_config || profile_config {
            evidence.push(DiscoveryEvidence::ConfigurationFile);
        }
        if evidence.is_empty() && marker_exists_without_following_symlinks(home, known.config_dir) {
            evidence.push(DiscoveryEvidence::PossibleLeftover);
        }
        if !evidence.is_empty() {
            discoveries.push(KnownDiscovery { known, evidence });
        }
    }
    (discoveries, limited)
}

/// Discover conventional JSON MCP configurations without crawling the user's
/// projects or following symlinks. Besides the known agent paths, support a
/// generic `~/.<agent>/mcp.json` and `~/.config/<agent>/mcp.json`. That lets a new
/// MCP-capable client be surfaced and connected before InnerWarden has shipped a
/// named signature for it, while keeping the scan narrow and predictable.
fn home_mcp_configs_with_status(home: &Path) -> HomeMcpDiscovery {
    fn scan_children(
        home: &Path,
        root: &Path,
        prefix: &str,
        dot_only: bool,
    ) -> (Vec<(String, u64)>, bool) {
        let Ok(entries) = std::fs::read_dir(root) else {
            return (Vec::new(), false);
        };
        let mut candidates = Vec::new();
        let mut seen = 0usize;
        let mut limited = false;
        for entry in entries {
            seen += 1;
            if seen > MAX_GENERIC_DIRECTORY_ENTRIES {
                limited = true;
                break;
            }
            let Ok(entry) = entry else {
                continue;
            };
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() || file_type.is_symlink() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if dot_only && (!name.starts_with('.') || name == ".config") {
                continue;
            }
            let candidate = entry.path().join("mcp.json");
            let Ok(metadata) = candidate.symlink_metadata() else {
                continue;
            };
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                continue;
            }
            let Ok(rel) = candidate.strip_prefix(home) else {
                continue;
            };
            let rendered = rel.to_string_lossy().replace('\\', "/");
            if prefix.is_empty() || rendered.starts_with(prefix) {
                candidates.push((rendered, metadata.len()));
            }
        }
        (candidates, limited)
    }

    let (mut candidates, mut limited) = scan_children(home, home, "", true);
    let (configured, config_limited) =
        scan_children(home, &home.join(".config"), ".config/", false);
    candidates.extend(configured);
    limited |= config_limited;
    candidates.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    candidates.dedup_by(|a, b| a.0 == b.0);

    let known_paths: Vec<&str> = KNOWN.iter().filter_map(|known| known.mcp_json).collect();
    let mut paths = Vec::new();
    let mut bytes = 0u64;
    for (path, len) in candidates {
        if known_paths.contains(&path.as_str()) {
            continue;
        }
        if paths.len() >= MAX_GENERIC_MCP_CONFIGS
            || len > crate::file_update::MAX_CONFIG_BYTES
            || bytes.saturating_add(len) > MAX_GENERIC_MCP_BYTES
        {
            limited = true;
            continue;
        }
        bytes = bytes.saturating_add(len);
        paths.push(path);
    }
    HomeMcpDiscovery { paths, limited }
}

#[cfg(test)]
fn home_mcp_configs(home: &Path) -> Vec<String> {
    home_mcp_configs_with_status(home).paths
}

fn generic_mcp_name(rel: &str, rows: &[AgentStatus]) -> String {
    let base = Path::new(rel)
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .trim_start_matches('.')
        .to_ascii_lowercase()
        .replace([' ', '_'], "-");
    let base = if base.is_empty() { "unknown" } else { &base };
    let available = |name: &str| {
        rows.iter().all(|row| row.name != name) && KNOWN.iter().all(|known| known.name != name)
    };
    if available(base) {
        return base.to_string();
    }
    let candidate = format!("{base}-mcp");
    if available(&candidate) {
        return candidate;
    }
    let mut suffix = 2usize;
    loop {
        let candidate = format!("{base}-mcp-{suffix}");
        if available(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

fn read_json(path: &Path) -> Option<Value> {
    crate::file_update::read_config(path)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

fn read_config_for_update(
    trusted_root: &Path,
    path: &Path,
    reject_symlinks: bool,
) -> Result<Option<Vec<u8>>, String> {
    if reject_symlinks {
        crate::file_update::read_config_no_symlinks(trusted_root, path)
    } else {
        crate::file_update::read_config(path)
    }
}

fn read_json_for_update(
    trusted_root: &Path,
    path: &Path,
    reject_symlinks: bool,
) -> Result<Option<(Value, Vec<u8>)>, String> {
    let Some(source) = read_config_for_update(trusted_root, path, reject_symlinks)? else {
        return Ok(None);
    };
    let value = serde_json::from_slice(&source)
        .map_err(|error| format!("{} is not valid JSON: {error}", path.display()))?;
    Ok(Some((value, source)))
}

fn write_json(
    trusted_root: &Path,
    path: &Path,
    v: &Value,
    expected: &[u8],
    reject_symlinks: bool,
) -> Result<(), String> {
    // The person's keys stay in their order: only what the guard changed moves.
    let body = crate::json_order::pretty_in_order(Some(expected), v)?;
    if reject_symlinks {
        crate::file_update::replace_if_unchanged_no_symlinks(
            trusted_root,
            path,
            Some(expected),
            body.as_bytes(),
        )
    } else {
        crate::file_update::replace_if_unchanged(path, Some(expected), body.as_bytes())
    }
}

/// A YAML MCP config (Goose's) read as a JSON client's server table
/// ([`mcp_wire_yaml::YamlDoc::view`]), so every decision on it is
/// [`mcp_wire`]'s.
fn read_yaml(path: &Path) -> Option<Value> {
    crate::file_update::read_config(path)
        .ok()
        .flatten()
        .and_then(|bytes| mcp_wire_yaml::view_of_bytes(&bytes))
}

/// Why a YAML MCP config that is there cannot be read ([`read_yaml`] is
/// `None` for it): not text, not one YAML mapping (several documents), a
/// merge key in its extensions. `None` for a config that is missing or
/// reads. Its servers are then not known to be guarded, which the status says
/// rather than "nothing left to guard".
fn yaml_unreadable(path: &Path) -> Option<String> {
    let bytes = match crate::file_update::read_config(path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return None,
        Err(error) => return Some(error),
    };
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text,
        Err(error) => return Some(format!("not valid UTF-8: {error}")),
    };
    mcp_wire_yaml::YamlDoc::parse(text).err()
}

/// The extensions of a YAML MCP config the proxy does not screen, as the
/// words a line says them in (`remote-tools (streamable_http)`); empty when
/// there are none or the config cannot be read.
fn yaml_unscreened(path: &Path) -> Vec<String> {
    crate::file_update::read_config(path)
        .ok()
        .flatten()
        .and_then(|bytes| mcp_wire_yaml::YamlDoc::parse(std::str::from_utf8(&bytes).ok()?).ok())
        .map(|doc| {
            doc.unscreened()
                .into_iter()
                .filter(|(_, kind)| matches!(kind.as_str(), "streamable_http" | "sse"))
                .map(|(name, kind)| format!("{name} ({kind})"))
                .collect()
        })
        .unwrap_or_default()
}

/// The remote extensions the proxy does not screen, as the end of a
/// connect line says them (`; not screened by the proxy: a (sse)`), or
/// nothing.
fn yaml_unscreened_line(doc: &mcp_wire_yaml::YamlDoc) -> String {
    let names: Vec<String> = doc
        .unscreened()
        .into_iter()
        .filter(|(_, kind)| matches!(kind.as_str(), "streamable_http" | "sse"))
        .map(|(name, kind)| format!("{name} ({kind})"))
        .collect();
    if names.is_empty() {
        String::new()
    } else {
        format!("; not screened by the proxy: {}", names.join(", "))
    }
}

/// The extensions of a YAML MCP config that run code inside the agent
/// ([`mcp_wire_yaml::YamlDoc::runs_inside`]), as a line says them.
fn yaml_runs_inside(path: &Path) -> Vec<String> {
    crate::file_update::read_config(path)
        .ok()
        .flatten()
        .and_then(|bytes| mcp_wire_yaml::YamlDoc::parse(std::str::from_utf8(&bytes).ok()?).ok())
        .map(|doc| {
            doc.runs_inside()
                .into_iter()
                .map(|(name, kind)| format!("{name} ({kind})"))
                .collect()
        })
        .unwrap_or_default()
}

fn read_yaml_for_update(
    trusted_root: &Path,
    path: &Path,
    reject_symlinks: bool,
) -> Result<Option<(mcp_wire_yaml::YamlDoc, Vec<u8>)>, String> {
    let Some(source) = read_config_for_update(trusted_root, path, reject_symlinks)? else {
        return Ok(None);
    };
    let body = std::str::from_utf8(&source)
        .map_err(|error| format!("{} is not valid UTF-8: {error}", path.display()))?;
    let document = mcp_wire_yaml::YamlDoc::parse(body)
        .map_err(|error| format!("{} is {error}", path.display()))?;
    Ok(Some((document, source)))
}

fn write_yaml(
    trusted_root: &Path,
    path: &Path,
    doc: &mcp_wire_yaml::YamlDoc,
    expected: &[u8],
    reject_symlinks: bool,
) -> Result<(), String> {
    if reject_symlinks {
        crate::file_update::replace_if_unchanged_no_symlinks(
            trusted_root,
            path,
            Some(expected),
            doc.text().as_bytes(),
        )
    } else {
        crate::file_update::replace_if_unchanged(path, Some(expected), doc.text().as_bytes())
    }
}

fn read_toml(path: &Path) -> Option<toml_edit::DocumentMut> {
    crate::file_update::read_config(path)
        .ok()
        .flatten()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|body| body.parse::<toml_edit::DocumentMut>().ok())
}

fn read_toml_for_update(
    trusted_root: &Path,
    path: &Path,
    reject_symlinks: bool,
) -> Result<Option<(toml_edit::DocumentMut, Vec<u8>)>, String> {
    let Some(source) = read_config_for_update(trusted_root, path, reject_symlinks)? else {
        return Ok(None);
    };
    let body = std::str::from_utf8(&source)
        .map_err(|error| format!("{} is not valid UTF-8: {error}", path.display()))?;
    let document = body
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| format!("{} is not valid TOML: {error}", path.display()))?;
    Ok(Some((document, source)))
}

fn write_toml(
    trusted_root: &Path,
    path: &Path,
    doc: &toml_edit::DocumentMut,
    expected: &[u8],
    reject_symlinks: bool,
) -> Result<(), String> {
    if reject_symlinks {
        crate::file_update::replace_if_unchanged_no_symlinks(
            trusted_root,
            path,
            Some(expected),
            doc.to_string().as_bytes(),
        )
    } else {
        crate::file_update::replace_if_unchanged(path, Some(expected), doc.to_string().as_bytes())
    }
}

/// The hook wiring of an agent that has one beside its MCP proxy (Codex,
/// Gemini), for a name found through that agent's reviewed MCP config. The
/// same name over any other config file is not that agent.
fn hook_spec(
    name: &str,
    mcp_json: Option<&str>,
    mcp_toml: Option<&str>,
) -> Option<&'static HookSpec> {
    let spec = agent_hooks::spec_for(name)?;
    // An agent wired by its hook alone (Antigravity) has no MCP config to
    // match: a row that names one is not that agent.
    if !spec.has_mcp_config() {
        return (mcp_json.is_none() && mcp_toml.is_none()).then_some(spec);
    }
    (mcp_json.or(mcp_toml) == Some(spec.mcp_config)).then_some(spec)
}

fn hook_spec_of(agent: &AgentStatus) -> Option<&'static HookSpec> {
    hook_spec(
        &agent.name,
        agent.mcp_json.as_deref(),
        agent.mcp_toml.as_deref(),
    )
}

fn hook_state_with(
    home: &Path,
    agent: &AgentStatus,
    path_env: Option<&OsStr>,
) -> Option<(&'static HookSpec, HookState)> {
    let spec = hook_spec_of(agent)?;
    Some((spec, agent_hooks::state(home, spec, path_env)))
}

/// Where the blocking hook of Codex or Gemini stands, with the wiring it was
/// read against. `None` for every other agent. Shared by `status` and
/// `agents` so both say the same thing of one hook.
pub fn hook_state(home: &Path, agent: &AgentStatus) -> Option<(&'static HookSpec, HookState)> {
    let path_env = std::env::var_os("PATH");
    hook_state_with(home, agent, path_env.as_deref())
}

/// Whether every stdio server in an agent's MCP config runs behind a proxy
/// that is there to start. `None` when the config is missing, cannot be read,
/// or holds no stdio server: the proxy has nothing to say either way.
fn mcp_guarded(
    home: &Path,
    mcp_json: Option<&str>,
    mcp_toml: Option<&str>,
    path_env: Option<&OsStr>,
) -> Option<bool> {
    if let Some(rel) = mcp_json {
        let v = read_json(&home.join(rel))?;
        return mcp_wire::is_guardable(&v).then(|| {
            mcp_wire::is_guarded(&v)
                && !proxy_is_broken(&mcp_wire::guard_wrapper_commands(&v), path_env)
        });
    }
    let d = read_toml(&home.join(mcp_toml?))?;
    mcp_wire_toml::is_guardable_toml(&d).then(|| {
        mcp_wire_toml::is_guarded_toml(&d)
            && !proxy_is_broken(&mcp_wire_toml::guard_wrapper_commands_toml(&d), path_env)
    })
}

/// Is the guard wired for this agent? Claude Code = the PreToolUse hook; an MCP
/// agent = every stdio server in its config (reviewed JSON or Codex's TOML
/// `[mcp_servers]`) routed through the proxy. Codex and Gemini have both: their
/// MCP servers decide when they have any, and their hook does when they have
/// none, so the hook never hides a server that still runs outside the proxy.
fn is_guarded(home: &Path, agent: &str, path_env: Option<&OsStr>) -> bool {
    let Some(k) = canonical(agent) else {
        return false;
    };
    if k.name == hermes_hook::AGENT {
        return hermes_hook::state(home, path_env).is_on();
    }
    if k.hookable {
        return read_json(&home.join(".claude/settings.json"))
            .map(|v| claude_hook_screens(&v, path_env))
            .unwrap_or(false);
    }
    if let Some(spec) = hook_spec(k.name, k.mcp_json, k.mcp_toml) {
        return mcp_guarded(home, k.mcp_json, k.mcp_toml, path_env)
            .unwrap_or_else(|| agent_hooks::state(home, spec, path_env).is_on());
    }
    if let Some(rel) = k.mcp_json {
        return read_json(&home.join(rel))
            .map(|v| {
                mcp_wire::is_guarded(&v)
                    && !proxy_is_broken(&mcp_wire::guard_wrapper_commands(&v), path_env)
            })
            .unwrap_or(false);
    }
    if let Some(rel) = k.mcp_toml {
        return read_toml(&home.join(rel))
            .map(|d| {
                mcp_wire_toml::is_guarded_toml(&d)
                    && !proxy_is_broken(&mcp_wire_toml::guard_wrapper_commands_toml(&d), path_env)
            })
            .unwrap_or(false);
    }
    if let Some(rel) = k.mcp_yaml {
        // An extension that runs code inside Goose is seen by no proxy: a
        // config that holds one is never counted guarded.
        let path = home.join(rel);
        return read_yaml(&path)
            .map(|v| {
                mcp_wire::is_guarded(&v)
                    && !proxy_is_broken(&mcp_wire::guard_wrapper_commands(&v), path_env)
            })
            .unwrap_or(false)
            && yaml_runs_inside(&path).is_empty();
    }
    false
}

/// Whether this agent has any InnerWarden wiring at all. Unlike `is_guarded`,
/// partial MCP coverage counts: mode switches use this to repair/reconfigure the
/// existing wrappers and bring newly-added local servers under the same posture.
pub fn has_guard_wiring(home: &Path, agent: &str) -> bool {
    // Rows produced by discovery already carry canonical names. Require an exact
    // reviewed name here: substring canonicalization is for process aliases and
    // must never redirect a generic MCP row to a known agent's static path.
    if let Some(k) = KNOWN.iter().find(|known| known.name == agent) {
        if k.name == hermes_hook::AGENT {
            return hermes_hook::state(home, None).installed();
        }
        if k.hookable {
            return read_json(&home.join(".claude/settings.json"))
                .map(|v| hook::has_iwguard_wiring(&v))
                .unwrap_or(false);
        }
        if hook_spec(k.name, k.mcp_json, k.mcp_toml)
            .is_some_and(|spec| agent_hooks::state(home, spec, None).installed())
        {
            return true;
        }
        if let Some(rel) = k.mcp_json {
            return read_json(&home.join(rel))
                .map(|v| mcp_wire::has_guard_wiring(&v))
                .unwrap_or(false);
        }
        if let Some(rel) = k.mcp_toml {
            return read_toml(&home.join(rel))
                .map(|d| mcp_wire_toml::has_guard_wiring_toml(&d))
                .unwrap_or(false);
        }
        if let Some(rel) = k.mcp_yaml {
            return read_yaml(&home.join(rel))
                .map(|v| mcp_wire::has_guard_wiring(&v))
                .unwrap_or(false);
        }
        return false;
    }

    // Generic MCP clients have no static `Known` row. Resolve the narrow-scan
    // status by its stable generated name, then inspect that exact relative path.
    rows(home)
        .into_iter()
        .find(|row| row.name == agent)
        .and_then(|row| row.mcp_json)
        .and_then(|rel| read_json(&home.join(rel)))
        .map(|config| mcp_wire::has_guard_wiring(&config))
        .unwrap_or(false)
}

/// Inspect any recognised wiring using an already-discovered row. Repair and
/// mode-switching callers use this form to avoid rediscovering every generic MCP
/// config once per row; dashboard posture uses [`status_is_effectively_guarded`].
/// Is there guarding work still to do for this agent?
///
/// For a hook agent this is simply "the hook is absent": there is no partial
/// state. For an MCP agent it means at least one stdio server is still open,
/// which is NOT the same as "the file has never been touched". See
/// [`mcp_wire::has_unguarded_stdio_server`].
pub fn status_has_unguarded_server(home: &Path, agent: &AgentStatus) -> bool {
    if agent.name == hermes_hook::AGENT {
        return !hermes_hook::state(home, None).installed();
    }
    // Wired by its hook alone: the hook is the work left.
    if let Some(spec) = hook_spec_of(agent).filter(|spec| !spec.has_mcp_config()) {
        return !agent_hooks::state(home, spec, None).installed();
    }
    if agent.hookable {
        return !read_json(&home.join(".claude/settings.json"))
            .map(|value| hook::has_iwguard_wiring(&value))
            .unwrap_or(false);
    }
    if let Some(relative) = &agent.mcp_json {
        return read_json(&home.join(relative))
            .map(|value| mcp_wire::has_unguarded_stdio_server(&value))
            .unwrap_or(false);
    }
    if let Some(relative) = &agent.mcp_toml {
        return read_toml(&home.join(relative))
            .map(|document| mcp_wire_toml::has_unguarded_stdio_server_toml(&document))
            .unwrap_or(false);
    }
    if let Some(relative) = &agent.mcp_yaml {
        // A config that is there and cannot be read is not "nothing left to
        // guard": what its servers run is not known.
        let path = home.join(relative);
        return match read_yaml(&path) {
            Some(value) => mcp_wire::has_unguarded_stdio_server(&value),
            None => yaml_unreadable(&path).is_some(),
        };
    }
    false
}

pub fn status_has_guard_wiring(home: &Path, agent: &AgentStatus) -> bool {
    if agent.name == hermes_hook::AGENT {
        return hermes_hook::state(home, None).installed();
    }
    if agent.hookable {
        return read_json(&home.join(".claude/settings.json"))
            .map(|value| hook::has_iwguard_wiring(&value))
            .unwrap_or(false);
    }
    // A hook of Codex or Gemini that is in the file counts, on or not: a
    // mode switch has to rewrite its line with the wrappers'.
    if hook_spec_of(agent).is_some_and(|spec| agent_hooks::state(home, spec, None).installed()) {
        return true;
    }
    mcp_has_guard_wiring(home, agent)
}

/// Whether any MCP server of this agent runs behind the proxy.
fn mcp_has_guard_wiring(home: &Path, agent: &AgentStatus) -> bool {
    if let Some(relative) = &agent.mcp_json {
        return read_json(&home.join(relative))
            .map(|value| mcp_wire::has_guard_wiring(&value))
            .unwrap_or(false);
    }
    if let Some(relative) = &agent.mcp_toml {
        return read_toml(&home.join(relative))
            .map(|document| mcp_wire_toml::has_guard_wiring_toml(&document))
            .unwrap_or(false);
    }
    if let Some(relative) = &agent.mcp_yaml {
        return read_yaml(&home.join(relative))
            .map(|value| mcp_wire::has_guard_wiring(&value))
            .unwrap_or(false);
    }
    false
}

/// Whether this discovered row currently provides an effective guardrail signal
/// for dashboard/status purposes. Claude wiring counts only under the exact
/// `PreToolUse:Bash` matcher; a recognised hook under another matcher remains
/// discoverable through [`status_has_guard_wiring`] so automatic reconciliation
/// can repair it without falsely claiming active shell protection.
pub fn status_is_effectively_guarded(home: &Path, agent: &AgentStatus) -> bool {
    if agent.name == hermes_hook::AGENT {
        let path_env = std::env::var_os("PATH");
        return hermes_hook::state(home, path_env.as_deref()).is_on();
    }
    if agent.hookable {
        let path_env = std::env::var_os("PATH");
        return read_json(&home.join(".claude/settings.json"))
            .map(|value| claude_hook_screens(&value, path_env.as_deref()))
            .unwrap_or(false);
    }
    // An agent wired by its hook alone (Antigravity) has nothing else to
    // count: its hook, when the agent runs it.
    if let Some(spec) = hook_spec_of(agent).filter(|spec| !spec.has_mcp_config()) {
        let path_env = std::env::var_os("PATH");
        return agent_hooks::state(home, spec, path_env.as_deref()).is_on();
    }
    // The MCP wiring alone: the dashboard reads the mode of these rows from
    // their MCP config, so the hook of Codex or Gemini is not counted here.
    // `status` and `agents` state that hook on a line of its own.
    mcp_has_guard_wiring(home, agent)
        && !matches!(
            mcp_proxy_program(home, agent),
            Some(hook::HookProgram::Broken { .. })
        )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CompatibleMcpSchema {
    ProxyWrappable,
    NestedVisibilityOnly,
}

fn compatible_mcp_configuration(config: &Value) -> Option<CompatibleMcpSchema> {
    if ["mcpServers", "servers"]
        .iter()
        .any(|key| config.get(key).is_some_and(Value::is_object))
    {
        return Some(CompatibleMcpSchema::ProxyWrappable);
    }
    config
        .get("mcp")
        .and_then(|mcp| mcp.get("servers"))
        .is_some_and(Value::is_object)
        .then_some(CompatibleMcpSchema::NestedVisibilityOnly)
}

fn rows_from_sources(
    home: &Path,
    running: &[(String, u32)],
    path_env: Option<&OsStr>,
) -> (Vec<AgentStatus>, bool) {
    let (discovered, profile_limited) = discover_known(home, path_env);
    let mut rows = summarize_discovered(running, &discovered, |name| {
        is_guarded(home, name, path_env)
    });

    // A valid-looking MCP config is itself a discovery signal. Known paths have
    // richer reviewed rows above; every other match stays a generic MCP client
    // for visibility and explicit/manual setup only.
    let generic = home_mcp_configs_with_status(home);
    for rel in generic.paths {
        if rows
            .iter()
            .any(|row| row.mcp_json.as_deref() == Some(rel.as_str()))
        {
            continue;
        }
        let Some(config) = read_json(&home.join(&rel)) else {
            continue;
        };
        let Some(schema) = compatible_mcp_configuration(&config) else {
            continue;
        };
        let guarded = schema == CompatibleMcpSchema::ProxyWrappable
            && mcp_wire::is_guarded(&config)
            && !proxy_is_broken(&mcp_wire::guard_wrapper_commands(&config), path_env);
        let name = generic_mcp_name(&rel, &rows);
        rows.push(AgentStatus {
            name,
            pids: Vec::new(),
            installed: false,
            evidence: vec![DiscoveryEvidence::CompatibleMcpConfiguration],
            hookable: false,
            // `mcp.servers` proves capability, but the current lossless proxy
            // editor supports only top-level `mcpServers` / `servers`. Keep the
            // nested schema visible without granting connect authority.
            mcp_json: (schema == CompatibleMcpSchema::ProxyWrappable).then_some(rel),
            mcp_toml: None,
            mcp_yaml: None,
            guarded,
            mode: None,
        });
    }
    // Read back what the wiring actually DOES, per agent, so the listing can
    // say "monitor" or "enforce" instead of only "guarded".
    for r in &mut rows {
        if r.guarded {
            r.mode = read_guard_mode(home, r, path_env);
        }
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    (rows, generic.limited || profile_limited)
}

/// All detected agents with the evidence that caused each row to be surfaced.
pub fn rows_with_discovery_status(home: &Path) -> (Vec<AgentStatus>, bool) {
    let running = scan_running();
    let path_env = std::env::var_os("PATH");
    rows_from_sources(home, &running, path_env.as_deref())
}

pub fn rows(home: &Path) -> Vec<AgentStatus> {
    rows_with_discovery_status(home).0
}

/// The detected agents the guard can wire (hook or MCP), for the setup wizard.
pub fn detected_guardable(home: &Path) -> Vec<AgentStatus> {
    rows(home).into_iter().filter(|r| r.guardable()).collect()
}

/// The absolute path to THIS binary, used inside an agent's config so the wiring
/// keeps working regardless of `$PATH`.
pub fn guard_bin() -> String {
    std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "innerwarden".to_string())
}

fn mechanism(r: &AgentStatus) -> &'static str {
    if r.hookable || r.name == hermes_hook::AGENT || r.name == crate::antigravity_hook::AGENT {
        "hook"
    } else if r.mcp_json.is_some() || r.mcp_toml.is_some() || r.mcp_yaml.is_some() {
        "MCP proxy"
    } else {
        "manual"
    }
}

/// The listing's words for Codex or Gemini, which are screened two ways: the
/// hook for shell commands and file changes, the proxy for MCP servers.
///
/// "✓ guarded" is said only with the hook on and no MCP server left outside
/// the proxy. One of the two alone is "partly guarded", and names which one,
/// so a hook the agent skips is never under a check mark.
fn two_way_label(home: &Path, r: &AgentStatus, state: &HookState) -> String {
    let mode = |mode: Option<GuardMode>| mode.map_or("mode unreadable", GuardMode::label);
    match (r.guarded, state.is_on()) {
        (true, true) if mcp_has_guard_wiring(home, r) => {
            format!("✓ guarded (hook + proxy, {})", mode(r.mode))
        }
        (true, true) => format!("✓ guarded (hook, {})", mode(r.mode)),
        (true, false) => format!("partly guarded (MCP proxy, {})", mode(r.mode)),
        (false, true) => format!("partly guarded (hook, {})", mode(hook_guard_mode(state))),
        (false, false) if hook_spec_of(r).is_some_and(|spec| !spec.has_mcp_config()) => {
            "not guarded, connect via hook".to_string()
        }
        (false, false) => "not guarded, connect via hook + proxy".to_string(),
    }
}

/// Machine-readable effect of a wiring request. Callers must not infer success
/// by parsing the human-facing line (which previously caused mode/setup counts to
/// silently stay at zero when punctuation changed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectEffect {
    Connected,
    Unchanged,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResult {
    pub effect: ConnectEffect,
    pub line: String,
    /// Set by a mode switch that rewrote a hook's line and left a hook the
    /// agent does not run: one line that names the agent and the step left.
    pub hook_stopped: Option<String>,
}

impl ConnectResult {
    fn new(effect: ConnectEffect, line: String) -> Self {
        Self {
            effect,
            line,
            hook_stopped: None,
        }
    }

    pub fn configured(&self) -> bool {
        matches!(
            self.effect,
            ConnectEffect::Connected | ConnectEffect::Unchanged
        )
    }
}

/// Wire ONE agent by its best mechanism and return a structured outcome.
/// `strict` also blocks `review` (hook only). `monitor` selects observe-only
/// behavior; existing wiring is reconfigured in place so mode changes never
/// stack wrappers.
pub fn connect_one_result(
    home: &Path,
    r: &AgentStatus,
    guard_bin: &str,
    strict: bool,
    monitor: bool,
) -> ConnectResult {
    connect_one_result_with_link_policy(home, r, guard_bin, strict, monitor, false)
}

/// Background/automatic wiring variant. It has the same monitor invariant at
/// the policy layer and additionally refuses config symlinks at read and commit.
pub fn connect_one_result_automatic(
    home: &Path,
    r: &AgentStatus,
    guard_bin: &str,
    strict: bool,
    monitor: bool,
) -> ConnectResult {
    connect_one_result_with_link_policy(home, r, guard_bin, strict, monitor, true)
}

fn connect_one_result_with_link_policy(
    home: &Path,
    r: &AgentStatus,
    guard_bin: &str,
    strict: bool,
    monitor: bool,
    reject_symlinks: bool,
) -> ConnectResult {
    // Hermes's hook goes in on a connect a person ran, never by automatic
    // setup: it records an approval in Hermes's allowlist, which is the
    // person's to give.
    if r.name == hermes_hook::AGENT {
        return if reject_symlinks {
            ConnectResult::new(
                ConnectEffect::Skipped,
                format!(
                    "  {} - its hook is wired only by `innerwarden agents connect {}`",
                    r.name, r.name
                ),
            )
        } else {
            connect_hermes(home, &r.name, guard_bin, strict, monitor)
        };
    }
    // Codex and Gemini get their blocking hook with the proxy, on a connect a
    // person ran. Automatic setup never writes that hook: what it changes and
    // prints for these two agents is what it was.
    match hook_spec_of(r) {
        Some(spec) if !reject_symlinks => {
            connect_hook_and_proxy(home, r, spec, guard_bin, strict, monitor, false)
        }
        _ => connect_by_one_mechanism(home, r, guard_bin, strict, monitor, reject_symlinks),
    }
}

/// Switch ONE agent that is already wired to the mode `monitor` names.
///
/// The hook of Codex or Gemini is rewritten only when it is already in the
/// agent's file. A switch never installs one, and never asks Codex to trust
/// one, for an agent that only has its MCP servers behind the proxy: a new
/// hook comes from `agents connect` and setup, which the person runs for it.
///
/// A switch that leaves a Codex hook Codex does not run is a failure, and
/// [`ConnectResult::hook_stopped`] holds the line that says so: whether this
/// run rewrote the line or found it already in the mode asked for, the mode
/// is not in force for that agent.
pub fn switch_mode_one_result(
    home: &Path,
    r: &AgentStatus,
    guard_bin: &str,
    strict: bool,
    monitor: bool,
) -> ConnectResult {
    if r.name == hermes_hook::AGENT {
        return if hermes_hook::state(home, None).installed() {
            connect_hermes(home, &r.name, guard_bin, strict, monitor)
        } else {
            ConnectResult::new(
                ConnectEffect::Skipped,
                format!("  {} - not connected; nothing to switch", r.name),
            )
        };
    }
    match hook_spec_of(r) {
        Some(spec) if agent_hooks::state(home, spec, None).installed() => {
            connect_hook_and_proxy(home, r, spec, guard_bin, strict, monitor, true)
        }
        _ => connect_by_one_mechanism(home, r, guard_bin, strict, monitor, false),
    }
}

/// Wire Hermes Agent's hook ([`hermes_hook`]) in the mode asked for, and say
/// where it stands after: on only when Hermes runs it, with what it screens
/// and what it does not.
fn connect_hermes(
    home: &Path,
    name: &str,
    guard_bin: &str,
    strict: bool,
    monitor: bool,
) -> ConnectResult {
    let changed = match hermes_hook::install(home, Path::new(guard_bin), strict, monitor) {
        Ok(changed) => changed,
        Err(error) => {
            return ConnectResult::new(ConnectEffect::Failed, format!("  {name} - failed: {error}"))
        }
    };
    let path_env = std::env::var_os("PATH");
    let state = hermes_hook::state(home, path_env.as_deref());
    let mut lines = vec![format!("  {name} - {}", hermes_hook::state_line(&state))];
    let effect = match (&state, changed) {
        (hermes_hook::State::On { .. }, true) => ConnectEffect::Connected,
        (hermes_hook::State::On { .. }, false) => ConnectEffect::Unchanged,
        _ => ConnectEffect::Failed,
    };
    if state.is_on() {
        lines.extend(
            hermes_hook::coverage()
                .into_iter()
                .map(|line| format!("      {line}")),
        );
    }
    ConnectResult::new(effect, lines.join("\n"))
}

/// Wire the blocking hook and the MCP proxy of Codex or Gemini in one go.
///
/// The hook goes first and the proxy second, in series: Gemini keeps both in
/// one file, so the proxy step reads that file with the hook already in it and
/// neither write drops the other. For Codex the proxy step reads the config
/// after Codex has written its trust for the hook into it.
///
/// The result holds one line for the hook, one for the proxy, then what is
/// screened and what is not. A hook the agent would skip adds nothing to the
/// effect: it is installed, and it screens nothing yet.
///
/// `mode_switch` is true when the caller is `enforce` or `dry-run` and the
/// hook was already in the file. Then a Codex hook that Codex does not run
/// afterwards is a failure, whether this run rewrote its line (Codex trusted
/// the old line and skips the new one without a word) or found it already in
/// that mode: the switch is not in force for that agent, with or without
/// MCP servers behind the proxy.
fn connect_hook_and_proxy(
    home: &Path,
    r: &AgentStatus,
    spec: &HookSpec,
    guard_bin: &str,
    strict: bool,
    monitor: bool,
    mode_switch: bool,
) -> ConnectResult {
    let codex = agent_hooks::codex_to_ask(home);
    let hooked = agent_hooks::connect_noting_write(
        home,
        spec,
        Path::new(guard_bin),
        strict,
        monitor,
        codex.as_deref(),
    );
    // An agent with no MCP config here (Antigravity) gets its hook alone.
    let proxy = if spec.has_mcp_config() {
        connect_by_one_mechanism(home, r, guard_bin, strict, monitor, false)
    } else {
        ConnectResult::new(
            ConnectEffect::Skipped,
            format!(
                "  {} - its MCP servers are not routed through the guard proxy (where {} keeps \
                 them is not confirmed)",
                r.name, spec.product
            ),
        )
    };

    let mut lines = Vec::new();
    let mut hook_stopped = None;
    let hook_effect = match &hooked {
        Ok(connected) => {
            lines.push(agent_hooks::connect_line(
                &r.name,
                spec,
                &connected.outcome,
                strict,
                monitor,
            ));
            // What the write did beside the hook itself: a hook of the
            // person's that moved, a yes from Codex that status cannot read.
            lines.extend(
                connected
                    .notes(spec)
                    .into_iter()
                    .map(|note| format!("      {note}")),
            );
            match &connected.outcome {
                agent_hooks::Outcome::Active { changed: true } => ConnectEffect::Connected,
                agent_hooks::Outcome::Active { changed: false } => ConnectEffect::Unchanged,
                agent_hooks::Outcome::NotActive { step, .. }
                    if mode_switch && spec.host == agent_hooks::Host::Codex =>
                {
                    hook_stopped = Some(format!(
                        "{} - its {} hook is not active after this switch. {step}",
                        r.name, spec.event
                    ));
                    ConnectEffect::Failed
                }
                agent_hooks::Outcome::NotActive { .. } => ConnectEffect::Skipped,
            }
        }
        Err(error) => {
            lines.push(format!("  {} - failed: {error}", r.name));
            ConnectEffect::Failed
        }
    };
    // On a connect a person ran, the proxy step is skipped for one reason
    // only: the agent has no stdio server to wrap. Its own words for that end
    // in "nothing to guard", which is not true beside a hook.
    lines.push(
        if proxy.effect == ConnectEffect::Skipped && spec.has_mcp_config() {
            format!(
                "  {} - no local MCP servers to route through the guard proxy",
                r.name
            )
        } else {
            proxy.line
        },
    );
    if let Ok(connected) = &hooked {
        lines.extend(
            agent_hooks::connect_notes(spec, &connected.outcome)
                .into_iter()
                .map(|note| format!("      {note}")),
        );
    }
    ConnectResult {
        hook_stopped,
        ..ConnectResult::new(both_effects(hook_effect, proxy.effect), lines.join("\n"))
    }
}

/// The effect of two wiring steps on one agent: a failure in either is a
/// failure, then a change in either is a change, then wiring that was already
/// there counts, and only two skips are a skip.
fn both_effects(first: ConnectEffect, second: ConnectEffect) -> ConnectEffect {
    [
        ConnectEffect::Failed,
        ConnectEffect::Connected,
        ConnectEffect::Unchanged,
    ]
    .into_iter()
    .find(|effect| first == *effect || second == *effect)
    .unwrap_or(ConnectEffect::Skipped)
}

/// Wire an agent by the one mechanism its row names: Claude Code's hook, or
/// the MCP proxy over the row's own config.
fn connect_by_one_mechanism(
    home: &Path,
    r: &AgentStatus,
    guard_bin: &str,
    strict: bool,
    monitor: bool,
    reject_symlinks: bool,
) -> ConnectResult {
    if r.hookable {
        let installed: Result<bool, String> = if reject_symlinks {
            hook::install_hook_no_symlinks(
                home,
                &r.name,
                None,
                Path::new(guard_bin),
                strict,
                monitor,
            )
            .map(|result| matches!(result, hook::AutomaticHookInstall::Installed(_)))
        } else {
            hook::install_hook(home, &r.name, None, Path::new(guard_bin), strict, monitor)
                .map(|_| true)
        };
        return match installed {
            Ok(false) => ConnectResult::new(
                ConnectEffect::Skipped,
                format!("  {} - existing hook wiring left unchanged", r.name),
            ),
            Ok(true) => {
                let mode = if monitor {
                    ", monitor (records, never blocks)"
                } else if strict {
                    ", strict"
                } else {
                    ""
                };
                // NOT keyed on `r.guarded`.
                //
                // A first attempt reported "already guarded" whenever a hook was
                // present, which broke hook REPAIR: a hook pointing at an old
                // binary path is present, is rewritten to the current path, and
                // that is a change. `reconciler_repairs_hooks_without_promoting_a_wrong_matcher_mode`
                // caught it, expecting connected=1 and getting 0.
                //
                // `Ok(true)` here already means bytes were written. The genuine
                // no-op has its own arm above (`Ok(false)` -> Skipped, "existing
                // hook wiring left unchanged"), so the distinction the user needs
                // is carried by the LISTING showing the mode, not by weakening
                // this signal.
                ConnectResult::new(
                    ConnectEffect::Connected,
                    format!("  {} - connected (PreToolUse hook{mode})", r.name),
                )
            }
            Err(e) => {
                ConnectResult::new(ConnectEffect::Failed, format!("  {} - failed: {e}", r.name))
            }
        };
    }
    if let Some(rel) = &r.mcp_json {
        let path = home.join(rel);
        let (cfg, source) = match read_json_for_update(home, &path, reject_symlinks) {
            Ok(Some(pair)) => pair,
            Ok(None) => {
                return ConnectResult::new(
                    ConnectEffect::Skipped,
                    format!(
                        "  {} - {} does not exist yet; nothing to guard until it has MCP servers",
                        r.name,
                        path.display()
                    ),
                )
            }
            Err(error) => {
                return ConnectResult::new(
                    ConnectEffect::Failed,
                    format!("  {} - failed: {error}", r.name),
                )
            }
        };
        if reject_symlinks && mcp_wire::has_guard_wiring(&cfg) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!("  {} - existing MCP wiring left unchanged", r.name),
            );
        }
        if reject_symlinks && !mcp_wire::is_automatic_wrap_safe(&cfg) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!(
                    "  {} - invalid MCP structure requires an explicit manual connect",
                    r.name
                ),
            );
        }
        if !mcp_wire::is_guardable(&cfg) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!(
                    "  {} - {} has no local MCP servers to guard (remote-only or empty)",
                    r.name,
                    path.display()
                ),
            );
        }
        // Every wrapper names this agent, so the decisions its proxy records
        // say which agent asked (`--label`/`--agent`, see `mcp_wire::naming`).
        // A wrapper an earlier release wrote gains the name here, on a connect
        // a person ran. Automatic setup never reaches this for existing wiring
        // (it stops at "existing MCP wiring left unchanged" above), exactly as
        // it never adds a name to an existing hook.
        // Automatic setup wraps only local servers; a remote server goes
        // through the proxy on a connect a person runs (`mcp_wire::wrap_local`).
        let (wrapped, n, fully_guarded) = if reject_symlinks {
            let (wrapped, n) = mcp_wire::wrap_local(cfg, guard_bin, monitor, &r.name);
            let guarded = mcp_wire::local_servers_guarded(&wrapped);
            (wrapped, n, guarded)
        } else {
            let (wrapped, n) = mcp_wire::wrap(cfg, guard_bin, monitor, &r.name);
            let guarded = mcp_wire::is_guarded(&wrapped);
            (wrapped, n, guarded)
        };
        if !fully_guarded {
            return ConnectResult::new(
                ConnectEffect::Failed,
                format!(
                    "  {} - failed: incomplete InnerWarden MCP wrapper in {}; restore its child command, then reconnect",
                    r.name,
                    path.display()
                ),
            );
        }
        return match write_json(home, &path, &wrapped, &source, reject_symlinks) {
            Ok(()) if n == 0 => ConnectResult::new(
                ConnectEffect::Unchanged,
                format!(
                    "  {} - already guarded (MCP proxy, {})",
                    r.name,
                    if monitor { "monitor" } else { "enforce" }
                ),
            ),
            Ok(()) => ConnectResult::new(
                ConnectEffect::Connected,
                format!(
                    "  {} - connected ({n} MCP server{} routed through the guard proxy, {})",
                    r.name,
                    if n == 1 { "" } else { "s" },
                    if monitor { "monitor" } else { "enforce" }
                ),
            ),
            Err(e) => {
                ConnectResult::new(ConnectEffect::Failed, format!("  {} - failed: {e}", r.name))
            }
        };
    }
    if let Some(rel) = &r.mcp_toml {
        // Codex: wrap the [mcp_servers.*] tables in ~/.codex/config.toml
        // (format-preserving), routing each server through the guard proxy.
        let path = home.join(rel);
        let (mut doc, source) = match read_toml_for_update(home, &path, reject_symlinks) {
            Ok(Some(pair)) => pair,
            Ok(None) => {
                return ConnectResult::new(
                    ConnectEffect::Skipped,
                    format!(
                        "  {} - {} does not exist yet; nothing to guard until it has [mcp_servers]",
                        r.name,
                        path.display()
                    ),
                )
            }
            Err(error) => {
                return ConnectResult::new(
                    ConnectEffect::Failed,
                    format!("  {} - failed: {error}", r.name),
                )
            }
        };
        if reject_symlinks && mcp_wire_toml::has_guard_wiring_toml(&doc) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!("  {} - existing MCP wiring left unchanged", r.name),
            );
        }
        if reject_symlinks && !mcp_wire_toml::is_automatic_wrap_safe_toml(&doc) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!(
                    "  {} - invalid MCP structure requires an explicit manual connect",
                    r.name
                ),
            );
        }
        if !mcp_wire_toml::is_guardable_toml(&doc) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!(
                    "  {} - {} has no local MCP servers to guard (remote-only or none)",
                    r.name,
                    path.display()
                ),
            );
        }
        // Automatic setup wraps only local servers; a server reached by URL
        // goes through the proxy on a connect a person runs.
        let (n, fully_guarded) = if reject_symlinks {
            let n = mcp_wire_toml::wrap_toml_local(&mut doc, guard_bin, monitor, &r.name);
            (n, mcp_wire_toml::local_servers_guarded_toml(&doc))
        } else {
            let n = mcp_wire_toml::wrap_toml(&mut doc, guard_bin, monitor, &r.name);
            (n, mcp_wire_toml::is_guarded_toml(&doc))
        };
        if !fully_guarded {
            return ConnectResult::new(
                ConnectEffect::Failed,
                format!(
                    "  {} - failed: incomplete InnerWarden MCP wrapper in {}; restore its child command, then reconnect",
                    r.name,
                    path.display()
                ),
            );
        }
        // A server reached by URL the proxy does not carry is named, with
        // the key that keeps it out, as Goose's line names its own.
        let unscreened = mcp_wire_toml::unscreened_remote_toml(&doc);
        let unscreened = if unscreened.is_empty() {
            String::new()
        } else {
            format!("; not screened by the proxy: {}", unscreened.join(", "))
        };
        // Their calls still reach the guard through Codex's hook, which
        // judges them with the proxy's rules (`crate::mcp_unproxied`).
        let judged_by_hook = if unscreened.is_empty() {
            ""
        } else {
            "; the Codex hook, when it is on, judges calls to those servers with the proxy's rules"
        };
        return match write_toml(home, &path, &doc, &source, reject_symlinks) {
            Ok(()) if n == 0 => ConnectResult::new(
                ConnectEffect::Unchanged,
                format!(
                    "  {} - already guarded (MCP proxy, {}{unscreened}){judged_by_hook}",
                    r.name,
                    if monitor { "monitor" } else { "enforce" }
                ),
            ),
            Ok(()) => ConnectResult::new(
                ConnectEffect::Connected,
                format!(
                    "  {} - connected ({n} MCP server{} routed through the guard proxy, {}{unscreened}){judged_by_hook}",
                    r.name,
                    if n == 1 { "" } else { "s" },
                    if monitor { "monitor" } else { "enforce" }
                ),
            ),
            Err(e) => {
                ConnectResult::new(ConnectEffect::Failed, format!("  {} - failed: {e}", r.name))
            }
        };
    }
    if let Some(rel) = &r.mcp_yaml {
        // Goose: wrap the stdio `extensions` in ~/.config/goose/config.yaml,
        // read as a JSON client's servers and written back line by line: only
        // the `cmd` and `args` lines of the servers that change are touched.
        let path = home.join(rel);
        let doc_and_source = match read_yaml_for_update(home, &path, reject_symlinks) {
            Ok(Some((mut doc, source))) => {
                doc.set_path(&path);
                Ok(Some((doc, source)))
            }
            other => other,
        };
        let (mut doc, source) = match doc_and_source {
            Ok(Some(pair)) => pair,
            Ok(None) => {
                return ConnectResult::new(
                    ConnectEffect::Skipped,
                    format!(
                        "  {} - {} does not exist yet; nothing to guard until it has extensions",
                        r.name,
                        path.display()
                    ),
                )
            }
            Err(error) => {
                return ConnectResult::new(
                    ConnectEffect::Failed,
                    format!("  {} - failed: {error}", r.name),
                )
            }
        };
        let cfg = doc.view();
        // Each extension the proxy never sees, named on the line, so a
        // remote server is not taken for one behind the guard.
        let unscreened = yaml_unscreened_line(&doc);
        // Code that runs inside Goose: the wiring is done, the agent is not
        // guarded, and the line says "partly", never "connected" alone.
        let inside: Vec<String> = doc
            .runs_inside()
            .iter()
            .map(|(name, kind)| format!("{name} ({kind})"))
            .collect();
        let partly = if inside.is_empty() {
            String::new()
        } else {
            format!(
                ". Partly guarded: {} run{} code inside Goose that no proxy sees",
                inside.join(", "),
                if inside.len() == 1 { "s" } else { "" }
            )
        };
        if reject_symlinks && mcp_wire::has_guard_wiring(&cfg) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!("  {} - existing MCP wiring left unchanged", r.name),
            );
        }
        if reject_symlinks && !mcp_wire::is_automatic_wrap_safe(&cfg) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!(
                    "  {} - invalid MCP structure requires an explicit manual connect",
                    r.name
                ),
            );
        }
        if !mcp_wire::is_guardable(&cfg) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!(
                    "  {} - {} has no local MCP servers to guard (built-in or remote only, or none){unscreened}",
                    r.name,
                    path.display()
                ),
            );
        }
        // Automatic setup wraps only local servers; a remote extension goes
        // through the proxy on a connect a person runs.
        let (wrapped, n, fully_guarded) = if reject_symlinks {
            let (wrapped, n) = mcp_wire::wrap_local(cfg, guard_bin, monitor, &r.name);
            let guarded = mcp_wire::local_servers_guarded(&wrapped);
            (wrapped, n, guarded)
        } else {
            let (wrapped, n) = mcp_wire::wrap(cfg, guard_bin, monitor, &r.name);
            let guarded = mcp_wire::is_guarded(&wrapped);
            (wrapped, n, guarded)
        };
        if !fully_guarded {
            return ConnectResult::new(
                ConnectEffect::Failed,
                format!(
                    "  {} - failed: incomplete InnerWarden MCP wrapper in {}; restore its child command, then reconnect",
                    r.name,
                    path.display()
                ),
            );
        }
        if let Err(error) = doc.apply(&wrapped) {
            return ConnectResult::new(
                ConnectEffect::Failed,
                format!("  {} - failed: {} {error}", r.name, path.display()),
            );
        }
        // A remote extension this connect carried is screened now: the line
        // names only those still outside the proxy.
        let unscreened = yaml_unscreened_line(&doc);
        return match write_yaml(home, &path, &doc, &source, reject_symlinks) {
            Ok(()) if n == 0 => ConnectResult::new(
                ConnectEffect::Unchanged,
                format!(
                    "  {} - {} (MCP proxy, {}){unscreened}{partly}",
                    r.name,
                    if partly.is_empty() { "already guarded" } else { "already wired" },
                    if monitor { "monitor" } else { "enforce" }
                ),
            ),
            Ok(()) => ConnectResult::new(
                ConnectEffect::Connected,
                format!(
                    "  {} - {} ({n} MCP server{} routed through the guard proxy, {}; built-in extensions are not screened by it{unscreened}){partly}",
                    r.name,
                    if partly.is_empty() { "connected" } else { "wired" },
                    if n == 1 { "" } else { "s" },
                    if monitor { "monitor" } else { "enforce" }
                ),
            ),
            Err(e) => {
                ConnectResult::new(ConnectEffect::Failed, format!("  {} - failed: {e}", r.name))
            }
        };
    }
    ConnectResult::new(
        ConnectEffect::Skipped,
        format!(
            "  {} - no automatic wiring; point it at `innerwarden hook` or `innerwarden proxy` manually",
            r.name
        ),
    )
}

/// Backwards-compatible human-facing adapter used by the thin CLI wrappers.
pub fn connect_one(
    home: &Path,
    r: &AgentStatus,
    guard_bin: &str,
    strict: bool,
    monitor: bool,
) -> String {
    connect_one_result(home, r, guard_bin, strict, monitor).line
}

fn disconnect_one(home: &Path, r: &AgentStatus) -> String {
    if r.name == hermes_hook::AGENT {
        return match hermes_hook::uninstall(home) {
            Ok(0) => format!("  {}, was not connected", r.name),
            Ok(_) => format!("  {}, disconnected", r.name),
            Err(e) => format!("  {}, failed: {e}", r.name),
        };
    }
    // Codex and Gemini: the hook comes out first, then the wrappers. Gemini
    // keeps both in one file, so the second step reads what the first wrote.
    let Some(spec) = hook_spec_of(r) else {
        return disconnect_by_one_mechanism(home, r);
    };
    let unhooked = agent_hooks::uninstall_noting_moved(home, spec);
    // An agent wired by its hook alone (Antigravity) has no proxy step.
    if !spec.has_mcp_config() {
        return match unhooked {
            Ok((0, _)) => format!("  {}, was not connected", r.name),
            Ok(_) => format!("  {}, disconnected", r.name),
            Err(error) => format!("  {}, failed: {error}", r.name),
        };
    }
    let proxy = disconnect_by_one_mechanism(home, r);
    let (removed, moved) = match unhooked {
        Ok(done) => done,
        // The wrappers were handled whatever the hook's file did, so their
        // line stays above the failure. `failed:` is what the caller reads.
        Err(error) => return format!("{proxy}\n  {}, failed: {error}", r.name),
    };
    // The wrappers had nothing to say and the hook was taken out: that is a
    // disconnect. A failure on the proxy side is still the line to read.
    let line = if removed > 0 && proxy.ends_with("was not connected") {
        format!("  {}, disconnected", r.name)
    } else {
        proxy
    };
    // Taking our hook out moves the person's later hooks up one place, and
    // Codex trusts a hook by its place.
    match agent_hooks::moved_note(spec, &moved) {
        Some(note) => format!("{line}\n      {note}"),
        None => line,
    }
}

/// Unwire an agent from the one mechanism its row names.
fn disconnect_by_one_mechanism(home: &Path, r: &AgentStatus) -> String {
    if r.hookable {
        return match hook::uninstall_hook(home, &r.name, None) {
            Ok((_, n)) if n > 0 => format!("  {}, disconnected", r.name),
            Ok(_) => format!("  {}, was not connected", r.name),
            Err(e) => format!("  {}, failed: {e}", r.name),
        };
    }
    if let Some(rel) = &r.mcp_json {
        let path = home.join(rel);
        let (cfg, source) = match read_json_for_update(home, &path, false) {
            Ok(Some(pair)) => pair,
            Ok(None) => return format!("  {} - was not connected", r.name),
            Err(error) => return format!("  {} - failed: {error}", r.name),
        };
        let (restored, n) = mcp_wire::unwrap(cfg);
        if n == 0 {
            return format!("  {}, was not connected", r.name);
        }
        return match write_json(home, &path, &restored, &source, false) {
            Ok(()) => format!("  {}, disconnected", r.name),
            Err(e) => format!("  {}, failed: {e}", r.name),
        };
    }
    if let Some(rel) = &r.mcp_toml {
        let path = home.join(rel);
        let (mut doc, source) = match read_toml_for_update(home, &path, false) {
            Ok(Some(pair)) => pair,
            Ok(None) => return format!("  {} - was not connected", r.name),
            Err(error) => return format!("  {} - failed: {error}", r.name),
        };
        let n = mcp_wire_toml::unwrap_toml(&mut doc);
        if n == 0 {
            return format!("  {}, was not connected", r.name);
        }
        return match write_toml(home, &path, &doc, &source, false) {
            Ok(()) => format!("  {}, disconnected", r.name),
            Err(e) => format!("  {}, failed: {e}", r.name),
        };
    }
    if let Some(rel) = &r.mcp_yaml {
        // Goose: only the `cmd` and `args` lines of the servers connect
        // wrapped are rewritten, back to the command each wrapper runs.
        let path = home.join(rel);
        let (mut doc, source) = match read_yaml_for_update(home, &path, false) {
            Ok(Some(pair)) => pair,
            Ok(None) => return format!("  {} - was not connected", r.name),
            Err(error) => return format!("  {} - failed: {error}", r.name),
        };
        let (restored, n) = mcp_wire::unwrap(doc.view());
        if n == 0 {
            return format!("  {}, was not connected", r.name);
        }
        if let Err(error) = doc.apply(&restored) {
            return format!("  {}, failed: {error}", r.name);
        }
        return match write_yaml(home, &path, &doc, &source, false) {
            Ok(()) => format!("  {}, disconnected", r.name),
            Err(e) => format!("  {}, failed: {e}", r.name),
        };
    }
    format!("  {}, nothing to disconnect", r.name)
}

/// What to say when the scan matched nothing.
///
/// Absence of a SIGNATURE is not absence of an agent, and saying the second when
/// you mean the first sends a beginner away believing they have nothing to
/// guard. Detection matches known agents by their command line, so a bespoke
/// script, a wrapper or a renamed binary matches nothing while running
/// perfectly. That reader is exactly the one who needs a next step, and exactly
/// the one the old single line ended the conversation on. Seen on a production
/// host running a hand-written Python agent this command called "no compatible
/// AI agents found".
fn nothing_detected_lines() -> Vec<String> {
    vec![
        "innerwarden agents, none of the agents I know by name are running.".into(),
        String::new(),
        "  I detect agents by matching known command lines, so a bespoke".into(),
        "  script, a wrapper or a renamed binary will not show up here even".into(),
        "  while it is running.".into(),
        String::new(),
        "  If you have an agent running:".into(),
        "    innerwarden hook <your-agent>   wire the in-path guard".into(),
        "    innerwarden agents --all        show every process I considered".into(),
    ]
}

fn list_lines(home: &Path) -> Vec<String> {
    list_lines_of(home, &rows(home))
}

/// The listing of `rows`, with each row's wiring read back from `home`.
fn list_lines_of(home: &Path, rows: &[AgentStatus]) -> Vec<String> {
    let mut out = Vec::new();
    if rows.is_empty() {
        out.extend(nothing_detected_lines());
    } else {
        // Say what is LEFT to do, not what the command can do in general.
        //
        // The header and the footer were both unconditional, so connecting an
        // agent changed nothing on screen: the same "connect wires all guardable
        // ones" line above, the same "connect one / all" invitation below, and
        // the row itself already reading "guarded" before and after. Someone who
        // had just wired three of four agents was still being told to wire them,
        // with no way to tell from the output that anything had happened.
        //
        // Codex and Gemini have work left while their hook is not on, even
        // with every MCP server behind the proxy: their shell commands and
        // file changes run unscreened until it is.
        let hooks: Vec<_> = rows.iter().map(|r| hook_state(home, r)).collect();
        let hook_off = |row: usize| hooks[row].as_ref().is_some_and(|(_, state)| !state.is_on());
        let pending = rows
            .iter()
            .enumerate()
            .filter(|(row, r)| r.guardable() && (!r.guarded || hook_off(*row)))
            .count();
        let guarded = rows
            .iter()
            .enumerate()
            .filter(|(row, r)| r.guarded && !hook_off(*row))
            .count();
        out.push(match pending {
            0 if guarded > 0 => format!(
                "innerwarden agents, all {guarded} guardable agent(s) are wired. Nothing to connect."
            ),
            0 => "innerwarden agents, found (none of these can be wired automatically):".into(),
            // "Not guarded", not "not wired": a hook whose program is gone is
            // wired and still screens nothing.
            n => format!("innerwarden agents, found ({n} not guarded yet):"),
        });
        for (r, hooked) in rows.iter().zip(&hooks) {
            // A hook whose program is gone is wiring that screens nothing. It
            // used to read "✓ guarded" here, as it did in `status` and on the
            // dashboard, because a hook was judged by its text alone.
            let broken = match (r.guarded, hook_program(home, r)) {
                (false, Some(hook::HookProgram::Broken { problem, .. })) => Some(problem),
                _ => None,
            };
            // The same for an MCP agent whose proxy wrapper's binary is gone:
            // its servers cannot start, which is closed, but not guarded.
            let proxy_broken = match (r.guarded, mcp_proxy_program(home, r)) {
                (false, Some(hook::HookProgram::Broken { problem, .. })) => Some(problem),
                _ => None,
            };
            // Bash screened, but a file-tool, read-tool or result hook points
            // at a program that is gone: those calls go through unscreened.
            let partly = if r.guarded {
                hook::unscreened_hooks_sentence(&unscreened_hooks(home, r))
            } else {
                None
            };
            // Goose's YAML config: one that is there and cannot be read says
            // so, and the extensions the proxy never sees are named.
            let yaml_path = r.mcp_yaml.as_deref().map(|rel| home.join(rel));
            let yaml_problem = yaml_path.as_deref().and_then(yaml_unreadable);
            let unscreened = yaml_path
                .as_deref()
                .map(yaml_unscreened)
                .unwrap_or_default();
            let runs_inside = yaml_path
                .as_deref()
                .map(yaml_runs_inside)
                .unwrap_or_default();
            let guard = if !r.guardable() {
                "detected (guard manually)".to_string()
            } else if broken.is_some() {
                "✗ wired, but its hook cannot run".to_string()
            } else if partly.is_some() {
                "✗ wired, part of its hook cannot run".to_string()
            } else if proxy_broken.is_some() {
                "✗ wired, but its MCP proxy cannot run".to_string()
            } else if yaml_problem.is_some() {
                "? its MCP config cannot be read".to_string()
            } else if !runs_inside.is_empty() && mcp_has_guard_wiring(home, r) {
                "partly guarded (MCP proxy)".to_string()
            } else if let Some((_, state)) = hooked {
                two_way_label(home, r, state)
            } else if r.guarded {
                // Name the MODE, not just the mechanism. "guarded (hook)" was the
                // same string whether the hook records or blocks.
                match r.mode {
                    Some(m) => format!("✓ guarded ({}, {})", mechanism(r), m.label()),
                    None => format!("✓ guarded ({}, mode unreadable)", mechanism(r)),
                }
            } else {
                format!("not guarded, connect via {}", mechanism(r))
            };
            let where_ = if r.installed && !r.pids.is_empty() {
                format!("executable on PATH, running pid {:?}", r.pids)
            } else if !r.pids.is_empty() {
                format!("running pid {:?}", r.pids)
            } else if r.installed {
                "executable on PATH".to_string()
            } else if r.has_evidence(DiscoveryEvidence::ConfigurationFile) {
                "recognized configuration; CLI not confirmed".to_string()
            } else if r.has_evidence(DiscoveryEvidence::CompatibleMcpConfiguration) {
                "compatible MCP configuration".to_string()
            } else if r.has_evidence(DiscoveryEvidence::PossibleLeftover) {
                "possible leftover; installation not confirmed".to_string()
            } else {
                "detected".to_string()
            };
            out.push(format!("  {:<13} {:<34} {where_}", r.name, guard));
            if let (Some(problem), Some(path)) = (&yaml_problem, &yaml_path) {
                out.push(format!(
                    "  {:<13} {} cannot be read ({problem}), so whether its MCP servers are behind the proxy is not known",
                    "",
                    path.display()
                ));
            }
            if !runs_inside.is_empty() {
                out.push(format!(
                    "  {:<13} runs code inside the agent that no proxy sees: {}",
                    "",
                    runs_inside.join(", ")
                ));
            }
            if !unscreened.is_empty() {
                out.push(format!(
                    "  {:<13} not screened by the proxy (the agent reaches them itself): {}",
                    "",
                    unscreened.join(", ")
                ));
            }
            if let Some(problem) = broken {
                out.push(format!(
                    "  {:<13} {problem}, so nothing is screened. Fix: {}",
                    "",
                    hook_repair_command(home, r)
                ));
            }
            if let Some(sentence) = partly {
                out.push(format!(
                    "  {:<13} {sentence}. Fix: {}",
                    "",
                    hook_repair_command(home, r)
                ));
            }
            let proxy_cannot_run = proxy_broken.is_some();
            if let Some(problem) = proxy_broken {
                out.push(format!(
                    "  {:<13} {problem}, so its MCP servers cannot start. Fix: {}",
                    "",
                    proxy_repair_command(home, r)
                ));
            }
            // Codex and Gemini are screened two ways. Under a row that has one
            // of the two only, say which is missing and the one step that adds
            // it. A row with neither, and no hook in the file, already says
            // "connect".
            if r.name == hermes_hook::AGENT {
                let state = hermes_hook::state(home, std::env::var_os("PATH").as_deref());
                if state.installed() && !state.is_on() {
                    out.push(format!("  {:<13} {}", "", hermes_hook::state_line(&state)));
                }
            }
            if let Some((spec, state)) = hooked {
                if !state.is_on() && (r.guarded || *state != HookState::Absent) {
                    out.push(format!(
                        "  {:<13} {}",
                        "",
                        agent_hooks::state_line(spec, state)
                    ));
                } else if state.is_on() && !r.guarded && !proxy_cannot_run {
                    out.push(format!(
                        "  {:<13} MCP servers: not all behind the guard proxy. Run: innerwarden agents connect {}",
                        "", spec.agent
                    ));
                }
            }
        }
        // Only offer the action when there is something to act on.
        if pending > 0 {
            out.push(
                "\n  connect one:  innerwarden agents connect <name>     all:  innerwarden agents connect --all"
                    .into(),
            );
        }
    }
    out
}

/// Everything one `agents` invocation produced: the human-facing lines, plus the
/// machine-readable count of integrations a CONNECT left wired.
///
/// The count exists so a caller can key follow-up advice (for example "restart
/// your agents so they reload the hook") on what actually happened. Callers must
/// take it from here rather than scanning `lines` for a word: the same defect
/// that kept mode/setup counts at zero when punctuation changed is waiting for
/// anyone who greps this text, and "was not connected" contains "connected"
/// while "already guarded (MCP proxy, monitor)" does not.
///
/// `configured` is zero for every command that is not `connect`, so keying on it
/// cannot fire after a `disconnect` or a plain listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOutcome {
    pub lines: Vec<String>,
    pub configured: usize,
}

fn connect_outcome(
    home: &Path,
    target: Option<&str>,
    strict: bool,
    monitor: bool,
    guard_bin: &str,
) -> RunOutcome {
    let rows = rows(home);
    let targets = connect_targets(&rows, target);
    if targets.is_empty() {
        return RunOutcome {
            lines: vec![match target {
                Some(name) => format!(
                    "innerwarden agents connect - failed: no guardable agent named `{name}` was found"
                ),
                None => "innerwarden agents connect - no guardable agent found. Run `innerwarden agents` to see what's detected.".into(),
            }],
            configured: 0,
        };
    }
    let results: Vec<ConnectResult> = targets
        .iter()
        .map(|r| connect_one_result(home, r, guard_bin, strict, monitor))
        .collect();
    RunOutcome {
        configured: results.iter().filter(|r| r.configured()).count(),
        lines: results.into_iter().map(|r| r.line).collect(),
    }
}

fn disconnect_lines(home: &Path, target: Option<&str>) -> Vec<String> {
    let rows = rows(home);
    let targets = connect_targets(&rows, target);
    if targets.is_empty() && target.is_some() {
        return vec![format!(
            "innerwarden agents disconnect - failed: no guardable agent named `{}` was found",
            target.unwrap_or_default()
        )];
    }
    targets.iter().map(|r| disconnect_one(home, r)).collect()
}

/// Validate the small `agents` CLI grammar before policy or third-party files
/// can be changed. Unknown flags are errors: a typo must never silently select
/// enforce mode or broaden an operation to every agent.
pub fn validate_args(args: &[String]) -> Result<(), String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(());
    };
    if matches!(command, "--help" | "-h") {
        return (args.len() == 1)
            .then_some(())
            .ok_or_else(|| "help does not accept additional arguments".to_string());
    }
    if command == "list" {
        return (args.len() == 1)
            .then_some(())
            .ok_or_else(|| "`agents list` does not accept additional arguments".to_string());
    }
    if !matches!(command, "connect" | "disconnect") {
        return Err(format!("unknown agents command `{command}`"));
    }

    let mut target: Option<&str> = None;
    let mut all = false;
    let mut monitor = false;
    let mut strict = false;
    for argument in &args[1..] {
        match argument.as_str() {
            "--all" if !all => all = true,
            "--all" => return Err("`--all` may only be specified once".into()),
            "--monitor" if command == "connect" => monitor = true,
            "--block-review" | "--strict" if command == "connect" => strict = true,
            flag if flag.starts_with('-') => {
                return Err(format!("unknown flag `{flag}` for `agents {command}`"));
            }
            name if target.is_none() => target = Some(name),
            name => {
                return Err(format!(
                    "multiple agent targets are not supported (`{}` and `{name}`)",
                    target.unwrap_or_default()
                ));
            }
        }
    }
    if all && target.is_some() {
        return Err("choose either one agent name or `--all`, not both".into());
    }
    if monitor && strict {
        return Err("`--monitor` cannot be combined with enforcement flags".into());
    }
    Ok(())
}

/// Run `agents [connect|disconnect [--all|<name>]]` using an explicitly selected
/// Community guardrail executable, reporting what the run actually configured.
/// Active Defence uses this entrypoint so it never writes its host-management
/// CLI into a `proxy` / `hook` configuration.
pub fn run_with_guard_bin_outcome(home: &Path, args: &[String], guard_bin: &str) -> RunOutcome {
    if let Err(error) = validate_args(args) {
        return RunOutcome {
            lines: vec![format!("innerwarden agents - failed: {error}")],
            configured: 0,
        };
    }
    match args.first().map(String::as_str) {
        Some("connect") => {
            let rest = &args[1..];
            // `--monitor` records but never blocks; `--block-review`/`--strict` also
            // blocks `review`. The target is the first non-flag arg (else --all).
            let monitor = rest.iter().any(|a| a == "--monitor");
            let strict = rest
                .iter()
                .any(|a| a == "--block-review" || a == "--strict");
            let target = rest
                .iter()
                .find(|a| !a.starts_with("--"))
                .map(String::as_str);
            connect_outcome(home, target, strict, monitor, guard_bin)
        }
        // Only `connect` can leave something newly wired, so every other command
        // reports zero configured integrations and cannot trigger connect-only
        // follow-up advice.
        Some("disconnect") => RunOutcome {
            lines: disconnect_lines(
                home,
                args.get(1)
                    .filter(|a| !a.starts_with("--"))
                    .map(String::as_str),
            ),
            configured: 0,
        },
        _ => RunOutcome {
            lines: list_lines(home),
            configured: 0,
        },
    }
}

/// Lines-only adapter for callers that do not act on what was configured.
pub fn run_with_guard_bin(home: &Path, args: &[String], guard_bin: &str) -> Vec<String> {
    run_with_guard_bin_outcome(home, args, guard_bin).lines
}

/// Community CLI entrypoint: its current executable is the guardrail that agent
/// configurations must launch, so resolving it here is safe and keeps callers
/// simple.
pub fn run_outcome(home: &Path, args: &[String]) -> RunOutcome {
    let bin = guard_bin();
    run_with_guard_bin_outcome(home, args, &bin)
}

/// Lines-only adapter over [`run_outcome`].
pub fn run(home: &Path, args: &[String]) -> Vec<String> {
    run_outcome(home, args).lines
}

/// What the wiring for this agent actually does: record, or block.
///
/// `is_guarded` answers "is it wired". That was the only thing the listing had,
/// so an agent connected with `--monitor` and one connected to block printed the
/// same "✓ guarded" row. Someone who chose monitor deliberately could not
/// confirm it, and someone who believed they were protected could not discover
/// they were only recording.
///
/// `None` means wired but unreadable, which is reported as unknown rather than
/// guessed at in either direction.
///
/// The row's OWN wiring is read: the hook for a hook agent, and otherwise the
/// MCP configuration the row was discovered from. Looking the row's name up in
/// the reviewed table instead gave every generic MCP client no mode at all, and
/// one whose directory is named like a reviewed agent's alias (`~/.claude/`,
/// `~/.codex-cli/`) the mode of that other agent's wiring.
///
/// An MCP mode is the one each wrapper's proxy runs in, read from its own
/// argument list ([`mcp_wire::guarded_mode`]). It used to be a search of the
/// file's text for the words `"advisory"`, `"warn"`, `"guard"` and `"kill"`
/// anywhere, so `--mode=advisory` (no quote before the word) beside any other
/// `"guard"` in the file read as enforce while every call was let through.
///
/// Codex and Gemini have a hook beside their wrappers. A hook that is on has a
/// mode of its own, and one that records beside wrappers that block is
/// neither mode: it reads `MIXED`, never the stricter of the two.
fn read_guard_mode(home: &Path, row: &AgentStatus, path_env: Option<&OsStr>) -> Option<GuardMode> {
    if row.name == hermes_hook::AGENT {
        return match hermes_hook::state(home, path_env) {
            hermes_hook::State::On { monitor: true, .. } => Some(GuardMode::Monitor),
            hermes_hook::State::On { monitor: false, .. } => Some(GuardMode::Enforce),
            _ => None,
        };
    }
    if row.hookable {
        return read_json(&home.join(".claude/settings.json"))
            .and_then(|v| hook::effective_iwguard_hook_mode(&v))
            .map(|m| match m {
                hook::EffectiveHookMode::Monitor => GuardMode::Monitor,
                hook::EffectiveHookMode::Enforce => GuardMode::Enforce,
                hook::EffectiveHookMode::Mixed => GuardMode::Mixed,
            });
    }
    let wrappers = mcp_guard_mode(home, row);
    let hooked =
        hook_state_with(home, row, path_env).and_then(|(_, state)| hook_guard_mode(&state));
    match (hooked, wrappers) {
        (Some(hooked), Some(wrappers)) if hooked != wrappers => Some(GuardMode::Mixed),
        (hooked, wrappers) => hooked.or(wrappers),
    }
}

/// The mode of a hook that is on. `None` for any other state: a hook the agent
/// does not run has no mode to report.
fn hook_guard_mode(state: &HookState) -> Option<GuardMode> {
    match state {
        HookState::On { monitor: true, .. } => Some(GuardMode::Monitor),
        HookState::On { monitor: false, .. } => Some(GuardMode::Enforce),
        _ => None,
    }
}

/// The mode the row's MCP wrappers run in, read from the row's own config.
fn mcp_guard_mode(home: &Path, row: &AgentStatus) -> Option<GuardMode> {
    if let Some(rel) = &row.mcp_json {
        return read_json(&home.join(rel))
            .and_then(|config| mcp_wire::guarded_mode(&config))
            .map(|m| match m {
                mcp_wire::WiringMode::Monitor => GuardMode::Monitor,
                mcp_wire::WiringMode::Enforce => GuardMode::Enforce,
                mcp_wire::WiringMode::Mixed => GuardMode::Mixed,
            });
    }
    if let Some(rel) = &row.mcp_toml {
        return read_toml(&home.join(rel))
            .and_then(|config| mcp_wire_toml::guarded_mode_toml(&config))
            .map(|m| match m {
                mcp_wire_toml::WiringMode::Monitor => GuardMode::Monitor,
                mcp_wire_toml::WiringMode::Enforce => GuardMode::Enforce,
                mcp_wire_toml::WiringMode::Mixed => GuardMode::Mixed,
            });
    }
    if let Some(rel) = &row.mcp_yaml {
        return read_yaml(&home.join(rel))
            .and_then(|config| mcp_wire::guarded_mode(&config))
            .map(|m| match m {
                mcp_wire::WiringMode::Monitor => GuardMode::Monitor,
                mcp_wire::WiringMode::Enforce => GuardMode::Enforce,
                mcp_wire::WiringMode::Mixed => GuardMode::Mixed,
            });
    }
    None
}

#[cfg(test)]
mod tests {

    /// A hook whose program could not be looked at is "could not tell", never
    /// "gone": only a path that is not there may be reported as a broken hook.
    /// The nightly cargo-mutants run found no test that told the two apart
    /// (`matches!(kind, NotFound | NotADirectory)` replaced with `true`
    /// survived).
    ///
    /// FAILS ON REVERT: classify every failed lookup as `Missing`.
    #[test]
    fn a_lookup_that_failed_is_unreadable_and_only_not_there_is_missing() {
        use crate::hook::ProgramFact;
        use std::io::ErrorKind;
        for kind in [ErrorKind::NotFound, ErrorKind::NotADirectory] {
            assert_eq!(
                super::failed_lookup_fact(kind),
                ProgramFact::Missing,
                "{kind:?}"
            );
        }
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::Interrupted,
            ErrorKind::Other,
        ] {
            assert_eq!(
                super::failed_lookup_fact(kind),
                ProgramFact::Unreadable,
                "{kind:?} is a failed look, not a missing program"
            );
        }
    }

    /// `disconnect --all` must not be read as "the agent named --all".
    ///
    /// The `!` in `.filter(|a| !a.starts_with("--"))` is what separates a flag
    /// from a name. A mutant that deleted it survived: nothing asked what
    /// `disconnect --all` does, so inverting the filter passed every test while
    /// turning a disconnect-everything into a lookup for an agent that cannot
    /// exist.
    ///
    /// FAILS ON REVERT: delete the `!`.
    #[test]
    fn disconnect_all_is_a_flag_not_an_agent_name() {
        let home = tempfile::TempDir::new().unwrap();
        let out = run(home.path(), &["disconnect".into(), "--all".into()]);
        let joined = out.join("\n");
        assert!(
            !joined.contains("no guardable agent named `--all`"),
            "--all is a flag; reading it as a name is the mutant that survived:\n{joined}"
        );
    }

    /// A named target that does not exist still says so, or the assertion above
    /// would pass on a function that ignores its argument entirely.
    #[test]
    fn disconnect_a_name_that_does_not_exist_says_which_name() {
        let home = tempfile::TempDir::new().unwrap();
        let out = run(home.path(), &["disconnect".into(), "nope".into()]);
        assert!(
            out.join("\n").contains("no guardable agent named `nope`"),
            "a real name must still be looked up: {out:?}"
        );
    }

    /// The lines-only adapters are the public entry points, and three mutants
    /// survived on them by returning empty or default: nothing called them and
    /// checked the result.
    ///
    /// FAILS ON REVERT: make `run` return `vec![]`, or `run_outcome` return
    /// `Default::default()`.
    #[test]
    fn the_lines_adapters_return_what_the_outcome_carries() {
        let home = tempfile::TempDir::new().unwrap();
        let args = vec!["list".to_string()];

        let outcome = run_outcome(home.path(), &args);
        let lines = run(home.path(), &args);

        assert!(
            !outcome.lines.is_empty(),
            "run_outcome must produce output for `list`, even on an empty home"
        );
        assert_eq!(
            lines, outcome.lines,
            "`run` is the lines-only view of `run_outcome`; returning anything \
             else makes the two entry points disagree"
        );

        let via_bin = run_with_guard_bin(home.path(), &args, "/usr/local/bin/innerwarden");
        assert!(
            !via_bin.is_empty(),
            "run_with_guard_bin must produce the same shape of output"
        );
    }
    /// Absence of a SIGNATURE is not absence of an agent.
    ///
    /// Detection matches known agents by command line, so a bespoke script, a
    /// wrapper or a renamed binary matches nothing while running perfectly.
    /// Saying "no compatible AI agents found" to that reader tells them they
    /// have nothing to guard, which is the opposite of true and the end of the
    /// conversation. Seen on a production host running a hand-written Python
    /// agent.
    #[test]
    fn an_empty_scan_explains_itself_and_says_what_to_do() {
        let text = nothing_detected_lines().join("\n");

        assert!(
            !text.contains("no compatible AI agents found"),
            "the old wording reported absence of an agent when it had only \
             established absence of a signature: {text}"
        );
        assert!(
            text.contains("know by name"),
            "it must say detection is by name, not by presence: {text}"
        );
        assert!(
            text.contains("bespoke") || text.contains("wrapper") || text.contains("renamed"),
            "it must name the case where detection cannot work: {text}"
        );
        assert!(
            text.contains("innerwarden hook"),
            "it must give the reader their next command: {text}"
        );
    }

    use super::*;

    #[test]
    fn empty_or_invalid_openclaw_directory_is_only_a_possible_leftover() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".openclaw")).unwrap();

        let (rows, _) = rows_from_sources(home.path(), &[], None);
        let openclaw = rows.iter().find(|row| row.name == "openclaw").unwrap();
        assert!(!openclaw.installed);
        assert_eq!(openclaw.evidence, vec![DiscoveryEvidence::PossibleLeftover]);

        std::fs::write(
            home.path().join(".openclaw/openclaw.json"),
            "{ truncated: [",
        )
        .unwrap();
        let (rows, _) = rows_from_sources(home.path(), &[], None);
        let openclaw = rows.iter().find(|row| row.name == "openclaw").unwrap();
        assert_eq!(openclaw.evidence, vec![DiscoveryEvidence::PossibleLeftover]);
    }

    #[test]
    fn openclaw_profiles_and_hermes_config_are_configuration_evidence() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".openclaw-work")).unwrap();
        std::fs::write(
            home.path().join(".openclaw-work/openclaw.json"),
            "// profile\n{ gateway: { port: 18789, }, name: 'work' }",
        )
        .unwrap();
        std::fs::create_dir_all(home.path().join(".hermes")).unwrap();
        std::fs::write(
            home.path().join(".hermes/config.yaml"),
            "model: test\nmcp_servers: {}\n",
        )
        .unwrap();

        let (rows, limited) = rows_from_sources(home.path(), &[], None);

        assert!(!limited);
        for name in ["openclaw", "hermes"] {
            let row = rows.iter().find(|row| row.name == name).unwrap();
            assert!(!row.installed, "config alone is not an installed CLI");
            assert_eq!(
                row.evidence,
                vec![DiscoveryEvidence::ConfigurationFile],
                "{name} evidence"
            );
        }
        // Hermes is wired through its own fail-closed hook (`hermes_hook`).
        // OpenClaw became guardable on 2026-08-05 once `mcp_wire` could locate
        // a nested `mcp.servers` table; the point of THIS test is that a
        // config file alone is evidence of configuration and not of an
        // installed CLI, which holds for both regardless.
        let hermes = rows.iter().find(|row| row.name == "hermes").unwrap();
        assert!(hermes.guardable(), "hermes is wired through its hook");
    }

    #[cfg(unix)]
    #[test]
    fn path_detection_reads_metadata_without_executing_agent_binary() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::TempDir::new().unwrap();
        let bin = home.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let execution_marker = home.path().join("agent-was-executed");
        let executable = bin.join("openclaw");
        std::fs::write(
            &executable,
            format!("#!/bin/sh\ntouch '{}'\n", execution_marker.display()),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();

        let (rows, _) = rows_from_sources(home.path(), &[], Some(bin.as_os_str()));

        let openclaw = rows.iter().find(|row| row.name == "openclaw").unwrap();
        assert!(openclaw.installed);
        assert_eq!(openclaw.evidence, vec![DiscoveryEvidence::ExecutableOnPath]);
        assert!(
            !execution_marker.exists(),
            "discovery executed an agent binary"
        );
    }

    /// A running Hermes is found by its process. Its hook is written only on
    /// a connect a person runs: automatic setup records no approval in
    /// Hermes's allowlist, which is the person's to give.
    ///
    /// Changed on purpose on 2026-11-15 (main's
    /// `process_evidence_detects_hermes_without_granting_guardability` held
    /// `!hermes.guardable()`): Hermes now has a hook of its own, so it can be
    /// connected (`guardable`). What it does not get until that hook is on is
    /// counted as screened: `status_is_effectively_guarded` is false before
    /// the person's connect and true after it (pinned below, 2026-11-20).
    ///
    /// FAILS ON REVERT: drop the `reject_symlinks` arm of the Hermes branch
    /// in `connect_one_result_with_link_policy` and automatic setup writes the
    /// hook and its approval; count Hermes as screened by its name alone in
    /// `status_is_effectively_guarded` and the first check below fails.
    #[cfg(unix)]
    #[test]
    fn process_evidence_detects_hermes_and_automatic_setup_never_wires_it() {
        let home = tempfile::TempDir::new().unwrap();
        let running = [("Hermes Agent".to_string(), 91)];

        let (rows, _) = rows_from_sources(home.path(), &running, None);

        let hermes = rows.iter().find(|row| row.name == "hermes").unwrap();
        assert_eq!(hermes.pids, vec![91]);
        assert_eq!(hermes.evidence, vec![DiscoveryEvidence::Process]);
        assert!(!hermes.installed);
        assert!(hermes.guardable());
        let automatic =
            connect_one_result_automatic(home.path(), hermes, "/abs/innerwarden", false, false);
        assert_eq!(
            automatic.effect,
            ConnectEffect::Skipped,
            "{}",
            automatic.line
        );
        assert!(!home.path().join(".hermes").exists());
        assert!(
            !status_is_effectively_guarded(home.path(), hermes),
            "screened before any hook is on"
        );

        // The person's connect, with the guard's program there to run.
        use std::os::unix::fs::PermissionsExt;
        let bin = home.path().join("guard-bin/innerwarden");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(home.path().join(".hermes")).unwrap();
        let args = ["connect".to_string(), "hermes".to_string()];
        let outcome = run_with_guard_bin_outcome(home.path(), &args, &bin.display().to_string());
        assert_eq!(outcome.configured, 1, "{:?}", outcome.lines);
        let (rows, _) = rows_from_sources(home.path(), &running, None);
        let hermes = rows.iter().find(|row| row.name == "hermes").unwrap();
        assert!(hermes.guardable());
        assert!(
            status_is_effectively_guarded(home.path(), hermes),
            "screened once its hook is on"
        );
    }

    /// The listing and the repair checks read Hermes from its hook: a hook
    /// Hermes skips is said under the row with its step, a hook that is on
    /// is not, and an agent with no hook has guarding work left while one
    /// with the hook in its file has wiring to switch.
    ///
    /// FAILS ON REVERT: turn `installed() && !is_on()` under the Hermes row
    /// in `list_lines_of` into `||`, or the Hermes test in
    /// `status_has_unguarded_server` into `!=`.
    #[cfg(unix)]
    #[test]
    fn the_listing_says_when_hermes_skips_its_hook() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".hermes")).unwrap();
        std::fs::write(home.path().join(".hermes/config.yaml"), "model: test\n").unwrap();
        let bin = format!("{}innerwarden", installed_guard_dir(home.path()));
        let row = |home: &Path| {
            let (rows, _) = rows_from_sources(home, &[], None);
            rows.into_iter().find(|row| row.name == "hermes").unwrap()
        };
        let skipped = "pre_tool_call hook: installed, but Hermes skips it";
        let hermes = row(home.path());
        assert!(status_has_unguarded_server(home.path(), &hermes));
        assert!(!status_has_guard_wiring(home.path(), &hermes));
        // No hook yet: the row's own words say connect, through its hook,
        // and no hook line.
        let listed = list_lines_of(home.path(), std::slice::from_ref(&hermes)).join("\n");
        assert!(!listed.contains("pre_tool_call hook:"), "{listed}");
        assert!(listed.contains("not guarded, connect via hook"), "{listed}");

        connect_one_result(home.path(), &hermes, &bin, false, false);
        let hermes = row(home.path());
        assert!(!status_has_unguarded_server(home.path(), &hermes));
        assert!(status_has_guard_wiring(home.path(), &hermes));
        let listed = list_lines_of(home.path(), std::slice::from_ref(&hermes)).join("\n");
        assert!(!listed.contains("pre_tool_call hook:"), "{listed}");

        std::fs::remove_file(home.path().join(hermes_hook::ALLOWLIST)).unwrap();
        let hermes = row(home.path());
        let listed = list_lines_of(home.path(), std::slice::from_ref(&hermes)).join("\n");
        assert!(listed.contains(skipped), "{listed}");
        assert!(status_has_guard_wiring(home.path(), &hermes));
        // The line is Hermes's alone: another agent's row does not carry it.
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::write(home.path().join(".cursor/mcp.json"), r#"{"mcpServers":{}}"#).unwrap();
        let (rows, _) = rows_from_sources(home.path(), &[], None);
        let cursor: Vec<AgentStatus> = rows.into_iter().filter(|r| r.name == "cursor").collect();
        assert_eq!(cursor.len(), 1);
        let listed = list_lines_of(home.path(), &cursor).join("\n");
        assert!(!listed.contains("pre_tool_call hook:"), "{listed}");
    }

    /// `agents connect hermes` writes the fail-closed entry and its approval,
    /// says the hook is on with what it screens, `agents` lists it as
    /// guarded by the hook in enforce mode, and `disconnect` takes it out.
    ///
    /// FAILS ON REVERT: drop the Hermes branch of
    /// `connect_one_result_with_link_policy` and the row is connected by no
    /// mechanism.
    #[cfg(unix)]
    #[test]
    fn connect_hermes_wires_its_hook_and_disconnect_takes_it_out() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".hermes")).unwrap();
        std::fs::write(
            home.path().join(".hermes/config.yaml"),
            "model: test
",
        )
        .unwrap();
        let bin = format!("{}innerwarden", installed_guard_dir(home.path()));
        let (rows, _) = rows_from_sources(home.path(), &[], None);
        let hermes = rows.iter().find(|row| row.name == "hermes").unwrap();

        let result = connect_one_result(home.path(), hermes, &bin, false, false);
        assert_eq!(result.effect, ConnectEffect::Connected, "{}", result.line);
        assert!(
            result
                .line
                .starts_with("  hermes - pre_tool_call hook: on (enforce)"),
            "{}",
            result.line
        );
        let config = std::fs::read_to_string(home.path().join(".hermes/config.yaml")).unwrap();
        assert!(config.contains("fail_closed: true"), "{config}");
        let again = connect_one_result(home.path(), hermes, &bin, false, false);
        assert_eq!(again.effect, ConnectEffect::Unchanged, "{}", again.line);
        let (rows, _) = rows_from_sources(home.path(), &[], None);
        let hermes = rows.iter().find(|row| row.name == "hermes").unwrap();
        assert!(hermes.guarded);
        assert_eq!(hermes.mode, Some(GuardMode::Enforce));

        assert_eq!(
            disconnect_one(home.path(), hermes),
            "  hermes, disconnected"
        );
        assert_eq!(
            std::fs::read_to_string(home.path().join(".hermes/config.yaml")).unwrap(),
            "model: test\n"
        );
        assert_eq!(
            disconnect_one(home.path(), hermes),
            "  hermes, was not connected"
        );

        // Monitor is read back as monitor.
        let watched = connect_one_result(home.path(), hermes, &bin, false, true);
        assert_eq!(watched.effect, ConnectEffect::Connected, "{}", watched.line);
        let (rows, _) = rows_from_sources(home.path(), &[], None);
        let hermes = rows.iter().find(|row| row.name == "hermes").unwrap();
        assert_eq!(hermes.mode, Some(GuardMode::Monitor));
    }

    #[test]
    fn generic_mcp_configs_are_discovered_connected_and_reported() {
        let home = tempfile::TempDir::new().unwrap();
        for rel in [".new-agent", ".config/another-agent"] {
            std::fs::create_dir_all(home.path().join(rel)).unwrap();
            std::fs::write(
                home.path().join(rel).join("mcp.json"),
                r#"{"mcpServers":{"local":{"command":"npx","args":["server"]}}}"#,
            )
            .unwrap();
        }
        // Do not crawl project/workspace trees merely because they contain an
        // mcp.json; discovery is intentionally limited to config roots.
        std::fs::create_dir_all(home.path().join("work/project")).unwrap();
        std::fs::write(
            home.path().join("work/project/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"node"}}}"#,
        )
        .unwrap();

        assert_eq!(
            home_mcp_configs(home.path()),
            vec![
                ".config/another-agent/mcp.json".to_string(),
                ".new-agent/mcp.json".to_string()
            ]
        );
        let before = rows(home.path());
        let generic: Vec<_> = before
            .iter()
            .filter(|row| row.name == "another-agent" || row.name == "new-agent")
            .collect();
        assert_eq!(generic.len(), 2);
        assert!(generic.iter().all(|row| {
            row.guardable()
                && !row.guarded
                && !row.installed
                && row.evidence == vec![DiscoveryEvidence::CompatibleMcpConfiguration]
        }));

        let guard = format!("{}innerwarden", installed_guard_dir(home.path()));
        for row in generic {
            let line = connect_one(home.path(), row, &guard, false, true);
            assert!(line.contains("connected"), "{line}");
        }
        let after = rows(home.path());
        assert!(after
            .iter()
            .filter(|row| row.name == "another-agent" || row.name == "new-agent")
            .all(|row| row.guarded && has_guard_wiring(home.path(), &row.name)));
    }

    /// A guardable agent that needs nothing installed on the host running the
    /// suite: a recognizable MCP configuration under a disposable HOME.
    fn a_generic_mcp_agent(home: &Path) {
        std::fs::create_dir_all(home.join(".new-agent")).unwrap();
        std::fs::write(
            home.join(".new-agent/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"node"}}}"#,
        )
        .unwrap();
    }

    /// The structured signal a caller needs in order to say "restart your
    /// agents" without scanning the human-facing lines for a word.
    ///
    /// One NAMED target, so the count is exact and does not depend on which
    /// agents happen to be installed on the machine running the suite.
    ///
    /// The direction a scan gets wrong is asserted directly: re-running
    /// `connect` over an already-wired integration prints `already guarded
    /// (...)`, which does NOT contain the word "connected" while the integration
    /// is very much configured. Counting by `contains("connected")` reports zero
    /// there, and the caller stays silent about the restart.
    #[test]
    fn an_already_wired_integration_still_counts_as_configured() {
        let home = tempfile::TempDir::new().unwrap();
        a_generic_mcp_agent(home.path());
        let args = vec!["connect".into(), "new-agent".into(), "--monitor".into()];

        let first = run_with_guard_bin_outcome(home.path(), &args, "/abs/innerwarden");
        assert_eq!(first.lines.len(), 1, "{:?}", first.lines);
        assert_eq!(first.configured, 1, "{:?}", first.lines);

        let again = run_with_guard_bin_outcome(home.path(), &args, "/abs/innerwarden");
        assert_eq!(again.lines.len(), 1, "{:?}", again.lines);
        assert!(
            again.lines[0].contains("already guarded"),
            "this test only proves something while the second connect reports \
             the unchanged wording: {:?}",
            again.lines
        );
        assert!(
            !again.lines[0].contains("connected"),
            "and only while that wording lacks the word a naive scan keys on: {:?}",
            again.lines
        );
        assert_eq!(
            again.configured, 1,
            "an integration that is already wired IS configured; counting by \
             scanning the line reports zero here: {:?}",
            again.lines
        );
    }

    /// `disconnect` unwires, so it configures nothing and a caller keying on the
    /// count cannot tell someone to restart after they deliberately unwired.
    /// Its `was not connected` line CONTAINS the word a naive scan keys on.
    #[test]
    fn disconnect_configures_nothing_even_when_its_lines_say_connected() {
        let home = tempfile::TempDir::new().unwrap();
        a_generic_mcp_agent(home.path());

        let outcome = run_with_guard_bin_outcome(
            home.path(),
            &["disconnect".into(), "new-agent".into()],
            "/abs/innerwarden",
        );
        assert_eq!(outcome.configured, 0, "{:?}", outcome.lines);
        assert!(
            outcome.lines.iter().any(|line| line.contains("connected")),
            "this test only proves something while a disconnect line carries \
             the word a naive scan keys on: {:?}",
            outcome.lines
        );

        let listed = run_with_guard_bin_outcome(home.path(), &["list".into()], "/abs/innerwarden");
        assert_eq!(listed.configured, 0, "listing configures nothing");
    }

    /// A `connect` that found nothing to wire configured nothing.
    #[test]
    fn a_connect_with_no_guardable_target_configures_nothing() {
        let home = tempfile::TempDir::new().unwrap();

        let outcome = run_with_guard_bin_outcome(
            home.path(),
            &["connect".into(), "no-such-agent".into()],
            "/abs/innerwarden",
        );

        assert_eq!(outcome.configured, 0, "{:?}", outcome.lines);
    }

    #[test]
    fn generic_discovery_reports_when_the_aggregate_byte_budget_is_limited() {
        let home = tempfile::TempDir::new().unwrap();
        for name in [
            ".large-one",
            ".large-two",
            ".large-three",
            ".large-four",
            ".large-five",
        ] {
            let directory = home.path().join(name);
            std::fs::create_dir_all(&directory).unwrap();
            let file = std::fs::File::create(directory.join("mcp.json")).unwrap();
            file.set_len(15 * 1024 * 1024).unwrap();
        }

        let discovery = home_mcp_configs_with_status(home.path());

        assert!(discovery.limited);
        assert_eq!(discovery.paths.len(), 4);
        assert!(!discovery.paths.contains(&".large-two/mcp.json".into()));
    }

    #[test]
    fn known_mcp_path_does_not_create_a_duplicate_generic_row() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::write(
            home.path().join(".cursor/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"npx"}}}"#,
        )
        .unwrap();
        let found = rows(home.path());
        assert_eq!(found.iter().filter(|row| row.name == "cursor").count(), 1);
        assert!(found.iter().all(|row| row.name != "cursor-mcp"));
    }

    #[test]
    fn generic_config_cannot_impersonate_a_known_agent_name() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".config/cursor")).unwrap();
        std::fs::write(
            home.path().join(".config/cursor/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"npx"}}}"#,
        )
        .unwrap();
        let before = rows(home.path());
        let generic = before
            .iter()
            .find(|row| row.mcp_json.as_deref() == Some(".config/cursor/mcp.json"))
            .unwrap();
        assert_eq!(generic.name, "cursor-mcp");
        assert!(!has_guard_wiring(home.path(), &generic.name));

        let result = connect_one_result(home.path(), generic, "/abs/innerwarden", false, true);
        assert_eq!(result.effect, ConnectEffect::Connected);
        assert!(has_guard_wiring(home.path(), "cursor-mcp"));
    }

    #[test]
    fn unreviewed_aider_shaped_mcp_file_stays_a_generic_manual_client() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".config/aider")).unwrap();
        std::fs::write(
            home.path().join(".config/aider/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"aider-mcp"}}}"#,
        )
        .unwrap();
        let found = rows(home.path());
        assert!(found.iter().all(|row| row.name != "aider"));
        let generic = found.iter().find(|row| row.name == "aider-mcp").unwrap();
        assert!(!generic.installed);
        assert_eq!(
            generic.evidence,
            vec![DiscoveryEvidence::CompatibleMcpConfiguration]
        );
        assert_eq!(generic.mcp_json.as_deref(), Some(".config/aider/mcp.json"));
    }

    #[test]
    fn arbitrary_file_named_mcp_json_is_not_capability_evidence() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".not-an-agent")).unwrap();
        std::fs::write(
            home.path().join(".not-an-agent/mcp.json"),
            r#"{"theme":"dark"}"#,
        )
        .unwrap();

        let (rows, _) = rows_from_sources(home.path(), &[], None);

        assert!(rows.iter().all(|row| row.name != "not-an-agent"));
    }

    #[test]
    fn nested_mcp_servers_are_visible_but_never_gain_connect_authority() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".nested-agent")).unwrap();
        std::fs::write(
            home.path().join(".nested-agent/mcp.json"),
            r#"{"mcp":{"servers":{"local":{"command":"npx"}}}}"#,
        )
        .unwrap();

        let (rows, _) = rows_from_sources(home.path(), &[], None);

        let nested = rows.iter().find(|row| row.name == "nested-agent").unwrap();
        assert_eq!(
            nested.evidence,
            vec![DiscoveryEvidence::CompatibleMcpConfiguration]
        );
        assert!(!nested.installed);
        assert!(!nested.guardable());
        assert!(connect_targets(&rows, Some("nested-agent")).is_empty());
    }

    #[test]
    fn partial_json_and_toml_wiring_is_still_discoverable_for_repair() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::write(
            home.path().join(".cursor/mcp.json"),
            r#"{"mcpServers":{"guarded":{"command":"innerwarden","args":["proxy","--mode","advisory","--","npx","one"]},"late":{"command":"npx","args":["two"]}}}"#,
        )
        .unwrap();
        assert!(has_guard_wiring(home.path(), "cursor"));
        assert!(!is_guarded(home.path(), "cursor", None));

        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            "[mcp_servers.guarded]\ncommand = \"innerwarden\"\nargs = [\"proxy\", \"--\", \"npx\"]\n\n[mcp_servers.late]\ncommand = \"node\"\n",
        )
        .unwrap();
        assert!(has_guard_wiring(home.path(), "codex"));
        assert!(!is_guarded(home.path(), "codex", None));
    }

    /// The mode `agents` and `status` print for an MCP agent was a search of
    /// the configuration's text for `"advisory"`, `"warn"`, `"guard"` and
    /// `"kill"` anywhere. The words a configuration holds for other reasons
    /// (a log level, a server's own argument) decided it, and the inline
    /// `--mode=advisory` matched nothing.
    ///
    /// The attacker form is the first: whoever can edit the agent's own
    /// configuration (the agent itself, under its user's account) turns every
    /// wrapper to `--mode=advisory`, so the proxies only record, and the listing
    /// kept saying enforce because another `"guard"` was in the file.
    ///
    /// FAILS ON REVERT: restore the text search in `read_guard_mode`; the
    /// recording Cursor wiring reads `Some(Enforce)`.
    #[test]
    fn the_listed_mcp_mode_is_what_each_wrapper_runs_not_a_word_in_the_file() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        let cases = [
            (
                // Records only; `"guard"` is a profile the server is given.
                r#"{"mcpServers":{"fs":{"command":"/abs/innerwarden","args":["proxy","--label","cursor","--agent","cursor","--mode=advisory","--","npx","fs-server","--profile","guard"]}}}"#,
                "[mcp_servers.icm]\ncommand = \"/abs/innerwarden\"\nargs = [\"proxy\", \"--mode=advisory\", \"--\", \"icm\"]\nenv = { ICM_POLICY = \"kill\" }\n",
                GuardMode::Monitor,
            ),
            (
                // Blocks; `"warn"` is the server's log level.
                r#"{"mcpServers":{"fs":{"command":"/abs/innerwarden","args":["proxy","--mode","guard","--","npx","fs-server"],"env":{"LOG_LEVEL":"warn"}}}}"#,
                "log_level = \"warn\"\n\n[mcp_servers.icm]\ncommand = \"/abs/innerwarden\"\nargs = [\"proxy\", \"--mode\", \"guard\", \"--\", \"icm\"]\n",
                GuardMode::Enforce,
            ),
        ];
        for (cursor, codex, mode) in cases {
            let abs = installed_guard_dir(home.path());
            std::fs::write(
                home.path().join(".cursor/mcp.json"),
                cursor.replace("/abs/", &abs),
            )
            .unwrap();
            std::fs::write(
                home.path().join(".codex/config.toml"),
                codex.replace("/abs/", &abs),
            )
            .unwrap();

            let (rows, _) = rows_from_sources(home.path(), &[], None);

            for name in ["cursor", "codex"] {
                let row = rows.iter().find(|row| row.name == name).unwrap();
                assert!(row.guarded, "{name}: {cursor} / {codex}");
                assert_eq!(row.mode, Some(mode), "{name}: {cursor} / {codex}");
            }
        }
    }

    /// A wrapper is the guard only when its command is the guard's binary,
    /// and only when its proxy starts.
    ///
    /// The attacker forms: the agent's own account writes a script named
    /// `innerwarden-shim` that runs whatever follows `--`, and points each
    /// server at it with `proxy --mode guard -- <server>`; every call then
    /// reaches the server unscreened while the listing said enforce, because
    /// any command whose name began with `innerwarden` counted. Or it adds an
    /// option the proxy does not take (`--verbose`): the proxy exits on it,
    /// the server never starts through it, and the listing said enforce
    /// because unknown words were stepped over. Both are now listed as not
    /// guarded. The installer's `iw-guard` shortcut, which was not recognised
    /// at all, is the guard.
    ///
    /// FAILS ON REVERT: accept any `innerwarden*` command again, or step over
    /// a word the proxy refuses, and the first two read guarded, `Enforce`.
    #[test]
    fn a_shim_or_a_proxy_that_cannot_start_is_not_listed_as_guarded() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        let cases = [
            (
                r#"{"mcpServers":{"fs":{"command":"/home/u/.local/bin/innerwarden-shim","args":["proxy","--mode","guard","--","npx","fs-server"]}}}"#,
                "[mcp_servers.icm]\ncommand = \"/home/u/.local/bin/innerwarden-shim\"\nargs = [\"proxy\", \"--mode\", \"guard\", \"--\", \"icm\"]\n",
                false,
                None,
            ),
            (
                r#"{"mcpServers":{"fs":{"command":"/abs/innerwarden","args":["proxy","--mode","guard","--verbose","--","npx","fs-server"]}}}"#,
                "[mcp_servers.icm]\ncommand = \"/abs/innerwarden\"\nargs = [\"proxy\", \"--mode\", \"guard\", \"--verbose\", \"--\", \"icm\"]\n",
                false,
                None,
            ),
            (
                r#"{"mcpServers":{"fs":{"command":"/abs/iw-guard","args":["proxy","--mode","guard","--error-response","--","npx","fs-server"]}}}"#,
                "[mcp_servers.icm]\ncommand = \"C:\\\\Tools\\\\IW-GUARD.EXE\"\nargs = [\"proxy\", \"--mode\", \"guard\", \"--\", \"icm\"]\n",
                true,
                Some(GuardMode::Enforce),
            ),
        ];
        for (cursor, codex, guarded, mode) in cases {
            let abs = installed_guard_dir(home.path());
            std::fs::write(
                home.path().join(".cursor/mcp.json"),
                cursor.replace("/abs/", &abs),
            )
            .unwrap();
            std::fs::write(
                home.path().join(".codex/config.toml"),
                codex.replace("/abs/", &abs),
            )
            .unwrap();

            let (rows, _) = rows_from_sources(home.path(), &[], None);

            for name in ["cursor", "codex"] {
                let row = rows.iter().find(|row| row.name == name).unwrap();
                assert_eq!(row.guarded, guarded, "{name}: {cursor} / {codex}");
                assert_eq!(row.mode, mode, "{name}: {cursor} / {codex}");
            }
        }
    }

    /// A generic MCP client's mode is read from ITS configuration. The row's
    /// name was looked up in the reviewed table instead, so a guarded generic
    /// client had no mode ("mode unreadable", and `status` printed the mode as
    /// unknown for the whole host), and one in `~/.claude/`, which is named
    /// `claude`, an alias of Claude Code, was given the Claude Code hook's mode.
    ///
    /// FAILS ON REVERT: look the row up by name again; `claude` reads
    /// `Some(Enforce)` (the hook's) and `windsurf` reads `None`.
    #[test]
    fn a_generic_mcp_client_reports_the_mode_of_its_own_configuration() {
        let home = tempfile::TempDir::new().unwrap();
        let recording = r#"{"mcpServers":{"fs":{"command":"/abs/innerwarden","args":["proxy","--mode","advisory","--","npx","fs-server"]}}}"#
            .replace("/abs/", &installed_guard_dir(home.path()));
        for dir in [".claude", ".windsurf"] {
            std::fs::create_dir_all(home.path().join(dir)).unwrap();
            std::fs::write(home.path().join(dir).join("mcp.json"), &recording).unwrap();
        }
        // Claude Code's own hook enforces.
        std::fs::write(
            home.path().join(".claude/settings.json"),
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/abs/innerwarden hook"}]}]}}"#,
        )
        .unwrap();

        let (rows, _) = rows_from_sources(home.path(), &[], None);

        for name in ["claude", "windsurf"] {
            let row = rows.iter().find(|row| row.name == name).unwrap();
            assert_eq!(
                row.mcp_json.as_deref(),
                Some(format!(".{name}/mcp.json").as_str())
            );
            assert!(row.guarded, "{name}");
            assert_eq!(row.mode, Some(GuardMode::Monitor), "{name}");
        }
    }

    #[test]
    fn unknown_connect_flag_fails_without_wiring_every_agent() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        let original = r#"{"mcpServers":{"local":{"command":"npx"}}}"#;
        std::fs::write(home.path().join(".cursor/mcp.json"), original).unwrap();

        let output = run_with_guard_bin(
            home.path(),
            &["connect".into(), "--monitro".into()],
            "/abs/innerwarden",
        );
        assert!(output.iter().any(|line| line.contains("failed:")));
        assert_eq!(
            std::fs::read_to_string(home.path().join(".cursor/mcp.json")).unwrap(),
            original
        );
    }

    #[test]
    fn unknown_disconnect_flag_fails_without_broadening_to_all() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::write(
            home.path().join(".cursor/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"npx"}}}"#,
        )
        .unwrap();
        let row = rows(home.path())
            .into_iter()
            .find(|agent| agent.name == "cursor")
            .unwrap();
        let guard = format!("{}innerwarden", installed_guard_dir(home.path()));
        assert!(connect_one_result(home.path(), &row, &guard, false, true).configured());

        let output = run_with_guard_bin(home.path(), &["disconnect".into(), "--al".into()], &guard);
        assert!(output.iter().any(|line| line.contains("failed:")));
        assert!(is_guarded(home.path(), "cursor", None));
    }

    #[test]
    fn automatic_connect_rechecks_structure_and_existing_wiring_from_exact_bytes() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        let invalid = r#"{"mcpServers":{"local":{"command":"npx","args":"--foo"}}}"#;
        std::fs::write(home.path().join(".cursor/mcp.json"), invalid).unwrap();
        let row = rows(home.path())
            .into_iter()
            .find(|agent| agent.name == "cursor")
            .unwrap();
        let result =
            connect_one_result_automatic(home.path(), &row, "/abs/innerwarden", false, true);
        assert_eq!(result.effect, ConnectEffect::Skipped);
        assert_eq!(
            std::fs::read_to_string(home.path().join(".cursor/mcp.json")).unwrap(),
            invalid
        );

        let existing = r#"{"mcpServers":{"local":{"command":"innerwarden","args":["proxy","--mode","guard","--","npx"]}}}"#;
        std::fs::write(home.path().join(".cursor/mcp.json"), existing).unwrap();
        let row = rows(home.path())
            .into_iter()
            .find(|agent| agent.name == "cursor")
            .unwrap();
        let result =
            connect_one_result_automatic(home.path(), &row, "/abs/innerwarden", false, true);
        assert_eq!(result.effect, ConnectEffect::Skipped);
        assert_eq!(
            std::fs::read_to_string(home.path().join(".cursor/mcp.json")).unwrap(),
            existing
        );
    }

    /// cs-L279. An MCP agent wired to a proxy whose binary is gone is not
    /// guarded: its servers cannot start (closed, not open), and the row
    /// says why and how to repair it, never by unwrapping the servers.
    ///
    /// FAILS ON REVERT (wrappers judged by their text alone): the row reads
    /// guarded and the dashboard counts it as an effective guard.
    #[cfg(unix)]
    #[test]
    fn an_mcp_agent_whose_proxy_binary_is_gone_is_not_guarded() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        let gone = home.path().join("removed/innerwarden");
        std::fs::write(
            home.path().join(".cursor/mcp.json"),
            format!(
                r#"{{"mcpServers":{{"fs":{{"command":"{}","args":["proxy","--mode","advisory","--","npx","fs-server"]}}}}}}"#,
                gone.display()
            ),
        )
        .unwrap();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            format!(
                "[mcp_servers.icm]\ncommand = \"{}\"\nargs = [\"proxy\", \"--mode\", \"guard\", \"--\", \"icm\"]\n",
                gone.display()
            ),
        )
        .unwrap();

        let (rows, _) = rows_from_sources(home.path(), &[], None);
        for name in ["cursor", "codex"] {
            let row = rows.iter().find(|row| row.name == name).unwrap();
            assert!(
                !row.guarded,
                "{name}: a wrapper whose binary is gone guards nothing"
            );
            assert!(
                !status_is_effectively_guarded(home.path(), row),
                "{name}: the dashboard must not count it"
            );
            assert!(
                status_has_guard_wiring(home.path(), row),
                "{name}: still wired, for repair"
            );
            match mcp_proxy_program(home.path(), row) {
                Some(hook::HookProgram::Broken { problem, .. }) => {
                    assert!(problem.contains("does not exist"), "{problem}");
                    assert!(problem.contains(&gone.display().to_string()), "{problem}");
                }
                other => panic!("{name}: expected broken, got {other:?}"),
            }
        }
        assert_eq!(
            proxy_repair_command(
                home.path(),
                rows.iter().find(|r| r.name == "cursor").unwrap()
            ),
            "innerwarden agents connect cursor --monitor",
            "the repair keeps the mode the wrappers had"
        );
        assert_eq!(
            proxy_repair_command(
                home.path(),
                rows.iter().find(|r| r.name == "codex").unwrap()
            ),
            "innerwarden agents connect codex"
        );

        // The same wiring with its binary back is guarded again.
        let abs = installed_guard_dir(home.path());
        let back = format!("{abs}innerwarden");
        for rel in [".cursor/mcp.json", ".codex/config.toml"] {
            let text = std::fs::read_to_string(home.path().join(rel)).unwrap();
            std::fs::write(
                home.path().join(rel),
                text.replace(&gone.display().to_string(), &back),
            )
            .unwrap();
        }
        let (rows, _) = rows_from_sources(home.path(), &[], None);
        for name in ["cursor", "codex"] {
            let row = rows.iter().find(|row| row.name == name).unwrap();
            assert!(row.guarded, "{name}");
            assert!(status_is_effectively_guarded(home.path(), row), "{name}");
            assert_eq!(
                mcp_proxy_program(home.path(), row),
                Some(hook::HookProgram::Runs)
            );
        }
    }

    /// One wrapper that runs is enough; one that could not be checked is
    /// unknown, never broken.
    #[test]
    fn proxy_programs_are_judged_like_hooks() {
        use hook::{HookProgram, ProgramFact};
        let abs = if cfg!(windows) {
            r"C:\x\innerwarden.exe"
        } else {
            "/x/innerwarden"
        };
        let gone = vec![abs.to_string()];
        assert!(matches!(
            judge_proxy_programs(&gone, |_| ProgramFact::Missing),
            Some(HookProgram::Broken { .. })
        ));
        assert!(matches!(
            judge_proxy_programs(&gone, |_| ProgramFact::Unreadable),
            Some(HookProgram::Unknown { .. })
        ));
        let two = vec![abs.to_string(), "innerwarden".to_string()];
        assert_eq!(
            judge_proxy_programs(&two, |p| if p == "innerwarden" {
                ProgramFact::Missing
            } else {
                ProgramFact::Executable
            }),
            Some(HookProgram::Runs)
        );
        assert_eq!(judge_proxy_programs(&[], |_| ProgramFact::Missing), None);
    }

    /// A wrapper that names its program bare is found on the MCP client's
    /// PATH, not this one: found here it is "could not tell", with where it
    /// was found as a clue; found nowhere here (this PATH and the usual
    /// places), off. The same rule as a hook's bare name.
    ///
    /// FAILS ON REVERT: judge the bare name by this process's PATH alone,
    /// and the one found here reads as running.
    #[test]
    fn a_bare_proxy_program_found_here_could_not_be_told_and_one_found_nowhere_is_off() {
        use hook::{HookProgram, ProgramFact};
        for fact in [ProgramFact::Executable, ProgramFact::Unreadable] {
            match judge_proxy_program("innerwarden", fact) {
                HookProgram::Unknown { why, .. } => {
                    assert!(why.starts_with(hook::BARE_NAME), "{fact:?}: {why}");
                    assert!(why.contains("its MCP proxy runs `innerwarden`"), "{why}");
                }
                other => panic!("{fact:?}: {other:?}"),
            }
        }
        for fact in [ProgramFact::Missing, ProgramFact::NotExecutable] {
            match judge_proxy_program("innerwarden", fact) {
                HookProgram::Broken { problem, .. } => {
                    assert!(
                        problem
                            .starts_with("its MCP proxy runs `innerwarden`, which is not on PATH"),
                        "{problem}"
                    );
                }
                other => panic!("{fact:?}: {other:?}"),
            }
        }
        // End to end over a real config: the wrapper's bare name is on this
        // PATH, and the verdict says where, never "runs".
        let home = tempfile::TempDir::new().unwrap();
        let bin = home.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let exe = bin.join("innerwarden");
        std::fs::write(&exe, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::write(
            home.path().join(".cursor/mcp.json"),
            serde_json::json!({"mcpServers": {"fs": {
                "command": "innerwarden",
                "args": ["proxy", "--", "npx", "server-filesystem"]
            }}})
            .to_string(),
        )
        .unwrap();
        let (rows, _) = rows_from_sources(home.path(), &[], None);
        let row = rows
            .into_iter()
            .find(|row| row.name == "cursor")
            .expect("cursor row");
        assert_eq!(row.mcp_json.as_deref(), Some(".cursor/mcp.json"));
        let path = std::ffi::OsString::from(bin.as_os_str());
        match mcp_proxy_program_with(home.path(), &row, Some(&path), &[]) {
            Some(HookProgram::Unknown { why, .. }) => {
                assert!(why.starts_with(hook::BARE_NAME), "{why}");
                assert!(
                    why.contains(&format!("found here at {}", exe.display())),
                    "{why}"
                );
            }
            other => panic!("{other:?}"),
        }
        let nowhere = std::ffi::OsString::from(home.path().join("empty").as_os_str());
        assert!(matches!(
            mcp_proxy_program_with(home.path(), &row, Some(&nowhere), &[]),
            Some(HookProgram::Broken { .. })
        ));
    }

    /// A directory holding the guard's binaries (`innerwarden`, `iw-guard`)
    /// as executable files, ending in a separator: the `/abs/` these tests
    /// write wrappers with is replaced by it. A wrapper whose binary does not
    /// exist is not guarded (its servers cannot start), so a wrapper that IS
    /// guarded needs a binary that is there.
    ///
    /// Off Unix the fixed `/abs/` is kept: it is not an absolute path there,
    /// so it is judged unknown, which is never "off".
    fn installed_guard_dir(home: &Path) -> String {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = home.join("guard-bin");
            std::fs::create_dir_all(&dir).unwrap();
            for name in ["innerwarden", "iw-guard"] {
                let bin = dir.join(name);
                std::fs::write(&bin, "#!/bin/sh\n").unwrap();
                std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            format!("{}/", dir.display())
        }
        #[cfg(not(unix))]
        {
            let _ = home;
            "/abs/".to_string()
        }
    }

    /// With ~/.cursor a link to another folder, automatic setup writes
    /// nothing there: not the hooks (it never writes Cursor's, Codex's or
    /// Gemini's hook) and not the MCP config (it refuses a linked path). A
    /// connect the person runs follows the link, as it does for every agent:
    /// the person chose where their Cursor folder lives.
    ///
    /// FAILS ON REVERT: let automatic setup take the `connect_hook_and_proxy`
    /// arm in `connect_one_result_with_link_policy`, and hooks.json appears
    /// behind the link.
    #[cfg(unix)]
    #[test]
    fn a_linked_cursor_folder_is_never_written_by_automatic_setup() {
        let home = tempfile::TempDir::new().unwrap();
        let elsewhere = tempfile::TempDir::new().unwrap();
        let target = elsewhere.path().join("cursor");
        std::fs::create_dir_all(&target).unwrap();
        let mcp = r#"{"mcpServers":{"files":{"command":"npx","args":["files-server"]}}}"#;
        std::fs::write(target.join("mcp.json"), mcp).unwrap();
        // Discovery does not follow a linked folder: the row is read while
        // ~/.cursor is a folder, and the folder becomes a link after, as a
        // change between discovery and the write would.
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::write(home.path().join(".cursor/mcp.json"), mcp).unwrap();
        let cursor = known_row(home.path(), "cursor");
        std::fs::remove_dir_all(home.path().join(".cursor")).unwrap();
        std::os::unix::fs::symlink(&target, home.path().join(".cursor")).unwrap();

        let automatic =
            connect_one_result_automatic(home.path(), &cursor, "/abs/innerwarden", false, false);
        assert_ne!(
            automatic.effect,
            ConnectEffect::Connected,
            "{}",
            automatic.line
        );
        assert!(!target.join("hooks.json").exists(), "{}", automatic.line);
        assert_eq!(
            std::fs::read_to_string(target.join("mcp.json")).unwrap(),
            mcp
        );

        let person = connect_one_result(home.path(), &cursor, "/abs/innerwarden", false, false);
        assert_ne!(person.effect, ConnectEffect::Failed, "{}", person.line);
        assert!(target.join("hooks.json").exists(), "{}", person.line);
    }

    fn known_row(home: &Path, name: &str) -> AgentStatus {
        let (rows, _) = rows_from_sources(home, &[], None);
        rows.into_iter().find(|row| row.name == name).unwrap()
    }

    fn openclaw_server_args(config: &Value, name: &str) -> Vec<String> {
        config["mcp"]["servers"][name]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap().to_string())
            .collect()
    }

    fn read_openclaw(home: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(home.join(".openclaw/openclaw.json")).unwrap())
            .unwrap()
    }

    /// REGRESSION ANCHOR. `agents connect openclaw` wrote `proxy --mode M --
    /// <server>` and nothing else, so the proxy recorded every OpenClaw tool
    /// call in the session `mcp:innerwarden` naming no agent, and its cases
    /// said "An agent asked, through an MCP connection".
    ///
    /// FAILS ON REVERT: pass no agent to `mcp_wire::wrap` from
    /// `connect_one_result_with_link_policy`, and every proxy reads
    /// `proxy --mode advisory -- ...`.
    #[test]
    fn connect_openclaw_writes_its_id_on_every_proxy() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".openclaw")).unwrap();
        std::fs::write(
            home.path().join(".openclaw/openclaw.json"),
            r#"{"gateway":{"port":18789},"mcp":{"servers":{
                "fs":{"command":"npx","args":["-y","fs-server"]},
                "git":{"command":"uvx","args":["mcp-server-git"]},
                "remote":{"url":"https://example.com/sse"}}}}"#,
        )
        .unwrap();
        let row = known_row(home.path(), "openclaw");

        let result = connect_one_result(home.path(), &row, "/abs/innerwarden", false, true);
        assert_eq!(result.effect, ConnectEffect::Connected, "{}", result.line);

        let config = read_openclaw(home.path());
        for (name, child) in [
            ("fs", vec!["npx", "-y", "fs-server"]),
            ("git", vec!["uvx", "mcp-server-git"]),
        ] {
            let mut expected = vec![
                "proxy", "--label", "openclaw", "--agent", "openclaw", "--mode", "advisory", "--",
            ];
            expected.extend(child);
            assert_eq!(openclaw_server_args(&config, name), expected, "{name}");
            assert_eq!(
                config["mcp"]["servers"][name]["command"],
                "/abs/innerwarden"
            );
        }
        // A connect a person runs carries the remote server too
        // (`mcp_proxy::remote`); its proxy names OpenClaw and its address.
        assert_eq!(
            openclaw_server_args(&config, "remote"),
            vec![
                "proxy",
                "--label",
                "openclaw",
                "--agent",
                "openclaw",
                "--mode",
                "advisory",
                "--",
                "https://example.com/sse"
            ]
        );
        assert_eq!(config["gateway"], serde_json::json!({"port": 18789}));
    }

    /// The Goose twin: `agents connect goose` routes every stdio extension of
    /// a real `~/.config/goose/config.yaml` through the proxy, naming Goose,
    /// and changes no other line of the person's file; the row then reads
    /// guarded in that mode; a second connect writes nothing; disconnect
    /// takes out only what connect put in, and Goose reads back the document
    /// it had.
    ///
    /// FAILS ON REVERT: drop `mcp_yaml` from Goose's row (connect answers
    /// "no automatic wiring" and writes nothing).
    #[test]
    fn connect_goose_wraps_its_yaml_servers_and_disconnect_takes_out_only_ours() {
        const BIN: &str = "/abs/innerwarden";
        let original = "# my Goose\nGOOSE_PROVIDER: anthropic\nextensions:\n  developer:\n    enabled: true\n    name: developer\n    type: builtin\n  # added by hand\n  github:\n    args:\n    - -y\n    - '@modelcontextprotocol/server-github'\n    cmd: npx\n    enabled: true\n    envs: {}\n    name: github\n    timeout: 300\n    type: stdio\nGOOSE_MODE: smart_approve\n";
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".config/goose")).unwrap();
        let path = home.path().join(".config/goose/config.yaml");
        std::fs::write(&path, original).unwrap();
        let row = known_row(home.path(), "goose");
        assert_eq!(mechanism(&row), "MCP proxy");

        let result = connect_one_result(home.path(), &row, BIN, false, false);
        assert_eq!(result.effect, ConnectEffect::Connected, "{}", result.line);
        assert!(result.line.contains("1 MCP server"), "{}", result.line);
        assert!(
            result.line.contains("built-in extensions are not screened"),
            "{}",
            result.line
        );
        let wired = std::fs::read_to_string(&path).unwrap();
        for kept in [
            "# my Goose\n",
            "  # added by hand\n",
            "  developer:\n    enabled: true\n    name: developer\n    type: builtin\n",
            "    enabled: true\n    envs: {}\n    name: github\n    timeout: 300\n    type: stdio\nGOOSE_MODE: smart_approve\n",
        ] {
            assert!(wired.contains(kept), "{kept:?} in {wired}");
        }
        let doc: serde_yaml::Value = serde_yaml::from_str(&wired).unwrap();
        assert_eq!(doc["extensions"]["github"]["cmd"], BIN);
        let args: Vec<&str> = doc["extensions"]["github"]["args"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "proxy",
                "--label",
                "goose",
                "--agent",
                "goose",
                "--mode",
                "guard",
                "--",
                "npx",
                "-y",
                "@modelcontextprotocol/server-github"
            ]
        );
        assert!(has_guard_wiring(home.path(), "goose"));
        assert!(!status_has_unguarded_server(home.path(), &row));
        assert_eq!(mcp_guard_mode(home.path(), &row), Some(GuardMode::Enforce));

        let again = connect_one_result(home.path(), &row, BIN, false, false);
        assert_eq!(again.effect, ConnectEffect::Unchanged, "{}", again.line);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), wired);

        let monitor = connect_one_result(home.path(), &row, BIN, false, true);
        assert_eq!(monitor.effect, ConnectEffect::Connected, "{}", monitor.line);
        assert_eq!(mcp_guard_mode(home.path(), &row), Some(GuardMode::Monitor));

        assert_eq!(disconnect_one(home.path(), &row), "  goose, disconnected");
        let restored = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            serde_yaml::from_str::<serde_yaml::Value>(&restored).unwrap(),
            serde_yaml::from_str::<serde_yaml::Value>(original).unwrap()
        );
        assert!(
            restored.starts_with("# my Goose\nGOOSE_PROVIDER: anthropic\n"),
            "{restored}"
        );
        assert!(restored.contains("  # added by hand\n"), "{restored}");
        assert!(!has_guard_wiring(home.path(), "goose"));
        assert_eq!(
            disconnect_one(home.path(), &row),
            "  goose, was not connected"
        );
    }

    /// A Goose config that is there and cannot be read (two documents, a
    /// merge key in its extensions) is not "nothing left to guard": the
    /// status counts work left and the listing says the file cannot be read.
    ///
    /// FAILS ON REVERT of `yaml_unreadable` in `status_has_unguarded_server`
    /// (false: nothing unguarded) or of the listing's unreadable line.
    #[test]
    fn an_unreadable_goose_config_is_unknown_not_guarded() {
        for text in [
            "extensions:\n  github:\n    type: stdio\n    cmd: npx\n---\nGOOSE_MODE: auto\n",
            "base: &b\n  type: stdio\n  cmd: npx\nextensions:\n  github:\n    <<: *b\n    enabled: true\n",
        ] {
            let home = tempfile::TempDir::new().unwrap();
            std::fs::create_dir_all(home.path().join(".config/goose")).unwrap();
            let path = home.path().join(".config/goose/config.yaml");
            std::fs::write(&path, text).unwrap();
            let row = known_row(home.path(), "goose");
            assert!(status_has_unguarded_server(home.path(), &row), "{text}");
            let lines = list_lines_of(home.path(), std::slice::from_ref(&row)).join("\n");
            assert!(lines.contains("its MCP config cannot be read"), "{lines}");
            assert!(lines.contains("is not known"), "{lines}");
            let result = connect_one_result(home.path(), &row, "/abs/innerwarden", false, false);
            assert_eq!(result.effect, ConnectEffect::Failed, "{}", result.line);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        }
    }

    /// Review of #369, item 5: a Goose config with code that runs inside
    /// Goose (`inline_python`) is wired, and never said to be guarded: the
    /// connect line says "wired" and "Partly guarded" and names it, a second
    /// connect does not say "already guarded", the row is not counted
    /// guarded and the listing says "partly guarded".
    ///
    /// FAILS ON REVERT of `runs_inside` in `is_guarded` or on the lines.
    #[test]
    fn goose_code_run_inside_it_is_never_counted_guarded() {
        let text = "extensions:\n  filesystem:\n    type: stdio\n    name: filesystem\n    enabled: true\n    cmd: npx\n    args: [\"-y\", \"@modelcontextprotocol/server-filesystem\", \"/tmp\"]\n  helper:\n    type: inline_python\n    name: helper\n    enabled: true\n    code: \"print(1)\"\n";
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".config/goose")).unwrap();
        std::fs::write(home.path().join(".config/goose/config.yaml"), text).unwrap();
        // A guard program that is there, so the wiring is not "cannot run".
        let bin = home.path().join("bin/innerwarden");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let bin = bin.to_string_lossy().into_owned();
        let row = known_row(home.path(), "goose");
        let result = connect_one_result(home.path(), &row, &bin, false, false);
        assert_eq!(result.effect, ConnectEffect::Connected, "{}", result.line);
        assert!(result.line.contains("goose - wired ("), "{}", result.line);
        assert!(
            result
                .line
                .contains("Partly guarded: helper (inline_python) runs code inside Goose"),
            "{}",
            result.line
        );
        assert!(!result.line.contains("connected"), "{}", result.line);
        let again = connect_one_result(home.path(), &row, &bin, false, false);
        assert!(!again.line.contains("already guarded"), "{}", again.line);
        assert!(again.line.contains("Partly guarded"), "{}", again.line);
        assert!(!is_guarded(home.path(), "goose", None));
        let row = known_row(home.path(), "goose");
        assert!(!row.guarded);
        let lines = list_lines_of(home.path(), std::slice::from_ref(&row)).join("\n");
        assert!(lines.contains("partly guarded (MCP proxy)"), "{lines}");
        assert!(
            lines.contains("runs code inside the agent that no proxy sees: helper (inline_python)"),
            "{lines}"
        );
    }

    /// Goose's remote extensions are named, with their type, on the connect
    /// line and in the listing: the proxy never sees them.
    ///
    /// FAILS ON REVERT of `unscreened` on the connect line or the listing.
    #[test]
    fn goose_remote_extensions_are_named_on_connect_and_in_the_listing() {
        // `remote-tools` and `old` are carried by the proxy on this connect
        // (`mcp_wire_yaml::carried_remote`); `signin`, which Goose signs in
        // to by itself, is not, and stays named.
        let text = "extensions:\n  filesystem:\n    type: stdio\n    name: filesystem\n    enabled: true\n    cmd: npx\n    args: [\"-y\", \"@modelcontextprotocol/server-filesystem\", \"/tmp\"]\n    timeout: 300\n  remote-tools:\n    type: streamable_http\n    name: remote-tools\n    enabled: true\n    uri: \"https://example.com/mcp\"\n  old:\n    type: sse\n    name: old\n    enabled: true\n    uri: \"https://example.com/sse\"\n  signin:\n    type: streamable_http\n    name: signin\n    enabled: true\n    uri: \"https://example.com/oauth\"\n    client_id: registered-client.example\n";
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".config/goose")).unwrap();
        std::fs::write(home.path().join(".config/goose/config.yaml"), text).unwrap();
        let row = known_row(home.path(), "goose");
        let before = list_lines_of(home.path(), std::slice::from_ref(&row)).join("\n");
        assert!(
            before.contains("not screened by the proxy (the agent reaches them itself): remote-tools (streamable_http), old (sse), signin (streamable_http)"),
            "{before}"
        );
        let result = connect_one_result(home.path(), &row, "/abs/innerwarden", false, false);
        assert_eq!(result.effect, ConnectEffect::Connected, "{}", result.line);
        assert!(
            result
                .line
                .contains("3 MCP servers routed through the guard proxy")
                && result
                    .line
                    .contains("not screened by the proxy: signin (streamable_http)"),
            "{}",
            result.line
        );
        let row = known_row(home.path(), "goose");
        let lines = list_lines_of(home.path(), std::slice::from_ref(&row)).join("\n");
        assert!(
            lines.contains(
                "not screened by the proxy (the agent reaches them itself): signin (streamable_http)"
            ) && !lines.contains("remote-tools ("),
            "{lines}"
        );
    }

    /// A connect never rewrites a Goose config whose server it cannot edit in
    /// place: it says so and leaves the file as it was.
    #[test]
    fn connect_leaves_a_goose_config_it_cannot_edit_in_place() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".config/goose")).unwrap();
        let path = home.path().join(".config/goose/config.yaml");
        let inline = "extensions:\n  github: {cmd: npx, args: [x], type: stdio}\n";
        std::fs::write(&path, inline).unwrap();
        let row = known_row(home.path(), "goose");
        let result = connect_one_result(home.path(), &row, "/abs/innerwarden", false, false);
        assert_eq!(result.effect, ConnectEffect::Failed, "{}", result.line);
        assert!(
            result.line.contains("cannot be edited in place"),
            "{}",
            result.line
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), inline);
    }

    /// The Codex twin: its TOML wrappers name it too, in enforce here.
    ///
    /// FAILS ON REVERT: pass no agent to `mcp_wire_toml::wrap_toml`.
    #[test]
    fn connect_codex_writes_its_id_on_every_proxy() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            "model = \"gpt-5\"\n\n[mcp_servers.icm]\ncommand = \"icm\"\nargs = [\"serve\"]\n\n[mcp_servers.repl]\ncommand = \"node\"\n",
        )
        .unwrap();
        let row = known_row(home.path(), "codex");

        let result = connect_one_result(home.path(), &row, "/abs/innerwarden", false, false);
        assert_eq!(result.effect, ConnectEffect::Connected, "{}", result.line);

        let doc: toml_edit::DocumentMut =
            std::fs::read_to_string(home.path().join(".codex/config.toml"))
                .unwrap()
                .parse()
                .unwrap();
        for (name, child) in [("icm", vec!["icm", "serve"]), ("repl", vec!["node"])] {
            let args: Vec<&str> = doc["mcp_servers"][name]["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|arg| arg.as_str().unwrap())
                .collect();
            let mut expected = vec![
                "proxy", "--label", "codex", "--agent", "codex", "--mode", "guard", "--",
            ];
            expected.extend(child);
            assert_eq!(args, expected, "{name}");
        }
        assert_eq!(doc["model"].as_str(), Some("gpt-5"));
    }

    /// The Codex twin of the reconnect below, read back from the file the way
    /// every later connect and the dashboard read it.
    ///
    /// A TOML array read from a file keeps the spacing it was written with, and
    /// the wrapper compared that text against a freshly built array that has
    /// none, so an identical wrapper always looked changed: every connect
    /// rewrote `config.toml` and reported "connected", and the dashboard could
    /// never tell that a reconnect would change only the name. Wrappers are now
    /// compared word for word, formatting aside.
    ///
    /// FAILS ON REVERT: compare the arrays' text again, and the second connect
    /// reports `Connected` and the step is never offered.
    #[test]
    fn reconnect_names_a_codex_wrapper_and_then_leaves_the_file_alone() {
        const BIN: &str = "/abs/innerwarden";
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        let path = home.path().join(".codex/config.toml");
        let old = "# mine\nmodel = \"gpt-5\"\n\n[mcp_servers.icm]\ncommand = \"/abs/innerwarden\"\nargs = [\"proxy\", \"--mode\", \"guard\", \"--\", \"icm\", \"serve\"]\n";
        std::fs::write(&path, old).unwrap();
        let read = || -> toml_edit::DocumentMut {
            std::fs::read_to_string(&path).unwrap().parse().unwrap()
        };
        let row = known_row(home.path(), "codex");

        let automatic = connect_one_result_automatic(home.path(), &row, BIN, false, false);
        assert_eq!(
            automatic.effect,
            ConnectEffect::Skipped,
            "{}",
            automatic.line
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), old);
        assert_eq!(
            mcp_wire_toml::unnamed_reconnect_flag_toml(&read(), BIN, "codex"),
            Some("")
        );

        let manual = connect_one_result(home.path(), &row, BIN, false, false);
        assert_eq!(manual.effect, ConnectEffect::Connected, "{}", manual.line);
        let named = std::fs::read_to_string(&path).unwrap();
        assert!(named.starts_with("# mine\nmodel = \"gpt-5\"\n"), "{named}");
        let doc = read();
        let args: Vec<&str> = doc["mcp_servers"]["icm"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "proxy", "--label", "codex", "--agent", "codex", "--mode", "guard", "--", "icm",
                "serve"
            ]
        );
        assert_eq!(
            mcp_wire_toml::unnamed_reconnect_flag_toml(&doc, BIN, "codex"),
            None
        );

        let again = connect_one_result(home.path(), &row, BIN, false, false);
        assert_eq!(again.effect, ConnectEffect::Unchanged, "{}", again.line);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), named);
    }

    /// A host upgraded from a release whose wrappers named no agent.
    ///
    /// Automatic setup leaves that wiring exactly as it is: background setup
    /// never rewrites existing wiring, as it never adds a name to an existing
    /// hook. The dashboard offers the reconnect in the wiring's own mode, and
    /// that connect, run by a person, adds the name and changes nothing else:
    /// same program, same mode, the options it had, the server's own command
    /// line, every key outside the wrapper. A second connect has nothing to do.
    ///
    /// FAILS ON REVERT: pass no agent to `mcp_wire::wrap`, and the connect
    /// reports "already guarded" with the wrapper still unnamed.
    #[test]
    fn reconnect_adds_the_agent_to_a_label_less_wrapper_and_changes_nothing_else() {
        const BIN: &str = "/abs/innerwarden";
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".openclaw")).unwrap();
        let old = r#"{"gateway":{"port":18789},"mcp":{"servers":{"fs":{"command":"/abs/innerwarden","args":["proxy","--error-response","--mode","advisory","--","npx","-y","fs-server","--root","/srv/a b"]}}}}"#;
        std::fs::write(home.path().join(".openclaw/openclaw.json"), old).unwrap();
        let before = read_openclaw(home.path());
        let row = known_row(home.path(), "openclaw");

        let automatic = connect_one_result_automatic(home.path(), &row, BIN, false, true);
        assert_eq!(
            automatic.effect,
            ConnectEffect::Skipped,
            "{}",
            automatic.line
        );
        assert_eq!(
            std::fs::read_to_string(home.path().join(".openclaw/openclaw.json")).unwrap(),
            old
        );
        assert_eq!(
            mcp_wire::unnamed_reconnect_flag(&before, BIN, "openclaw"),
            Some(" --monitor")
        );

        let manual = connect_one_result(home.path(), &row, BIN, false, true);
        assert_eq!(manual.effect, ConnectEffect::Connected, "{}", manual.line);
        let after = read_openclaw(home.path());
        assert_eq!(
            openclaw_server_args(&after, "fs"),
            [
                "proxy",
                "--error-response",
                "--label",
                "openclaw",
                "--agent",
                "openclaw",
                "--mode",
                "advisory",
                "--",
                "npx",
                "-y",
                "fs-server",
                "--root",
                "/srv/a b"
            ]
        );
        assert_eq!(after["mcp"]["servers"]["fs"]["command"], BIN);
        assert_eq!(after["gateway"], before["gateway"]);
        assert_eq!(
            mcp_wire::guarded_mode(&after),
            Some(mcp_wire::WiringMode::Monitor)
        );
        assert_eq!(
            mcp_wire::unwrap(after.clone()).0,
            mcp_wire::unwrap(before).0
        );
        assert_eq!(
            mcp_wire::unnamed_reconnect_flag(&after, BIN, "openclaw"),
            None
        );

        let again = connect_one_result(home.path(), &row, BIN, false, true);
        assert_eq!(again.effect, ConnectEffect::Unchanged, "{}", again.line);
    }

    /// Wire Claude Code's hook at `bin` exactly as `install` writes it.
    fn wire_claude_hook_at(home: &Path, bin: &Path) {
        let settings = hook::merge_pretooluse_bash_hook(
            serde_json::json!({}),
            &hook::hook_command_for(bin, false, true, Some("claude-code")),
        );
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(
            home.join(".claude/settings.json"),
            serde_json::to_vec_pretty(&settings).unwrap(),
        )
        .unwrap();
    }

    /// A hook is only text. When the program it names is gone, Claude Code's
    /// exec fails, it reports a non-blocking hook error, and the command runs
    /// unscreened. `status`, `agents` and the dashboard all called that agent
    /// guarded, because each judged the hook by its text alone. Measured on a
    /// real Mac whose hook pointed at a cleaned `target/release` build.
    ///
    /// All three now ask the one shared judgement, so this pins each surface
    /// against the same file, then puts the program back and checks every one
    /// of them returns to guarded.
    #[test]
    fn a_hook_whose_program_is_gone_is_not_guarded_on_any_surface() {
        let home = tempfile::TempDir::new().unwrap();
        let bin = home.path().join("cleaned/target/release/innerwarden");
        wire_claude_hook_at(home.path(), &bin);

        let (rows, _) = rows_from_sources(home.path(), &[], None);
        let claude = rows.iter().find(|row| row.name == "claude-code").unwrap();
        assert!(!claude.guarded, "the listing and status read this flag");
        assert!(
            !status_is_effectively_guarded(home.path(), claude),
            "the dashboard reads this one"
        );
        assert!(
            status_has_guard_wiring(home.path(), claude),
            "the wiring is still there to repair; only the claim of screening changes"
        );
        match hook_program(home.path(), claude) {
            Some(hook::HookProgram::Broken { program, problem }) => {
                assert_eq!(program, bin.display().to_string());
                assert!(problem.contains("which does not exist"), "{problem}");
            }
            other => panic!("a missing program must be reported as broken: {other:?}"),
        }
        assert_eq!(
            hook_repair_command(home.path(), claude),
            "innerwarden install claude-code --monitor",
            "the remedy is the real install command, in the mode the hook had"
        );

        let listed =
            run_with_guard_bin(home.path(), &["list".into()], "/abs/innerwarden").join("\n");
        assert!(!listed.contains("✓ guarded"), "{listed}");
        assert!(
            listed.contains("✗ wired, but its hook cannot run"),
            "{listed}"
        );
        assert!(
            listed.contains(&format!(
                "its hook runs {}, which does not exist",
                bin.display()
            )),
            "{listed}"
        );
        assert!(
            listed.contains("Fix: innerwarden install claude-code --monitor"),
            "{listed}"
        );

        // The program comes back: every surface returns to guarded.
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let (rows, _) = rows_from_sources(home.path(), &[], None);
        let claude = rows.iter().find(|row| row.name == "claude-code").unwrap();
        assert!(claude.guarded);
        assert!(status_is_effectively_guarded(home.path(), claude));
        assert_eq!(
            hook_program(home.path(), claude),
            Some(hook::HookProgram::Runs)
        );
        let listed =
            run_with_guard_bin(home.path(), &["list".into()], "/abs/innerwarden").join("\n");
        assert!(listed.contains("✓ guarded (hook, monitor)"), "{listed}");
    }

    /// A file that is there but cannot be executed starts nothing either.
    #[cfg(unix)]
    #[test]
    fn a_hook_whose_program_is_not_executable_is_not_guarded() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::TempDir::new().unwrap();
        let bin = home.path().join("bin/innerwarden");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o644)).unwrap();
        wire_claude_hook_at(home.path(), &bin);

        let (rows, _) = rows_from_sources(home.path(), &[], None);
        let claude = rows.iter().find(|row| row.name == "claude-code").unwrap();
        assert!(!claude.guarded);
        match hook_program(home.path(), claude) {
            Some(hook::HookProgram::Broken { problem, .. }) => {
                assert!(
                    problem.contains("which is not an executable file"),
                    "{problem}"
                )
            }
            other => panic!("a non-executable program must be reported as broken: {other:?}"),
        }
    }

    /// A bare name is looked up along `PATH`, from metadata only, never run.
    #[test]
    fn a_bare_hook_program_is_found_along_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let bin = dir.path().join("innerwarden");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path_env = std::env::join_paths([dir.path()]).unwrap();
        assert_eq!(
            program_fact("innerwarden", Some(&path_env)),
            hook::ProgramFact::Executable
        );
        let elsewhere = tempfile::TempDir::new().unwrap();
        let path_env = std::env::join_paths([elsewhere.path()]).unwrap();
        assert_eq!(
            program_fact("innerwarden", Some(&path_env)),
            hook::ProgramFact::Missing
        );
        assert_eq!(
            program_fact("innerwarden", None),
            hook::ProgramFact::Missing
        );
    }

    /// Gemini settings a person wrote: a setting, a hook of their own and one
    /// local MCP server.
    const GEMINI_SETTINGS: &str = r#"{"theme":"dark","hooks":{"BeforeTool":[{"matcher":"write_file","hooks":[{"type":"command","command":"/usr/local/bin/mine"}]}]},"mcpServers":{"fs":{"command":"npx","args":["fs"]}}}"#;

    /// What `agents connect` says of a Codex hook with nobody to ask and no
    /// trust on file, and the note it prints under the agent's lines.
    const CODEX_NOT_ACTIVE: &str = "  codex - its PreToolUse hook is installed, but it is NOT active: Codex skips it: it is not trusted yet. Run `/hooks` inside Codex and trust the innerwarden hook";
    const CODEX_UNSCREENED: &str = "      Until the hook is active, only calls to MCP servers behind the proxy are screened. Codex's shell commands and file changes run unscreened.";

    #[cfg(unix)]
    const NOTHING_TO_CONNECT: &str =
        "innerwarden agents, all 1 guardable agent(s) are wired. Nothing to connect.";
    const ONE_NOT_GUARDED: &str = "innerwarden agents, found (1 not guarded yet):";
    const CONNECT_FOOTER: &str = "\n  connect one:  innerwarden agents connect <name>     all:  innerwarden agents connect --all";
    const BY_ITS_CONFIG: &str = "recognized configuration; CLI not confirmed";

    fn write_gemini_settings(home: &Path) -> std::path::PathBuf {
        let path = home.join(".gemini/settings.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, GEMINI_SETTINGS).unwrap();
        path
    }

    fn json_at(path: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    /// The notes `agents connect` prints under an agent's lines, as they sit
    /// in its result.
    #[cfg(unix)]
    fn indented(notes: Vec<String>) -> String {
        notes.iter().map(|note| format!("\n      {note}")).collect()
    }

    /// One row of the listing, and a line under it.
    fn listed(name: &str, guard: &str, found: &str) -> String {
        format!("  {name:<13} {guard:<34} {found}")
    }

    fn under_row(text: &str) -> String {
        format!("  {:<13} {text}", "")
    }

    /// Codex's config with the first hook in `home`'s `hooks.json` trusted for
    /// `command`.
    #[cfg(unix)]
    fn codex_trusting(home: &Path, command: &str) -> String {
        format!(
            "[hooks.state.'{}:pre_tool_use:0:0']\ntrusted_hash = \"{}\"\n",
            agent_hooks::CODEX.path(home).display(),
            crate::codex_trust::hook_hash(command, 60)
        )
    }

    /// A hook that is on reports its own mode: monitor as monitor, enforce
    /// and block-review as enforce. A hook in any other state has none.
    ///
    /// FAILS ON REVERT: drop the `monitor: false` arm of `hook_guard_mode`
    /// and an enforcing hook has no mode to report.
    #[test]
    fn a_hook_that_is_on_reports_its_own_mode() {
        for (state, mode) in [
            (
                HookState::On {
                    monitor: true,
                    block_review: false,
                },
                Some(GuardMode::Monitor),
            ),
            (
                HookState::On {
                    monitor: false,
                    block_review: false,
                },
                Some(GuardMode::Enforce),
            ),
            (
                HookState::On {
                    monitor: false,
                    block_review: true,
                },
                Some(GuardMode::Enforce),
            ),
            (HookState::Absent, None),
            (HookState::Unreadable, None),
        ] {
            assert_eq!(hook_guard_mode(&state), mode, "{state:?}");
        }
    }

    /// One connect wires Gemini's hook and its MCP proxy, in the one file
    /// Gemini keeps both in, and leaves the person's own hook and settings
    /// where they were. A second connect has nothing to write.
    ///
    /// FAILS ON REVERT: send Gemini's row down `connect_by_one_mechanism`
    /// alone, and the file has no hook of ours and the result has one line.
    #[cfg(unix)]
    #[test]
    fn connect_gemini_wires_its_hook_and_its_proxy_and_keeps_the_rest() {
        let home = tempfile::TempDir::new().unwrap();
        let bin = format!("{}innerwarden", installed_guard_dir(home.path()));
        let path = write_gemini_settings(home.path());
        let row = known_row(home.path(), "gemini");
        assert!(!row.guarded);

        let first = connect_one_result(home.path(), &row, &bin, false, true);
        assert_eq!(first.effect, ConnectEffect::Connected, "{}", first.line);
        assert_eq!(
            first.line,
            format!(
                "  gemini - connected (BeforeTool hook, monitor (records, never blocks))\n  gemini - connected (1 MCP server routed through the guard proxy, monitor){}",
                indented(agent_hooks::GEMINI.coverage())
            )
        );
        assert_eq!(
            json_at(&path),
            serde_json::json!({
                "theme": "dark",
                "hooks": {"BeforeTool": [
                    {
                        "matcher": "write_file",
                        "hooks": [{"type": "command", "command": "/usr/local/bin/mine"}]
                    },
                    {"hooks": [{
                        "type": "command",
                        "name": "innerwarden",
                        "command": agent_hooks::GEMINI.command(std::path::Path::new(&bin), false, true),
                        "timeout": 60000
                    }]}
                ]},
                "mcpServers": {"fs": {
                    "command": bin,
                    "args": [
                        "proxy", "--label", "gemini", "--agent", "gemini", "--mode", "advisory",
                        "--", "npx", "fs"
                    ]
                }}
            })
        );
        let written = std::fs::read(&path).unwrap();

        let row = known_row(home.path(), "gemini");
        assert!(row.guarded);
        assert_eq!(row.mode, Some(GuardMode::Monitor));
        assert_eq!(
            list_lines_of(home.path(), std::slice::from_ref(&row)),
            [
                NOTHING_TO_CONNECT.to_string(),
                listed("gemini", "✓ guarded (hook + proxy, monitor)", BY_ITS_CONFIG),
            ]
        );
        // An agent that cannot be wired is not counted among the wired ones
        // (FAILS ON REVERT: read `&&` as `||` in the count of the guarded in
        // `list_lines_of` and Aider is one of "all 2").
        std::fs::write(home.path().join(".aider.conf.yml"), "model: gpt\n").unwrap();
        let aider = known_row(home.path(), "aider");
        assert!(!aider.guardable());
        assert_eq!(
            list_lines_of(home.path(), &[row.clone(), aider])[0],
            NOTHING_TO_CONNECT
        );

        let again = connect_one_result(home.path(), &row, &bin, false, true);
        assert_eq!(again.effect, ConnectEffect::Unchanged, "{}", again.line);
        assert_eq!(
            again.line,
            format!(
                "  gemini - already guarded (BeforeTool hook, monitor)\n  gemini - already guarded (MCP proxy, monitor){}",
                indented(agent_hooks::GEMINI.coverage())
            )
        );
        assert_eq!(std::fs::read(&path).unwrap(), written);
    }

    /// Disconnect takes Gemini's hook and its wrappers out together and leaves
    /// the settings the person had.
    ///
    /// FAILS ON REVERT: unwire by `disconnect_by_one_mechanism` alone, and the
    /// hook stays in the file.
    #[test]
    fn disconnect_gemini_removes_its_hook_and_its_proxy_and_keeps_the_rest() {
        let home = tempfile::TempDir::new().unwrap();
        let path = write_gemini_settings(home.path());
        let before = json_at(&path);
        let row = known_row(home.path(), "gemini");
        let connected = connect_one_result(home.path(), &row, "/abs/innerwarden", false, false);
        assert_eq!(
            connected.effect,
            ConnectEffect::Connected,
            "{}",
            connected.line
        );
        assert!(has_guard_wiring(home.path(), "gemini"));
        assert_ne!(json_at(&path), before);

        assert_eq!(disconnect_one(home.path(), &row), "  gemini, disconnected");
        assert_eq!(json_at(&path), before);
        assert!(!has_guard_wiring(home.path(), "gemini"));
        assert_eq!(
            disconnect_one(home.path(), &row),
            "  gemini, was not connected"
        );
    }

    /// The Codex connect line names each server reached by URL that the
    /// proxy does not carry, with the key that keeps it out, and no value.
    ///
    /// FAILS ON REVERT: print the Codex line without
    /// `unscreened_remote_toml`, and a server Codex signs in to by itself is
    /// left out of the line without a word.
    #[test]
    fn connect_codex_names_the_remote_servers_the_proxy_leaves_out() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            "[mcp_servers.icm]\ncommand = \"icm\"\n\n[mcp_servers.signin]\nurl = \"https://x.example/mcp\"\nscopes = [\"read\"]\n\n[mcp_servers.raw]\nurl = \"https://y.example/mcp\"\nbearer_token = \"sk-not-a-token\"\n",
        )
        .unwrap();
        let row = known_row(home.path(), "codex");
        let result = connect_one_result(home.path(), &row, "/abs/innerwarden", false, false);
        assert!(
            result.line.contains(
                "codex - connected (1 MCP server routed through the guard proxy, enforce; not screened by the proxy: signin (scopes), raw (bearer_token))"
            ),
            "{}",
            result.line
        );
        assert!(!result.line.contains("sk-not-a-token"), "{}", result.line);
    }

    /// The Codex connect line says that calls to the servers the proxy
    /// leaves out are judged by the hook with the proxy's rules, and says
    /// nothing of it when there is no such server.
    ///
    /// FAILS ON REVERT: print the line without `judged_by_hook`.
    #[test]
    fn connect_codex_says_the_hook_judges_the_servers_the_proxy_leaves_out() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            "[mcp_servers.icm]\ncommand = \"icm\"\n\n[mcp_servers.linear]\nurl = \"https://l.example/mcp\"\noauth_resource = \"https://l.example/mcp\"\n",
        )
        .unwrap();
        let row = known_row(home.path(), "codex");
        let result = connect_one_result(home.path(), &row, "/abs/innerwarden", false, false);
        assert!(
            result.line.contains(
                "not screened by the proxy: linear (oauth_resource)); the Codex hook, when it is on, judges calls to those servers with the proxy's rules"
            ),
            "{}",
            result.line
        );
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            "[mcp_servers.icm]\ncommand = \"icm\"\n",
        )
        .unwrap();
        let row = known_row(home.path(), "codex");
        let result = connect_one_result(home.path(), &row, "/abs/innerwarden", false, false);
        assert!(!result.line.contains("judges calls"), "{}", result.line);
    }

    /// Codex runs a hook only once it trusts it. With nobody to ask and no
    /// trust on file, connect says the hook is NOT active and names the one
    /// step, while the MCP servers still go behind the proxy.
    ///
    /// FAILS ON REVERT: report the hook by the file it was written to (active
    /// whenever the install succeeded), and the first line reads "connected
    /// (PreToolUse hook)".
    #[test]
    fn connect_codex_never_says_connected_for_a_hook_codex_would_skip() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            "[mcp_servers.icm]\ncommand = \"icm\"\n",
        )
        .unwrap();
        let row = known_row(home.path(), "codex");

        let result = connect_one_result(home.path(), &row, "/abs/innerwarden", false, false);
        assert_eq!(result.effect, ConnectEffect::Connected, "{}", result.line);
        assert_eq!(
            result.line,
            format!(
                "{CODEX_NOT_ACTIVE}\n  codex - connected (1 MCP server routed through the guard proxy, enforce)\n{CODEX_UNSCREENED}"
            )
        );
        assert_eq!(
            json_at(&home.path().join(".codex/hooks.json")),
            serde_json::json!({"hooks": {"PreToolUse": [{"hooks": [{
                "type": "command",
                "command": agent_hooks::CODEX.command(Path::new("/abs/innerwarden"), false, false),
                "timeout": 60
            }]}]}})
        );
    }

    /// A hook Codex has not trusted, on an agent with no MCP server, wires
    /// nothing that screens: the result is not a configured agent, and the
    /// listing says installed and skipped, never guarded, with the step.
    ///
    /// FAILS ON REVERT: count a hook that is in the file as guarding
    /// (`installed()` where `is_guarded` asks `is_on()`), and the row reads
    /// "✓ guarded".
    #[cfg(unix)]
    #[test]
    fn a_codex_hook_codex_would_skip_is_never_listed_as_guarded() {
        let home = tempfile::TempDir::new().unwrap();
        let bin = format!("{}innerwarden", installed_guard_dir(home.path()));
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        let row = known_row(home.path(), "codex");
        let line = format!(
            "{CODEX_NOT_ACTIVE}\n  codex - no local MCP servers to route through the guard proxy\n{CODEX_UNSCREENED}"
        );

        let result = connect_one_result(home.path(), &row, &bin, false, false);
        assert_eq!(result.effect, ConnectEffect::Skipped, "{}", result.line);
        assert!(!result.configured());
        assert_eq!(result.line, line);
        let outcome = run_with_guard_bin_outcome(
            home.path(),
            &["connect".to_string(), "codex".to_string()],
            &bin,
        );
        assert_eq!(outcome.configured, 0);
        assert_eq!(outcome.lines, [line]);

        let row = known_row(home.path(), "codex");
        assert!(!row.guarded);
        assert!(!is_guarded(home.path(), "codex", None));
        assert!(has_guard_wiring(home.path(), "codex"));
        assert!(status_has_guard_wiring(home.path(), &row));
        assert!(!status_is_effectively_guarded(home.path(), &row));
        assert_eq!(
            list_lines_of(home.path(), std::slice::from_ref(&row)),
            [
                ONE_NOT_GUARDED.to_string(),
                listed(
                    "codex",
                    "not guarded, connect via hook + proxy",
                    "possible leftover; installation not confirmed"
                ),
                under_row(
                    "PreToolUse hook: installed, but Codex skips it: it is not trusted yet. Run: innerwarden agents connect codex"
                ),
                CONNECT_FOOTER.to_string(),
            ]
        );
    }

    /// Codex with a hook it trusts and no MCP server is guarded by the hook
    /// alone, in the hook's mode. The dashboard's predicate stays on the MCP
    /// wiring it reads the mode from.
    ///
    /// FAILS ON REVERT: leave `is_guarded` on the MCP config alone, and a
    /// Codex with a trusted hook and no server reads "not guarded".
    #[cfg(unix)]
    #[test]
    fn a_codex_hook_that_is_on_guards_an_agent_with_no_servers() {
        let home = tempfile::TempDir::new().unwrap();
        let bin = format!("{}innerwarden", installed_guard_dir(home.path()));
        let command = agent_hooks::CODEX.command(Path::new(&bin), false, true);
        let config = codex_trusting(home.path(), &command);
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        std::fs::write(home.path().join(".codex/config.toml"), &config).unwrap();
        let row = known_row(home.path(), "codex");
        assert!(!row.guarded);
        assert!(!status_has_guard_wiring(home.path(), &row));

        let result = connect_one_result(home.path(), &row, &bin, false, true);
        assert_eq!(result.effect, ConnectEffect::Connected, "{}", result.line);
        assert!(result.configured());
        assert_eq!(
            result.line,
            format!(
                "  codex - connected (PreToolUse hook, monitor (records, never blocks))\n  codex - no local MCP servers to route through the guard proxy{}",
                indented(agent_hooks::CODEX.coverage())
            )
        );
        assert_eq!(
            std::fs::read_to_string(home.path().join(".codex/config.toml")).unwrap(),
            config
        );

        let row = known_row(home.path(), "codex");
        assert!(row.guarded);
        assert_eq!(row.mode, Some(GuardMode::Monitor));
        assert!(status_has_guard_wiring(home.path(), &row));
        assert!(!status_is_effectively_guarded(home.path(), &row));
        assert_eq!(
            list_lines_of(home.path(), std::slice::from_ref(&row)),
            [
                NOTHING_TO_CONNECT.to_string(),
                listed("codex", "✓ guarded (hook, monitor)", BY_ITS_CONFIG),
            ]
        );
    }

    /// `enforce` and `dry-run` rewrite the wiring that is there. An agent that
    /// only has its MCP servers behind the proxy gets no hook from them: a new
    /// hook, and the trust Codex is asked for it, come from `agents connect`
    /// and setup, which the person runs for that.
    ///
    /// FAILS ON REVERT: drop the `installed()` guard in
    /// `switch_mode_one_result` (take the hook branch for every row that has a
    /// hook spec), and `.codex/hooks.json` is there after the switch and
    /// Gemini's `BeforeTool` holds two groups.
    #[test]
    fn a_mode_switch_installs_no_hook_an_agent_did_not_have() {
        const BIN: &str = "/abs/innerwarden";
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            "[mcp_servers.icm]\ncommand = \"icm\"\n",
        )
        .unwrap();
        let gemini = write_gemini_settings(home.path());

        for name in ["codex", "gemini"] {
            let row = known_row(home.path(), name);
            // Automatic setup wires the proxy and never the hook.
            let wired = connect_one_result_automatic(home.path(), &row, BIN, false, true);
            assert_eq!(wired.effect, ConnectEffect::Connected, "{}", wired.line);

            let row = known_row(home.path(), name);
            assert!(status_has_guard_wiring(home.path(), &row), "{name}");
            let switched = switch_mode_one_result(home.path(), &row, BIN, false, false);
            assert_eq!(
                switched.line,
                format!(
                    "  {name} - connected (1 MCP server routed through the guard proxy, enforce)"
                )
            );
            assert_eq!(switched.effect, ConnectEffect::Connected);
            assert_eq!(switched.hook_stopped, None);
        }

        assert!(!home.path().join(".codex/hooks.json").exists());
        assert_eq!(
            json_at(&gemini)["hooks"],
            serde_json::json!({"BeforeTool": [{
                "matcher": "write_file",
                "hooks": [{"type": "command", "command": "/usr/local/bin/mine"}]
            }]})
        );
    }

    /// A mode switch rewrites Codex's hook line, and Codex runs a hook only
    /// while it trusts the line it has. When nobody is there to trust the new
    /// one, the hook that recorded every call before the switch runs for none
    /// after it. That is a failed switch, and the result names the agent and
    /// the one step, for the summary under the agents' lines.
    ///
    /// A second switch to the same mode rewrites nothing, and the mode is
    /// still not in force for Codex: it fails the same way. `agents connect`
    /// on a hook Codex does not trust is not a failure:
    /// `a_codex_hook_codex_would_skip_is_never_listed_as_guarded` holds that
    /// one at `Skipped`.
    ///
    /// FAILS ON REVERT: drop the `NotActive` arm guarded by `mode_switch` in
    /// `connect_hook_and_proxy`, and the first switch is `Skipped` with no
    /// line in `hook_stopped`; guard it on this run having written the line
    /// as well, and the second switch is `Skipped`.
    #[cfg(unix)]
    #[test]
    fn a_mode_switch_that_stops_codexs_hook_is_a_failure() {
        let home = tempfile::TempDir::new().unwrap();
        let bin = format!("{}innerwarden", installed_guard_dir(home.path()));
        let monitor_line = agent_hooks::CODEX.command(Path::new(&bin), false, true);
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            codex_trusting(home.path(), &monitor_line),
        )
        .unwrap();
        let row = known_row(home.path(), "codex");
        let connected = connect_one_result(home.path(), &row, &bin, false, true);
        assert_eq!(
            connected.effect,
            ConnectEffect::Connected,
            "{}",
            connected.line
        );
        assert_eq!(connected.hook_stopped, None);

        let row = known_row(home.path(), "codex");
        assert!(row.guarded);
        let switched = switch_mode_one_result(home.path(), &row, &bin, false, false);
        assert_eq!(switched.effect, ConnectEffect::Failed, "{}", switched.line);
        assert!(!switched.configured());
        assert_eq!(
            switched.hook_stopped.as_deref(),
            Some(
                "codex - its PreToolUse hook is not active after this switch. Run `/hooks` inside Codex and trust the innerwarden hook"
            )
        );
        assert!(
            switched
                .line
                .starts_with("  codex - its PreToolUse hook is installed, but it is NOT active: "),
            "{}",
            switched.line
        );
        assert!(
            switched.line.ends_with(CODEX_UNSCREENED),
            "{}",
            switched.line
        );
        assert!(!known_row(home.path(), "codex").guarded);

        let row = known_row(home.path(), "codex");
        let again = switch_mode_one_result(home.path(), &row, &bin, false, false);
        assert_eq!(again.effect, ConnectEffect::Failed, "{}", again.line);
        assert!(!again.configured());
        assert_eq!(again.hook_stopped, switched.hook_stopped);
    }

    /// With MCP servers behind the proxy the wrappers switch, and the hook
    /// Codex skips still makes the switch fail for Codex: the summary never
    /// counts it among the agents the mode is configured on.
    ///
    /// FAILS ON REVERT: let the `NotActive` arm guarded by `mode_switch` in
    /// `connect_hook_and_proxy` answer `Skipped`, and the wrappers' effect
    /// makes each switch `Connected` or `Unchanged`, counted as configured.
    #[cfg(unix)]
    #[test]
    fn a_switch_that_leaves_codexs_hook_skipped_fails_beside_its_mcp_servers() {
        let home = tempfile::TempDir::new().unwrap();
        let bin = format!("{}innerwarden", installed_guard_dir(home.path()));
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            "[mcp_servers.icm]\ncommand = \"icm\"\n",
        )
        .unwrap();
        let row = known_row(home.path(), "codex");
        let connected = connect_one_result(home.path(), &row, &bin, false, false);
        assert!(
            home.path().join(".codex/hooks.json").is_file(),
            "{}",
            connected.line
        );
        assert_eq!(connected.hook_stopped, None);

        for _ in 0..2 {
            let row = known_row(home.path(), "codex");
            let switched = switch_mode_one_result(home.path(), &row, &bin, false, false);
            assert_eq!(switched.effect, ConnectEffect::Failed, "{}", switched.line);
            assert!(!switched.configured());
            assert!(
                switched.hook_stopped.as_deref().is_some_and(|line| line
                    .starts_with("codex - its PreToolUse hook is not active after this switch.")),
                "{:?}",
                switched.hook_stopped
            );
        }
    }

    /// Wrappers alone are half of what Codex is screened by. The listing says
    /// "partly guarded", states the hook and the one step under the row, and
    /// still counts the agent as work left.
    ///
    /// FAILS ON REVERT: label the row by `r.guarded` alone, and it reads
    /// "✓ guarded (MCP proxy, enforce)" under "Nothing to connect".
    #[test]
    fn the_listing_says_partly_guarded_while_the_hook_is_not_installed() {
        let home = tempfile::TempDir::new().unwrap();
        let bin = format!("{}innerwarden", installed_guard_dir(home.path()));
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            format!(
                "[mcp_servers.icm]\ncommand = \"{bin}\"\nargs = [\"proxy\", \"--label\", \"codex\", \"--agent\", \"codex\", \"--mode\", \"guard\", \"--\", \"icm\"]\n"
            ),
        )
        .unwrap();
        let row = known_row(home.path(), "codex");
        assert!(row.guarded);
        assert_eq!(row.mode, Some(GuardMode::Enforce));
        assert!(status_is_effectively_guarded(home.path(), &row));

        assert_eq!(
            list_lines_of(home.path(), std::slice::from_ref(&row)),
            [
                ONE_NOT_GUARDED.to_string(),
                listed(
                    "codex",
                    "partly guarded (MCP proxy, enforce)",
                    BY_ITS_CONFIG
                ),
                under_row("PreToolUse hook: not installed. Run: innerwarden agents connect codex"),
                CONNECT_FOOTER.to_string(),
            ]
        );
    }

    /// A hook that is on does not hide an MCP server that still runs outside
    /// the proxy: the row is not guarded, and the listing says which half is
    /// missing.
    ///
    /// FAILS ON REVERT: let a hook that is on decide `is_guarded` ahead of
    /// the MCP servers, and the row reads "✓ guarded".
    #[cfg(unix)]
    #[test]
    fn a_hook_that_is_on_does_not_hide_a_server_outside_the_proxy() {
        let home = tempfile::TempDir::new().unwrap();
        let bin = format!("{}innerwarden", installed_guard_dir(home.path()));
        let path = write_gemini_settings(home.path());
        let row = known_row(home.path(), "gemini");
        assert!(connect_one_result(home.path(), &row, &bin, false, true).configured());
        assert!(known_row(home.path(), "gemini").guarded);

        // A server the person adds after the connect.
        let mut settings = json_at(&path);
        settings["mcpServers"]["later"] = serde_json::json!({"command": "node"});
        std::fs::write(&path, serde_json::to_vec(&settings).unwrap()).unwrap();

        let row = known_row(home.path(), "gemini");
        assert!(!row.guarded);
        assert_eq!(row.mode, None);
        assert_eq!(
            list_lines_of(home.path(), std::slice::from_ref(&row)),
            [
                ONE_NOT_GUARDED.to_string(),
                listed("gemini", "partly guarded (hook, monitor)", BY_ITS_CONFIG),
                under_row(
                    "MCP servers: not all behind the guard proxy. Run: innerwarden agents connect gemini"
                ),
                CONNECT_FOOTER.to_string(),
            ]
        );
    }

    /// A hook that records beside wrappers that block is neither mode.
    ///
    /// FAILS ON REVERT: read the mode from the wrappers alone, and the row
    /// says "enforce" while the hook lets every shell command through.
    #[cfg(unix)]
    #[test]
    fn a_hook_and_wrappers_in_two_modes_read_as_mixed() {
        let home = tempfile::TempDir::new().unwrap();
        let bin = format!("{}innerwarden", installed_guard_dir(home.path()));
        write_gemini_settings(home.path());
        let row = known_row(home.path(), "gemini");
        assert!(connect_one_result(home.path(), &row, &bin, false, true).configured());
        assert_eq!(
            known_row(home.path(), "gemini").mode,
            Some(GuardMode::Monitor)
        );

        // The wrappers alone move to enforce; the hook line stays in monitor.
        let proxy = connect_by_one_mechanism(home.path(), &row, &bin, false, false, false);
        assert_eq!(proxy.effect, ConnectEffect::Connected, "{}", proxy.line);
        let row = known_row(home.path(), "gemini");
        assert!(row.guarded);
        assert_eq!(row.mode, Some(GuardMode::Mixed));
        assert_eq!(
            list_lines_of(home.path(), std::slice::from_ref(&row)),
            [
                NOTHING_TO_CONNECT.to_string(),
                listed("gemini", "✓ guarded (hook + proxy, MIXED)", BY_ITS_CONFIG),
            ]
        );
    }

    /// Automatic setup never writes the hook of Codex or Gemini: what it does
    /// and prints for them is the proxy step alone.
    ///
    /// FAILS ON REVERT: wire the hook whatever the link policy, and background
    /// setup adds a hook nobody asked for.
    #[test]
    fn automatic_setup_wires_the_proxy_of_gemini_and_never_its_hook() {
        let home = tempfile::TempDir::new().unwrap();
        let path = write_gemini_settings(home.path());
        let before = json_at(&path);
        let row = known_row(home.path(), "gemini");

        let result =
            connect_one_result_automatic(home.path(), &row, "/abs/innerwarden", false, true);
        assert_eq!(result.effect, ConnectEffect::Connected, "{}", result.line);
        assert_eq!(
            result.line,
            "  gemini - connected (1 MCP server routed through the guard proxy, monitor)"
        );
        let after = json_at(&path);
        assert_eq!(after["hooks"], before["hooks"]);
        assert_eq!(after["mcpServers"]["fs"]["command"], "/abs/innerwarden");
        assert_eq!(
            hook_state(home.path(), &row).map(|(_, state)| state),
            Some(HookState::Absent)
        );
    }

    /// Disconnect takes the hook of Codex out when there is no wrapper to
    /// unwrap, and says so. A second run has nothing to remove.
    ///
    /// FAILS ON REVERT: print the proxy step's line whatever the hook step
    /// removed, and the first disconnect reads "was not connected".
    #[test]
    fn disconnect_codex_with_only_a_hook_removes_it() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        let row = known_row(home.path(), "codex");
        connect_one_result(home.path(), &row, "/abs/innerwarden", false, false);
        assert!(has_guard_wiring(home.path(), "codex"));

        assert_eq!(disconnect_one(home.path(), &row), "  codex, disconnected");
        assert_eq!(
            json_at(&home.path().join(".codex/hooks.json")),
            serde_json::json!({"hooks": {"PreToolUse": []}})
        );
        assert!(!has_guard_wiring(home.path(), "codex"));
        assert_eq!(
            disconnect_one(home.path(), &row),
            "  codex - was not connected"
        );
    }

    /// Codex trusts a hook by its place in the file. Taking our hook out
    /// leaves an empty group where it was, so a hook of the person's that sat
    /// behind it keeps its place and its trust, and there is nothing to name.
    #[test]
    fn disconnect_codex_keeps_the_persons_hook_in_its_place() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        let row = known_row(home.path(), "codex");
        connect_one_result(home.path(), &row, "/abs/innerwarden", false, false);
        let theirs = serde_json::json!({
            "hooks": [{"type": "command", "command": "/opt/audit/before"}]
        });
        let path = home.path().join(".codex/hooks.json");
        let mut settings = json_at(&path);
        settings["hooks"]["PreToolUse"]
            .as_array_mut()
            .expect("the connect wrote a list of groups")
            .push(theirs.clone());
        std::fs::write(&path, serde_json::to_vec(&settings).unwrap()).unwrap();

        assert_eq!(disconnect_one(home.path(), &row), "  codex, disconnected");
        assert_eq!(
            json_at(&path),
            serde_json::json!({"hooks": {"PreToolUse": [{"hooks": []}, theirs]}})
        );
    }

    /// A connect that finds our hook inside a group of the person's takes it
    /// out of that group, which moves the person's hook behind it. The connect
    /// names that hook under the line for ours.
    ///
    /// FAILS ON REVERT: drop the `lines.extend` over `connected.notes(spec)`
    /// in `connect_hook_and_proxy`, and the hook Codex now skips is not named.
    #[test]
    fn connect_codex_names_the_persons_hook_it_moved() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        let row = known_row(home.path(), "codex");
        connect_one_result(home.path(), &row, "/abs/innerwarden", false, false);
        // The person adds a hook of their own behind ours, in the same group.
        let path = home.path().join(".codex/hooks.json");
        let mut settings = json_at(&path);
        settings["hooks"]["PreToolUse"][0]["hooks"]
            .as_array_mut()
            .expect("the connect wrote a group with a list of hooks")
            .push(serde_json::json!({"type": "command", "command": "/opt/audit/before"}));
        std::fs::write(&path, serde_json::to_vec(&settings).unwrap()).unwrap();

        let again = connect_one_result(home.path(), &row, "/abs/innerwarden", false, false);
        assert!(
            again.line.contains(
                "\n      A PreToolUse hook of your own moved to a new place in ~/.codex/hooks.json: `/opt/audit/before`. Codex trusts a hook by its place and skips it until it is trusted there. Run `/hooks` inside Codex and trust it again."
            ),
            "{}",
            again.line
        );
    }

    /// The wrappers come off whatever the hook's file holds. When that file
    /// cannot be read, the disconnect still says what happened to the
    /// wrappers, above the failure the exit code is read from.
    ///
    /// FAILS ON REVERT: take `{proxy}\n` out of the `Err` arm of
    /// `disconnect_one`, and the line starts with the failure: the person is
    /// not told the MCP servers no longer run behind the proxy.
    #[test]
    fn disconnect_says_what_the_wrappers_did_when_the_hook_file_is_broken() {
        const BIN: &str = "/abs/innerwarden";
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        let config = home.path().join(".codex/config.toml");
        std::fs::write(&config, "[mcp_servers.icm]\ncommand = \"icm\"\n").unwrap();
        let row = known_row(home.path(), "codex");
        let wired = connect_one_result_automatic(home.path(), &row, BIN, false, true);
        assert_eq!(wired.effect, ConnectEffect::Connected, "{}", wired.line);
        assert!(std::fs::read_to_string(&config).unwrap().contains(BIN));
        std::fs::write(home.path().join(".codex/hooks.json"), "{\"hooks\": ").unwrap();

        let row = known_row(home.path(), "codex");
        let line = disconnect_one(home.path(), &row);
        assert!(
            line.starts_with("  codex, disconnected\n  codex, failed: "),
            "{line}"
        );
        assert!(line.contains("hooks.json is not valid JSON"), "{line}");
        assert!(!std::fs::read_to_string(&config).unwrap().contains(BIN));
    }

    /// The effect of a hook step and a proxy step on one agent.
    #[test]
    fn two_wiring_steps_report_a_failure_then_a_change_then_what_was_there() {
        use ConnectEffect::{Connected, Failed, Skipped, Unchanged};
        for (first, second, both) in [
            (Failed, Connected, Failed),
            (Connected, Failed, Failed),
            (Skipped, Failed, Failed),
            (Connected, Unchanged, Connected),
            (Skipped, Connected, Connected),
            (Unchanged, Skipped, Unchanged),
            (Skipped, Unchanged, Unchanged),
            (Unchanged, Unchanged, Unchanged),
            (Skipped, Skipped, Skipped),
        ] {
            assert_eq!(both_effects(first, second), both, "{first:?} + {second:?}");
        }
    }

    /// Only Codex, Gemini and Cursor, found through their own reviewed MCP
    /// config, have a hook beside the proxy. The same name over another file
    /// does not.
    #[test]
    fn the_hook_beside_the_proxy_is_for_codex_and_gemini_by_their_own_config() {
        assert_eq!(
            hook_spec("codex", None, Some(".codex/config.toml")),
            Some(&agent_hooks::CODEX)
        );
        assert_eq!(
            hook_spec("gemini", Some(".gemini/settings.json"), None),
            Some(&agent_hooks::GEMINI)
        );
        assert_eq!(hook_spec("codex", Some(".codex/mcp.json"), None), None);
        assert_eq!(hook_spec("gemini", Some(".gemini/mcp.json"), None), None);
        assert_eq!(hook_spec("codex", None, None), None);
        assert_eq!(
            hook_spec("cursor", Some(".cursor/mcp.json"), None),
            Some(&agent_hooks::CURSOR)
        );
        assert_eq!(hook_spec("cursor", Some(".cursor/other.json"), None), None);
        assert_eq!(hook_spec("claude-code", None, None), None);
    }
}

// Every case runs a program found by a bare name, with Unix modes.
#[cfg(all(test, unix))]
mod bare_name_clue_tests {
    use super::*;

    fn runnable_in(dir: &Path) -> std::path::PathBuf {
        let bin = dir.join("innerwarden");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        bin
    }

    fn bare() -> Value {
        serde_json::json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "innerwarden hook --agent claude-code"}
        ]}]}})
    }

    /// A bare name found here, on this PATH or in a usual place, is "could
    /// not tell" with where it was found; found nowhere, it is off.
    ///
    /// FAILS ON REVERT of `with_bare_name_clue` (no "found here at"), of the
    /// usual places in `find_bare_name` (a guard only in a usual place reads
    /// off), and of the bare-name rule (found on PATH reads `Runs`).
    #[test]
    fn a_bare_name_found_here_says_where_and_one_found_nowhere_is_off() {
        let on_path = tempfile::TempDir::new().unwrap();
        let bin = runnable_in(on_path.path());
        let empty = tempfile::TempDir::new().unwrap();
        let none: Vec<std::path::PathBuf> = Vec::new();

        match hook_program_with(&bare(), Some(on_path.path().as_os_str()), &none) {
            Some(hook::HookProgram::Unknown { why, .. }) => {
                assert!(why.starts_with(hook::BARE_NAME), "{why}");
                assert!(
                    why.contains(&format!(
                        "found here at {}, the agent may resolve another",
                        bin.display()
                    )),
                    "{why}"
                );
            }
            other => panic!("found on this PATH is could not tell: {other:?}"),
        }

        // Not on PATH, but in a usual place: found here all the same.
        let usual = tempfile::TempDir::new().unwrap();
        let in_usual = runnable_in(usual.path());
        match hook_program_with(
            &bare(),
            Some(empty.path().as_os_str()),
            &[usual.path().to_path_buf()],
        ) {
            Some(hook::HookProgram::Unknown { why, .. }) => {
                assert!(why.contains(&in_usual.display().to_string()), "{why}")
            }
            other => panic!("found in a usual place is could not tell: {other:?}"),
        }

        // Found nowhere: off.
        match hook_program_with(
            &bare(),
            Some(empty.path().as_os_str()),
            &[empty.path().to_path_buf()],
        ) {
            Some(hook::HookProgram::Broken { problem, .. }) => {
                assert!(problem.ends_with(hook::BARE_NOT_FOUND), "{problem}")
            }
            other => panic!("found nowhere is off: {other:?}"),
        }
    }
}
