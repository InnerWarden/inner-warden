//! Thin I/O for `innerwarden contain`: resolve the host facts the pure `contain`
//! builders need, arm the in-jail hook, resolve the sandbox backend from a trusted
//! absolute path, and spawn. All the wall-building logic (and every security
//! invariant) lives in the pure `contain` module and is unit-tested there; this
//! file only touches the OS. Excluded from the coverage floor like the other `_io`
//! adapters.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use innerwarden_agent_guard::hook;

use crate::contain::{
    build_linux_jail, build_macos_profile, parse_contain_args, validate_jail_inputs_for,
    ContainArgs, JailInputs, Worktree,
};

/// `innerwarden contain [--agent claude-code] [--monitor|--enforce|--block-review]
/// [--project DIR] [--dry-run] [--setup] -- <command...>` - run the command inside
/// a filesystem/namespace jail with the InnerWarden hook active inside it.
pub fn cmd(rest: &[String]) -> ExitCode {
    if let Some(asked) = accept_request(rest) {
        return cmd_accept(asked);
    }
    let args = match parse_contain_args(rest) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("innerwarden contain: {e}");
            return ExitCode::from(2);
        }
    };
    // A jail rewires the agent's hook: it is the person's to start, never a
    // command an AI agent's shell runs (live gate of Active Defence 0.17.4,
    // G1). Its own `--dry-run` changes nothing and stays open.
    if !args.dry_run && crate::suppress_io::in_agent_shell() {
        eprintln!(
            "innerwarden contain: refused inside an AI agent's shell. A jail rewires the \
             agent's hook, so it is started by the person, from their own terminal. Nothing \
             was changed."
        );
        return ExitCode::from(1);
    }

    let home = match std::env::var_os("HOME").map(PathBuf::from) {
        Some(h) if !h.as_os_str().is_empty() => h,
        _ => {
            eprintln!("innerwarden contain: HOME is not set");
            return ExitCode::from(2);
        }
    };
    // CRITICAL on macOS: sandbox-exec matches RESOLVED paths, and /var, /tmp are
    // symlinks (/private/var, /private/tmp). Every path baked into the profile /
    // bind list must be the real (symlink-resolved) path, or a deny of the secret
    // dir silently misses. Canonicalize the home root here.
    let home = std::fs::canonicalize(&home).unwrap_or(home);
    // Resolved: what `/usr` holds is told by where the file is, not by the
    // name it was started by.
    let iw_binary = match std::env::current_exe() {
        Ok(p) => std::fs::canonicalize(&p).unwrap_or(p),
        Err(e) => {
            eprintln!("innerwarden contain: cannot resolve own path: {e}");
            return ExitCode::from(1);
        }
    };
    // The CLI the guard's hook runs: root's copy where this launcher is
    // one the account can replace ([`crate::contain::hook_cli_for`]).
    #[cfg(unix)]
    let (hook_cli, hook_said) = crate::contain::hook_cli_for(
        &iw_binary,
        &|path: &Path| backend_facts(path).is_some_and(|facts| backend_trusted(&facts)),
        cfg!(target_os = "linux"),
    );
    #[cfg(not(unix))]
    let (hook_cli, hook_said): (PathBuf, Option<String>) = (iw_binary.clone(), None);
    if !args.dry_run {
        if let Some(said) = &hook_said {
            eprintln!("innerwarden contain: {said}");
        }
    }

    // --setup intentionally only arms the hook and therefore needs no project.
    // Every normal run validates all future writable binds BEFORE this host
    // mutation; an unsafe project must fail closed without changing settings.
    // A mode asked for on the command line is set; with none, the hook keeps
    // the mode it already has (live gate of Active Defence 0.17.4, G2: a plain
    // `contain` rewired an enforcing hook to monitor, unsaid, a failed start
    // included). Only a first wiring takes the default.
    let mode_given = rest
        .iter()
        .take_while(|a| *a != "--")
        .any(|a| matches!(a.as_str(), "--monitor" | "--enforce" | "--block-review"));
    let mut args = args;
    // The person's Claude Code folder: `~/.claude`, or the one
    // `CLAUDE_CONFIG_DIR` names where it is handed in.
    let claude_dir = match crate::contain::persons_claude_dir(
        &home,
        &args.pass_env,
        std::env::var_os(crate::contain::CLAUDE_CONFIG_ENV).as_deref(),
    ) {
        Ok(dir) => dir,
        Err(error) => {
            eprintln!("innerwarden contain: {error}");
            return ExitCode::from(2);
        }
    };
    // Checked before anything is written: a refused folder is never made
    // or armed (`hook::install_hook` makes the folder it is given).
    if let Some(why) = crate::contain::claude_dir_refusal(
        &home,
        (!args.setup_only).then_some(args.project.as_path()),
        &claude_dir,
    ) {
        eprintln!("innerwarden contain: {why}");
        return ExitCode::from(2);
    }
    let claude_settings = claude_dir.join("settings.json");
    let claude_settings_arg = claude_settings.to_string_lossy().to_string();
    let settings_named = (claude_dir != home.join(crate::contain::CLAUDE_DIR))
        .then_some(claude_settings_arg.as_str());
    if !mode_given {
        if let Some((block_review, monitor)) = std::fs::read_to_string(&claude_settings)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .as_ref()
            .and_then(hook::kept_hook_flags)
        {
            args.mode = match (block_review, monitor) {
                (true, _) => crate::contain::Mode::BlockReview,
                (false, true) => crate::contain::Mode::Monitor,
                (false, false) => crate::contain::Mode::Enforce,
            };
        }
    }
    let (block_review, monitor) = args.mode.hook_flags();
    if args.setup_only {
        match hook::install_hook(
            &home,
            &args.agent,
            settings_named,
            &hook_cli,
            block_review,
            monitor,
        ) {
            Ok(_) => {}
            Err(e) => eprintln!(
                "innerwarden contain: could not arm the in-jail hook: {e} (running with walls only)"
            ),
        }
    }
    if args.setup_only {
        println!(
            "innerwarden contain - hook armed for {} (mode: {}).",
            args.agent,
            mode_label(&args)
        );
        return ExitCode::SUCCESS;
    }

    // Before anything is installed or started: a jail reads the host's agent
    // profiles through its own view of `/etc`, where the owners cannot be
    // told apart, so the launcher proves here, with the real owners, that the
    // way to that file is root's alone: always for an identified jail, and
    // for a plain one where the file exists. A plain jail on a host without
    // the file checks nothing and is the jail it always was.
    #[cfg(target_os = "linux")]
    let marks =
        match crate::contain::launch::profiles_chain(args.identity, &system_profiles_entries()) {
            crate::contain::launch::ProfilesChain::Refused(why) => {
                eprintln!("{why}");
                return ExitCode::from(2);
            }
            chain => chain.marks(),
        };
    #[cfg(not(target_os = "linux"))]
    let marks = false;

    // An identified launch takes its jail settings from the agent type's
    // profile, where a profiles file exists; a flag given here still wins.
    // Without `--identity` no profile is read and the jail is what it was.
    if args.identity {
        match crate::agent_profiles_io::load() {
            crate::agent_profiles::ProfilesState::Off => {}
            crate::agent_profiles::ProfilesState::Invalid(why) => {
                eprintln!("innerwarden contain: the agent profiles cannot be used: {why}");
                return ExitCode::from(2);
            }
            crate::agent_profiles::ProfilesState::On(profiles) => {
                if let Some(profile) = profiles.get(&args.agent) {
                    crate::contain::apply_jail_profile(
                        &mut args,
                        &profile.jail,
                        crate::contain::jail_flags_given(rest),
                        &home,
                    );
                    eprintln!(
                        "innerwarden contain: jail settings from the `{}` agent profile",
                        args.agent
                    );
                }
            }
        }
    }
    // Resolve the project dir (default cwd), canonicalized so binds are absolute.
    let project = resolve_project(&args.project);
    if !project.is_dir() {
        eprintln!(
            "innerwarden contain: project directory not found: {} (pass --project <dir>)",
            project.display()
        );
        return ExitCode::from(2);
    }
    args.project = project;

    // Each extra path found where it leads, with every link on its way
    // ([`crate::contain::screen_extra_paths`]): a read-only path is laid
    // where the jail shows the place it leads to, a link a program in a jail
    // can change is never followed to a place the jail shows nothing else
    // of, and each path left out is said. Empty lists (every jail without a
    // profile that names some) read nothing.
    let mut extra_said = screen_extra(&mut args, &home, &iw_binary);
    // A profile that starts the jail only once the host admitted it asked
    // for every defence in effect: a read-only path of it this bubblewrap
    // cannot keep read-only stops the launch, in a dry run too.
    if let Some(refused) = crate::contain::unheld_refused(args.start, &args.extra_ro_unheld) {
        eprintln!("innerwarden contain: {refused}");
        return ExitCode::from(2);
    }

    let mut input = match resolve_screened(args, home, iw_binary, &mut extra_said) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("innerwarden contain: {error}");
            return ExitCode::from(2);
        }
    };
    input.hook_cli = Some(hook_cli.clone());
    if let Err(error) = validate_jail_inputs_for(&input, cfg!(target_os = "macos")) {
        eprintln!("innerwarden contain: {error}");
        return ExitCode::from(2);
    }
    // Claude Code's settings, the person's and the project's: one that may
    // turn the guard's hook off, that cannot be read, or that sets hooks in
    // a form InnerWarden does not read, keeps the jail from starting,
    // before anything on the host is changed.
    if let Some(why) = claude_settings_refused(&input.claude_host_dir, &input.args.project) {
        eprintln!("innerwarden contain: refusing to start: {why}");
        return ExitCode::from(2);
    }
    // What the last jail here made of the project's Claude Code files that
    // were not there when it started.
    #[cfg(unix)]
    if let Some(why) = project_files_made(&input).into_iter().next() {
        eprintln!(
            "innerwarden contain: refusing to start: {why}; {}",
            accept_hint(&input.args.project)
        );
        return ExitCode::from(2);
    }

    // Arm the guard hook for the agent (idempotent) - but NOT on --dry-run, which
    // must be read-only and never mutate the real ~/.claude/settings.json. The jail
    // reads a read-only copy of this same settings.json, made just before it
    // starts, so it is what fires the hook INSIDE the jail; it also keeps the
    // guard on for the host agent (same guard, walls only in the jail). Mode
    // comes from the flags.
    if !input.args.dry_run {
        match hook::install_hook(
            &input.home,
            &input.args.agent,
            settings_named,
            &hook_cli,
            block_review,
            monitor,
        ) {
            // Said every time, so a change of mode is never silent.
            Ok(_) => eprintln!(
                "innerwarden contain: the guard hook for {} is in {}{}.",
                input.args.agent,
                match input.args.mode {
                    crate::contain::Mode::Monitor => "monitor (records, never blocks)",
                    crate::contain::Mode::Enforce => "enforce (blocks dangerous commands)",
                    crate::contain::Mode::BlockReview => "enforce with review",
                },
                if mode_given { "" } else { ", as it was" }
            ),
            Err(e) => eprintln!(
                "innerwarden contain: could not arm the in-jail hook: {e} (running with walls only)"
            ),
        }
        // A plain jail shows the launcher's records folder read-only, so it
        // is made first where it is not there yet.
        #[cfg(target_os = "linux")]
        let records_made = make_plain_records(&input);
        #[cfg(not(target_os = "linux"))]
        let records_made = false;
        // On an account where Claude Code never ran, arming the hook made
        // `~/.claude` after the jail was planned without it: the jail would
        // show no `~/.claude`, so no settings file and no hook. The jail is
        // planned again, and checked again, on what is there now.
        if records_made || existing_home_paths(&input.home) != input.existing_paths {
            input = match resolve_screened(
                input.args.clone(),
                input.home.clone(),
                input.iw_binary.clone(),
                &mut extra_said,
            ) {
                Ok(input) => input,
                Err(error) => {
                    eprintln!("innerwarden contain: {error}");
                    return ExitCode::from(2);
                }
            };
            input.hook_cli = Some(hook_cli.clone());
            if let Err(error) = validate_jail_inputs_for(&input, cfg!(target_os = "macos")) {
                eprintln!("innerwarden contain: {error}");
                return ExitCode::from(2);
            }
        }
    }

    // Each extra path the jail leaves out, and why. Each place the jail
    // hides that a link leads out of the home, onto what the jail needs, or
    // round in a loop: left as it is, and said.
    for line in extra_said.iter().chain(&input.left) {
        eprintln!("innerwarden contain: {line}");
    }

    if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
        let code = if cfg!(target_os = "linux") {
            run_linux(&input, marks)
        } else {
            run_macos(&input)
        };
        // Said as the jail ends: what it made of the project's Claude Code
        // files that were not there (the next start refuses on it), and the
        // launch does not end in success, so whoever runs it unattended
        // sees it (the command's own failure is kept).
        #[cfg(unix)]
        if !input.args.dry_run {
            let made = finish_project_files(&input);
            for why in &made {
                eprintln!("innerwarden contain: {why}");
            }
            if !made.is_empty() {
                let succeeded = code == ExitCode::SUCCESS;
                let status = if succeeded {
                    format!("exiting {PROJECT_FILES_MADE_EXIT}")
                } else {
                    "the command failed, and its exit status is kept".to_string()
                };
                eprintln!(
                    "innerwarden contain: the jail made Claude Code files the next start \
                     refuses on; {status}. {}",
                    accept_hint(&input.args.project)
                );
                if succeeded {
                    return ExitCode::from(PROJECT_FILES_MADE_EXIT);
                }
            }
        }
        code
    } else {
        eprintln!(
            "innerwarden contain: containment needs Linux (bubblewrap) or macOS (sandbox-exec); this OS is not supported"
        );
        ExitCode::from(2)
    }
}

/// The exit status of a launch whose jail made Claude Code files in the
/// project that the next start refuses on, where the command itself
/// succeeded ([`finish_project_files`]).
#[cfg(unix)]
const PROJECT_FILES_MADE_EXIT: u8 = 3;

/// The flag by which the person accepts the files of the project's that
/// jails made ([`accept_project_files`]).
const ACCEPT_FLAG: &str = "--accept-project-files";

/// PURE. Where `rest` asks to accept a project's files (the flag among
/// `contain`'s own arguments): the project (`.` by default), or why the
/// request is not one: it takes `--project <dir>` and nothing else.
fn accept_request(rest: &[String]) -> Option<Result<PathBuf, String>> {
    let mut words = rest.iter();
    let mut asked = false;
    let mut project = PathBuf::from(".");
    let mut other = None;
    while let Some(word) = words.next() {
        match word.as_str() {
            ACCEPT_FLAG => asked = true,
            "--project" => match words.next() {
                Some(dir) => project = PathBuf::from(dir),
                None => other = Some("--project needs a folder".to_string()),
            },
            "--" => {
                other = Some("it runs no command".to_string());
                break;
            }
            flag if flag.starts_with('-') => {
                other.get_or_insert_with(|| format!("it takes no {flag}"));
            }
            _ => {
                // A bare word starts the agent's command: the flag after it
                // is the command's.
                break;
            }
        }
    }
    if !asked {
        return None;
    }
    Some(match other {
        Some(why) => Err(format!("{ACCEPT_FLAG} takes only --project <dir>: {why}")),
        None => Ok(project),
    })
}

/// `innerwarden contain --accept-project-files`, as the person runs it
/// ([`accept_project_files`]).
fn cmd_accept(asked: Result<PathBuf, String>) -> ExitCode {
    let project = match asked {
        Ok(project) => project,
        Err(why) => {
            eprintln!("innerwarden contain: {why}");
            return ExitCode::from(2);
        }
    };
    if crate::suppress_io::in_agent_shell() {
        eprintln!(
            "innerwarden contain: refused inside an AI agent's shell. Accepting the files a \
             jail made is the person's, from their own terminal. Nothing was changed."
        );
        return ExitCode::from(1);
    }
    let home = match std::env::var_os("HOME").map(PathBuf::from) {
        Some(h) if !h.as_os_str().is_empty() => h,
        _ => {
            eprintln!("innerwarden contain: HOME is not set");
            return ExitCode::from(2);
        }
    };
    let home = std::fs::canonicalize(&home).unwrap_or(home);
    let project = resolve_project(&project);
    if !project.is_dir() {
        eprintln!(
            "innerwarden contain: project directory not found: {} (pass --project <dir>)",
            project.display()
        );
        return ExitCode::from(2);
    }
    #[cfg(unix)]
    {
        accept_project_files(&home, &project)
    }
    #[cfg(not(unix))]
    {
        let _ = home;
        eprintln!("innerwarden contain: containment needs Linux or macOS; nothing to accept");
        ExitCode::from(2)
    }
}

/// `innerwarden contain-gate --instance <id> -- <command...>`: run inside a
/// jail whose profile starts it only once the host admitted it, as the jail's
/// command ([`crate::contain::launch::gated_child`]). It starts `command`
/// only when the record mounted in the jail names `id`; otherwise it says so
/// and exits 2, and nothing else runs.
pub fn cmd_gate(rest: &[String]) -> ExitCode {
    use crate::contain::launch::{gate_opens, parse_gate_args, GATE_REFUSED};
    let Some((instance, command)) = parse_gate_args(rest) else {
        eprintln!("innerwarden contain: the gate takes --instance <id> -- <command>");
        return ExitCode::from(2);
    };
    let opens =
        crate::hook_identity::mounted_record().is_some_and(|record| gate_opens(&record, instance));
    if !opens {
        eprintln!("innerwarden contain: {GATE_REFUSED}");
        return ExitCode::from(2);
    }
    run_in_place(command)
}

/// Replace this process with `command`, as the jail's own child would have
/// been started. Returns only when it could not be.
#[cfg(unix)]
fn run_in_place(command: &[String]) -> ExitCode {
    use std::os::unix::process::CommandExt;
    let error = Command::new(&command[0]).args(&command[1..]).exec();
    eprintln!("innerwarden contain: cannot run {}: {error}", command[0]);
    ExitCode::from(if error.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    })
}

#[cfg(not(unix))]
fn run_in_place(_command: &[String]) -> ExitCode {
    ExitCode::from(2)
}

/// Each entry on the way to the system profiles file, as the host shows it:
/// `symlink_metadata`, never followed. A path that is not there, or that sits
/// in a folder closed to this user, is absent.
#[cfg(target_os = "linux")]
fn system_profiles_entries() -> Vec<(PathBuf, crate::contain::launch::HostEntry)> {
    use crate::contain::launch::{system_profiles_chain, HostEntry};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    system_profiles_chain()
        .into_iter()
        .map(|path| {
            let entry = match std::fs::symlink_metadata(&path) {
                Ok(meta) => HostEntry::Found {
                    symlink: meta.file_type().is_symlink(),
                    dir: meta.is_dir(),
                    file: innerwarden_safe_io::is_regular_file(&meta),
                    uid: meta.uid(),
                    mode: meta.permissions().mode(),
                },
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                    ) || e.raw_os_error() == Some(libc::ENOTDIR) =>
                {
                    HostEntry::Absent
                }
                Err(_) => HostEntry::Unreadable,
            };
            (path, entry)
        })
        .collect()
}

fn mode_label(a: &ContainArgs) -> &'static str {
    match a.mode {
        crate::contain::Mode::Monitor => "monitor - records, never blocks",
        crate::contain::Mode::Enforce => "enforce - blocks dangerous commands",
        crate::contain::Mode::BlockReview => "enforce+review - blocks dangerous and ambiguous",
    }
}

fn resolve_project(p: &Path) -> PathBuf {
    let base = if p == Path::new(".") {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        p.to_path_buf()
    };
    std::fs::canonicalize(&base).unwrap_or(base)
}

/// The home's dotdirs and dotfiles the builders may bind, those that are
/// there (a link is taken where it leads): bwrap fails on a missing source.
fn existing_home_paths(home: &Path) -> Vec<PathBuf> {
    [
        ".claude",
        ".config",
        ".cache",
        ".cargo",
        ".rustup",
        ".npm",
        ".local",
        ".gitconfig",
        ".claude.json",
    ]
    .iter()
    .map(|name| home.join(name))
    .filter(|path| path.exists())
    .collect()
}

/// The first of Claude Code's settings files that keeps a jail from
/// starting, and why: the person's ([`crate::contain::CLAUDE_GUARD_SETTINGS`])
/// and the project's ([`crate::contain::PROJECT_CLAUDE_SETTINGS`]), each
/// read by [`read_claude_settings`] and judged by
/// [`crate::contain::claude_settings_refusal`]. One that is not there
/// keeps nothing from starting; every other doubt does.
fn claude_settings_refused(claude: &Path, project: &Path) -> Option<String> {
    let person = crate::contain::CLAUDE_GUARD_SETTINGS
        .iter()
        .map(|name| (claude_setting(claude, name), false));
    let projects = crate::contain::PROJECT_CLAUDE_SETTINGS
        .iter()
        .map(|name| (project.join(name), true));
    person
        .chain(projects)
        .find_map(|(path, of_project)| claude_settings_value(&path, of_project).err())
        .or_else(|| project_guard_refused(project))
}

/// Why the project's Claude Code folder or MCP servers file keeps a jail
/// from starting, or `None`: either a link (the jail shows each read-only
/// where it is, and a link leads where the jail may write), or a
/// `.mcp.json` that does not read as a JSON object.
fn project_guard_refused(project: &Path) -> Option<String> {
    for name in crate::contain::PROJECT_GUARD_NAMES {
        let path = project.join(name);
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Some(format!(
                "{} is a link, and the jail shows that place read-only only where it is no \
                 link; replace the link with what it leads to and start the jail again",
                crate::contain::printable(&path)
            ));
        }
    }
    let mcp = project.join(".mcp.json");
    match read_claude_settings(&mcp) {
        Err(why) => Some(why),
        Ok(None) => None,
        Ok(Some(bytes)) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(value) if value.is_object() => None,
            _ => Some(format!(
                "{} is not a JSON object InnerWarden reads; fix it and start the jail again",
                crate::contain::printable(&mcp)
            )),
        },
    }
}

/// The project's [`crate::contain::ProjectClaude`], planned from the
/// launcher's records folder whether it is made yet or not.
#[cfg(unix)]
fn planned_project_claude(input: &JailInputs) -> Option<crate::contain::ProjectClaude> {
    if let Some(claude) = &input.project_claude {
        return Some(claude.clone());
    }
    let nominal = crate::contain::launch::records_dir(
        std::env::var("XDG_STATE_HOME").ok().as_deref(),
        &input.home,
    );
    let real = std::fs::canonicalize(&nominal).unwrap_or_else(|_| nominal.clone());
    let records = if input.records_dirs.is_empty() {
        vec![nominal]
    } else {
        input.records_dirs.clone()
    };
    crate::contain::plan_project_claude(&records, &real, &input.args.project)
}

/// The launcher's markers for the project's Claude Code files, kept beside
/// the project's own folder, out of every jail's reach:
///
/// * `<key>.run.<pid>`: which of [`crate::contain::PROJECT_GUARD_NAMES`]
///   were not there when this launch's jail started; removed as the launch
///   ends ([`finish_project_files`]). One another launch left (its jail
///   runs still, or its launcher stopped before the end) keeps its names
///   judged at every start;
/// * `<key>.made`: each file a jail made there that keeps a jail from
///   starting, as the launcher found it when that jail ended, until the
///   person accepts it (`innerwarden contain --accept-project-files`);
/// * `<key>.absent`: the one marker of an earlier launcher, read as a run
///   marker left behind.
///
/// A file the person makes in the project between two runs is in none of
/// them, so it is the person's: the start check of their settings
/// ([`claude_settings_refused`]) reads it like any other.
#[cfg(unix)]
fn marker_base(claude: &crate::contain::ProjectClaude) -> Option<(PathBuf, String)> {
    let name = claude.source.file_name()?.to_string_lossy().to_string();
    Some((claude.source.parent()?.to_path_buf(), name))
}

/// This launch's run marker ([`marker_base`]).
#[cfg(unix)]
fn run_marker(claude: &crate::contain::ProjectClaude) -> Option<PathBuf> {
    let (dir, name) = marker_base(claude)?;
    Some(dir.join(format!("{name}.run.{}", std::process::id())))
}

/// The marker of the files jails made ([`marker_base`]).
#[cfg(unix)]
fn made_marker(claude: &crate::contain::ProjectClaude) -> Option<PathBuf> {
    let (dir, name) = marker_base(claude)?;
    Some(dir.join(format!("{name}.made")))
}

/// Every run marker there, this launch's included, and an earlier
/// launcher's `.absent`, whatever each is (one that is no plain file is
/// never followed, and refuses the start when read: [`read_note`]), or why
/// the folder cannot be read.
#[cfg(unix)]
fn run_markers(claude: &crate::contain::ProjectClaude) -> Result<Vec<PathBuf>, String> {
    let Some((dir, name)) = marker_base(claude) else {
        return Ok(Vec::new());
    };
    let run = format!("{name}.run.");
    let legacy = format!("{name}.absent");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(note_unreadable(&dir, &e.to_string())),
    };
    let mut out: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            let file = entry.file_name().to_string_lossy().to_string();
            file.starts_with(&run) || file == legacy
        })
        .map(|entry| entry.path())
        .collect();
    out.sort();
    Ok(out)
}

/// Why a start does not go on where a launcher's note cannot be read: what
/// a jail made in the project is then not known.
#[cfg(unix)]
fn note_unreadable(note: &Path, why: &str) -> String {
    format!(
        "the launcher's note {} cannot be read ({why}), so what a jail made in this project \
         is not known",
        crate::contain::printable(note)
    )
}

/// The text of a launcher's note, `None` where it is not there, or why it
/// cannot be read (it is no plain file, or closed to this account): a note
/// that cannot be read refuses the start, never counts as none.
#[cfg(unix)]
fn read_note(note: &Path) -> Result<Option<String>, String> {
    match std::fs::symlink_metadata(note) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(note_unreadable(note, &e.to_string())),
        Ok(meta) if !meta.is_file() => return Err(note_unreadable(note, "it is no plain file")),
        Ok(_) => {}
    }
    std::fs::read_to_string(note)
        .map(Some)
        .map_err(|e| note_unreadable(note, &e.to_string()))
}

/// The launch a run marker names is running (its pid answers); an earlier
/// launcher's `.absent` names none.
#[cfg(unix)]
fn marker_launch_runs(marker: &Path) -> bool {
    let Some(pid) = marker
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.rsplit_once(".run."))
        .and_then(|(_, pid)| pid.parse::<i32>().ok())
        .filter(|pid| *pid > 0)
    else {
        return false;
    };
    // SAFETY: signal 0 sends nothing; it only asks whether the pid exists.
    let answer = unsafe { libc::kill(pid, 0) };
    let exists = answer == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    if !exists {
        return false;
    }
    // A pid used again: the process that has it started after the note was
    // written, so it is not the launch that wrote it. Where the start time
    // cannot be read, the launch is taken to run.
    let written = std::fs::symlink_metadata(marker).and_then(|m| m.modified());
    match (process_started(pid), written) {
        (Some(started), Ok(written)) => started <= written + std::time::Duration::from_secs(2),
        _ => true,
    }
}

/// When process `pid` started, where the system says.
#[cfg(target_os = "linux")]
fn process_started(pid: i32) -> Option<std::time::SystemTime> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    // Field 22 (`starttime`), counted from field 3 after the name.
    let ticks: u64 = after.split_whitespace().nth(19)?.parse().ok()?;
    let boot: u64 = std::fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("btime ")?.trim().parse().ok())?;
    // SAFETY: sysconf has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz <= 0 {
        return None;
    }
    Some(
        std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(boot)
            + std::time::Duration::from_millis(ticks.saturating_mul(1000) / hz as u64),
    )
}

/// When process `pid` started, where the system says.
#[cfg(target_os = "macos")]
fn process_started(pid: i32) -> Option<std::time::SystemTime> {
    // SAFETY: a zeroed proc_bsdinfo is a valid value of plain integers.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: the buffer is `size` bytes of the struct the call fills.
    let filled = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if filled != size {
        return None;
    }
    Some(
        std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(info.pbi_start_tvsec)
            + std::time::Duration::from_micros(info.pbi_start_tvusec),
    )
}

/// When process `pid` started: not read on other systems.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn process_started(_pid: i32) -> Option<std::time::SystemTime> {
    None
}

/// The Claude Code files of `project` that the `names` of
/// [`crate::contain::PROJECT_GUARD_NAMES`] stand for.
#[cfg(unix)]
fn files_of_names<'a>(project: &Path, names: impl Iterator<Item = &'a str>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for name in names.filter(|n| crate::contain::PROJECT_GUARD_NAMES.contains(n)) {
        if name == ".claude" {
            for file in ["settings.json", "settings.local.json"] {
                out.push(project.join(".claude").join(file));
            }
        } else {
            out.push(project.join(name));
        }
    }
    out
}

/// Why `file`, made while a jail ran, keeps a jail from starting, or
/// `None` where it is not there or sets nothing that reaches the host
/// ([`crate::contain::project_settings_made_refusal`]).
#[cfg(unix)]
fn made_file_refusal(file: &Path) -> Option<String> {
    std::fs::symlink_metadata(file).ok()?;
    let value = read_claude_settings(file)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    crate::contain::project_settings_made_refusal(&crate::contain::printable(file), value.as_ref())
}

/// The files a jail may have made that a start judges: each one `.made`
/// lists, and each a run marker names (this launch's included, where it
/// asks before its jail starts: none yet).
///
/// Each note that cannot be read is said instead (`Err`): a start refuses
/// on it ([`read_note`]).
#[cfg(unix)]
fn files_jails_made(input: &JailInputs) -> (Vec<PathBuf>, Vec<String>) {
    let Some(claude) = planned_project_claude(input) else {
        return (Vec::new(), Vec::new());
    };
    let project = &input.args.project;
    let allowed = files_of_names(project, crate::contain::PROJECT_GUARD_NAMES.iter().copied());
    let mut unread = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(marker) = made_marker(&claude) {
        match read_note(&marker) {
            Ok(Some(text)) => files.extend(
                text.lines()
                    .map(PathBuf::from)
                    .filter(|file| allowed.contains(file)),
            ),
            Ok(None) => {}
            Err(why) => unread.push(why),
        }
    }
    match run_markers(&claude) {
        Ok(markers) => {
            for marker in markers {
                match read_note(&marker) {
                    Ok(Some(text)) => files.extend(files_of_names(project, text.lines())),
                    Ok(None) => {}
                    Err(why) => unread.push(why),
                }
            }
        }
        Err(why) => unread.push(why),
    }
    let mut seen = std::collections::HashSet::new();
    files.retain(|file| seen.insert(file.clone()));
    (files, unread)
}

/// Each reason a file of the project's that a jail made keeps the next
/// jail from starting: one `.made` lists, or one a run marker another
/// launch left names that is there now ([`marker_base`]), still setting
/// what reaches the host.
#[cfg(unix)]
fn project_files_made(input: &JailInputs) -> Vec<String> {
    let (files, mut out) = files_jails_made(input);
    out.extend(files.iter().filter_map(|file| made_file_refusal(file)));
    out
}

/// What to do about a file a jail made that the person wants to keep:
/// accepted by the person, from outside any jail.
#[cfg(unix)]
fn accept_hint(project: &Path) -> String {
    format!(
        "if you made it yourself, or read it and want to keep it, accept it from outside \
         any jail: innerwarden contain --accept-project-files --project {}",
        crate::contain::printable(project)
    )
}

/// The names each launch's jail found absent, kept by this process as
/// well as in its run marker: the end of the run judges what its own jail
/// started without even where the marker was taken away meanwhile.
#[cfg(unix)]
fn absent_at_start() -> &'static std::sync::Mutex<std::collections::HashMap<PathBuf, Vec<String>>> {
    static NAMES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, Vec<String>>>,
    > = std::sync::OnceLock::new();
    NAMES.get_or_init(Default::default)
}

/// As the jail ends: each file of the project's its jail made (absent when
/// it started, there now) that keeps the next jail from starting, said
/// back, and kept in `.made` for the next start; the run marker is taken
/// away. A dry run, or a jail without the launcher's folder, made nothing.
#[cfg(unix)]
fn finish_project_files(input: &JailInputs) -> Vec<String> {
    let Some(claude) = planned_project_claude(input) else {
        return Vec::new();
    };
    let (Some(marker), Some(made)) = (run_marker(&claude), made_marker(&claude)) else {
        return Vec::new();
    };
    let kept = absent_at_start()
        .lock()
        .ok()
        .and_then(|mut names| names.remove(&marker));
    let names = kept.unwrap_or_else(|| {
        std::fs::read_to_string(&marker)
            .map(|text| text.lines().map(str::to_string).collect())
            .unwrap_or_default()
    });
    let files = files_of_names(&input.args.project, names.iter().map(String::as_str));
    let refused: Vec<(PathBuf, String)> = files
        .into_iter()
        .filter_map(|file| made_file_refusal(&file).map(|why| (file, why)))
        .collect();
    if !refused.is_empty() {
        let mut listed: Vec<String> = std::fs::read_to_string(&made)
            .map(|text| text.lines().map(str::to_string).collect())
            .unwrap_or_default();
        for (file, _) in &refused {
            let line = file.to_string_lossy().to_string();
            if !listed.contains(&line) {
                listed.push(line);
            }
        }
        let dir = made.parent().unwrap_or(Path::new("/"));
        let temp = launch_temp_name(&made);
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        if let Err(e) = write_private_file(dir, &made, &temp, listed.join("\n").as_bytes(), uid) {
            eprintln!(
                "innerwarden contain: the launcher cannot keep which files the jail made ({e}); \
                 its run marker stays, so the next start judges them"
            );
            return refused.into_iter().map(|(_, why)| why).collect();
        }
    }
    let _ = std::fs::remove_file(&marker);
    refused.into_iter().map(|(_, why)| why).collect()
}

/// `innerwarden contain --accept-project-files [--project <dir>]`: the
/// person takes the files of the project's that jails made as theirs. It
/// says each, takes away `.made` and the run markers of launches that no
/// longer run, and starts nothing. A launch still running keeps its marker
/// (what its jail makes is judged when it ends). Inside a jail the
/// launcher's folder is out of reach, and the guard refuses the command to
/// an agent: accepting is the person's.
#[cfg(unix)]
fn accept_project_files(home: &Path, project: &Path) -> ExitCode {
    let mut args = match crate::contain::parse_contain_args(&["--setup".to_string()]) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("innerwarden contain: {e}");
            return ExitCode::from(2);
        }
    };
    args.project = project.to_path_buf();
    match resolve_inputs(args, home.to_path_buf(), PathBuf::from("/usr/bin/true")) {
        Ok(input) => accept_project_files_for(&input),
        Err(e) => {
            eprintln!("innerwarden contain: {e}");
            ExitCode::from(2)
        }
    }
}

/// [`accept_project_files`] for the project and the launcher's folder
/// `input` plans.
#[cfg(unix)]
fn accept_project_files_for(input: &JailInputs) -> ExitCode {
    let project = &input.args.project;
    let Some(claude) = planned_project_claude(input) else {
        println!(
            "innerwarden contain: nothing to accept in {}",
            crate::contain::printable(project)
        );
        return ExitCode::SUCCESS;
    };
    let (files, unread) = files_jails_made(input);
    let files: Vec<PathBuf> = files
        .into_iter()
        .filter(|file| std::fs::symlink_metadata(file).is_ok())
        .collect();
    for why in &unread {
        println!("innerwarden contain: {why}; taken away");
    }
    let mut failed = false;
    let mut running = Vec::new();
    let markers = match run_markers(&claude) {
        Ok(markers) => markers,
        Err(why) => {
            eprintln!("innerwarden contain: {why}");
            return ExitCode::from(1);
        }
    };
    for marker in made_marker(&claude).into_iter().chain(markers) {
        if marker_launch_runs(&marker) {
            running.push(marker);
            continue;
        }
        match std::fs::remove_file(&marker) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                eprintln!(
                    "innerwarden contain: cannot take away {} ({e})",
                    crate::contain::printable(&marker)
                );
                failed = true;
            }
        }
    }
    if failed {
        return ExitCode::from(1);
    }
    if files.is_empty() {
        println!(
            "innerwarden contain: nothing to accept in {}",
            crate::contain::printable(project)
        );
    }
    for file in &files {
        println!(
            "innerwarden contain: accepted as yours: {}",
            crate::contain::printable(file)
        );
    }
    if !running.is_empty() {
        println!(
            "innerwarden contain: a jail still runs in this project; what it makes is judged \
             when it ends"
        );
    }
    ExitCode::SUCCESS
}

/// Before the jail runs: which of the project's
/// [`crate::contain::PROJECT_GUARD_NAMES`] are not there, kept in this
/// launch's run marker ([`marker_base`]) and by this process.
#[cfg(unix)]
fn keep_absent_names(
    input: &JailInputs,
    claude: &crate::contain::ProjectClaude,
    uid: u32,
) -> Result<(), String> {
    let Some(marker) = run_marker(claude) else {
        return Ok(());
    };
    let absent: Vec<&str> = crate::contain::PROJECT_GUARD_NAMES
        .iter()
        .copied()
        .filter(|name| std::fs::symlink_metadata(input.args.project.join(name)).is_err())
        .collect();
    if let Ok(mut names) = absent_at_start().lock() {
        names.insert(
            marker.clone(),
            absent.iter().map(|n| n.to_string()).collect(),
        );
    }
    // The start check passed: what launches that no longer run left, and
    // the files `.made` lists that no longer refuse, were judged now and
    // set nothing. Kept, they would take a file the person makes later
    // for a jail's.
    for left in run_markers(claude)? {
        if left != marker && !marker_launch_runs(&left) {
            let _ = std::fs::remove_file(&left);
        }
    }
    if let Some(made) = made_marker(claude) {
        if let Ok(Some(text)) = read_note(&made) {
            let still: Vec<&str> = text
                .lines()
                .filter(|line| made_file_refusal(Path::new(line)).is_some())
                .collect();
            if still.is_empty() {
                let _ = std::fs::remove_file(&made);
            } else if still.len() < text.lines().count() {
                let temp = launch_temp_name(&made);
                let dir = made.parent().unwrap_or(Path::new("/"));
                write_private_file(dir, &made, &temp, still.join("\n").as_bytes(), uid).map_err(
                    |e| format!("the launcher cannot keep which files jails made ({e})"),
                )?;
            }
        }
    }
    let dir = marker.parent().unwrap_or(Path::new("/"));
    let temp = launch_temp_name(&marker);
    write_private_file(dir, &marker, &temp, absent.join("\n").as_bytes(), uid)
        .map(|_| ())
        .map_err(|e| format!("the launcher cannot keep what the project lacks ({e})"))
}

/// The person's Claude Code settings file `name` (one of
/// [`crate::contain::CLAUDE_GUARD_SETTINGS`]) in their Claude Code folder
/// `claude` ([`crate::contain::persons_claude_dir`]).
fn claude_setting(claude: &Path, name: &str) -> PathBuf {
    claude.join(Path::new(name).file_name().unwrap_or_default())
}

/// The settings in the Claude Code settings file `path` (`None` where it is
/// not there), or why a jail does not start on it
/// ([`read_claude_settings`], [`crate::contain::claude_settings_refusal`]).
fn claude_settings_value(
    path: &Path,
    project: bool,
) -> Result<Option<(Vec<u8>, serde_json::Value)>, String> {
    let shown = crate::contain::printable(path);
    let Some(bytes) = read_claude_settings(path)? else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "{shown} is not JSON InnerWarden reads ({e}), so what it does to the guard's hook \
             cannot be told; fix it and start the jail again"
        )
    })?;
    match crate::contain::claude_settings_refusal(&shown, &value, project) {
        Some(why) => Err(why),
        None => Ok(Some((bytes, value))),
    }
}

/// The bytes of the Claude Code settings file `path`, `None` where nothing
/// is there, or why a jail does not start on it: a link (what it leads to
/// can change after the check), anything but a file, one larger than
/// [`MAX_CLAUDE_SETTINGS_READ`], or one that cannot be read.
fn read_claude_settings(path: &Path) -> Result<Option<Vec<u8>>, String> {
    use std::io::Read;
    let shown = crate::contain::printable(path);
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{shown} cannot be read ({e})")),
    };
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{shown} is a link, and what it leads to can change after the check; replace the \
             link with the file it leads to and start the jail again"
        ));
    }
    if !meta.is_file() {
        return Err(format!("{shown} is not a file"));
    }
    let too_large = || {
        format!(
            "{shown} is larger than {} MiB, more than InnerWarden reads to check the guard's \
             hook; make it smaller and start the jail again",
            MAX_CLAUDE_SETTINGS_READ / (1024 * 1024)
        )
    };
    if meta.len() > MAX_CLAUDE_SETTINGS_READ {
        return Err(too_large());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    innerwarden_safe_io::harden(&mut options);
    let mut bytes = Vec::new();
    options
        .open(path)
        .and_then(|f| f.take(MAX_CLAUDE_SETTINGS_READ + 1).read_to_end(&mut bytes))
        .map_err(|e| format!("{shown} cannot be read ({e})"))?;
    if bytes.len() as u64 > MAX_CLAUDE_SETTINGS_READ {
        return Err(too_large());
    }
    Ok(Some(bytes))
}

/// The largest Claude Code settings file read before a jail starts.
const MAX_CLAUDE_SETTINGS_READ: u64 = 4 * 1024 * 1024;

/// What the jail is, from what is on the host now: the worktree the
/// project's `.git` file names ([`detect_worktree`]), then the jail planned
/// with it. A worktree the plan finds the jail shows writable anyway, or
/// over a place it hides, is taken out, and the jail planned again without
/// it ([`crate::contain::worktree_planned`]): no worktree, one line at
/// most, and the jail starts.
fn resolve_inputs(
    args: ContainArgs,
    home: PathBuf,
    iw_binary: PathBuf,
) -> Result<JailInputs, crate::contain::ContainError> {
    use crate::contain::WorktreePlanned;
    let found = detect_worktree(&args.project, &home);
    let input = resolve_planned(args.clone(), home.clone(), iw_binary.clone(), found)?;
    let said = match crate::contain::worktree_planned(&input) {
        WorktreePlanned::Kept => return Ok(input),
        WorktreePlanned::ShownAnyway => None,
        WorktreePlanned::Left(why) => input.worktree.as_ref().map(|worktree| {
            crate::contain::worktree_left_out(&args.project.join(".git"), &worktree.git_dir, &why)
        }),
    };
    resolve_planned(args, home, iw_binary, (None, said))
}

/// [`resolve_inputs`], with the worktree (and the line said of it) given.
fn resolve_planned(
    args: ContainArgs,
    home: PathBuf,
    iw_binary: PathBuf,
    found: (Option<Worktree>, Option<String>),
) -> Result<JailInputs, crate::contain::ContainError> {
    // Canonicalize TMPDIR too (macOS $TMPDIR is under the /var symlink) so the
    // writable-set rule matches the resolved path.
    let tmpdir = launcher_tmpdir();

    let existing_paths = existing_home_paths(&home);

    let usr_merged = std::fs::symlink_metadata("/bin")
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);

    let (worktree, worktree_said) = found;

    // Symlink-resolve the secret dir (dotfile managers symlink ~/.config): resolve
    // the ~/.config parent then append, so it works even before innerwarden/ exists.
    let iw_config_named = home.join(".config/innerwarden");
    let iw_config_through = std::fs::canonicalize(home.join(".config"))
        .map(|c| c.join("innerwarden"))
        .unwrap_or_else(|_| iw_config_named.clone());
    // The dir itself a link (a dotfiles manager's): taken where it leads.
    let iw_config_link = goes_through_a_link(&home, &iw_config_named);

    // Each host folder the jail shows, as the jail sees it and as its host
    // path resolves: what the jail covers is covered at each such place.
    let shown = crate::contain::shown_host_folders(
        &args,
        &home,
        worktree.as_ref(),
        &existing_paths,
        |path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()),
    );
    // What the planner of the places the jail hides knows of this jail:
    // where it shows each host folder, which ones it writes, what it needs
    // as it is (the guard, the agent's command and settings, the system
    // profiles) and what it works in.
    let agent_command = args.child.first().and_then(|command| command_path(command));
    let facts = crate::contain::place_facts(
        &args,
        &home,
        worktree.as_ref(),
        &existing_paths,
        &iw_binary,
        agent_command.as_deref(),
        &tmpdir,
        cfg!(target_os = "macos"),
        |path| leads_to(path).unwrap_or_else(|| path.to_path_buf()),
    );
    let mut left: Vec<String> = worktree_said.into_iter().collect();
    // The places the jail never shows are planned with hiding first: a
    // read-only path of the profile never keeps one from being hidden where
    // a link leads it ([`crate::contain::PlaceFacts::hiding_first`]).
    let hiding = facts.hiding_first();

    // Linux: the secret dir at every other place a home folder the jail
    // binds shows it. Empty in every common layout. Where the dir itself
    // is a link: refused on Linux (a program in the jail could replace
    // the link on the host), denied where it leads on macOS, unless the
    // jail leaves that place as it is (said).
    let (iw_config_real, iw_config_shown, iw_config_left) = if iw_config_link {
        let place = hidden_place(&iw_config_named, &facts.writable, true);
        let real = place
            .leads_to
            .clone()
            .unwrap_or_else(|| iw_config_through.clone());
        if !facts.macos {
            return Err(crate::contain::iw_folder_link_refused(
                &iw_config_named,
                &real,
            ));
        }
        // Through a link a program in the jail can change: refused.
        let mut linked = crate::contain::plan_linked_places(&[place], &hiding, &[], false)?;
        // Left as it is: needed, or a loop.
        let iw_left = linked.hidden.is_empty();
        left.append(&mut linked.left);
        (real, Vec::new(), iw_left)
    } else {
        let views = if cfg!(target_os = "linux") {
            crate::contain::other_jail_views(
                &iw_config_through,
                &[iw_config_named.clone(), iw_config_through.clone()],
                &shown,
            )
        } else {
            Vec::new()
        };
        (iw_config_through, views, false)
    };

    // Expand the deny_read globs against the real project + stat each match so the
    // builder knows file-vs-dir (Linux masks a file with /dev/null, a dir with tmpfs).
    // Each is hidden where it leads, and at every other place the jail
    // shows it; one a link leads onto what the jail needs, or (through a
    // link a program in the jail can change) onto what the jail runs on,
    // is left as it is (said).
    let (deny_paths, mut deny_linked) = crate::contain::plan_denied_paths(
        &deny_read_places(&args.project, &args.deny_read, &facts.writable),
        &facts,
    );
    left.append(&mut deny_linked.left);

    // The dotdirs the jail never shows, where a link leads one into a
    // folder it shows (`~/.ssh` a link to `.config/ssh`): covered there too
    // on Linux, denied where it leads on macOS. Empty in every common
    // layout. One through a link a program in the jail can change (one in
    // `~/.config`, the project, `/tmp`) refuses the launch. And each link
    // inside one of them that leads out of it (`~/.ssh/config` a link into
    // `~/.local/share`), the same way.
    let mut dotdirs_linked = crate::contain::plan_linked_places(
        &never_shown_places(&home, &facts, &mut left),
        &hiding,
        &[
            vec![iw_config_named.clone(), iw_config_real.clone()],
            iw_config_shown.clone(),
        ]
        .concat(),
        false,
    )?;
    left.append(&mut dotdirs_linked.left);
    // Each plan holds only its own OS's: masks on Linux, denies on macOS.
    let mut linked_masks = dotdirs_linked.masks;
    for mask in deny_linked.masks {
        if !linked_masks.iter().any(|seen| seen.abs == mask.abs) {
            linked_masks.push(mask);
        }
    }
    let mut linked_missing = dotdirs_linked.missing;
    linked_missing.append(&mut deny_linked.missing);
    let linked_denies = dotdirs_linked.denies;
    let hidden_targets = dotdirs_linked.hidden;

    // The home paths a jail profile hides: where each leads, every link
    // followed, covered where the jail shows it (Linux) and denied as named
    // and as resolved (macOS). Without such a profile nothing is read.
    let hidden = if args.hide_home.is_empty() {
        crate::contain::HiddenPlan::default()
    } else {
        let found = hidden_home_facts(&home, &args.hide_home, &facts.writable, facts.macos);
        crate::contain::plan_hidden_home(&found, &home, &shown)?
    };

    // Every Linux jail, `--identity` or not: where `/etc/resolv.conf` is a
    // link into `/run`, the file it names, if that is a file, or the folder
    // of resolver data alone that holds it.
    let resolv_conf = if cfg!(target_os = "linux") {
        std::fs::read_link("/etc/resolv.conf")
            .ok()
            .and_then(|link| crate::contain::launch::resolv_conf_target(&link))
            .filter(|target| std::fs::metadata(target).is_ok_and(|m| m.is_file()))
            .map(|target| crate::contain::launch::resolv_conf_bind(&target, holds_a_socket))
    } else {
        None
    };

    // Every launch keeps the launcher's records out of the jail's writing:
    // an identified one hides them, a plain one shows them read-only. Only
    // an identified launch keeps its helpers' environment apart.
    let (records_dirs, records_real) = {
        let nominal = crate::contain::launch::records_dir(
            std::env::var("XDG_STATE_HOME").ok().as_deref(),
            &home,
        );
        // Linux: never through a link in a folder the jail writes
        // (`~/.local/state` a link): a program in the jail could replace
        // that link on the host, and the launcher would keep its records,
        // and read them, in a folder of the agent's. Refused, as
        // InnerWarden's own folder kept as a link is. A link the jail
        // cannot change (`~/.local` itself a link, in the home) is fine.
        if !facts.macos {
            let (_, links) = trace_links(&nominal);
            if let Some(link) = crate::contain::steering_link(&links, None, &facts.writable) {
                return Err(crate::contain::records_link_refused(&nominal, link));
            }
        }
        let real = leads_to(&nominal).unwrap_or_else(|| resolved_through_existing(&nominal));
        let named = [nominal.clone(), real.clone()];
        let mut dirs = vec![nominal];
        if real != dirs[0] {
            dirs.push(real.clone());
        }
        // Linux: and at every other place a home folder the jail binds
        // shows it (`~/.local` a link into a `~/.cache` that leads off the
        // home).
        if cfg!(target_os = "linux") {
            let others = crate::contain::other_jail_views(&real, &named, &shown);
            dirs.extend(others);
        }
        (dirs, real)
    };
    let child_env = if args.identity {
        // The command's own `PATH` (and a loader variable only when passed
        // by name): what the allow list lets in, as without the flag.
        crate::contain::launch_env(std::env::vars_os())
            .child_env
            .into_iter()
            .filter(|(name, _)| {
                crate::contain::env_goes_in(std::ffi::OsStr::new(name), &args.pass_env)
            })
            .collect()
    } else {
        Vec::new()
    };
    // Every jail has a `~/.claude` of its own for this project, beside the
    // records ([`crate::contain::ProjectClaude`]); made by the real run
    // alone ([`prepare_project_claude`]).
    let project_claude =
        crate::contain::plan_project_claude(&records_dirs, &records_real, &args.project)
            .filter(|claude| std::fs::symlink_metadata(&claude.source).is_ok_and(|m| m.is_dir()));
    // The host's `~/.claude`, never shown writable: as named, where it
    // leads, and (Linux) every other place a folder the jail shows it.
    let claude_host_dir = crate::contain::persons_claude_dir(
        &home,
        &args.pass_env,
        std::env::var_os(crate::contain::CLAUDE_CONFIG_ENV).as_deref(),
    )?;
    let claude_views = {
        let named = claude_host_dir.clone();
        let real = std::fs::canonicalize(&named).unwrap_or_else(|_| named.clone());
        let mut views = vec![named.clone()];
        if real != named {
            views.push(real.clone());
        }
        if cfg!(target_os = "linux") {
            let others = crate::contain::other_jail_views(&real, &views, &shown);
            views.extend(others);
        }
        views
    };
    // A plain Linux jail shows a records folder read-only only where it is
    // there: the real run makes it before the jail is planned
    // ([`make_plain_records`]), and a folder that is not there is never
    // pinned. An identified one hides it where it is.
    let records_dirs = if args.identity || !cfg!(target_os = "linux") {
        records_dirs
    } else {
        records_dirs
            .into_iter()
            .filter(|dir| std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir()))
            .collect()
    };

    // The project's Claude Code folder and MCP servers file, where each is
    // there and no link: read-only in the jail.
    let project_guard_files = crate::contain::PROJECT_GUARD_NAMES
        .iter()
        .map(|name| args.project.join(name))
        .filter(|path| std::fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_symlink()))
        .collect();
    Ok(JailInputs {
        args,
        home,
        tmpdir,
        iw_binary,
        agent_binary: None, // v1: the .local/.claude dotdir binds cover the agent binary
        worktree,
        usr_merged,
        stdin_is_tty: std::io::stdin().is_terminal(),
        existing_paths,
        iw_config_real,
        iw_config_shown,
        iw_config_link,
        iw_config_left,
        linked_masks,
        linked_missing,
        linked_denies,
        hidden_targets,
        left,
        deny_paths,
        info_fd: None,
        record_fd: None,
        key_fd: None,
        profiles_marker_fd: None,
        records_dirs,
        child_env,
        close_userns: false,
        seccomp_fd: None,
        hide_paths: hidden.masks,
        hide_denies: hidden.denies,
        hide_links: hidden.links,
        resolv_conf,
        gate_instance: None,
        claude_views,
        claude_hook_files: Vec::new(),
        project_guard_files,
        claude_host_dir,
        hook_cli: None,
        jail_writes: facts.writable.clone(),
        bind_fds: Vec::new(),
        record_channel: None,
        project_claude,
    })
}

/// [`resolve_inputs`], with each extra path of the jail that would show
/// what it must not left out first ([`crate::contain::extra_paths_left_out`]:
/// one over the home, in a place the jail hides, under a profile's hidden
/// home path, or with `--identity` over `/run` or `/sys`; on Linux, one
/// that holds a place the jail hides where the jail shows nothing else of
/// it), and the line that says so added to `said` once. The jail is
/// planned again without it, so nothing of it is left in the plan, and it
/// still starts: one wrong extra path never keeps the agent from starting.
/// Each round takes one path or more out, so it ends.
fn resolve_screened(
    args: ContainArgs,
    home: PathBuf,
    iw_binary: PathBuf,
    said: &mut Vec<String>,
) -> Result<JailInputs, crate::contain::ContainError> {
    let mut args = args;
    loop {
        let input = resolve_inputs(args.clone(), home.clone(), iw_binary.clone())?;
        let left = crate::contain::extra_paths_left_out(&input, cfg!(target_os = "macos"));
        if left.is_empty() {
            return Ok(input);
        }
        for (_, line) in &left {
            if !said.contains(line) {
                said.push(line.clone());
            }
        }
        crate::contain::leave_out_extra_paths(&mut args, &left);
    }
}

/// The trusted places of the bwrap a Linux jail runs with.
const BWRAP_PATHS: &[&str] = &["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];

/// The launcher's temporary folder, `TMPDIR` symlink-resolved (macOS's is
/// under the `/var` link) so the writable-set rule matches the resolved
/// path, else `/tmp`.
fn launcher_tmpdir() -> PathBuf {
    std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// Each extra path of `args` laid where the jail lays it, and the lines
/// that say what is left out ([`crate::contain::screen_extra_paths`]), from
/// what is on the host now: where each path leads and through which links
/// ([`extra_found`]), what the jail shows and writes (the project, the
/// worktree, the home's folders it binds), and whether bwrap binds a place
/// from a descriptor ([`bwrap_binds_fds`]). A jail without such a path
/// reads nothing.
fn screen_extra(args: &mut ContainArgs, home: &Path, iw_binary: &Path) -> Vec<String> {
    if args.extra_ro.is_empty() && args.extra_rw.is_empty() {
        return Vec::new();
    }
    let macos = cfg!(target_os = "macos");
    let existing = existing_home_paths(home);
    let (worktree, _) = detect_worktree(&args.project, home);
    let mut bare = args.clone();
    bare.extra_ro.clear();
    bare.extra_ro_sources.clear();
    let facts = crate::contain::place_facts(
        &bare,
        home,
        worktree.as_ref(),
        &existing,
        iw_binary,
        None,
        &launcher_tmpdir(),
        macos,
        |path| leads_to(path).unwrap_or_else(|| path.to_path_buf()),
    );
    let jail = crate::contain::ExtraJail {
        shown: &facts.shown,
        writable: &facts.writable,
        macos,
        binds_fds: bwrap_binds_fds(),
    };
    crate::contain::screen_extra_paths(args, extra_found, jail)
}

/// What is at an extra path of the jail on the host: where it leads with
/// every link on the way followed, and each link followed ([`trace_links`],
/// one `lstat` and `readlink` per step). On macOS the place it leads to is
/// taken as the disk spells its names (`~/Code` named `~/code` on a disk
/// that tells no case apart), as the sandbox matches it.
fn extra_found(path: &Path) -> crate::contain::ExtraFound {
    use crate::contain::ExtraFound;
    if !crate::contain::plain_absolute(path) {
        return ExtraFound::NotPlain;
    }
    let (at, links) = trace_links(path);
    let Some(at) = at else {
        return ExtraFound::Loop;
    };
    if std::fs::symlink_metadata(&at).is_err() {
        return ExtraFound::Missing;
    }
    #[cfg(target_os = "macos")]
    let at = std::fs::canonicalize(&at).unwrap_or(at);
    ExtraFound::Found {
        leads_to: at,
        links,
    }
}

/// Whether the bwrap this launcher would use binds a place from a
/// descriptor (`--ro-bind-fd`, `--bind-fd`), as its own `--help` says;
/// asked once. A host with no bwrap the launcher trusts answers yes: its
/// real run stops anyway ("bwrap not found"), and its dry run shows the
/// plan such a bwrap would run. Not Linux: no.
fn bwrap_binds_fds() -> bool {
    #[cfg(target_os = "linux")]
    {
        static TAKES: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *TAKES.get_or_init(|| match resolve_backend(BWRAP_PATHS) {
            None => true,
            Some(bwrap) => Command::new(&bwrap)
                .arg("--help")
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output()
                .is_ok_and(|out| crate::contain::help_binds_fds(&out.stdout)),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Linux: open `path` to bind from the descriptor, one step at a time from
/// the root, each step opened with no link followed (`O_PATH`,
/// `O_NOFOLLOW`), so what is opened is what each step held when it was
/// opened, whatever is renamed or linked there after. A link is followed
/// only where it sits in a folder no program in a jail can write
/// (`writes`): the person's own (`~/.local` a link to another disk), and a
/// home folder the jail binds (`dotdirs`, as named), which the jail's own
/// bind of that folder follows by name too. Any other link in such a folder
/// refuses, as does a step that is not there: a program in a jail could
/// have put a link there since the launcher looked. Returns the descriptor,
/// the place it opened (every link it followed resolved) and whether that
/// is a folder.
#[cfg(target_os = "linux")]
fn open_held(
    path: &Path,
    writes: &[PathBuf],
    dotdirs: &[PathBuf],
) -> Result<(std::os::fd::OwnedFd, PathBuf, bool), String> {
    use std::ffi::{CString, OsStr, OsString};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;
    let open = |dir: libc::c_int, name: &OsStr| -> Result<OwnedFd, String> {
        let c = CString::new(name.as_bytes()).map_err(|_| "a name with a NUL".to_string())?;
        // SAFETY: a NUL-ended name alive for the call, on a descriptor this
        // function holds (or the current folder's, for an absolute name).
        let fd = unsafe {
            libc::openat(
                dir,
                c.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: the descriptor was opened by this call, and is owned once.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    };
    let mode = |fd: &OwnedFd| -> Result<libc::mode_t, String> {
        // SAFETY: an all-zero `stat` is a valid value to be written over.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat on a descriptor this function holds, into `st`.
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(st.st_mode & libc::S_IFMT)
    };
    if !path.is_absolute() {
        return Err("not an absolute path".to_string());
    }
    let push_steps = |todo: &mut Vec<OsString>, of: &Path| {
        for part in of.components().rev() {
            match part {
                Component::Normal(name) => todo.push(name.to_os_string()),
                Component::ParentDir => todo.push("..".into()),
                Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            }
        }
    };
    let root = || open(libc::AT_FDCWD, OsStr::new("/"));
    let mut todo: Vec<OsString> = Vec::new();
    push_steps(&mut todo, path);
    let mut at = PathBuf::from("/");
    let mut fd = root()?;
    let mut links = 0usize;
    while let Some(step) = todo.pop() {
        if step == ".." {
            at.pop();
            fd = open(fd.as_raw_fd(), OsStr::new(".."))?;
            continue;
        }
        let next = open(fd.as_raw_fd(), &step)
            .map_err(|why| format!("{}: {why}", crate::contain::printable(&at.join(&step))))?;
        if mode(&next)? != libc::S_IFLNK {
            at.push(&step);
            fd = next;
            continue;
        }
        let link = at.join(&step);
        if writes.iter().any(|folder| at.starts_with(folder)) && !dotdirs.contains(&link) {
            return Err(format!(
                "{} is a link in a folder a program in the jail can write",
                crate::contain::printable(&link)
            ));
        }
        links += 1;
        if links > MAX_LINKS {
            return Err("its links loop".to_string());
        }
        let mut target = vec![0u8; libc::PATH_MAX as usize];
        // SAFETY: readlinkat on the link's own descriptor (an `O_PATH` one
        // of a link, read with an empty name), into a buffer of the length
        // given.
        let read = unsafe {
            libc::readlinkat(
                next.as_raw_fd(),
                c"".as_ptr(),
                target.as_mut_ptr().cast(),
                target.len(),
            )
        };
        let Ok(read) = usize::try_from(read) else {
            return Err(std::io::Error::last_os_error().to_string());
        };
        target.truncate(read);
        let target = PathBuf::from(OsStr::from_bytes(&target));
        if target.is_absolute() {
            at = PathBuf::from("/");
            fd = root()?;
        }
        push_steps(&mut todo, &target);
    }
    let folder = mode(&fd)? == libc::S_IFDIR;
    Ok((fd, at, folder))
}

/// Linux, the real run: [`JailInputs::bind_fds`] filled where bwrap binds a
/// place from a descriptor ([`bwrap_binds_fds`]): each place of
/// [`crate::contain::places_bound_from_descriptors`] opened now, after
/// every check ([`open_held`]), its descriptor handed to bwrap, which binds
/// what it holds and closes it before the jail's command runs. The
/// descriptors are returned, to be kept open until bwrap has started. Where
/// bwrap binds none, the input as it is. A place that cannot be opened so
/// stops the launch: a link a program in a jail put on its way since the
/// launcher looked, a pinned folder or a worktree's folder that is no
/// folder now, a worktree's folder or a read-only path that leads elsewhere
/// now.
#[cfg(target_os = "linux")]
fn with_held_binds(input: &JailInputs) -> Result<(JailInputs, Vec<std::os::fd::OwnedFd>), String> {
    hold_binds(input, bwrap_binds_fds())
}

/// [`with_held_binds`], `takes_fds` saying whether bwrap binds a place
/// from a descriptor.
#[cfg(target_os = "linux")]
fn hold_binds(
    input: &JailInputs,
    takes_fds: bool,
) -> Result<(JailInputs, Vec<std::os::fd::OwnedFd>), String> {
    use std::os::fd::AsRawFd;
    let mut out = input.clone();
    let mut held = Vec::new();
    if !takes_fds {
        return Ok((out, held));
    }
    let dotdirs: Vec<PathBuf> = crate::contain::writable_home_dirs()
        .iter()
        .map(|name| input.home.join(name))
        .collect();
    // A worktree's folders are folders where they were found: exact, and
    // folders still.
    let worktree_dirs: Vec<&PathBuf> = input
        .worktree
        .iter()
        .flat_map(|worktree| [&worktree.git_dir, &worktree.common_dir])
        .collect();
    for (at, host, exact) in crate::contain::places_bound_from_descriptors(input) {
        let (fd, opened, folder) = open_held(&host, &input.jail_writes, &dotdirs)
            .map_err(|why| crate::contain::held_place_changed(&at, &why))?;
        if exact && opened != host {
            return Err(crate::contain::held_place_changed(
                &at,
                &format!("it leads to {} now", crate::contain::printable(&opened)),
            ));
        }
        if (!exact || worktree_dirs.contains(&&at)) && !folder {
            return Err(crate::contain::held_place_changed(
                &at,
                "it is no folder now",
            ));
        }
        if !hand_to_child(&fd) {
            return Err(crate::contain::held_place_changed(
                &at,
                "its descriptor cannot be handed to bwrap",
            ));
        }
        out.bind_fds.push((at, fd.as_raw_fd()));
        held.push(fd);
    }
    Ok((out, held))
}

/// Each home path a jail profile hides, as found on the host: where it
/// leads with every link followed, where a file would be made when nothing
/// is there, whether it is a folder, whether a link on the way leads to
/// nothing, every link on the way (which the macOS sandbox keeps in place,
/// [`crate::contain::macos_pins`]), and (Linux, `macos` false) the first
/// link on the way in a folder the jail writes (`writable`,
/// [`crate::contain::steering_link`]), which refuses the launch. On Linux a
/// path that is not there yet, in a folder of the home the jail writes, is
/// first made as an empty folder ([`make_hidden_folder`]), unless such a
/// link is on its way.
fn hidden_home_facts(
    home: &Path,
    paths: &[PathBuf],
    writable: &[PathBuf],
    macos: bool,
) -> Vec<crate::contain::HiddenHomePath> {
    paths
        .iter()
        .map(|nominal| {
            let (_, links) = trace_links(nominal);
            let steered_by = if macos {
                None
            } else {
                crate::contain::steering_link(&links, None, writable).cloned()
            };
            #[cfg(target_os = "linux")]
            if steered_by.is_none() && std::fs::symlink_metadata(nominal).is_err() {
                make_hidden_folder(home, nominal);
            }
            let real = std::fs::canonicalize(nominal).ok();
            let resolved = real
                .clone()
                .unwrap_or_else(|| resolved_through_existing(nominal));
            let is_dir = real
                .as_ref()
                .is_some_and(|path| std::fs::metadata(path).is_ok_and(|meta| meta.is_dir()));
            crate::contain::HiddenHomePath {
                nominal: nominal.clone(),
                real,
                resolved,
                is_dir,
                dangling_link: link_on_the_way_dangles(home, nominal),
                steered_by,
                links,
            }
        })
        .collect()
}

/// Whether a step of `path` below `home` is a link that leads to nothing.
fn link_on_the_way_dangles(home: &Path, path: &Path) -> bool {
    let Ok(rest) = path.strip_prefix(home) else {
        return false;
    };
    let mut at = home.to_path_buf();
    for part in rest.components() {
        at.push(part);
        match std::fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_symlink() => {
                if std::fs::canonicalize(&at).is_err() {
                    return true;
                }
            }
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    false
}

/// Make a hidden home path that is not there yet as an empty folder, mode
/// 0700, and each missing folder on the way the same, when it is in a
/// folder of the home the jail binds read-write: a host program that makes
/// it later (git's credential cache makes its socket folder 0700 on first
/// use) then makes it under the jail's mask, never beside it. That folder
/// is taken where it leads, as the jail binds it (`~/.cache` linked to
/// `/data/cache`: under `/data/cache`); nothing is made through a link or a
/// file below it, nor outside those folders.
#[cfg(target_os = "linux")]
pub(crate) fn make_hidden_folder(home: &Path, nominal: &Path) {
    use std::os::unix::fs::DirBuilderExt;
    let Ok(rest) = nominal.strip_prefix(home) else {
        return;
    };
    let mut parts = rest.components();
    let Some(first) = parts.next() else {
        return;
    };
    let writable = crate::contain::writable_home_dirs()
        .iter()
        .any(|dir| first.as_os_str() == *dir);
    if !writable {
        return;
    }
    let Ok(mut at) = std::fs::canonicalize(home.join(first)) else {
        return;
    };
    if !std::fs::metadata(&at).is_ok_and(|meta| meta.is_dir()) {
        return;
    }
    for part in parts {
        at.push(part);
        match std::fs::symlink_metadata(&at) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if std::fs::DirBuilder::new().mode(0o700).create(&at).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// Whether a folder, or a folder in it, holds a socket (or cannot be read
/// through): a folder bound into a jail must not hand it a service.
fn holds_a_socket(folder: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let Ok(entries) = std::fs::read_dir(folder) else {
            return true;
        };
        for entry in entries.take(256) {
            let Ok(kind) = entry.and_then(|entry| {
                let kind = entry.file_type()?;
                Ok((entry.path(), kind))
            }) else {
                return true;
            };
            let (path, kind) = kind;
            if kind.is_socket() || (kind.is_dir() && holds_a_socket(&path)) {
                return true;
            }
        }
        false
    }
    #[cfg(not(unix))]
    {
        let _ = folder;
        true
    }
}

/// `path` with its longest existing ancestor symlink-resolved and the rest kept
/// as written, so a folder that does not exist yet is named where it will be.
fn resolved_through_existing(path: &Path) -> PathBuf {
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    let mut at = path.to_path_buf();
    loop {
        if let Ok(real) = std::fs::canonicalize(&at) {
            let mut out = real;
            for name in rest.iter().rev() {
                out.push(name);
            }
            return out;
        }
        match (at.file_name().map(|n| n.to_os_string()), at.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name);
                at = parent.to_path_buf();
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// Expand each `deny_read` pattern against the REAL project and stat the matches.
/// Literals are taken as-is; `dir/**` or `dir/*` mask the directory (one entry
/// covers all descendants); other globs are enumerated with the `glob` crate.
/// Each is found as [`hidden_place`] finds it: where it leads, every link
/// followed, so the mask/deny targets the real path
/// ([`crate::contain::plan_denied_paths`]). Every link on the way counts
/// toward [`crate::contain::HiddenPlace::steerable`]: a link in the project
/// is the agent's to change.
fn deny_read_places(
    project: &Path,
    patterns: &[String],
    writable: &[PathBuf],
) -> Vec<crate::contain::HiddenPlace> {
    let mut out: Vec<crate::contain::HiddenPlace> = Vec::new();
    let mut add = |path: PathBuf| {
        if !out.iter().any(|seen| seen.nominal == path) {
            out.push(hidden_place(&path, writable, false));
        }
    };
    for pat in patterns {
        if !pat.contains(['*', '?', '[']) {
            add(project.join(pat));
            continue;
        }
        if let Some(prefix) = pat.strip_suffix("/**").or_else(|| pat.strip_suffix("/*")) {
            add(project.join(prefix));
            continue;
        }
        if let Ok(paths) = glob::glob(&project.join(pat).to_string_lossy()) {
            for p in paths.flatten() {
                add(p);
            }
        }
    }
    out
}

/// A place the jail hides, as found on the host: where it leads
/// ([`leads_to`]), whether something is there and whether it is a folder
/// (`metadata`, which follows the links, so both describe what is there),
/// and the first link on the way that sits in a folder the jail writes
/// (`writable`, [`crate::contain::steering_link`]), also where the links
/// loop. `hidden_as_named`: the jail hides the place as named (a dotdir,
/// InnerWarden's folder), so its own entry is not the jail's to change.
fn hidden_place(
    nominal: &Path,
    writable: &[PathBuf],
    hidden_as_named: bool,
) -> crate::contain::HiddenPlace {
    let meta = std::fs::metadata(nominal);
    let (at, links) = trace_links(nominal);
    let own_entry = hidden_as_named
        .then(|| nominal.parent().zip(nominal.file_name()))
        .flatten()
        .map(|(parent, name)| {
            leads_to(parent)
                .unwrap_or_else(|| parent.to_path_buf())
                .join(name)
        });
    crate::contain::HiddenPlace {
        nominal: nominal.to_path_buf(),
        steered_by: crate::contain::steering_link(&links, own_entry.as_deref(), writable).cloned(),
        leads_to: at,
        there: meta.is_ok(),
        is_dir: meta.is_ok_and(|meta| meta.is_dir()),
        inner: false,
    }
}

/// The links inside a dotdir the jail never shows (`dotdir`, as named; its
/// own link is followed), each by the name the host reaches it by
/// (`~/.ssh/config`), never through one of them, and whether the walk
/// stopped short of the end ([`crate::contain::INNER_WALK_ENTRIES`],
/// [`crate::contain::INNER_WALK_DEPTH`], a folder it cannot read). A
/// dotdir that is not there holds none.
fn links_inside(dotdir: &Path) -> (Vec<PathBuf>, bool) {
    use crate::contain::{INNER_WALK_DEPTH, INNER_WALK_ENTRIES};
    let mut links = Vec::new();
    if !std::fs::metadata(dotdir).is_ok_and(|meta| meta.is_dir()) {
        return (links, false);
    }
    let mut seen = 0usize;
    let mut todo: Vec<(PathBuf, usize)> = vec![(dotdir.to_path_buf(), 0)];
    while let Some((folder, depth)) = todo.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            return (links, true);
        };
        for entry in entries {
            seen += 1;
            if seen > INNER_WALK_ENTRIES {
                return (links, true);
            }
            let Ok(entry) = entry else {
                return (links, true);
            };
            let Ok(kind) = entry.file_type() else {
                return (links, true);
            };
            if kind.is_symlink() {
                links.push(entry.path());
            } else if kind.is_dir() {
                if depth + 1 > INNER_WALK_DEPTH {
                    return (links, true);
                }
                todo.push((entry.path(), depth + 1));
            }
        }
    }
    (links, false)
}

/// The places the jail hides of each dotdir it never shows
/// ([`crate::contain::never_shown_home_paths`]): the dotdir, and each link
/// inside one of the home's own dotdirs ([`links_inside`]) that leads out
/// of it ([`crate::contain::HiddenPlace::inner`]). What is said of a dotdir
/// the launcher looked in only so far is added to `left`.
fn never_shown_places(
    home: &Path,
    facts: &crate::contain::PlaceFacts,
    left: &mut Vec<String>,
) -> Vec<crate::contain::HiddenPlace> {
    let never_shown = crate::contain::never_shown_home_paths(home, facts.macos);
    let mut places: Vec<crate::contain::HiddenPlace> = never_shown
        .iter()
        .map(|path| hidden_place(path, &facts.writable, true))
        .collect();
    for (dotdir, place) in never_shown.iter().zip(places.clone()) {
        if dotdir.parent() != Some(home) {
            continue;
        }
        let (links, cut) = links_inside(dotdir);
        if cut {
            left.push(crate::contain::left_unwalked(dotdir));
        }
        let within = [Some(dotdir.clone()), place.leads_to];
        for link in links {
            let mut found = hidden_place(&link, &facts.writable, true);
            let stays = found
                .leads_to
                .as_ref()
                .is_some_and(|to| within.iter().flatten().any(|folder| to.starts_with(folder)));
            if !stays {
                found.inner = true;
                places.push(found);
            }
        }
    }
    places
}

/// Where the agent's command is on the host: as given where it names a
/// path, else the first file of that name in a folder of `PATH`, as the
/// jail's shell finds it.
fn command_path(command: &str) -> Option<PathBuf> {
    if command.contains('/') {
        let path = Path::new(command);
        return Some(if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir().ok()?.join(path)
        });
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|folder| folder.join(command))
        .find(|candidate| candidate.is_file())
}

/// Whether `path`, in a home folder the jail binds ([`crate::contain::writable_home_dirs`]),
/// goes through a link below that folder on the host. bwrap binds the
/// folder where it leads, at its own name, so a link there is fine; one
/// below it is the host's link in the jail, and a mount through it lands
/// in bwrap's own root, where it leads nowhere: bwrap aborts ("Can't
/// mount tmpfs", "Can't mkdir parents"). Such a path is hidden where it
/// leads, never as named.
fn goes_through_a_link(home: &Path, path: &Path) -> bool {
    let Ok(rest) = path.strip_prefix(home) else {
        return false;
    };
    let mut parts = rest.components();
    let Some(first) = parts.next() else {
        return false;
    };
    let bound = crate::contain::writable_home_dirs()
        .iter()
        .any(|dir| first.as_os_str() == *dir);
    if !bound {
        return false;
    }
    let Ok(mut at) = std::fs::canonicalize(home.join(first)) else {
        return false;
    };
    for part in parts {
        at.push(part);
        match std::fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_symlink() => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    false
}

/// The most links followed on the way to one place, as the kernel's own
/// limit (`ELOOP` past 40).
const MAX_LINKS: usize = 40;

/// Where the absolute `path` leads on the host: every link on the way
/// followed, each step read with `symlink_metadata` and `read_link`, and,
/// below a step that is not there (or cannot be read), the rest as
/// written, since nothing below it can be a link (`realpath -m`); a `..`
/// that takes the way back above such a step is taken, and each step after
/// it is read again. That is the place a file made through it would land,
/// also where a link leads to nothing yet. `None` where the links loop, or
/// for a relative path.
pub(crate) fn leads_to(path: &Path) -> Option<PathBuf> {
    trace(path).map(|(at, _)| at)
}

/// [`leads_to`], with each link followed on the way, as found on the host
/// (the folder it sits in with every link before it followed).
pub(crate) fn trace(path: &Path) -> Option<(PathBuf, Vec<PathBuf>)> {
    match trace_links(path) {
        (Some(at), links) => Some((at, links)),
        (None, _) => None,
    }
}

/// [`trace`], with the links it followed also where it gives no place
/// (they loop, or one cannot be read): a link a program in the jail can
/// change is one on a way that loops too.
fn trace_links(path: &Path) -> (Option<PathBuf>, Vec<PathBuf>) {
    let walked = walk(path);
    (walked.at, walked.links)
}

/// What [`walk`] found on the way to a place.
struct Walked {
    /// Where the way leads ([`leads_to`]), `None` where its links loop or
    /// one cannot be read, or for a relative path.
    at: Option<PathBuf>,
    /// Each link followed on the way, where it sits.
    links: Vec<PathBuf>,
    /// The first step on the way that was not there (or could not be
    /// read), as found. The kernel stops there, also where a later `..`
    /// would take the way back to folders that are there.
    missing: Option<PathBuf>,
}

/// The walk of [`trace_links`]: one `lstat` per step, every step, a link
/// followed with `read_link`. Each step after one that is not there is
/// read too: below that step none is there, and a `..` that takes the way
/// back above it reaches folders that are, where a link is a link again
/// (`<project>/gone/../L` goes through the link `L`).
fn walk(path: &Path) -> Walked {
    use std::path::Component;
    let mut walked = Walked {
        at: None,
        links: Vec::new(),
        missing: None,
    };
    if !path.is_absolute() {
        return walked;
    }
    // The steps still to take, the next one last.
    let mut todo: Vec<std::ffi::OsString> = Vec::new();
    let push_steps = |todo: &mut Vec<std::ffi::OsString>, of: &Path| {
        for part in of.components().rev() {
            match part {
                Component::Normal(name) => todo.push(name.to_os_string()),
                Component::ParentDir => todo.push("..".into()),
                Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            }
        }
    };
    push_steps(&mut todo, path);
    let mut at = PathBuf::from("/");
    while let Some(step) = todo.pop() {
        if step == ".." {
            at.pop();
            continue;
        }
        at.push(&step);
        match std::fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_symlink() => {
                if walked.links.len() >= MAX_LINKS {
                    return walked;
                }
                walked.links.push(at.clone());
                let Ok(target) = std::fs::read_link(&at) else {
                    return walked;
                };
                at.pop();
                if target.is_absolute() {
                    at = PathBuf::from("/");
                }
                push_steps(&mut todo, &target);
            }
            Ok(_) => {}
            Err(_) => {
                if walked.missing.is_none() {
                    walked.missing = Some(at.clone());
                }
            }
        }
    }
    walked.at = Some(at);
    walked
}

/// Make `place`, which is not there, as an empty folder, mode 0700, and
/// each folder missing on the way to it the same, as a folder of the
/// person's (as `ssh` or `gpg` would make it): from the nearest folder on
/// the way that is there, never through a link or a file. Whether it is a
/// folder now.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn make_place(place: &Path) -> bool {
    use std::os::unix::fs::DirBuilderExt;
    let mut missing: Vec<&std::ffi::OsStr> = Vec::new();
    let mut at = place;
    while std::fs::symlink_metadata(at).is_err() {
        let (Some(name), Some(parent)) = (at.file_name(), at.parent()) else {
            return false;
        };
        missing.push(name);
        at = parent;
    }
    if !std::fs::symlink_metadata(at).is_ok_and(|meta| meta.is_dir()) {
        return false;
    }
    let mut at = at.to_path_buf();
    for name in missing.into_iter().rev() {
        at.push(name);
        match std::fs::DirBuilder::new().mode(0o700).create(&at) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return false,
        }
        if !std::fs::symlink_metadata(&at).is_ok_and(|meta| meta.is_dir()) {
            return false;
        }
    }
    true
}

/// The real run of a Linux jail, after every check: each place the jail
/// hides that a link leads somewhere not there yet is made, empty and 0700
/// ([`make_place`]), so the jail's mount lands on a folder of the person's;
/// one that cannot be made cannot hold anything either, and its masks are
/// dropped, so the jail never fails to start over it. Then each folder the
/// jail pins ([`crate::contain::linux_pins`]) that is not there yet is made
/// the same way, where it leads on the host: bwrap would make it anyway, as
/// the way to the mount below it, but after the pins, and so unpinned. One
/// that cannot be made stops bwrap at its pin.
#[cfg(target_os = "linux")]
fn with_linked_places_made(input: &JailInputs) -> JailInputs {
    let mut input = input.clone();
    for (place, views) in std::mem::take(&mut input.linked_missing) {
        if make_place(&place) {
            continue;
        }
        input.linked_masks.retain(|mask| !views.contains(&mask.abs));
        input.iw_config_shown.retain(|view| !views.contains(view));
    }
    for (_, folder) in crate::contain::linux_pins(&input) {
        if std::fs::symlink_metadata(&folder).is_err() {
            make_place(&resolved_through_existing(&folder));
        }
    }
    input
}

/// The most bytes read of a git file the jail's programs can write (a
/// `.git` file, `commondir`, `gitdir`): each holds one path.
const GIT_FILE_MAX: u64 = 4096;

/// The most bytes read of a git folder's `config`.
const GIT_CONFIG_MAX: u64 = 64 * 1024;

/// The text of the small file at `path`, read as the launcher reads any
/// file a program in the jail can write: opened with no link followed and
/// without waiting (`O_NOFOLLOW | O_NONBLOCK`, so a FIFO put there never
/// holds the launcher), only a regular file, at most `max` bytes. `None`
/// for anything else.
fn read_small_file(path: &Path, max: u64) -> Option<String> {
    use std::io::Read;
    let file = innerwarden_safe_io::open_no_follow(path).ok()?;
    let meta = file.metadata().ok()?;
    if !innerwarden_safe_io::is_regular_file(&meta) || meta.len() > max {
        return None;
    }
    let mut text = String::new();
    file.take(max).read_to_string(&mut text).ok()?;
    Some(text)
}

/// The first line of a git file that names a path, `prefix` taken off
/// (`gitdir:` in a `.git` file), trimmed.
fn git_file_path(text: &str, prefix: &str) -> Option<PathBuf> {
    let line = text.lines().next()?;
    let named = line.strip_prefix(prefix)?.trim();
    (!named.is_empty()).then(|| PathBuf::from(named))
}

/// Where `path` (absolute) is, found with the walk the launcher takes for a
/// profile's extra paths ([`walk`]: one `lstat` per step), taken only where
/// no step on the way is a link and every step is there: git writes the
/// paths of its own folders as they really are, and a link on the way is
/// one a program in a jail may have put there. A `..` step is taken where
/// it stands, which, with no link before it and every step before it
/// there, is where the kernel takes it; after a step that is not there the
/// kernel takes none (`<project>/gone/../L` is no place to git, whatever
/// `L` is), so neither does the launcher.
fn place_without_links(path: &Path) -> Result<PathBuf, crate::contain::WorktreeLeft> {
    use crate::contain::WorktreeLeft;
    let Walked { at, links, missing } = walk(path);
    if let Some(link) = links.first() {
        return Err(WorktreeLeft::Link(link.clone()));
    }
    if let Some(missing) = missing {
        return Err(WorktreeLeft::NotThere(missing));
    }
    // macOS: as the disk spells its names (`~/Code` named `~/code` on a
    // disk that tells no case apart), as the sandbox matches it and as the
    // project is found; with no link on the way nothing else changes.
    #[cfg(target_os = "macos")]
    let at = at.map(|at| std::fs::canonicalize(&at).unwrap_or(at));
    match at {
        Some(at) if std::fs::symlink_metadata(&at).is_ok() => Ok(at),
        Some(at) => Err(WorktreeLeft::NotThere(at)),
        None => Err(WorktreeLeft::NotThere(path.to_path_buf())),
    }
}

/// [`place_without_links`], and a folder there.
fn folder_without_links(path: &Path) -> Result<PathBuf, crate::contain::WorktreeLeft> {
    let at = place_without_links(path)?;
    if std::fs::symlink_metadata(&at).is_ok_and(|meta| meta.is_dir()) {
        Ok(at)
    } else {
        Err(crate::contain::WorktreeLeft::NoFolder(at))
    }
}

/// Whether `dir` is a git folder, as git itself tells one: a `HEAD` file,
/// and an `objects` and a `refs` folder, none of them a link.
fn is_git_dir(dir: &Path) -> bool {
    let meta = |name: &str| std::fs::symlink_metadata(dir.join(name));
    meta("HEAD").is_ok_and(|m| m.is_file())
        && meta("objects").is_ok_and(|m| m.is_dir())
        && meta("refs").is_ok_and(|m| m.is_dir())
}

/// Whether the folder `dir` (no link followed) belongs to the account `uid`.
#[cfg(unix)]
fn owned_by(dir: &Path, uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.uid() == uid)
}

#[cfg(not(unix))]
fn owned_by(_dir: &Path, _uid: u32) -> bool {
    false
}

/// The account this launcher runs as.
fn own_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: geteuid takes no arguments and cannot fail.
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        u32::MAX
    }
}

/// Whether the git `config` of `git_dir` names `project` as its work tree
/// (`core.worktree`, relative to `git_dir`), as a submodule's own git
/// folder does, with no link on the way to it.
fn config_names_work_tree(git_dir: &Path, project: &Path) -> bool {
    let Some(text) = read_small_file(&git_dir.join("config"), GIT_CONFIG_MAX) else {
        return false;
    };
    let mut in_core = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_core = line.trim_start_matches('[').trim_end_matches(']').trim() == "core";
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if in_core && key.trim().eq_ignore_ascii_case("worktree") {
            let named = value.trim().trim_matches('"');
            return folder_without_links(&git_dir.join(named)).is_ok_and(|tree| tree == project);
        }
    }
    false
}

/// A linked git worktree stores its admin data OUTSIDE the project (its `.git` is a
/// FILE `gitdir: <path>`). Expose those dirs so `git` keeps working inside the jail.
///
/// The jail binds both read-write, and a program in the jail writes the
/// project, so it could name any folder there (`gitdir: ~/.kube`,
/// `gitdir: ~/Library/LaunchAgents`, another repository) and have the next
/// jail in the project bind it read-write. So the folders are shown only
/// where they ARE a git worktree of this project ([`detect_worktree_as`]).
/// Anything else: no worktree, and the line that says so; the jail starts.
fn detect_worktree(project: &Path, home: &Path) -> (Option<Worktree>, Option<String>) {
    detect_worktree_as(project, home, own_uid())
}

/// [`detect_worktree`], for the account `uid`. A worktree's folders are
/// taken only as git lays them out: the git folder is
/// `<repository>/worktrees/<name>` of the repository its `commondir` names,
/// and its `gitdir` file names exactly this project's `.git` file back; or,
/// a submodule's, the git folder's `config` names exactly this project as
/// its work tree. Every path is found with no link on the way
/// ([`place_without_links`]), the repository is a git folder
/// ([`is_git_dir`]), both folders belong to `uid`, and neither is a place
/// no jail shows read-write ([`crate::contain::worktree_place_left`]: the
/// home, a folder above it, a place a jail hides, a hidden folder of the
/// home). Each file is read as one a program in the jail can write
/// ([`read_small_file`]: no link, no FIFO, a few bytes), and a relative
/// path in it is taken as git takes it (a `.git` file's from the project,
/// the others' from the git folder). A git folder that is no worktree but
/// that every jail shows writable anyway (in the project, or in a home
/// folder such as `~/.local`, [`crate::contain::worktree_shown_anyway`]) is
/// not said: the jail binds nothing for it either way, and git in the jail
/// sees what the jail shows there (a repository made with
/// `--separate-git-dir` into `~/.local/share` works).
fn detect_worktree_as(project: &Path, home: &Path, uid: u32) -> (Option<Worktree>, Option<String>) {
    let dotgit = project.join(".git");
    if !std::fs::symlink_metadata(&dotgit).is_ok_and(|meta| meta.is_file()) {
        return (None, None); // a normal repo: .git is a dir, already inside the project bind
    }
    let Some(named) =
        read_small_file(&dotgit, GIT_FILE_MAX).and_then(|text| git_file_path(&text, "gitdir:"))
    else {
        return (None, None);
    };
    let mut homes = vec![home.to_path_buf()];
    if let Ok(real) = std::fs::canonicalize(home) {
        if real != home {
            homes.push(real);
        }
    }
    let said = |why| {
        (
            None,
            Some(crate::contain::worktree_left_out(&dotgit, &named, &why)),
        )
    };
    let git_dir = match folder_without_links(&project.join(&named)) {
        Ok(git_dir) => git_dir,
        Err(why) => return said(why),
    };
    match worktree_of(project, &dotgit, git_dir.clone(), &homes, uid) {
        Ok(worktree) => (Some(worktree), None),
        Err(_) if crate::contain::worktree_shown_anyway(home, project, &git_dir) => (None, None),
        Err(why) => said(why),
    }
}

/// The worktree whose git folder is `git_dir` (where the `.git` file
/// `dotgit` leads, with no link on the way), or why it is none
/// ([`detect_worktree_as`]).
fn worktree_of(
    project: &Path,
    dotgit: &Path,
    git_dir: PathBuf,
    homes: &[PathBuf],
    uid: u32,
) -> Result<Worktree, crate::contain::WorktreeLeft> {
    use crate::contain::WorktreeLeft;
    let read_path = |name: &str| {
        read_small_file(&git_dir.join(name), GIT_FILE_MAX).and_then(|text| git_file_path(&text, ""))
    };
    let common_dir = match read_path("commondir") {
        // A submodule's own git folder: no `commondir`, its work tree named
        // in its config.
        None => {
            if !config_names_work_tree(&git_dir, project) {
                return Err(WorktreeLeft::NoBackLink);
            }
            git_dir.clone()
        }
        // A linked worktree: git's own link back to this `.git` file, and
        // the git folder in the repository's `worktrees`.
        Some(common) => {
            let back = read_path("gitdir").ok_or(WorktreeLeft::NoBackLink)?;
            let back = place_without_links(&git_dir.join(back))?;
            if back != dotgit {
                return Err(WorktreeLeft::OtherProject(back));
            }
            let common_dir = folder_without_links(&git_dir.join(common))?;
            if git_dir.parent() != Some(common_dir.join("worktrees").as_path()) {
                return Err(WorktreeLeft::NotInWorktrees(common_dir));
            }
            common_dir
        }
    };
    if !is_git_dir(&common_dir) {
        return Err(WorktreeLeft::NotGitDir(common_dir));
    }
    for folder in [&git_dir, &common_dir] {
        if !owned_by(folder, uid) {
            return Err(WorktreeLeft::NotYours(folder.clone()));
        }
        if crate::contain::worktree_place_left(homes, folder) {
            return Err(WorktreeLeft::Place(folder.clone()));
        }
    }
    Ok(Worktree {
        git_dir,
        common_dir,
    })
}

/// The jail backend `innerwarden contain` would use on this machine, by name,
/// or `None` when there is none it trusts. The same lookup `contain` runs, so
/// the dashboard never says "Ready" for a jail that would refuse to start.
pub(crate) fn jail_backend() -> Option<&'static str> {
    if cfg!(target_os = "linux") {
        resolve_backend(BWRAP_PATHS).map(|_| "bwrap")
    } else if cfg!(target_os = "macos") {
        resolve_backend(&["/usr/bin/sandbox-exec"]).map(|_| "sandbox-exec")
    } else {
        None
    }
}

/// Whether a jail starts on this machine, by the checks `contain` runs
/// before it builds one: `None` without a backend it trusts (as
/// [`jail_backend`]); otherwise `Ok`, or the lines `contain` says and stops
/// on (on Linux, a kernel that restricts unprivileged user namespaces and
/// a bwrap with no profile that grants it one). On macOS, finding
/// `sandbox-exec` is not a check: it starts one sandboxed `true`
/// ([`sandbox_exec_starts`]), so "ready" is said only for a sandbox that
/// started here (one already inside a sandbox cannot start another).
pub(crate) fn jail_start_here() -> Option<Result<(), Vec<String>>> {
    if cfg!(target_os = "linux") {
        let bwrap = resolve_backend(BWRAP_PATHS)?;
        Some(restriction_advice(&bwrap, true).map_or(Ok(()), Err))
    } else if cfg!(target_os = "macos") {
        let sandbox = resolve_backend(&["/usr/bin/sandbox-exec"])?;
        Some(sandbox_start_answer(sandbox_exec_starts(&sandbox)))
    } else {
        jail_backend().map(|_| Ok(()))
    }
}

/// The profile of the test start: it allows everything, so what it measures
/// is that `sandbox-exec` can put a process in a sandbox here at all.
const SANDBOX_TEST_PROFILE: &str = "(version 1)(allow default)";

/// Run `/usr/bin/true` under `sandbox-exec` once: `Some((exited 0, the
/// first line it said on stderr))`, or `None` when it could not be started
/// or did not end within 5 s (killed).
fn sandbox_exec_starts(sandbox: &Path) -> Option<(bool, String)> {
    let mut command = Command::new(sandbox);
    command
        .args(["-p", SANDBOX_TEST_PROFILE, "/usr/bin/true"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    // As every program a launch starts: root's two folders as PATH and no
    // loader variable, so the account's environment cannot pick what
    // answers "a sandbox started".
    helper_env(&mut command);
    let mut child = command.spawn().ok()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut said = String::new();
                if let Some(mut stderr) = child.stderr.take() {
                    let _ = std::io::Read::read_to_string(&mut stderr, &mut said);
                }
                let first = said.lines().next().unwrap_or("").trim().to_string();
                return Some((status.success(), first));
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// What the test start of `sandbox-exec` says: ready only when it ran and
/// exited 0; otherwise the line a person reads, with what it said. Pure.
fn sandbox_start_answer(outcome: Option<(bool, String)>) -> Result<(), Vec<String>> {
    match outcome {
        Some((true, _)) => Ok(()),
        Some((false, said)) if !said.is_empty() => Err(vec![format!(
            "sandbox-exec could not start a sandboxed process here: {said}"
        )]),
        Some((false, _)) => Err(vec![
            "sandbox-exec could not start a sandboxed process here.".to_string(),
        ]),
        None => Err(vec![
            "sandbox-exec did not start a sandboxed process within 5 seconds here.".to_string(),
        ]),
    }
}

/// Resolve a sandbox backend from a compile-time list of trusted absolute paths.
/// Release builds have no environment/PATH override. On Unix the executable and
/// every path component must be root-owned, not group/world-writable, and not a
/// symlink; validation fails closed when any metadata cannot be inspected.
fn resolve_backend(trusted: &[&str]) -> Option<PathBuf> {
    trusted.iter().find_map(|candidate| {
        let path = Path::new(candidate);
        trusted_backend_candidate(path).then(|| std::fs::canonicalize(path).ok())?
    })
}

#[cfg(unix)]
fn trusted_backend_candidate(path: &Path) -> bool {
    backend_facts(path).is_some_and(|facts| backend_trusted(&facts))
}

#[cfg(not(unix))]
fn trusted_backend_candidate(_path: &Path) -> bool {
    false
}

/// One entry on a sandbox backend's path, as `symlink_metadata` reads it: a
/// symlink is described, never followed.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathEntry {
    symlink: bool,
    file: bool,
    dir: bool,
    uid: u32,
    /// `st_mode`, so the permission bits are its low twelve.
    mode: u32,
}

/// What [`backend_trusted`] decides from, read by [`backend_facts`].
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BackendFacts {
    /// Each component of the path as the trusted list spells it, from `/`
    /// down, ending at the first symlink if there is one.
    components: Vec<PathEntry>,
    /// The resolved executable, then each directory above it, up to `/`.
    /// Empty when a component is a symlink: it is refused without being
    /// followed.
    chain: Vec<PathEntry>,
}

/// Read the facts about `path`. `None`, which refuses the backend, when the
/// path is relative or any entry on it cannot be inspected.
#[cfg(unix)]
pub(crate) fn backend_facts(path: &Path) -> Option<BackendFacts> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let entry = |at: &Path| {
        std::fs::symlink_metadata(at)
            .ok()
            .map(|metadata| PathEntry {
                symlink: metadata.file_type().is_symlink(),
                file: metadata.is_file(),
                dir: metadata.is_dir(),
                uid: metadata.uid(),
                mode: metadata.permissions().mode(),
            })
    };
    if !path.is_absolute() {
        return None;
    }
    let mut components = Vec::new();
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        let read = entry(&prefix)?;
        components.push(read);
        if read.symlink {
            return Some(BackendFacts {
                components,
                chain: Vec::new(),
            });
        }
    }
    let canonical = std::fs::canonicalize(path).ok()?;
    let chain = canonical
        .ancestors()
        .map(entry)
        .collect::<Option<Vec<_>>>()?;
    Some(BackendFacts { components, chain })
}

/// Whether `contain` may run the backend these facts describe. PURE.
///
/// No component of the path as written may be a symlink (the usr-merged
/// `/bin` candidate is skipped on purpose, and the canonical `/usr/bin` one
/// from the same list is accepted instead). The resolved executable must be
/// a regular file with an execute bit, and it and every directory above it
/// must be owned by root and writable by no group and no other account:
/// whoever can write any of them can replace the jail.
#[cfg(unix)]
fn backend_trusted(facts: &BackendFacts) -> bool {
    sound_root_file(facts, &|uid| uid == 0).is_some_and(|executable| executable.mode & 0o111 != 0)
}

/// Whether a file of root's these facts describe may be believed: the rules of
/// [`backend_trusted`] for every entry on its path, with `root` saying which
/// owner is root where the reader runs, and no execute bit asked for. PURE.
#[cfg(unix)]
pub(crate) fn root_file_trusted(facts: &BackendFacts, root: &dyn Fn(u32) -> bool) -> bool {
    sound_root_file(facts, root).is_some()
}

/// The file the facts end at, when no entry on its path is a symlink, it is a
/// regular file, and it and every directory above it are root's (`root`) and
/// writable by no group and no other account.
#[cfg(unix)]
fn sound_root_file<'a>(
    facts: &'a BackendFacts,
    root: &dyn Fn(u32) -> bool,
) -> Option<&'a PathEntry> {
    let sound = |entry: &PathEntry| !entry.symlink && root(entry.uid) && entry.mode & 0o022 == 0;
    let (file, directories) = facts.chain.split_first()?;
    (!facts.components.is_empty()
        && facts.components.iter().all(|entry| !entry.symlink)
        && sound(file)
        && file.file
        && directories.iter().all(|entry| sound(entry) && entry.dir))
    .then_some(file)
}

/// `marks`: the launcher proved the way to the system profiles file root's
/// and the file is there, so a jail with no record gets the marker.
fn run_linux(input: &JailInputs, marks: bool) -> ExitCode {
    use crate::contain::launch::{dry_run_filter, DryRunFilter};
    use innerwarden_agent_guard::seccomp::Rules;
    // A dry run with `--identity` shows the arguments the real run adds.
    let dry_identity;
    let dry_plain;
    // What a real run would do about the jail's filter, asked of the bwrap it
    // would use: first whether the host's restriction stops the real run
    // before any jail (then that is what is said, and nothing is probed),
    // then the probe. A host with no bwrap says nothing here: the real run
    // says it has none.
    let dry_bwrap = input
        .args
        .dry_run
        .then(|| resolve_backend(BWRAP_PATHS))
        .flatten();
    let dry_filter = dry_bwrap.as_ref().map(|bwrap| {
        dry_run_filter(restriction_advice(bwrap, false), || {
            filter_plan_for_channel(bwrap, input.args.identity)
        })
    });
    let dry_rules = dry_filter.as_ref().and_then(DryRunFilter::filter);
    let dry_seccomp = dry_rules.map(|_| crate::contain::launch::DRY_RUN_SECCOMP_FD);
    let planned = if input.args.identity && input.args.dry_run {
        dry_identity = JailInputs {
            info_fd: Some(crate::contain::launch::DRY_RUN_INFO_FD),
            record_fd: Some(crate::contain::launch::DRY_RUN_RECORD_FD),
            // The key is handed in only when the host has one this launcher
            // believes, as the real run does.
            key_fd: host_key()
                .is_some()
                .then_some(crate::contain::launch::DRY_RUN_KEY_FD),
            close_userns: dry_rules == Some(Rules::Identified),
            seccomp_fd: dry_seccomp,
            record_channel: (dry_rules == Some(Rules::Identified))
                .then(|| PathBuf::from(crate::contain::launch::DRY_RUN_RECORD_CHANNEL)),
            ..input.clone()
        };
        &dry_identity
    } else if input.args.dry_run {
        // A plain jail shows the marker the real run hands in, and the
        // identified filter where the host takes it (the terminal one where
        // it takes only that); the record channel only with the first.
        dry_plain = JailInputs {
            profiles_marker_fd: marks.then_some(crate::contain::launch::DRY_RUN_MARKER_FD),
            close_userns: dry_rules == Some(Rules::Identified),
            seccomp_fd: dry_seccomp,
            record_channel: (dry_rules == Some(Rules::Identified))
                .then(|| PathBuf::from(crate::contain::launch::DRY_RUN_RECORD_CHANNEL)),
            ..input.clone()
        };
        &dry_plain
    } else {
        input
    };
    let plan = match build_linux_jail(planned) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("innerwarden contain: {e}");
            return ExitCode::from(2);
        }
    };
    if input.args.dry_run {
        println!("# innerwarden contain - DRY RUN (Linux / bubblewrap)");
        print_plan_env(&plan.env);
        print_credentials_kept_out(input);
        #[cfg(target_os = "linux")]
        if input.args.identity {
            println!("# {}", dry_run_scope_line());
        }
        for line in dry_filter
            .iter()
            .flat_map(|filter| filter.lines(input.args.identity))
        {
            println!("{line}");
        }
        // The real run binds these from descriptors it opens just before
        // bwrap starts; the dry run names each by its host folder.
        if bwrap_binds_fds() && !crate::contain::places_bound_from_descriptors(planned).is_empty() {
            println!("# {}", crate::contain::FROM_DESCRIPTORS_SAID);
        }
        println!("bwrap \\");
        println!("  {}", plan.bwrap_args.join(" "));
        return ExitCode::SUCCESS;
    }
    let Some(bwrap) = resolve_backend(BWRAP_PATHS) else {
        eprintln!(
            "innerwarden contain: bubblewrap (bwrap) not found. Install it:\n  Debian/Ubuntu: apt install bubblewrap\n  Fedora: dnf install bubblewrap\n  Arch: pacman -S bubblewrap"
        );
        return ExitCode::from(1);
    };
    // Say why the jail cannot be built BEFORE bwrap dies with an error that
    // names neither the cause nor the fix.
    if let Some(lines) = restriction_advice(&bwrap, true) {
        for line in lines {
            eprintln!("{line}");
        }
        return ExitCode::from(1);
    }
    // The places a link leads a hidden one to that are not there yet,
    // made as folders of the person's before the jail mounts on them.
    #[cfg(target_os = "linux")]
    let made = with_linked_places_made(input);
    #[cfg(target_os = "linux")]
    let input = &made;
    // The jail's own `~/.claude` ([`crate::contain::ProjectClaude`]),
    // with the read-only copies of the person's settings: no jail starts
    // without it.
    #[cfg(target_os = "linux")]
    let prepared = match prepare_project_claude(input) {
        Ok(prepared) => prepared,
        Err(why) => {
            eprintln!("innerwarden contain: refusing to start: {why}");
            return ExitCode::from(2);
        }
    };
    #[cfg(target_os = "linux")]
    let input = &prepared;
    #[cfg(target_os = "linux")]
    if input.args.identity {
        return run_linux_identified(input, &bwrap, marks);
    }
    announce(input);
    run_unrecorded(&bwrap, input, marks)
}

/// Linux: the launcher's records folder `dir` as the launcher keeps it,
/// whether anything was made or moved. A folder at that name that is not
/// this account's own, or that others may write, is moved aside whole and
/// made again; one that is not there is made, `0700`. In it, every entry
/// that is not one the launcher writes ([`record_entry_kept`]) is moved to
/// a folder beside it (`instances.set-aside-<seconds>-<pid>`), which the
/// host's readers never read, and said.
#[cfg(target_os = "linux")]
fn vet_records_dir(dir: &Path, uid: u32) -> std::io::Result<bool> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    // Seconds, nanoseconds and the launcher's pid: two set-asides in one
    // second never meet at one name.
    let stamp = || {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        format!(
            "{}-{:09}-{}",
            now.as_secs(),
            now.subsec_nanos(),
            std::process::id()
        )
    };
    let mut changed = false;
    match std::fs::symlink_metadata(dir) {
        Ok(found) if !(found.is_dir() && found.uid() == uid && found.mode() & 0o022 == 0) => {
            let aside = dir.with_file_name(format!(
                "{}.set-aside-{}",
                dir.file_name().unwrap_or_default().to_string_lossy(),
                stamp()
            ));
            std::fs::rename(dir, &aside)?;
            eprintln!(
                "innerwarden contain: {} was not a folder of this account that only it can \
                 write; moved aside to {} and made again.",
                crate::contain::printable(dir),
                crate::contain::printable(&aside)
            );
            changed = true;
        }
        Ok(_) => {}
        Err(_) => changed = true,
    }
    own_records_dir(dir, uid)?;
    let mut aside: Option<PathBuf> = None;
    let mut moved = 0usize;
    for entry in std::fs::read_dir(dir)?.flatten().take(MAX_VETTED_ENTRIES) {
        let path = entry.path();
        if record_entry_kept(dir, &path, uid) {
            continue;
        }
        let to = match &aside {
            Some(to) => to.clone(),
            None => {
                let to = dir.with_file_name(format!(
                    "{}.set-aside-{}",
                    dir.file_name().unwrap_or_default().to_string_lossy(),
                    stamp()
                ));
                std::fs::DirBuilder::new().mode(0o700).create(&to)?;
                aside = Some(to.clone());
                to
            }
        };
        std::fs::rename(&path, to.join(entry.file_name()))?;
        moved += 1;
    }
    if let (true, Some(to)) = (moved > 0, &aside) {
        eprintln!(
            "innerwarden contain: {moved} entr{} in {} the launcher does not write moved aside to {}.",
            if moved == 1 { "y" } else { "ies" },
            crate::contain::printable(dir),
            crate::contain::printable(to)
        );
        changed = true;
    }
    Ok(changed)
}

/// The most entries of the records folder looked at in one launch.
#[cfg(target_os = "linux")]
const MAX_VETTED_ENTRIES: usize = 4096;

/// Linux: whether `path`, in the launcher's records folder `dir`, is an
/// entry the launcher writes: a regular file of `uid`'s with one name
/// that no one else may write, no larger than a record, named
/// `<id>.json` and holding the record of that id and account, `<id>.project`
/// beside such a record and holding a path of its project, or a temporary
/// file a launcher writing now has not renamed yet (`.<id>.tmp`,
/// `.<id>.project.tmp`), which no reader takes.
#[cfg(target_os = "linux")]
fn record_entry_kept(dir: &Path, path: &Path, uid: u32) -> bool {
    use innerwarden_agent_guard::identity::{is_instance_id, parse_launch_record};
    use std::os::unix::fs::MetadataExt;
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let sound = |at: &Path| {
        std::fs::symlink_metadata(at).is_ok_and(|m| {
            m.is_file()
                && m.uid() == uid
                && m.nlink() == 1
                && m.mode() & 0o022 == 0
                && m.len() <= MAX_RECORD_ENTRY_BYTES
        })
    };
    if !sound(path) {
        return false;
    }
    let record = |id: &str| {
        let bytes = std::fs::read(dir.join(format!("{id}.json"))).ok()?;
        parse_launch_record(&bytes)
            .ok()
            .filter(|record| record.uid == uid && record.instance_id == id)
    };
    if let Some(id) = name.strip_suffix(".json") {
        return is_instance_id(id) && record(id).is_some();
    }
    if let Some(id) = name.strip_suffix(".project") {
        return is_instance_id(id)
            && sound(&dir.join(format!("{id}.json")))
            && record(id).is_some_and(|record| {
                std::fs::read(path).ok().is_some_and(|bytes| {
                    crate::contain::launch::parse_project_path(&bytes, &record.project).is_some()
                })
            });
    }
    let temp = name
        .strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .map(|rest| rest.strip_suffix(".project").unwrap_or(rest));
    temp.is_some_and(is_instance_id)
}

/// The largest entry of the records folder taken as one the launcher
/// writes.
#[cfg(target_os = "linux")]
const MAX_RECORD_ENTRY_BYTES: u64 = 64 * 1024;

/// Linux, before a plain jail runs: this project's `.claude.json` kept by
/// the last run ([`crate::contain::ProjectClaude`]) cut to what Claude
/// Code's own state and preferences are
/// ([`crate::contain::kept_claude_settings`]): MCP servers, allowed
/// tools, the trust of a folder and the rest the jail wrote are never
/// carried into the next run. A file that is not a plain file of this
/// account's with one name, is larger than [`MAX_CLAUDE_SETTINGS_BYTES`],
/// or is not JSON is removed, and said. Best effort: a write that fails is
/// said, and the file is removed.
#[cfg(unix)]
fn trim_project_claude(claude: &crate::contain::ProjectClaude, uid: u32) {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let file = claude.source.join(crate::contain::CLAUDE_SETTINGS);
    let Ok(meta) = std::fs::symlink_metadata(&file) else {
        return;
    };
    let read = (meta.is_file()
        && meta.uid() == uid
        && meta.nlink() == 1
        && meta.len() <= MAX_CLAUDE_SETTINGS_BYTES)
        .then(|| {
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            innerwarden_safe_io::harden(&mut options);
            let mut bytes = Vec::new();
            options
                .open(&file)
                .and_then(|f| {
                    f.take(MAX_CLAUDE_SETTINGS_BYTES + 1)
                        .read_to_end(&mut bytes)
                })
                .ok()
                .map(|_| bytes)
        })
        .flatten();
    let left: Option<serde_json::Value> =
        read.and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let gone = |why: &str| {
        let _ = std::fs::remove_file(&file);
        eprintln!(
            "innerwarden contain: Claude Code's settings file kept for this project ({}) {why}; \
             removed, and the jail starts with none.",
            crate::contain::printable(&file)
        );
    };
    let Some(left) = left else {
        gone("is not a plain JSON file of this account");
        return;
    };
    let kept = crate::contain::kept_claude_settings(&left);
    if kept == left {
        return;
    }
    let temp = launch_temp_name(&file);
    let bytes = serde_json::to_vec(&kept).unwrap_or_else(|_| b"{}".to_vec());
    if let Err(e) = write_private_file(&claude.source, &file, &temp, &bytes, uid) {
        gone(&format!(
            "could not be cut to Claude Code's own state ({e})"
        ));
    }
}

/// The largest `.claude.json` a plain jail's next run starts from.
#[cfg(unix)]
const MAX_CLAUDE_SETTINGS_BYTES: u64 = 16 * 1024 * 1024;

/// The real run, once the jail was planned with every check passed: the
/// jail's own `~/.claude` for this project
/// ([`crate::contain::ProjectClaude`]) made (0700, this account's) where it
/// is not there, and readied, or why no jail starts:
///
/// - what a program in an earlier jail put at a name the launcher writes or
///   shows there as a link is removed;
/// - its `.claude.json` cut to Claude Code's own state ([`trim_project_claude`]);
/// - the person's Claude Code settings read again (the hook was armed since
///   the check, [`claude_settings_value`]) and copied there, `{}` where
///   the person has none: the jail lays each read-only (Linux) or the
///   sandbox denies writing it (macOS);
/// - Linux: the person's Claude Code login (`.credentials.json`) copied
///   there, so the jail's Claude Code is logged in and what it refreshes
///   stays the jail's; and each file a hook in the settings runs from
///   `~/.claude` found ([`crate::contain::claude_hook_files`]);
/// - macOS: a link there to each of
///   [`crate::contain::CLAUDE_READ_ONLY_SHARED`] the person has.
#[cfg(unix)]
fn prepare_project_claude(input: &JailInputs) -> Result<JailInputs, String> {
    use crate::contain::{printable, CLAUDE_GUARD_SETTINGS, CLAUDE_READ_ONLY_SHARED};
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let mut out = input.clone();
    let claude = match &input.project_claude {
        Some(claude) => claude.clone(),
        None => {
            let nominal = crate::contain::launch::records_dir(
                std::env::var("XDG_STATE_HOME").ok().as_deref(),
                &input.home,
            );
            let real = std::fs::canonicalize(&nominal).unwrap_or_else(|_| nominal.clone());
            let records = if input.records_dirs.is_empty() {
                vec![nominal]
            } else {
                input.records_dirs.clone()
            };
            crate::contain::plan_project_claude(&records, &real, &input.args.project).ok_or_else(
                || "there is no folder of the launcher's for Claude Code's own state".to_string(),
            )?
        }
    };
    let source = claude.source.clone();
    own_records_dir(&source, uid).map_err(|e| {
        format!(
            "Claude Code's folder for this project ({}) cannot be used ({e})",
            printable(&source)
        )
    })?;
    let mut names: Vec<&str> = vec![crate::contain::CLAUDE_SETTINGS, ".credentials.json"];
    names.extend(
        CLAUDE_GUARD_SETTINGS
            .iter()
            .filter_map(|name| Path::new(name).file_name().and_then(|n| n.to_str())),
    );
    names.extend(CLAUDE_READ_ONLY_SHARED.iter().copied());
    for name in names {
        let at = source.join(name);
        if std::fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_symlink()) {
            std::fs::remove_file(&at)
                .map_err(|e| format!("{} cannot be removed ({e})", printable(&at)))?;
        }
    }
    trim_project_claude(&claude, uid);
    let mut settings = Vec::new();
    for name in CLAUDE_GUARD_SETTINGS {
        let from = claude_setting(&input.claude_host_dir, name);
        let (bytes, value) = claude_settings_value(&from, false)?
            .unwrap_or_else(|| (b"{}".to_vec(), serde_json::json!({})));
        let to = crate::contain::claude_copy_of(&source, &from);
        let temp = launch_temp_name(&to);
        write_private_file(&source, &to, &temp, &bytes, uid).map_err(|e| {
            format!(
                "the copy of {} for the jail cannot be made ({e})",
                printable(&from)
            )
        })?;
        settings.push(value);
    }
    #[cfg(target_os = "linux")]
    {
        copy_claude_login(&input.claude_host_dir, &source, uid)?;
        out.claude_hook_files =
            crate::contain::claude_hook_files(&settings, &input.home, &input.claude_host_dir);
    }
    // What a jail wrote in its own folder at a name the person's folder
    // does not have (`CLAUDE.md`, `skills`, a hook's script) is no longer
    // laid over from the host, so it would reach the next jail: removed.
    let host = &input.claude_host_dir;
    let hook_names = crate::contain::claude_hook_files(&settings, &input.home, host)
        .into_iter()
        .filter_map(|file| file.strip_prefix(host).ok().map(Path::to_path_buf));
    let shared = CLAUDE_READ_ONLY_SHARED.iter().map(PathBuf::from);
    for name in shared.chain(hook_names) {
        if std::fs::symlink_metadata(host.join(&name)).is_ok() {
            continue;
        }
        let at = source.join(&name);
        let removed = match std::fs::symlink_metadata(&at) {
            Err(_) => Ok(()),
            Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(&at),
            Ok(_) => std::fs::remove_file(&at),
        };
        removed.map_err(|e| format!("{} cannot be removed ({e})", printable(&at)))?;
    }
    keep_absent_names(input, &claude, uid)?;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = settings;
        for name in CLAUDE_READ_ONLY_SHARED {
            let host = input.claude_host_dir.join(name);
            let at = source.join(name);
            if std::fs::symlink_metadata(&host).is_ok() && std::fs::symlink_metadata(&at).is_err() {
                let _ = std::os::unix::fs::symlink(&host, &at);
            }
        }
    }
    out.project_claude = Some(claude);
    Ok(out)
}

/// The temporary name, beside `target`, a launch writes it under before
/// the rename: of this launch alone (its pid and the time), so two launches
/// on one project at once never take or remove each other's (measured: a
/// second identified jail started at the same moment did not start).
#[cfg(unix)]
fn launch_temp_name(target: &Path) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!(
        ".{}.innerwarden.{}.{nanos}.tmp",
        target.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    )
}

/// Linux: the person's Claude Code login (`~/.claude/.credentials.json`),
/// a file of its own of at most 1 MiB, copied into the jail's own
/// `~/.claude` (`source`), `0600`. Nothing where the person has none.
#[cfg(target_os = "linux")]
fn copy_claude_login(claude: &Path, source: &Path, uid: u32) -> Result<(), String> {
    use std::io::Read;
    const MAX_LOGIN_BYTES: u64 = 1024 * 1024;
    let from = claude.join(".credentials.json");
    let Ok(meta) = std::fs::symlink_metadata(&from) else {
        return Ok(());
    };
    if !meta.is_file() || meta.len() > MAX_LOGIN_BYTES {
        return Ok(());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    innerwarden_safe_io::harden(&mut options);
    let mut bytes = Vec::new();
    if options
        .open(&from)
        .and_then(|f| f.take(MAX_LOGIN_BYTES + 1).read_to_end(&mut bytes))
        .is_err()
        || bytes.len() as u64 > MAX_LOGIN_BYTES
    {
        return Ok(());
    }
    let to = source.join(".credentials.json");
    let temp = launch_temp_name(&to);
    write_private_file(source, &to, &temp, &bytes, uid)
        .map(|_| ())
        .map_err(|e| format!("Claude Code's login cannot be copied for the jail ({e})"))
}

/// Linux, the real run of a plain jail, once the jail was planned with
/// every check passed: the launcher's records folder made (0700, this
/// account's) where it is not there, so the jail is planned again and shows
/// it read-only, and never makes one of its own in the `~/.local` it
/// writes. Whether it was made now. One that cannot be made is said, and
/// the jail runs without it, as before.
#[cfg(target_os = "linux")]
fn make_plain_records(input: &JailInputs) -> bool {
    if input.args.identity {
        return false;
    }
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let nominal = crate::contain::launch::records_dir(
        std::env::var("XDG_STATE_HOME").ok().as_deref(),
        &input.home,
    );
    // Made where it is not there; where it is, it and what is in it vetted
    // ([`vet_records_dir`]): a jail before this one could plant what the
    // host reads.
    let mut made = match vet_records_dir(&nominal, uid) {
        Ok(changed) => changed,
        Err(e) => {
            eprintln!(
                "innerwarden contain: the launcher's records folder cannot be used ({e}); \
                 the jail may write there this run"
            );
            return false;
        }
    };
    // This project's folder for Claude Code's settings file, beside it.
    let real = std::fs::canonicalize(&nominal).unwrap_or(nominal.clone());
    if input.project_claude.is_none() {
        if let Some(claude) =
            crate::contain::plan_project_claude(&[nominal], &real, &input.args.project)
        {
            match own_records_dir(&claude.source, uid) {
                Ok(()) => made = true,
                Err(e) => eprintln!(
                    "innerwarden contain: Claude Code's settings file for this project cannot be \
                     kept ({e}); it is gone when the jail ends"
                ),
            }
        }
    }
    made
}

/// Linux: the project's record folder ([`crate::contain::jail_graph_dir`])
/// made where it is not there, and the launcher's record channel opened
/// ([`crate::jail_record::Channel`]): the jail then shows the folder
/// read-only and the hook hands each decision to the launcher, which puts
/// `instance` and the project's name on it.
///
/// An entry at the folder's name that is not a real folder of this account
/// (a link, a file, a folder of another account, left there by an earlier
/// jail, say) is moved aside and the folder made again, and contain says
/// so. Where the folder or the channel still cannot be had, an
/// `--identity` jail is refused (`Err`, said): its record is what the
/// host reads of the instance. A plain jail runs as before (the hook
/// writes the record in the project, where the jail can change it), and
/// the launcher says so.
#[cfg(target_os = "linux")]
fn with_record_channel(
    input: &JailInputs,
    instance: Option<&str>,
) -> Result<(JailInputs, Option<crate::jail_record::Channel>), ExitCode> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let dir = crate::contain::jail_graph_dir(&input.args.project);
    let mut out = input.clone();
    out.record_channel = None;
    let identity = input.args.identity;
    let failed = |why: &str| {
        if identity {
            eprintln!(
                "innerwarden contain: refusing to start: the jail's record ({}) would stay writable inside the jail: {why}",
                crate::contain::printable(&dir)
            );
            Err(ExitCode::from(2))
        } else {
            eprintln!(
                "innerwarden contain: the jail's record ({}) stays writable inside the jail this run: {why}",
                crate::contain::printable(&dir)
            );
            Ok((out.clone(), None))
        }
    };
    // A program in a jail whose user namespaces are open can make one with
    // a mount namespace of its own, mount a folder over the place the hook
    // looks for the launcher's socket, and put its own there: the hook would
    // hand it every decision and hear "ok". The channel holds only where
    // the jail's filter keeps them closed.
    if !input.close_userns {
        return failed(
            "user namespaces stay open in this jail, so a program there could put a socket of its own where the hook hands its decisions",
        );
    }
    let vet = |found: &std::fs::Metadata| {
        crate::contain::launch::vet_jail_graph_dir(
            &crate::contain::launch::GraphEntry {
                symlink: found.file_type().is_symlink(),
                dir: found.is_dir(),
                regular: false,
                uid: found.uid(),
                len: 0,
            },
            own_uid(),
        )
    };
    if let Ok(found) = std::fs::symlink_metadata(&dir) {
        if let Err(why) = vet(&found) {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let aside = dir.with_file_name(format!(
                "{}.set-aside-{secs}-{}",
                crate::contain::JAIL_GRAPH_DIR,
                std::process::id()
            ));
            match std::fs::rename(&dir, &aside) {
                Ok(()) => eprintln!(
                    "innerwarden contain: {} was not a folder of this account ({why}); moved aside to {} and made again.",
                    crate::contain::printable(&dir),
                    crate::contain::printable(&aside)
                ),
                Err(e) => return failed(&format!("{why}, and it could not be moved aside ({e})")),
            }
        }
    }
    let _ = std::fs::DirBuilder::new().mode(0o700).create(&dir);
    let found = match std::fs::symlink_metadata(&dir) {
        Ok(m) => m,
        Err(e) => return failed(&format!("it cannot be made ({e})")),
    };
    if let Err(why) = vet(&found) {
        return failed(why);
    }
    let base = match record_base(input) {
        Ok(base) => base,
        Err(why) => return failed(&why),
    };
    let stamp = crate::jail_record::Stamp {
        instance_id: instance.map(str::to_string),
        project: input
            .args
            .project
            .file_name()
            .map(|name| name.to_string_lossy().into_owned()),
    };
    match crate::jail_record::Channel::open(&base, dir.join(crate::contain::JAIL_GRAPH_NAME), stamp)
    {
        Ok(channel) => {
            // The host's own record hears each refusal too: on a host with
            // InnerWarden Community alone it is the only one read.
            if let Some(host) = crate::graph_io::graph_path() {
                channel.mirror_blocks_to(host);
            }
            out.record_channel = Some(channel.dir().to_path_buf());
            eprintln!(
                "  the jail's record ({}) is read-only inside the jail; the launcher writes each decision the hook hands it.",
                crate::contain::printable(&dir)
            );
            Ok((out, Some(channel)))
        }
        Err(why) => failed(&format!(
            "the launcher's record channel did not open ({why})"
        )),
    }
}

/// Linux: the folder the launcher's record channel is made in. The
/// account's `XDG_RUNTIME_DIR` where it is a folder of this account that
/// no one else may enter (the jail hides `/run` under a folder of its
/// own), else the launcher's temporary folder. Never a folder the jail
/// shows writable (the project, a home folder it binds, `--rw`): from
/// there a program in the jail could remove the socket or put one of its
/// own in its place; such a folder is refused, with what to set instead.
#[cfg(target_os = "linux")]
fn record_base(input: &JailInputs) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt;
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .filter(|dir| {
            std::fs::symlink_metadata(dir)
                .is_ok_and(|m| m.is_dir() && m.uid() == own_uid() && m.mode() & 0o077 == 0)
        });
    let base = runtime.unwrap_or_else(launcher_tmpdir);
    let base = std::fs::canonicalize(&base).unwrap_or(base);
    let real = |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let writable = std::iter::once(&input.args.project)
        .chain(&input.jail_writes)
        .chain(&input.args.extra_rw)
        .map(|path| real(path));
    for place in writable {
        if base.starts_with(&place) {
            return Err(format!(
                "the folder for its socket ({}) is inside {}, which the jail can write; \
                 set XDG_RUNTIME_DIR or TMPDIR to a folder the jail does not show",
                crate::contain::printable(&base),
                crate::contain::printable(&place)
            ));
        }
    }
    Ok(base)
}

/// A jail with no launch record, as it runs: under the jail's seccomp filter
/// where the host takes it, and with the marker that the way to the system
/// profiles file was proven root's when `marks`. A marker that cannot be
/// handed in is none: the jail's hook then reads the file as it did before.
/// A filter that cannot be handed in is none too, said once: the jail then
/// runs as it did before the filter.
fn run_unrecorded(bwrap: &Path, input: &JailInputs, marks: bool) -> ExitCode {
    #[cfg(target_os = "linux")]
    let marker = marks.then(marker_pipe).flatten();
    #[cfg(target_os = "linux")]
    let (filter, userns_closed) = unrecorded_filter(bwrap, input.args.identity);
    #[cfg(target_os = "linux")]
    let closed = JailInputs {
        close_userns: userns_closed,
        ..input.clone()
    };
    #[cfg(target_os = "linux")]
    let (with_channel, channel) = match with_record_channel(&closed, None) {
        Ok(with_channel) => with_channel,
        Err(code) => return code,
    };
    #[cfg(target_os = "linux")]
    let input = &JailInputs {
        profiles_marker_fd: marker.as_ref().map(std::os::fd::AsRawFd::as_raw_fd),
        seccomp_fd: filter.as_ref().map(std::os::fd::AsRawFd::as_raw_fd),
        ..with_channel
    };
    #[cfg(not(target_os = "linux"))]
    let _ = marks;
    // Each pin and read-only path from a descriptor opened now, after every
    // check ([`with_held_binds`]); kept open until bwrap has run.
    #[cfg(target_os = "linux")]
    let (held_input, held) = match with_held_binds(input) {
        Ok(held) => held,
        Err(why) => {
            eprintln!("innerwarden contain: {why}");
            return ExitCode::from(2);
        }
    };
    #[cfg(target_os = "linux")]
    let input = &held_input;
    let code = match build_linux_jail(input) {
        Ok(plan) => run_plain(bwrap, &plan, input),
        Err(e) => {
            eprintln!("innerwarden contain: {e}");
            ExitCode::from(2)
        }
    };
    // Ours close only once bwrap has read them.
    #[cfg(target_os = "linux")]
    drop((marker, filter, held));
    // Every decision the hook handed over is written before the launcher
    // ends.
    #[cfg(target_os = "linux")]
    drop(channel);
    code
}

/// The filter of a jail with no instance record, on a pipe for bwrap, and
/// whether it closes the jail's user namespaces: the identified one where
/// the host takes it, plain jails included, since every jail may hold the
/// launcher's record channel and a program in a jail with user namespaces
/// open could mount a socket of its own where the hook looks for it (the
/// channel is then not opened: [`with_record_channel`]). Else the terminal
/// one where the host takes only that. What it lost is said once; `None`
/// where the host took neither or the pipe could not be made.
#[cfg(target_os = "linux")]
fn unrecorded_filter(bwrap: &Path, identity: bool) -> (Option<std::io::PipeReader>, bool) {
    let plan = filter_plan_for_channel(bwrap, identity);
    for line in &plan.said {
        eprintln!("{line}");
    }
    let planned = plan.filter;
    let reader = handed_filter(planned);
    let closed =
        planned == Some(innerwarden_agent_guard::seccomp::Rules::Identified) && reader.is_some();
    (reader, closed)
}

/// The planned filter on a pipe for bwrap. One whose pipe cannot be made is
/// none, and the lines that say so are printed: the jail then runs as it did
/// before the filter.
#[cfg(target_os = "linux")]
fn handed_filter(
    planned: Option<innerwarden_agent_guard::seccomp::Rules>,
) -> Option<std::io::PipeReader> {
    let rules = planned?;
    let filter = filter_pipe(rules);
    if filter.is_none() {
        for line in crate::contain::launch::filter_lost_sentences(rules) {
            eprintln!("{line}");
        }
    }
    filter
}

/// A pipe that holds `bytes` whole, its write end closed so bwrap reads them
/// to their end, its read end handed to bwrap. Each use here is far below a
/// pipe's buffer, so the write never waits for a reader.
#[cfg(target_os = "linux")]
fn data_pipe(bytes: &[u8]) -> Option<std::io::PipeReader> {
    use std::io::Write;
    let (reader, mut writer) = std::io::pipe().ok()?;
    writer.write_all(bytes).ok()?;
    drop(writer);
    hand_to_child(&reader).then_some(reader)
}

/// The marker on a pipe for bwrap.
#[cfg(target_os = "linux")]
fn marker_pipe() -> Option<std::io::PipeReader> {
    data_pipe(crate::agent_profiles::SYSTEM_PROFILES_MARKER)
}

/// This build's filter with `rules` on a pipe for bwrap. `None` where this
/// build has no filter for the architecture it runs as, or the pipe cannot
/// be made.
#[cfg(target_os = "linux")]
fn filter_pipe(rules: innerwarden_agent_guard::seccomp::Rules) -> Option<std::io::PipeReader> {
    data_pipe(&innerwarden_agent_guard::seccomp::native_filter(rules)?)
}

/// What to say, and stop on, when this kernel restricts unprivileged user
/// namespaces and `bwrap` is not granted one. The sysctl file exists only on
/// kernels that carry the restriction. Where it applies, a run (`probe`)
/// asks bwrap itself ([`bwrap_gets_a_userns`]): the loaded-profiles list is
/// root-only, and a profile file on disk says nothing of what is loaded (the
/// distribution's own, Ubuntu 26.04, is loaded and named otherwise). A dry
/// run, which runs nothing, goes by the files on disk.
fn restriction_advice(bwrap: &Path, probe: bool) -> Option<Vec<String>> {
    let sysctl =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").ok();
    let grant = crate::contain::UsernsGrant {
        // Run wherever it may run, restricted or not: a kernel with no
        // AppArmor restriction can still refuse one (NEW-20261018: the
        // dashboard said "Ready" where a jail could not start).
        probed: probe.then(|| bwrap_gets_a_userns(bwrap)).flatten(),
        own_profile: Path::new("/etc/apparmor.d/bwrap").exists()
            || Path::new("/etc/apparmor.d/usr.bin.bwrap").exists(),
        distro_profile: Path::new(crate::contain::DISTRO_BWRAP_PROFILE).exists(),
    };
    let read = |path: &str| std::fs::read_to_string(path).ok();
    crate::contain::userns_advice(
        sysctl.as_deref(),
        grant,
        read("/proc/sys/kernel/unprivileged_userns_clone").as_deref(),
        read("/proc/sys/user/max_user_namespaces").as_deref(),
        bwrap,
    )
}

/// Whether `bwrap` gets a user namespace here: run once with one, the root
/// bound read-only, running `true`. `None` when it could not be started or
/// did not end within 5 s (killed): not known, and the files on disk decide.
///
/// Like every program the launcher starts, under [`helper_env`]: root's two
/// folders as `PATH` and no dynamic loader variable (Active Defence reads the
/// launcher's contract by that shape; 1.6.1 cleared the environment instead).
#[cfg(target_os = "linux")]
fn bwrap_gets_a_userns(bwrap: &Path) -> Option<bool> {
    let mut command = Command::new(bwrap);
    helper_env(&mut command);
    command
        .args(["--unshare-user", "--ro-bind", "/", "/", "true"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = command.spawn().ok()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status.success()),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// No user namespace restriction to ask about where there is no bwrap jail.
#[cfg(not(target_os = "linux"))]
fn bwrap_gets_a_userns(_bwrap: &Path) -> Option<bool> {
    None
}

/// The key of Active Defence on this host, read from its file with the
/// host's real owners (root's, in folders only root can write), for the
/// launcher to hand into an identified jail. A file that is there and not
/// believed is said once; with none, nothing is said and nothing is handed in.
fn host_key() -> Option<[u8; 32]> {
    let path = Path::new(innerwarden_agent_guard::identity::AGENT_TLS_SPKI_PATH);
    let key = crate::host_decide_io::read_pin(path);
    if key.is_none() && std::fs::symlink_metadata(path).is_ok() {
        eprintln!(
            "innerwarden contain: {} is not a key this launcher believes (it must be root's, in \
             folders only root can write), so the jail's hook will not ask InnerWarden Pro",
            path.display()
        );
    }
    key
}

/// The jail as it runs without `--identity`: bwrap, its arguments, waited for.
fn run_plain(bwrap: &Path, plan: &crate::contain::LinuxJailPlan, input: &JailInputs) -> ExitCode {
    let mut command = Command::new(bwrap);
    command
        .args(&plan.bwrap_args)
        .envs(plan.env.iter().cloned());
    without_credentials(&mut command, input);
    exit_from(command.status())
}

/// The variables of the launcher's environment the jail's command does not
/// get ([`crate::contain::env_kept_out`]): all but the few a shell needs and
/// those passed with `--pass-env`. The jail's own `IW_*`, which the launch
/// sets, are never among them.
fn credentials_kept_out(input: &JailInputs) -> Vec<std::ffi::OsString> {
    let set = crate::contain::compute_jail_env(input);
    let set: Vec<&str> = set.iter().map(|(name, _)| name.as_str()).collect();
    crate::contain::env_kept_out(
        std::env::vars_os().map(|(name, _)| name),
        &input.args.pass_env,
        &set,
    )
}

/// Take those variables out of the environment `command` (bwrap, or the
/// program that starts it, or sandbox-exec) hands the jail.
fn without_credentials(command: &mut Command, input: &JailInputs) {
    without_credentials_but(command, input, &[]);
}

/// As [`without_credentials`], leaving `kept` for the program that starts
/// bwrap (`systemd-run` finds the user's manager by them); bwrap then takes
/// them out of the jail's own environment ([`unset_in_jail`]).
fn without_credentials_but(command: &mut Command, input: &JailInputs, kept: &[&str]) {
    for name in credentials_kept_out(input) {
        if !kept.iter().any(|k| name.as_os_str() == *k) {
            command.env_remove(name);
        }
    }
}

/// The variables `systemd-run --user` needs to reach the user's manager.
/// They are no secret (a folder and a socket address), and the jail still
/// never gets them unless passed: bwrap unsets them ([`unset_in_jail`]).
#[cfg(target_os = "linux")]
const SCOPE_RUNNER_ENV: &[&str] = &["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"];

/// `--unsetenv NAME` for each of `names` the launcher has and the jail must
/// not get, put right after bwrap's path in the scope's argv
/// (`[.., "--", bwrap, bwrap_args..]`), so bwrap applies it to the jail.
#[cfg(target_os = "linux")]
fn unset_in_jail(args: &mut Vec<String>, names: &[&str], input: &JailInputs) {
    let out = credentials_kept_out(input);
    let Some(at) = args.iter().position(|a| a == "--") else {
        return;
    };
    let mut put = at + 2;
    for name in names {
        if out.iter().any(|o| o.as_os_str() == *name) {
            args.insert(put, "--unsetenv".to_string());
            args.insert(put + 1, (*name).to_string());
            put += 2;
        }
    }
}

// ---------------------------------------------------------------------------
// `contain --identity`: the thin I/O around the pure record parts in
// `contain::launch`.
// ---------------------------------------------------------------------------

/// Write one launch record under `dir`, readable by its owner only.
///
/// The directory is the launcher's own: created `0700` if missing, and refused
/// if it is a symlink, someone else's, or writable by anyone but its owner. The
/// record goes to a temp name opened `O_EXCL | O_NOFOLLOW` at `0600`, is synced,
/// then renamed into place, so a reader sees either no record or a whole one.
#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn write_launch_record(
    dir: &Path,
    instance_id: &str,
    json: &[u8],
    owner_uid: u32,
) -> std::io::Result<PathBuf> {
    use std::io::{Error, ErrorKind};

    let target = crate::contain::launch::record_path(dir, instance_id)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "not an instance id"))?;
    write_private_file(
        dir,
        &target,
        &format!(".{instance_id}.tmp"),
        json,
        owner_uid,
    )
}

/// Write, beside an instance's record, the absolute path of its project
/// (`<id>.project`, one line), with the record's own care. The dashboard
/// reads it to find the graph the jail's hook keeps in the project; the jail
/// never sees it (the records directory is hidden inside the jail).
#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn write_project_path(
    dir: &Path,
    instance_id: &str,
    project: &Path,
    owner_uid: u32,
) -> std::io::Result<PathBuf> {
    use std::io::{Error, ErrorKind};

    let name = crate::contain::launch::project_path_file(instance_id)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "not an instance id"))?;
    let text = project
        .to_str()
        .filter(|text| {
            project
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|folder| {
                    crate::contain::launch::parse_project_path(text.as_bytes(), folder).is_some()
                })
        })
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "not a plain absolute project path"))?;
    write_private_file(
        dir,
        &dir.join(&name),
        &format!(".{name}.tmp"),
        format!("{text}\n").as_bytes(),
        owner_uid,
    )
}

/// Put `bytes` at `target` in the launcher's own `dir`: a temp name opened
/// `O_EXCL | O_NOFOLLOW` at `0600`, synced, renamed into place.
#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn write_private_file(
    dir: &Path,
    target: &Path,
    temp_name: &str,
    json: &[u8],
    owner_uid: u32,
) -> std::io::Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    own_records_dir(dir, owner_uid)?;
    let temp = dir.join(temp_name);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    innerwarden_safe_io::harden(&mut options);
    let mut file = options.open(&temp)?;
    let written = file
        .write_all(json)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&temp, target));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }
    Ok(target.to_path_buf())
}

/// Make the launcher's records directory if it is missing (`0700`), and
/// refuse it if it is a symlink, someone else's, or writable by anyone but its
/// owner.
#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn own_records_dir(dir: &Path, owner_uid: u32) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    // symlink_metadata: a symlinked directory is described, not followed.
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != owner_uid || meta.mode() & 0o022 != 0 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "{} is not a directory of its own that only its owner can write",
                dir.display()
            ),
        ));
    }
    Ok(())
}

/// Run the jail with `--identity`.
///
/// The order is in `contain::launch` (the comment above `ScopePlan`): the user
/// scope is made around bwrap, bwrap reports the jail's first process through
/// one pipe, that process waits for the record on a second pipe, and the
/// launcher reads the jail from the host's `/proc`, asks for a system scope
/// where Active Defence runs, and hands the record in. The jail itself is
/// built exactly as without the flag, plus `--ro-bind-data` and `--info-fd`.
///
/// A record that cannot be made is said, not hidden, and the jail still runs
/// with an empty record (unreadable inside, so `declared`): an instance with no
/// record is an unidentified one, which is what every instance was before.
#[cfg(target_os = "linux")]
fn run_linux_identified(input: &JailInputs, bwrap: &Path, marks: bool) -> ExitCode {
    use crate::contain::launch::{no_scope_sentence, plan_scope, NoScope, ScopePlan};
    use innerwarden_agent_guard::identity::scope_unit_name;

    let named = new_instance_id().and_then(|id| {
        let unit = scope_unit_name(&id).ok_or("the instance id is not a name")?;
        Ok((id, unit))
    });
    let (instance_id, unit) = match named {
        Ok(named) => named,
        Err(why) if !crate::contain::launch::starts(input.args.start, false) => {
            // No instance, so nothing the host could admit.
            eprintln!("innerwarden contain: no instance record written ({why})");
            eprintln!(
                "innerwarden contain: {}",
                crate::contain::launch::NOT_ADMITTED
            );
            eprintln!(
                "innerwarden contain: {}",
                crate::contain::launch::not_admitted_remedy(
                    &crate::agent_profiles_io::files_that_wait_for_the_host(&input.args.agent),
                    None
                )
            );
            return ExitCode::from(2);
        }
        Err(why) => {
            eprintln!(
                "innerwarden contain: no instance record written ({why}); the jail runs, unidentified"
            );
            announce(input);
            // No record to say the way to the system profiles file was
            // proven: the marker says it.
            return run_unrecorded(bwrap, input, marks);
        }
    };
    // The records directory exists before the jail does, so the jail hides a
    // folder of the launcher's and bwrap makes none on the host. One that
    // cannot be made, and is not there, is not hidden: nothing can be in it.
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let mut input = input.clone();
    // Once, before the jail is built: whether this host takes the identified
    // filter, which also keeps the jail's programs from making user
    // namespaces. A host that does not gets the terminal filter where it
    // takes that, or runs the jail as it did before the filter, and says
    // what the jail runs without.
    let plan = filter_plan_here(bwrap, true);
    for line in &plan.said {
        eprintln!("{line}");
    }
    input.close_userns = plan.close_userns();
    if let Some(dir) = input.records_dirs.first() {
        if let Err(e) = own_records_dir(dir, uid) {
            eprintln!("innerwarden contain: the launcher's records folder is not usable ({e})");
        }
    }
    input
        .records_dirs
        .retain(|dir| std::fs::symlink_metadata(dir).is_ok());
    let input = &input;
    // Read once, outside the jail, with the host's real owners: inside it the
    // owners cannot be told apart, so the hook there reads only this copy.
    let key = host_key();
    let mut scope = plan_scope(&scope_facts(), &unit);
    if let ScopePlan::None(why) = scope {
        eprintln!("{}", no_scope_sentence(why));
    }
    announce(input);
    loop {
        let ids = (instance_id.as_str(), unit.as_str());
        match launch_identified(input, bwrap, ids, &scope, key.as_ref(), plan.filter) {
            Attempt::Done(code) => return code,
            // Nothing of the jail ran: bwrap never reported a pid, and the
            // jail cannot pass the record it never got. Only the scope was
            // new, so run once more without it.
            Attempt::NeverStarted(_) if matches!(scope, ScopePlan::User { .. }) => {
                eprintln!("{}", no_scope_sentence(NoScope::ScopeNotStarted));
                scope = ScopePlan::None(NoScope::ScopeNotStarted);
            }
            Attempt::NeverStarted(status) => return exit_from(status),
        }
    }
}

#[cfg(target_os = "linux")]
enum Attempt {
    Done(ExitCode),
    /// The jail never started: no pid was reported and the launch ended.
    NeverStarted(std::io::Result<std::process::ExitStatus>),
}

/// 16 random bytes from the kernel, as an instance id.
#[cfg(target_os = "linux")]
fn new_instance_id() -> Result<String, String> {
    let mut random = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut random))
        .map_err(|e| format!("no randomness for the instance id: {e}"))?;
    Ok(crate::contain::launch::instance_id_from(random))
}

/// Clear close-on-exec on a descriptor bwrap must inherit. `std` opens both
/// ends of a pipe close-on-exec; only bwrap's end is cleared, so the launcher's
/// ends never reach the jail.
#[cfg(target_os = "linux")]
fn hand_to_child(fd: &impl std::os::fd::AsRawFd) -> bool {
    // SAFETY: fcntl on a descriptor the caller owns.
    unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) == 0 }
}

/// One launch of the identified jail.
#[cfg(target_os = "linux")]
fn launch_identified(
    input: &JailInputs,
    bwrap: &Path,
    (instance_id, unit): (&str, &str),
    scope: &crate::contain::launch::ScopePlan,
    key: Option<&[u8; 32]>,
    filter: Option<innerwarden_agent_guard::seccomp::Rules>,
) -> Attempt {
    use crate::contain::launch::{launch_argv, ScopePlan};
    use std::io::Write;
    use std::os::fd::AsRawFd;

    let pipes = std::io::pipe().and_then(|info| Ok((info, std::io::pipe()?)));
    let ((mut info_reader, info_writer), (record_reader, mut record_writer)) = match pipes {
        Ok(p) => p,
        Err(e) => {
            eprintln!("innerwarden contain: cannot open the jail's pipes: {e}");
            return Attempt::Done(ExitCode::from(1));
        }
    };
    if !hand_to_child(&info_writer) || !hand_to_child(&record_reader) {
        eprintln!("innerwarden contain: cannot hand the jail's pipes to bwrap");
        return Attempt::Done(ExitCode::from(1));
    }
    // The key goes in whole before bwrap starts: one line, far below a pipe's
    // buffer, and the launcher's end is closed so bwrap reads it to its end.
    // A key that cannot be handed in is no key: the hook then never asks.
    let key_reader = key.and_then(|key| {
        data_pipe(innerwarden_agent_guard::identity::spki_pin_line(key).as_bytes())
    });
    // The filter the same way, the one the host took before the launch. One
    // that cannot be handed in is none: the jail then runs as it did before
    // the filter, its record says nothing of user namespaces, and the
    // launcher says so.
    let filter_reader = handed_filter(filter);
    let mut identified = input.clone();
    identified.info_fd = Some(info_writer.as_raw_fd());
    identified.record_fd = Some(record_reader.as_raw_fd());
    identified.key_fd = key_reader.as_ref().map(AsRawFd::as_raw_fd);
    identified.seccomp_fd = filter_reader.as_ref().map(AsRawFd::as_raw_fd);
    identified.close_userns = input.close_userns
        && filter == Some(innerwarden_agent_guard::seccomp::Rules::Identified)
        && filter_reader.is_some();
    // Under a profile that starts the jail only once the host admitted it,
    // the jail's command starts through the gate, which needs the record
    // the launcher writes only after the admission: a launcher that dies
    // before the host answered leaves the jail an empty record.
    identified.gate_instance = crate::contain::launch::gate_for(input.args.start, instance_id);
    let (identified, channel) = match with_record_channel(&identified, Some(instance_id)) {
        Ok(with_channel) => with_channel,
        Err(code) => return Attempt::Done(code),
    };
    // Each pin and read-only path from a descriptor opened now, after every
    // check ([`with_held_binds`]); bwrap holds its own copies once started.
    let (identified, held) = match with_held_binds(&identified) {
        Ok(held) => held,
        Err(why) => {
            eprintln!("innerwarden contain: {why}");
            return Attempt::Done(ExitCode::from(2));
        }
    };
    let plan = match build_linux_jail(&identified) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("innerwarden contain: {e}");
            return Attempt::Done(ExitCode::from(2));
        }
    };
    let (program, mut args) = launch_argv(bwrap, &plan.bwrap_args, scope);
    let runner_env: &[&str] = if matches!(scope, ScopePlan::User { .. }) {
        unset_in_jail(&mut args, SCOPE_RUNNER_ENV, input);
        SCOPE_RUNNER_ENV
    } else {
        &[]
    };
    let started_ms = now_ms();
    let mut command = Command::new(&program);
    command.args(&args).envs(plan.env.iter().cloned());
    helper_env(&mut command);
    without_credentials_but(&mut command, input, runner_env);
    let spawned = command.spawn();
    // Ours must close, or the read below never ends and the jail never sees
    // the end of its record.
    drop(info_writer);
    drop(record_reader);
    drop(key_reader);
    drop(filter_reader);
    drop(held);
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) if matches!(scope, ScopePlan::User { .. }) => return Attempt::NeverStarted(Err(e)),
        Err(e) => return Attempt::Done(exit_from(Err(e))),
    };
    // Under the gate, the record ends only once bwrap is gone (or once the
    // launcher let go of it), so a launcher that dies here leaves the gate
    // to say why nothing ran ([`hold_record_until_bwrap_ends`]).
    let holder = identified
        .gate_instance
        .as_ref()
        .and_then(|_| hold_record_until_bwrap_ends(child.id(), &record_writer));
    let info = read_info(&mut info_reader);
    drop(info_reader);
    let reported = match &info {
        InfoRead::Got(info) => Some(info.child_pid),
        _ => None,
    };
    let record = match info {
        InfoRead::Nothing => {
            drop(record_writer);
            let status = child.wait();
            RecordHolder::wait_out(holder);
            return match status {
                Ok(status) if status.success() => Attempt::Done(exit_from(Ok(status))),
                status => Attempt::NeverStarted(status),
            };
        }
        InfoRead::Failed(why) => Err(why),
        // The record says what this launch handed in, filter included.
        InfoRead::Got(info) => identify(&identified, instance_id, unit, scope, info, key),
    };
    // Under a profile that starts the jail only once the host admitted it,
    // a jail the host did not admit (no answer, a record that could not be
    // made, a scope the kernel does not show) is ended here, before its
    // command can run: its first process is still waiting for the record,
    // and the record is never handed in.
    let made = record
        .as_ref()
        .ok()
        .map(|(_, answer, scope)| (answer, scope.as_ref()));
    if !crate::contain::launch::launch_starts(input.args.start, made) {
        if let Err(why) = &record {
            eprintln!("innerwarden contain: no instance record written ({why})");
        }
        // The host was asked, but without its key its answer was never
        // read: say so, rather than send the person to check a host that
        // may well be running.
        let unbelieved = (record.is_ok() && crate::upsell_io::active_defence_installed())
            .then(|| {
                crate::contain::launch::answer_unbelieved(
                    key.is_some(),
                    crate::agent_report::agent_route(
                        std::env::var(crate::agent_report::AGENT_URL_VAR)
                            .ok()
                            .as_deref(),
                        innerwarden_agent_guard::identity::SYSTEM_SCOPE_ROUTE,
                    )
                    .as_deref(),
                )
            })
            .flatten();
        if let Some(why) = &unbelieved {
            eprintln!(
                "innerwarden contain: {}",
                crate::contain::launch::unbelieved_sentence(why)
            );
        }
        eprintln!(
            "innerwarden contain: {}",
            crate::contain::launch::NOT_ADMITTED
        );
        eprintln!(
            "innerwarden contain: {}",
            crate::contain::launch::not_admitted_remedy(
                &crate::agent_profiles_io::files_that_wait_for_the_host(&input.args.agent),
                unbelieved.as_ref()
            )
        );
        end_jail(&mut child, reported);
        drop(record_writer);
        // Not let go: the holder ends with bwrap, which `end_jail` ended.
        RecordHolder::wait_out(holder);
        // The launcher's own copy of a record it never handed in, and the
        // project path beside it: no instance of it ever ran.
        if record.is_ok() {
            forget_instance(input, instance_id);
        }
        return Attempt::Done(ExitCode::from(2));
    }
    let mut identified = false;
    match record.map(|(json, _, _)| json) {
        Ok(json) => {
            // The jail reads this to its end before it builds its root.
            if let Err(e) = record_writer.write_all(&json) {
                eprintln!("innerwarden contain: the jail did not take its record: {e}");
            } else {
                identified = true;
                eprintln!(
                    "  inside the jail: {} (read-only)",
                    innerwarden_agent_guard::identity::JAIL_RECORD_PATH
                );
            }
        }
        Err(why) => eprintln!(
            "innerwarden contain: no instance record written ({why}); the jail runs, unidentified"
        ),
    }
    drop(record_writer);
    RecordHolder::release(holder);
    let code = exit_from(child.wait());
    // Every decision the hook handed over is written before the record is
    // read.
    drop(channel);
    if identified {
        report_contained_run(input, instance_id, started_ms, now_ms());
    }
    Attempt::Done(code)
}

/// The process that keeps the write end of a gated jail's record open after
/// the launcher, until bwrap is gone or the launcher lets go of it.
///
/// Why (bubblewrap 0.9.0): bwrap arms `--die-with-parent` before it reports
/// the jail, and the jail's first process arms its own only after it read its
/// record. When the launcher dies, the kernel closes the launcher's
/// descriptors (the record ends, empty) before it signals bwrap, so the
/// jail's first process could arm it in that gap and die with bwrap, before
/// the gate said anything: nothing ran, and nothing said why. With this
/// process holding the record open until bwrap is gone, the jail's first
/// process reads the end of its record only once its parent is dead; the
/// death signal it then arms never comes, and the gate refuses the empty
/// record on stderr, every time.
#[cfg(target_os = "linux")]
struct RecordHolder {
    pid: libc::pid_t,
    /// One byte here says the launcher let go of the record.
    release: std::io::PipeWriter,
}

#[cfg(target_os = "linux")]
impl RecordHolder {
    /// The launcher handed the record in (or runs the jail without one): the
    /// holder lets go now, and is waited for.
    fn release(holder: Option<Self>) {
        if let Some(mut holder) = holder {
            let _ = std::io::Write::write_all(&mut holder.release, &[1]);
            holder.reap();
        }
    }

    /// The launcher did not let go: the holder ends once bwrap is gone. Called
    /// once bwrap was waited for or ended, so this does not block on it.
    fn wait_out(holder: Option<Self>) {
        if let Some(holder) = holder {
            holder.reap();
        }
    }

    fn reap(self) {
        let RecordHolder { pid, release } = self;
        drop(release);
        let mut status = 0;
        // SAFETY: waitpid on our own child, which nothing else waits for.
        while unsafe { libc::waitpid(pid, &mut status, 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
        {}
    }
}

/// Fork the [`RecordHolder`] of the record whose write end is `record`, for
/// the bwrap whose pid is `bwrap`. `None` (and the record behaves as before)
/// where the kernel has no `pidfd_open` (before 5.3) or the fork fails.
#[cfg(target_os = "linux")]
fn hold_record_until_bwrap_ends(
    bwrap: u32,
    record: &impl std::os::fd::AsRawFd,
) -> Option<RecordHolder> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let pid = libc::pid_t::try_from(bwrap).ok()?;
    // SAFETY: pidfd_open takes a pid and no flags; bwrap is our child, not
    // yet waited for, so its pid names it.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    let raw = libc::c_int::try_from(raw).ok().filter(|fd| *fd >= 0)?;
    // SAFETY: a descriptor the kernel just opened for us.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let (release_reader, release) = std::io::pipe().ok()?;
    let keep = [
        pidfd.as_raw_fd(),
        release_reader.as_raw_fd(),
        record.as_raw_fd(),
    ];
    // SAFETY: the child runs only async-signal-safe calls (sigaction, close,
    // poll, read, _exit) and never returns: see [`record_holder`].
    match unsafe { libc::fork() } {
        -1 => None,
        0 => unsafe { record_holder(keep) },
        holder => Some(RecordHolder {
            pid: holder,
            release,
        }),
    }
}

/// The forked holder: it keeps only `[pidfd, release, record]`, ignores the
/// signals a terminal sends, and exits when bwrap is gone (the pidfd reads)
/// or the launcher let go (one byte on `release`). A `release` that ends
/// with no byte is a launcher that died: then only bwrap's end counts.
///
/// # Safety
///
/// Only in the child of a `fork`, which it ends.
#[cfg(target_os = "linux")]
unsafe fn record_holder(keep: [libc::c_int; 3]) -> ! {
    for signal in [
        libc::SIGINT,
        libc::SIGTERM,
        libc::SIGHUP,
        libc::SIGQUIT,
        libc::SIGPIPE,
    ] {
        libc::signal(signal, libc::SIG_IGN);
    }
    let mut sorted = keep;
    sorted.sort_unstable();
    let mut first: libc::c_uint = 0;
    for fd in sorted {
        let fd = fd as libc::c_uint;
        if fd > first {
            close_from_to(first, fd - 1);
        }
        first = fd + 1;
    }
    close_from_to(first, libc::c_uint::MAX);
    let [pidfd, release, _record] = keep;
    let mut fds = [
        libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: release,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        if libc::poll(fds.as_mut_ptr(), 2, -1) < 0 {
            if *libc::__errno_location() == libc::EINTR {
                continue;
            }
            libc::_exit(1);
        }
        if fds[0].revents != 0 {
            libc::_exit(0);
        }
        if fds[1].revents != 0 {
            let mut byte = 0u8;
            match libc::read(release, (&raw mut byte).cast(), 1) {
                1 => libc::_exit(0),
                -1 if *libc::__errno_location() == libc::EINTR => {}
                // The launcher is gone without letting go: wait for bwrap.
                _ => fds[1].fd = -1,
            }
        }
    }
}

/// Close every descriptor from `first` to `last`: `close_range` (Linux 5.9),
/// or one at a time up to 65536 where it is missing.
///
/// # Safety
///
/// Only in [`record_holder`], which owns no descriptor in that range.
#[cfg(target_os = "linux")]
unsafe fn close_from_to(first: libc::c_uint, last: libc::c_uint) {
    if libc::syscall(libc::SYS_close_range, first, last, 0) == 0 {
        return;
    }
    let mut fd = first;
    while fd <= last.min(65_535) {
        libc::close(fd as libc::c_int);
        fd += 1;
    }
}

/// End a jail whose command must not run, while its first process is still
/// waiting for the record: SIGSTOP to bwrap, so it starts nothing more while
/// its processes are read, then SIGKILL to each process bwrap started (the
/// one it reported on its info descriptor first, then those `/proc` lists),
/// then to bwrap. Killing bwrap alone is not enough: measured with bwrap
/// 0.9.0, its child waiting on the record outlives it (`--die-with-parent`
/// is not in force yet at that point), reads the end of the closed pipe,
/// and runs the command. A process SIGKILLed while it waits never runs
/// another instruction of its own. One this misses still runs nothing but
/// the gate, which refuses an empty record ([`crate::contain::launch::gate_opens`]).
#[cfg(target_os = "linux")]
fn end_jail(child: &mut std::process::Child, reported: Option<u32>) {
    let bwrap = child.id();
    if let Ok(pid) = libc::pid_t::try_from(bwrap) {
        // SAFETY: kill on the pid of this launcher's own child.
        unsafe { libc::kill(pid, libc::SIGSTOP) };
    }
    let listed = proc_children(bwrap);
    for pid in crate::contain::launch::jail_processes_to_end(bwrap, reported, &listed, proc_parent)
    {
        if let Ok(pid) = libc::pid_t::try_from(pid) {
            // SAFETY: kill on a pid this launcher's own child started, whose
            // parent is still that child.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// The processes `pid` started, as `/proc/<pid>/task/<tid>/children` lists
/// them for each of its threads.
#[cfg(target_os = "linux")]
fn proc_children(pid: u32) -> Vec<u32> {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for task in tasks.flatten() {
        if let Ok(text) = std::fs::read_to_string(task.path().join("children")) {
            out.extend(
                text.split_whitespace()
                    .filter_map(|p| p.parse::<u32>().ok()),
            );
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// The parent of `pid`: field 4 of `/proc/<pid>/stat`.
#[cfg(target_os = "linux")]
fn proc_parent(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    crate::contain::launch::parse_parent_pid(&stat)
}

/// Remove the launcher's record of `instance_id` and the project path beside
/// it, best effort: the jail was ended before its command ran.
#[cfg(target_os = "linux")]
fn forget_instance(input: &JailInputs, instance_id: &str) {
    use crate::contain::launch::{project_path_file, record_path, records_dir};
    let dir = records_dir(std::env::var("XDG_STATE_HOME").ok().as_deref(), &input.home);
    let files = [
        record_path(&dir, instance_id),
        project_path_file(instance_id).map(|name| dir.join(name)),
    ];
    for file in files.into_iter().flatten() {
        let _ = std::fs::remove_file(file);
    }
}

/// The launcher's clock, in ms since the epoch.
#[cfg(target_os = "linux")]
fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

/// Tell the local Active Defence agent, best effort, what the ended jail's
/// hook screened: counts and times, `declared`. Only where Active Defence is
/// installed and its route is on; the jail's graph is read only then.
#[cfg(target_os = "linux")]
fn report_contained_run(input: &JailInputs, instance_id: &str, started_ms: u64, ended_ms: u64) {
    use crate::agent_report::{agent_route, send_report, AGENT_URL_VAR};
    use crate::contain::launch::{contained_run_report_for, JailGraph};
    use innerwarden_agent_guard::identity::CONTAINED_RUN_ROUTE;

    if !crate::upsell_io::active_defence_installed() {
        return;
    }
    let Some(url) = agent_route(
        std::env::var(AGENT_URL_VAR).ok().as_deref(),
        CONTAINED_RUN_ROUTE,
    ) else {
        return;
    };
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let Some(body) =
        contained_run_report_for(&input.args, instance_id, started_ms, ended_ms, || {
            let read = read_jail_graph(&input.args.project, uid);
            if let JailGraph::Unreadable(why) = &read {
                eprintln!("innerwarden contain: the jail's graph was not read ({why})");
            }
            read
        })
    else {
        return;
    };
    match send_report(&url, &body) {
        Ok(()) if body["graph"] == "read" => eprintln!(
            "innerwarden contain: {} command(s) screened in the jail, reported to the local agent as declared",
            body["commands"]
        ),
        Ok(()) => eprintln!(
            "innerwarden contain: the run was reported to the local agent with no count (the jail's graph is {})",
            body["graph"].as_str().unwrap_or("unknown")
        ),
        Err(why) => {
            eprintln!("innerwarden contain: the local agent did not take the run's report: {why}")
        }
    }
}

/// Read the jail's graph from the project once the jail has ended.
///
/// Everything in the project is the agent's to write, so this read is
/// hardened like any read of a file someone else prepared: the graph folder
/// must be a real folder of `uid` (not followed if it is a link), the file is
/// opened once without following a link and without waiting on a FIFO, its
/// facts come from that open, and no more than a graph's cap is read.
#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn read_jail_graph(project: &Path, uid: u32) -> crate::contain::launch::JailGraph {
    use crate::contain::launch::{
        parse_jail_graph, vet_jail_graph_dir, vet_jail_graph_file, GraphEntry, JailGraph,
        MAX_JAIL_GRAPH_BYTES,
    };
    use crate::contain::{jail_graph_dir, JAIL_GRAPH_NAME};
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let entry = |m: &std::fs::Metadata| GraphEntry {
        symlink: m.file_type().is_symlink(),
        dir: m.is_dir(),
        regular: innerwarden_safe_io::is_regular_file(m),
        uid: m.uid(),
        len: m.len(),
    };
    let dir = jail_graph_dir(project);
    match std::fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return JailGraph::Absent,
        Err(_) => return JailGraph::Unreadable("graph_dir_unreadable"),
        Ok(m) => {
            if let Err(why) = vet_jail_graph_dir(&entry(&m), uid) {
                return JailGraph::Unreadable(why);
            }
        }
    }
    let file = match innerwarden_safe_io::open_no_follow(&dir.join(JAIL_GRAPH_NAME)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return JailGraph::Absent,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return JailGraph::Unreadable("graph_not_a_regular_file")
        }
        Err(_) => return JailGraph::Unreadable("graph_unreadable"),
    };
    match file.metadata() {
        Ok(m) => {
            if let Err(why) = vet_jail_graph_file(&entry(&m), uid) {
                return JailGraph::Unreadable(why);
            }
        }
        Err(_) => return JailGraph::Unreadable("graph_unreadable"),
    }
    let mut bytes = Vec::new();
    if file
        .take(MAX_JAIL_GRAPH_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return JailGraph::Unreadable("graph_unreadable");
    }
    parse_jail_graph(&bytes)
}

/// The bytes of a jail's record, what the host answered of its admission,
/// and the system scope the kernel showed it in.
#[cfg(target_os = "linux")]
type IdentifiedJail = (
    Vec<u8>,
    innerwarden_agent_guard::identity::SystemScopeAdmission,
    Option<innerwarden_agent_guard::identity::Scope>,
);

/// Read the facts about the jail from the host, make the record, write the
/// launcher's copy, and return the bytes for the jail's copy.
///
/// Also what the host answered of its admission of the jail and the system
/// scope the kernel showed it in ([`crate::contain::launch::launch_starts`]
/// decides), asked only where Active Defence is installed and believed only
/// over a connection held to `key`.
#[cfg(target_os = "linux")]
fn identify(
    input: &JailInputs,
    instance_id: &str,
    unit: &str,
    scope: &crate::contain::launch::ScopePlan,
    info: crate::contain::launch::InfoFd,
    key: Option<&[u8; 32]>,
) -> Result<IdentifiedJail, String> {
    use crate::contain::launch::{
        assemble_record, no_scope_sentence, parse_mnt_ns_link, parse_ns_link, records_dir,
        user_scope_seen, LaunchFacts, NoScope, ScopePlan,
    };
    use innerwarden_agent_guard::identity::Scopes;

    let pid = info.child_pid;
    // Start time before the namespace and the cgroups and after them: the
    // same process both times, or the pid was reused and nothing here
    // describes the jail.
    let before =
        start_ticks(pid).ok_or("the jail process is gone or its start time is unreadable")?;
    let pid_ns = std::fs::read_link(format!("/proc/{pid}/ns/pid"))
        .ok()
        .and_then(|l| parse_ns_link(&l.to_string_lossy()))
        .ok_or("the jail's PID namespace is unreadable")?;
    let mnt_ns = std::fs::read_link(format!("/proc/{pid}/ns/mnt"))
        .ok()
        .and_then(|l| parse_mnt_ns_link(&l.to_string_lossy()))
        .ok_or("the jail's mount namespace is unreadable")?;
    let launcher_mnt_ns = std::fs::read_link("/proc/self/ns/mnt")
        .ok()
        .and_then(|l| parse_mnt_ns_link(&l.to_string_lossy()));
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };

    let mut scopes = Scopes::default();
    if let ScopePlan::User { .. } = scope {
        let cgroup = proc_cgroup(pid);
        scopes.user = cgroup
            .as_deref()
            .and_then(|c| user_scope_seen(c, unit, uid));
        if scopes.user.is_none() {
            eprintln!(
                "innerwarden contain: the jail is not in its user scope (the kernel says {})",
                cgroup.as_deref().unwrap_or("nothing")
            );
        }
    }
    let mut answer = innerwarden_agent_guard::identity::SystemScopeAdmission::NONE;
    if crate::upsell_io::active_defence_installed() {
        (scopes.system, answer) = request_system_scope(instance_id, unit, pid, key);
    }
    let system_scope = scopes.system.clone();
    if scopes.is_empty() && matches!(scope, ScopePlan::User { .. }) {
        eprintln!("{}", no_scope_sentence(NoScope::NotSeenInScope));
    }
    if start_ticks(pid) != Some(before) {
        return Err("the jail process changed while it was read".into());
    }

    let launcher_root_owned =
        backend_facts(&input.iw_binary).is_some_and(|facts| backend_trusted(&facts));
    let facts = LaunchFacts {
        instance_id: instance_id.to_string(),
        agent_type: &input.args.agent,
        launcher_path: &input.iw_binary,
        launcher_version: env!("CARGO_PKG_VERSION"),
        launcher_root_owned,
        uid,
        project: &input.args.project,
        mode: &input.args.mode,
        started_at: chrono::Utc::now(),
        info,
        start_ticks: before,
        pid_ns,
        mnt_ns,
        launcher_mnt_ns,
        scope: scopes,
        userns_closed: input.close_userns,
    };
    let record = assemble_record(facts).map_err(|e| e.to_string())?;
    let json = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
    let dir = records_dir(std::env::var("XDG_STATE_HOME").ok().as_deref(), &input.home);
    match write_launch_record(&dir, &record.instance_id, &json, uid) {
        Ok(path) => {
            eprintln!("innerwarden contain - instance record: {}", path.display());
            // Best effort: without it the dashboard lists the instance and
            // no sessions, as for a record written before it existed.
            if let Err(e) = write_project_path(&dir, &record.instance_id, &input.args.project, uid)
            {
                eprintln!(
                    "innerwarden contain: the project path beside the record was not written ({e})"
                );
            }
        }
        Err(e) => eprintln!(
            "innerwarden contain: the launcher's copy of the record was not written ({e})"
        ),
    }
    Ok((json, answer, system_scope))
}

/// `/proc/<pid>/stat` field 22.
#[cfg(target_os = "linux")]
fn start_ticks(pid: u32) -> Option<u64> {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| crate::contain::launch::parse_start_ticks(&s))
}

/// The cgroup of `pid` as the kernel reports it.
#[cfg(target_os = "linux")]
fn proc_cgroup(pid: u32) -> Option<String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(format!("/proc/{pid}/cgroup"))
        .ok()?
        .take(64 * 1024)
        .read_to_string(&mut text)
        .ok()?;
    crate::contain::launch::parse_proc_cgroup(&text)
}

/// How long the launcher waits for the kernel to show the jail in its system
/// scope once the request was taken. Placing a pid takes a systemd job, which
/// was measured to show in `/proc/<pid>/cgroup` about one second later.
#[cfg(target_os = "linux")]
const SYSTEM_SCOPE_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// How long the launcher waits for the answer to its request for a system
/// scope, connect to the end of the answer: the host places the jail and
/// decides its admission before it answers.
#[cfg(target_os = "linux")]
const SYSTEM_SCOPE_ANSWER_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// Ask the local Active Defence agent, best effort, for a system scope around
/// the instance, and return it only if the KERNEL then shows the jail in it,
/// with what the host's answer says of its admission of the jail.
///
/// The request names the instance and nothing else; it gives no process to
/// move. The answer is never the fact: a system scope is recorded only when
/// `/proc/<pid>/cgroup` reads exactly `/system.slice/<unit>`, a cgroup only
/// root can make or move a process into.
///
/// With the key the host publishes (`key`), the request goes over a
/// connection held to it ([`crate::host_decide_io::post`]), and the body of
/// its 202 is read: an admission and a note, the note printed as it came.
/// Without one, the request goes as it always did and its body is not read:
/// a server that took the port while the agent was away could say anything
/// there, so nothing is admitted.
#[cfg(target_os = "linux")]
fn request_system_scope(
    instance_id: &str,
    unit: &str,
    pid: u32,
    key: Option<&[u8; 32]>,
) -> (
    Option<innerwarden_agent_guard::identity::Scope>,
    innerwarden_agent_guard::identity::SystemScopeAdmission,
) {
    use crate::agent_report::{agent_route, AGENT_URL_VAR};
    use crate::contain::launch::system_scope_seen;
    use innerwarden_agent_guard::identity::{
        system_scope_request, SystemScopeAdmission, SYSTEM_SCOPE_ROUTE,
    };

    let said = |why: &str| eprintln!("innerwarden contain: no system scope ({why})");
    let Some(url) = agent_route(
        std::env::var(AGENT_URL_VAR).ok().as_deref(),
        SYSTEM_SCOPE_ROUTE,
    ) else {
        said("the local agent route is off");
        return (None, SystemScopeAdmission::NONE);
    };
    let Some(body) = system_scope_request(instance_id) else {
        return (None, SystemScopeAdmission::NONE);
    };
    let (sent, answer) = send_scope_request(&url, &body, key);
    if let Some(note) = &answer.note {
        eprintln!("innerwarden contain: {note}");
    }
    let seen = await_system_scope(
        sent,
        SYSTEM_SCOPE_WAIT,
        || proc_cgroup(pid).and_then(|c| system_scope_seen(&c, unit)),
        said,
    );
    if let Some(seen) = &seen {
        eprintln!("  system scope: {}", seen.cgroup_path);
    }
    (seen, answer)
}

/// The request for a system scope, sent: whether the host took it, and what
/// its answer says of the admission ([`request_system_scope`]).
#[cfg(target_os = "linux")]
fn send_scope_request(
    url: &str,
    body: &serde_json::Value,
    key: Option<&[u8; 32]>,
) -> (
    Result<(), String>,
    innerwarden_agent_guard::identity::SystemScopeAdmission,
) {
    use crate::host_decide_io::{pinnable, post, system_scope_wanted};
    use innerwarden_agent_guard::identity::SystemScopeAdmission;
    let Some(pin) = key.filter(|_| pinnable(url)) else {
        return (
            crate::agent_report::send_report(url, body),
            SystemScopeAdmission::NONE,
        );
    };
    let Ok(bytes) = serde_json::to_vec(body) else {
        return (
            Err("the request could not be written".into()),
            SystemScopeAdmission::NONE,
        );
    };
    crate::contain::launch::scope_answer(post(
        url,
        &bytes,
        SYSTEM_SCOPE_ANSWER_WAIT,
        pin,
        system_scope_wanted(),
    ))
}

/// Wait up to `wait` for `seen` to find the jail in its system scope, and only
/// once the request was taken. A route that is not there answers at once (no
/// listener, `404`, `401`), and a request that was not taken is not waited
/// for: the launch goes on with no system scope, which is what an instance
/// without one is (observed at most, from inside the jail's view of it).
#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn await_system_scope<T>(
    sent: Result<(), String>,
    wait: std::time::Duration,
    mut seen: impl FnMut() -> Option<T>,
    said: impl Fn(&str),
) -> Option<T> {
    if let Err(why) = sent {
        said(&format!("the local agent did not take the request: {why}"));
        return None;
    }
    let deadline = std::time::Instant::now() + wait;
    loop {
        if let Some(found) = seen() {
            return Some(found);
        }
        if std::time::Instant::now() >= deadline {
            said("the kernel does not show the jail in it");
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// The environment of a program the launcher runs to start an identified
/// jail: [`crate::contain::HELPER_PATH`] and no dynamic loader variable. The
/// jail's command gets its own back through bwrap ([`JailInputs::child_env`]).
/// On every platform: the jail check on macOS starts `sandbox-exec` under it.
fn helper_env(command: &mut Command) {
    for name in crate::contain::launch_env(std::env::vars_os()).helper_remove {
        command.env_remove(name);
    }
    command.env("PATH", crate::contain::HELPER_PATH);
}

/// Start the throwaway jail under this build's filter with `rules`, shaped
/// as the launch's jail (`identity`: its capabilities dropped): `Ran` only
/// when it ran and exited 0 within five seconds. Its `true` runs under the
/// filter, so a filter this kernel cannot load, or one whose architecture is
/// not the kernel's (a binary under emulation), fails here and never in the
/// jail. A filter whose pipe cannot be made, or a bwrap the launcher has not
/// the means to start (out of descriptors, processes or memory:
/// [`crate::contain::launch::spawn_failed_answer`]), runs no bwrap and
/// answers `NotHanded`.
#[cfg(target_os = "linux")]
fn filter_probe(
    bwrap: &Path,
    rules: innerwarden_agent_guard::seccomp::Rules,
    identity: bool,
) -> crate::contain::launch::ProbeAnswer {
    use crate::contain::launch::ProbeAnswer;
    use std::os::fd::AsRawFd;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let Some(filter) = filter_pipe(rules) else {
        return ProbeAnswer::NotHanded;
    };
    let mut command = Command::new(bwrap);
    command
        .args(crate::contain::launch::filter_probe_argv(
            filter.as_raw_fd(),
            identity,
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    helper_env(&mut command);
    let spawned = command.spawn();
    // Ours closes once bwrap has its own.
    drop(filter);
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return crate::contain::launch::spawn_failed_answer(&error),
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return ProbeAnswer::Ran,
            Ok(Some(_)) => return ProbeAnswer::Failed,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return ProbeAnswer::Failed;
            }
        }
    }
}

/// The kernel's own file for its release.
#[cfg(target_os = "linux")]
const OSRELEASE: &str = "/proc/sys/kernel/osrelease";

/// `UNAME26` (`include/uapi/linux/personality.h`). A process under this
/// personality (`setarch --uname-2.6`, inherited across `exec`) gets any
/// 3.x or later kernel's release from `uname` as `2.6.<minor + 60>`; the
/// kernel's own file still says the real one.
#[cfg(target_os = "linux")]
const UNAME26: libc::c_int = 0x0002_0000;

/// The kernel's release, as `uname -r` prints it. First from `osrelease`
/// (the kernel's own file), which no personality rewrites. Where that file
/// cannot be read or is empty (a chroot or a container with no `/proc`),
/// from the `uname` call, except under [`UNAME26`], whose `uname` names an
/// older kernel than the one running. Empty where neither tells it, which
/// reads as an unknown release: never as an older kernel.
#[cfg(target_os = "linux")]
fn kernel_release(osrelease: &Path) -> String {
    if let Ok(release) = std::fs::read_to_string(osrelease) {
        let release = release.trim();
        if !release.is_empty() {
            return release.to_string();
        }
    }
    // SAFETY: `personality(0xffffffff)` only reads this process's
    // personality and changes nothing.
    let personality = unsafe { libc::personality(0xffff_ffff) };
    if personality == -1 || personality & UNAME26 != 0 {
        return String::new();
    }
    // SAFETY: `uname` fills the struct it is given, which lives until it
    // returns; `release` is then a NUL-terminated string inside it.
    unsafe {
        let mut names: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut names) != 0 {
            return String::new();
        }
        std::ffi::CStr::from_ptr(names.release.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

/// What the filter plan reads of this host: whether this build has the
/// filter for the architecture it runs as, and the kernel's release from
/// `osrelease` ([`kernel_release`]).
#[cfg(target_os = "linux")]
fn filter_host_here(osrelease: &Path) -> crate::contain::launch::FilterHost {
    use crate::contain::launch::{tracer_order, FilterHost};
    FilterHost {
        built: innerwarden_agent_guard::seccomp::Arch::native().is_some(),
        tracer: tracer_order(&kernel_release(osrelease)),
    }
}

/// The filter a launch hands this host's bwrap, and what it says about it:
/// from this build's architecture, the kernel's release, and one throwaway
/// jail under a filter (two for an identified launch whose host does not take
/// the identified one).
#[cfg(target_os = "linux")]
fn filter_plan_here(bwrap: &Path, identity: bool) -> crate::contain::launch::FilterPlan {
    let host = filter_host_here(Path::new(OSRELEASE));
    crate::contain::launch::filter_plan(identity, host, |rules| {
        filter_probe(bwrap, rules, identity)
    })
}

/// [`filter_plan_here`] asking for the identified filter in every jail,
/// a plain one included (probed under the plain jail's own options): a
/// jail that holds the launcher's record channel keeps its user namespaces
/// closed.
#[cfg(target_os = "linux")]
fn filter_plan_for_channel(bwrap: &Path, identity: bool) -> crate::contain::launch::FilterPlan {
    let host = filter_host_here(Path::new(OSRELEASE));
    crate::contain::launch::filter_plan(true, host, |rules| filter_probe(bwrap, rules, identity))
}

#[cfg(not(target_os = "linux"))]
fn filter_plan_for_channel(bwrap: &Path, identity: bool) -> crate::contain::launch::FilterPlan {
    filter_plan_here(bwrap, identity)
}

#[cfg(not(target_os = "linux"))]
fn filter_plan_here(_bwrap: &Path, _identity: bool) -> crate::contain::launch::FilterPlan {
    crate::contain::launch::FilterPlan {
        filter: None,
        said: Vec::new(),
    }
}

/// What decides the user scope, read from this host.
#[cfg(target_os = "linux")]
fn scope_facts() -> crate::contain::launch::ScopeFacts {
    use crate::contain::launch::{parse_systemd_version, user_manager_socket, ScopeFacts};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let systemd_run = resolve_backend(&["/usr/bin/systemd-run", "/bin/systemd-run"]);
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let user_manager = user_manager_socket(std::env::var("XDG_RUNTIME_DIR").ok().as_deref())
        .and_then(|socket| std::fs::symlink_metadata(socket).ok())
        .is_some_and(|m| m.file_type().is_socket() && m.uid() == uid);
    // Only asked when it could matter: the answer decides one switch.
    let systemd_version = match (&systemd_run, user_manager) {
        (Some(run), true) => {
            let mut command = Command::new(run);
            helper_env(&mut command);
            command
                .arg("--version")
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output()
                .ok()
                .filter(|out| out.status.success())
                .and_then(|out| parse_systemd_version(&String::from_utf8_lossy(&out.stdout)))
        }
        _ => None,
    };
    ScopeFacts {
        systemd_run,
        systemd_version,
        user_manager,
    }
}

/// The scope a dry run would get, as one line.
#[cfg(target_os = "linux")]
fn dry_run_scope_line() -> String {
    use crate::contain::launch::{no_scope_sentence, plan_scope, ScopePlan};
    use innerwarden_agent_guard::identity::SCOPE_UNIT_PREFIX;
    let unit = format!("{SCOPE_UNIT_PREFIX}<instance-id>.scope");
    match plan_scope(&scope_facts(), &unit) {
        ScopePlan::User {
            systemd_run,
            unit,
            no_expand,
        } => format!(
            "scope: {} --user --scope --quiet --unit {unit}{} -- (a new instance id at each launch)",
            systemd_run.display(),
            if no_expand {
                " --expand-environment=no"
            } else {
                ""
            }
        ),
        ScopePlan::None(why) => no_scope_sentence(why),
    }
}

/// What bwrap reported on the info descriptor.
#[cfg(target_os = "linux")]
enum InfoRead {
    Got(crate::contain::launch::InfoFd),
    /// The descriptor closed with nothing written: bwrap never reached the
    /// point where the jail has a pid.
    Nothing,
    Failed(String),
}

/// Read bwrap's report: until it parses, the stream ends, or ten seconds pass.
#[cfg(target_os = "linux")]
fn read_info(reader: &mut std::io::PipeReader) -> InfoRead {
    use crate::contain::launch::{parse_info_fd, InfoError, MAX_INFO_BYTES};
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut got: Vec<u8> = Vec::new();
    loop {
        match parse_info_fd(&got) {
            Ok(info) => return InfoRead::Got(info),
            Err(InfoError::TooLarge) => return InfoRead::Failed(InfoError::TooLarge.to_string()),
            Err(_) => {}
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return InfoRead::Failed("bwrap did not report the jail in time".into());
        }
        let mut poll = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = i32::try_from(left.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: one valid pollfd, count 1.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return InfoRead::Failed("waiting for bwrap failed".into());
        }
        if ready <= 0 {
            continue;
        }
        let mut chunk = [0u8; 512];
        match reader.read(&mut chunk) {
            Ok(0) if got.is_empty() => return InfoRead::Nothing,
            Ok(0) => {
                return match parse_info_fd(&got) {
                    Ok(info) => InfoRead::Got(info),
                    Err(e) => InfoRead::Failed(e.to_string()),
                };
            }
            Ok(n) => {
                got.extend_from_slice(&chunk[..n]);
                if got.len() > MAX_INFO_BYTES {
                    return InfoRead::Failed(InfoError::TooLarge.to_string());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return InfoRead::Failed(format!("reading bwrap's report failed: {e}")),
        }
    }
}

/// Each folder the macOS sandbox keeps in place as itself
/// ([`crate::contain::macos_pins`]) that is not there yet: `~/.config` on an
/// account that has none, and any folder above a place the jail hides that
/// it may write (a folder above where a hidden dotdir leads, or above a
/// profile's hidden home path). Parents before the folders in them.
fn macos_pins_missing(input: &JailInputs) -> Vec<PathBuf> {
    crate::contain::macos_pins(input)
        .into_iter()
        .filter(|folder| std::fs::symlink_metadata(folder).is_err())
        .collect()
}

/// The real run of a macOS jail, after every check: each folder of
/// [`macos_pins_missing`] is made, empty and 0700, as a folder of the
/// person's ([`make_place`]), and said, so no folder appears in the home
/// without a word. The sandbox refuses to make it, so the jail never has
/// to, and none of its programs can put a link of its own at that name. One
/// that cannot be made is said too: no program in the jail can make it
/// either. A dry run makes nothing and names each.
#[cfg(target_os = "macos")]
fn made_before_the_sandbox(input: &JailInputs) {
    for folder in macos_pins_missing(input) {
        if std::fs::symlink_metadata(&folder).is_ok() {
            // Made already, with a folder below it.
            continue;
        }
        if make_place(&folder) {
            eprintln!(
                "innerwarden contain: made {} (empty, 0700), a folder the jail writes in but cannot rename or remove",
                crate::contain::printable(&folder)
            );
        } else {
            eprintln!(
                "innerwarden contain: {} is not there and could not be made; no program in the jail can make it either",
                crate::contain::printable(&folder)
            );
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn made_before_the_sandbox(_input: &JailInputs) {}

fn run_macos(input: &JailInputs) -> ExitCode {
    // The jail's own `~/.claude` ([`crate::contain::ProjectClaude`]), made
    // by the real run before the profile names it: no jail starts without
    // it. A dry run makes nothing.
    #[cfg(unix)]
    let prepared;
    #[cfg(unix)]
    let input = if input.args.dry_run {
        input
    } else {
        prepared = match prepare_project_claude(input) {
            Ok(prepared) => prepared,
            Err(why) => {
                eprintln!("innerwarden contain: refusing to start: {why}");
                return ExitCode::from(2);
            }
        };
        &prepared
    };
    let plan = match build_macos_profile(input) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("innerwarden contain: {e}");
            return ExitCode::from(2);
        }
    };
    if input.args.dry_run {
        println!("# innerwarden contain - DRY RUN (macOS / sandbox-exec)");
        print_plan_env(&plan.env);
        print_credentials_kept_out(input);
        println!("# --- sandbox profile ---");
        println!("{}", plan.profile);
        // What a real run would make in the home; a dry run makes nothing.
        for folder in macos_pins_missing(input) {
            println!(
                "# would make {} (empty, 0700) before the sandbox starts",
                crate::contain::printable(&folder)
            );
        }
        println!("# --- argv ---");
        println!(
            "/usr/bin/sandbox-exec -p <profile> -- {}",
            input.args.child.join(" ")
        );
        return ExitCode::SUCCESS;
    }
    let Some(sb) = resolve_backend(&["/usr/bin/sandbox-exec"]) else {
        eprintln!("innerwarden contain: /usr/bin/sandbox-exec not found (expected on macOS)");
        return ExitCode::from(1);
    };
    if input.args.identity {
        eprintln!(
            "innerwarden contain: --identity needs a PID namespace, which sandbox-exec does not have; no instance record is written"
        );
    }
    // No record, so nothing the host could admit.
    if !crate::contain::launch::starts(input.args.start, false) {
        eprintln!(
            "innerwarden contain: {}",
            crate::contain::launch::NOT_ADMITTED
        );
        return ExitCode::from(2);
    }
    made_before_the_sandbox(input);
    announce(input);
    // argv = [sandbox-exec, -p, <profile>, --, child...]; run argv[1..] under the
    // resolved binary.
    let mut command = Command::new(sb);
    command.args(&plan.argv[1..]).envs(plan.env.iter().cloned());
    without_credentials(&mut command, input);
    exit_from(command.status())
}

fn announce(input: &JailInputs) {
    let backend = if cfg!(target_os = "macos") {
        "sandbox-exec"
    } else {
        "bubblewrap"
    };
    let child = input
        .args
        .child
        .first()
        .map(String::as_str)
        .unwrap_or("command");
    // The PreToolUse hook only screens the CLAUDE agent's commands. For any other
    // child (e.g. codex) be honest: the jail isolates it, but its commands are NOT
    // command-screened.
    let child_base = child.rsplit(['/', '\\']).next().unwrap_or(child);
    let screened = child_base.to_ascii_lowercase().contains("claude");
    if screened {
        eprintln!(
            "innerwarden contain - {child} running inside a {backend} jail (project: {}); commands screened ({}).",
            input.args.project.display(),
            mode_label(&input.args),
        );
    } else {
        eprintln!(
            "innerwarden contain - {child} running inside a {backend} jail (project: {}); WALLS ONLY: its commands are not screened (the guard hook screens Claude Code, not {child_base}).",
            input.args.project.display(),
        );
    }
    eprintln!("{}", crate::contain::iw_folder_said(input));
    if let Some(said) = crate::contain::env_said(&credentials_kept_out(input)) {
        eprintln!("{said}");
    }
}

/// Map a finished child status to an exit code, mapping a signal death to
/// `128 + signal` (shell convention) instead of collapsing it to 1.
fn exit_from(status: std::io::Result<std::process::ExitStatus>) -> ExitCode {
    match status {
        Ok(s) => {
            if let Some(code) = s.code() {
                return ExitCode::from(code.clamp(0, 255) as u8);
            }
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(sig) = s.signal() {
                    return ExitCode::from((128 + sig).clamp(0, 255) as u8);
                }
            }
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("innerwarden contain: failed to launch the jail: {e}");
            ExitCode::from(1)
        }
    }
}

fn print_credentials_kept_out(input: &JailInputs) {
    if let Some(said) = crate::contain::env_said(&credentials_kept_out(input)) {
        println!("#{}", said.trim_start());
    }
}

fn print_plan_env(env: &[(String, String)]) {
    println!("# in-jail env (secret-safe: no LLM/notify config, graph is jail-local)");
    for (k, v) in env {
        println!("#   {k}={v}");
    }
}

#[cfg(test)]
mod tests {
    /// Every program this file starts outside the launch paths runs under
    /// `helper_env` (root's two folders as PATH, no loader variable): Active
    /// Defence reads the same rule off the shipped source before it pins a
    /// release (1.6.4's jail check started `sandbox-exec` with the account's
    /// environment and was held back). The launch paths themselves start the
    /// person's own agent. FAILS ON REVERT of `helper_env` in any helper.
    #[test]
    fn every_helper_this_file_starts_runs_under_helper_env() {
        const LAUNCH_PATHS: &[&str] = &["run_in_place", "run_plain", "run_macos"];
        // Asks the bubblewrap it resolved from absolute paths for its own
        // `--help` and nothing else (Active Defence reads it as allowed as it
        // is, and refuses any argument or environment added to it).
        const HELP_PROBE: &str = "bwrap_binds_fds";
        let text = include_str!("contain_io.rs");
        let shipped = &text[..text.find("#[cfg(test)]\nmod tests {").unwrap_or(text.len())];
        let mut checked = 0;
        for chunk in shipped.split("\nfn ").skip(1) {
            let name = chunk.split(['(', '<']).next().unwrap_or("");
            let body = &chunk[..chunk.find("\n}\n").unwrap_or(chunk.len())];
            if !body.contains("Command::new(") || LAUNCH_PATHS.contains(&name) || name == HELP_PROBE
            {
                continue;
            }
            checked += 1;
            assert!(
                body.contains("helper_env(&mut "),
                "{name} starts a program without helper_env"
            );
        }
        assert!(
            checked >= 3,
            "only {checked} helpers read: the scan stopped matching"
        );
    }

    /// Finding `sandbox-exec` is not a check: ready only when a sandboxed
    /// `true` ran and exited 0; a failed or hung start says so, with what
    /// `sandbox-exec` said. FAILS ON REVERT to the lookup alone (every macOS
    /// read "Ready" with no start made).
    #[test]
    fn a_macos_jail_is_ready_only_when_a_sandbox_started() {
        assert_eq!(sandbox_start_answer(Some((true, String::new()))), Ok(()));
        assert_eq!(
            sandbox_start_answer(Some((false, "sandbox-exec: sandbox_apply: Operation not permitted".into()))),
            Err(vec!["sandbox-exec could not start a sandboxed process here: sandbox-exec: sandbox_apply: Operation not permitted".to_string()])
        );
        assert_eq!(
            sandbox_start_answer(Some((false, String::new()))),
            Err(vec![
                "sandbox-exec could not start a sandboxed process here.".to_string()
            ])
        );
        assert_eq!(
            sandbox_start_answer(None),
            Err(vec![
                "sandbox-exec did not start a sandboxed process within 5 seconds here.".to_string()
            ])
        );
    }

    /// On a Mac the check starts a real sandbox, and its answer is a check
    /// that ran: never the bare lookup's `Ok` for a start that failed.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_macos_jail_check_starts_a_sandbox() {
        let Some(sandbox) = resolve_backend(&["/usr/bin/sandbox-exec"]) else {
            return;
        };
        let outcome = sandbox_exec_starts(&sandbox).expect("sandbox-exec answers within 5 s");
        assert_eq!(jail_start_here(), Some(sandbox_start_answer(Some(outcome))));
    }

    use super::*;

    /// Set in a child these tests start: what it answers.
    #[cfg(target_os = "linux")]
    const CHILD_VAR: &str = "IW_CONTAIN_IO_TEST_CHILD";

    /// A path where no `osrelease` is: the plan's read of a host with no
    /// `/proc`.
    #[cfg(target_os = "linux")]
    const NO_OSRELEASE: &str = "/nonexistent/proc/sys/kernel/osrelease";

    /// What a child these tests start answers, one `key=value` per line.
    #[cfg(target_os = "linux")]
    fn child_side(side: &str) -> Vec<String> {
        use crate::contain::launch::TracerOrder;
        let order = |tracer: TracerOrder| format!("{tracer:?}");
        match side {
            "release" => {
                // SAFETY: as in `kernel_release`.
                let uname = unsafe {
                    let mut names: libc::utsname = std::mem::zeroed();
                    assert_eq!(libc::uname(&mut names), 0);
                    std::ffi::CStr::from_ptr(names.release.as_ptr())
                        .to_string_lossy()
                        .into_owned()
                };
                vec![
                    format!("uname={uname}"),
                    format!(
                        "proc={}",
                        order(filter_host_here(Path::new(OSRELEASE)).tracer)
                    ),
                    format!(
                        "no_proc={}",
                        order(filter_host_here(Path::new(NO_OSRELEASE)).tracer)
                    ),
                    // What an identified launch says there, its probes
                    // passing.
                    format!(
                        "no_proc_said={}",
                        crate::contain::launch::filter_plan(
                            true,
                            filter_host_here(Path::new(NO_OSRELEASE)),
                            |_| crate::contain::launch::ProbeAnswer::Ran,
                        )
                        .said
                        .join(" | ")
                    ),
                ]
            }
            "no_descriptors" => {
                // No descriptor left to open: the probe's pipe cannot be
                // made, so no bwrap may be started for it.
                probe_answers_under_nofile(0)
            }
            "two_descriptors" => {
                // Two descriptors left: the probe's pipe is made, its writer
                // closed, and then starting bwrap (which opens `/dev/null`
                // for each of its three standard streams) runs out.
                let limit = limit_leaving_free_descriptors(2);
                let mut answers = vec![format!("limit={limit}")];
                answers.extend(probe_answers_under_nofile(limit));
                answers
            }
            other => panic!("a child these tests do not know: {other}"),
        }
    }

    /// Each start-up probe's answer, with `/bin/true` as bwrap: a probe that
    /// starts it answers `Ran`.
    #[cfg(target_os = "linux")]
    fn probe_answers() -> Vec<String> {
        [
            innerwarden_agent_guard::seccomp::Rules::Identified,
            innerwarden_agent_guard::seccomp::Rules::Terminal,
        ]
        .into_iter()
        .map(|rules| {
            let answer = filter_probe(Path::new("/bin/true"), rules, true);
            format!("{rules:?}={answer:?}")
        })
        .collect()
    }

    /// The soft descriptor limit under which exactly `free` descriptor
    /// numbers are left unused below it, from the ones open now.
    #[cfg(target_os = "linux")]
    fn limit_leaving_free_descriptors(free: usize) -> u64 {
        let listed: Vec<libc::c_int> = std::fs::read_dir("/proc/self/fd")
            .expect("this test host has /proc")
            .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
            .collect();
        // The listing's own descriptor is closed by now: keep only the open.
        // SAFETY: F_GETFD only reads a descriptor's flags.
        let open: std::collections::BTreeSet<libc::c_int> = listed
            .into_iter()
            .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } != -1)
            .collect();
        let mut left = free;
        let mut fd: libc::c_int = 0;
        loop {
            if !open.contains(&fd) {
                left -= 1;
                if left == 0 {
                    return fd as u64 + 1;
                }
            }
            fd += 1;
        }
    }

    /// [`probe_answers`] with the soft descriptor limit lowered to `limit`
    /// (the hard one kept, so an unprivileged child may lower the soft one
    /// as far as 0).
    #[cfg(target_os = "linux")]
    fn probe_answers_under_nofile(limit: u64) -> Vec<String> {
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit fills the struct it is given and setrlimit reads
        // it.
        let lowered = unsafe {
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut current), 0);
            current.rlim_cur = limit as libc::rlim_t;
            libc::setrlimit(libc::RLIMIT_NOFILE, &current)
        };
        assert_eq!(lowered, 0, "{}", std::io::Error::last_os_error());
        probe_answers()
    }

    /// Run this test binary again as a child (never a fork of the harness)
    /// that answers `side`, under the `UNAME26` personality or with it
    /// cleared, as a launcher started from such a shell inherits it. Every
    /// child runs in [`the_plan_reads_the_running_kernel_without_proc`].
    #[cfg(target_os = "linux")]
    fn answers_of_a_child(side: &str, uname26: bool) -> std::collections::BTreeMap<String, String> {
        use std::os::unix::process::CommandExt;
        let name = module_path!()
            .split_once("::")
            .map(|(_, rest)| format!("{rest}::the_plan_reads_the_running_kernel_without_proc"))
            .unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD_VAR, side)
            .stdin(std::process::Stdio::null());
        // SAFETY: `personality` is one system call on this process's own
        // state, safe between `fork` and `exec`.
        unsafe {
            command.pre_exec(move || {
                let current = libc::personality(0xffff_ffff);
                if current == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                let wanted = if uname26 {
                    current | UNAME26
                } else {
                    current & !UNAME26
                };
                if libc::personality(wanted as u32 as libc::c_ulong) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let out = command.output().expect("run the child");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "child failed: {stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // libtest may print the test's name on the line the first answer
        // starts, so an answer is found anywhere on its line.
        stdout
            .lines()
            .filter_map(|l| l.split_once("answer ").map(|(_, answer)| answer))
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// The plan reads the running kernel's release where `/proc` cannot be
    /// read (a chroot, a container with no `/proc`): `uname` tells it there.
    /// Where `/proc` is readable the plan reads it. Every kernel CI and the
    /// labs run reads as 4.8 or later either way. Run in a child with the
    /// `UNAME26` personality cleared, so the shell that runs the tests does
    /// not decide the answer.
    ///
    /// FAILS ON REVERT: drop the `uname` fallback (a host with no `/proc`
    /// reads as `Unknown`, and an identified jail leaves user namespaces
    /// open on a modern kernel), or read the release from `/proc` alone.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_plan_reads_the_running_kernel_without_proc() {
        if let Ok(side) = std::env::var(CHILD_VAR) {
            for line in child_side(&side) {
                println!("answer {line}");
            }
            return;
        }
        let proc = std::fs::read_to_string(OSRELEASE).expect("this test host has /proc");
        assert_eq!(kernel_release(Path::new(OSRELEASE)), proc.trim());
        let plain = answers_of_a_child("release", false);
        assert_eq!(
            plain["uname"],
            proc.trim(),
            "uname and /proc agree: {plain:?}"
        );
        assert_eq!(plain["proc"], "After", "{plain:?}");
        assert_eq!(plain["no_proc"], "After", "{plain:?}");
        assert_eq!(plain["no_proc_said"], "", "{plain:?}");
    }

    /// A launcher started under the `UNAME26` personality (`setarch
    /// --uname-2.6`, which a shell passes to everything it runs) gets a 2.6
    /// release from `uname` on any modern kernel. The plan still reads the
    /// running kernel from `/proc`, and where `/proc` cannot be read it says
    /// the release is unknown: never that the kernel is older than 4.8. Its
    /// words name what hid it (no `/proc`, and the personality), never a
    /// release that is not a version alone.
    ///
    /// FAILS ON REVERT: read `uname` before `/proc` (`proc` reads `Before`,
    /// and an identified jail says `userns_kernel_too_old` on a 6.x
    /// kernel), take `uname`'s answer under `UNAME26` (`no_proc` reads
    /// `Before`), or say the unread release as one that "does not read as a
    /// version".
    #[cfg(target_os = "linux")]
    #[test]
    fn under_uname26_the_plan_never_reads_an_older_kernel() {
        let old = answers_of_a_child("release", true);
        assert!(
            old["uname"].starts_with("2.6."),
            "the child runs under UNAME26: {old:?}"
        );
        assert_eq!(old["proc"], "After", "{old:?}");
        assert_eq!(old["no_proc"], "Unknown", "{old:?}");
        let said: Vec<&str> = old["no_proc_said"].split(" | ").collect();
        assert_eq!(said.len(), 2, "{said:?}");
        assert!(said[0].contains("(userns_kernel_unknown)"), "{said:?}");
        assert!(said[1].contains("(filter_kernel_unknown)"), "{said:?}");
        for line in said {
            assert!(
                line.contains("no /proc and a personality such as setarch --uname-2.6"),
                "{line}"
            );
            assert!(!line.contains("does not read as a version"), "{line}");
            assert!(!line.contains("This kernel is older"), "{line}");
        }
    }

    /// A start-up probe whose filter pipe cannot be made (the launcher is
    /// out of descriptors) starts no bwrap and answers that the filter was
    /// not handed in, which the plan says as the launcher's failure, never
    /// as bubblewrap's.
    ///
    /// FAILS ON REVERT: answer a lost pipe as a failed probe (`Failed`).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_probe_whose_pipe_cannot_be_made_says_it_was_not_handed() {
        let answers = answers_of_a_child("no_descriptors", false);
        assert_eq!(answers["Identified"], "NotHanded", "{answers:?}");
        assert_eq!(answers["Terminal"], "NotHanded", "{answers:?}");
    }

    /// A start-up probe whose pipe was made, but whose bwrap the launcher
    /// could not start (two descriptors left: the pipe takes them, and
    /// starting a program needs `/dev/null` three times) never ran bwrap:
    /// it answers that the filter was not handed in, the launcher's words,
    /// never that bubblewrap could not start a jail.
    ///
    /// FAILS ON REVERT: answer a failed start `Failed` whatever its cause.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_probe_whose_bwrap_cannot_be_started_says_it_was_not_handed() {
        let answers = answers_of_a_child("two_descriptors", false);
        assert_eq!(answers["Identified"], "NotHanded", "{answers:?}");
        assert_eq!(answers["Terminal"], "NotHanded", "{answers:?}");
    }

    /// What the launcher puts on bwrap's pipe is the library's filter
    /// (`innerwarden_agent_guard::seccomp`), byte for byte, for each set of
    /// rules: the bytes end where the program does, and the end bwrap reads
    /// is inherited across its `exec`.
    ///
    /// FAILS ON REVERT: put any other bytes on the pipe (the other rules, or
    /// a program built here instead of by the library).
    #[cfg(target_os = "linux")]
    #[test]
    fn the_launcher_hands_bwrap_the_librarys_filter_bytes() {
        use innerwarden_agent_guard::seccomp::{filter, Arch, Rules};
        use std::io::Read;
        use std::os::fd::AsRawFd;
        let arch = Arch::native().expect("a Linux build the filter knows");
        for rules in [Rules::Identified, Rules::Terminal] {
            let mut reader = filter_pipe(rules).expect("the filter's pipe");
            // SAFETY: F_GETFD on a descriptor this test owns.
            let flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFD) };
            assert_eq!(flags & libc::FD_CLOEXEC, 0, "{rules:?} inherited");
            let mut got = Vec::new();
            reader.read_to_end(&mut got).unwrap();
            assert_eq!(got, filter(arch, rules), "{rules:?}");
        }
    }

    /// One loopback listener that answers its first request with `status`.
    #[cfg(unix)]
    fn answering(status: &'static str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // The whole request first, headers and body: answering and
                // closing with the body unread resets the connection on Linux
                // and the client sees an error instead of the status.
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                let (mut head_end, mut length) = (None, 0usize);
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                    if head_end.is_none() {
                        if let Some(at) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            head_end = Some(at + 4);
                            length = String::from_utf8_lossy(&request[..at])
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .and_then(|v| v.trim().parse().ok())
                                })
                                .unwrap_or(0);
                        }
                    }
                    if head_end.is_some_and(|end| request.len() >= end + length) {
                        break;
                    }
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
            }
        });
        format!("http://127.0.0.1:{port}/api/agent/contain-scope")
    }

    /// Where Active Defence is installed but its agent has no such route (an
    /// older release, the route off, no session), the request is refused at
    /// once and the launch does not wait for a scope that cannot come. The
    /// wait is only for a request the agent took.
    ///
    /// FAILS ON REVERT: wait whatever `send_report` answered and the probe is
    /// called and the launch waits the whole wait.
    #[cfg(unix)]
    #[test]
    fn a_system_scope_is_waited_for_only_when_the_request_was_taken() {
        use std::cell::Cell;
        use std::time::{Duration, Instant};
        let body = serde_json::json!({ "instance": "abc" });
        let closed = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            format!("http://127.0.0.1:{port}/api/agent/contain-scope")
        };
        for url in [
            answering("404 Not Found"),
            answering("401 Unauthorized"),
            answering("405 Method Not Allowed"),
            closed,
        ] {
            let probes = Cell::new(0);
            let started = Instant::now();
            let got = await_system_scope(
                crate::agent_report::send_report(&url, &body),
                Duration::from_secs(3),
                || {
                    probes.set(probes.get() + 1);
                    None::<()>
                },
                |_| {},
            );
            assert_eq!(got, None, "{url}");
            assert_eq!(probes.get(), 0, "{url}: nothing to wait for");
            assert!(started.elapsed() < Duration::from_secs(2), "{url}");
        }
        // Taken: the kernel is asked until it shows the jail, or the wait ends.
        let probes = Cell::new(0);
        let got = await_system_scope(
            crate::agent_report::send_report(&answering("200 OK"), &body),
            Duration::from_secs(3),
            || {
                probes.set(probes.get() + 1);
                (probes.get() == 2).then_some("seen")
            },
            |_| {},
        );
        assert_eq!((got, probes.get()), (Some("seen"), 2));
        let started = Instant::now();
        let never = await_system_scope(Ok(()), Duration::from_millis(250), || None::<()>, |_| {});
        assert_eq!(never, None);
        assert!(started.elapsed() >= Duration::from_millis(250));
    }

    // The trust decision is tested on facts handed in. It used to be tested
    // on a file under the checkout, so its answer depended on every directory
    // above the checkout: one group-writable or foreign-owned ancestor and the
    // secure backend was refused, and the refusal tests passed whatever they
    // changed.

    #[cfg(unix)]
    fn dir(uid: u32, permissions: u32) -> PathEntry {
        PathEntry {
            symlink: false,
            file: false,
            dir: true,
            uid,
            mode: 0o040_000 | permissions,
        }
    }

    #[cfg(unix)]
    fn file(uid: u32, permissions: u32) -> PathEntry {
        PathEntry {
            symlink: false,
            file: true,
            dir: false,
            uid,
            mode: 0o100_000 | permissions,
        }
    }

    #[cfg(unix)]
    fn link() -> PathEntry {
        PathEntry {
            symlink: true,
            file: false,
            dir: false,
            uid: 0,
            mode: 0o120_777,
        }
    }

    /// `/usr/bin/bwrap` as a distribution installs it: root's, 0755, under
    /// root's 0755 directories.
    #[cfg(unix)]
    fn installed() -> BackendFacts {
        BackendFacts {
            components: vec![dir(0, 0o755), dir(0, 0o755), dir(0, 0o755), file(0, 0o755)],
            chain: vec![file(0, 0o755), dir(0, 0o755), dir(0, 0o755), dir(0, 0o755)],
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_root_owned_backend_no_other_account_can_write_is_trusted() {
        assert!(backend_trusted(&installed()));
        let mut owner_only = installed();
        owner_only.chain[0] = file(0, 0o700);
        owner_only.components[3] = file(0, 0o700);
        assert!(
            backend_trusted(&owner_only),
            "an execute bit for root is enough"
        );
    }

    /// Each unsafe fact alone refuses the backend: every case is the trusted
    /// install with exactly that one fact changed.
    #[cfg(unix)]
    #[test]
    fn each_unsafe_fact_alone_refuses_the_backend() {
        assert!(
            backend_trusted(&installed()),
            "the starting point is trusted"
        );
        // What is unsafe, and the change that makes it so.
        type Case = (&'static str, fn(&mut BackendFacts));
        let cases: &[Case] = &[
            ("the executable has no execute bit", |f| {
                f.chain[0] = file(0, 0o644)
            }),
            ("the executable is group-writable", |f| {
                f.chain[0] = file(0, 0o775)
            }),
            ("the executable is writable by anyone", |f| {
                f.chain[0] = file(0, 0o757)
            }),
            ("the executable is another account's", |f| {
                f.chain[0] = file(1000, 0o755)
            }),
            ("the executable is a directory", |f| {
                f.chain[0] = dir(0, 0o755)
            }),
            ("the executable is a symlink", |f| f.chain[0] = link()),
            ("a directory above it is group-writable", |f| {
                f.chain[1] = dir(0, 0o775)
            }),
            ("a directory above it is world-writable, sticky", |f| {
                f.chain[2] = dir(0, 0o1777)
            }),
            ("a directory above it is another account's", |f| {
                f.chain[1] = dir(1000, 0o755)
            }),
            ("`/` is another account's", |f| {
                f.chain[3] = dir(1000, 0o755)
            }),
            ("an entry above it is not a directory", |f| {
                f.chain[2] = file(0, 0o755)
            }),
            ("a component as written is a symlink", |f| {
                f.components.truncate(2);
                f.components[1] = link();
                f.chain.clear();
            }),
            (
                "a component as written is a symlink, chain read anyway",
                |f| {
                    f.components[1] = link();
                },
            ),
            ("nothing was resolved", |f| f.chain.clear()),
            ("no component was read", |f| f.components.clear()),
        ];
        for &(unsafe_fact, change) in cases {
            let mut facts = installed();
            change(&mut facts);
            assert_ne!(
                facts,
                installed(),
                "{unsafe_fact}: the case changes nothing"
            );
            assert!(!backend_trusted(&facts), "trusted although {unsafe_fact}");
        }
    }

    /// A file of root's that is read, not run (the key the hook holds the
    /// host's answer to), is held to the backend's rules without an execute
    /// bit, with root as the reader sees it.
    ///
    /// FAILS ON REVERT: drop the owner check from `sound_root_file` and the
    /// file of another account is believed.
    #[cfg(unix)]
    #[test]
    fn a_root_file_is_held_to_the_backends_rules_without_an_execute_bit() {
        let mut key = installed();
        key.chain[0] = file(0, 0o644);
        key.components[3] = file(0, 0o644);
        let root = |uid: u32| uid == 0;
        assert!(root_file_trusted(&key, &root));
        assert!(
            !backend_trusted(&key),
            "a backend still needs its execute bit"
        );
        let mut seen = key.clone();
        for entry in seen.chain.iter_mut().chain(seen.components.iter_mut()) {
            entry.uid = 65534;
        }
        assert!(!root_file_trusted(&seen, &root));
        assert!(root_file_trusted(&seen, &|uid| uid == 65534));
        type Case = (&'static str, fn(&mut BackendFacts));
        let cases: &[Case] = &[
            ("the file is another account's", |f| {
                f.chain[0] = file(1000, 0o644)
            }),
            ("the file is group-writable", |f| {
                f.chain[0] = file(0, 0o664)
            }),
            ("the file is a directory", |f| f.chain[0] = dir(0, 0o755)),
            ("the file is a symlink", |f| f.chain[0] = link()),
            ("a directory above it is world-writable", |f| {
                f.chain[1] = dir(0, 0o757)
            }),
            ("a directory above it is another account's", |f| {
                f.chain[2] = dir(1000, 0o755)
            }),
            ("a component as written is a symlink", |f| {
                f.components[1] = link()
            }),
            ("nothing was resolved", |f| f.chain.clear()),
        ];
        for &(unsafe_fact, change) in cases {
            let mut facts = key.clone();
            change(&mut facts);
            assert!(
                !root_file_trusted(&facts, &root),
                "trusted although {unsafe_fact}"
            );
        }
    }

    /// The facts are read from the file system as it is, a symlink described
    /// and not followed. Nothing here depends on the directories above the
    /// temporary root: no test asks whether a real path is trusted.
    #[cfg(unix)]
    #[test]
    fn backend_facts_read_each_entry_without_following_a_symlink() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        let root = tempfile::tempdir().unwrap();
        // macOS puts the temporary directory under the `/var` symlink.
        let root = std::fs::canonicalize(root.path()).unwrap();
        let backend = root.join("bwrap");
        std::fs::write(&backend, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&backend, std::fs::Permissions::from_mode(0o710)).unwrap();
        let owner = std::fs::metadata(&backend).unwrap().uid();

        let facts = backend_facts(&backend).expect("an existing absolute path is read");
        assert_eq!(facts.components.len(), backend.components().count());
        assert!(facts.components.iter().all(|entry| !entry.symlink));
        assert_eq!(facts.chain.len(), backend.ancestors().count());
        let executable = facts.chain[0];
        assert!(executable.file && !executable.dir && !executable.symlink);
        assert_eq!((executable.uid, executable.mode & 0o7777), (owner, 0o710));
        assert_eq!(facts.components.last(), Some(&executable));
        assert!(facts.chain[1..].iter().all(|entry| entry.dir));

        let link_path = root.join("bwrap-link");
        symlink(&backend, &link_path).unwrap();
        let facts = backend_facts(&link_path).expect("a symlink is read, not followed");
        assert!(facts.components.last().unwrap().symlink);
        assert!(facts.chain.is_empty(), "the symlink's target was read");
        assert!(!backend_trusted(&facts));

        assert_eq!(backend_facts(Path::new("bwrap")), None, "a relative path");
        assert_eq!(backend_facts(&root.join("missing")), None, "a missing path");
    }

    #[cfg(unix)]
    fn me() -> u32 {
        use std::os::unix::fs::MetadataExt;
        let probe = tempfile::tempdir().unwrap();
        std::fs::metadata(probe.path()).unwrap().uid()
    }

    #[cfg(unix)]
    #[test]
    fn a_launch_record_is_written_private_whole_and_alone() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("state/innerwarden/instances");
        let id = "0123456789abcdef0123456789abcdef";
        let path = write_launch_record(&dir, id, b"{\"a\":1}", me()).unwrap();
        assert_eq!(path, dir.join(format!("{id}.json")));
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"a\":1}");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&dir), 0o700);
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(format!("{id}.json"))]);
    }

    #[cfg(unix)]
    #[test]
    fn a_launch_record_is_not_written_through_a_bad_directory_or_name() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let id = "0123456789abcdef0123456789abcdef";

        // a name that is not an id never becomes a path
        let dir = root.path().join("ok");
        for bad in ["../evil", "a/b", "", "UPPER", "x.json"] {
            assert!(
                write_launch_record(&dir, bad, b"{}", me()).is_err(),
                "{bad}"
            );
        }

        // the directory is a symlink to somewhere else: refused, nothing lands there
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let link = root.path().join("link");
        symlink(&elsewhere, &link).unwrap();
        assert!(write_launch_record(&link, id, b"{}", me()).is_err());
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);

        // the directory belongs to someone else
        let foreign = root.path().join("foreign");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(write_launch_record(&foreign, id, b"{}", me() + 1).is_err());

        // anyone but the owner can write the directory
        let open = root.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(write_launch_record(&open, id, b"{}", me()).is_err());
        assert_eq!(std::fs::read_dir(&open).unwrap().count(), 0);

        // a planted symlink at the temp name is not followed
        let guarded = root.path().join("guarded");
        std::fs::create_dir(&guarded).unwrap();
        std::fs::set_permissions(&guarded, std::fs::Permissions::from_mode(0o700)).unwrap();
        let victim = root.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        symlink(&victim, guarded.join(format!(".{id}.tmp"))).unwrap();
        assert!(write_launch_record(&guarded, id, b"{}", me()).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    }

    /// The project path beside a record is written like the record (private,
    /// whole, never through a planted link) and only as a plain absolute path
    /// that the dashboard's reader takes back.
    #[cfg(unix)]
    #[test]
    fn a_project_path_is_written_beside_the_record_as_one_line() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("instances");
        let id = "0123456789abcdef0123456789abcdef";
        let project = root.path().join("my-app");
        let path = write_project_path(&dir, id, &project, me()).unwrap();
        assert_eq!(path, dir.join(format!("{id}.project")));
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            crate::contain::launch::parse_project_path(&bytes, "my-app"),
            Some(project.clone())
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_project_path(&dir, "../x", &project, me()).is_err());
        assert!(write_project_path(&dir, id, Path::new("rel/my-app"), me()).is_err());
        let guarded = root.path().join("guarded");
        std::fs::create_dir(&guarded).unwrap();
        std::fs::set_permissions(&guarded, std::fs::Permissions::from_mode(0o700)).unwrap();
        let victim = root.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        symlink(&victim, guarded.join(format!(".{id}.project.tmp"))).unwrap();
        assert!(write_project_path(&guarded, id, &project, me()).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    }

    /// The jail's graph is read from a real folder and file of the user, and
    /// whatever else the agent may have left there is refused without being
    /// followed or waited on.
    #[cfg(unix)]
    #[test]
    fn the_jails_graph_is_read_only_from_a_real_file_of_the_user() {
        use crate::contain::launch::JailGraph;
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("proj");
        std::fs::create_dir(&project).unwrap();
        assert_eq!(read_jail_graph(&project, me()), JailGraph::Absent);

        let dir = project.join(".innerwarden");
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(read_jail_graph(&project, me()), JailGraph::Absent);

        let graph = dir.join("graph.json");
        std::fs::write(&graph, br#"{"nodes":[],"edges":[]}"#).unwrap();
        assert_eq!(
            read_jail_graph(&project, me()),
            JailGraph::Read(innerwarden_graph::Graph::default())
        );
        assert_eq!(
            read_jail_graph(&project, me() + 1),
            JailGraph::Unreadable("graph_dir_not_owned"),
            "another user's folder"
        );

        std::fs::write(&graph, b"{not a graph").unwrap();
        assert_eq!(
            read_jail_graph(&project, me()),
            JailGraph::Unreadable("graph_malformed")
        );

        // the file is a link to another file of the user's
        let elsewhere = root.path().join("elsewhere.json");
        std::fs::write(&elsewhere, br#"{"nodes":[],"edges":[]}"#).unwrap();
        std::fs::remove_file(&graph).unwrap();
        symlink(&elsewhere, &graph).unwrap();
        assert_eq!(
            read_jail_graph(&project, me()),
            JailGraph::Unreadable("graph_not_a_regular_file")
        );

        // a FIFO: refused at once, never waited on
        std::fs::remove_file(&graph).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(&graph)
            .status()
            .unwrap();
        assert!(made.success());
        let started = std::time::Instant::now();
        assert_eq!(
            read_jail_graph(&project, me()),
            JailGraph::Unreadable("graph_not_a_regular_file")
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(5));

        // a folder in the file's place
        std::fs::remove_file(&graph).unwrap();
        std::fs::create_dir(&graph).unwrap();
        assert_eq!(
            read_jail_graph(&project, me()),
            JailGraph::Unreadable("graph_not_a_regular_file")
        );

        // the folder itself is a link to a folder with a good graph in it
        let real = root.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("graph.json"), br#"{"nodes":[],"edges":[]}"#).unwrap();
        std::fs::remove_dir(&graph).unwrap();
        std::fs::remove_dir(&dir).unwrap();
        symlink(&real, &dir).unwrap();
        assert_eq!(
            read_jail_graph(&project, me()),
            JailGraph::Unreadable("graph_dir_is_a_symlink")
        );
    }

    /// CWWT-SEC-1: a `..` after a step that is not there takes the way back
    /// to folders that are there, and a link there is a link. The walk read
    /// no step after the first that was not there, so `proj/gone/../L/x`
    /// led to `proj/L/x` as written, the link `L` (to a hidden folder of
    /// the home) never seen nor followed, and a worktree named so was bound
    /// by that spelling while bwrap followed the link. Every step is read
    /// now: the way leads where `L` leads, `L` is a link on it, and the
    /// first step that is not there is found.
    ///
    /// FAILS ON REVERT: stop reading steps after the first that is not
    /// there (as before) and the way leads to `proj/L/x`, with no link.
    #[cfg(unix)]
    #[test]
    fn a_link_after_a_step_that_is_not_there_and_a_dotdot_is_still_followed() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir_all(r.join("home/.kube/x")).unwrap();
        std::fs::create_dir_all(r.join("proj")).unwrap();
        symlink(r.join("home/.kube"), r.join("proj/L")).unwrap();
        let (at, links) = trace(&r.join("proj/gone/../L/x")).unwrap();
        assert_eq!(at, r.join("home/.kube/x"));
        assert_eq!(links, [r.join("proj/L")]);
        assert_eq!(
            walk(&r.join("proj/gone/../L/x")).missing,
            Some(r.join("proj/gone"))
        );
        // Below a step that is not there nothing is a link: as written.
        assert_eq!(
            trace(&r.join("proj/gone/L/x")),
            Some((r.join("proj/gone/L/x"), Vec::new()))
        );
        assert_eq!(walk(&r.join("proj/L/x")).missing, None);
    }

    /// M30-CW-link: where a place the jail hides really is on the host,
    /// every link on the way followed: a link into another folder, a chain
    /// of two links (one with `..`), a link to a folder above, a link that
    /// leads to nothing yet (the rest as written: where `ssh` would make the
    /// folder through it), and a loop (`None`). Where nothing is a link it
    /// is the path itself, as `canonicalize` gives it.
    ///
    /// FAILS ON REVERT: follow one link only (stop at the second) and the
    /// chain is taken for a loop, so nothing is covered through it.
    #[cfg(unix)]
    #[test]
    fn a_hidden_place_is_taken_where_every_link_on_the_way_leads() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir_all(home.join(".config/ssh")).unwrap();
        std::fs::create_dir_all(home.join("dots/gnupg")).unwrap();
        std::fs::create_dir_all(home.join(".ordinary")).unwrap();
        symlink(".config/ssh", home.join(".ssh")).unwrap();
        // A chain: `.gnupg` to `.mid`, `.mid` to `.config/../dots/gnupg`.
        symlink(".mid", home.join(".gnupg")).unwrap();
        symlink(".config/../dots/gnupg", home.join(".mid")).unwrap();
        // A link to a folder above: `.up/aws` is `<home>/.aws-real`.
        std::fs::create_dir_all(home.join(".aws-real")).unwrap();
        symlink(&home, home.join(".up")).unwrap();
        // Leads to nothing yet, through an absolute link.
        symlink(home.join(".config/not-yet/keys"), home.join(".dangling")).unwrap();
        symlink(".loop-b", home.join(".loop-a")).unwrap();
        symlink(".loop-a", home.join(".loop-b")).unwrap();
        for (path, leads) in [
            (".ssh", Some(".config/ssh")),
            (".ssh/id_test", Some(".config/ssh/id_test")),
            (".gnupg", Some("dots/gnupg")),
            (".up/.aws-real", Some(".aws-real")),
            (".dangling", Some(".config/not-yet/keys")),
            (".dangling/sub/../file", Some(".config/not-yet/keys/file")),
            (".ordinary", Some(".ordinary")),
            (".not-there/x", Some(".not-there/x")),
            (".loop-a", None),
            (".loop-a/x", None),
        ] {
            assert_eq!(
                leads_to(&home.join(path)),
                leads.map(|rest| home.join(rest)),
                "{path}"
            );
        }
        assert_eq!(
            leads_to(&home.join(".gnupg")).unwrap(),
            std::fs::canonicalize(home.join(".gnupg")).unwrap()
        );
        assert_eq!(leads_to(Path::new("relative")), None);
    }

    /// Each link followed on the way is found where it sits, and a place
    /// is steered only through a link in a folder the jail writes: a
    /// `.env` link in the project always; a dotdir only past its own entry
    /// (`~/.ssh` itself sits in the home, which the jail never writes),
    /// through a second link in `~/.config`.
    ///
    /// FAILS ON REVERT: count the dotdir's own entry, or skip the links
    /// `trace` follows, and `.ssh` and `.env` swap answers; drop the links
    /// of a way that loops and `~/.aws` names none.
    #[cfg(unix)]
    #[test]
    fn a_place_is_steerable_only_through_a_link_the_jail_can_change() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(root.path()).unwrap();
        let project = home.join("proj");
        std::fs::create_dir_all(home.join(".config/ssh-real")).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        symlink(".config/ssh", home.join(".ssh")).unwrap();
        symlink("ssh-real", home.join(".config/ssh")).unwrap();
        symlink(home.join(".config/ssh-real"), home.join(".gnupg")).unwrap();
        symlink(home.join(".gnupg"), project.join(".env")).unwrap();
        let (at, links) = trace(&home.join(".ssh")).unwrap();
        assert_eq!(at, home.join(".config/ssh-real"));
        assert_eq!(links, [home.join(".ssh"), home.join(".config/ssh")]);
        let writable = [home.join(".config"), project.clone()];
        assert_eq!(
            hidden_place(&home.join(".ssh"), &writable, true).steered_by,
            Some(home.join(".config/ssh"))
        );
        assert_eq!(
            hidden_place(&home.join(".gnupg"), &writable, true).steered_by,
            None
        );
        assert_eq!(
            hidden_place(&project.join(".env"), &writable, false).steered_by,
            Some(project.join(".env"))
        );
        assert_eq!(
            hidden_place(&project.join(".env"), &[], false).steered_by,
            None
        );
        // M30C-1: a way that loops still names the link the jail can change.
        symlink("loop-b", home.join(".config/loop-a")).unwrap();
        symlink("loop-a", home.join(".config/loop-b")).unwrap();
        symlink(".config/loop-a", home.join(".aws")).unwrap();
        let looped = hidden_place(&home.join(".aws"), &writable, true);
        assert_eq!(looped.leads_to, None);
        assert_eq!(looped.steered_by, Some(home.join(".config/loop-a")));
        let place = hidden_place(&home.join(".gnupg"), &writable, true);
        assert_eq!(place.leads_to, Some(home.join(".config/ssh-real")));
        assert!(place.there && place.is_dir);
    }

    /// JP-2 completeness: a hidden home path names every link on its way,
    /// each where it sits on the host, on both OSes: the macOS sandbox keeps
    /// each in place ([`crate::contain::macos_pins`]), and Linux refuses the
    /// first the jail can change. With `~/.cache/git` a link to
    /// `~/.local/a/git` and `~/.local/a` a link to `~/.local/b`, the second
    /// link is above neither the path nor where it leads.
    ///
    /// FAILS ON REVERT: give `hidden_home_facts` no links and the chain
    /// names none.
    #[cfg(unix)]
    #[test]
    fn a_hidden_home_path_names_every_link_on_its_way() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir_all(home.join(".cache")).unwrap();
        std::fs::create_dir_all(home.join(".local/b/git/credential")).unwrap();
        symlink(home.join(".local/a/git"), home.join(".cache/git")).unwrap();
        symlink("b", home.join(".local/a")).unwrap();
        let nominal = home.join(".cache/git/credential");
        let writable = [home.join(".cache"), home.join(".local")];
        for macos in [true, false] {
            let found = hidden_home_facts(&home, std::slice::from_ref(&nominal), &writable, macos);
            assert_eq!(
                found[0].links,
                [home.join(".cache/git"), home.join(".local/a")]
            );
            assert_eq!(found[0].real, Some(home.join(".local/b/git/credential")));
            assert_eq!(
                found[0].steered_by,
                (!macos).then(|| home.join(".cache/git")),
                "macos={macos}"
            );
        }
        // No link on the way: none.
        let plain = home.join(".local/b/git/credential");
        let found = hidden_home_facts(&home, &[plain], &writable, true);
        assert!(found[0].links.is_empty());
    }

    /// M30C-3: the launcher finds every link inside a dotdir the jail
    /// never shows, at any depth, by the name the host reaches it by, and
    /// never walks through one (a link to a folder is one place, not a
    /// folder to look in). Each that leads out of the dotdir is a place
    /// the jail hides ([`crate::contain::HiddenPlace::inner`]), also inside
    /// a dotdir that is itself a link; one that stays in it (Firefox's
    /// `lock`, a link to a name in the same folder) is none. A dotdir
    /// deeper than the walk goes is said.
    ///
    /// FAILS ON REVERT: look only at the dotdir's own entry and no link
    /// inside is found; walk through a link and `keys/inside` is found.
    #[cfg(unix)]
    #[test]
    fn the_links_inside_a_dotdir_the_jail_never_shows_are_found() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(root.path()).unwrap();
        let dots = home.join(".config/dotfiles");
        std::fs::create_dir_all(dots.join("keydir")).unwrap();
        std::fs::write(dots.join("config"), "Host *\n").unwrap();
        std::fs::write(dots.join("keydir/inside"), "").unwrap();
        std::fs::create_dir_all(home.join(".ssh/sub")).unwrap();
        std::fs::create_dir_all(home.join(".ssh/real")).unwrap();
        symlink(dots.join("config"), home.join(".ssh/config")).unwrap();
        symlink(dots.join("id"), home.join(".ssh/sub/id")).unwrap();
        symlink("127.0.0.1:+4242", home.join(".ssh/lock")).unwrap();
        symlink("real", home.join(".ssh/self")).unwrap();
        symlink(dots.join("keydir"), home.join(".ssh/keys")).unwrap();
        std::fs::create_dir_all(home.join("dots/gnupg")).unwrap();
        symlink("dots/gnupg", home.join(".gnupg")).unwrap();
        symlink(dots.join("gpg.conf"), home.join("dots/gnupg/gpg.conf")).unwrap();
        let mut deep = home.join(".aws");
        for _ in 0..=crate::contain::INNER_WALK_DEPTH {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        let (mut links, cut) = links_inside(&home.join(".ssh"));
        links.sort();
        assert!(!cut);
        assert_eq!(
            links,
            ["config", "keys", "lock", "self", "sub/id"].map(|name| home.join(".ssh").join(name))
        );
        assert_eq!(links_inside(&home.join(".nothing")), (Vec::new(), false));
        let facts = crate::contain::PlaceFacts {
            home: home.clone(),
            writable: vec![home.join(".config")],
            ..Default::default()
        };
        let mut left = Vec::new();
        let places = never_shown_places(&home, &facts, &mut left);
        let mut inner: Vec<PathBuf> = places
            .iter()
            .filter(|place| place.inner)
            .map(|place| place.nominal.clone())
            .collect();
        inner.sort();
        assert_eq!(
            inner,
            [
                home.join(".gnupg/gpg.conf"),
                home.join(".ssh/config"),
                home.join(".ssh/keys"),
                home.join(".ssh/sub/id"),
            ]
        );
        let config = places
            .iter()
            .find(|place| place.nominal == home.join(".ssh/config"))
            .unwrap();
        assert_eq!(config.leads_to, Some(dots.join("config")));
        assert!(config.there && !config.is_dir && config.steered_by.is_none());
        assert_eq!(left, [crate::contain::left_unwalked(&home.join(".aws"))]);
    }

    /// The agent's command is where the jail's shell finds it: a path as
    /// given, or the first file of that name in a folder of `PATH`.
    #[cfg(unix)]
    #[test]
    fn the_agents_command_is_found_as_the_shell_finds_it() {
        assert_eq!(
            command_path("/opt/claude/bin/claude"),
            Some(PathBuf::from("/opt/claude/bin/claude"))
        );
        assert_eq!(
            command_path("bin/claude"),
            Some(std::env::current_dir().unwrap().join("bin/claude"))
        );
        assert_eq!(command_path("sh").map(|p| p.is_file()), Some(true));
        assert_eq!(command_path("innerwarden-no-such-command-x9"), None);
    }

    /// A path goes through a link below the home folder the jail binds it
    /// in (where a mount through it would abort bwrap) only for a link
    /// below that folder: the folder itself a link is bound where it leads,
    /// and a path in a folder the jail does not bind is not in the jail.
    #[cfg(unix)]
    #[test]
    fn a_path_goes_through_a_link_only_below_the_folder_the_jail_binds() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir_all(home.join("dots/config/iw")).unwrap();
        std::fs::create_dir_all(home.join(".local")).unwrap();
        std::fs::create_dir_all(home.join("elsewhere")).unwrap();
        symlink("dots/config", home.join(".config")).unwrap();
        symlink(home.join("elsewhere"), home.join(".local/state")).unwrap();
        symlink("dots", home.join(".unbound")).unwrap();
        std::fs::create_dir_all(home.join(".cache")).unwrap();
        for (path, through) in [
            (".config/iw", false),
            (".config/innerwarden", false),
            (".local/state/innerwarden/instances", true),
            (".local/share", false),
            (".unbound/config", false),
            (".cache/x/y", false),
        ] {
            assert_eq!(
                goes_through_a_link(&home, &home.join(path)),
                through,
                "{path}"
            );
        }
        symlink("../dots/config/iw", home.join("dots/config/innerwarden")).unwrap();
        assert!(goes_through_a_link(
            &home,
            &home.join(".config/innerwarden")
        ));
    }

    /// A place not there yet is made empty and 0700, each folder on the
    /// way the same, as a folder of the person's; never through a link or a
    /// file on the way, and one that is there already is no failure.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_place_not_there_yet_is_made_as_a_folder_of_the_persons() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let place = root.path().join("cfg/ssh");
        assert!(make_place(&place));
        for made in [root.path().join("cfg"), place.clone()] {
            let mode = std::fs::metadata(&made).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", made.display());
        }
        assert!(make_place(&place), "there already");
        std::fs::write(root.path().join("file"), "").unwrap();
        assert!(!make_place(&root.path().join("file/below")));
        symlink(root.path().join("cfg"), root.path().join("link")).unwrap();
        assert!(!make_place(&root.path().join("link")));
    }

    /// CWNF (CW-extra-nofollow review), on this host's own disk: an extra
    /// path is found where it leads, each link on the way kept with the
    /// folder it sits in, so the planner can tell a link a program in a jail
    /// could change from the person's own. A link at the path, one on the
    /// way and one of the person's are each listed; a real folder has none;
    /// a path not there, or one a link leads to nothing through, is missing;
    /// links that loop are said; a path with `..` is not plain. On macOS a
    /// path spelled in another case than the disk's is found as the disk
    /// spells it.
    ///
    /// FAILS ON REVERT: find each path with `std::fs::canonicalize` alone
    /// (no links kept) and the planted link at `.local/share/demo` is found
    /// with none, so nothing tells it from the person's own.
    #[cfg(unix)]
    #[test]
    fn an_extra_path_is_found_where_it_leads_with_each_link_on_the_way() {
        use crate::contain::ExtraFound;
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::create_dir_all(home.join("sdk/lib")).unwrap();
        std::fs::create_dir_all(home.join(".local/share")).unwrap();
        std::fs::create_dir_all(home.join("private/ro")).unwrap();
        symlink(home.join(".ssh"), home.join(".local/share/demo")).unwrap();
        symlink("private", home.join("shared")).unwrap();
        symlink(home.join("nowhere"), home.join("dangling")).unwrap();
        symlink("loop", home.join("loop")).unwrap();
        let found = |to: &str, links: &[&str]| ExtraFound::Found {
            leads_to: home.join(to),
            links: links.iter().map(|link| home.join(link)).collect(),
        };
        let cases = [
            (".local/share/demo", found(".ssh", &[".local/share/demo"])),
            (".local/share/demo/id", ExtraFound::Missing),
            ("shared/ro", found("private/ro", &["shared"])),
            ("sdk/lib", found("sdk/lib", &[])),
            ("dangling", ExtraFound::Missing),
            ("gone", ExtraFound::Missing),
            ("loop", ExtraFound::Loop),
        ];
        for (path, want) in &cases {
            let path = home.join(path);
            assert_eq!(&extra_found(&path), want, "{}", path.display());
        }
        assert_eq!(extra_found(&home.join("sdk/../.ssh")), ExtraFound::NotPlain);
        #[cfg(target_os = "macos")]
        if home.join("SDK").exists() {
            assert_eq!(extra_found(&home.join("SDK/Lib")), found("sdk/lib", &[]));
        }
    }

    /// CWNF-1, on this host's own disk (Linux): a place the jail binds from
    /// a descriptor is opened one step at a time with no link followed, so
    /// the launcher holds what each step held when it looked. A link in a
    /// folder a program in a jail can write refuses (one could have put it
    /// there after the launcher planned the jail: measured, a link swapped
    /// in while the launcher waited on the project's `commondir` showed the
    /// host's `/tmp`, sockets and all, in the next identified jail). The
    /// person's own link, in a folder no jail writes, is followed. A step
    /// not there refuses. The descriptor names the folder it opened.
    ///
    /// FAILS ON REVERT: follow every link (the `writes` check dropped) and
    /// the link planted in `.local` opens the folder it leads to.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_place_to_bind_is_opened_with_no_link_a_jail_can_change_followed() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        std::fs::create_dir_all(home.join(".local/share/tool")).unwrap();
        std::fs::create_dir_all(home.join("private/ro")).unwrap();
        std::fs::write(home.join("private/ro/notes"), "PRIVATE").unwrap();
        symlink(home.join("private"), home.join(".local/share/demo")).unwrap();
        symlink("private", home.join("shared")).unwrap();
        let writes = vec![home.join(".local")];
        let (fd, at, folder) = open_held(&home.join(".local/share/tool"), &writes, &[]).unwrap();
        assert_eq!(at, home.join(".local/share/tool"));
        assert!(folder);
        let shown = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
        assert_eq!(shown, home.join(".local/share/tool"));
        let refused = open_held(&home.join(".local/share/demo/ro"), &writes, &[]).unwrap_err();
        assert!(
            refused.contains("is a link in a folder a program in the jail can write"),
            "{refused}"
        );
        let (_, at, _) = open_held(&home.join("shared/ro"), &writes, &[]).unwrap();
        assert_eq!(at, home.join("private/ro"));
        let (_, at, folder) = open_held(&home.join("private/ro/notes"), &writes, &[]).unwrap();
        assert!(at.ends_with("private/ro/notes") && !folder);
        assert!(open_held(&home.join("gone/x"), &writes, &[]).is_err());
        assert!(open_held(Path::new("relative"), &writes, &[]).is_err());
        // A home folder the jail binds, kept as a link, where the home is a
        // folder a jail writes (another home folder a link to the home
        // itself): the jail's own bind of it follows it by name, and so
        // does this; any other link there is refused.
        let wide = vec![home.clone()];
        std::fs::create_dir_all(home.join("disk/cache/x")).unwrap();
        symlink("disk/cache", home.join(".cache")).unwrap();
        assert!(open_held(&home.join(".cache/x"), &wide, &[]).is_err());
        let (_, at, _) = open_held(&home.join(".cache/x"), &wide, &[home.join(".cache")]).unwrap();
        assert_eq!(at, home.join("disk/cache/x"));
        assert!(open_held(&home.join("shared/ro"), &wide, &[home.join(".cache")]).is_err());
    }

    /// A plain jail's real run makes the launcher's records folder and this
    /// project's folder for Claude Code's settings file (0700, this
    /// account's) before the jail is planned again, and the plan then shows
    /// both: the records read-only, the project's folder writable. Before
    /// they are there the plan shows neither, so nothing missing is pinned.
    ///
    /// FAILS ON REVERT: let `make_plain_records` make nothing and the second
    /// plan has no records folder and no project folder.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_plain_jails_real_run_makes_the_records_and_the_projects_claude_folder() {
        use std::os::unix::fs::PermissionsExt;
        if std::env::var_os("XDG_STATE_HOME").is_some() {
            eprintln!("XDG_STATE_HOME is set: this test makes folders only in a home of its own");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        std::fs::create_dir_all(home.join(".local")).unwrap();
        let project = r.join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let rest: Vec<String> = ["--project", project.to_str().unwrap(), "--", "true"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let args = parse_contain_args(&rest).unwrap();
        let plan = |args: &ContainArgs| {
            resolve_inputs(args.clone(), home.clone(), PathBuf::from("/usr/bin/true")).unwrap()
        };
        let before = plan(&args);
        assert!(before.records_dirs.is_empty(), "{:?}", before.records_dirs);
        assert_eq!(before.project_claude, None);
        assert!(make_plain_records(&before));
        let records = home.join(".local/state/innerwarden/instances");
        let key = crate::contain::project_claude_key(&project);
        let folder = home.join(".local/state/innerwarden/jail-claude").join(&key);
        for dir in [&records, &folder] {
            let mode = std::fs::metadata(dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{}", dir.display());
        }
        let after = plan(&args);
        assert_eq!(after.records_dirs, std::slice::from_ref(&records));
        let claude = after.project_claude.clone().expect("the project's folder");
        assert_eq!(claude.folder, folder);
        assert_eq!(claude.source, folder);
        let argv = crate::contain::build_linux_jail(&after).unwrap().bwrap_args;
        let shown = records.to_string_lossy().to_string();
        assert!(
            argv.windows(3)
                .any(|w| w == ["--ro-bind-try", shown.as_str(), shown.as_str()]),
            "{argv:?}"
        );
        // Made once; an identified launch makes nothing here.
        assert!(!make_plain_records(&after));
        let mut identified = args.clone();
        identified.identity = true;
        std::fs::remove_dir(&folder).unwrap();
        assert!(!make_plain_records(&plan(&identified)));
        assert!(!folder.exists());
    }

    /// Claude Code's settings as the launcher reads them before a jail
    /// starts, the person's and the project's: nothing there starts; every
    /// doubt refuses and names the file (second review of #352, item 3): a
    /// link (never followed), JSON that does not read (a comment in it
    /// included), a file over the limit, `disableAllHooks` with any value
    /// but `false`, hooks in a form it does not read.
    ///
    /// FAILS ON REVERT: skip a file that does not read, or follow a link.
    #[test]
    fn claude_settings_are_read_before_a_jail_starts_and_every_doubt_refuses() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let p = root.path().join("proj");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(p.join(".claude")).unwrap();
        assert_eq!(claude_settings_refused(&home.join(".claude"), &p), None);
        let ours = r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/innerwarden hook --agent claude-code"}]}]}}"#;
        std::fs::write(home.join(".claude/settings.json"), ours).unwrap();
        std::fs::write(
            p.join(".claude/settings.local.json"),
            r#"{"permissions":{"allow":["Bash(ls)"]},"disableAllHooks":false}"#,
        )
        .unwrap();
        assert_eq!(claude_settings_refused(&home.join(".claude"), &p), None);
        let refused = |path: &Path, text: &[u8]| {
            let before = std::fs::read(path).ok();
            std::fs::write(path, text).unwrap();
            let why = claude_settings_refused(&home.join(".claude"), &p);
            match before {
                Some(before) => std::fs::write(path, before).unwrap(),
                None => std::fs::remove_file(path).unwrap(),
            }
            why.unwrap_or_else(|| {
                panic!(
                    "{} with {:?} starts",
                    path.display(),
                    String::from_utf8_lossy(text)
                )
            })
        };
        let local = home.join(".claude/settings.local.json");
        for value in [r#""true""#, "1", r#""yes""#, "true", "null", "{}"] {
            let why = refused(
                &local,
                format!(r#"{{"disableAllHooks":{value}}}"#).as_bytes(),
            );
            assert!(
                why.contains("disableAllHooks") && why.contains("settings.local.json"),
                "{why}"
            );
        }
        let why = refused(&local, b"{\"model\":\"x\" // a comment\n}");
        assert!(
            why.contains("not JSON") && why.contains("settings.local.json"),
            "{why}"
        );
        let why = refused(&p.join(".claude/settings.json"), b"[]");
        assert!(why.contains("not a JSON object"), "{why}");
        for hooks in [
            r#"{"hooks":[]}"#,
            r#"{"hooks":{"PreToolUse":{"matcher":"Bash"}}}"#,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":"x"}]}}"#,
            r#"{"hooks":{"Stop":[{"hooks":[{"command":"x"}]}]}}"#,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":["x"]}]}]}}"#,
        ] {
            let why = refused(&local, hooks.as_bytes());
            assert!(why.contains("form"), "{hooks}: {why}");
        }
        let mut big = br#"{"model":""#.to_vec();
        big.extend(std::iter::repeat_n(b'x', 5 * 1024 * 1024));
        big.extend(br#""}"#);
        let why = refused(&local, &big);
        assert!(why.contains("larger than 4 MiB"), "{why}");
        #[cfg(unix)]
        {
            let elsewhere = root.path().join("fine.json");
            std::fs::write(&elsewhere, "{}").unwrap();
            for link in [local.clone(), p.join(".claude/settings.json")] {
                std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
                let why = claude_settings_refused(&home.join(".claude"), &p).unwrap();
                assert!(why.contains("is a link"), "{why}");
                std::fs::remove_file(&link).unwrap();
            }
        }
        // The project's PreToolUse hooks without the guard's: refused there
        // alone (the person's settings get the guard's when it is armed).
        let others = r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/other"}]}]}}"#;
        assert!(refused(&p.join(".claude/settings.json"), others.as_bytes())
            .contains("none of InnerWarden's"));
        std::fs::write(&local, others).unwrap();
        assert_eq!(claude_settings_refused(&home.join(".claude"), &p), None);
    }

    /// Second review of #352, item 1, as the real run readies the jail's
    /// own `~/.claude`: made 0700 where it is not there; the person's two
    /// settings files copied there 0600 (`{}` where the person has none),
    /// what a jail planted as a link at a name the launcher writes or shows
    /// removed without following it, the person's login copied, and each
    /// file a hook runs from `~/.claude` found. A settings file the check
    /// refuses refuses here too (it is read again after the hook was armed).
    ///
    /// FAILS ON REVERT: copy nothing, or follow a planted link.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_jails_own_claude_folder_is_readied_with_copies_of_the_settings() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        std::fs::create_dir_all(home.join(".claude/hooks")).unwrap();
        std::fs::write(
            home.join(".claude/settings.json"),
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"sh ~/.claude/hooks/done.sh"}]}]}}"#,
        )
        .unwrap();
        std::fs::write(home.join(".claude/.credentials.json"), "LOGIN").unwrap();
        let mut input = resolve_inputs(
            parse_contain_args(&["--".to_string(), "true".to_string()]).unwrap(),
            home.clone(),
            PathBuf::from("/usr/bin/true"),
        )
        .unwrap();
        let source = r.join("state/innerwarden/jail-claude/proj-0123456789abcdef");
        input.project_claude = Some(crate::contain::ProjectClaude {
            covered: vec![r.join("state/innerwarden/jail-claude")],
            folder: source.clone(),
            source: source.clone(),
        });
        // A planted link where the copy goes: removed, never followed.
        std::fs::create_dir_all(&source).unwrap();
        for dir in [&source, &r.join("state/innerwarden/jail-claude")] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let victim = r.join("victim");
        std::fs::write(&victim, "VICTIM").unwrap();
        std::os::unix::fs::symlink(&victim, source.join("settings.local.json")).unwrap();
        let out = prepare_project_claude(&input).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "VICTIM");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&source), 0o700);
        assert_eq!(
            std::fs::read(source.join("settings.json")).unwrap(),
            std::fs::read(home.join(".claude/settings.json")).unwrap()
        );
        assert_eq!(
            std::fs::read_to_string(source.join("settings.local.json")).unwrap(),
            "{}"
        );
        assert_eq!(
            std::fs::read_to_string(source.join(".credentials.json")).unwrap(),
            "LOGIN"
        );
        for name in ["settings.json", "settings.local.json", ".credentials.json"] {
            assert_eq!(mode(&source.join(name)), 0o600, "{name}");
        }
        assert_eq!(out.claude_hook_files, [home.join(".claude/hooks/done.sh")]);
        // Nothing was made in the host's `~/.claude`.
        assert!(!home.join(".claude/settings.local.json").exists());
        // Armed since the check with a value that turns hooks off: refused.
        std::fs::write(
            home.join(".claude/settings.local.json"),
            r#"{"disableAllHooks":"1"}"#,
        )
        .unwrap();
        let why = prepare_project_claude(&input).unwrap_err();
        assert!(why.contains("disableAllHooks"), "{why}");
    }

    /// Final review of #352, items 1 and 2, as the real run readies the
    /// jail's own `~/.claude`: what a jail wrote there at a name the
    /// person's folder does not have (`CLAUDE.md`, a hook's script the
    /// settings name) is removed before the next run, so the next jail never
    /// loads it, while what the person has is left to be laid from the host.
    /// And which of the project's `.claude` and `.mcp.json` were not there
    /// is kept: one that appears with hooks off refuses the next start, one
    /// that sets nothing that reaches the host does not, and one that was
    /// there already is the person's.
    ///
    /// FAILS ON REVERT: leave what the jail wrote, or keep no absent names.
    #[cfg(target_os = "linux")]
    #[test]
    fn what_a_jail_left_at_a_name_the_host_lacks_is_gone_and_new_project_files_are_judged() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        let project = r.join("proj");
        std::fs::create_dir_all(home.join(".claude/agents")).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            home.join(".claude/settings.json"),
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"sh ~/.claude/hooks/x.sh"}]}]}}"#,
        )
        .unwrap();
        let mut args = parse_contain_args(&["--".to_string(), "true".to_string()]).unwrap();
        args.project = project.clone();
        let mut input = resolve_inputs(args, home.clone(), PathBuf::from("/usr/bin/true")).unwrap();
        let all = r.join("state/innerwarden/jail-claude");
        let source = all.join("proj-0123456789abcdef");
        std::fs::create_dir_all(source.join("hooks")).unwrap();
        std::fs::create_dir_all(source.join("skills/s")).unwrap();
        for dir in [&source, &all] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        input.project_claude = Some(crate::contain::ProjectClaude {
            covered: vec![all.clone()],
            folder: source.clone(),
            source: source.clone(),
        });
        // What the last jail wrote in its own folder.
        std::fs::write(source.join("CLAUDE.md"), "JAIL-WROTE").unwrap();
        std::fs::write(source.join("hooks/x.sh"), "JAIL-WROTE").unwrap();
        std::fs::write(source.join("skills/s/SKILL.md"), "JAIL-WROTE").unwrap();
        std::fs::create_dir_all(source.join("agents")).unwrap();
        prepare_project_claude(&input).unwrap();
        for gone in ["CLAUDE.md", "hooks/x.sh", "skills"] {
            assert!(
                std::fs::symlink_metadata(source.join(gone)).is_err(),
                "{gone}"
            );
        }
        // The person has agents: left, laid from the host.
        assert!(source.join("agents").exists());
        // Both of the project's names were absent: kept.
        assert!(project_files_made(&input).is_empty());
        std::fs::create_dir_all(project.join(".claude")).unwrap();
        std::fs::write(
            project.join(".claude/settings.local.json"),
            r#"{"permissions":{"allow":["Bash(ls)"]}}"#,
        )
        .unwrap();
        assert!(
            project_files_made(&input).is_empty(),
            "nothing that reaches the host"
        );
        std::fs::write(
            project.join(".mcp.json"),
            r#"{"mcpServers":{"evil":{"command":"nc"}}}"#,
        )
        .unwrap();
        let why = project_files_made(&input);
        assert_eq!(why.len(), 1, "{why:?}");
        assert!(
            why[0].contains(".mcp.json") && why[0].contains("MCP servers"),
            "{why:?}"
        );
        std::fs::write(
            project.join(".claude/settings.local.json"),
            r#"{"disableAllHooks":true}"#,
        )
        .unwrap();
        assert_eq!(project_files_made(&input).len(), 2);
        // The next start, with both there now: they are the person's from
        // here on (read-only in the jail), and nothing is judged.
        prepare_project_claude(&input).unwrap();
        assert!(project_files_made(&input).is_empty());
    }

    /// T-109 item 3, as the launcher sees each run: a file the person makes
    /// in the project between two runs (here, hooks of their own in
    /// `.claude/settings.json`) is theirs and refuses no start; one a jail
    /// makes during its run (MCP servers in `.mcp.json`) is said as the run
    /// ends, kept, and refuses each next start until the person accepts it.
    ///
    /// FAILS ON REVERT: keep the names absent at the start until the next
    /// good start (the person's file refuses), or keep nothing as the run
    /// ends (the jail's file is forgotten).
    #[cfg(unix)]
    #[test]
    fn a_file_the_person_makes_between_runs_is_theirs_and_a_jails_waits_for_them() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        let project = r.join("proj");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        let mut args = parse_contain_args(&["--".to_string(), "true".to_string()]).unwrap();
        args.project = project.clone();
        let mut input = resolve_inputs(args, home.clone(), PathBuf::from("/usr/bin/true")).unwrap();
        let all = r.join("state/innerwarden/jail-claude");
        let source = all.join("proj-0123456789abcdef");
        std::fs::create_dir_all(&source).unwrap();
        for dir in [&source, &all] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        input.project_claude = Some(crate::contain::ProjectClaude {
            covered: vec![all.clone()],
            folder: source.clone(),
            source: source.clone(),
        });
        // Run 1 makes nothing.
        prepare_project_claude(&input).unwrap();
        assert!(finish_project_files(&input).is_empty());
        assert!(run_markers(input.project_claude.as_ref().unwrap())
            .unwrap()
            .is_empty());
        // Between runs the person adds hooks of their own: no refusal.
        std::fs::create_dir_all(project.join(".claude")).unwrap();
        std::fs::write(
            project.join(".claude/settings.json"),
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"make lint"}]}]}}"#,
        )
        .unwrap();
        assert!(project_files_made(&input).is_empty(), "the person's file");
        // Run 2: its jail makes MCP servers.
        prepare_project_claude(&input).unwrap();
        std::fs::write(
            project.join(".mcp.json"),
            r#"{"mcpServers":{"evil":{"command":"nc"}}}"#,
        )
        .unwrap();
        let said = finish_project_files(&input);
        assert_eq!(said.len(), 1, "{said:?}");
        assert!(said[0].contains(".mcp.json"), "{said:?}");
        // Each next start refuses on it, even after a start that skipped
        // the check would have pruned what no longer refuses.
        let why = project_files_made(&input);
        assert_eq!(why.len(), 1, "{why:?}");
        assert!(why[0].contains(".mcp.json"), "{why:?}");
        // The person accepts it: nothing refuses any more.
        assert_eq!(accept_project_files_for(&input), ExitCode::SUCCESS);
        assert!(project_files_made(&input).is_empty());
    }

    /// T-109 item 3: a launch that stopped before its end (no clean end, so
    /// no judgement) leaves its run marker, and what its jail may have made
    /// refuses the next start; an earlier launcher's `.absent` is read the
    /// same way. A start that passes the check takes away what launches that
    /// no longer run left, and a file the person makes after it is theirs.
    ///
    /// FAILS ON REVERT: read only this launch's names.
    #[cfg(unix)]
    #[test]
    fn a_launch_stopped_before_its_end_leaves_its_names_judged() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        let project = r.join("proj");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        let mut args = parse_contain_args(&["--".to_string(), "true".to_string()]).unwrap();
        args.project = project.clone();
        let mut input = resolve_inputs(args, home.clone(), PathBuf::from("/usr/bin/true")).unwrap();
        let all = r.join("state/innerwarden/jail-claude");
        let source = all.join("proj-0123456789abcdef");
        std::fs::create_dir_all(&source).unwrap();
        for dir in [&source, &all] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        input.project_claude = Some(crate::contain::ProjectClaude {
            covered: vec![all.clone()],
            folder: source.clone(),
            source: source.clone(),
        });
        // A launch whose pid no longer runs, and an earlier launcher's marker.
        let gone = all.join("proj-0123456789abcdef.run.2147483646");
        std::fs::write(&gone, ".mcp.json").unwrap();
        std::fs::write(all.join("proj-0123456789abcdef.absent"), ".claude").unwrap();
        assert!(!marker_launch_runs(&gone));
        std::fs::write(project.join(".mcp.json"), r#"{"mcpServers":{"e":{}}}"#).unwrap();
        std::fs::create_dir_all(project.join(".claude")).unwrap();
        std::fs::write(
            project.join(".claude/settings.local.json"),
            r#"{"disableAllHooks":true}"#,
        )
        .unwrap();
        assert_eq!(project_files_made(&input).len(), 2);
        // Both taken away by the person: a start passes and prunes them.
        std::fs::remove_file(project.join(".mcp.json")).unwrap();
        std::fs::remove_dir_all(project.join(".claude")).unwrap();
        assert!(project_files_made(&input).is_empty());
        prepare_project_claude(&input).unwrap();
        let left = run_markers(input.project_claude.as_ref().unwrap()).unwrap();
        assert_eq!(
            left,
            vec![run_marker(input.project_claude.as_ref().unwrap()).unwrap()]
        );
        assert!(finish_project_files(&input).is_empty());
        // After the run, the person's own file is theirs.
        std::fs::write(project.join(".mcp.json"), r#"{"mcpServers":{"mine":{}}}"#).unwrap();
        assert!(project_files_made(&input).is_empty());
    }

    /// Review of #361, item 6: the project's `.claude` and `.mcp.json` that
    /// are THERE when the jail starts (the end of the run only judges those
    /// that were not) are found by the real resolve and denied writing in
    /// the macOS profile, after the project itself is allowed.
    #[cfg(unix)]
    #[test]
    fn present_project_claude_files_are_denied_writing_on_macos() {
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        let project = r.join("proj");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(project.join(".claude")).unwrap();
        std::fs::write(project.join(".mcp.json"), r#"{"mcpServers":{}}"#).unwrap();
        let mut args = parse_contain_args(&["--".to_string(), "true".to_string()]).unwrap();
        args.project = project.clone();
        let mut input = resolve_inputs(args, home.clone(), PathBuf::from("/usr/bin/true")).unwrap();
        for name in [".claude", ".mcp.json"] {
            assert!(
                input.project_guard_files.contains(&project.join(name)),
                "{name}: {:?}",
                input.project_guard_files
            );
        }
        let all = r.join("state/innerwarden/jail-claude");
        input.project_claude = Some(crate::contain::ProjectClaude {
            covered: vec![all.clone()],
            folder: all.join("proj-0123456789abcdef"),
            source: all.join("proj-0123456789abcdef"),
        });
        let profile = build_macos_profile(&input).unwrap().profile;
        let allowed = profile
            .find(&format!(
                "(allow file-write* (subpath \"{}\"))",
                project.display()
            ))
            .unwrap_or_else(|| panic!("{profile}"));
        for name in [".claude", ".mcp.json"] {
            let deny = profile
                .find(&format!(
                    "(deny file-write* (subpath \"{}\"))",
                    project.join(name).display()
                ))
                .unwrap_or_else(|| panic!("{name}: {profile}"));
            assert!(allowed < deny, "{profile}");
        }
    }

    /// Review of #361, item 2: a note that cannot be read (closed to this
    /// account, or no plain file) refuses the start; it never counts as no
    /// note.
    ///
    /// FAILS ON REVERT: read a note that cannot be read as empty.
    #[cfg(unix)]
    #[test]
    fn a_note_that_cannot_be_read_refuses_the_start() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        let project = r.join("proj");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        let mut args = parse_contain_args(&["--".to_string(), "true".to_string()]).unwrap();
        args.project = project.clone();
        let mut input = resolve_inputs(args, home.clone(), PathBuf::from("/usr/bin/true")).unwrap();
        let all = r.join("state/innerwarden/jail-claude");
        let source = all.join("proj-0123456789abcdef");
        std::fs::create_dir_all(&source).unwrap();
        input.project_claude = Some(crate::contain::ProjectClaude {
            covered: vec![all.clone()],
            folder: source.clone(),
            source: source.clone(),
        });
        // A note made a folder: no plain file.
        let made = all.join("proj-0123456789abcdef.made");
        std::fs::create_dir_all(&made).unwrap();
        let why = project_files_made(&input);
        assert_eq!(why.len(), 1, "{why:?}");
        assert!(why[0].contains("cannot be read"), "{why:?}");
        std::fs::remove_dir(&made).unwrap();
        // Closed to its owner (root reads it anyway: checked only where not).
        std::fs::write(
            &made,
            project.join(".mcp.json").to_string_lossy().as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&made, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_to_string(&made).is_err() {
            let why = project_files_made(&input);
            assert!(why.iter().any(|w| w.contains("cannot be read")), "{why:?}");
        }
        std::fs::set_permissions(&made, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// Review of #361, item 3: a run note whose pid now belongs to a process
    /// that started after the note was written is no running launch.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_pid_used_again_is_no_running_launch() {
        let root = tempfile::tempdir().unwrap();
        let own = root.path().join(format!("k.run.{}", std::process::id()));
        std::fs::write(&own, "").unwrap();
        // This process started before its note: it runs.
        assert!(marker_launch_runs(&own));
        // A note written long before this process started.
        let old = std::fs::File::options().write(true).open(&own).unwrap();
        old.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(86_400))
            .unwrap();
        assert!(process_started(std::process::id() as i32).is_some());
        assert!(!marker_launch_runs(&own));
    }

    /// T-109 item 3: the request to accept is the flag with `--project` and
    /// nothing else; after the agent's command a flag is the command's.
    #[test]
    fn accepting_takes_only_a_project() {
        let s = |a: &[&str]| a.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            accept_request(&s(&["--accept-project-files"])),
            Some(Ok(PathBuf::from(".")))
        );
        assert_eq!(
            accept_request(&s(&["--project", "/w/app", "--accept-project-files"])),
            Some(Ok(PathBuf::from("/w/app")))
        );
        assert!(matches!(
            accept_request(&s(&["--accept-project-files", "--enforce"])),
            Some(Err(_))
        ));
        assert!(matches!(
            accept_request(&s(&["--accept-project-files", "--", "claude"])),
            Some(Err(_))
        ));
        assert_eq!(
            accept_request(&s(&["--", "claude", "--accept-project-files"])),
            None
        );
        assert_eq!(
            accept_request(&s(&["claude", "--accept-project-files"])),
            None
        );
        assert_eq!(accept_request(&s(&["--enforce", "--", "claude"])), None);
    }

    /// T-109 item 2: on macOS too, the launcher clears what a jail wrote in
    /// its own `~/.claude` at a name the person's folder lacks before the
    /// next run, and links each shared name the person has
    /// (`CLAUDE_READ_ONLY_SHARED`) that the jail's folder lacks.
    ///
    /// FAILS ON REVERT: leave what the jail wrote, or link nothing.
    #[cfg(target_os = "macos")]
    #[test]
    fn on_macos_what_a_jail_left_is_cleared_and_the_persons_shared_names_linked() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        let project = r.join("proj");
        std::fs::create_dir_all(home.join(".claude/agents")).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            home.join(".claude/settings.json"),
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"sh ~/.claude/hooks/x.sh"}]}]}}"#,
        )
        .unwrap();
        let mut args = parse_contain_args(&["--".to_string(), "true".to_string()]).unwrap();
        args.project = project.clone();
        let mut input = resolve_inputs(args, home.clone(), PathBuf::from("/usr/bin/true")).unwrap();
        let all = r.join("state/innerwarden/jail-claude");
        let source = all.join("proj-0123456789abcdef");
        std::fs::create_dir_all(source.join("hooks")).unwrap();
        std::fs::create_dir_all(source.join("skills/s")).unwrap();
        for dir in [&source, &all] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        input.project_claude = Some(crate::contain::ProjectClaude {
            covered: vec![all.clone()],
            folder: source.clone(),
            source: source.clone(),
        });
        std::fs::write(source.join("CLAUDE.md"), "JAIL-WROTE").unwrap();
        std::fs::write(source.join("hooks/x.sh"), "JAIL-WROTE").unwrap();
        std::fs::write(source.join("skills/s/SKILL.md"), "JAIL-WROTE").unwrap();
        prepare_project_claude(&input).unwrap();
        for gone in ["CLAUDE.md", "hooks/x.sh", "skills"] {
            assert!(
                std::fs::symlink_metadata(source.join(gone)).is_err(),
                "{gone}"
            );
        }
        let agents = std::fs::symlink_metadata(source.join("agents")).unwrap();
        assert!(agents.file_type().is_symlink());
        assert_eq!(
            std::fs::read_link(source.join("agents")).unwrap(),
            home.join(".claude/agents")
        );
    }

    /// Final review of #352, item 1: the start reads the project's
    /// `.mcp.json` too, and refuses where it or the project's `.claude`
    /// is a link, or where `.mcp.json` does not read as a JSON object.
    ///
    /// FAILS ON REVERT: read neither.
    #[cfg(unix)]
    #[test]
    fn the_projects_claude_folder_and_mcp_file_are_read_before_a_jail_starts() {
        let root = tempfile::tempdir().unwrap();
        let p = root.path().join("proj");
        let home = root.path().join("home");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        assert_eq!(claude_settings_refused(&home, &p), None);
        std::fs::write(p.join(".mcp.json"), r#"{"mcpServers":{}}"#).unwrap();
        assert_eq!(claude_settings_refused(&home, &p), None);
        std::fs::write(p.join(".mcp.json"), "servers = 1").unwrap();
        assert!(claude_settings_refused(&home, &p)
            .unwrap()
            .contains(".mcp.json"));
        std::fs::remove_file(p.join(".mcp.json")).unwrap();
        std::fs::create_dir_all(root.path().join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(root.path().join("elsewhere"), p.join(".claude")).unwrap();
        let why = claude_settings_refused(&home, &p).unwrap();
        assert!(
            why.contains(".claude") && why.contains("is a link"),
            "{why}"
        );
    }

    /// Measured on the lab host (#352, second review): two identified jails
    /// started at once on one project each removed and made the same
    /// temporary name for the copies, and the second did not start. Each
    /// launch's temporary name is its own now.
    ///
    /// FAILS ON REVERT: a fixed temporary name.
    #[cfg(unix)]
    #[test]
    fn each_launch_writes_under_a_temporary_name_of_its_own() {
        let target = Path::new("/s/settings.json");
        let a = launch_temp_name(target);
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = launch_temp_name(target);
        assert_ne!(a, b);
        assert!(a.starts_with(".settings.json.innerwarden."), "{a}");
        assert!(a.contains(&std::process::id().to_string()), "{a}");
    }

    /// Review of #352, item 3, as the launcher does it before a plain jail
    /// runs: the project's kept `.claude.json` is cut to Claude Code's own
    /// state in place, 0600; a file that is not JSON, or a link, is removed.
    ///
    /// FAILS ON REVERT: leave `trim_project_claude` doing nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_projects_claude_json_is_cut_before_a_plain_jail_runs() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let folder = r.join("jail-claude/proj-0123456789abcdef");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut input = resolve_inputs(
            parse_contain_args(&["--".to_string(), "true".to_string()]).unwrap(),
            r.join("home"),
            PathBuf::from("/usr/bin/true"),
        )
        .unwrap();
        input.project_claude = Some(crate::contain::ProjectClaude {
            covered: vec![r.join("jail-claude")],
            folder: folder.clone(),
            source: folder.clone(),
        });
        let file = folder.join(".claude.json");
        std::fs::write(
            &file,
            r#"{"theme":"dark","mcpServers":{"evil":{"command":"nc"}},"projects":{"/p":{"allowedTools":["Bash(*)"],"history":[]}}}"#,
        )
        .unwrap();
        trim_project_claude(input.project_claude.as_ref().unwrap(), me());
        let kept: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        assert_eq!(
            kept,
            serde_json::json!({"theme": "dark", "projects": {"/p": {"history": []}}})
        );
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // Not JSON: removed.
        std::fs::write(&file, "mcpServers = evil").unwrap();
        trim_project_claude(input.project_claude.as_ref().unwrap(), me());
        assert!(!file.exists());
        // A link: removed, never followed.
        let elsewhere = r.join("elsewhere.json");
        std::fs::write(&elsewhere, r#"{"mcpServers":{}}"#).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &file).unwrap();
        trim_project_claude(input.project_claude.as_ref().unwrap(), me());
        assert!(std::fs::symlink_metadata(&file).is_err());
        assert_eq!(
            std::fs::read_to_string(&elsewhere).unwrap(),
            r#"{"mcpServers":{}}"#
        );
    }

    /// Review of #352, item 1: a records folder that was already there was
    /// taken as it was. Now a plain launch checks it: one that others may
    /// write is moved aside whole and made again, 0700; in it, every entry
    /// the launcher does not write (a file of another name, a record that
    /// does not parse or names another id, a link, a folder) is moved aside;
    /// a record of the launcher's, its project file and a temporary file of
    /// a launcher writing now are kept.
    ///
    /// FAILS ON REVERT: check the folder only where it is made.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_records_folder_already_there_is_checked_and_what_was_planted_moved_aside() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let dir = r.join("state/innerwarden/instances");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = own_uid();
        let id = "07070707070707070707070707070707";
        let record = format!(
            r#"{{"schema":1,"instance_id":"{id}","agent_type":"claude-code","launcher":{{"path":"/usr/local/bin/innerwarden","version":"1.5.5","root_owned":true}},"uid":{uid},"project":"my-app","mode":"enforce","started_at":"2026-10-16T12:00:00Z","jail":{{"backend":"bwrap","pid":2778,"start_ticks":123456,"pid_ns":4026532220,"mnt_ns":4026532218}}}}"#
        );
        let private = |path: &Path, text: &str| {
            std::fs::write(path, text).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        private(&dir.join(format!("{id}.json")), &record);
        private(&dir.join(format!("{id}.project")), "/home/dev/my-app\n");
        private(&dir.join(format!(".{id}.tmp")), "{");
        let forged = "08080808080808080808080808080808";
        private(&dir.join(format!("{forged}.json")), &record);
        private(&dir.join("notes.txt"), "x");
        private(
            &dir.join("09090909090909090909090909090909.json"),
            "not json",
        );
        std::os::unix::fs::symlink(&r, dir.join("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a.json")).unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        assert!(vet_records_dir(&dir, uid).unwrap());
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                format!(".{id}.tmp"),
                format!("{id}.json"),
                format!("{id}.project")
            ]
        );
        let aside: Vec<_> = std::fs::read_dir(dir.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("instances.set-aside-"))
            .collect();
        assert_eq!(aside.len(), 1, "{aside:?}");
        let moved = std::fs::read_dir(dir.with_file_name(&aside[0]))
            .unwrap()
            .count();
        assert_eq!(moved, 5);
        // Nothing more to move: unchanged.
        assert!(!vet_records_dir(&dir, uid).unwrap());
        // A folder others may write: moved aside whole and made again.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(vet_records_dir(&dir, uid).unwrap());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    /// CWNF-1 (Linux): the real run opens each pin and each read-only path
    /// of the jail just before bwrap starts, after every check, and hands
    /// bwrap those descriptors: the read-only path and the folder pinned
    /// above it are bound from them. Where a program in an earlier jail
    /// swapped the read-only path for a link since the launcher planned the
    /// jail (the race the review measured), the launch stops and says so;
    /// nothing is bound by name. Where bwrap binds no descriptor nothing is
    /// opened.
    ///
    /// FAILS ON REVERT: open nothing (`hold_binds` returning the input as it
    /// is) and the swapped path is bound by name, so the jail shows where
    /// the link leads.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_read_only_path_swapped_for_a_link_after_the_plan_stops_the_launch() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        let versions = home.join(".local/share/claude/versions");
        std::fs::create_dir_all(&versions).unwrap();
        std::fs::create_dir_all(home.join("private")).unwrap();
        let project = r.join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let rest: Vec<String> = ["--project", project.to_str().unwrap(), "--", "true"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut args = parse_contain_args(&rest).unwrap();
        args.extra_ro = vec![versions.clone()];
        let said = screen_extra(&mut args, &home, Path::new("/usr/bin/true"));
        // The plan keeps it where this host's bwrap binds a descriptor, and
        // says it leaves it out where it binds none.
        if bwrap_binds_fds() {
            assert!(said.is_empty(), "{said:?}");
            assert_eq!(args.extra_ro, std::slice::from_ref(&versions));
        } else {
            assert_eq!(said, [crate::contain::extra_not_held(&versions)]);
            args.extra_ro = vec![versions.clone()];
        }
        let input = resolve_inputs(args, home.clone(), PathBuf::from("/usr/bin/true")).unwrap();
        let (held_input, held) = hold_binds(&input, true).unwrap();
        let places = crate::contain::places_bound_from_descriptors(&input);
        assert_eq!(held.len(), places.len());
        assert!(
            held_input.bind_fds.iter().any(|(at, _)| *at == versions),
            "{:?}",
            held_input.bind_fds
        );
        assert!(
            held_input
                .bind_fds
                .iter()
                .any(|(at, _)| *at == home.join(".local/share/claude")),
            "{:?}",
            held_input.bind_fds
        );
        // The command line binds the held folder from its descriptor only
        // where this host's bwrap can (a CI runner's 0.9.0 cannot).
        if bwrap_binds_fds() {
            let a = build_linux_jail(&held_input).unwrap().bwrap_args;
            assert!(
                a.windows(3)
                    .any(|x| x[0] == "--ro-bind-fd" && x[2] == versions.to_str().unwrap()),
                "{a:?}"
            );
            // Never also by name (the host's resolver file may be, a
            // systemd-resolved runner binds its stub with -try).
            assert!(
                !a.windows(3)
                    .any(|x| x[0] == "--ro-bind-try" && x[2] == versions.to_str().unwrap()),
                "{a:?}"
            );
        }
        drop(held);
        // An earlier jail swaps the planned folder for a link meanwhile.
        std::fs::rename(&versions, home.join(".local/share/claude/versions.old")).unwrap();
        symlink(home.join("private"), &versions).unwrap();
        let refused = hold_binds(&input, true).unwrap_err();
        assert!(
            refused.starts_with(&format!(
                "{} changed since the launcher looked at it",
                versions.display()
            )),
            "{refused}"
        );
        // A bwrap that binds no descriptor: nothing opened.
        let (same, none) = hold_binds(&input, false).unwrap();
        assert!(none.is_empty() && same.bind_fds.is_empty());
    }

    /// CWNF-1 (tests lens), on this host's own disk: `~/.aws` a link to a
    /// folder outside the home, and a profile's read-only path in that
    /// folder. The planner left that folder as it was (the read-only path
    /// counted as what the jail needs), so the jail hid nothing there,
    /// while the read-only path was kept: the unit test that said otherwise
    /// set the hidden target by hand. Planned for real now: the folder is
    /// hidden where `~/.aws` leads (denied on macOS), and the read-only path
    /// is left out and said.
    ///
    /// FAILS ON REVERT: plan the dotdirs with `facts` instead of
    /// `facts.hiding_first()` and the read-only path is kept, the folder
    /// not hidden.
    #[cfg(unix)]
    #[test]
    fn a_read_only_path_where_a_hidden_dotdir_leads_is_left_out_and_the_place_hidden() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        let aws = r.join("data/aws");
        std::fs::create_dir_all(aws.join("creds")).unwrap();
        std::fs::write(aws.join("credentials"), "AWS-SECRET").unwrap();
        std::fs::create_dir_all(&home).unwrap();
        symlink(&aws, home.join(".aws")).unwrap();
        let project = r.join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let rest: Vec<String> = ["--project", project.to_str().unwrap(), "--", "true"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut args = parse_contain_args(&rest).unwrap();
        args.extra_ro = vec![aws.join("creds")];
        let mut said = screen_extra(&mut args, &home, Path::new("/usr/bin/true"));
        let input = resolve_screened(
            args,
            home.clone(),
            PathBuf::from("/usr/bin/true"),
            &mut said,
        )
        .unwrap();
        assert!(input.args.extra_ro.is_empty(), "{:?}", input.args.extra_ro);
        assert_eq!(input.hidden_targets, [(home.join(".aws"), aws.clone())]);
        assert!(
            said.iter().any(|line| line.contains(&format!(
                "where {} leads, which the jail hides; the jail starts without it",
                home.join(".aws").display()
            ))),
            "{said:?}"
        );
        #[cfg(target_os = "macos")]
        assert!(
            input.linked_denies.contains(&aws),
            "{:?}",
            input.linked_denies
        );
        assert!(validate_jail_inputs_for(&input, cfg!(target_os = "macos")).is_ok());
    }

    /// A git folder at `dir` as git makes one: a `HEAD` file, and an
    /// `objects` and a `refs` folder.
    #[cfg(unix)]
    fn git_dir_by_hand(dir: &Path) {
        for sub in ["objects", "refs/heads"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        std::fs::write(dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    }

    /// A worktree laid out by hand as `git worktree add` lays it: the
    /// repository `main`, a git folder, its worktree's git folder
    /// `main/.git/worktrees/w` with `gitdir` naming `w/.git` back and
    /// `commondir` naming the repository's `.git`, and `w/.git` naming that
    /// git folder. `relative`: each named as git 2.48 does with
    /// `worktree.useRelativePaths`.
    #[cfg(unix)]
    fn worktree_by_hand(root: &Path, relative: bool) -> (PathBuf, PathBuf, PathBuf) {
        let common = root.join("main/.git");
        git_dir_by_hand(&common);
        let git_dir = common.join("worktrees/w");
        let tree = root.join("w");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::create_dir_all(&tree).unwrap();
        if relative {
            std::fs::write(tree.join(".git"), "gitdir: ../main/.git/worktrees/w\n").unwrap();
            std::fs::write(git_dir.join("gitdir"), "../../../../w/.git\n").unwrap();
        } else {
            std::fs::write(
                tree.join(".git"),
                format!("gitdir: {}\n", git_dir.display()),
            )
            .unwrap();
            std::fs::write(
                git_dir.join("gitdir"),
                format!("{}\n", tree.join(".git").display()),
            )
            .unwrap();
        }
        std::fs::write(git_dir.join("commondir"), "../..\n").unwrap();
        (tree, git_dir, common)
    }

    /// What [`detect_worktree`] says of the project `tree` whose `.git`
    /// file names `named`, left out for `why`.
    #[cfg(unix)]
    fn left_out(
        tree: &Path,
        named: &Path,
        why: crate::contain::WorktreeLeft,
    ) -> (Option<Worktree>, Option<String>) {
        (
            None,
            Some(crate::contain::worktree_left_out(
                &tree.join(".git"),
                named,
                &why,
            )),
        )
    }

    /// Run git with no config of the person's, in `dir`; whether it ran.
    #[cfg(unix)]
    fn git_in(dir: &Path, home: &Path, args: &[&str]) -> bool {
        Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", home)
            .stdin(std::process::Stdio::null())
            .output()
            .is_ok_and(|out| out.status.success())
    }

    /// NEW-WORKTREE (found fixing CWNF-1): a jail binds a linked worktree's
    /// git folders read-write, and took them from the project's `.git`
    /// file, which every program in the jail can write: `gitdir: ~/.bashrc`
    /// (or `~/bin`, `~/Library/LaunchAgents`) had the next jail in the
    /// project bind that place read-write. A git folder is taken now only
    /// where git took it: a worktree's, whose `gitdir` names this `.git`
    /// back, in the repository's `worktrees`, absolute or relative, laid out
    /// by hand and by `git worktree add` itself where this host has git; or
    /// a submodule's, whose config names this project as its work tree. Any
    /// other is no worktree, and the line says why.
    ///
    /// FAILS ON REVERT: take the folder the `.git` file names as it is (as
    /// before) and `~/.bashrc` and `~/bin` are worktree folders.
    #[cfg(unix)]
    #[test]
    fn a_worktree_is_taken_only_where_git_names_the_project_back() {
        use crate::contain::WorktreeLeft;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        std::fs::create_dir_all(&home).unwrap();
        for relative in [false, true] {
            let at = r.join(if relative { "rel" } else { "abs" });
            let (tree, git_dir, common) = worktree_by_hand(&at, relative);
            assert_eq!(
                detect_worktree(&tree, &home),
                (
                    Some(Worktree {
                        git_dir: git_dir.clone(),
                        common_dir: common.clone(),
                    }),
                    None
                ),
                "relative {relative}"
            );
        }
        // Made by `git worktree add` itself, where this host has git, with
        // absolute and with relative paths.
        let made = r.join("made");
        std::fs::create_dir_all(&made).unwrap();
        if git_in(&made, &r, &["init", "-q", "main"])
            && git_in(
                &made.join("main"),
                &r,
                &["commit", "-q", "--allow-empty", "-m", "x"],
            )
        {
            for (name, relative) in [("w", false), ("w2", true)] {
                let mut args = vec!["worktree", "add", "-q"];
                if relative {
                    args = vec![
                        "-c",
                        "worktree.useRelativePaths=true",
                        "worktree",
                        "add",
                        "-q",
                    ];
                }
                let tree = format!("../{name}");
                args.push(&tree);
                assert!(
                    git_in(&made.join("main"), &r, &args),
                    "git worktree add {name}"
                );
                assert_eq!(
                    detect_worktree(&made.join(name), &home),
                    (
                        Some(Worktree {
                            git_dir: made.join("main/.git/worktrees").join(name),
                            common_dir: made.join("main/.git"),
                        }),
                        None
                    ),
                    "{name}"
                );
            }
        }
        // A submodule: its git folder in the superproject's `.git/modules`.
        let modules = r.join("super/.git/modules/sub");
        git_dir_by_hand(&modules);
        std::fs::create_dir_all(r.join("super/sub")).unwrap();
        std::fs::write(
            modules.join("config"),
            "[core]\n\tbare = false\n\tworktree = ../../../sub\n",
        )
        .unwrap();
        std::fs::write(r.join("super/sub/.git"), "gitdir: ../.git/modules/sub\n").unwrap();
        assert_eq!(
            detect_worktree(&r.join("super/sub"), &home),
            (
                Some(Worktree {
                    git_dir: modules.clone(),
                    common_dir: modules.clone(),
                }),
                None
            )
        );
        // Forged by a program in the jail: none is a worktree.
        std::fs::create_dir_all(home.join("bin")).unwrap();
        std::fs::write(home.join(".bashrc"), "# rc\n").unwrap();
        let proj = r.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        // A git folder that names this `.git` back, outside `worktrees` of
        // the repository its `commondir` names, in a folder no jail shows
        // (`~/w`) and in one every jail shows writable (`~/.local/w`).
        for at in ["w", ".local/w"] {
            let x = home.join(at).join("worktrees/x");
            std::fs::create_dir_all(&x).unwrap();
            std::fs::write(
                x.join("gitdir"),
                format!("{}\n", proj.join(".git").display()),
            )
            .unwrap();
            std::fs::write(
                x.join("commondir"),
                format!("{}\n", home.join("bin").display()),
            )
            .unwrap();
        }
        for (named, why) in [
            (
                home.join(".bashrc"),
                WorktreeLeft::NoFolder(home.join(".bashrc")),
            ),
            (home.join("bin"), WorktreeLeft::NoBackLink),
            (
                home.join("w/worktrees/x"),
                WorktreeLeft::NotInWorktrees(home.join("bin")),
            ),
            (r.join("gone"), WorktreeLeft::NotThere(r.join("gone"))),
        ] {
            std::fs::write(proj.join(".git"), format!("gitdir: {}\n", named.display())).unwrap();
            assert_eq!(
                detect_worktree(&proj, &home),
                left_out(&proj, &named, why),
                "{}",
                named.display()
            );
        }
        // The same in a folder every jail shows writable anyway: nothing is
        // bound and nothing said (the jail shows `~/.local` as it is).
        std::fs::write(
            proj.join(".git"),
            format!("gitdir: {}\n", home.join(".local/w/worktrees/x").display()),
        )
        .unwrap();
        assert_eq!(detect_worktree(&proj, &home), (None, None));
        // A plain repository (`.git` a folder) and no repository: nothing.
        std::fs::remove_file(proj.join(".git")).unwrap();
        assert_eq!(detect_worktree(&proj, &home), (None, None));
        std::fs::create_dir_all(proj.join(".git")).unwrap();
        assert_eq!(detect_worktree(&proj, &home), (None, None));
    }

    /// CW-worktree-gitdir: the project's `.git` file is the agent's to
    /// write, and the jail binds the folders it names read-write, a plain
    /// jail too. Each of these is no git worktree of this project, and none
    /// is shown:
    ///
    /// - an arbitrary folder of the home (`~/kube-test`, `~/.kube`, with a
    ///   `config` that is no git config);
    /// - a folder with a fake `worktrees/<name>` and no link back;
    /// - a git folder whose link back names another project;
    /// - a project in a folder named `worktrees` whose `.git` names the
    ///   project itself, with a link back and a `commondir` of `../..`:
    ///   the repository it names is the folder two up (`~/code`, every
    ///   repository of the person's), which is no git folder (taken before;
    ///   the git folder it names is the project, which the jail shows
    ///   anyway, so nothing is said of it, CWWT-C2; the same layout named
    ///   from another project is said);
    /// - a worktree's layout in a hidden folder of the home (`~/.kube`), in
    ///   a place the jail hides (`~/Library/Mail`), or with the home itself
    ///   as its repository (taken before, or refused only by the late check
    ///   that stopped the launch);
    /// - a real worktree of another account's.
    ///
    /// Each says why on one line, and git in the jail then sees no
    /// repository.
    ///
    /// FAILS ON REVERT: drop the git folder check (`is_git_dir`) and
    /// `~/code` is the repository; drop the place check
    /// (`worktree_place_left`) and the `~/.kube`, `~/Library/Mail` and home
    /// layouts are; drop the owner check and another account's is.
    #[cfg(unix)]
    #[test]
    fn a_git_file_never_shows_a_folder_that_is_no_worktree_of_this_project() {
        use crate::contain::WorktreeLeft;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let h = r.join("home");
        let proj = h.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let other = h.join("other");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join(".git"), "gitdir: elsewhere\n").unwrap();
        let name_back = |git_dir: &Path, to: &Path| {
            std::fs::create_dir_all(git_dir).unwrap();
            std::fs::write(git_dir.join("gitdir"), format!("{}\n", to.display())).unwrap();
            std::fs::write(git_dir.join("commondir"), "../..\n").unwrap();
        };
        // An arbitrary folder of the home, and a hidden one, each with a
        // config that is no git config.
        for folder in ["kube-test", ".kube"] {
            std::fs::create_dir_all(h.join(folder)).unwrap();
            std::fs::write(
                h.join(folder).join("config"),
                "apiVersion: v1\nkind: Config\n",
            )
            .unwrap();
        }
        // A fake `worktrees/<name>` with no link back.
        git_dir_by_hand(&h.join("fake"));
        std::fs::create_dir_all(h.join("fake/worktrees/x")).unwrap();
        std::fs::write(h.join("fake/worktrees/x/commondir"), "../..\n").unwrap();
        // A git folder that names another project back.
        git_dir_by_hand(&h.join("repo"));
        name_back(&h.join("repo/worktrees/x"), &other.join(".git"));
        // A worktree's layout in a hidden folder of the home, in a place
        // the jail hides, and with the home as its repository.
        for repo in [h.join(".kube/repo"), h.join("Library/Mail/repo"), h.clone()] {
            git_dir_by_hand(&repo);
            name_back(&repo.join("worktrees/x"), &proj.join(".git"));
        }
        let cases = [
            (h.join("kube-test"), WorktreeLeft::NoBackLink),
            (h.join(".kube"), WorktreeLeft::NoBackLink),
            (h.join("fake/worktrees/x"), WorktreeLeft::NoBackLink),
            (
                h.join("repo/worktrees/x"),
                WorktreeLeft::OtherProject(other.join(".git")),
            ),
            (
                h.join(".kube/repo/worktrees/x"),
                WorktreeLeft::Place(h.join(".kube/repo/worktrees/x")),
            ),
            (
                h.join("Library/Mail/repo/worktrees/x"),
                WorktreeLeft::Place(h.join("Library/Mail/repo/worktrees/x")),
            ),
            (h.join("worktrees/x"), WorktreeLeft::Place(h.clone())),
        ];
        for (named, why) in cases {
            std::fs::write(proj.join(".git"), format!("gitdir: {}\n", named.display())).unwrap();
            assert_eq!(
                detect_worktree(&proj, &h),
                left_out(&proj, &named, why),
                "{}",
                named.display()
            );
        }
        // A project in a folder named `worktrees` that names itself: the
        // repository would be `~/code`, which is no git folder. The git
        // folder it names is the project, which the jail shows anyway:
        // nothing more is bound, and nothing said. The same layout named
        // from another project is said.
        let code = h.join("code");
        let p = code.join("worktrees/p");
        name_back(&p, &p.join(".git"));
        std::fs::create_dir_all(code.join("another-repo")).unwrap();
        std::fs::write(p.join(".git"), "gitdir: .\n").unwrap();
        assert_eq!(detect_worktree(&p, &h), (None, None));
        let p3 = h.join("p3");
        std::fs::create_dir_all(&p3).unwrap();
        name_back(&code.join("worktrees/q"), &p3.join(".git"));
        std::fs::write(
            p3.join(".git"),
            format!("gitdir: {}\n", code.join("worktrees/q").display()),
        )
        .unwrap();
        assert_eq!(
            detect_worktree(&p3, &h),
            left_out(
                &p3,
                &code.join("worktrees/q"),
                WorktreeLeft::NotGitDir(code.clone())
            )
        );
        // A real worktree, of another account's.
        let (tree, git_dir, common) = worktree_by_hand(&h.join("mine"), false);
        let uid = own_uid();
        assert_eq!(
            detect_worktree_as(&tree, &h, uid.wrapping_add(1)),
            left_out(&tree, &git_dir, WorktreeLeft::NotYours(git_dir.clone()))
        );
        assert_eq!(
            detect_worktree_as(&tree, &h, uid),
            (
                Some(Worktree {
                    git_dir,
                    common_dir: common
                }),
                None
            )
        );
    }

    /// CW-worktree-gitdir: git writes every path of a worktree's folders as
    /// it really is, with no link on the way (measured with git 2.52, also
    /// through a link to the repository), and a link on the way is one a
    /// program in a jail may have put there (in the project, or in a
    /// repository it writes). So a worktree whose `.git` names its git
    /// folder through a link, whose git folder is a link, whose `commondir`
    /// or link back goes through one, is no worktree, and the line names the
    /// link. So is each named through a folder that is not there and a `..`
    /// back to that link (`nx/../L`, CWWT-SEC-1: the walk saw no step after
    /// `nx`, and on Linux the worktree was bound by that spelling, the link
    /// in it; a submodule's work tree has its own test), and a project that
    /// is its own repository with a link `L` to the folder above it (the
    /// layout a
    /// program in a jail can leave, measured to make a read-only path of
    /// the project writable). A way through a folder that is not there is no
    /// place to git, whatever comes after it. The same layout with no link
    /// is one.
    ///
    /// FAILS ON REVERT: find each path with `std::fs::canonicalize` (as
    /// before) and each is a worktree; stop reading steps after one that is
    /// not there and each `nx/../L` is one.
    #[cfg(unix)]
    #[test]
    fn a_link_on_the_way_to_a_worktree_is_no_worktree() {
        use crate::contain::WorktreeLeft;
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let (tree, git_dir, common) = worktree_by_hand(&r, false);
        let dotgit = tree.join(".git");
        let real_dotgit = std::fs::read_to_string(&dotgit).unwrap();
        // The git folder named through a link in the project.
        symlink(&common, tree.join("L")).unwrap();
        let through = tree.join("L/worktrees/w");
        std::fs::write(&dotgit, format!("gitdir: {}\n", through.display())).unwrap();
        assert_eq!(
            detect_worktree(&tree, &home),
            left_out(&tree, &through, WorktreeLeft::Link(tree.join("L")))
        );
        // The same through a folder that is not there and back.
        let gone_through = Path::new("nx/../L/worktrees/w");
        std::fs::write(&dotgit, format!("gitdir: {}\n", gone_through.display())).unwrap();
        assert_eq!(
            detect_worktree(&tree, &home),
            left_out(&tree, gone_through, WorktreeLeft::Link(tree.join("L")))
        );
        // A folder that is not there on the way, and no link at all: the
        // kernel stops at `nx`, and so does git.
        let gone_only = tree.join("nx/../../main/.git/worktrees/w");
        std::fs::write(&dotgit, format!("gitdir: {}\n", gone_only.display())).unwrap();
        assert_eq!(
            detect_worktree(&tree, &home),
            left_out(&tree, &gone_only, WorktreeLeft::NotThere(tree.join("nx")))
        );
        // The git folder itself a link.
        symlink(&git_dir, common.join("worktrees/v")).unwrap();
        let linked = common.join("worktrees/v");
        std::fs::write(&dotgit, format!("gitdir: {}\n", linked.display())).unwrap();
        assert_eq!(
            detect_worktree(&tree, &home),
            left_out(&tree, &linked, WorktreeLeft::Link(linked.clone()))
        );
        // `commondir` through a link.
        std::fs::write(&dotgit, &real_dotgit).unwrap();
        symlink(r.join("main"), r.join("alias")).unwrap();
        std::fs::write(
            git_dir.join("commondir"),
            format!("{}\n", r.join("alias/.git").display()),
        )
        .unwrap();
        assert_eq!(
            detect_worktree(&tree, &home),
            left_out(&tree, &git_dir, WorktreeLeft::Link(r.join("alias")))
        );
        std::fs::write(
            git_dir.join("commondir"),
            format!("{}\n", r.join("nx/../alias/.git").display()),
        )
        .unwrap();
        assert_eq!(
            detect_worktree(&tree, &home),
            left_out(&tree, &git_dir, WorktreeLeft::Link(r.join("alias")))
        );
        // The link back through a link.
        std::fs::write(git_dir.join("commondir"), "../..\n").unwrap();
        symlink(&tree, r.join("walias")).unwrap();
        for back in ["walias/.git", "nx/../walias/.git"] {
            std::fs::write(
                git_dir.join("gitdir"),
                format!("{}\n", r.join(back).display()),
            )
            .unwrap();
            assert_eq!(
                detect_worktree(&tree, &home),
                left_out(&tree, &git_dir, WorktreeLeft::Link(r.join("walias"))),
                "{back}"
            );
        }
        // With no link on the way: a worktree.
        std::fs::write(git_dir.join("gitdir"), format!("{}\n", dotgit.display())).unwrap();
        assert_eq!(
            detect_worktree(&tree, &home),
            (
                Some(Worktree {
                    git_dir,
                    common_dir: common
                }),
                None
            )
        );
        // A project that is its own repository, its `worktrees/x` naming it
        // back, with `L` a link to the folder above it: its `.git` and the
        // `commondir` name the project through `nx/../L/app`.
        let app = r.join("code/app");
        git_dir_by_hand(&app);
        let x = app.join("worktrees/x");
        std::fs::create_dir_all(&x).unwrap();
        std::fs::write(
            x.join("gitdir"),
            format!("{}\n", app.join(".git").display()),
        )
        .unwrap();
        std::fs::write(
            x.join("commondir"),
            format!("{}\n", app.join("nx/../L/app").display()),
        )
        .unwrap();
        symlink("..", app.join("L")).unwrap();
        let forged = Path::new("nx/../L/app/worktrees/x");
        std::fs::write(app.join(".git"), format!("gitdir: {}\n", forged.display())).unwrap();
        assert_eq!(
            detect_worktree(&app, &home),
            left_out(&app, forged, WorktreeLeft::Link(app.join("L")))
        );
    }

    /// CWWT-SEC-1, C4: a submodule's git folder names its work tree in its
    /// config (`core.worktree`), which a program in the jail can write too.
    /// Named through a folder that is not there and a link back to the
    /// folder above (`../../../nx/../SL/sub`, `SL` a link to `.`), or
    /// through a folder that is not there alone (`../../../nx/../sub`), it
    /// names no work tree: the kernel stops at `nx`, and so does git. Its
    /// own test, so that each assert here is reached with the fix reverted.
    ///
    /// FAILS ON REVERT (Linux and macOS): stop reading steps after one that
    /// is not there and take a way through one (as before): the walk takes
    /// `nx/../SL/sub` with no link and `nx/../sub` as a place, and
    /// `nx/../sub` names the project as its work tree. (On Linux the
    /// spelling through `SL` was no worktree before either: the walk gave
    /// `super/SL/sub`, which is not the project's spelling.)
    #[cfg(unix)]
    #[test]
    fn a_submodule_whose_work_tree_is_named_through_a_missing_folder_is_no_worktree() {
        use crate::contain::WorktreeLeft;
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        std::fs::create_dir_all(&home).unwrap();
        // A submodule whose config names its work tree through a folder
        // that is not there and a link back to it: no work tree named.
        let modules = r.join("super/.git/modules/sub");
        git_dir_by_hand(&modules);
        std::fs::create_dir_all(r.join("super/sub")).unwrap();
        symlink(".", r.join("super/SL")).unwrap();
        std::fs::write(r.join("super/sub/.git"), "gitdir: ../.git/modules/sub\n").unwrap();
        let named = Path::new("../.git/modules/sub");
        // What the walk finds for each spelling, apart: on Linux the
        // spelling through `SL` was no worktree before either (`super/SL/
        // sub` is not the project's spelling), so the walk itself is what
        // these hold: through the link, and through `nx` alone.
        assert_eq!(
            folder_without_links(&modules.join("../../../nx/../SL/sub")),
            Err(WorktreeLeft::Link(r.join("super/SL")))
        );
        assert_eq!(
            folder_without_links(&modules.join("../../../nx/../sub")),
            Err(WorktreeLeft::NotThere(r.join("super/nx")))
        );
        for tree_named in [
            "../../../sub",
            "../../../nx/../SL/sub",
            "../../../nx/../sub",
        ] {
            std::fs::write(
                modules.join("config"),
                format!("[core]\n\tbare = false\n\tworktree = {tree_named}\n"),
            )
            .unwrap();
            let found = detect_worktree(&r.join("super/sub"), &home);
            if tree_named == "../../../sub" {
                assert!(found.0.is_some(), "{found:?}");
            } else {
                assert_eq!(
                    found,
                    left_out(&r.join("super/sub"), named, WorktreeLeft::NoBackLink),
                    "{tree_named}"
                );
            }
        }
    }

    /// CW-worktree-gitdir (macOS): on a disk that tells no case apart, a
    /// worktree's `.git` and its link back may spell a folder in another
    /// case than the disk does (`~/Code` for `~/code`), as git keeps what
    /// it was given. That is no link: the worktree is found, spelled as the
    /// disk spells it, as the project is and as the sandbox matches it. A
    /// disk that tells case apart has no such folder, and the test says so.
    ///
    /// FAILS ON REVERT: keep each place as the files spell it and the link
    /// back names another project.
    #[cfg(target_os = "macos")]
    #[test]
    fn on_macos_a_worktree_spelled_in_another_case_is_found_as_the_disk_spells_it() {
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let (tree, git_dir, common) = worktree_by_hand(&r, false);
        if std::fs::symlink_metadata(r.join("MAIN")).is_err() {
            eprintln!("this disk tells case apart: nothing to find");
            return;
        }
        std::fs::write(
            tree.join(".git"),
            format!("gitdir: {}\n", r.join("MAIN/.git/worktrees/w").display()),
        )
        .unwrap();
        std::fs::write(
            git_dir.join("gitdir"),
            format!("{}\n", r.join("W/.git").display()),
        )
        .unwrap();
        assert_eq!(
            detect_worktree(&tree, Path::new("/nonexistent-home")),
            (
                Some(Worktree {
                    git_dir,
                    common_dir: common
                }),
                None
            )
        );
    }

    /// CW-worktree-gitdir (Linux): the real run binds a worktree's git
    /// folder and its repository from descriptors it opens just before
    /// bwrap starts ([`hold_binds`]), as it binds a profile's read-only
    /// paths. A program in a jail of the repository's own project writes
    /// that repository, and swapped its `.git` for a link to a folder of
    /// the home after the launcher found the worktree: the launch stops and
    /// says so; nothing of the worktree is bound by name. That folder of the
    /// home holds a `worktrees/w` folder, so the walk opens it to the end
    /// and the launch stops because the git folder leads there now (not on
    /// a step that is not there). And a git folder swapped for a regular
    /// file opens with no link on the way, at its own place, and stops the
    /// launch because it is no folder now (CWWT-T2).
    ///
    /// FAILS ON REVERT: leave the worktree's folders out of
    /// `places_bound_from_descriptors` and the swapped folder is bound by
    /// name, read-write, where the link leads; drop the check that a place
    /// opened is where it was found and the link is held; drop the check
    /// that a worktree's folder is a folder still and bwrap is handed the
    /// file.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_worktree_folder_swapped_for_a_link_after_the_plan_stops_the_launch() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        std::fs::create_dir_all(home.join(".kube/worktrees/w")).unwrap();
        let (tree, git_dir, common) = worktree_by_hand(&r, false);
        let rest: Vec<String> = ["--project", tree.to_str().unwrap(), "--", "true"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let args = parse_contain_args(&rest).unwrap();
        let input = resolve_inputs(args, home.clone(), PathBuf::from("/usr/bin/true")).unwrap();
        assert_eq!(
            input.worktree,
            Some(Worktree {
                git_dir: git_dir.clone(),
                common_dir: common.clone(),
            })
        );
        let (held_input, held) = hold_binds(&input, true).unwrap();
        let a = build_linux_jail(&held_input).unwrap().bwrap_args;
        for dir in [&git_dir, &common] {
            assert!(
                a.windows(3)
                    .any(|x| x[0] == "--bind-fd" && x[2] == dir.to_str().unwrap()),
                "{a:?}"
            );
            assert!(
                !a.windows(3)
                    .any(|x| x[0] == "--bind" && x[2] == dir.to_str().unwrap()),
                "{a:?}"
            );
        }
        drop(held);
        // A jail of `main` swaps its `.git` for a link to `~/.kube`.
        std::fs::rename(&common, r.join("main/.git.old")).unwrap();
        symlink(home.join(".kube"), &common).unwrap();
        assert_eq!(
            hold_binds(&input, true).unwrap_err(),
            crate::contain::held_place_changed(
                &git_dir,
                &format!(
                    "it leads to {} now",
                    home.join(".kube/worktrees/w").display()
                )
            )
        );
        // Put back, then the git folder swapped for a regular file.
        std::fs::remove_file(&common).unwrap();
        std::fs::rename(r.join("main/.git.old"), &common).unwrap();
        assert!(hold_binds(&input, true).is_ok());
        std::fs::rename(&git_dir, common.join("worktrees/w.old")).unwrap();
        std::fs::write(&git_dir, "not a folder\n").unwrap();
        assert_eq!(
            hold_binds(&input, true).unwrap_err(),
            crate::contain::held_place_changed(&git_dir, "it is no folder now")
        );
        // A bwrap that binds no descriptor: nothing opened.
        let (same, none) = hold_binds(&input, false).unwrap();
        assert!(none.is_empty() && same.bind_fds.is_empty());
    }

    /// CWWT-SEC-1, live (Linux, the host's own bwrap): a program in a jail
    /// of the project `app` lays it out as its own repository (`HEAD`,
    /// `objects`, `refs`, `worktrees/x` naming its `.git` back), puts `L`, a
    /// link to the folder above it, there, and has its `.git` and
    /// `commondir` name the project through `nx/../L/app` (`nx` is not
    /// there). The profile shows `app/vendor` read-only. The worktree was
    /// taken by that spelling, `app/L/app`: the read-only bind of `vendor`
    /// came before the worktree's bind, which bwrap took through `L` onto
    /// the project, and the jail wrote `vendor` (measured with bwrap 0.9.0
    /// on Ubuntu 24.04); where bwrap binds from descriptors the link stopped
    /// every launch. Now no worktree is found, the one line says why, and in
    /// the plan bwrap runs by name (a bwrap that binds no descriptor) and,
    /// where this bwrap binds them, in the one it runs from descriptors, the
    /// jail starts and `vendor` stays as it was. A host whose bwrap cannot
    /// start a jail fails the test (CWWT-C5): it would prove nothing.
    ///
    /// FAILS ON REVERT: stop reading steps after one that is not there and
    /// take a way through one (as before): the line is not said. (The
    /// worktree it then finds, spelled through `L`, lies in the project by
    /// that spelling, so since CWWT-C2 it is not bound either; before that
    /// the by-name jail wrote `vendor`, and the descriptor plan stopped the
    /// launch.)
    #[cfg(target_os = "linux")]
    #[test]
    fn a_worktree_forged_through_a_missing_folder_never_makes_a_read_only_path_writable() {
        use crate::contain::WorktreeLeft;
        use std::os::unix::fs::symlink;
        let bwrap = resolve_backend(BWRAP_PATHS)
            .expect("this test runs the host's bubblewrap: install bwrap instead of skipping it");
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let app = r.join("code/app");
        git_dir_by_hand(&app);
        let x = app.join("worktrees/x");
        std::fs::create_dir_all(&x).unwrap();
        std::fs::write(
            x.join("gitdir"),
            format!("{}\n", app.join(".git").display()),
        )
        .unwrap();
        std::fs::write(
            x.join("commondir"),
            format!("{}\n", app.join("nx/../L/app").display()),
        )
        .unwrap();
        symlink("..", app.join("L")).unwrap();
        let forged = Path::new("nx/../L/app/worktrees/x");
        std::fs::write(app.join(".git"), format!("gitdir: {}\n", forged.display())).unwrap();
        let vendor = app.join("vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(vendor.join("f"), "orig").unwrap();
        let script = format!(
            "echo AGENT > '{}' 2>/dev/null; echo STARTED",
            vendor.join("f").display()
        );
        let rest: Vec<String> = [
            "--project",
            app.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &script,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let mut args = parse_contain_args(&rest).unwrap();
        args.extra_ro = vec![vendor.clone()];
        let input = resolve_inputs(args, home.clone(), PathBuf::from("/usr/bin/true")).unwrap();
        assert_eq!(input.worktree, None);
        assert!(
            input.left.contains(&crate::contain::worktree_left_out(
                &app.join(".git"),
                forged,
                &WorktreeLeft::Link(app.join("L"))
            )),
            "{:?}",
            input.left
        );
        let input = with_linked_places_made(&input);
        // CWWT-C5: a host whose bwrap cannot start a jail proves nothing
        // here, so it fails rather than pass with nothing run.
        if let Some(lines) = restriction_advice(&bwrap, true) {
            panic!(
                "this test runs a jail with the host's bubblewrap, which cannot start one here \
                 (lift the restriction, as CI does, instead of skipping it): {lines:?}"
            );
        }
        let by_descriptor = bwrap_binds_fds();
        for takes_fds in [false, true] {
            if takes_fds && !by_descriptor {
                eprintln!("this bwrap binds no descriptor: the by-name plan only");
                continue;
            }
            let (held_input, held) = hold_binds(&input, takes_fds)
                .unwrap_or_else(|why| panic!("fds {takes_fds}: the launch stopped: {why}"));
            let plan = build_linux_jail(&held_input).unwrap();
            assert!(
                !plan.bwrap_args.iter().any(|arg| arg.contains("/L/")),
                "{:?}",
                plan.bwrap_args
            );
            let out = Command::new(&bwrap)
                .args(&plan.bwrap_args)
                .envs(plan.env.iter().cloned())
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            drop(held);
            let said = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success() && said.contains("STARTED"),
                "fds {takes_fds}: {said} {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                std::fs::read_to_string(vendor.join("f")).unwrap(),
                "orig",
                "fds {takes_fds}"
            );
        }
    }

    /// CWWT-C3: a link inside a hidden dotdir leads into a folder every jail
    /// writes (`~/.ssh/config` a link to `~/.local/share/dots/ssh_config`),
    /// and a program in a jail lays a repository out around it there (it
    /// writes `~/.local`), with `worktrees/x` naming the project back and the
    /// project's `.git` naming that. The next launch refused to start
    /// ("unsafe worktree common path ... which the jail hides"), where any
    /// other `.git` file that is no worktree to show is one line and a jail
    /// that starts. The jail shows `~/.local` anyway, so the worktree is not
    /// bound and nothing is said; the same in `~/dots`, which no jail shows,
    /// is left out with one line. Either way the jail starts, and the place
    /// the link leads to stays hidden.
    ///
    /// FAILS ON REVERT: keep the worktree the plan finds over a hidden place
    /// (as before) and the launch is refused.
    #[cfg(unix)]
    #[test]
    fn a_worktree_over_where_a_link_in_a_hidden_dotdir_leads_never_stops_the_launch() {
        use crate::contain::WorktreeLeft;
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let proj = r.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let macos = cfg!(target_os = "macos");
        for (repo, said) in [
            (home.join(".local/share/dots"), false),
            (home.join("dots"), true),
        ] {
            git_dir_by_hand(&repo);
            std::fs::write(repo.join("ssh_config"), "Host *\n").unwrap();
            let x = repo.join("worktrees/x");
            std::fs::create_dir_all(&x).unwrap();
            std::fs::write(
                x.join("gitdir"),
                format!("{}\n", proj.join(".git").display()),
            )
            .unwrap();
            std::fs::write(x.join("commondir"), "../..\n").unwrap();
            let _ = std::fs::remove_file(home.join(".ssh/config"));
            symlink(repo.join("ssh_config"), home.join(".ssh/config")).unwrap();
            std::fs::write(proj.join(".git"), format!("gitdir: {}\n", x.display())).unwrap();
            assert_eq!(
                detect_worktree(&proj, &home).0,
                Some(Worktree {
                    git_dir: x.clone(),
                    common_dir: repo.clone(),
                }),
                "{}",
                repo.display()
            );
            let rest: Vec<String> = ["--project", proj.to_str().unwrap(), "--", "true"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let args = parse_contain_args(&rest).unwrap();
            let input = resolve_inputs(args, home.clone(), PathBuf::from("/usr/bin/true")).unwrap();
            assert_eq!(input.worktree, None, "{}", repo.display());
            let line = crate::contain::worktree_left_out(
                &proj.join(".git"),
                &x,
                &WorktreeLeft::Hidden {
                    folder: repo.clone(),
                    place: repo.join("ssh_config"),
                    through: Some(home.join(".ssh/config")),
                },
            );
            assert_eq!(input.left.contains(&line), said, "{:?}", input.left);
            assert!(
                !input.left.iter().any(|l| l.contains("as its git folder")) || said,
                "{:?}",
                input.left
            );
            validate_jail_inputs_for(&input, macos)
                .unwrap_or_else(|why| panic!("{}: the launch stopped: {why}", repo.display()));
        }
    }

    /// CWWT-BRK-1, C2: a worktree of a repository in a home folder every
    /// jail shows writable (`~/.config/nvim`) is a worktree, and the jail
    /// shows it there anyway: once planned it is not bound, and nothing is
    /// said. Where a profile's read-only path holds the repository, the
    /// worktree is bound as any other, so git in the jail still writes it
    /// (the worktree's write wins there, as it does in every other place).
    ///
    /// FAILS ON REVERT: take every folder of the home whose name starts with
    /// a dot as one no jail shows (before BRK-1) and the read-only path wins
    /// over the worktree; bind a worktree the jail shows anyway (before C2)
    /// and the plan keeps it.
    #[cfg(unix)]
    #[test]
    fn a_worktree_in_a_folder_every_jail_writes_is_shown_by_that_folder() {
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let home = r.join("home");
        let repo = home.join(".config/nvim");
        git_dir_by_hand(&repo.join(".git"));
        let git_dir = repo.join(".git/worktrees/w");
        std::fs::create_dir_all(&git_dir).unwrap();
        let tree = home.join("code/w");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(
            git_dir.join("gitdir"),
            format!("{}\n", tree.join(".git").display()),
        )
        .unwrap();
        std::fs::write(git_dir.join("commondir"), "../..\n").unwrap();
        std::fs::write(
            tree.join(".git"),
            format!("gitdir: {}\n", git_dir.display()),
        )
        .unwrap();
        let worktree = Worktree {
            git_dir: git_dir.clone(),
            common_dir: repo.join(".git"),
        };
        assert_eq!(
            detect_worktree(&tree, &home),
            (Some(worktree.clone()), None)
        );
        let rest: Vec<String> = ["--project", tree.to_str().unwrap(), "--", "true"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let args = parse_contain_args(&rest).unwrap();
        let input =
            resolve_inputs(args.clone(), home.clone(), PathBuf::from("/usr/bin/true")).unwrap();
        assert_eq!(input.worktree, None);
        assert!(input.left.is_empty(), "{:?}", input.left);
        let mut read_only = args;
        read_only.extra_ro = vec![repo.clone()];
        let input = resolve_inputs(read_only, home, PathBuf::from("/usr/bin/true")).unwrap();
        assert_eq!(input.worktree, Some(worktree));
    }

    /// CRIT-3: a repository made with `--separate-git-dir` (`git init` or
    /// `git clone`, as dotfile managers lay theirs out): its `.git` file
    /// names a git folder that keeps no `commondir`, no `gitdir` back and no
    /// `core.worktree` (git 2.52 writes only `repositoryformatversion`,
    /// `filemode`, `bare` and `logallrefupdates`), the same as a folder a
    /// program in a jail named. It is not shown (the jail before this phase
    /// bound it read-write), and the line says what to do: move the git
    /// folder into the project, or work in a linked worktree. Laid out by
    /// hand as git lays it, and by git itself where this host has git.
    ///
    /// FAILS ON REVERT: take a git folder with no `commondir` as the
    /// project's own (as before), or drop the remedy from the line.
    #[cfg(unix)]
    #[test]
    fn a_separate_git_dir_is_not_shown_and_the_line_says_what_to_do() {
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let effect = if cfg!(target_os = "macos") {
            "the jail does not let a program in it write there (git in the jail cannot commit \
             here)"
        } else {
            "the jail does not show it (git in the jail sees no repository here)"
        };
        let said = |dotgit: &Path, named: &Path| {
            format!(
                "{} names {} as its git folder, and that folder does not name this project \
                 back: {effect}. For a repository made with --separate-git-dir, move its git \
                 folder into the project in place of the .git file, or work in a worktree made \
                 with git worktree add",
                dotgit.display(),
                named.display()
            )
        };
        let store = r.join("store.git");
        let proj = r.join("proj");
        git_dir_by_hand(&store);
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            store.join("config"),
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\
             \tlogallrefupdates = true\n",
        )
        .unwrap();
        std::fs::write(proj.join(".git"), format!("gitdir: {}\n", store.display())).unwrap();
        assert_eq!(
            detect_worktree(&proj, &r),
            (None, Some(said(&proj.join(".git"), &store)))
        );
        // Made by git itself, where this host has it.
        let made = r.join("made");
        let made_store = r.join("made-store.git");
        let git = Command::new("git")
            .args(["init", "-q", "--separate-git-dir"])
            .arg(&made_store)
            .arg(&made)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", &r)
            .stdin(std::process::Stdio::null())
            .output();
        if git.is_ok_and(|out| out.status.success()) {
            assert_eq!(
                detect_worktree(&made, &r),
                (None, Some(said(&made.join(".git"), &made_store)))
            );
        }
    }

    /// CWNF-1: the launcher read the project's `.git` file and the
    /// `commondir` it names with a blocking read, and a program in the jail
    /// writes both: a FIFO there held the launcher for as long as that
    /// program liked, after it had looked at the profile's read-only paths
    /// and before bwrap bound them (measured: one stall was enough to swap
    /// a checked folder for a link). Each such file is read without
    /// waiting, a regular file only, a few bytes at most: a FIFO is no
    /// worktree, at once.
    ///
    /// FAILS ON REVERT: read `commondir` with `std::fs::read_to_string` (as
    /// before) and the launcher waits on the FIFO until the test gives up.
    #[cfg(unix)]
    #[test]
    fn a_fifo_in_the_projects_git_files_never_holds_the_launcher() {
        let root = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(root.path()).unwrap();
        let (tree, git_dir, _) = worktree_by_hand(&r, false);
        std::fs::remove_file(git_dir.join("commondir")).unwrap();
        let fifo = std::ffi::CString::new(git_dir.join("commondir").to_str().unwrap()).unwrap();
        // SAFETY: a NUL-ended path alive for the call.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let (done, waited) = std::sync::mpsc::channel();
        let looked = tree.clone();
        std::thread::spawn(move || {
            let _ = done.send(detect_worktree(&looked, Path::new("/nonexistent-home")));
        });
        let found = waited
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the launcher waited on a FIFO in the project's git files");
        assert_eq!(found.0, None);
        // A huge `.git` file is not read whole either.
        std::fs::write(tree.join(".git"), "x".repeat(1 << 20)).unwrap();
        assert_eq!(detect_worktree(&tree, &r), (None, None));
    }
}
