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
    build_linux_jail, build_macos_profile, parse_contain_args, validate_jail_inputs, ContainArgs,
    JailInputs, Worktree,
};

/// `innerwarden contain [--agent claude-code] [--monitor|--enforce|--block-review]
/// [--project DIR] [--dry-run] [--setup] -- <command...>` - run the command inside
/// a filesystem/namespace jail with the InnerWarden hook active inside it.
pub fn cmd(rest: &[String]) -> ExitCode {
    let args = match parse_contain_args(rest) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("innerwarden contain: {e}");
            return ExitCode::from(2);
        }
    };

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
    let iw_binary = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("innerwarden contain: cannot resolve own path: {e}");
            return ExitCode::from(1);
        }
    };

    // --setup intentionally only arms the hook and therefore needs no project.
    // Every normal run validates all future writable binds BEFORE this host
    // mutation; an unsafe project must fail closed without changing settings.
    let (block_review, monitor) = args.mode.hook_flags();
    if args.setup_only {
        match hook::install_hook(&home, &args.agent, None, &iw_binary, block_review, monitor) {
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
    let mut args = args;
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
                    // Links resolved, so the check of what may be shown read-only
                    // is made on the place the bind would really show. A path
                    // that is not there is dropped (bwrap would skip it).
                    args.extra_ro = args
                        .extra_ro
                        .iter()
                        .filter_map(|path| std::fs::canonicalize(path).ok())
                        .collect();
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

    let mut input = match resolve_inputs(args, home, iw_binary) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("innerwarden contain: {error}");
            return ExitCode::from(2);
        }
    };
    if let Err(error) = validate_jail_inputs(&input) {
        eprintln!("innerwarden contain: {error}");
        return ExitCode::from(2);
    }

    // Arm the guard hook for the agent (idempotent) - but NOT on --dry-run, which
    // must be read-only and never mutate the real ~/.claude/settings.json. The jail
    // binds the real ~/.claude, so this same settings.json is what fires the hook
    // INSIDE the jail; it also keeps the guard on for the host agent (same guard,
    // walls only in the jail). Mode comes from the flags.
    if !input.args.dry_run {
        match hook::install_hook(
            &input.home,
            &input.args.agent,
            None,
            &input.iw_binary,
            block_review,
            monitor,
        ) {
            Ok(_) => {}
            Err(e) => eprintln!(
                "innerwarden contain: could not arm the in-jail hook: {e} (running with walls only)"
            ),
        }
        // On an account where Claude Code never ran, arming the hook made
        // `~/.claude` after the jail was planned without it: the jail would
        // show no `~/.claude`, so no settings file and no hook. The jail is
        // planned again, and checked again, on what is there now.
        if existing_home_paths(&input.home) != input.existing_paths {
            input = match resolve_inputs(
                input.args.clone(),
                input.home.clone(),
                input.iw_binary.clone(),
            ) {
                Ok(input) => input,
                Err(error) => {
                    eprintln!("innerwarden contain: {error}");
                    return ExitCode::from(2);
                }
            };
            if let Err(error) = validate_jail_inputs(&input) {
                eprintln!("innerwarden contain: {error}");
                return ExitCode::from(2);
            }
        }
    }

    // Each place the jail hides that a link leads out of the home, onto
    // what the jail needs, or round in a loop: left as it is, and said.
    for line in &input.left {
        eprintln!("innerwarden contain: {line}");
    }

    if cfg!(target_os = "linux") {
        run_linux(&input, marks)
    } else if cfg!(target_os = "macos") {
        run_macos(&input)
    } else {
        eprintln!(
            "innerwarden contain: containment needs Linux (bubblewrap) or macOS (sandbox-exec); this OS is not supported"
        );
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

fn resolve_inputs(
    args: ContainArgs,
    home: PathBuf,
    iw_binary: PathBuf,
) -> Result<JailInputs, crate::contain::ContainError> {
    // Canonicalize TMPDIR too (macOS $TMPDIR is under the /var symlink) so the
    // writable-set rule matches the resolved path.
    let tmpdir = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
        .unwrap_or_else(|| PathBuf::from("/tmp"));

    let existing_paths = existing_home_paths(&home);

    let usr_merged = std::fs::symlink_metadata("/bin")
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);

    let worktree = detect_worktree(&args.project);

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
    // What no mask laid because of a link may cover, and where a place not
    // there yet is never covered (bwrap cannot make it there).
    let needed = crate::contain::jail_needs(&args, &home, worktree.as_ref(), &iw_binary, |path| {
        std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    });
    let read_only = crate::contain::read_only_shown(&args, &home);
    let mut left: Vec<String> = Vec::new();

    // Linux: the secret dir at every other place a home folder the jail
    // binds shows it. Empty in every common layout. Where the dir itself
    // is a link, at every place the jail shows where it leads, and never
    // where it leads outside the person's own places (said).
    let (iw_config_real, iw_config_shown, iw_config_outside, iw_linked) = if iw_config_link {
        let place = hidden_place(&iw_config_named);
        let real = place
            .leads_to
            .clone()
            .unwrap_or_else(|| iw_config_through.clone());
        let outside = place.leads_to.as_ref().is_some_and(|leads_to| {
            !crate::contain::in_own_places(leads_to, &home, &shown, &read_only)
        });
        let mut linked =
            crate::contain::plan_linked_places(&[place], &home, &shown, &read_only, &needed, &[]);
        // A mount over a file there would abort the jail; only a folder
        // is InnerWarden's folder.
        linked.masks.retain(|mask| mask.is_dir);
        let views = if cfg!(target_os = "linux") {
            linked.masks.iter().map(|mask| mask.abs.clone()).collect()
        } else {
            Vec::new()
        };
        left.append(&mut linked.left);
        (real, views, outside, linked.missing)
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
        (iw_config_through, views, false, Vec::new())
    };

    // Expand the deny_read globs against the real project + stat each match so the
    // builder knows file-vs-dir (Linux masks a file with /dev/null, a dir with tmpfs).
    // Each is masked where it leads, and at every other place the jail
    // shows it; one a link leads out of the home or onto what the jail
    // needs is left as it is (said).
    let (deny_paths, mut deny_linked) = crate::contain::plan_denied_paths(
        &deny_read_places(&args.project, &args.deny_read),
        &home,
        &shown,
        &read_only,
        &needed,
    );
    left.append(&mut deny_linked.left);

    // The dotdirs the jail never shows, where a link leads one into a
    // folder it shows (`~/.ssh` a link to `.config/ssh`): covered there too
    // on Linux, denied where it leads on macOS. Empty in every common
    // layout.
    let mut dotdirs_linked = crate::contain::plan_linked_places(
        &crate::contain::never_shown_home_paths(&home, cfg!(target_os = "macos"))
            .iter()
            .map(|path| hidden_place(path))
            .collect::<Vec<_>>(),
        &home,
        &shown,
        &read_only,
        &needed,
        &[
            vec![iw_config_named.clone(), iw_config_real.clone()],
            iw_config_shown.clone(),
        ]
        .concat(),
    );
    left.append(&mut dotdirs_linked.left);
    let (linked_masks, linked_missing, linked_denies) = if cfg!(target_os = "linux") {
        let mut masks = dotdirs_linked.masks;
        for mask in deny_linked.masks {
            if !masks.iter().any(|seen| seen.abs == mask.abs) {
                masks.push(mask);
            }
        }
        let mut missing = iw_linked;
        missing.append(&mut dotdirs_linked.missing);
        missing.append(&mut deny_linked.missing);
        (masks, missing, Vec::new())
    } else {
        (Vec::new(), Vec::new(), dotdirs_linked.denies)
    };

    // The home paths a jail profile hides: where each leads, every link
    // followed, covered where the jail shows it (Linux) and denied as named
    // and as resolved (macOS). Without such a profile nothing is read.
    let hidden = if args.hide_home.is_empty() {
        crate::contain::HiddenPlan::default()
    } else {
        let found = hidden_home_facts(&home, &args.hide_home);
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

    // Only an identified launch hides the launcher's records and keeps its
    // helpers' environment apart; without the flag none of this is read.
    let (records_dirs, child_env) = if args.identity {
        let nominal = crate::contain::launch::records_dir(
            std::env::var("XDG_STATE_HOME").ok().as_deref(),
            &home,
        );
        let real = leads_to(&nominal).unwrap_or_else(|| resolved_through_existing(&nominal));
        // Never as named where a link below the home folder it is in leads
        // it elsewhere (`~/.local/state` a link): bwrap would make the
        // mount point through the link in its own root, and the jail never
        // started. Where it leads is hidden, and the launcher makes it there.
        let named = [nominal.clone(), real.clone()];
        let mut dirs = if goes_through_a_link(&home, &nominal) {
            vec![real.clone()]
        } else {
            vec![nominal]
        };
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
        (
            dirs,
            crate::contain::launch_env(std::env::vars_os()).child_env,
        )
    } else {
        (Vec::new(), Vec::new())
    };

    // Only an identified Linux launch keeps Claude Code's own state in the
    // folder the jail shares with the host; without the flag none of it is
    // read. Read only here: the folders the jail covers are made by the
    // real run alone, after every check ([`with_claude_folders_made`]).
    #[cfg(target_os = "linux")]
    let claude_state = if args.identity {
        claude_state_for(
            &args,
            &home,
            worktree.as_ref(),
            &existing_paths,
            &iw_binary,
            false,
        )
    } else {
        crate::contain::ClaudeState::default()
    };
    #[cfg(not(target_os = "linux"))]
    let claude_state = crate::contain::ClaudeState::default();

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
        iw_config_outside,
        linked_masks,
        linked_missing,
        linked_denies,
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
        resolv_conf,
        gate_instance: None,
        claude_state,
    })
}

/// Where an identified jail can keep Claude Code's own state, as found on
/// the host for `args` ([`claude_state_here`]): what the jail shows of the
/// host ([`crate::contain::shown_host_folders`]) and what it needs under
/// it (the project, the worktree's folders, the read-only paths, the
/// guard).
#[cfg(target_os = "linux")]
fn claude_state_for(
    args: &ContainArgs,
    home: &Path,
    worktree: Option<&crate::contain::Worktree>,
    existing: &[PathBuf],
    iw_binary: &Path,
    make: bool,
) -> crate::contain::ClaudeState {
    let shown = crate::contain::shown_host_folders(args, home, worktree, existing, |path| {
        std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    });
    let mut needed = vec![args.project.clone(), iw_binary.to_path_buf()];
    if let Some(worktree) = worktree {
        needed.push(worktree.git_dir.clone());
        needed.push(worktree.common_dir.clone());
    }
    needed.extend(args.extra_ro.iter().cloned());
    claude_state_here(home, &shown, &needed, make)
}

/// Where an identified jail can keep Claude Code's own state, as found on
/// the host ([`crate::contain::ClaudeState`]). Only where `~/.claude` is a
/// folder (the jail shares it). Its settings file there may be a file or
/// not there yet, never a link or anything else, and never the person's
/// own `~/.claude.json` ([`own_settings_in_claude`]). Each folder of
/// Claude Code's runs there must be a folder of its own; one that is not
/// there yet counts as made when `make` is false (a dry run, or the plan
/// before the checks: nothing is made, and the real run does what it
/// shows), and is made, empty and 0700 as Claude Code makes it, when `make`
/// is true (the real run, after every check). Each is covered where the
/// jail shows it ([`crate::contain::plan_claude_folders`]).
#[cfg(target_os = "linux")]
fn claude_state_here(
    home: &Path,
    shown: &[(PathBuf, PathBuf)],
    needed: &[PathBuf],
    make: bool,
) -> crate::contain::ClaudeState {
    use crate::contain::{ClaudeState, CLAUDE_RUN_FOLDERS, CLAUDE_SETTINGS_KEPT};
    use std::io::ErrorKind;
    let claude = home.join(".claude");
    if !std::fs::metadata(&claude).is_ok_and(|meta| meta.is_dir()) {
        return ClaudeState::default();
    }
    let Ok(claude_real) = std::fs::canonicalize(&claude) else {
        return ClaudeState::default();
    };
    let kept = home.join(CLAUDE_SETTINGS_KEPT);
    let settings_kept = match std::fs::symlink_metadata(&kept) {
        Ok(meta) => meta.is_file(),
        Err(error) => error.kind() == ErrorKind::NotFound,
    } && !own_settings_in_claude(home, &claude_real, &kept);
    let mut real = Vec::new();
    let mut shared = false;
    for name in CLAUDE_RUN_FOLDERS {
        let folder = claude.join(name);
        let own = match std::fs::symlink_metadata(&folder) {
            Ok(meta) => meta.is_dir(),
            Err(error) if error.kind() == ErrorKind::NotFound => !make || own_folder(&folder),
            Err(_) => false,
        };
        if own {
            real.push(claude_real.join(name));
        } else {
            shared = true;
        }
    }
    let (own_folders, left) = crate::contain::plan_claude_folders(&real, shown, needed);
    ClaudeState {
        settings_kept,
        own_folders,
        shared: shared || left,
    }
}

/// The person's own `~/.claude.json` is the kept file, or leads into
/// `~/.claude` (a dotfiles manager's link to `.claude/.claude.json`, a hard
/// link, or a link that leads to nothing yet, where a save would make the
/// file): a jail's link to the kept file would then hand the jail the
/// person's own settings file, and its saves would land on it.
#[cfg(target_os = "linux")]
fn own_settings_in_claude(home: &Path, claude_real: &Path, kept: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let own = home.join(crate::contain::CLAUDE_SETTINGS);
    let entry = match std::fs::symlink_metadata(&own) {
        Ok(entry) => entry,
        Err(error) => return error.kind() != std::io::ErrorKind::NotFound,
    };
    let same_file = std::fs::metadata(&own)
        .ok()
        .zip(std::fs::symlink_metadata(kept).ok())
        .is_some_and(|(own, kept)| own.dev() == kept.dev() && own.ino() == kept.ino());
    if same_file {
        return true;
    }
    entry.file_type().is_symlink()
        && std::fs::canonicalize(&own).map_or(true, |real| real.starts_with(claude_real))
}

/// Make `folder` empty and 0700, as Claude Code makes it, and say whether it
/// is a folder of its own now. Another launch that made it first (two
/// identified launches at once, on a home that had none) is no failure: a
/// folder that is there, and no link, is the same folder.
#[cfg(target_os = "linux")]
fn own_folder(folder: &Path) -> bool {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o700).create(folder) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::symlink_metadata(folder).is_ok_and(|meta| meta.is_dir())
        }
        Err(_) => false,
    }
}

/// The real run of an identified jail, after every check: Claude Code's
/// folders of its runs made where they are not there, and what the jail
/// covers read again ([`claude_state_for`]). A folder that cannot be made
/// is shared, and that is said once.
#[cfg(target_os = "linux")]
fn with_claude_folders_made(input: &JailInputs) -> JailInputs {
    let mut input = input.clone();
    input.claude_state = claude_state_for(
        &input.args,
        &input.home,
        input.worktree.as_ref(),
        &input.existing_paths,
        &input.iw_binary,
        true,
    );
    say_claude_state(&input.claude_state);
    input
}

/// Said once where an identified jail cannot give Claude Code a folder of
/// its runs of its own.
#[cfg(target_os = "linux")]
fn say_claude_state(state: &crate::contain::ClaudeState) {
    if state.shared {
        eprintln!("innerwarden contain: {CLAUDE_FOLDERS_SHARED}");
    }
}

/// [`say_claude_state`]'s sentence.
#[cfg(target_os = "linux")]
const CLAUDE_FOLDERS_SHARED: &str = "Claude Code's ~/.claude/sessions or ~/.claude/backups \
     is the host's in this jail, not one of its own (a link is there, a path the jail shows \
     is in it, or it could not be made)";

/// Each home path a jail profile hides, as found on the host: where it
/// leads with every link followed, where a file would be made when nothing
/// is there, whether it is a folder, and whether a link on the way leads to
/// nothing. On Linux a path that is not there yet, in a folder of the home
/// the jail writes, is first made as an empty folder ([`make_hidden_folder`]).
fn hidden_home_facts(home: &Path, paths: &[PathBuf]) -> Vec<crate::contain::HiddenHomePath> {
    paths
        .iter()
        .map(|nominal| {
            #[cfg(target_os = "linux")]
            if std::fs::symlink_metadata(nominal).is_err() {
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
/// ([`crate::contain::plan_denied_paths`]).
fn deny_read_places(project: &Path, patterns: &[String]) -> Vec<crate::contain::HiddenPlace> {
    let mut out: Vec<crate::contain::HiddenPlace> = Vec::new();
    let mut add = |path: PathBuf| {
        if !out.iter().any(|seen| seen.nominal == path) {
            out.push(hidden_place(&path));
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
/// (`metadata`, which follows the links, so both describe what is there).
fn hidden_place(nominal: &Path) -> crate::contain::HiddenPlace {
    let meta = std::fs::metadata(nominal);
    crate::contain::HiddenPlace {
        nominal: nominal.to_path_buf(),
        leads_to: leads_to(nominal),
        there: meta.is_ok(),
        is_dir: meta.is_ok_and(|meta| meta.is_dir()),
    }
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
/// from the first step that is not there (or cannot be read), the rest as
/// written, since nothing below it can be a link (`realpath -m`). That is
/// the place a file made through it would land, also where a link leads to
/// nothing yet. `None` where the links loop, or for a relative path.
pub(crate) fn leads_to(path: &Path) -> Option<PathBuf> {
    use std::path::Component;
    if !path.is_absolute() {
        return None;
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
    let mut links = 0;
    let mut gone = false;
    while let Some(step) = todo.pop() {
        if step == ".." {
            at.pop();
            continue;
        }
        at.push(&step);
        if gone {
            continue;
        }
        match std::fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_symlink() => {
                links += 1;
                if links > MAX_LINKS {
                    return None;
                }
                let target = std::fs::read_link(&at).ok()?;
                at.pop();
                if target.is_absolute() {
                    at = PathBuf::from("/");
                }
                push_steps(&mut todo, &target);
            }
            Ok(_) => {}
            Err(_) => gone = true,
        }
    }
    Some(at)
}

/// Make `place`, which is not there, as an empty folder, mode 0700, and
/// each folder missing on the way to it the same, as a folder of the
/// person's (as `ssh` or `gpg` would make it): from the nearest folder on
/// the way that is there, never through a link or a file. Whether it is a
/// folder now.
#[cfg(target_os = "linux")]
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
/// dropped, so the jail never fails to start over it.
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
    input
}

/// A linked git worktree stores its admin data OUTSIDE the project (its `.git` is a
/// FILE `gitdir: <path>`). Expose those dirs so `git` keeps working inside the jail.
fn detect_worktree(project: &Path) -> Option<Worktree> {
    let dotgit = project.join(".git");
    let meta = std::fs::symlink_metadata(&dotgit).ok()?;
    if !meta.is_file() {
        return None; // a normal repo: .git is a dir, already inside the project bind
    }
    let content = std::fs::read_to_string(&dotgit).ok()?;
    let rel = content.strip_prefix("gitdir:")?.trim();
    let git_dir = std::fs::canonicalize(rel).ok()?;
    // commondir points at the main repo's .git (relative to git_dir).
    let common_dir = std::fs::read_to_string(git_dir.join("commondir"))
        .ok()
        .and_then(|c| std::fs::canonicalize(git_dir.join(c.trim())).ok())
        .unwrap_or_else(|| git_dir.clone());
    Some(Worktree {
        git_dir,
        common_dir,
    })
}

/// The jail backend `innerwarden contain` would use on this machine, by name,
/// or `None` when there is none it trusts. The same lookup `contain` runs, so
/// the dashboard never says "Ready" for a jail that would refuse to start.
pub(crate) fn jail_backend() -> Option<&'static str> {
    if cfg!(target_os = "linux") {
        resolve_backend(&["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"]).map(|_| "bwrap")
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
/// a bwrap with no profile that grants it one).
pub(crate) fn jail_start_here() -> Option<Result<(), Vec<String>>> {
    if cfg!(target_os = "linux") {
        let bwrap = resolve_backend(&["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"])?;
        Some(restriction_advice(&bwrap).map_or(Ok(()), Err))
    } else {
        jail_backend().map(|_| Ok(()))
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
        .then(|| resolve_backend(&["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"]))
        .flatten();
    let dry_filter = dry_bwrap.as_ref().map(|bwrap| {
        dry_run_filter(restriction_advice(bwrap), || {
            filter_plan_here(bwrap, input.args.identity)
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
            ..input.clone()
        };
        &dry_identity
    } else if input.args.dry_run {
        // A plain jail shows the marker the real run hands in, and the
        // terminal filter where the host takes it.
        dry_plain = JailInputs {
            profiles_marker_fd: marks.then_some(crate::contain::launch::DRY_RUN_MARKER_FD),
            seccomp_fd: dry_seccomp,
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
        #[cfg(target_os = "linux")]
        if input.args.identity {
            say_claude_state(&input.claude_state);
        }
        println!("# innerwarden contain - DRY RUN (Linux / bubblewrap)");
        print_plan_env(&plan.env);
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
        println!("bwrap \\");
        println!("  {}", plan.bwrap_args.join(" "));
        return ExitCode::SUCCESS;
    }
    let Some(bwrap) = resolve_backend(&["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"])
    else {
        eprintln!(
            "innerwarden contain: bubblewrap (bwrap) not found. Install it:\n  Debian/Ubuntu: apt install bubblewrap\n  Fedora: dnf install bubblewrap\n  Arch: pacman -S bubblewrap"
        );
        return ExitCode::from(1);
    };
    // Say why the jail cannot be built BEFORE bwrap dies with an error that
    // names neither the cause nor the fix.
    if let Some(lines) = restriction_advice(&bwrap) {
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
    #[cfg(target_os = "linux")]
    if input.args.identity {
        return run_linux_identified(&with_claude_folders_made(input), &bwrap, marks);
    }
    announce(input);
    run_unrecorded(&bwrap, input, marks)
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
    let filter = unrecorded_filter(bwrap, input.args.identity);
    #[cfg(target_os = "linux")]
    let input = &JailInputs {
        profiles_marker_fd: marker.as_ref().map(std::os::fd::AsRawFd::as_raw_fd),
        seccomp_fd: filter.as_ref().map(std::os::fd::AsRawFd::as_raw_fd),
        ..input.clone()
    };
    #[cfg(not(target_os = "linux"))]
    let _ = marks;
    let code = match build_linux_jail(input) {
        Ok(plan) => run_plain(bwrap, &plan),
        Err(e) => {
            eprintln!("innerwarden contain: {e}");
            ExitCode::from(2)
        }
    };
    // Ours close only once bwrap has read them.
    #[cfg(target_os = "linux")]
    drop((marker, filter));
    code
}

/// The filter of a jail with no record, on a pipe for bwrap: the terminal
/// one, or for an `--identity` launch that could not make its record the
/// identified one (the terminal one where the host takes only that). What
/// it lost is said once; `None` where the host took neither or the pipe
/// could not be made.
#[cfg(target_os = "linux")]
fn unrecorded_filter(bwrap: &Path, identity: bool) -> Option<std::io::PipeReader> {
    let plan = filter_plan_here(bwrap, identity);
    for line in &plan.said {
        eprintln!("{line}");
    }
    handed_filter(plan.filter)
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
/// namespaces and `bwrap` has no AppArmor profile that grants it one. The
/// sysctl file exists only on kernels that carry the restriction; the profile
/// check is on disk because the loaded-profiles list is root-only.
fn restriction_advice(bwrap: &Path) -> Option<Vec<String>> {
    let sysctl =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").ok();
    let profile_on_disk = Path::new("/etc/apparmor.d/bwrap").exists()
        || Path::new("/etc/apparmor.d/usr.bin.bwrap").exists();
    crate::contain::userns_restriction_advice(sysctl.as_deref(), profile_on_disk, bwrap)
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
             folders only root can write), so the jail's hook will not ask Active Defence",
            path.display()
        );
    }
    key
}

/// The jail as it runs without `--identity`: bwrap, its arguments, waited for.
fn run_plain(bwrap: &Path, plan: &crate::contain::LinuxJailPlan) -> ExitCode {
    let status = Command::new(bwrap)
        .args(&plan.bwrap_args)
        .envs(plan.env.iter().cloned())
        .status();
    exit_from(status)
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
    let plan = match build_linux_jail(&identified) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("innerwarden contain: {e}");
            return Attempt::Done(ExitCode::from(2));
        }
    };
    let (program, args) = launch_argv(bwrap, &plan.bwrap_args, scope);
    let started_ms = now_ms();
    let mut command = Command::new(&program);
    command.args(&args).envs(plan.env.iter().cloned());
    helper_env(&mut command);
    let spawned = command.spawn();
    // Ours must close, or the read below never ends and the jail never sees
    // the end of its record.
    drop(info_writer);
    drop(record_reader);
    drop(key_reader);
    drop(filter_reader);
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) if matches!(scope, ScopePlan::User { .. }) => return Attempt::NeverStarted(Err(e)),
        Err(e) => return Attempt::Done(exit_from(Err(e))),
    };
    let info = read_info(&mut info_reader);
    drop(info_reader);
    let reported = match &info {
        InfoRead::Got(info) => Some(info.child_pid),
        _ => None,
    };
    let record = match info {
        InfoRead::Nothing => {
            drop(record_writer);
            return match child.wait() {
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
    let code = exit_from(child.wait());
    if identified {
        report_contained_run(input, instance_id, started_ms, now_ms());
    }
    Attempt::Done(code)
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
#[cfg(target_os = "linux")]
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

fn run_macos(input: &JailInputs) -> ExitCode {
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
        println!("# --- sandbox profile ---");
        println!("{}", plan.profile);
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
    announce(input);
    // argv = [sandbox-exec, -p, <profile>, --, child...]; run argv[1..] under the
    // resolved binary.
    let status = Command::new(sb)
        .args(&plan.argv[1..])
        .envs(plan.env.iter().cloned())
        .status();
    exit_from(status)
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
    eprintln!(
        "  the agent's ~/.config/innerwarden (incl. the API key) is not visible inside the jail."
    );
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

fn print_plan_env(env: &[(String, String)]) {
    println!("# in-jail env (secret-safe: no LLM/notify config, graph is jail-local)");
    for (k, v) in env {
        println!("#   {k}={v}");
    }
}

#[cfg(test)]
mod tests {
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

    /// What the launcher takes as places an identified jail can keep Claude
    /// Code's own state in, for a home with nothing else shown.
    #[cfg(target_os = "linux")]
    fn claude_state_of(home: &Path, make: bool) -> crate::contain::ClaudeState {
        let shown: Vec<(PathBuf, PathBuf)> = [".claude", ".config"]
            .iter()
            .map(|name| home.join(name))
            .filter(|path| path.exists())
            .map(|path| {
                let real = std::fs::canonicalize(&path).unwrap();
                (path, real)
            })
            .collect();
        claude_state_here(home, &shown, &[home.join("proj")], make)
    }

    /// The launcher's view of an identified jail's Claude Code state with
    /// the kept file there or not and both folders of its own.
    #[cfg(target_os = "linux")]
    fn kept_and_own(home: &Path) -> crate::contain::ClaudeState {
        crate::contain::ClaudeState {
            settings_kept: true,
            own_folders: crate::contain::CLAUDE_RUN_FOLDERS
                .map(|name| home.join(".claude").join(name))
                .to_vec(),
            shared: false,
        }
    }

    /// What the launcher takes as places an identified jail can keep Claude
    /// Code's own state in: the settings file in `~/.claude` only where it
    /// is a file or not there yet, the folders of its runs only where each
    /// is a folder of its own, which the real run makes (empty, 0700) and a
    /// plan or a dry run does not. Nothing at all without a `~/.claude`
    /// folder.
    ///
    /// FAILS ON REVERT: take a link or a folder in place of the settings
    /// file, or follow a link in place of a folder of its runs, or make a
    /// folder when not asked to.
    #[cfg(target_os = "linux")]
    #[test]
    fn claude_state_here_takes_only_a_file_or_nothing_and_a_folder_of_its_own() {
        use crate::contain::ClaudeState;
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let home = std::fs::canonicalize(&home).unwrap();
        // No `~/.claude`: nothing, and nothing made.
        assert_eq!(claude_state_of(&home, true), ClaudeState::default());
        assert!(!home.join(".claude").exists());
        // A `~/.claude` file is no folder the jail shares.
        std::fs::write(home.join(".claude"), "").unwrap();
        assert_eq!(claude_state_of(&home, true), ClaudeState::default());
        std::fs::remove_file(home.join(".claude")).unwrap();

        let claude = home.join(".claude");
        std::fs::create_dir(&claude).unwrap();
        let sessions = claude.join("sessions");
        let backups = claude.join("backups");
        // The plan, and a dry run, show what a real run would do and make
        // nothing.
        assert_eq!(claude_state_of(&home, false), kept_and_own(&home));
        assert!(!sessions.exists() && !backups.exists());
        // The real run makes both folders, empty and 0700.
        assert_eq!(claude_state_of(&home, true), kept_and_own(&home));
        for made in [&sessions, &backups] {
            let meta = std::fs::symlink_metadata(made).unwrap();
            assert!(meta.is_dir());
            assert_eq!(meta.permissions().mode() & 0o777, 0o700);
            assert_eq!(std::fs::read_dir(made).unwrap().count(), 0);
        }
        // A settings file there already is kept.
        let kept = claude.join(".claude.json");
        std::fs::write(&kept, "{}").unwrap();
        assert_eq!(claude_state_of(&home, true), kept_and_own(&home));

        // A link in place of the settings file (a dotfiles manager's), or a
        // folder, is never taken.
        std::fs::remove_file(&kept).unwrap();
        std::fs::write(root.path().join("dotfiles.json"), "{}").unwrap();
        symlink(root.path().join("dotfiles.json"), &kept).unwrap();
        assert!(!claude_state_of(&home, true).settings_kept);
        std::fs::remove_file(&kept).unwrap();
        std::fs::create_dir(&kept).unwrap();
        assert!(!claude_state_of(&home, true).settings_kept);
        std::fs::remove_dir(&kept).unwrap();

        // A link in place of the sessions folder, even to a folder, is never
        // covered, and the folder it leads to is left as it was: shared,
        // and said.
        std::fs::remove_dir(&sessions).unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        symlink(&elsewhere, &sessions).unwrap();
        let got = claude_state_of(&home, true);
        assert!(got.settings_kept && got.shared, "{got:?}");
        assert_eq!(got.own_folders, std::slice::from_ref(&backups));
        assert!(std::fs::symlink_metadata(&sessions)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);

        // A `~/.claude` that is a link to a folder (a dotfiles manager's) is
        // the folder the jail binds: its places are read where it leads.
        std::fs::remove_file(&sessions).unwrap();
        std::fs::remove_dir(&backups).unwrap();
        std::fs::remove_dir(&claude).unwrap();
        let real = root.path().join("real-claude");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, &claude).unwrap();
        assert_eq!(claude_state_of(&home, true), kept_and_own(&home));
        assert!(real.join("sessions").is_dir() && real.join("backups").is_dir());
    }

    /// M30CW-SEC-2: the person's own `~/.claude.json` that is the kept file
    /// (a dotfiles manager's link to `.claude/.claude.json`, or a hard link
    /// to it), or that leads anywhere into `~/.claude` or to nothing yet,
    /// is never taken: the jail's link would lead to the person's own
    /// settings file, and its saves would land on it. A file of its own, or
    /// a link to a file outside `~/.claude`, keeps the jail's link.
    ///
    /// FAILS ON REVERT: drop the check of the person's own file, and the
    /// first three are taken.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_persons_own_settings_file_is_never_the_kept_one() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(root.path()).unwrap().join("home");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        let own = home.join(".claude.json");
        let kept = home.join(".claude/.claude.json");
        let reset = || {
            let _ = std::fs::remove_file(&own);
            let _ = std::fs::remove_file(&kept);
        };
        // A link to the kept file, the file there.
        std::fs::write(&kept, "OWN").unwrap();
        symlink(".claude/.claude.json", &own).unwrap();
        assert!(!claude_state_of(&home, false).settings_kept, "link");
        reset();
        // A link to the kept file, not there yet: the person's next save
        // makes it.
        symlink(".claude/.claude.json", &own).unwrap();
        assert!(!claude_state_of(&home, false).settings_kept, "dangling");
        reset();
        // A hard link.
        std::fs::write(&kept, "OWN").unwrap();
        std::fs::hard_link(&kept, &own).unwrap();
        assert!(!claude_state_of(&home, false).settings_kept, "hard link");
        reset();
        // A link elsewhere into `~/.claude`.
        std::fs::write(home.join(".claude/mine.json"), "OWN").unwrap();
        symlink(".claude/mine.json", &own).unwrap();
        assert!(!claude_state_of(&home, false).settings_kept, "into");
        reset();
        // A file of its own, a link outside `~/.claude`, or none: kept.
        std::fs::write(&own, "OWN").unwrap();
        assert!(claude_state_of(&home, false).settings_kept, "file");
        reset();
        std::fs::write(home.join("dotfiles.json"), "OWN").unwrap();
        symlink("dotfiles.json", &own).unwrap();
        assert!(claude_state_of(&home, false).settings_kept, "outside");
        reset();
        assert!(claude_state_of(&home, false).settings_kept, "none");
    }

    /// M30CW-3: a folder of Claude Code's runs another launch made first
    /// (two identified launches at once, on a home that had none) is the
    /// same folder, not a failure: the second jail covers it too. A link or
    /// a file there is never taken.
    ///
    /// FAILS ON REVERT: take any failure to make it as not its own, and the
    /// second launch shares the host's sessions.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_folder_another_launch_made_first_is_its_own() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let fresh = root.path().join("fresh");
        assert!(own_folder(&fresh));
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        // The other launch made it between this one's look and its make.
        assert!(own_folder(&fresh));
        symlink(&fresh, root.path().join("link")).unwrap();
        assert!(!own_folder(&root.path().join("link")));
        std::fs::write(root.path().join("file"), "").unwrap();
        assert!(!own_folder(&root.path().join("file")));
        assert!(!own_folder(&root.path().join("no/parent")));
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
}
