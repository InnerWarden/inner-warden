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

    // Resolve the project dir (default cwd), canonicalized so binds are absolute.
    let project = resolve_project(&args.project);
    if !project.is_dir() {
        eprintln!(
            "innerwarden contain: project directory not found: {} (pass --project <dir>)",
            project.display()
        );
        return ExitCode::from(2);
    }
    let mut args = args;
    args.project = project;

    let input = resolve_inputs(args, home, iw_binary);
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
    }

    if cfg!(target_os = "linux") {
        run_linux(&input)
    } else if cfg!(target_os = "macos") {
        run_macos(&input)
    } else {
        eprintln!(
            "innerwarden contain: containment needs Linux (bubblewrap) or macOS (sandbox-exec); this OS is not supported"
        );
        ExitCode::from(2)
    }
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

fn resolve_inputs(args: ContainArgs, home: PathBuf, iw_binary: PathBuf) -> JailInputs {
    // Canonicalize TMPDIR too (macOS $TMPDIR is under the /var symlink) so the
    // writable-set rule matches the resolved path.
    let tmpdir = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
        .unwrap_or_else(|| PathBuf::from("/tmp"));

    // Which home-relative paths the builder may bind actually exist.
    let candidates = [
        ".claude",
        ".config",
        ".cache",
        ".cargo",
        ".rustup",
        ".npm",
        ".local",
        ".gitconfig",
        ".claude.json",
    ];
    let existing_paths: Vec<PathBuf> = candidates
        .iter()
        .map(|n| home.join(n))
        .filter(|p| p.exists())
        .collect();

    let usr_merged = std::fs::symlink_metadata("/bin")
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);

    let worktree = detect_worktree(&args.project);

    // Symlink-resolve the secret dir (dotfile managers symlink ~/.config): resolve
    // the ~/.config parent then append, so it works even before innerwarden/ exists.
    let iw_config_real = std::fs::canonicalize(home.join(".config"))
        .map(|c| c.join("innerwarden"))
        .unwrap_or_else(|_| home.join(".config/innerwarden"));

    // Expand the deny_read globs against the real project + stat each match so the
    // builder knows file-vs-dir (Linux masks a file with /dev/null, a dir with tmpfs).
    let deny_paths = expand_deny_paths(&args.project, &args.deny_read);

    JailInputs {
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
        deny_paths,
        info_fd: None,
        record_fd: None,
    }
}

/// Expand each `deny_read` pattern against the REAL project and stat the matches.
/// Literals are taken as-is; `dir/**` or `dir/*` mask the directory (one entry
/// covers all descendants); other globs are enumerated with the `glob` crate.
/// Each result is symlink-resolved so the mask/deny targets the real path.
fn expand_deny_paths(project: &Path, patterns: &[String]) -> Vec<crate::contain::DenyPath> {
    use crate::contain::DenyPath;
    let mut out: Vec<DenyPath> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut add = |abs: PathBuf| {
        // metadata() follows symlinks so is_dir reflects the target; canonicalize
        // gives the real path the sandbox will match on.
        if let Ok(meta) = std::fs::metadata(&abs) {
            let real = std::fs::canonicalize(&abs).unwrap_or(abs);
            if seen.insert(real.clone()) {
                out.push(DenyPath {
                    abs: real,
                    is_dir: meta.is_dir(),
                });
            }
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
struct BackendFacts {
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
fn backend_facts(path: &Path) -> Option<BackendFacts> {
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
    let sound = |entry: &PathEntry| !entry.symlink && entry.uid == 0 && entry.mode & 0o022 == 0;
    let Some((executable, directories)) = facts.chain.split_first() else {
        return false;
    };
    !facts.components.is_empty()
        && facts.components.iter().all(|entry| !entry.symlink)
        && sound(executable)
        && executable.file
        && executable.mode & 0o111 != 0
        && directories.iter().all(|entry| sound(entry) && entry.dir)
}

fn run_linux(input: &JailInputs) -> ExitCode {
    // A dry run with `--identity` shows the arguments the real run adds.
    let dry_identity;
    let planned = if input.args.identity && input.args.dry_run {
        dry_identity = JailInputs {
            info_fd: Some(crate::contain::launch::DRY_RUN_INFO_FD),
            record_fd: Some(crate::contain::launch::DRY_RUN_RECORD_FD),
            ..input.clone()
        };
        &dry_identity
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
        #[cfg(target_os = "linux")]
        if input.args.identity {
            println!("# {}", dry_run_scope_line());
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
    // names neither the cause nor the fix. The sysctl file exists only on
    // kernels that carry the restriction; the profile check is on disk because
    // the loaded-profiles list is root-only.
    let sysctl =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").ok();
    let profile_on_disk = Path::new("/etc/apparmor.d/bwrap").exists()
        || Path::new("/etc/apparmor.d/usr.bin.bwrap").exists();
    if let Some(lines) =
        crate::contain::userns_restriction_advice(sysctl.as_deref(), profile_on_disk, &bwrap)
    {
        for line in lines {
            eprintln!("{line}");
        }
        return ExitCode::from(1);
    }
    #[cfg(target_os = "linux")]
    if input.args.identity {
        return run_linux_identified(input, &bwrap);
    }
    announce(input);
    run_plain(&bwrap, &plan)
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
    use std::io::{Error, ErrorKind, Write};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

    let target = crate::contain::launch::record_path(dir, instance_id)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "not an instance id"))?;
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
    let temp = dir.join(format!(".{instance_id}.tmp"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    innerwarden_safe_io::harden(&mut options);
    let mut file = options.open(&temp)?;
    let written = file
        .write_all(json)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&temp, &target));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }
    Ok(target)
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
fn run_linux_identified(input: &JailInputs, bwrap: &Path) -> ExitCode {
    use crate::contain::launch::{no_scope_sentence, plan_scope, NoScope, ScopePlan};
    use innerwarden_agent_guard::identity::scope_unit_name;

    let named = new_instance_id().and_then(|id| {
        let unit = scope_unit_name(&id).ok_or("the instance id is not a name")?;
        Ok((id, unit))
    });
    let (instance_id, unit) = match named {
        Ok(named) => named,
        Err(why) => {
            eprintln!(
                "innerwarden contain: no instance record written ({why}); the jail runs, unidentified"
            );
            announce(input);
            return match build_linux_jail(input) {
                Ok(plan) => run_plain(bwrap, &plan),
                Err(e) => {
                    eprintln!("innerwarden contain: {e}");
                    ExitCode::from(2)
                }
            };
        }
    };
    let mut scope = plan_scope(&scope_facts(), &unit);
    if let ScopePlan::None(why) = scope {
        eprintln!("{}", no_scope_sentence(why));
    }
    announce(input);
    loop {
        match launch_identified(input, bwrap, &instance_id, &unit, &scope) {
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
    instance_id: &str,
    unit: &str,
    scope: &crate::contain::launch::ScopePlan,
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
    let mut identified = input.clone();
    identified.info_fd = Some(info_writer.as_raw_fd());
    identified.record_fd = Some(record_reader.as_raw_fd());
    let plan = match build_linux_jail(&identified) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("innerwarden contain: {e}");
            return Attempt::Done(ExitCode::from(2));
        }
    };
    let (program, args) = launch_argv(bwrap, &plan.bwrap_args, scope);
    let spawned = Command::new(&program)
        .args(&args)
        .envs(plan.env.iter().cloned())
        .spawn();
    // Ours must close, or the read below never ends and the jail never sees
    // the end of its record.
    drop(info_writer);
    drop(record_reader);
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) if matches!(scope, ScopePlan::User { .. }) => return Attempt::NeverStarted(Err(e)),
        Err(e) => return Attempt::Done(exit_from(Err(e))),
    };
    let info = read_info(&mut info_reader);
    drop(info_reader);
    let record = match info {
        InfoRead::Nothing => {
            drop(record_writer);
            return match child.wait() {
                Ok(status) if status.success() => Attempt::Done(exit_from(Ok(status))),
                status => Attempt::NeverStarted(status),
            };
        }
        InfoRead::Failed(why) => Err(why),
        InfoRead::Got(info) => identify(input, instance_id, unit, scope, info),
    };
    match record {
        Ok(json) => {
            // The jail reads this to its end before it builds its root.
            if let Err(e) = record_writer.write_all(&json) {
                eprintln!("innerwarden contain: the jail did not take its record: {e}");
            } else {
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
    Attempt::Done(exit_from(child.wait()))
}

/// Read the facts about the jail from the host, make the record, write the
/// launcher's copy, and return the bytes for the jail's copy.
#[cfg(target_os = "linux")]
fn identify(
    input: &JailInputs,
    instance_id: &str,
    unit: &str,
    scope: &crate::contain::launch::ScopePlan,
    info: crate::contain::launch::InfoFd,
) -> Result<Vec<u8>, String> {
    use crate::contain::launch::{
        assemble_record, no_scope_sentence, parse_ns_link, records_dir, user_scope_seen,
        LaunchFacts, NoScope, ScopePlan,
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
    if crate::upsell_io::active_defence_installed() {
        scopes.system = request_system_scope(instance_id, unit, pid);
    }
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
        scope: scopes,
    };
    let record = assemble_record(facts).map_err(|e| e.to_string())?;
    let json = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
    let dir = records_dir(std::env::var("XDG_STATE_HOME").ok().as_deref(), &input.home);
    match write_launch_record(&dir, &record.instance_id, &json, uid) {
        Ok(path) => eprintln!("innerwarden contain - instance record: {}", path.display()),
        Err(e) => eprintln!(
            "innerwarden contain: the launcher's copy of the record was not written ({e})"
        ),
    }
    Ok(json)
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

/// Ask the local Active Defence agent, best effort, for a system scope around
/// the instance, and return it only if the KERNEL then shows the jail in it.
///
/// The request names the instance and nothing else; it gives no process to
/// move. The answer is never the fact: a system scope is recorded only when
/// `/proc/<pid>/cgroup` reads exactly `/system.slice/<unit>`, a cgroup only
/// root can make or move a process into.
#[cfg(target_os = "linux")]
fn request_system_scope(
    instance_id: &str,
    unit: &str,
    pid: u32,
) -> Option<innerwarden_agent_guard::identity::Scope> {
    use crate::agent_report::{agent_route, send_report, AGENT_URL_VAR};
    use crate::contain::launch::system_scope_seen;
    use innerwarden_agent_guard::identity::{system_scope_request, SYSTEM_SCOPE_ROUTE};

    let said = |why: &str| eprintln!("innerwarden contain: no system scope ({why})");
    let Some(url) = agent_route(
        std::env::var(AGENT_URL_VAR).ok().as_deref(),
        SYSTEM_SCOPE_ROUTE,
    ) else {
        said("the local agent route is off");
        return None;
    };
    let body = system_scope_request(instance_id)?;
    if let Err(why) = send_report(&url, &body) {
        said(&format!("the local agent did not take the request: {why}"));
        return None;
    }
    let deadline = std::time::Instant::now() + SYSTEM_SCOPE_WAIT;
    loop {
        if let Some(seen) = proc_cgroup(pid).and_then(|c| system_scope_seen(&c, unit)) {
            eprintln!("  system scope: {}", seen.cgroup_path);
            return Some(seen);
        }
        if std::time::Instant::now() >= deadline {
            said("the kernel does not show the jail in it");
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
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
        (Some(run), true) => Command::new(run)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| parse_systemd_version(&String::from_utf8_lossy(&out.stdout))),
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
}
