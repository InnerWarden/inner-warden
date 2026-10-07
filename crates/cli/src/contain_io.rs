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
    let plan = match build_linux_jail(input) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("innerwarden contain: {e}");
            return ExitCode::from(2);
        }
    };
    if input.args.dry_run {
        println!("# innerwarden contain - DRY RUN (Linux / bubblewrap)");
        print_plan_env(&plan.env);
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
    announce(input);
    let status = Command::new(bwrap)
        .args(&plan.bwrap_args)
        .envs(plan.env.iter().cloned())
        .status();
    exit_from(status)
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
}
