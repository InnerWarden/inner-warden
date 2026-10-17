//! `innerwarden contain` - run an AI coding agent inside a filesystem/namespace
//! JAIL (Linux: bubblewrap; macOS: sandbox-exec) while the InnerWarden PreToolUse
//! HOOK stays active INSIDE it. Jail = walls (limit what the agent can touch);
//! guard = brain (screen every command it runs). Together: prevent + detect.
//!
//! This module is the PURE core: it parses the CLI, and from a set of host facts
//! (`JailInputs`, resolved by the thin `contain_io` adapter) it computes the exact
//! backend invocation - the bwrap argv on Linux, the SBPL profile on macOS - plus
//! the in-jail environment. No I/O here, so every wall is unit-testable.
//!
//! Security invariants baked in (asserted by tests, NOT optional):
//!   * `~/.config/innerwarden` is NEVER bound into the jail and is always
//!     SHADOWED (Linux tmpfs mask / macOS read+write deny) - the 0600 `llm-key`
//!     therefore cannot be read by the agent. The hook needs no config: blocking
//!     uses the rules embedded in the binary (`RuleEngine::load_embedded`).
//!   * The key is NEVER passed via env (the agent shares the hook's environment).
//!     In-jail LLM/notify enrichment is simply disabled; a `deny` still denies.
//!   * v1 INHERITS the host environment (like a normal shell), so credential env
//!     vars already exported (`OPENAI_API_KEY`, `AWS_*`, ...) are visible in-jail -
//!     the agent needs its own key to run, so a blanket scrub would break it. An
//!     opt-in env allowlist is v2. (The InnerWarden key is not one of these: it is
//!     read from the shadowed `~/.config/innerwarden`, never the environment.)
//!   * `.ssh` / `.aws` / `.gnupg` (and macOS Mail/Messages/Safari) are never
//!     exposed. Deny rules are emitted LAST (last-wins on both backends).
//!   * The backend binary is resolved from trusted absolute paths by the I/O
//!     layer, never `$PATH`.

use std::path::{Path, PathBuf};

/// How the in-jail hook behaves. Default `Monitor` (records, never blocks) so a
/// user always starts safe; enforcement is an explicit opt-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Monitor,
    Enforce,
    BlockReview,
}

impl Mode {
    /// The hook flags this mode maps to (`block_review`, `monitor`) for
    /// `hook::install_hook` / `innerwarden hook`.
    pub fn hook_flags(&self) -> (bool, bool) {
        match self {
            Mode::Monitor => (false, true),
            Mode::Enforce => (false, false),
            Mode::BlockReview => (true, false),
        }
    }
}

/// Parsed `innerwarden contain` arguments (everything before `--`), plus the child
/// command (after `--`). Pure; the I/O layer canonicalizes `project` against cwd.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainArgs {
    pub agent: String,
    pub mode: Mode,
    pub allow_net: bool,
    pub project: PathBuf,
    pub dry_run: bool,
    pub setup_only: bool,
    pub child: Vec<String>,
    pub extra_rw: Vec<PathBuf>,
    pub extra_ro: Vec<PathBuf>,
    pub deny_read: Vec<String>,
    /// `--identity`: write a launch record for this instance. OFF by default;
    /// off, the jail and its argv are exactly what they were before the flag.
    pub identity: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ContainError {
    UnknownAgent(String),
    NoCommand,
    Unsupported(String),
    UnknownFlag(String),
}

impl std::fmt::Display for ContainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainError::UnknownAgent(a) => write!(
                f,
                "unsupported agent '{a}' (only 'claude-code' is supported today)"
            ),
            ContainError::NoCommand => write!(
                f,
                "no command to run - pass it after `--`, e.g. `innerwarden contain -- claude`"
            ),
            ContainError::Unsupported(m) => write!(f, "{m}"),
            ContainError::UnknownFlag(x) => write!(f, "unknown flag `{x}`"),
        }
    }
}

/// The project-relative secret globs denied by default inside the jail.
pub const DEFAULT_DENY_READ: &[&str] = &[".env", ".env.*", "secrets/**"];

/// Parse the `contain` argument list. Pure + unit-testable. `project` defaults to
/// `"."` (the I/O layer resolves it to the real cwd).
pub fn parse_contain_args(argv: &[String]) -> Result<ContainArgs, ContainError> {
    let mut agent = String::from("claude-code");
    let mut mode = Mode::Monitor;
    let mut allow_net = true;
    let mut project = PathBuf::from(".");
    let mut dry_run = false;
    let mut setup_only = false;
    let mut identity = false;
    let mut deny_read: Vec<String> = DEFAULT_DENY_READ.iter().map(|s| s.to_string()).collect();
    let extra_rw: Vec<PathBuf> = Vec::new();
    let extra_ro: Vec<PathBuf> = Vec::new();

    let mut it = argv.iter();
    let mut child: Vec<String> = Vec::new();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--" => {
                child = it.cloned().collect();
                break;
            }
            "--agent" => agent = it.next().cloned().unwrap_or_default(),
            "--project" => {
                project = it.next().map(PathBuf::from).unwrap_or(project);
            }
            "--monitor" => mode = Mode::Monitor,
            "--enforce" => {
                if mode != Mode::BlockReview {
                    mode = Mode::Enforce;
                }
            }
            "--block-review" => mode = Mode::BlockReview,
            "--allow-net" => allow_net = true,
            "--no-net" => {
                return Err(ContainError::Unsupported(
                    "--no-net (network lockdown) is a v2 feature; v1 shares the host network so the agent, the hook, and git keep working".into(),
                ))
            }
            "--deny-read" => {
                if let Some(g) = it.next() {
                    deny_read.push(g.clone());
                }
            }
            "--dry-run" => dry_run = true,
            "--setup" => setup_only = true,
            innerwarden_agent_guard::identity::IDENTITY_FLAG => identity = true,
            other if other.starts_with('-') => {
                return Err(ContainError::UnknownFlag(other.to_string()))
            }
            // A bare (non-flag) token also starts the child command, so
            // `innerwarden contain claude` works without an explicit `--`.
            other => {
                child.push(other.to_string());
                child.extend(it.cloned());
                break;
            }
        }
    }

    if agent != "claude-code" {
        return Err(ContainError::UnknownAgent(agent));
    }
    if child.is_empty() && !setup_only {
        return Err(ContainError::NoCommand);
    }

    Ok(ContainArgs {
        agent,
        mode,
        allow_net,
        project,
        dry_run,
        setup_only,
        child,
        extra_rw,
        extra_ro,
        deny_read,
        identity,
    })
}

/// Which of the jail settings a profile also sets were given on the command
/// line: those win over the profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JailFlagsGiven {
    pub project: bool,
}

/// PURE. Which jail flags `argv` (the `contain` arguments) gives before the
/// command starts.
pub fn jail_flags_given(argv: &[String]) -> JailFlagsGiven {
    let mut given = JailFlagsGiven::default();
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--" => break,
            "--project" => given.project = true,
            // Flags that take a value: skip it, it is not a flag.
            "--agent" | "--deny-read" => {
                it.next();
            }
            other if !other.starts_with('-') => break,
            _ => {}
        }
    }
    given
}

/// PURE. Apply a type's jail profile to parsed `contain --identity` arguments.
///
/// The profile's project is used only when `--project` was not given; its
/// read-only paths are added; its hidden globs are added to the defaults and
/// to any `--deny-read` (hiding more is never undone by a flag). A `~/` path
/// is under `home`. The I/O layer resolves links in the read-only paths
/// before the jail is built, so a link cannot put a protected directory
/// behind an allowed name.
pub fn apply_jail_profile(
    args: &mut ContainArgs,
    jail: &innerwarden_agent_guard::profiles::JailProfile,
    given: JailFlagsGiven,
    home: &Path,
) {
    let place = |path: &str| match path.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(path),
    };
    if !given.project {
        if let Some(project) = &jail.project_rw {
            args.project = place(project);
        }
    }
    for path in &jail.extra_ro {
        let path = place(path);
        if !args.extra_ro.contains(&path) {
            args.extra_ro.push(path);
        }
    }
    for glob in &jail.deny_read {
        if !args.deny_read.contains(glob) {
            args.deny_read.push(glob.clone());
        }
    }
}

/// A binary resolved to live under `$HOME` (so it must be re-bound after the HOME
/// tmpfs on Linux): the symlink/launcher path and the real directory it points to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBinary {
    pub link: PathBuf,
    pub target_dir: PathBuf,
}

/// A linked git worktree's external admin dirs, exposed so `git` keeps working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Worktree {
    pub git_dir: PathBuf,
    pub common_dir: PathBuf,
}

/// A resolved project secret to mask inside the jail. The I/O layer expands the
/// `deny_read` globs against the real project and stats each match, so the pure
/// builder knows whether to mask a FILE (Linux: bind /dev/null over it - a tmpfs
/// over a file makes bwrap abort with ENOTDIR) or a DIRECTORY (Linux: tmpfs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyPath {
    /// Absolute path inside the jail (same as on the host - binds are identity).
    pub abs: PathBuf,
    pub is_dir: bool,
}

/// Host facts the pure builders need, resolved by `contain_io` and injected so the
/// builders stay deterministic + testable.
#[derive(Debug, Clone)]
pub struct JailInputs {
    pub args: ContainArgs,
    pub home: PathBuf,
    pub tmpdir: PathBuf,
    pub iw_binary: PathBuf,
    pub agent_binary: Option<ResolvedBinary>,
    pub worktree: Option<Worktree>,
    pub usr_merged: bool,
    pub stdin_is_tty: bool,
    /// Absolute dotdir paths under `$HOME` that actually exist (binds are filtered
    /// to these so bwrap does not fail on a missing source).
    pub existing_paths: Vec<PathBuf>,
    /// The InnerWarden secret dir, SYMLINK-RESOLVED. On macOS `sandbox-exec` matches
    /// the real path, so a symlinked `~/.config` (dotfile managers) would evade a
    /// deny of the nominal path - the resolved path is denied as well.
    pub iw_config_real: PathBuf,
    /// The project secrets to mask (glob-expanded + statted by the I/O layer).
    pub deny_paths: Vec<DenyPath>,
    /// The descriptor bwrap writes its start-up facts to (`--info-fd`). `None`
    /// unless the launch asked for an identity record.
    pub info_fd: Option<i32>,
    /// The descriptor bwrap reads the launch record from and mounts, read-only,
    /// at [`JAIL_RECORD_PATH`] (`--ro-bind-data`). `None` unless the launch
    /// asked for an identity record.
    ///
    /// [`JAIL_RECORD_PATH`]: innerwarden_agent_guard::identity::JAIL_RECORD_PATH
    pub record_fd: Option<i32>,
    /// The launcher's own records directory, as named and as resolved, hidden
    /// inside an identified jail: the agent works in a home that holds it.
    /// Empty unless the launch asked for an identity record.
    pub records_dirs: Vec<PathBuf>,
    /// Variables the launcher keeps out of the programs it runs to start the
    /// jail, handed to the jail's command as they were ([`launch_env`]).
    /// Empty unless the launch asked for an identity record.
    pub child_env: Vec<(String, String)>,
}

impl JailInputs {
    fn exists(&self, p: &Path) -> bool {
        self.existing_paths.iter().any(|e| e == p)
    }
    /// The jail-local InnerWarden secret dir that must be shadowed (nominal path).
    fn iw_config_dir(&self) -> PathBuf {
        self.home.join(".config/innerwarden")
    }
    /// The graph file the in-jail hook writes to (project-local, writable).
    fn jail_graph_file(&self) -> PathBuf {
        jail_graph_dir(&self.args.project).join(JAIL_GRAPH_NAME)
    }
}

/// The folder, inside the project, where the jail's hook keeps its graph.
pub const JAIL_GRAPH_DIR: &str = ".innerwarden";

/// The jail's graph file, in [`JAIL_GRAPH_DIR`].
pub const JAIL_GRAPH_NAME: &str = "graph.json";

/// The session everything screened inside the jail is grouped under.
pub const JAIL_SESSION: &str = "contain";

/// [`JAIL_GRAPH_DIR`] of `project`.
pub fn jail_graph_dir(project: &Path) -> PathBuf {
    project.join(JAIL_GRAPH_DIR)
}

/// The dotdirs re-bound read-write after the HOME tmpfs (tool + agent state).
/// `.config` is included but IMMEDIATELY shadowed on the innerwarden subdir.
const DOTDIR_RW: &[&str] = &[
    ".claude", ".config", ".cache", ".cargo", ".rustup", ".npm", ".local",
];
/// Read-only git identity re-binds.
const DOTFILE_RO: &[&str] = &[".gitconfig"];
/// Dotdirs that must stay INVISIBLE (never re-bound → absent under the HOME tmpfs).
const DOTDIR_DENY: &[&str] = &[".ssh", ".gnupg", ".aws", ".mozilla", ".thunderbird"];
const MACOS_HOME_DENY: &[&str] = &["Library/Mail", "Library/Messages", "Library/Safari"];

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn protected_host_paths(input: &JailInputs) -> Vec<PathBuf> {
    let mut paths = vec![input.iw_config_dir(), input.iw_config_real.clone()];
    paths.extend(DOTDIR_DENY.iter().map(|name| input.home.join(name)));
    paths.extend(MACOS_HOME_DENY.iter().map(|name| input.home.join(name)));
    paths.sort();
    paths.dedup();
    paths
}

/// Validate every host path that will be writable inside the jail. A project may
/// live below HOME, but it may not be HOME itself, an ancestor of HOME, or overlap
/// any protected credential/policy directory. Otherwise the late writable bind
/// could undo an earlier mask. Worktree admin binds follow the same rule.
pub fn validate_jail_inputs(input: &JailInputs) -> Result<(), ContainError> {
    let protected = protected_host_paths(input);
    let validate_bind = |kind: &str, path: &Path| {
        let normalized_absolute = path.is_absolute()
            && path.components().all(|component| {
                matches!(
                    component,
                    std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                        | std::path::Component::Normal(_)
                )
            });
        if !normalized_absolute
            || path == input.home
            || input.home.starts_with(path)
            || protected.iter().any(|secret| paths_overlap(path, secret))
        {
            return Err(ContainError::Unsupported(format!(
                "unsafe {kind} path '{}': it overlaps the home or a protected credential/policy directory",
                path.display()
            )));
        }
        Ok(())
    };

    validate_bind("project", &input.args.project)?;
    if let Some(worktree) = &input.worktree {
        validate_bind("worktree git", &worktree.git_dir)?;
        validate_bind("worktree common", &worktree.common_dir)?;
    }
    for path in &input.args.extra_rw {
        validate_bind("extra writable", path)?;
    }
    // A read-only bind exposes the same as a writable one to a reader, so it
    // is held to the same places: never the home, an ancestor of it, or a
    // protected directory (the masks are re-applied after it anyway).
    for path in &input.args.extra_ro {
        validate_bind("extra read-only", path)?;
    }
    if input.args.identity {
        validate_sealed(input)?;
    }
    Ok(())
}

/// The host trees an identified jail must never see from the host: `/run`
/// holds the user's service manager and bus (a way to start a unit outside the
/// scope), `/sys` the cgroup files (a way to move a process out of it). The
/// jail replaces both (`/run` is a tmpfs, `/sys` is read-only), and a writable
/// bind of the project there would put the host's copy back.
const IDENTITY_SEALED: &[&str] = &["/run", "/sys"];

/// With `--identity`, refuse a writable bind that overlaps a sealed tree.
/// Without the flag nothing here runs, so a jail is what it was before.
fn validate_sealed(input: &JailInputs) -> Result<(), ContainError> {
    let mut writable: Vec<(&str, &Path)> = vec![("project", &input.args.project)];
    if let Some(worktree) = &input.worktree {
        writable.push(("worktree git", &worktree.git_dir));
        writable.push(("worktree common", &worktree.common_dir));
    }
    writable.extend(
        input
            .args
            .extra_rw
            .iter()
            .map(|p| ("extra writable", p.as_path())),
    );
    // Read-only is not enough here: a socket on a read-only mount still
    // accepts a connection, so the host's `/run` read-only is its bus.
    writable.extend(
        input
            .args
            .extra_ro
            .iter()
            .map(|p| ("extra read-only", p.as_path())),
    );
    for (kind, path) in writable {
        if let Some(sealed) = IDENTITY_SEALED
            .iter()
            .find(|sealed| paths_overlap(path, Path::new(sealed)))
        {
            return Err(ContainError::Unsupported(format!(
                "unsafe {kind} path '{}' for --identity: it overlaps {sealed}, which the jail keeps closed",
                path.display()
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxJailPlan {
    pub bwrap_args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub rlimit_nofile: u64,
}

/// Build the ordered bwrap argument vector. Order is load-bearing (bwrap is
/// last-wins): system RO → dev/proc/tmpfs → HOME tmpfs → dotdir re-binds → shadow
/// innerwarden → binary binds → project (late) → worktree → nested secret masks →
/// launch record (`--identity` only) → namespaces → child. `DOTDIR_DENY`
/// entries are never emitted, so they vanish under the HOME tmpfs.
pub fn build_linux_jail(input: &JailInputs) -> Result<LinuxJailPlan, ContainError> {
    validate_jail_inputs(input)?;
    let home = input.home.to_string_lossy().to_string();
    let mut a: Vec<String> = Vec::new();
    let mut push = |args: &[&str]| a.extend(args.iter().map(|s| s.to_string()));

    // --- system dirs (read-only) ---
    push(&["--ro-bind", "/usr", "/usr"]);
    push(&["--ro-bind", "/etc", "/etc"]);
    push(&["--ro-bind", "/sys", "/sys"]);
    if input.usr_merged {
        push(&["--symlink", "usr/bin", "/bin"]);
        push(&["--symlink", "usr/lib", "/lib"]);
        push(&["--symlink", "usr/lib64", "/lib64"]);
        push(&["--symlink", "usr/sbin", "/sbin"]);
    } else {
        // `--ro-bind-try`: skip a top-level dir that doesn't exist (e.g. no /lib64
        // on a 32-bit or non-standard layout) instead of aborting bwrap.
        for d in ["/bin", "/lib", "/lib64", "/sbin"] {
            push(&["--ro-bind-try", d, d]);
        }
    }

    // --- synthetic devices / fs ---
    push(&["--dev", "/dev"]);
    push(&["--proc", "/proc"]);
    push(&["--tmpfs", "/tmp"]);
    push(&["--tmpfs", "/run"]);

    // --- HOME: tmpfs, then selective re-bind of what exists ---
    push(&["--tmpfs", &home]);
    for name in DOTDIR_RW {
        // Belt-and-suspenders: a secret dir can never be re-bound even if it were
        // mistakenly added to DOTDIR_RW.
        if DOTDIR_DENY.contains(name) {
            continue;
        }
        let p = input.home.join(name);
        if input.exists(&p) {
            let s = p.to_string_lossy().to_string();
            push(&["--bind", &s, &s]);
        }
    }
    // Shadow the InnerWarden secret dir IMMEDIATELY after the `.config` bind
    // (last-wins). The 0600 llm-key is now absent inside the jail. Shadow BOTH the
    // nominal path and its symlink-resolved real path (a symlinked ~/.config would
    // otherwise leave the real dir reachable).
    let iw_cfg = input.iw_config_dir().to_string_lossy().to_string();
    push(&["--tmpfs", &iw_cfg]);
    let iw_cfg_real = input.iw_config_real.to_string_lossy().to_string();
    if iw_cfg_real != iw_cfg {
        push(&["--tmpfs", &iw_cfg_real]);
    }

    for name in DOTFILE_RO {
        let p = input.home.join(name);
        if input.exists(&p) {
            let s = p.to_string_lossy().to_string();
            push(&["--ro-bind", &s, &s]);
        }
    }
    // DOTDIR_DENY entries are intentionally NOT emitted here (asserted by tests),
    // so they stay invisible under the HOME tmpfs.

    // --- agent + guard binaries reachable after HOME tmpfs ---
    if let Some(bin) = &input.agent_binary {
        for p in [&bin.link, &bin.target_dir] {
            let s = p.to_string_lossy().to_string();
            push(&["--ro-bind", &s, &s]);
        }
    }
    let iw = input.iw_binary.to_string_lossy().to_string();
    push(&["--ro-bind", &iw, &iw]);

    // --- extra read-only paths (a jail profile's `extra_ro`), before the
    // project and before the protected masks are re-applied, so neither can
    // be undone by them. `-try`: a path that is gone is skipped. Empty unless
    // a profile named some, so a jail without one is what it was. ---
    for p in &input.args.extra_ro {
        let s = p.to_string_lossy().to_string();
        push(&["--ro-bind-try", &s, &s]);
    }

    // --- project (rw, same path), LATE so it wins over the HOME tmpfs ---
    let proj = input.args.project.to_string_lossy().to_string();
    push(&["--bind", &proj, &proj]);
    push(&["--chdir", &proj]);

    // --- git worktree admin dirs, AFTER the project bind ---
    if let Some(wt) = &input.worktree {
        for p in [&wt.git_dir, &wt.common_dir] {
            let s = p.to_string_lossy().to_string();
            push(&["--bind", &s, &s]);
        }
    }

    // Defense in depth: writable project/worktree mounts are deliberately late,
    // so re-apply every protected mask after them. Validation above should make
    // overlap impossible; this final last-wins layer keeps secrets hidden if a
    // future writable bind is added without the corresponding validation.
    for path in protected_host_paths(input) {
        let dest = path.to_string_lossy().to_string();
        push(&["--tmpfs", &dest]);
    }

    // --- the launcher's records directory, hidden (`--identity` only). It is
    // under the home's `.local`, which the agent may write, and it holds the
    // record the launcher keeps of every instance. After every writable bind,
    // so none of them brings it back. ---
    if input.args.identity {
        for dir in &input.records_dirs {
            let dest = dir.to_string_lossy().to_string();
            push(&["--tmpfs", &dest]);
        }
    }

    // --- nested project-secret masks, AFTER the project bind (last-wins). The I/O
    // layer glob-expanded + statted `deny_read` into `deny_paths`. A DIRECTORY is
    // masked with a tmpfs; a FILE is masked by binding /dev/null over it - a tmpfs
    // over a file makes bwrap abort with ENOTDIR, which would break every project
    // that has a real `.env`. ---
    for d in &input.deny_paths {
        let dest = d.abs.to_string_lossy().to_string();
        if d.is_dir {
            push(&["--tmpfs", &dest]);
        } else {
            push(&["--ro-bind", "/dev/null", &dest]);
        }
    }

    // --- the launch record, read-only, LAST of the mounts. It lands on the
    // `/run` tmpfs above (bwrap makes `/run/innerwarden`), and no later option
    // can mount over it, so last-wins keeps it the launcher's. bwrap copies
    // the descriptor's bytes into a file of its own outside the new root and
    // binds that read-only: the agent has no writable path to it. bwrap reads
    // the descriptor after it reports the jail's pid, so the launcher can
    // write a record that names the jail it is read into. ---
    if let Some(fd) = input.record_fd {
        push(&[
            "--ro-bind-data",
            &fd.to_string(),
            innerwarden_agent_guard::identity::JAIL_RECORD_PATH,
        ]);
    }

    // --- namespaces / lifecycle ---
    push(&["--die-with-parent"]);
    push(&["--unshare-pid", "--unshare-uts", "--unshare-ipc"]);
    push(&["--hostname", "ai-sandbox"]);
    if !input.stdin_is_tty {
        push(&["--new-session"]);
    }
    // The command's own `PATH` and loader variables, which the launcher kept
    // out of the programs that start the jail (`--identity` only).
    if input.args.identity {
        for (name, value) in &input.child_env {
            push(&["--setenv", name, value]);
        }
    }
    // Only an identified launch asks bwrap to report the jail's pid. Last before
    // the terminator, so no earlier option depends on it and none is moved.
    if let Some(fd) = input.info_fd {
        push(&["--info-fd", &fd.to_string()]);
    }
    // NO --unshare-net (agent/hook/git need it in v1); NO --clearenv.

    // --- terminator + child ---
    push(&["--"]);
    a.extend(input.args.child.iter().cloned());

    Ok(LinuxJailPlan {
        bwrap_args: a,
        env: compute_jail_env(input),
        rlimit_nofile: 65536,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosJailPlan {
    pub profile: String,
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// Escape a string for an SBPL string literal: backslash, double-quote, and the
/// control chars. Security-critical - a naive path with a `"` would otherwise
/// break out of the rule.
pub(crate) fn sbpl_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape a string to be a LITERAL inside an SBPL regex literal `#"..."`. In that
/// syntax the backslash IS the escape char, so this is a SINGLE pass: prepend one
/// backslash before every regex metacharacter (so a path `.` matches literally, not
/// any-char), before `\` and `"` (so the path cannot break the regex string), and
/// map control chars. Prevents a path from widening the regex.
pub(crate) fn sbpl_regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\'
            | '"' => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Build the macOS sandbox-exec (SBPL) profile + argv. v1 "normal" mode:
/// allow-read-all then deny secrets LAST; allow write to the project + a small
/// writable set then deny secrets LAST. `~/.config/innerwarden` is read+write
/// DENIED (secret + own-policy hide), so the agent cannot read `llm-key` or rewrite
/// the hook wiring. Denies are always emitted last (last-wins).
pub fn build_macos_profile(input: &JailInputs) -> Result<MacosJailPlan, ContainError> {
    validate_jail_inputs(input)?;
    let home = input.home.to_string_lossy().to_string();
    let proj = input.args.project.to_string_lossy().to_string();
    let iw_cfg = input.iw_config_dir().to_string_lossy().to_string();
    let e = |s: &str| sbpl_escape(s);

    let mut p = String::new();
    p.push_str("(version 1)\n(deny default)\n\n");

    // --- static ---
    p.push_str(
        "(allow process-exec)\n(allow process-fork)\n(allow process-info* (target same-sandbox))\n\
         (allow signal (target same-sandbox))\n(allow sysctl-read)\n(allow mach-lookup)\n\
         (allow mach-register)\n(allow mach-host*)\n(allow ipc-posix-shm*)\n(allow ipc-posix-sem)\n\
         (allow pseudo-tty)\n(allow file-ioctl)\n(allow iokit-open)\n\
         (allow file-read* file-write* (literal \"/dev/ptmx\"))\n\
         (allow file-read* file-write* (regex #\"^/dev/ttys[0-9]+\"))\n\
         (allow file-read* file-write* (literal \"/dev/null\"))\n\
         (allow file-read* file-write* (literal \"/dev/zero\"))\n\
         (allow file-read* (literal \"/dev/random\"))\n\
         (allow file-read* (literal \"/dev/urandom\"))\n\n",
    );

    // --- network (v1 = shared) ---
    if input.args.allow_net {
        p.push_str("(allow network*)\n(allow system-socket)\n\n");
    }

    // --- file-read: allow all, deny secrets LAST ---
    p.push_str("(allow file-read*)\n");
    for d in [".ssh", ".aws", ".gnupg"] {
        p.push_str(&format!(
            "(deny file-read* (subpath \"{}/{}\"))\n",
            e(&home),
            e(d)
        ));
    }
    for d in MACOS_HOME_DENY {
        p.push_str(&format!(
            "(deny file-read* (subpath \"{}/{}\"))\n",
            e(&home),
            e(d)
        ));
    }
    // SECRET CONSTRAINT + own-policy hide (both, not Linux-only). Deny BOTH the
    // nominal and the symlink-RESOLVED real path (sandbox-exec matches the resolved
    // path, so a symlinked ~/.config would otherwise leave the key readable).
    p.push_str(&format!("(deny file-read* (subpath \"{}\"))\n", e(&iw_cfg)));
    let iw_cfg_real = input.iw_config_real.to_string_lossy().to_string();
    if iw_cfg_real != iw_cfg {
        p.push_str(&format!(
            "(deny file-read* (subpath \"{}\"))\n",
            e(&iw_cfg_real)
        ));
    }
    // project secrets (glob-expanded + statted by the I/O layer into deny_paths):
    for d in &input.deny_paths {
        p.push_str(&format!(
            "(deny file-read* (subpath \"{}\"))\n",
            e(&d.abs.to_string_lossy())
        ));
    }
    p.push('\n');

    // --- file-write: allow project + writable set, deny secrets LAST ---
    p.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", e(&proj)));
    if let Some(wt) = &input.worktree {
        p.push_str(&format!(
            "(allow file-write* (subpath \"{}\"))\n",
            e(&wt.git_dir.to_string_lossy())
        ));
        p.push_str(&format!(
            "(allow file-write* (subpath \"{}\"))\n",
            e(&wt.common_dir.to_string_lossy())
        ));
    }
    // Tool state a real coding agent writes (build caches etc.). `~/.config` is
    // allowed here but `~/.config/innerwarden` is DENIED last (below), so the key
    // dir stays unreadable/unwritable.
    for w in [
        ".claude", ".cache", ".local", ".cargo", ".npm", ".rustup", ".config",
    ] {
        p.push_str(&format!(
            "(allow file-write* (subpath \"{}/{}\"))\n",
            e(&home),
            e(w)
        ));
    }
    for w in [
        "/tmp",
        "/private/tmp",
        "/private/var/tmp",
        "/private/var/folders",
    ] {
        p.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", e(w)));
    }
    p.push_str(&format!(
        "(allow file-write* (subpath \"{}\"))\n",
        e(&input.tmpdir.to_string_lossy())
    ));
    p.push_str(&format!(
        "(allow file-write* (subpath \"{}/Library/Caches\"))\n",
        e(&home)
    ));
    // atomic ~/.claude.json + its temp/lock siblings (doubly-anchored regex):
    let claude_json = input
        .home
        .join(".claude.json")
        .to_string_lossy()
        .to_string();
    p.push_str(&format!(
        "(allow file-write* (literal \"{}\"))\n",
        e(&claude_json)
    ));
    p.push_str(&format!(
        "(allow file-write* (regex #\"^{}(\\.tmp\\.[0-9]+\\.[0-9a-f]+|\\.lock)$\"))\n",
        sbpl_regex_escape(&claude_json)
    ));
    // write-denies LAST (nominal + resolved secret dir; then project secrets):
    p.push_str(&format!(
        "(deny file-write* (subpath \"{}\"))\n",
        e(&iw_cfg)
    ));
    if iw_cfg_real != iw_cfg {
        p.push_str(&format!(
            "(deny file-write* (subpath \"{}\"))\n",
            e(&iw_cfg_real)
        ));
    }
    for d in &input.deny_paths {
        p.push_str(&format!(
            "(deny file-write* (subpath \"{}\"))\n",
            e(&d.abs.to_string_lossy())
        ));
    }

    let argv = vec![
        "/usr/bin/sandbox-exec".to_string(),
        "-p".to_string(),
        p.clone(),
        "--".to_string(),
    ]
    .into_iter()
    .chain(input.args.child.iter().cloned())
    .collect();

    Ok(MacosJailPlan {
        profile: p,
        argv,
        env: compute_jail_env(input),
    })
}

/// The in-jail environment: redirect the graph to a jail-local writable file and
/// DISABLE the LLM second-opinion + notify inside the jail (their config lives in
/// the shadowed `~/.config/innerwarden`, so they must not be reached - blocking
/// still works from the embedded rules). `IW_GUARD_SESSION` groups the narrative.
///
/// With `--identity` the hook is also told the agent the jail was started for
/// (`IW_HOOK_AGENT`), so a hook wired for another agent, or for none, is not
/// held to the record of this one.
pub fn compute_jail_env(input: &JailInputs) -> Vec<(String, String)> {
    let mut env = vec![
        (
            "IW_GRAPH_FILE".to_string(),
            input.jail_graph_file().to_string_lossy().to_string(),
        ),
        ("IW_LLM_CONFIG".to_string(), String::new()),
        ("IW_NOTIFY_CONFIG".to_string(), String::new()),
        ("IW_GUARD_SESSION".to_string(), JAIL_SESSION.to_string()),
    ];
    if input.args.identity {
        env.push((
            innerwarden_agent_guard::identity::HOOK_AGENT_ENV.to_string(),
            input.args.agent.clone(),
        ));
    }
    env
}

/// The `PATH` of the programs the launcher runs to start an identified jail
/// (`systemd-run`, bwrap). Each is run by an absolute path already; a fixed
/// `PATH` of root-owned directories keeps a folder the user can write from
/// deciding anything they run on the way.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const HELPER_PATH: &str = "/usr/bin:/bin";

/// What [`launch_env`] decided about the launcher's environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchEnv {
    /// Taken out of the helpers' environment: every dynamic loader variable
    /// (`LD_*`), which would load the user's code into a root-owned helper.
    pub helper_remove: Vec<std::ffi::OsString>,
    /// Handed to the jail's command as it was (`--setenv`), so the agent runs
    /// in the environment it was started with: `PATH` and the loader
    /// variables. A value that is not text cannot be passed on an argument
    /// line and is left out.
    pub child_env: Vec<(String, String)>,
}

/// PURE. Split the launcher's environment for an identified launch: the
/// helpers get [`HELPER_PATH`] and no loader variable; the jail's command gets
/// back exactly the `PATH` and loader variables the launcher was given.
pub fn launch_env<I>(vars: I) -> LaunchEnv
where
    I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
{
    let mut out = LaunchEnv::default();
    for (name, value) in vars {
        let loader = name.as_encoded_bytes().starts_with(b"LD_");
        if loader {
            out.helper_remove.push(name.clone());
        }
        if loader || name == "PATH" {
            if let (Some(name), Some(value)) = (name.to_str(), value.to_str()) {
                out.child_env.push((name.to_string(), value.to_string()));
            }
        }
    }
    out.helper_remove.sort();
    out.child_env.sort();
    out
}

/// Ubuntu 24.04 and later restrict unprivileged user namespaces
/// (`kernel.apparmor_restrict_unprivileged_userns = 1`). Under that sysctl an
/// unconfined `bwrap` cannot set up its uid map and dies with
/// `bwrap: setting up uid map: Permission denied`, which names neither the
/// cause nor the fix. The supported fix is an AppArmor profile that grants the
/// binary `userns`; this says so before spawning, with the exact profile.
///
/// Measured on a stock Ubuntu 24.04 Azure image on 2026-09-08: the sysctl is
/// 1, the image ships no profile for bwrap, and the profile below makes
/// `innerwarden contain` run.
///
/// Pure: the sysctl's text (or `None` where the file does not exist, every
/// non-Ubuntu kernel), whether a bwrap profile is present on disk, and the
/// bwrap path to name in the profile. `Some(lines)` means refuse and print.
pub fn userns_restriction_advice(
    sysctl: Option<&str>,
    profile_on_disk: bool,
    bwrap: &Path,
) -> Option<Vec<String>> {
    let restricted = sysctl.map(|v| v.trim() == "1").unwrap_or(false);
    if !restricted || profile_on_disk {
        return None;
    }
    let bwrap = bwrap.display();
    Some(vec![
        "innerwarden contain: this kernel restricts unprivileged user namespaces".into(),
        "  (kernel.apparmor_restrict_unprivileged_userns = 1, the Ubuntu 24.04 default), and"
            .into(),
        format!("  {bwrap} has no AppArmor profile granting it one, so the jail cannot be built"),
        "  (bwrap would fail with: setting up uid map: Permission denied).".into(),
        "".into(),
        "  Grant bwrap a user namespace, once, without weakening the sysctl for everything else:"
            .into(),
        "    sudo tee /etc/apparmor.d/bwrap >/dev/null <<'EOF'".into(),
        "    abi <abi/4.0>,".into(),
        "    include <tunables/global>".into(),
        format!("    profile bwrap {bwrap} flags=(unconfined) {{"),
        "      userns,".into(),
        "      include if exists <local/bwrap>".into(),
        "    }".into(),
        "    EOF".into(),
        "    sudo apparmor_parser -r /etc/apparmor.d/bwrap".into(),
        "".into(),
        "  Then run this command again. Nothing was run.".into(),
    ])
}

/// The pure half of `contain --identity`: read what bwrap reported, read what
/// the host says about the jail process, and put the facts into a
/// [`LaunchRecord`]. Nothing here opens a file or a process; the thin adapter
/// in `contain_io` reads the facts and hands them in.
///
/// The record is a LABEL file (agent type, project) plus the facts the launcher
/// saw. It never says how much to trust the instance: that is decided by whoever
/// reads it, from the kernel's word (`identity::judge_trust_in_jail`).
pub mod launch {
    // The adapter that calls these is Linux-only; the tests run everywhere.
    #![cfg_attr(not(target_os = "linux"), allow(dead_code))]

    use std::path::{Path, PathBuf};

    use chrono::{DateTime, Utc};
    use innerwarden_agent_guard::identity::{
        instance_record_file, is_instance_id, is_user_scope_cgroup, system_scope_cgroup, Jail,
        JailBackend, LaunchMode, LaunchRecord, Launcher, RecordError, Scope, Scopes,
        INITIAL_PID_NS_INODE, LAUNCHER_RECORD_DIR, LAUNCH_SCHEMA,
    };
    use serde::Deserialize;

    use super::Mode;

    /// The most bytes read from the info descriptor. bwrap writes one short
    /// JSON object; anything near this is not that.
    pub const MAX_INFO_BYTES: usize = 4096;

    /// The descriptor number a dry run shows. A real run uses the pipe's own.
    pub const DRY_RUN_INFO_FD: i32 = 9;

    /// The record descriptor a dry run shows. A real run uses the pipe's own.
    pub const DRY_RUN_RECORD_FD: i32 = 10;

    // -- the user scope ------------------------------------------------------
    //
    // The order a launch runs in, and why it is this order:
    //
    // 1. `systemd-run --user --scope` asks the user's manager for the scope,
    //    waits until it exists, and becomes bwrap (exec, same pid, same
    //    terminal). The scope is made OUTSIDE the jail, by the launcher.
    // 2. bwrap clones the jail's first process; the jail's user, PID and mount
    //    namespaces are made by that clone. bwrap reports the pid.
    // 3. The jail's first process waits: it reads the launch record from the
    //    launcher before it builds the jail's root, so nothing of the agent
    //    has run yet.
    // 4. The launcher reads the pid's start time, namespace and cgroup from
    //    the host, asks for a system scope where Active Defence runs, and
    //    hands the record in. The jail continues.
    //
    // A host policy that restricts new user namespaces, applied to the
    // instance's scope, therefore never sees bwrap's own namespaces (made at
    // 2, before any placement at 4) and does see any the agent tries later.
    // A bwrap option that makes a SECOND user namespace after step 3
    // (`--disable-userns`, or `--uid`/`--gid` other than the caller's) would
    // be refused by such a policy and kill the jail: moving this order is a
    // change to make with that in view. Nothing here arms anything. On Ubuntu
    // 24.04 bwrap itself needs the AppArmor profile that grants it `userns`
    // (`userns_restriction_advice`, `flags=(unconfined)`).

    /// The first systemd whose `systemd-run` has `--expand-environment=`, the
    /// switch that turns `$NAME` expansion of the command line on and off.
    /// With `--scope`, systemd 257 was measured NOT to expand by default; the
    /// jail's arguments and the agent's own command line must reach bwrap as
    /// typed whatever another version's default is, so from this version on
    /// `--expand-environment=no` is passed. An older systemd has neither the
    /// switch nor the expansion.
    pub const EXPAND_ENVIRONMENT_SWITCH_SINCE: u32 = 254;

    /// What decides whether a launch gets a user scope. Read by the caller.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ScopeFacts {
        /// `systemd-run`, resolved like the jail backend: a root-owned file at
        /// a fixed path no other account can write, never `$PATH`.
        pub systemd_run: Option<PathBuf>,
        /// The major version the first line of `systemd-run --version` gave.
        pub systemd_version: Option<u32>,
        /// The user's service manager has its socket at
        /// `$XDG_RUNTIME_DIR/systemd/private`, a socket this user owns.
        pub user_manager: bool,
    }

    /// Why a launch runs without a user scope.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum NoScope {
        NoSystemdRun,
        /// No manager for this session: no login session, `env -i`, a cron or
        /// CI job without lingering.
        NoUserManager,
        /// `systemd-run --version` gave nothing this build reads, so whether it
        /// takes the switch that keeps `$NAME` in the agent's command as typed
        /// is unknown.
        UnknownSystemd,
        /// systemd-run was tried and the jail never started under it.
        ScopeNotStarted,
        /// The jail started, and the kernel does not show it in its scope.
        NotSeenInScope,
    }

    impl NoScope {
        pub fn why(self) -> &'static str {
            match self {
                NoScope::NoSystemdRun => "systemd-run is not installed at a root-owned path",
                NoScope::NoUserManager => "no user service manager in this session",
                NoScope::UnknownSystemd => "the systemd version is unknown",
                NoScope::ScopeNotStarted => "systemd-run did not start the jail in a scope",
                NoScope::NotSeenInScope => "the kernel does not show the jail in its scope",
            }
        }
    }

    /// The line `contain --identity` prints when the instance has no scope.
    pub fn no_scope_sentence(why: NoScope) -> String {
        format!(
            "innerwarden contain: no scope ({}): identity is at most observed",
            why.why()
        )
    }

    /// How the jail is launched: in a user scope, or directly.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ScopePlan {
        User {
            systemd_run: PathBuf,
            /// `innerwarden-contain-<instance_id>.scope`.
            unit: String,
            /// Pass `--expand-environment=no`.
            no_expand: bool,
        },
        None(NoScope),
    }

    /// Decide the scope from the facts. `unit` is the instance's
    /// `identity::scope_unit_name`.
    pub fn plan_scope(facts: &ScopeFacts, unit: &str) -> ScopePlan {
        let Some(systemd_run) = facts.systemd_run.clone() else {
            return ScopePlan::None(NoScope::NoSystemdRun);
        };
        if !facts.user_manager {
            return ScopePlan::None(NoScope::NoUserManager);
        }
        let Some(version) = facts.systemd_version else {
            return ScopePlan::None(NoScope::UnknownSystemd);
        };
        ScopePlan::User {
            systemd_run,
            unit: unit.to_string(),
            no_expand: version >= EXPAND_ENVIRONMENT_SWITCH_SINCE,
        }
    }

    /// Where the user's manager listens, from `$XDG_RUNTIME_DIR`. A relative or
    /// empty value names nothing (the XDG rule).
    pub fn user_manager_socket(xdg_runtime_dir: Option<&str>) -> Option<PathBuf> {
        let dir = Path::new(xdg_runtime_dir?);
        dir.is_absolute().then(|| dir.join("systemd/private"))
    }

    /// The major version in `systemd-run --version`, whose first line is
    /// `systemd 255 (255.4-1ubuntu8.17)`.
    pub fn parse_systemd_version(text: &str) -> Option<u32> {
        let first = text.lines().next()?;
        let rest = first.strip_prefix("systemd ")?;
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() || digits.len() > 6 {
            return None;
        }
        digits.parse().ok()
    }

    /// The program and arguments that start the jail. Without a scope it is
    /// bwrap and the plan's arguments, untouched.
    pub fn launch_argv(
        bwrap: &Path,
        bwrap_args: &[String],
        scope: &ScopePlan,
    ) -> (PathBuf, Vec<String>) {
        match scope {
            ScopePlan::None(_) => (bwrap.to_path_buf(), bwrap_args.to_vec()),
            ScopePlan::User {
                systemd_run,
                unit,
                no_expand,
            } => {
                let mut args: Vec<String> = ["--user", "--scope", "--quiet", "--unit"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                args.push(unit.clone());
                if *no_expand {
                    args.push("--expand-environment=no".to_string());
                }
                args.push("--".to_string());
                args.push(bwrap.to_string_lossy().into_owned());
                args.extend(bwrap_args.iter().cloned());
                (systemd_run.clone(), args)
            }
        }
    }

    /// The cgroup in `/proc/<pid>/cgroup`: the unified line `0::<path>`, or on
    /// a hybrid host systemd's own `name=systemd` line. `None` for anything
    /// else, including a path that is not absolute.
    pub fn parse_proc_cgroup(text: &str) -> Option<String> {
        let unified = text.lines().find_map(|l| l.strip_prefix("0::"));
        let named = || {
            text.lines().find_map(|l| {
                let mut parts = l.splitn(3, ':');
                let (_, controllers, path) = (parts.next()?, parts.next()?, parts.next()?);
                (controllers == "name=systemd").then_some(path)
            })
        };
        let path = unified.or_else(named)?.trim_end();
        (path.starts_with('/') && !path.chars().any(char::is_control)).then(|| path.to_string())
    }

    /// The user scope the jail is in, if the kernel's word for its cgroup is
    /// the instance's unit under this user's own manager.
    pub fn user_scope_seen(cgroup: &str, unit: &str, uid: u32) -> Option<Scope> {
        is_user_scope_cgroup(cgroup, unit, uid).then(|| Scope {
            unit: unit.to_string(),
            cgroup_path: cgroup.to_string(),
        })
    }

    /// The system scope the jail is in, if the kernel's word for its cgroup is
    /// exactly the instance's unit under the system slice, which only root
    /// can make.
    pub fn system_scope_seen(cgroup: &str, unit: &str) -> Option<Scope> {
        (cgroup == system_scope_cgroup(unit)).then(|| Scope {
            unit: unit.to_string(),
            cgroup_path: cgroup.to_string(),
        })
    }

    /// What bwrap reports through `--info-fd`. Fields it adds later are ignored.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct InfoFd {
        /// The jail's first process, as a pid in the launcher's namespace.
        pub child_pid: u32,
        /// bwrap's own word for the jail's PID namespace inode, if it gave one.
        pub pid_namespace: Option<u64>,
        /// bwrap's own word for the jail's mount namespace inode, if it gave one.
        pub mnt_namespace: Option<u64>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum InfoError {
        Empty,
        TooLarge,
        Malformed(String),
        /// No `child-pid`, or zero, or more than a pid can be.
        NoChildPid,
    }

    impl std::fmt::Display for InfoError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                InfoError::Empty => write!(f, "bwrap reported nothing on the info descriptor"),
                InfoError::TooLarge => {
                    write!(f, "bwrap's info is larger than {MAX_INFO_BYTES} bytes")
                }
                InfoError::Malformed(why) => write!(f, "bwrap's info is not JSON: {why}"),
                InfoError::NoChildPid => write!(f, "bwrap's info has no usable child-pid"),
            }
        }
    }

    /// Parse the JSON bwrap writes to `--info-fd`, for example
    /// `{"child-pid": 2778, "mnt-namespace": 4026532218, "pid-namespace": 4026532220}`.
    pub fn parse_info_fd(bytes: &[u8]) -> Result<InfoFd, InfoError> {
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Err(InfoError::Empty);
        }
        if bytes.len() > MAX_INFO_BYTES {
            return Err(InfoError::TooLarge);
        }
        #[derive(Deserialize)]
        struct Wire {
            #[serde(rename = "child-pid")]
            child_pid: Option<u64>,
            #[serde(rename = "pid-namespace")]
            pid_namespace: Option<u64>,
            #[serde(rename = "mnt-namespace")]
            mnt_namespace: Option<u64>,
        }
        let wire: Wire =
            serde_json::from_slice(bytes).map_err(|e| InfoError::Malformed(e.to_string()))?;
        let child_pid = wire
            .child_pid
            .and_then(|p| u32::try_from(p).ok())
            .filter(|p| *p != 0)
            .ok_or(InfoError::NoChildPid)?;
        Ok(InfoFd {
            child_pid,
            pid_namespace: wire.pid_namespace,
            mnt_namespace: wire.mnt_namespace,
        })
    }

    /// Field 22 of `/proc/<pid>/stat` (start time in clock ticks since boot).
    /// The process name in field 2 is in parentheses and may hold spaces and
    /// parentheses, so the fields are counted from the LAST `)`.
    pub fn parse_start_ticks(stat: &str) -> Option<u64> {
        let after_name = &stat[stat.rfind(')')? + 1..];
        // after_name starts at field 3 (state); field 22 is its 20th token.
        after_name.split_ascii_whitespace().nth(19)?.parse().ok()
    }

    /// The inode in a namespace link such as `pid:[4026532222]`.
    pub fn parse_ns_link(link: &str) -> Option<u64> {
        parse_ns_link_of("pid", link)
    }

    /// The inode in a mount namespace link such as `mnt:[4026532218]`.
    pub fn parse_mnt_ns_link(link: &str) -> Option<u64> {
        parse_ns_link_of("mnt", link)
    }

    /// The inode in a `<kind>:[<inode>]` link. Another kind of namespace's
    /// link is not this one.
    fn parse_ns_link_of(kind: &str, link: &str) -> Option<u64> {
        let rest = link
            .trim()
            .strip_prefix(kind)?
            .strip_prefix(":[")?
            .strip_suffix(']')?;
        if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        rest.parse().ok()
    }

    /// An instance id from 16 random bytes: 32 lowercase hex characters.
    pub fn instance_id_from(bytes: [u8; 16]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The directory that holds the launcher's records:
    /// `$XDG_STATE_HOME/innerwarden/instances`, or
    /// `~/.local/state/innerwarden/instances` when the variable is unset, empty
    /// or not an absolute path (the XDG rule: a relative value is ignored).
    pub fn records_dir(xdg_state_home: Option<&str>, home: &Path) -> PathBuf {
        match xdg_state_home {
            Some(dir) if Path::new(dir).is_absolute() => Path::new(dir).join(LAUNCHER_RECORD_DIR),
            _ => home.join(".local/state").join(LAUNCHER_RECORD_DIR),
        }
    }

    /// Where one record lives, or `None` for an id that is not an id.
    pub fn record_path(dir: &Path, instance_id: &str) -> Option<PathBuf> {
        Some(dir.join(instance_record_file(instance_id)?))
    }

    /// The name of the file, beside an instance's record, that holds the
    /// absolute path of its project: `<instance id>.project`, or `None` for
    /// an id that is not an id.
    ///
    /// It lives only in the launcher's records directory, never in the jail:
    /// the record shown inside the jail names the project by its folder name
    /// alone. The local dashboard reads it to find the graph the jail's hook
    /// writes (`<project>/.innerwarden/graph.json`).
    pub fn project_path_file(instance_id: &str) -> Option<String> {
        is_instance_id(instance_id).then(|| format!("{instance_id}.project"))
    }

    /// The longest project path a `.project` file may hold.
    pub const MAX_PROJECT_PATH_BYTES: usize = 4096;

    /// The project path a `.project` file holds, or `None` unless it is one
    /// line of UTF-8 naming an absolute path, bounded, with no control
    /// character, no `.` or `..` step, whose folder name is `project` (the
    /// record's own label): a file copied from another instance's record
    /// names another folder and is not taken.
    pub fn parse_project_path(bytes: &[u8], project: &str) -> Option<PathBuf> {
        let text = std::str::from_utf8(bytes).ok()?;
        let text = text.strip_suffix('\n').unwrap_or(text);
        if text.is_empty()
            || text.len() > MAX_PROJECT_PATH_BYTES
            || !text.starts_with('/')
            || text.chars().any(char::is_control)
        {
            return None;
        }
        // Read step by step on the text: `Path::components` would drop a `.`
        // step and an empty one before they could be refused.
        let plain = text[1..]
            .split('/')
            .all(|step| !step.is_empty() && step != "." && step != "..");
        let path = Path::new(text);
        (plain && path.file_name().and_then(|n| n.to_str()) == Some(project))
            .then(|| path.to_path_buf())
    }

    pub fn launch_mode(mode: &Mode) -> LaunchMode {
        match mode {
            Mode::Monitor => LaunchMode::Monitor,
            Mode::Enforce => LaunchMode::Enforce,
            Mode::BlockReview => LaunchMode::BlockReview,
        }
    }

    /// Every fact the record is made from, all read by the caller.
    #[derive(Debug, Clone)]
    pub struct LaunchFacts<'a> {
        pub instance_id: String,
        pub agent_type: &'a str,
        pub launcher_path: &'a Path,
        pub launcher_version: &'a str,
        /// The launcher binary is a file only root can replace: the answer of
        /// `contain_io::backend_trusted`, the one definition of a trusted file.
        pub launcher_root_owned: bool,
        pub uid: u32,
        /// The project directory; only its last component is recorded.
        pub project: &'a Path,
        pub mode: &'a Mode,
        pub started_at: DateTime<Utc>,
        pub info: InfoFd,
        /// `/proc/<child-pid>/stat` field 22, read by the launcher.
        pub start_ticks: u64,
        /// `/proc/<child-pid>/ns/pid`, read by the launcher.
        pub pid_ns: u64,
        /// `/proc/<child-pid>/ns/mnt`, read by the launcher.
        pub mnt_ns: u64,
        /// `/proc/self/ns/mnt` of the launcher, `None` if it could not be read.
        pub launcher_mnt_ns: Option<u64>,
        /// The scopes the kernel showed the jail in ([`user_scope_seen`],
        /// [`system_scope_seen`]); empty for none.
        pub scope: Scopes,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AssembleError {
        /// The jail process shares the launcher's own PID namespace, so there
        /// is no boundary to record.
        NoPidNamespace,
        /// bwrap and the host disagree about the jail's namespace.
        NamespaceDisagrees,
        /// The jail process has no mount namespace of its own, or it could not
        /// be told apart from the launcher's.
        NoMountNamespace,
        /// bwrap and the host disagree about the jail's mount namespace.
        MountNamespaceDisagrees,
        /// The launcher path is not valid UTF-8.
        LauncherPathNotUtf8,
        /// The project has no folder name to record.
        NoProjectName,
        /// A value is outside what its record field may hold.
        Record(RecordError),
    }

    impl std::fmt::Display for AssembleError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                AssembleError::NoPidNamespace => {
                    write!(f, "the jail process is in the launcher's own PID namespace")
                }
                AssembleError::NamespaceDisagrees => {
                    write!(
                        f,
                        "bwrap and the host disagree about the jail's PID namespace"
                    )
                }
                AssembleError::NoMountNamespace => {
                    write!(f, "the jail process is not in a mount namespace of its own")
                }
                AssembleError::MountNamespaceDisagrees => write!(
                    f,
                    "bwrap and the host disagree about the jail's mount namespace"
                ),
                AssembleError::LauncherPathNotUtf8 => write!(f, "the launcher path is not UTF-8"),
                AssembleError::NoProjectName => write!(f, "the project has no folder name"),
                AssembleError::Record(e) => write!(f, "{e}"),
            }
        }
    }

    /// Put the delivered facts into a record, or say why they make none.
    ///
    /// A record is never produced for a jail that has no PID namespace of its
    /// own: writing one would claim a boundary that is not there.
    pub fn assemble_record(facts: LaunchFacts<'_>) -> Result<LaunchRecord, AssembleError> {
        if facts.pid_ns == 0 || facts.pid_ns == INITIAL_PID_NS_INODE {
            return Err(AssembleError::NoPidNamespace);
        }
        if facts
            .info
            .pid_namespace
            .is_some_and(|ns| ns != facts.pid_ns)
        {
            return Err(AssembleError::NamespaceDisagrees);
        }
        // The launcher's own mount namespace must be known to be another one:
        // otherwise the jail's root is the launcher's filesystem, not one it
        // built.
        if facts.mnt_ns == 0 || facts.launcher_mnt_ns.is_none_or(|own| own == facts.mnt_ns) {
            return Err(AssembleError::NoMountNamespace);
        }
        if facts
            .info
            .mnt_namespace
            .is_some_and(|ns| ns != facts.mnt_ns)
        {
            return Err(AssembleError::MountNamespaceDisagrees);
        }
        let launcher_path = facts
            .launcher_path
            .to_str()
            .ok_or(AssembleError::LauncherPathNotUtf8)?
            .to_string();
        let project = facts
            .project
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(AssembleError::NoProjectName)?
            .to_string();
        let record = LaunchRecord {
            schema: LAUNCH_SCHEMA,
            instance_id: facts.instance_id,
            agent_type: facts.agent_type.to_string(),
            launcher: Launcher {
                path: launcher_path,
                version: facts.launcher_version.to_string(),
                root_owned: facts.launcher_root_owned,
            },
            uid: facts.uid,
            project,
            mode: launch_mode(facts.mode),
            started_at: facts.started_at,
            jail: Jail {
                backend: JailBackend::Bwrap,
                pid: facts.info.child_pid,
                start_ticks: facts.start_ticks,
                pid_ns: facts.pid_ns,
                mnt_ns: facts.mnt_ns,
            },
            scope: (!facts.scope.is_empty()).then_some(facts.scope),
        };
        record.validate().map_err(AssembleError::Record)?;
        Ok(record)
    }

    // -- after the jail: what its hook screened ------------------------------
    //
    // The hook inside the jail writes its graph into the project, which the
    // agent can write too, so everything read from it is the jail's own word.
    // The launcher reads it only once the jail has ended: the jail's PID
    // namespace is gone then, so no process of the jail is left to change the
    // file while it is read. It counts, and sends counts; it copies nothing,
    // and it never writes the host's shared graph.

    /// The most bytes of the jail's graph read: the cap every writer of a
    /// graph prunes to.
    pub const MAX_JAIL_GRAPH_BYTES: u64 = innerwarden_graph::Graph::MAX_BYTES as u64;

    /// One entry on the way to the jail's graph, described without following
    /// a link.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct GraphEntry {
        pub symlink: bool,
        pub dir: bool,
        pub regular: bool,
        pub uid: u32,
        pub len: u64,
    }

    /// What the launcher found where the jail's hook keeps its graph.
    #[derive(Debug, Clone, PartialEq)]
    pub enum JailGraph {
        Absent,
        /// There, and refused, with a stable reason code.
        Unreadable(&'static str),
        Read(innerwarden_graph::Graph),
    }

    /// The project's graph folder may be read only if it is a real folder of
    /// the launching user: a link there could aim the read at another file.
    pub fn vet_jail_graph_dir(entry: &GraphEntry, uid: u32) -> Result<(), &'static str> {
        if entry.symlink {
            return Err("graph_dir_is_a_symlink");
        }
        if !entry.dir {
            return Err("graph_dir_not_a_directory");
        }
        if entry.uid != uid {
            return Err("graph_dir_not_owned");
        }
        Ok(())
    }

    /// The graph file, as opened (no link followed): a regular file of the
    /// launching user, no larger than a graph can be.
    pub fn vet_jail_graph_file(entry: &GraphEntry, uid: u32) -> Result<(), &'static str> {
        if entry.symlink || !entry.regular {
            return Err("graph_not_a_regular_file");
        }
        if entry.uid != uid {
            return Err("graph_not_owned");
        }
        if entry.len > MAX_JAIL_GRAPH_BYTES {
            return Err("graph_too_large");
        }
        Ok(())
    }

    /// The graph in `bytes`. An empty file is an empty graph; anything that
    /// is not a graph is refused, never read as zero.
    pub fn parse_jail_graph(bytes: &[u8]) -> JailGraph {
        if bytes.len() as u64 > MAX_JAIL_GRAPH_BYTES {
            return JailGraph::Unreadable("graph_too_large");
        }
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return JailGraph::Read(innerwarden_graph::Graph::default());
        }
        std::str::from_utf8(bytes)
            .ok()
            .and_then(|json| innerwarden_graph::Graph::from_json(json).ok())
            .map(JailGraph::Read)
            .unwrap_or(JailGraph::Unreadable("graph_malformed"))
    }

    /// The commands of this instance in the jail's graph, and the newest.
    ///
    /// A command counts when it was recorded inside the launch window and is
    /// this instance's: it carries this instance's `instance_id`, or it
    /// carries none and the jail's session ran it. A command labelled with
    /// another instance never counts, and neither does one with no time.
    pub fn count_contained_run(
        graph: &innerwarden_graph::Graph,
        instance_id: &str,
        started_ms: u64,
        ended_ms: u64,
    ) -> (u32, Option<u64>) {
        let session = format!("session:{}", super::JAIL_SESSION);
        let ran: std::collections::HashSet<&str> = graph
            .edges
            .iter()
            .filter(|e| e.kind == "ran" && e.from == session)
            .map(|e| e.to.as_str())
            .collect();
        let mut commands: u32 = 0;
        let mut last: Option<u64> = None;
        for node in graph.nodes.iter().filter(|n| n.kind == "command") {
            let ours = match node.attrs.get("instance_id") {
                Some(labelled) => labelled == instance_id,
                None => ran.contains(node.id.as_str()),
            };
            let Some(at) = node
                .attrs
                .get("recorded_at_ms")
                .and_then(|ms| ms.parse::<u64>().ok())
            else {
                continue;
            };
            if !ours || at < started_ms || at > ended_ms {
                continue;
            }
            commands = commands.saturating_add(1);
            last = Some(last.map_or(at, |l| l.max(at)));
        }
        (commands, last)
    }

    /// Of the commands [`count_contained_run`] counts, the ones the hook
    /// recorded as allowed by a per-agent rule the host decided: labelled
    /// `trust_source=host` with a host decision, recommended `allow`, decided
    /// by the type or the instance layer (a profile's deny decides there too,
    /// and is not one). Their number, and each (decision, command hash) pair
    /// once, sorted, at most `MAX_HOST_DECISIONS`. The hash is of the text the
    /// node holds for the command.
    pub fn host_allowances_in(
        graph: &innerwarden_graph::Graph,
        instance_id: &str,
        started_ms: u64,
        ended_ms: u64,
    ) -> (
        u32,
        Vec<innerwarden_agent_guard::identity::HostDecisionClaim>,
    ) {
        use innerwarden_agent_guard::identity::{
            is_decision_id, HostDecisionClaim, HOST_TRUST_SOURCE, MAX_HOST_DECISIONS,
        };
        use sha2::{Digest, Sha256};
        let session = format!("session:{}", super::JAIL_SESSION);
        let ran: std::collections::HashSet<&str> = graph
            .edges
            .iter()
            .filter(|e| e.kind == "ran" && e.from == session)
            .map(|e| e.to.as_str())
            .collect();
        let mut allowances: u32 = 0;
        let mut claims = std::collections::BTreeSet::new();
        for node in graph.nodes.iter().filter(|n| n.kind == "command") {
            let attr = |key: &str| node.attrs.get(key).map(String::as_str);
            let ours = match attr("instance_id") {
                Some(labelled) => labelled == instance_id,
                None => ran.contains(node.id.as_str()),
            };
            let in_window = attr("recorded_at_ms")
                .and_then(|ms| ms.parse::<u64>().ok())
                .is_some_and(|at| (started_ms..=ended_ms).contains(&at));
            let Some(decision) = attr("host_decision").filter(|id| is_decision_id(id)) else {
                continue;
            };
            let allowed = attr("trust_source") == Some(HOST_TRUST_SOURCE)
                && attr("recommendation") == Some("allow")
                && matches!(attr("deciding_layer"), Some("agent_type" | "instance"));
            if !ours || !in_window || !allowed {
                continue;
            }
            allowances = allowances.saturating_add(1);
            let digest = Sha256::digest(node.label.as_bytes());
            claims.insert(HostDecisionClaim {
                decision_id: decision.to_string(),
                command_sha256: digest.iter().map(|b| format!("{b:02x}")).collect(),
            });
        }
        let claims: Vec<HostDecisionClaim> = claims.into_iter().take(MAX_HOST_DECISIONS).collect();
        (allowances, claims)
    }

    /// The report of an ended identified run, or `None`.
    ///
    /// Without `--identity` this is `None` and `read_graph` is never called:
    /// a jail launched without the flag reads no new file and sends nothing.
    pub fn contained_run_report_for(
        args: &super::ContainArgs,
        instance_id: &str,
        started_ms: u64,
        ended_ms: u64,
        read_graph: impl FnOnce() -> JailGraph,
    ) -> Option<serde_json::Value> {
        use innerwarden_agent_guard::identity::{
            contained_run_report, ContainedRun, JailGraphState,
        };
        if !args.identity {
            return None;
        }
        let (graph, (commands, last_ms), (host_allowances, host_decisions)) = match read_graph() {
            JailGraph::Absent => (JailGraphState::Absent, (0, None), (0, Vec::new())),
            JailGraph::Unreadable(_) => (JailGraphState::Unreadable, (0, None), (0, Vec::new())),
            JailGraph::Read(g) => (
                JailGraphState::Read,
                count_contained_run(&g, instance_id, started_ms, ended_ms),
                host_allowances_in(&g, instance_id, started_ms, ended_ms),
            ),
        };
        contained_run_report(&ContainedRun {
            instance_id,
            started_ms,
            ended_ms,
            graph,
            commands,
            last_ms,
            host_allowances,
            host_decisions: &host_decisions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(child: &[&str]) -> ContainArgs {
        ContainArgs {
            agent: "claude-code".into(),
            mode: Mode::Monitor,
            allow_net: true,
            project: PathBuf::from("/home/dev/proj"),
            dry_run: false,
            setup_only: false,
            child: child.iter().map(|s| s.to_string()).collect(),
            extra_rw: vec![],
            extra_ro: vec![],
            deny_read: DEFAULT_DENY_READ.iter().map(|s| s.to_string()).collect(),
            identity: false,
        }
    }

    fn inputs(child: &[&str]) -> JailInputs {
        JailInputs {
            args: args(child),
            home: PathBuf::from("/home/dev"),
            tmpdir: PathBuf::from("/tmp"),
            iw_binary: PathBuf::from("/home/dev/.local/bin/innerwarden"),
            agent_binary: None,
            worktree: None,
            usr_merged: true,
            stdin_is_tty: true,
            existing_paths: vec![
                PathBuf::from("/home/dev/.claude"),
                PathBuf::from("/home/dev/.config"),
                PathBuf::from("/home/dev/.cache"),
                PathBuf::from("/home/dev/.gitconfig"),
                // .ssh EXISTS on the host - must still never be bound:
                PathBuf::from("/home/dev/.ssh"),
            ],
            iw_config_real: PathBuf::from("/home/dev/.config/innerwarden"),
            deny_paths: vec![
                // a resolved project .env FILE (masked with /dev/null, not tmpfs)
                DenyPath {
                    abs: PathBuf::from("/home/dev/proj/.env"),
                    is_dir: false,
                },
                // a resolved secrets/ DIRECTORY (masked with tmpfs)
                DenyPath {
                    abs: PathBuf::from("/home/dev/proj/secrets"),
                    is_dir: true,
                },
            ],
            info_fd: None,
            record_fd: None,
            records_dirs: vec![],
            child_env: vec![],
        }
    }

    /// The whole bwrap argument vector of today's jail, one token per line.
    /// Written before the identity flag existed: a jail launched without the
    /// flag must stay byte for byte this.
    #[test]
    fn golden_argv_of_the_jail_without_any_identity_flag() {
        let plan = build_linux_jail(&inputs(&["claude", "--print"])).unwrap();
        assert_eq!(plan.bwrap_args.join("\n"), GOLDEN_ARGV_PLAIN);
        let mut rich = inputs(&["/bin/sh", "-c", "true"]);
        rich.stdin_is_tty = false;
        rich.agent_binary = Some(ResolvedBinary {
            link: PathBuf::from("/home/dev/.local/bin/claude"),
            target_dir: PathBuf::from("/home/dev/.local/share/claude/v1"),
        });
        rich.worktree = Some(Worktree {
            git_dir: PathBuf::from("/home/dev/repo/.git/worktrees/w"),
            common_dir: PathBuf::from("/home/dev/repo/.git"),
        });
        let plan = build_linux_jail(&rich).unwrap();
        assert_eq!(plan.bwrap_args.join("\n"), GOLDEN_ARGV_RICH);
    }

    #[test]
    fn parse_defaults_and_child_capture() {
        let a =
            parse_contain_args(&["--".into(), "claude".into(), "--dangerously".into()]).unwrap();
        assert_eq!(a.agent, "claude-code");
        assert_eq!(a.mode, Mode::Monitor);
        assert!(a.allow_net);
        assert_eq!(a.child, vec!["claude", "--dangerously"]);
        // bare form without `--`
        let b = parse_contain_args(&["claude".into()]).unwrap();
        assert_eq!(b.child, vec!["claude"]);
    }

    #[test]
    fn parse_modes_and_errors() {
        assert_eq!(
            parse_contain_args(&["--enforce".into(), "--".into(), "x".into()])
                .unwrap()
                .mode,
            Mode::Enforce
        );
        // block-review implies (and is not downgraded by) enforce
        assert_eq!(
            parse_contain_args(&[
                "--block-review".into(),
                "--enforce".into(),
                "--".into(),
                "x".into()
            ])
            .unwrap()
            .mode,
            Mode::BlockReview
        );
        assert_eq!(
            parse_contain_args(&["--agent".into(), "cursor".into(), "--".into(), "x".into()]),
            Err(ContainError::UnknownAgent("cursor".into()))
        );
        assert_eq!(parse_contain_args(&[]), Err(ContainError::NoCommand));
        assert!(matches!(
            parse_contain_args(&["--no-net".into(), "--".into(), "x".into()]),
            Err(ContainError::Unsupported(_))
        ));
        // --setup needs no child
        assert!(parse_contain_args(&["--setup".into()]).is_ok());
    }

    #[test]
    fn mode_maps_to_hook_flags() {
        assert_eq!(Mode::Monitor.hook_flags(), (false, true));
        assert_eq!(Mode::Enforce.hook_flags(), (false, false));
        assert_eq!(Mode::BlockReview.hook_flags(), (true, false));
    }

    // POSIX-only: these build a jail plan for a hardcoded POSIX project path
    // (`/home/dev/proj`, `/Users/dev/proj`). On Windows that path is not
    // absolute in the platform's sense, so the safety check rejects it and the
    // test fails for a reason that has nothing to do with what it asserts.
    // They were never gated because the suite had never run on Windows.
    #[cfg(unix)]
    #[test]
    fn linux_shadows_the_secret_dir_and_never_binds_ssh() {
        let plan = build_linux_jail(&inputs(&["claude"])).unwrap();
        let a = &plan.bwrap_args;
        // the innerwarden config dir is SHADOWED with a tmpfs...
        let shadow_idx = a
            .windows(2)
            .position(|w| w[0] == "--tmpfs" && w[1] == "/home/dev/.config/innerwarden")
            .expect("innerwarden config dir must be shadowed");
        // ...and is NEVER bound (no --bind/--ro-bind of it, in either slot).
        assert!(
            !a.iter().any(|x| x == "/home/dev/.config/innerwarden") || a[shadow_idx] == "--tmpfs",
            "the secret dir must only appear as a --tmpfs shadow"
        );
        assert!(
            !a.windows(2)
                .any(|w| (w[0] == "--bind" || w[0] == "--ro-bind")
                    && w[1] == "/home/dev/.config/innerwarden"),
            "innerwarden config dir must never be bound into the jail"
        );
        // NONE of the deny-listed secret dirs may ever be bound, even if they
        // exist on the host (.ssh is in `existing_paths` above) - they stay
        // invisible under the HOME tmpfs.
        for deny in DOTDIR_DENY {
            let p = format!("/home/dev/{deny}");
            assert!(
                !a.windows(3).any(|w| {
                    (w[0] == "--bind" || w[0] == "--ro-bind") && (w[1] == p || w[2] == p)
                }),
                "{deny} must never be bound from the host into the jail"
            );
        }
        // net is shared in v1
        assert!(!a.iter().any(|x| x == "--unshare-net"));
        // guard binary is reachable
        assert!(a
            .windows(2)
            .any(|w| w[0] == "--ro-bind" && w[1] == "/home/dev/.local/bin/innerwarden"));
        // project bound + chdir
        assert!(a
            .windows(2)
            .any(|w| w[0] == "--bind" && w[1] == "/home/dev/proj"));
        assert!(a
            .windows(2)
            .any(|w| w[0] == "--chdir" && w[1] == "/home/dev/proj"));
        // child at the end after the terminator
        let term = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(&a[term + 1..], &["claude".to_string()]);
    }

    #[test]
    fn jail_rejects_project_roots_that_overlap_protected_host_paths() {
        for unsafe_project in [
            "/",
            "/home",
            "/home/dev",
            "/home/dev/.config",
            "/home/dev/.config/innerwarden",
            "/home/dev/.ssh",
        ] {
            let mut input = inputs(&["claude"]);
            input.args.project = PathBuf::from(unsafe_project);
            assert!(
                build_linux_jail(&input).is_err(),
                "Linux jail accepted unsafe project {unsafe_project}"
            );
            assert!(
                build_macos_profile(&input).is_err(),
                "macOS jail accepted unsafe project {unsafe_project}"
            );
        }
    }

    // POSIX-only: these build a jail plan for a hardcoded POSIX project path
    // (`/home/dev/proj`, `/Users/dev/proj`). On Windows that path is not
    // absolute in the platform's sense, so the safety check rejects it and the
    // test fails for a reason that has nothing to do with what it asserts.
    // They were never gated because the suite had never run on Windows.
    #[cfg(unix)]
    #[test]
    fn jail_accepts_a_safe_project_sibling() {
        let mut input = inputs(&["claude"]);
        input.args.project = PathBuf::from("/home/dev/projects/safe");
        input.deny_paths.clear();
        assert!(build_linux_jail(&input).is_ok());
        assert!(build_macos_profile(&input).is_ok());
    }

    // POSIX-only: these build a jail plan for a hardcoded POSIX project path
    // (`/home/dev/proj`, `/Users/dev/proj`). On Windows that path is not
    // absolute in the platform's sense, so the safety check rejects it and the
    // test fails for a reason that has nothing to do with what it asserts.
    // They were never gated because the suite had never run on Windows.
    #[cfg(unix)]
    #[test]
    fn linux_reapplies_protected_masks_after_every_writable_bind() {
        let mut input = inputs(&["claude"]);
        input.worktree = Some(Worktree {
            git_dir: PathBuf::from("/home/dev/repos/main/.git/worktrees/safe"),
            common_dir: PathBuf::from("/home/dev/repos/main/.git"),
        });
        let plan = build_linux_jail(&input).unwrap();
        let args = &plan.bwrap_args;
        let last_writable_bind = args
            .windows(3)
            .enumerate()
            .filter(|(_, w)| w[0] == "--bind")
            .map(|(index, _)| index)
            .max()
            .unwrap();

        for protected in [
            "/home/dev/.config/innerwarden",
            "/home/dev/.ssh",
            "/home/dev/.aws",
            "/home/dev/.gnupg",
        ] {
            let final_mask = args
                .windows(2)
                .enumerate()
                .filter(|(_, w)| w[0] == "--tmpfs" && w[1] == protected)
                .map(|(index, _)| index)
                .max()
                .unwrap_or_else(|| panic!("missing final mask for {protected}"));
            assert!(
                final_mask > last_writable_bind,
                "{protected} mask must be applied after writable binds"
            );
        }
    }

    #[test]
    fn jail_rejects_a_worktree_bind_that_overlaps_secrets() {
        let mut input = inputs(&["claude"]);
        input.worktree = Some(Worktree {
            git_dir: PathBuf::from("/home/dev/.ssh/worktree"),
            common_dir: PathBuf::from("/home/dev/.ssh"),
        });
        assert!(build_linux_jail(&input).is_err());
        assert!(build_macos_profile(&input).is_err());
    }

    // POSIX-only: these build a jail plan for a hardcoded POSIX project path
    // (`/home/dev/proj`, `/Users/dev/proj`). On Windows that path is not
    // absolute in the platform's sense, so the safety check rejects it and the
    // test fails for a reason that has nothing to do with what it asserts.
    // They were never gated because the suite had never run on Windows.
    #[cfg(unix)]
    #[test]
    fn linux_masks_secret_file_with_devnull_and_dir_with_tmpfs() {
        // A tmpfs over a FILE aborts bwrap (ENOTDIR); a file must be masked with a
        // /dev/null bind, a directory with a tmpfs.
        let plan = build_linux_jail(&inputs(&["claude"])).unwrap();
        let a = &plan.bwrap_args;
        // .env is a file -> /dev/null bind
        assert!(
            a.windows(3).any(|w| w[0] == "--ro-bind"
                && w[1] == "/dev/null"
                && w[2] == "/home/dev/proj/.env"),
            "a secret FILE must be masked with a /dev/null bind, not a tmpfs"
        );
        assert!(
            !a.windows(2)
                .any(|w| w[0] == "--tmpfs" && w[1] == "/home/dev/proj/.env"),
            "a secret file must NOT be tmpfs'd (bwrap would abort ENOTDIR)"
        );
        // secrets/ is a dir -> tmpfs
        assert!(
            a.windows(2)
                .any(|w| w[0] == "--tmpfs" && w[1] == "/home/dev/proj/secrets"),
            "a secret DIRECTORY must be masked with a tmpfs"
        );
    }

    // POSIX-only: these build a jail plan for a hardcoded POSIX project path
    // (`/home/dev/proj`, `/Users/dev/proj`). On Windows that path is not
    // absolute in the platform's sense, so the safety check rejects it and the
    // test fails for a reason that has nothing to do with what it asserts.
    // They were never gated because the suite had never run on Windows.
    #[cfg(unix)]
    #[test]
    fn macos_denies_the_resolved_project_secrets() {
        let mut i = inputs(&["claude"]);
        i.home = PathBuf::from("/Users/dev");
        i.iw_config_real = PathBuf::from("/Users/dev/.config/innerwarden");
        i.args.project = PathBuf::from("/Users/dev/proj");
        i.deny_paths = vec![DenyPath {
            abs: PathBuf::from("/Users/dev/proj/.env.local"),
            is_dir: false,
        }];
        let p = build_macos_profile(&i).unwrap().profile;
        assert!(p.contains("(deny file-read* (subpath \"/Users/dev/proj/.env.local\"))"));
        assert!(p.contains("(deny file-write* (subpath \"/Users/dev/proj/.env.local\"))"));
    }

    // POSIX-only: these build a jail plan for a hardcoded POSIX project path
    // (`/home/dev/proj`, `/Users/dev/proj`). On Windows that path is not
    // absolute in the platform's sense, so the safety check rejects it and the
    // test fails for a reason that has nothing to do with what it asserts.
    // They were never gated because the suite had never run on Windows.
    #[cfg(unix)]
    #[test]
    fn linux_env_is_secret_safe() {
        let plan = build_linux_jail(&inputs(&["claude"])).unwrap();
        let env: std::collections::HashMap<_, _> = plan.env.into_iter().collect();
        assert_eq!(
            env["IW_GRAPH_FILE"],
            "/home/dev/proj/.innerwarden/graph.json"
        );
        assert_eq!(env["IW_LLM_CONFIG"], "");
        assert_eq!(env["IW_NOTIFY_CONFIG"], "");
    }

    // POSIX-only: these build a jail plan for a hardcoded POSIX project path
    // (`/home/dev/proj`, `/Users/dev/proj`). On Windows that path is not
    // absolute in the platform's sense, so the safety check rejects it and the
    // test fails for a reason that has nothing to do with what it asserts.
    // They were never gated because the suite had never run on Windows.
    #[cfg(unix)]
    #[test]
    fn macos_denies_secret_dir_read_and_write_last() {
        let mut i = inputs(&["claude"]);
        i.home = PathBuf::from("/Users/dev");
        i.args.project = PathBuf::from("/Users/dev/proj");
        i.tmpdir = PathBuf::from("/var/folders/xx/T");
        let plan = build_macos_profile(&i).unwrap();
        let p = &plan.profile;
        assert!(p.starts_with("(version 1)\n(deny default)"));
        // the secret dir is read+write denied
        assert!(p.contains("(deny file-read* (subpath \"/Users/dev/.config/innerwarden\"))"));
        assert!(p.contains("(deny file-write* (subpath \"/Users/dev/.config/innerwarden\"))"));
        // deny of the secret dir comes AFTER the allow-read-all (last-wins)
        let allow_all = p.find("(allow file-read*)").unwrap();
        let deny_secret = p
            .find("(deny file-read* (subpath \"/Users/dev/.config/innerwarden\"))")
            .unwrap();
        assert!(
            deny_secret > allow_all,
            "secret deny must come after allow-read-all"
        );
        // ssh/aws/gnupg denied
        for d in [".ssh", ".aws", ".gnupg"] {
            assert!(p.contains(&format!("(deny file-read* (subpath \"/Users/dev/{d}\"))")));
        }
        // project writable
        assert!(p.contains("(allow file-write* (subpath \"/Users/dev/proj\"))"));
        // argv shape
        assert_eq!(plan.argv[0], "/usr/bin/sandbox-exec");
        assert_eq!(plan.argv[1], "-p");
        assert_eq!(plan.argv[3], "--");
        assert_eq!(plan.argv.last().unwrap(), "claude");
    }

    #[test]
    fn sbpl_escaping_cannot_break_out() {
        // a path with a quote + backslash must not terminate the string
        let evil = "/Users/dev/a\"b\\c";
        let esc = sbpl_escape(evil);
        // every `"` in the output is escaped (immediately preceded by a backslash),
        // so a path can never terminate the SBPL string literal.
        assert_eq!(esc, "/Users/dev/a\\\"b\\\\c");
        let bytes: Vec<char> = esc.chars().collect();
        for (i, c) in bytes.iter().enumerate() {
            if *c == '"' {
                assert!(i > 0 && bytes[i - 1] == '\\', "found an unescaped quote");
            }
        }
        // regex escape neutralizes metachars
        let r = sbpl_regex_escape("a.b*c|d");
        assert_eq!(r, "a\\.b\\*c\\|d");
    }

    #[test]
    fn userns_restriction_is_named_only_when_it_will_bite() {
        use std::path::Path;
        let bwrap = Path::new("/usr/bin/bwrap");
        // The measured stock Ubuntu 24.04 host: restricted, no profile.
        let lines = userns_restriction_advice(Some("1\n"), false, bwrap).expect("advice");
        let text = lines.join("\n");
        assert!(
            text.contains("apparmor_restrict_unprivileged_userns"),
            "{text}"
        );
        assert!(
            text.contains("profile bwrap /usr/bin/bwrap flags=(unconfined)"),
            "{text}"
        );
        assert!(text.contains("userns,"), "{text}");
        assert!(
            text.contains("apparmor_parser -r /etc/apparmor.d/bwrap"),
            "{text}"
        );
        assert!(text.contains("Nothing was run"), "{text}");
        // With the profile on disk the jail builds: say nothing.
        assert!(userns_restriction_advice(Some("1"), true, bwrap).is_none());
        // Sysctl off, or absent (every non-Ubuntu kernel): say nothing.
        assert!(userns_restriction_advice(Some("0"), false, bwrap).is_none());
        assert!(userns_restriction_advice(None, false, bwrap).is_none());
        // The profile names the resolved binary, not a guess.
        let other =
            userns_restriction_advice(Some("1"), false, Path::new("/usr/local/bin/bwrap")).unwrap();
        assert!(other
            .join("\n")
            .contains("profile bwrap /usr/local/bin/bwrap"));
    }

    // ---- `--identity`: argv, flag parse, the pure record parts ----

    #[test]
    fn identity_flag_is_off_unless_asked_for() {
        let off = parse_contain_args(&["--".into(), "x".into()]).unwrap();
        assert!(!off.identity);
        let on = parse_contain_args(&["--identity".into(), "--".into(), "x".into()]).unwrap();
        assert!(on.identity);
        // The flag is not the child's: after `--` it belongs to the child.
        let child = parse_contain_args(&["--".into(), "--identity".into()]).unwrap();
        assert!(!child.identity);
        assert_eq!(child.child, vec!["--identity"]);
    }

    #[test]
    fn info_fd_goes_before_the_terminator_and_moves_nothing_else() {
        let plain = build_linux_jail(&inputs(&["claude", "--print"]))
            .unwrap()
            .bwrap_args;
        let mut with = inputs(&["claude", "--print"]);
        with.info_fd = Some(7);
        let got = build_linux_jail(&with).unwrap().bwrap_args;
        let at = got
            .iter()
            .position(|a| a == "--info-fd")
            .expect("--info-fd");
        assert_eq!(got[at + 1], "7");
        let terminator = got.iter().position(|a| a == "--").expect("--");
        assert!(at + 1 < terminator, "--info-fd must come before `--`");
        // Removing the two tokens gives exactly today's vector.
        let mut without = got.clone();
        without.drain(at..at + 2);
        assert_eq!(without, plain);
        assert_eq!(plain.join("\n"), GOLDEN_ARGV_PLAIN);
    }

    #[test]
    fn info_fd_json_is_read_and_bounded() {
        use launch::*;
        let real =
            br#"{"child-pid": 2778, "mnt-namespace": 4026532218, "pid-namespace": 4026532220}"#;
        assert_eq!(
            parse_info_fd(real).unwrap(),
            InfoFd {
                child_pid: 2778,
                pid_namespace: Some(4026532220),
                mnt_namespace: Some(4026532218),
            }
        );
        // newer bwrap fields are ignored, the namespaces are optional
        let more = br#"{"child-pid": 5, "cgroup-namespace": 1, "future": [1,2]}"#;
        let got = parse_info_fd(more).unwrap();
        assert_eq!(
            (got.child_pid, got.pid_namespace, got.mnt_namespace),
            (5, None, None)
        );
        assert_eq!(parse_info_fd(b""), Err(InfoError::Empty));
        assert_eq!(parse_info_fd(b" \n"), Err(InfoError::Empty));
        assert_eq!(parse_info_fd(b"{}"), Err(InfoError::NoChildPid));
        assert_eq!(
            parse_info_fd(br#"{"child-pid": 0}"#),
            Err(InfoError::NoChildPid)
        );
        assert_eq!(
            parse_info_fd(br#"{"child-pid": 99999999999}"#),
            Err(InfoError::NoChildPid)
        );
        assert!(matches!(
            parse_info_fd(br#"{"child-pid": -3}"#),
            Err(InfoError::Malformed(_))
        ));
        assert!(matches!(
            parse_info_fd(b"not json"),
            Err(InfoError::Malformed(_))
        ));
        let mut big = br#"{"child-pid": 5, "pad": ""#.to_vec();
        big.extend(std::iter::repeat_n(b'a', MAX_INFO_BYTES));
        big.extend(br#""}"#);
        assert_eq!(parse_info_fd(&big), Err(InfoError::TooLarge));
    }

    #[test]
    fn start_ticks_are_counted_from_the_last_parenthesis() {
        use launch::parse_start_ticks;
        // 52 fields as the kernel writes them; field 22 is 123456.
        let tail = "S 1 2778 2778 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 123456 9999 99 18446744073709551615";
        for comm in ["bash", "ba sh", "a) S 1 (b", "(", ")"] {
            let stat = format!("2778 ({comm}) {tail}");
            assert_eq!(parse_start_ticks(&stat), Some(123456), "comm {comm:?}");
        }
        assert_eq!(parse_start_ticks("2778 (bash) S 1 2"), None);
        assert_eq!(parse_start_ticks("no parenthesis"), None);
        assert_eq!(parse_start_ticks(""), None);
    }

    #[test]
    fn pid_namespace_link_is_parsed_strictly() {
        use launch::parse_ns_link;
        assert_eq!(parse_ns_link("pid:[4026532222]"), Some(4026532222));
        assert_eq!(parse_ns_link("pid:[4026532222]\n"), Some(4026532222));
        for bad in [
            "",
            "pid:[]",
            "pid:[12x]",
            "net:[1]",
            "pid:[1",
            "[1]",
            "pid:[-1]",
        ] {
            assert_eq!(parse_ns_link(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn mount_namespace_link_is_parsed_strictly() {
        use launch::parse_mnt_ns_link;
        assert_eq!(parse_mnt_ns_link("mnt:[4026532218]"), Some(4026532218));
        assert_eq!(parse_mnt_ns_link("mnt:[4026532218]\n"), Some(4026532218));
        for bad in [
            "",
            "mnt:[]",
            "mnt:[12x]",
            "pid:[4026532218]",
            "mntx:[1]",
            "mnt:[1",
            "mnt:[-1]",
        ] {
            assert_eq!(parse_mnt_ns_link(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn instance_id_is_thirty_two_lowercase_hex_and_a_valid_name() {
        use launch::*;
        let id = instance_id_from([0xab; 16]);
        assert_eq!(id, "abababababababababababababababab");
        let id = instance_id_from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 255]);
        assert_eq!(id.len(), 32);
        assert!(id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert!(record_path(Path::new("/s"), &id).is_some());
        assert_eq!(record_path(Path::new("/s"), "../x"), None);
        assert_eq!(record_path(Path::new("/s"), "ab"), None, "too short");
        assert_eq!(
            record_path(Path::new("/s"), &id).unwrap(),
            PathBuf::from(format!("/s/{id}.json"))
        );
    }

    /// The project path beside a record is taken only as one plain absolute
    /// path whose folder is the record's project: a relative path, a `..`
    /// step, a control character, another folder's name or an id that is not
    /// an id gives none.
    ///
    /// FAILS ON REVERT: drop the folder name check and a `.project` file
    /// copied from another instance (naming another folder) is taken.
    #[test]
    fn a_project_path_is_one_plain_absolute_path_of_the_records_project() {
        use launch::*;
        let id = instance_id_from([0xab; 16]);
        assert_eq!(project_path_file(&id), Some(format!("{id}.project")));
        assert_eq!(project_path_file("../x"), None);
        assert_eq!(
            parse_project_path(b"/home/dev/my-app\n", "my-app"),
            Some(PathBuf::from("/home/dev/my-app"))
        );
        assert_eq!(
            parse_project_path(b"/home/dev/my-app", "my-app"),
            Some(PathBuf::from("/home/dev/my-app"))
        );
        let long = format!("/{}/my-app", "a".repeat(MAX_PROJECT_PATH_BYTES));
        for bad in [
            &b""[..],
            b"\n",
            b"home/dev/my-app",
            b"/home/dev/other",
            b"/home/dev/../dev/my-app",
            b"/home/./dev/my-app",
            b"/home//dev/my-app",
            b"/",
            b"/home/dev/my-app\n\n",
            b"/home/dev\x1b/my-app",
            b"/home/dev/my-app\r",
            b"\xff/my-app",
            long.as_bytes(),
        ] {
            assert_eq!(
                parse_project_path(bad, "my-app"),
                None,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn records_live_under_the_state_home_and_a_relative_one_is_ignored() {
        use launch::records_dir;
        let home = Path::new("/home/dev");
        assert_eq!(
            records_dir(Some("/var/state"), home),
            PathBuf::from("/var/state/innerwarden/instances")
        );
        let fallback = PathBuf::from("/home/dev/.local/state/innerwarden/instances");
        assert_eq!(records_dir(None, home), fallback);
        assert_eq!(records_dir(Some(""), home), fallback);
        assert_eq!(records_dir(Some("relative/state"), home), fallback);
    }

    fn launch_facts<'a>(
        mode: &'a Mode,
        launcher: &'a Path,
        project: &'a Path,
    ) -> launch::LaunchFacts<'a> {
        launch::LaunchFacts {
            instance_id: launch::instance_id_from([7; 16]),
            agent_type: "claude-code",
            launcher_path: launcher,
            launcher_version: "1.5.5",
            launcher_root_owned: true,
            uid: 1000,
            project,
            mode,
            started_at: "2026-10-16T12:00:00Z".parse().unwrap(),
            info: launch::InfoFd {
                child_pid: 2778,
                pid_namespace: Some(4026532220),
                mnt_namespace: Some(4026532218),
            },
            start_ticks: 123456,
            pid_ns: 4026532220,
            mnt_ns: 4026532218,
            launcher_mnt_ns: Some(4026531841),
            scope: Default::default(),
        }
    }

    #[test]
    fn record_is_assembled_from_delivered_facts_only() {
        use innerwarden_agent_guard::identity::{parse_launch_record, JailBackend, LaunchMode};
        let (mode, launcher, project) = (
            Mode::Enforce,
            Path::new("/usr/local/bin/innerwarden"),
            Path::new("/home/dev/work/my project"),
        );
        let record = launch::assemble_record(launch_facts(&mode, launcher, project)).unwrap();
        assert_eq!(record.project, "my project", "a folder NAME, never a path");
        assert_eq!(record.mode, LaunchMode::Enforce);
        assert_eq!(record.agent_type, "claude-code");
        assert_eq!(record.uid, 1000);
        assert_eq!(record.launcher.path, "/usr/local/bin/innerwarden");
        assert!(record.launcher.root_owned);
        assert_eq!(record.jail.backend, JailBackend::Bwrap);
        assert_eq!(
            (
                record.jail.pid,
                record.jail.start_ticks,
                record.jail.pid_ns,
                record.jail.mnt_ns
            ),
            (2778, 123456, 4026532220, 4026532218)
        );
        assert!(
            record.scope.is_none(),
            "no scope when the kernel showed the jail in none"
        );
        // what is written is what a reader accepts, and it carries no secret
        let json = serde_json::to_vec(&record).unwrap();
        assert_eq!(parse_launch_record(&json).unwrap(), record);
        let text = String::from_utf8(json).unwrap();
        assert!(
            !text.contains("/home/dev"),
            "no path of the project: {text}"
        );
        // the launcher's trust is a fact handed in, not assumed
        let mut per_user = launch_facts(&mode, launcher, project);
        per_user.launcher_root_owned = false;
        assert!(
            !launch::assemble_record(per_user)
                .unwrap()
                .launcher
                .root_owned
        );
    }

    #[test]
    fn no_record_is_made_for_a_jail_without_a_namespace_of_its_own() {
        use innerwarden_agent_guard::identity::INITIAL_PID_NS_INODE;
        use launch::AssembleError;
        let (mode, launcher, project) = (
            Mode::Monitor,
            Path::new("/usr/local/bin/innerwarden"),
            Path::new("/home/dev/proj"),
        );
        // the host's own namespace: a record would claim a boundary that is not there
        let mut host = launch_facts(&mode, launcher, project);
        host.pid_ns = INITIAL_PID_NS_INODE;
        host.info.pid_namespace = None;
        assert_eq!(
            launch::assemble_record(host),
            Err(AssembleError::NoPidNamespace)
        );
        let mut zero = launch_facts(&mode, launcher, project);
        zero.pid_ns = 0;
        zero.info.pid_namespace = None;
        assert_eq!(
            launch::assemble_record(zero),
            Err(AssembleError::NoPidNamespace)
        );
        // bwrap and the host name two different namespaces: trust neither
        let mut split = launch_facts(&mode, launcher, project);
        split.info.pid_namespace = Some(4026532999);
        assert_eq!(
            launch::assemble_record(split),
            Err(AssembleError::NamespaceDisagrees)
        );
        // the jail's mount namespace is the launcher's own, unknown, or not
        // the one bwrap named: no record names a root the launcher did not
        // build
        for (jail, launcher_ns) in [
            (4026531841, Some(4026531841)),
            (0, Some(4026531841)),
            (4026532218, None),
        ] {
            let mut shared = launch_facts(&mode, launcher, project);
            shared.mnt_ns = jail;
            shared.info.mnt_namespace = None;
            shared.launcher_mnt_ns = launcher_ns;
            assert_eq!(
                launch::assemble_record(shared),
                Err(AssembleError::NoMountNamespace),
                "{jail} {launcher_ns:?}"
            );
        }
        let mut split_mnt = launch_facts(&mode, launcher, project);
        split_mnt.info.mnt_namespace = Some(4026532999);
        assert_eq!(
            launch::assemble_record(split_mnt),
            Err(AssembleError::MountNamespaceDisagrees)
        );
        // facts that make an invalid record are refused, not written
        let mut no_time = launch_facts(&mode, launcher, project);
        no_time.start_ticks = 0;
        assert!(matches!(
            launch::assemble_record(no_time),
            Err(AssembleError::Record(_))
        ));
        let root_project = launch_facts(&mode, launcher, Path::new("/"));
        assert_eq!(
            launch::assemble_record(root_project),
            Err(AssembleError::NoProjectName)
        );
        let relative = launch_facts(&mode, Path::new("innerwarden"), project);
        assert!(matches!(
            launch::assemble_record(relative),
            Err(AssembleError::Record(_))
        ));
    }

    // ---- `--identity`: the record mount, the sealed trees, the scope ----

    /// The record, mounted where the hook looks for it.
    fn record_mount(fd: &str) -> Vec<String> {
        vec![
            "--ro-bind-data".into(),
            fd.into(),
            innerwarden_agent_guard::identity::JAIL_RECORD_PATH.into(),
        ]
    }

    /// The options that may follow the record: none of them mounts anything.
    const AFTER_THE_RECORD: &[&str] = &[
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-ipc",
        "--hostname",
        "--new-session",
        "--setenv",
        "--info-fd",
    ];

    /// The record is mounted read-only, after the `/run` tmpfs it lands on,
    /// and LAST of all mounts, so no later option can cover it (bwrap is
    /// last-wins). Removing it and the info descriptor gives today's jail.
    ///
    /// FAILS ON REVERT: mount it with `--bind-data` (writable by the agent),
    /// or before `--tmpfs /run` (which then hides it), or before the project
    /// and the masks (a later mount could cover it).
    #[test]
    fn the_record_is_mounted_read_only_after_the_run_tmpfs_and_last_of_all_mounts() {
        let mut rich = inputs(&["/bin/sh", "-c", "true"]);
        rich.stdin_is_tty = false;
        rich.agent_binary = Some(ResolvedBinary {
            link: PathBuf::from("/home/dev/.local/bin/claude"),
            target_dir: PathBuf::from("/home/dev/.local/share/claude/v1"),
        });
        rich.worktree = Some(Worktree {
            git_dir: PathBuf::from("/home/dev/repo/.git/worktrees/w"),
            common_dir: PathBuf::from("/home/dev/repo/.git"),
        });
        for (mut input, golden) in [
            (inputs(&["claude", "--print"]), GOLDEN_ARGV_PLAIN),
            (rich, GOLDEN_ARGV_RICH),
        ] {
            input.args.identity = true;
            input.info_fd = Some(7);
            input.record_fd = Some(8);
            let got = build_linux_jail(&input).unwrap().bwrap_args;
            let mount = record_mount("8");
            let at = got
                .windows(3)
                .position(|w| w == mount.as_slice())
                .expect("the record is mounted");
            assert!(
                !got.iter().any(|a| a == "--bind-data"),
                "never a writable copy"
            );
            let run_tmpfs = got
                .windows(2)
                .position(|w| w[0] == "--tmpfs" && w[1] == "/run")
                .expect("--tmpfs /run");
            assert!(run_tmpfs < at, "the record lands on the /run tmpfs");
            let terminator = got.iter().position(|a| a == "--").expect("--");
            for option in got[at + 3..terminator]
                .iter()
                .filter(|a| a.starts_with("--"))
            {
                assert!(
                    AFTER_THE_RECORD.contains(&option.as_str()),
                    "{option} comes after the record and may cover it"
                );
            }
            // Without its two additions the jail is exactly today's.
            let mut without = got.clone();
            without.drain(at..at + 3);
            let info = without.iter().position(|a| a == "--info-fd").unwrap();
            without.drain(info..info + 2);
            assert_eq!(without.join("\n"), golden);
        }
    }

    /// An identified jail as the launcher builds it: the records folder, as
    /// named and as resolved, hidden after every writable bind; the command's
    /// own `PATH` and loader variables handed back after the namespaces; the
    /// record last of the mounts.
    fn identified_inputs() -> JailInputs {
        let mut input = inputs(&["claude", "--print"]);
        input.args.identity = true;
        input.existing_paths.push(PathBuf::from("/home/dev/.local"));
        input.info_fd = Some(7);
        input.record_fd = Some(8);
        input.records_dirs = vec![
            PathBuf::from("/home/dev/.local/state/innerwarden/instances"),
            PathBuf::from("/data/dev/state/innerwarden/instances"),
        ];
        input.child_env = vec![
            ("LD_LIBRARY_PATH".into(), "/home/dev/lib".into()),
            ("PATH".into(), "/home/dev/.local/bin:/usr/bin".into()),
        ];
        input
    }

    /// The whole argv of an identified jail, one token per line.
    ///
    /// FAILS ON REVERT: drop the records folder `--tmpfs` (the agent can
    /// rewrite the launcher's records through the `.local` bind), or move it
    /// before the project and dotdir binds, or drop the `--setenv` lines.
    #[test]
    fn golden_argv_of_an_identified_jail() {
        let plan = build_linux_jail(&identified_inputs()).unwrap();
        assert_eq!(plan.bwrap_args.join("\n"), GOLDEN_ARGV_IDENTIFIED);
    }

    /// The records folder is hidden after the last writable bind that could
    /// show it (`.local`, the project), so none of them brings it back, and
    /// before the record, which stays last of the mounts.
    #[test]
    fn the_records_folder_is_hidden_after_every_writable_bind() {
        let got = build_linux_jail(&identified_inputs()).unwrap().bwrap_args;
        let shadow = |dir: &str| {
            got.windows(2)
                .position(|w| w[0] == "--tmpfs" && w[1] == dir)
                .unwrap_or_else(|| panic!("{dir} is hidden"))
        };
        let named = shadow("/home/dev/.local/state/innerwarden/instances");
        let resolved = shadow("/data/dev/state/innerwarden/instances");
        let last_bind = got
            .iter()
            .rposition(|a| a == "--bind")
            .expect("a writable bind");
        assert!(last_bind < named && last_bind < resolved);
        let record = got.iter().position(|a| a == "--ro-bind-data").unwrap();
        assert!(named < record && resolved < record);
    }

    /// Without `--identity` neither the records folder nor the command's
    /// variables reach the argv, whatever the inputs carry.
    #[test]
    fn without_identity_the_records_folder_and_variables_change_nothing() {
        let mut off = identified_inputs();
        off.args.identity = false;
        off.info_fd = None;
        off.record_fd = None;
        off.existing_paths.pop();
        assert_eq!(
            build_linux_jail(&off).unwrap().bwrap_args.join("\n"),
            GOLDEN_ARGV_PLAIN
        );
        assert!(!compute_jail_env(&off)
            .iter()
            .any(|(k, _)| k == "IW_HOOK_AGENT"));
    }

    /// The helpers get no loader variable; the command gets `PATH` and every
    /// loader variable back as it was, and nothing else is moved.
    ///
    /// FAILS ON REVERT: let `launch_env` keep `LD_*` in the helpers.
    #[test]
    fn the_launchers_helpers_lose_the_loader_variables_and_the_command_keeps_them() {
        use std::ffi::OsString;
        let vars = [
            ("PATH", "/home/dev/.local/bin:/usr/bin"),
            ("LD_PRELOAD", "/home/dev/hook.so"),
            ("LD_LIBRARY_PATH", "/home/dev/lib"),
            ("HOME", "/home/dev"),
            ("ANTHROPIC_API_KEY", "secret"),
            ("OLD_LD_PRELOAD", "x"),
        ]
        .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let env = launch_env(vars);
        assert_eq!(
            env.helper_remove,
            [
                OsString::from("LD_LIBRARY_PATH"),
                OsString::from("LD_PRELOAD")
            ]
        );
        assert_eq!(
            env.child_env,
            [
                ("LD_LIBRARY_PATH", "/home/dev/lib"),
                ("LD_PRELOAD", "/home/dev/hook.so"),
                ("PATH", "/home/dev/.local/bin:/usr/bin"),
            ]
            .map(|(k, v)| (k.to_string(), v.to_string()))
        );
        assert_eq!(HELPER_PATH, "/usr/bin:/bin");
        // no PATH and no loader variable: nothing to hand back
        let bare = launch_env([(OsString::from("HOME"), OsString::from("/h"))]);
        assert_eq!(bare, LaunchEnv::default());
    }

    /// With `--identity` a writable bind may not bring the host's `/run` (the
    /// user's manager and bus) or `/sys` (the cgroup files) back into the
    /// jail. Without the flag nothing changes.
    ///
    /// FAILS ON REVERT: drop the check and a project under `/run` opens the
    /// user bus inside an identified jail.
    #[test]
    fn identity_refuses_a_writable_bind_over_run_or_sys_and_nothing_changes_without_it() {
        let identified = |project: &str| {
            let mut input = inputs(&["claude"]);
            input.args.project = PathBuf::from(project);
            input.args.identity = true;
            input
        };
        for unsafe_project in ["/run/user/1000/proj", "/run", "/sys/fs/cgroup/x", "/sys"] {
            let input = identified(unsafe_project);
            assert!(
                matches!(validate_jail_inputs(&input), Err(ContainError::Unsupported(ref m)) if m.contains("--identity")),
                "{unsafe_project}"
            );
            assert!(build_linux_jail(&input).is_err(), "{unsafe_project}");
            // the same project without the flag is what it was before
            let mut plain = input.clone();
            plain.args.identity = false;
            assert!(validate_jail_inputs(&plain).is_ok(), "{unsafe_project}");
        }
        let mut worktree = identified("/home/dev/proj");
        worktree.worktree = Some(Worktree {
            git_dir: PathBuf::from("/run/user/1000/repo/.git/worktrees/w"),
            common_dir: PathBuf::from("/home/dev/repo/.git"),
        });
        assert!(validate_jail_inputs(&worktree).is_err());
        let mut extra = identified("/home/dev/proj");
        extra.args.extra_rw = vec![PathBuf::from("/sys/fs/cgroup")];
        assert!(validate_jail_inputs(&extra).is_err());
        for fine in ["/home/dev/proj", "/tmp/proj", "/srv/run", "/runner/proj"] {
            assert!(validate_jail_inputs(&identified(fine)).is_ok(), "{fine}");
        }
    }

    // -- a jail profile (`contain --identity` with a profiles file) ----------

    fn jail_profile(
        project: Option<&str>,
        extra_ro: &[&str],
        deny_read: &[&str],
    ) -> innerwarden_agent_guard::profiles::JailProfile {
        innerwarden_agent_guard::profiles::JailProfile {
            project_rw: project.map(str::to_string),
            extra_ro: extra_ro.iter().map(|s| s.to_string()).collect(),
            deny_read: deny_read.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn only_a_project_flag_before_the_command_counts_as_given() {
        assert!(jail_flags_given(&argv(&["--project", "/x", "--", "claude"])).project);
        assert!(
            !jail_flags_given(&argv(&["--identity", "--", "claude", "--project", "/x"])).project
        );
        assert!(!jail_flags_given(&argv(&["claude", "--project", "/x"])).project);
        assert!(!jail_flags_given(&argv(&["--deny-read", "--project", "--", "x"])).project);
        assert!(!jail_flags_given(&argv(&["--identity"])).project);
    }

    /// The profile fills what the command line left out; an explicit flag
    /// wins, and hiding more is never undone.
    ///
    /// FAILS ON REVERT: apply `project_rw` even when `--project` was given and
    /// the explicit project is replaced.
    #[test]
    fn a_jail_profile_fills_the_gaps_and_an_explicit_flag_wins() {
        let home = Path::new("/home/dev");
        let profile = jail_profile(
            Some("~/work/app"),
            &["/opt/sdk", "~/tools"],
            &["config/prod.yaml", ".env"],
        );
        let mut defaulted = args(&["claude"]);
        apply_jail_profile(&mut defaulted, &profile, JailFlagsGiven::default(), home);
        assert_eq!(defaulted.project, PathBuf::from("/home/dev/work/app"));
        assert_eq!(
            defaulted.extra_ro,
            [PathBuf::from("/opt/sdk"), PathBuf::from("/home/dev/tools")]
        );
        assert_eq!(
            defaulted.deny_read,
            [".env", ".env.*", "secrets/**", "config/prod.yaml"]
        );
        let mut explicit = args(&["claude"]);
        apply_jail_profile(
            &mut explicit,
            &profile,
            JailFlagsGiven { project: true },
            home,
        );
        assert_eq!(explicit.project, PathBuf::from("/home/dev/proj"));
        // An empty profile changes nothing.
        let mut plain = args(&["claude"]);
        apply_jail_profile(
            &mut plain,
            &jail_profile(None, &[], &[]),
            JailFlagsGiven::default(),
            home,
        );
        assert_eq!(plain, args(&["claude"]));
    }

    /// A read-only path from a profile is bound before the project and before
    /// the protected masks are laid again, so neither can be undone by it.
    #[test]
    fn an_extra_read_only_path_is_bound_before_the_project_and_the_masks() {
        let mut input = inputs(&["claude"]);
        input.args.extra_ro = vec![PathBuf::from("/opt/sdk")];
        let a = build_linux_jail(&input).unwrap().bwrap_args;
        let bind = a
            .windows(3)
            .position(|w| w[0] == "--ro-bind-try" && w[1] == "/opt/sdk" && w[2] == "/opt/sdk")
            .expect("the read-only bind");
        let project = a
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == "/home/dev/proj")
            .unwrap();
        let last_mask = a
            .windows(2)
            .rposition(|w| w[0] == "--tmpfs" && w[1] == "/home/dev/.ssh")
            .unwrap();
        assert!(bind < project && bind < last_mask);
        // Without one there is no such bind (the golden test pins the whole
        // argv of that jail).
        assert!(!build_linux_jail(&inputs(&["claude"]))
            .unwrap()
            .bwrap_args
            .iter()
            .any(|w| w == "--ro-bind-try"));
    }

    /// A read-only bind shows a reader what is there: the home, an ancestor
    /// of it, a protected directory, and (with `--identity`) the host's
    /// `/run` and `/sys` are refused.
    ///
    /// FAILS ON REVERT: drop the `extra_ro` loop from `validate_jail_inputs`
    /// and the home is bound read-only.
    #[test]
    fn an_extra_read_only_path_is_held_to_the_writable_rules() {
        for bad in [
            "/home/dev",
            "/home",
            "/",
            "/home/dev/.ssh",
            "/home/dev/.config",
            "/home/dev/.config/innerwarden/llm-key",
            "relative/path",
        ] {
            let mut input = inputs(&["claude"]);
            input.args.extra_ro = vec![PathBuf::from(bad)];
            assert!(validate_jail_inputs(&input).is_err(), "{bad}");
        }
        for sealed in ["/run/user/1000", "/sys/fs/cgroup"] {
            let mut input = inputs(&["claude"]);
            input.args.identity = true;
            input.args.extra_ro = vec![PathBuf::from(sealed)];
            assert!(validate_jail_inputs(&input).is_err(), "{sealed}");
        }
        let mut fine = inputs(&["claude"]);
        fine.args.identity = true;
        fine.args.extra_ro = vec![PathBuf::from("/opt/sdk"), PathBuf::from("/home/dev/tools")];
        assert!(validate_jail_inputs(&fine).is_ok());
    }

    fn facts(systemd_run: Option<&str>, version: Option<u32>, manager: bool) -> launch::ScopeFacts {
        launch::ScopeFacts {
            systemd_run: systemd_run.map(PathBuf::from),
            systemd_version: version,
            user_manager: manager,
        }
    }

    const UNIT: &str = "innerwarden-contain-0123456789abcdef0123456789abcdef.scope";

    #[test]
    fn the_scope_plan_follows_the_facts() {
        use launch::{plan_scope, NoScope, ScopePlan};
        let run = Some("/usr/bin/systemd-run");
        assert_eq!(
            plan_scope(&facts(None, Some(255), true), UNIT),
            ScopePlan::None(NoScope::NoSystemdRun)
        );
        assert_eq!(
            plan_scope(&facts(run, Some(255), false), UNIT),
            ScopePlan::None(NoScope::NoUserManager)
        );
        assert_eq!(
            plan_scope(&facts(run, None, true), UNIT),
            ScopePlan::None(NoScope::UnknownSystemd)
        );
        for (version, no_expand) in [(252, false), (253, false), (254, true), (255, true)] {
            assert_eq!(
                plan_scope(&facts(run, Some(version), true), UNIT),
                ScopePlan::User {
                    systemd_run: PathBuf::from("/usr/bin/systemd-run"),
                    unit: UNIT.into(),
                    no_expand,
                },
                "systemd {version}"
            );
        }
    }

    /// Without a scope the jail is started as it is today: bwrap, its
    /// arguments, nothing in front. In a scope, systemd-run is in front and
    /// bwrap's arguments, the agent's command among them, reach it as typed.
    ///
    /// FAILS ON REVERT: wrap every launch (flag-off argv changes), or drop
    /// `--expand-environment=no` (then the agent's command line reaches bwrap
    /// as typed only where that systemd's default happens not to expand).
    #[test]
    fn a_scope_puts_systemd_run_in_front_and_changes_nothing_behind_it() {
        use launch::{launch_argv, NoScope, ScopePlan};
        let bwrap = Path::new("/usr/bin/bwrap");
        let args: Vec<String> = ["--unshare-pid", "--", "sh", "-c", "echo $HOME ${USER}"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        for why in [NoScope::NoSystemdRun, NoScope::NoUserManager] {
            assert_eq!(
                launch_argv(bwrap, &args, &ScopePlan::None(why)),
                (bwrap.to_path_buf(), args.clone())
            );
        }
        let scoped = |no_expand| ScopePlan::User {
            systemd_run: PathBuf::from("/usr/bin/systemd-run"),
            unit: UNIT.into(),
            no_expand,
        };
        let (program, got) = launch_argv(bwrap, &args, &scoped(true));
        assert_eq!(program, PathBuf::from("/usr/bin/systemd-run"));
        let mut want: Vec<String> = [
            "--user",
            "--scope",
            "--quiet",
            "--unit",
            UNIT,
            "--expand-environment=no",
            "--",
            "/usr/bin/bwrap",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        want.extend(args.iter().cloned());
        assert_eq!(got, want);
        // An older systemd has no such switch and no expansion to stop.
        let (_, old) = launch_argv(bwrap, &args, &scoped(false));
        assert!(!old.iter().any(|a| a.starts_with("--expand-environment")));
        let behind = old.iter().position(|a| a == "--").unwrap();
        assert_eq!(old[behind + 1], "/usr/bin/bwrap");
        assert_eq!(&old[behind + 2..], args.as_slice());
    }

    #[test]
    fn the_user_manager_socket_and_the_systemd_version_are_read_strictly() {
        use launch::{parse_systemd_version, user_manager_socket};
        assert_eq!(
            user_manager_socket(Some("/run/user/1000")),
            Some(PathBuf::from("/run/user/1000/systemd/private"))
        );
        for no in [None, Some(""), Some("run/user/1000")] {
            assert_eq!(user_manager_socket(no), None, "{no:?}");
        }
        assert_eq!(
            parse_systemd_version("systemd 255 (255.4-1ubuntu8.17)\n+PAM +AUDIT\n"),
            Some(255)
        );
        assert_eq!(
            parse_systemd_version("systemd 252 (252-55.el9_7.8.rocky.0.1)\n"),
            Some(252)
        );
        for bad in [
            "",
            "systemd",
            "systemd x",
            "foo 255",
            " systemd 255",
            "systemd 9999999",
        ] {
            assert_eq!(parse_systemd_version(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_cgroup_is_the_kernels_unified_line_or_systemds_own() {
        use launch::parse_proc_cgroup;
        let user = "/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope";
        assert_eq!(parse_proc_cgroup(&format!("0::{user}\n")).unwrap(), user);
        // hybrid: the unified line wins over the named one
        let hybrid = format!("12:pids:/user.slice\n1:name=systemd:/elsewhere\n0::{user}\n");
        assert_eq!(parse_proc_cgroup(&hybrid).unwrap(), user);
        let legacy = format!("4:memory:/user.slice\n1:name=systemd:{user}\n");
        assert_eq!(parse_proc_cgroup(&legacy).unwrap(), user);
        for bad in [
            "",
            "0::relative/x\n",
            "4:memory:/user.slice\n",
            "0::/a\u{7}b\n",
        ] {
            assert_eq!(parse_proc_cgroup(bad), None, "{bad:?}");
        }
    }

    /// A scope is recorded only when the kernel's word for the jail's cgroup
    /// is THIS instance's unit, under this user's manager (user) or directly
    /// under the system slice (system).
    ///
    /// FAILS ON REVERT: accept any cgroup ending in the unit name and a
    /// user-made `.../system.slice/<unit>` is recorded as a system scope.
    #[test]
    fn a_scope_is_recorded_only_from_the_instances_own_cgroup() {
        use launch::{system_scope_seen, user_scope_seen};
        let user = format!("/user.slice/user-1000.slice/user@1000.service/app.slice/{UNIT}");
        assert_eq!(
            user_scope_seen(&user, UNIT, 1000).unwrap().cgroup_path,
            user
        );
        assert!(user_scope_seen(&user, UNIT, 1001).is_none(), "another user");
        let other = user.replace("0123456789abcdef0123", "ffffffffffffffffffff");
        assert!(
            user_scope_seen(&other, UNIT, 1000).is_none(),
            "another unit"
        );
        let session = format!("/user.slice/user-1000.slice/session-2.scope/{UNIT}");
        assert!(
            user_scope_seen(&session, UNIT, 1000).is_none(),
            "not the manager's"
        );

        let system = format!("/system.slice/{UNIT}");
        assert_eq!(
            system_scope_seen(&system, UNIT).unwrap().cgroup_path,
            system
        );
        for not_root in [
            format!("/user.slice/user-1000.slice/user@1000.service/app.slice/system.slice/{UNIT}"),
            format!("/system.slice/nested.slice/{UNIT}"),
            user.clone(),
            "/system.slice".to_string(),
        ] {
            assert!(system_scope_seen(&not_root, UNIT).is_none(), "{not_root}");
        }
    }

    #[test]
    fn the_record_carries_the_scopes_the_kernel_showed() {
        use innerwarden_agent_guard::identity::{parse_launch_record, Scope, Scopes};
        use launch::{system_scope_seen, user_scope_seen};
        let (mode, launcher, project) = (
            Mode::Monitor,
            Path::new("/usr/local/bin/innerwarden"),
            Path::new("/home/dev/proj"),
        );
        let mut both = launch_facts(&mode, launcher, project);
        let unit = format!("innerwarden-contain-{}.scope", both.instance_id);
        let user = format!("/user.slice/user-1000.slice/user@1000.service/app.slice/{unit}");
        both.scope = Scopes {
            user: user_scope_seen(&user, &unit, 1000),
            system: system_scope_seen(&format!("/system.slice/{unit}"), &unit),
        };
        let record = launch::assemble_record(both).unwrap();
        let scopes = record.scope.clone().expect("scopes recorded");
        assert_eq!(scopes.user.unwrap().cgroup_path, user);
        assert_eq!(
            scopes.system.unwrap().cgroup_path,
            format!("/system.slice/{unit}")
        );
        let json = serde_json::to_vec(&record).unwrap();
        assert_eq!(parse_launch_record(&json).unwrap(), record);

        // A scope that is not this instance's makes no record at all.
        let mut borrowed = launch_facts(&mode, launcher, project);
        borrowed.scope.system = Some(Scope {
            unit: UNIT.into(),
            cgroup_path: format!("/system.slice/{UNIT}"),
        });
        assert!(matches!(
            launch::assemble_record(borrowed),
            Err(launch::AssembleError::Record(_))
        ));
    }

    #[test]
    fn a_launch_without_a_scope_says_identity_is_at_most_observed() {
        use launch::{no_scope_sentence, NoScope};
        assert_eq!(
            no_scope_sentence(NoScope::NoUserManager),
            "innerwarden contain: no scope (no user service manager in this session): identity is at most observed"
        );
        for why in [
            NoScope::NoSystemdRun,
            NoScope::NoUserManager,
            NoScope::UnknownSystemd,
            NoScope::ScopeNotStarted,
            NoScope::NotSeenInScope,
        ] {
            assert!(no_scope_sentence(why).contains(why.why()), "{why:?}");
        }
    }

    // -- after the jail ------------------------------------------------------

    const OURS: &str = "0123456789abcdef0123456789abcdef";
    const OTHER: &str = "fedcba9876543210fedcba9876543210";

    fn command(id: &str, at: Option<u64>, instance: Option<&str>) -> innerwarden_graph::Node {
        let mut attrs = std::collections::BTreeMap::new();
        if let Some(at) = at {
            attrs.insert("recorded_at_ms".to_string(), at.to_string());
        }
        if let Some(instance) = instance {
            attrs.insert("instance_id".to_string(), instance.to_string());
        }
        innerwarden_graph::Node {
            id: id.to_string(),
            kind: "command".to_string(),
            label: "ls".to_string(),
            attrs,
        }
    }

    fn ran(from: &str, to: &str) -> innerwarden_graph::Edge {
        innerwarden_graph::Edge {
            from: from.to_string(),
            to: to.to_string(),
            kind: "ran".to_string(),
        }
    }

    /// A jail graph of runs in the window 1000..=9000 and around it.
    fn jail_graph() -> innerwarden_graph::Graph {
        let mut labelled_elsewhere = command("cmd:x:1", Some(6_000), Some(OURS));
        labelled_elsewhere.kind = "category".to_string();
        innerwarden_graph::Graph {
            nodes: vec![
                // counts: the jail's session ran it inside the window
                command("cmd:contain:1", Some(5_000), None),
                // counts: labelled with this instance, whatever the session
                command("cmd:labelled:1", Some(7_000), Some(OURS)),
                // the edges of the window count too
                command("cmd:contain:2", Some(1_000), None),
                command("cmd:contain:3", Some(9_000), None),
                // does not count: before and after the window
                command("cmd:contain:4", Some(999), None),
                command("cmd:contain:5", Some(9_001), None),
                // does not count: no time
                command("cmd:contain:6", None, None),
                // does not count: labelled with another instance
                command("cmd:contain:7", Some(5_000), Some(OTHER)),
                // does not count: another session ran it, no label
                command("cmd:local:1", Some(5_000), None),
                // does not count: not a command
                labelled_elsewhere,
            ],
            edges: vec![
                ran("session:contain", "cmd:contain:1"),
                ran("session:contain", "cmd:contain:2"),
                ran("session:contain", "cmd:contain:3"),
                ran("session:contain", "cmd:contain:4"),
                ran("session:contain", "cmd:contain:5"),
                ran("session:contain", "cmd:contain:6"),
                ran("session:contain", "cmd:contain:7"),
                ran("session:local", "cmd:local:1"),
                ran("session:x", "cmd:labelled:1"),
            ],
        }
    }

    /// Only this instance's commands, inside its window, count.
    ///
    /// FAILS ON REVERT: drop the window and the commands of earlier runs in
    /// the same project count; take any label for the session's own and
    /// another instance's commands count.
    #[test]
    fn a_contained_run_counts_only_this_instance_inside_its_window() {
        use launch::count_contained_run;
        assert_eq!(
            count_contained_run(&jail_graph(), OURS, 1_000, 9_000),
            (4, Some(9_000))
        );
        assert_eq!(
            count_contained_run(&jail_graph(), OURS, 4_000, 6_000),
            (1, Some(5_000))
        );
        assert_eq!(
            count_contained_run(&jail_graph(), OTHER, 4_000, 6_000),
            (2, Some(5_000)),
            "the other instance's own label, and the session's unlabelled command"
        );
        assert_eq!(
            count_contained_run(&innerwarden_graph::Graph::default(), OURS, 0, u64::MAX),
            (0, None)
        );
        assert_eq!(JAIL_SESSION, "contain");
    }

    /// Without `--identity` the jail's graph is never read and nothing is
    /// reported; with it, it is read once.
    ///
    /// FAILS ON REVERT: drop the flag check and a jail launched without the
    /// flag reads the project graph and builds a report.
    #[test]
    fn without_identity_the_jails_graph_is_not_read_and_nothing_is_reported() {
        use launch::{contained_run_report_for, JailGraph};
        let reads = std::cell::Cell::new(0);
        let read = || {
            reads.set(reads.get() + 1);
            JailGraph::Read(jail_graph())
        };
        let off = args(&["claude"]);
        assert!(!off.identity);
        assert_eq!(
            contained_run_report_for(&off, OURS, 1_000, 9_000, read),
            None
        );
        assert_eq!(reads.get(), 0, "the graph was read without --identity");

        let on = ContainArgs {
            identity: true,
            ..args(&["claude"])
        };
        let body = contained_run_report_for(&on, OURS, 1_000, 9_000, || {
            reads.set(reads.get() + 1);
            JailGraph::Read(jail_graph())
        })
        .expect("a report");
        assert_eq!(reads.get(), 1);
        assert_eq!(body["commands"], 4);
        assert_eq!(body["last_ms"], 9_000);
        assert_eq!(body["trust"], "declared");
        assert_eq!(body["graph"], "read");
    }

    /// A graph that is not there or not readable is said, with no count.
    #[test]
    fn a_jail_graph_that_was_not_read_reports_no_count() {
        use launch::{contained_run_report_for, JailGraph};
        let on = ContainArgs {
            identity: true,
            ..args(&["claude"])
        };
        for (read, state) in [
            (JailGraph::Absent, "absent"),
            (JailGraph::Unreadable("graph_malformed"), "unreadable"),
        ] {
            let body = contained_run_report_for(&on, OURS, 1_000, 9_000, || read).unwrap();
            assert_eq!(body["graph"], state);
            assert_eq!(body["commands"], 0);
            assert_eq!(body["last_ms"], serde_json::Value::Null);
            assert_eq!(body["trust"], "declared");
        }
    }

    const HOST_DECISION: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn sha_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// A command of this instance the hook recorded with the host's labels.
    fn host_labelled(
        id: &str,
        at: u64,
        recommendation: &str,
        layer: &str,
    ) -> innerwarden_graph::Node {
        let mut node = command(id, Some(at), Some(OURS));
        for (key, value) in [
            ("trust_source", "host"),
            ("host_decision", HOST_DECISION),
            ("recommendation", recommendation),
            ("deciding_layer", layer),
        ] {
            node.attrs.insert(key.to_string(), value.to_string());
        }
        node
    }

    /// A profile's deny decides at the type layer too, and claims no
    /// allowance; neither does a general decision, an allow without the
    /// host's labels, another instance's, or one outside the window.
    ///
    /// FAILS ON REVERT: count every node with a host decision and the deny
    /// is claimed as an allowance.
    #[test]
    fn a_profile_deny_in_the_jail_is_not_an_allowance_claim() {
        use launch::host_allowances_in;
        let mut graph = jail_graph();
        graph
            .nodes
            .push(host_labelled("cmd:h:1", 5_000, "allow", "agent_type"));
        graph
            .nodes
            .push(host_labelled("cmd:h:2", 5_100, "allow", "instance"));
        graph
            .nodes
            .push(host_labelled("cmd:h:3", 5_200, "deny", "agent_type"));
        graph
            .nodes
            .push(host_labelled("cmd:h:4", 5_300, "review", "general"));
        graph
            .nodes
            .push(host_labelled("cmd:h:5", 9_500, "allow", "agent_type"));
        let mut other = host_labelled("cmd:h:6", 5_400, "allow", "agent_type");
        other.attrs.insert("instance_id".into(), OTHER.into());
        graph.nodes.push(other);
        let mut no_source = host_labelled("cmd:h:7", 5_500, "allow", "agent_type");
        no_source.attrs.remove("trust_source");
        graph.nodes.push(no_source);
        let (count, claims) = host_allowances_in(&graph, OURS, 1_000, 9_000);
        assert_eq!(count, 2);
        assert_eq!(
            claims.len(),
            1,
            "the two allowances name one decision for one text"
        );
        assert_eq!(claims[0].decision_id, HOST_DECISION);
        // Every node of the fixture holds the text `ls`.
        assert_eq!(
            claims[0].command_sha256,
            sha_hex(b"ls"),
            "the hash of the text the node holds"
        );
        let on = ContainArgs {
            identity: true,
            ..args(&["claude"])
        };
        let body = launch::contained_run_report_for(&on, OURS, 1_000, 9_000, || {
            launch::JailGraph::Read(graph.clone())
        })
        .expect("a report");
        assert_eq!(body["host_allowances"], 2);
        assert_eq!(body["host_decisions"][0]["decision_id"], HOST_DECISION);
    }

    /// A jail graph without host labels reports the body it always did.
    #[test]
    fn a_jail_graph_without_host_labels_reports_no_host_keys() {
        let on = ContainArgs {
            identity: true,
            ..args(&["claude"])
        };
        let body = launch::contained_run_report_for(&on, OURS, 1_000, 9_000, || {
            launch::JailGraph::Read(jail_graph())
        })
        .unwrap();
        assert!(body.get("host_allowances").is_none(), "{body}");
        assert!(body.get("host_decisions").is_none(), "{body}");
    }

    fn entry(symlink: bool, dir: bool, regular: bool, uid: u32, len: u64) -> launch::GraphEntry {
        launch::GraphEntry {
            symlink,
            dir,
            regular,
            uid,
            len,
        }
    }

    /// The graph folder and file must be the launching user's, real, and
    /// bounded: each case is a good one with one fact changed.
    ///
    /// FAILS ON REVERT: drop a check and its case is read.
    #[test]
    fn the_jail_graph_folder_and_file_are_vetted() {
        use launch::{vet_jail_graph_dir, vet_jail_graph_file, MAX_JAIL_GRAPH_BYTES};
        assert_eq!(
            vet_jail_graph_dir(&entry(false, true, false, 1000, 0), 1000),
            Ok(())
        );
        for (dir, why) in [
            (entry(true, false, false, 1000, 0), "graph_dir_is_a_symlink"),
            (
                entry(false, false, true, 1000, 0),
                "graph_dir_not_a_directory",
            ),
            (entry(false, true, false, 0, 0), "graph_dir_not_owned"),
        ] {
            assert_eq!(vet_jail_graph_dir(&dir, 1000), Err(why));
        }
        let good = entry(false, false, true, 1000, MAX_JAIL_GRAPH_BYTES);
        assert_eq!(vet_jail_graph_file(&good, 1000), Ok(()));
        for (file, why) in [
            (
                entry(true, false, false, 1000, 10),
                "graph_not_a_regular_file",
            ),
            (
                entry(false, true, false, 1000, 10),
                "graph_not_a_regular_file",
            ),
            (entry(false, false, true, 1001, 10), "graph_not_owned"),
            (
                entry(false, false, true, 1000, MAX_JAIL_GRAPH_BYTES + 1),
                "graph_too_large",
            ),
        ] {
            assert_eq!(vet_jail_graph_file(&file, 1000), Err(why));
        }
    }

    /// What is not a graph is refused, never read as an empty one.
    #[test]
    fn a_jail_graph_is_parsed_or_refused() {
        use launch::{parse_jail_graph, JailGraph};
        assert_eq!(
            parse_jail_graph(b"  \n"),
            JailGraph::Read(innerwarden_graph::Graph::default())
        );
        let json = jail_graph().to_json();
        assert_eq!(
            parse_jail_graph(json.as_bytes()),
            JailGraph::Read(jail_graph())
        );
        for bad in [&b"not json"[..], b"[1,2]", b"\xff\xfe{}"] {
            assert_eq!(
                parse_jail_graph(bad),
                JailGraph::Unreadable("graph_malformed"),
                "{bad:?}"
            );
        }
    }

    /// The identity flag adds one variable to the jail, the agent the jail was
    /// started for, so the hook can hold the record's type to it; without the
    /// flag the environment is exactly today's.
    ///
    /// FAILS ON REVERT: drop the `HOOK_AGENT_ENV` push from
    /// `compute_jail_env` and the identified environment has no agent.
    #[test]
    fn identity_adds_only_the_agent_to_the_jails_environment() {
        let plain = build_linux_jail(&inputs(&["claude"])).unwrap().env;
        let mut identified = inputs(&["claude"]);
        identified.args.identity = true;
        let mut expected = plain.clone();
        expected.push(("IW_HOOK_AGENT".to_string(), "claude-code".to_string()));
        assert_eq!(build_linux_jail(&identified).unwrap().env, expected);
        assert_eq!(compute_jail_env(&identified), expected, "macOS too");
        assert_eq!(
            plain,
            [
                ("IW_GRAPH_FILE", "/home/dev/proj/.innerwarden/graph.json"),
                ("IW_LLM_CONFIG", ""),
                ("IW_NOTIFY_CONFIG", ""),
                ("IW_GUARD_SESSION", "contain"),
            ]
            .map(|(k, v)| (k.to_string(), v.to_string()))
        );
    }

    const GOLDEN_ARGV_IDENTIFIED: &str = "\
        --ro-bind\n\
        /usr\n\
        /usr\n\
        --ro-bind\n\
        /etc\n\
        /etc\n\
        --ro-bind\n\
        /sys\n\
        /sys\n\
        --symlink\n\
        usr/bin\n\
        /bin\n\
        --symlink\n\
        usr/lib\n\
        /lib\n\
        --symlink\n\
        usr/lib64\n\
        /lib64\n\
        --symlink\n\
        usr/sbin\n\
        /sbin\n\
        --dev\n\
        /dev\n\
        --proc\n\
        /proc\n\
        --tmpfs\n\
        /tmp\n\
        --tmpfs\n\
        /run\n\
        --tmpfs\n\
        /home/dev\n\
        --bind\n\
        /home/dev/.claude\n\
        /home/dev/.claude\n\
        --bind\n\
        /home/dev/.config\n\
        /home/dev/.config\n\
        --bind\n\
        /home/dev/.cache\n\
        /home/dev/.cache\n\
        --bind\n\
        /home/dev/.local\n\
        /home/dev/.local\n\
        --tmpfs\n\
        /home/dev/.config/innerwarden\n\
        --ro-bind\n\
        /home/dev/.gitconfig\n\
        /home/dev/.gitconfig\n\
        --ro-bind\n\
        /home/dev/.local/bin/innerwarden\n\
        /home/dev/.local/bin/innerwarden\n\
        --bind\n\
        /home/dev/proj\n\
        /home/dev/proj\n\
        --chdir\n\
        /home/dev/proj\n\
        --tmpfs\n\
        /home/dev/.aws\n\
        --tmpfs\n\
        /home/dev/.config/innerwarden\n\
        --tmpfs\n\
        /home/dev/.gnupg\n\
        --tmpfs\n\
        /home/dev/.mozilla\n\
        --tmpfs\n\
        /home/dev/.ssh\n\
        --tmpfs\n\
        /home/dev/.thunderbird\n\
        --tmpfs\n\
        /home/dev/Library/Mail\n\
        --tmpfs\n\
        /home/dev/Library/Messages\n\
        --tmpfs\n\
        /home/dev/Library/Safari\n\
        --tmpfs\n\
        /home/dev/.local/state/innerwarden/instances\n\
        --tmpfs\n\
        /data/dev/state/innerwarden/instances\n\
        --ro-bind\n\
        /dev/null\n\
        /home/dev/proj/.env\n\
        --tmpfs\n\
        /home/dev/proj/secrets\n\
        --ro-bind-data\n\
        8\n\
        /run/innerwarden/instance.json\n\
        --die-with-parent\n\
        --unshare-pid\n\
        --unshare-uts\n\
        --unshare-ipc\n\
        --hostname\n\
        ai-sandbox\n\
        --setenv\n\
        LD_LIBRARY_PATH\n\
        /home/dev/lib\n\
        --setenv\n\
        PATH\n\
        /home/dev/.local/bin:/usr/bin\n\
        --info-fd\n\
        7\n\
        --\n\
        claude\n\
        --print";

    const GOLDEN_ARGV_PLAIN: &str = "\
        --ro-bind\n\
        /usr\n\
        /usr\n\
        --ro-bind\n\
        /etc\n\
        /etc\n\
        --ro-bind\n\
        /sys\n\
        /sys\n\
        --symlink\n\
        usr/bin\n\
        /bin\n\
        --symlink\n\
        usr/lib\n\
        /lib\n\
        --symlink\n\
        usr/lib64\n\
        /lib64\n\
        --symlink\n\
        usr/sbin\n\
        /sbin\n\
        --dev\n\
        /dev\n\
        --proc\n\
        /proc\n\
        --tmpfs\n\
        /tmp\n\
        --tmpfs\n\
        /run\n\
        --tmpfs\n\
        /home/dev\n\
        --bind\n\
        /home/dev/.claude\n\
        /home/dev/.claude\n\
        --bind\n\
        /home/dev/.config\n\
        /home/dev/.config\n\
        --bind\n\
        /home/dev/.cache\n\
        /home/dev/.cache\n\
        --tmpfs\n\
        /home/dev/.config/innerwarden\n\
        --ro-bind\n\
        /home/dev/.gitconfig\n\
        /home/dev/.gitconfig\n\
        --ro-bind\n\
        /home/dev/.local/bin/innerwarden\n\
        /home/dev/.local/bin/innerwarden\n\
        --bind\n\
        /home/dev/proj\n\
        /home/dev/proj\n\
        --chdir\n\
        /home/dev/proj\n\
        --tmpfs\n\
        /home/dev/.aws\n\
        --tmpfs\n\
        /home/dev/.config/innerwarden\n\
        --tmpfs\n\
        /home/dev/.gnupg\n\
        --tmpfs\n\
        /home/dev/.mozilla\n\
        --tmpfs\n\
        /home/dev/.ssh\n\
        --tmpfs\n\
        /home/dev/.thunderbird\n\
        --tmpfs\n\
        /home/dev/Library/Mail\n\
        --tmpfs\n\
        /home/dev/Library/Messages\n\
        --tmpfs\n\
        /home/dev/Library/Safari\n\
        --ro-bind\n\
        /dev/null\n\
        /home/dev/proj/.env\n\
        --tmpfs\n\
        /home/dev/proj/secrets\n\
        --die-with-parent\n\
        --unshare-pid\n\
        --unshare-uts\n\
        --unshare-ipc\n\
        --hostname\n\
        ai-sandbox\n\
        --\n\
        claude\n\
        --print";
    const GOLDEN_ARGV_RICH: &str = "\
        --ro-bind\n\
        /usr\n\
        /usr\n\
        --ro-bind\n\
        /etc\n\
        /etc\n\
        --ro-bind\n\
        /sys\n\
        /sys\n\
        --symlink\n\
        usr/bin\n\
        /bin\n\
        --symlink\n\
        usr/lib\n\
        /lib\n\
        --symlink\n\
        usr/lib64\n\
        /lib64\n\
        --symlink\n\
        usr/sbin\n\
        /sbin\n\
        --dev\n\
        /dev\n\
        --proc\n\
        /proc\n\
        --tmpfs\n\
        /tmp\n\
        --tmpfs\n\
        /run\n\
        --tmpfs\n\
        /home/dev\n\
        --bind\n\
        /home/dev/.claude\n\
        /home/dev/.claude\n\
        --bind\n\
        /home/dev/.config\n\
        /home/dev/.config\n\
        --bind\n\
        /home/dev/.cache\n\
        /home/dev/.cache\n\
        --tmpfs\n\
        /home/dev/.config/innerwarden\n\
        --ro-bind\n\
        /home/dev/.gitconfig\n\
        /home/dev/.gitconfig\n\
        --ro-bind\n\
        /home/dev/.local/bin/claude\n\
        /home/dev/.local/bin/claude\n\
        --ro-bind\n\
        /home/dev/.local/share/claude/v1\n\
        /home/dev/.local/share/claude/v1\n\
        --ro-bind\n\
        /home/dev/.local/bin/innerwarden\n\
        /home/dev/.local/bin/innerwarden\n\
        --bind\n\
        /home/dev/proj\n\
        /home/dev/proj\n\
        --chdir\n\
        /home/dev/proj\n\
        --bind\n\
        /home/dev/repo/.git/worktrees/w\n\
        /home/dev/repo/.git/worktrees/w\n\
        --bind\n\
        /home/dev/repo/.git\n\
        /home/dev/repo/.git\n\
        --tmpfs\n\
        /home/dev/.aws\n\
        --tmpfs\n\
        /home/dev/.config/innerwarden\n\
        --tmpfs\n\
        /home/dev/.gnupg\n\
        --tmpfs\n\
        /home/dev/.mozilla\n\
        --tmpfs\n\
        /home/dev/.ssh\n\
        --tmpfs\n\
        /home/dev/.thunderbird\n\
        --tmpfs\n\
        /home/dev/Library/Mail\n\
        --tmpfs\n\
        /home/dev/Library/Messages\n\
        --tmpfs\n\
        /home/dev/Library/Safari\n\
        --ro-bind\n\
        /dev/null\n\
        /home/dev/proj/.env\n\
        --tmpfs\n\
        /home/dev/proj/secrets\n\
        --die-with-parent\n\
        --unshare-pid\n\
        --unshare-uts\n\
        --unshare-ipc\n\
        --hostname\n\
        ai-sandbox\n\
        --new-session\n\
        --\n\
        /bin/sh\n\
        -c\n\
        true";
}
