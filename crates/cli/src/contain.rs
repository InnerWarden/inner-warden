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
        self.args.project.join(".innerwarden/graph.json")
    }
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
/// namespaces → child. `DOTDIR_DENY` entries are never emitted, so they vanish
/// under the HOME tmpfs.
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

    // --- namespaces / lifecycle ---
    push(&["--die-with-parent"]);
    push(&["--unshare-pid", "--unshare-uts", "--unshare-ipc"]);
    push(&["--hostname", "ai-sandbox"]);
    if !input.stdin_is_tty {
        push(&["--new-session"]);
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
pub fn compute_jail_env(input: &JailInputs) -> Vec<(String, String)> {
    vec![
        (
            "IW_GRAPH_FILE".to_string(),
            input.jail_graph_file().to_string_lossy().to_string(),
        ),
        ("IW_LLM_CONFIG".to_string(), String::new()),
        ("IW_NOTIFY_CONFIG".to_string(), String::new()),
        ("IW_GUARD_SESSION".to_string(), "contain".to_string()),
    ]
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
        instance_record_file, Jail, JailBackend, LaunchMode, LaunchRecord, Launcher, RecordError,
        INITIAL_PID_NS_INODE, LAUNCHER_RECORD_DIR, LAUNCH_SCHEMA,
    };
    use serde::Deserialize;

    use super::Mode;

    /// The most bytes read from the info descriptor. bwrap writes one short
    /// JSON object; anything near this is not that.
    pub const MAX_INFO_BYTES: usize = 4096;

    /// The descriptor number a dry run shows. A real run uses the pipe's own.
    pub const DRY_RUN_INFO_FD: i32 = 9;

    /// What bwrap reports through `--info-fd`. Fields it adds later are ignored.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct InfoFd {
        /// The jail's first process, as a pid in the launcher's namespace.
        pub child_pid: u32,
        /// bwrap's own word for the jail's PID namespace inode, if it gave one.
        pub pid_namespace: Option<u64>,
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
        let rest = link.trim().strip_prefix("pid:[")?.strip_suffix(']')?;
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
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AssembleError {
        /// The jail process shares the launcher's own PID namespace, so there
        /// is no boundary to record.
        NoPidNamespace,
        /// bwrap and the host disagree about the jail's namespace.
        NamespaceDisagrees,
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
            },
            scope: None,
        };
        record.validate().map_err(AssembleError::Record)?;
        Ok(record)
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
                pid_namespace: Some(4026532220)
            }
        );
        // newer bwrap fields are ignored, the namespace is optional
        let more = br#"{"child-pid": 5, "cgroup-namespace": 1, "future": [1,2]}"#;
        let got = parse_info_fd(more).unwrap();
        assert_eq!((got.child_pid, got.pid_namespace), (5, None));
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
        assert_eq!(
            record_path(Path::new("/s"), "ab").unwrap(),
            PathBuf::from("/s/ab.json")
        );
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
            },
            start_ticks: 123456,
            pid_ns: 4026532220,
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
            (record.jail.pid, record.jail.start_ticks, record.jail.pid_ns),
            (2778, 123456, 4026532220)
        );
        assert!(
            record.scope.is_none(),
            "no scope until the launcher makes one"
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
