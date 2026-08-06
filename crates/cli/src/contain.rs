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
        }
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
}
