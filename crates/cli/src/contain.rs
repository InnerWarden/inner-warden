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
//!   * On Linux every jail starts its programs under a seccomp filter
//!     (`innerwarden_agent_guard::seccomp`) where the host takes it: no
//!     `TIOCSTI` or `TIOCLINUX` into a terminal, no new btrfs or bcachefs
//!     subvolume or snapshot (one would copy the files the jail hides; one
//!     made before the jail started, in a folder it shows, still holds them),
//!     and with `--identity` no new user namespace and no joining one. A host
//!     that does not take it is told by a throwaway jail first, and the jail
//!     then runs without it and says what it runs without.
//!   * An identified jail drops every capability (`--cap-drop ALL`): a
//!     launcher run as root would otherwise hand its programs root's
//!     capabilities in the host's user namespace.

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
    /// When an identified jail starts its command: a jail profile's `start`
    /// ([`apply_jail_profile`]); [`JailStart::Always`] without one.
    ///
    /// [`JailStart::Always`]: innerwarden_agent_guard::profiles::JailStart::Always
    pub start: innerwarden_agent_guard::profiles::JailStart,
    /// Paths under the home a jail profile hides (`hide_home`), joined to the
    /// home. Empty without one.
    pub hide_home: Vec<PathBuf>,
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
        start: innerwarden_agent_guard::profiles::JailStart::Always,
        hide_home: Vec::new(),
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
/// to any `--deny-read` (hiding more is never undone by a flag); its hidden
/// home paths are joined to `home`; and it says when the jail starts. A `~/`
/// path is under `home`. The I/O layer resolves links in the read-only paths
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
    for path in &jail.hide_home {
        let path = home.join(path);
        if !args.hide_home.contains(&path) {
            args.hide_home.push(path);
        }
    }
    args.start = args.start.max(jail.start());
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

/// A home path a jail profile hides ([`ContainArgs::hide_home`]), as the
/// launcher found it on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenHomePath {
    /// The path as the profile names it, joined to the home.
    pub nominal: PathBuf,
    /// Where it leads with every link followed, when something is there.
    pub real: Option<PathBuf>,
    /// Where it leads with every link on the way that exists followed, the
    /// rest as written: `real` when something is there, and otherwise the
    /// place a later file would be made.
    pub resolved: PathBuf,
    /// What is there is a folder.
    pub is_dir: bool,
    /// A link on the way leads to nothing: where a file made through it
    /// would land is not known before it is made.
    pub dangling_link: bool,
    /// Linux: the first link on the way that sits in a folder the jail
    /// writes ([`steering_link`]), such as `~/.cache/git` a link to
    /// `~/.local/git` for `.cache/git/credential`. A mount covers where the
    /// path leads, never the link, so a program in the jail could replace
    /// the link with a folder of its own, and the host's programs would
    /// then read and write that folder at the path's name. Never set on
    /// macOS, where the sandbox keeps that link in place ([`macos_pins`]).
    pub steered_by: Option<PathBuf>,
}

/// What the jail hides of the home ([`plan_hidden_home`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HiddenPlan {
    /// Linux: each path as the jail sees it, covered by an empty mount.
    pub masks: Vec<DenyPath>,
    /// macOS: each path the sandbox denies, as named and as it resolves
    /// (the sandbox matches the resolved path).
    pub denies: Vec<PathBuf>,
}

/// PURE. Plan the home paths a jail profile hides.
///
/// A link anywhere on the way is followed: what is hidden is the place the
/// path leads to (`real`), never a link, so bwrap never mounts on a link
/// and the sandbox denies the path it matches. On Linux it is covered where
/// the jail shows it: `shown` lists each host folder the jail shows, as the
/// jail sees it and as its host path resolves, and a place none of them
/// shows is not in the jail at all (the jail's home is empty), so nothing
/// is laid there. On macOS both the path as named and where it leads are
/// denied, and a path that is not there yet is denied too.
///
/// A path that leads outside the home is refused: a link the agent planted
/// in a folder it can write would otherwise move the mask onto anything the
/// jail shows (`/etc/innerwarden`). A home folder the jail binds read-write
/// is taken where it leads, as the jail binds it: below `~/.cache` linked to
/// `/data/cache`, the jail's home is `/data/cache`, and only a link below it
/// that leaves it is refused (the agent cannot replace the folder itself,
/// a mount point in the jail). What a path leads to that the jail needs
/// (the project, the guard, the agent's own settings) is refused by
/// [`validate_jail_inputs`]. A path whose way goes through a link a program
/// in the jail can replace (`steered_by`, Linux) is refused too
/// ([`hidden_home_link_refused`]).
pub fn plan_hidden_home(
    paths: &[HiddenHomePath],
    home: &Path,
    shown: &[(PathBuf, PathBuf)],
) -> Result<HiddenPlan, ContainError> {
    let mut plan = HiddenPlan::default();
    let deny = |path: &Path, plan: &mut HiddenPlan| {
        if !plan.denies.iter().any(|seen| seen == path) {
            plan.denies.push(path.to_path_buf());
        }
    };
    for path in paths {
        if path.dangling_link {
            return Err(ContainError::Unsupported(format!(
                "the hidden home path '{}' goes through a link that leads to nothing: \
                 remove the link, or name the path it should lead to in hide_home",
                printable(&path.nominal)
            )));
        }
        if let Some(link) = &path.steered_by {
            return Err(hidden_home_link_refused(&path.nominal, link));
        }
        let leads_to = path.real.as_ref().unwrap_or(&path.resolved);
        let in_its_folder = writable_folder_target(&path.nominal, home, shown)
            .is_some_and(|folder| leads_to.starts_with(folder));
        if !leads_to.starts_with(home) && !in_its_folder {
            return Err(ContainError::Unsupported(format!(
                "the hidden home path '{}' leads to '{}', outside the home: name a path \
                 inside the home in hide_home, or remove the link",
                printable(&path.nominal),
                printable(leads_to)
            )));
        }
        deny(&path.nominal, &mut plan);
        deny(leads_to, &mut plan);
        let Some(real) = &path.real else {
            continue;
        };
        for abs in jail_views(real, shown) {
            if !plan.masks.iter().any(|seen| seen.abs == abs) {
                plan.masks.push(DenyPath {
                    abs,
                    is_dir: path.is_dir,
                });
            }
        }
    }
    Ok(plan)
}

/// PURE. Every place the jail shows the host place `real` (`shown`,
/// [`shown_host_folders`]), each once, in the order of `shown`. One host
/// folder can be shown at two places (`~/.claude` a link to
/// `~/.config/claude`, which the `.config` bind shows too), and a mount laid
/// at one of them is not seen at the other, so whatever covers `real`
/// covers each.
fn jail_views(real: &Path, shown: &[(PathBuf, PathBuf)]) -> Vec<PathBuf> {
    let mut views: Vec<PathBuf> = Vec::new();
    for (jail, host) in shown {
        let Ok(rest) = real.strip_prefix(host) else {
            continue;
        };
        let view = jail.join(rest);
        if !views.contains(&view) {
            views.push(view);
        }
    }
    views
}

/// PURE. The places a Linux jail shows the host folder `real` besides those
/// already covered (`covered`: the folder as named and as it resolves), each
/// once ([`jail_views`]). `~/.cache` a link to `/data/cache` and `~/.config`
/// a link to `~/.cache/cfg`: InnerWarden's folder resolves to
/// `/data/cache/cfg/innerwarden`, which nothing in the jail shows at that
/// place, while the `.cache` bind shows it at `~/.cache/cfg/innerwarden`.
/// Empty in every layout where each place is one already covered, so such
/// a jail is the one it was.
pub fn other_jail_views(
    real: &Path,
    covered: &[PathBuf],
    shown: &[(PathBuf, PathBuf)],
) -> Vec<PathBuf> {
    jail_views(real, shown)
        .into_iter()
        .filter(|view| !covered.contains(view))
        .collect()
}

/// PURE. Where an identified jail covers Claude Code's folders of its runs
/// ([`CLAUDE_RUN_FOLDERS`]): `real` holds each such folder of the host's as
/// its path resolves, and each is covered at every place the jail shows it
/// ([`jail_views`]), the project or a read-only path of the profile that
/// shows `~/.claude` too. A place that holds something the jail shows later
/// (`needed`: the project, the worktree's folders, the read-only paths, the
/// guard) is not covered, or that would be empty in the jail, and the second
/// value says one was not.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn plan_claude_folders(
    real: &[PathBuf],
    shown: &[(PathBuf, PathBuf)],
    needed: &[PathBuf],
) -> (Vec<PathBuf>, bool) {
    let mut covered: Vec<PathBuf> = Vec::new();
    let mut left = false;
    for folder in real {
        for view in jail_views(folder, shown) {
            if needed.iter().any(|path| path.starts_with(&view)) {
                left = true;
            } else if !covered.contains(&view) {
                covered.push(view);
            }
        }
    }
    (covered, left)
}

/// A place the jail hides by default (a dotdir it never shows,
/// InnerWarden's own folder) or by `deny_read` (a path of the project), as
/// the launcher found it on the host ([`plan_linked_places`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenPlace {
    /// As the jail names it: `~/.ssh`, `<project>/.env`.
    pub nominal: PathBuf,
    /// Where it leads on the host, every link on the way followed and the
    /// rest as written where nothing is there yet: where a file made
    /// through it would land. `None` where its links loop.
    pub leads_to: Option<PathBuf>,
    /// Something is there.
    pub there: bool,
    /// What is there is a folder (a place not there yet is made as one).
    pub is_dir: bool,
    /// The first link on the way that sits in a folder the jail writes
    /// ([`PlaceFacts::writable`], [`steering_link`]): a program in the jail
    /// can replace it, on the host, and change where the place leads. Every
    /// `deny_read` link in the project is one. Read also where the links
    /// loop.
    pub steered_by: Option<PathBuf>,
    /// A link found inside a dotdir the jail never shows
    /// ([`never_shown_home_paths`]): `~/.ssh/config` a link into
    /// `~/.local/share`, as a dotfiles manager makes one per file. Whether
    /// the place it leads to is a file or a folder is not known before it
    /// is made, so one that is not there yet is never made: where a Linux
    /// jail shows it, the launch is refused ([`inner_link_to_nothing_refused`]).
    pub inner: bool,
}

/// What the jail does with the places it hides that a link leads
/// somewhere else ([`plan_linked_places`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkedPlan {
    /// Linux: each other place the jail shows one of them, as the jail sees
    /// it, covered like the place as named.
    pub masks: Vec<DenyPath>,
    /// macOS: where each such place leads, denied, read and write, like the
    /// place as named (the sandbox matches the path a link leads to).
    pub denies: Vec<PathBuf>,
    /// Linux: each host place not there yet, with the places the jail shows
    /// it at (in `masks`). The real run makes it first, empty and 0700, as
    /// a folder of the person's; where it cannot be made, nothing can be
    /// there, and those masks are dropped, so the jail never fails to start
    /// over it.
    pub missing: Vec<(PathBuf, Vec<PathBuf>)>,
    /// Each place the jail hides by default that a link leads somewhere
    /// else, and that it hides there: `(as named, where it leads)`. A
    /// worktree, writable or read-only path over one is refused
    /// ([`validate_jail_inputs`]), as one over the place as named is.
    pub hidden: Vec<(PathBuf, PathBuf)>,
    /// What the launcher says of each place it leaves as it is, and of each
    /// dotdir it hides inside the project.
    pub left: Vec<String>,
}

/// The system folders a Linux jail shows from the host at their own place,
/// read-only.
pub const LINUX_SYSTEM_SHOWN: &[&str] =
    &["/usr", "/etc", "/sys", "/bin", "/lib", "/lib64", "/sbin"];

/// The system's own folders, on either OS: no place a link leads to that
/// holds one is hidden, or the jail would hide what it runs on.
const SYSTEM_FOLDERS: &[&str] = &[
    "/usr",
    "/etc",
    "/sys",
    "/bin",
    "/lib",
    "/lib64",
    "/sbin",
    "/var",
    "/dev",
    "/System",
    "/Library",
    "/Applications",
    "/private/etc",
    "/private/var",
];

/// macOS: the places of the system where a link a program in the jail can
/// change never moves a deny, in them or above them. A deny there could
/// close what the guard's hook runs on (a shell, a library) and leave the
/// agent's own commands running unscreened.
const MACOS_SYSTEM_PLACES: &[&str] = &[
    "/System",
    "/Library",
    "/Applications",
    "/usr",
    "/bin",
    "/sbin",
    "/etc",
    "/private/etc",
    "/var",
    "/private/var",
    "/tmp",
    "/private/tmp",
    "/dev",
    "/cores",
    "/opt/homebrew",
    "/opt/local",
];

/// macOS: the host folders outside the home the sandbox lets the jail
/// write, besides the project, the worktree and the home's dotdirs.
const MACOS_WRITABLE: &[&str] = &[
    "/tmp",
    "/private/tmp",
    "/private/var/tmp",
    "/private/var/folders",
];

/// What the planner of the places a jail hides knows of the jail
/// ([`place_facts`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlaceFacts {
    /// The home, as named.
    pub home: PathBuf,
    /// Each host folder the jail shows, as `(where the jail shows it, where
    /// its host path leads)`: those of [`shown_host_folders`], and on Linux
    /// each system folder it shows at its own place ([`LINUX_SYSTEM_SHOWN`]).
    pub shown: Vec<(PathBuf, PathBuf)>,
    /// The jail paths in `shown` it shows read-only. No place that is not
    /// there yet is covered through them: bwrap could not make the mount
    /// point there, and nothing can be made there from the jail.
    pub read_only: Vec<PathBuf>,
    /// The person's own places: the home, and the host folder behind each
    /// folder the jail shows read-write, but the worktree's (the project's
    /// `.git` names it, and the agent writes that file). On Linux a link a
    /// program in the jail can change covers a place only in them.
    pub own: Vec<PathBuf>,
    /// The host folders behind the person's read-only paths (the home's
    /// dotfiles, a profile's `extra_ro`): own too, for a place that is there.
    pub own_read_only: Vec<PathBuf>,
    /// The host folders the jail writes, as named and as they lead
    /// ([`HiddenPlace::steered_by`]).
    pub writable: Vec<PathBuf>,
    /// What the guard needs as it is, as named and as it leads: its binary,
    /// the agent's command, the agent's settings that carry the hook, the
    /// folder of the system profiles. No place a link leads into one, or
    /// that holds one, is hidden.
    pub guard: Vec<PathBuf>,
    /// What the jail works in or runs on: the project and the read-only
    /// paths (as named and as they lead) and the system's own folders. No
    /// place a link leads to that holds one is hidden (one inside the
    /// project is: the project's own secrets are there).
    pub work: Vec<PathBuf>,
    /// The project: a dotdir a link leads into it is hidden there, and
    /// that is said.
    pub project: Vec<PathBuf>,
    /// The jail is macOS's sandbox: each place is denied where it leads
    /// ([`LinkedPlan::denies`]), never covered by a mount.
    pub macos: bool,
}

impl PlaceFacts {
    /// No link may move a mask or a deny onto `place`: it overlaps what the
    /// guard needs, either way, or it holds what the jail works in or runs
    /// on.
    fn needs(&self, place: &Path) -> bool {
        self.guard.iter().any(|need| paths_overlap(need, place))
            || self.work.iter().any(|need| need.starts_with(place))
    }

    /// Linux: `place` is in one of the person's own places.
    fn own_place(&self, place: &Path, there: bool) -> bool {
        self.own.iter().any(|own| place.starts_with(own))
            || (there && self.own_read_only.iter().any(|own| place.starts_with(own)))
    }

    /// Whether a place that a link a program in the jail can change leads
    /// to is left as it is: on Linux one outside the person's own places,
    /// where a mount would land on what the jail runs on; on macOS one in
    /// or above a place of the system ([`MACOS_SYSTEM_PLACES`]), but never
    /// one in the project, which the jail works in (a project kept under
    /// `/private/tmp` or `/Applications`).
    fn leaves_steered(&self, place: &Path, there: bool) -> bool {
        if self.macos {
            !self.in_project(place)
                && MACOS_SYSTEM_PLACES
                    .iter()
                    .any(|system| paths_overlap(Path::new(system), place))
        } else {
            !self.own_place(place, there)
        }
    }

    /// What is said of such a place: on macOS always (the sandbox lets the
    /// jail read everywhere else); on Linux only where the jail shows it,
    /// for elsewhere it is not in the jail at all.
    fn said_steered(&self, nominal: &Path, place: &Path) -> Option<String> {
        (self.macos || !jail_views(place, &self.shown).is_empty())
            .then(|| left_steered(nominal, place))
    }

    /// `place` is in the project.
    fn in_project(&self, place: &Path) -> bool {
        self.project.iter().any(|folder| place.starts_with(folder))
    }
}

/// PURE. The folders a jail shows read-only, as the jail sees them: the
/// home's dotfiles ([`DOTFILE_RO`]) and the profile's read-only paths.
pub fn read_only_shown(input: &ContainArgs, home: &Path) -> Vec<PathBuf> {
    DOTFILE_RO
        .iter()
        .map(|name| home.join(name))
        .chain(input.extra_ro.iter().cloned())
        .collect()
}

/// PURE. What the planner of the places a jail hides knows of a jail
/// ([`PlaceFacts`]), from the arguments and the host facts: `existing` the
/// home's dotdirs and dotfiles that are there, `agent_command` where the
/// agent's command is on the host, `tmpdir` the launcher's temporary
/// folder, and `real` where a host path leads.
#[allow(clippy::too_many_arguments)]
pub fn place_facts(
    input: &ContainArgs,
    home: &Path,
    worktree: Option<&Worktree>,
    existing: &[PathBuf],
    iw_binary: &Path,
    agent_command: Option<&Path>,
    tmpdir: &Path,
    macos: bool,
    real: impl Fn(&Path) -> PathBuf,
) -> PlaceFacts {
    let mut shown = shown_host_folders(input, home, worktree, existing, &real);
    let mut read_only = read_only_shown(input, home);
    let worktree_folders: Vec<PathBuf> = worktree
        .map(|worktree| vec![worktree.git_dir.clone(), worktree.common_dir.clone()])
        .unwrap_or_default();
    let own: Vec<PathBuf> = std::iter::once(home.to_path_buf())
        .chain(
            shown
                .iter()
                .filter(|(jail, _)| !read_only.contains(jail) && !worktree_folders.contains(jail))
                .map(|(_, host)| host.clone()),
        )
        .collect();
    let own_read_only: Vec<PathBuf> = shown
        .iter()
        .filter(|(jail, _)| read_only.contains(jail))
        .map(|(_, host)| host.clone())
        .collect();
    let mut writable: Vec<PathBuf> = shown
        .iter()
        .filter(|(jail, _)| !read_only.contains(jail))
        .flat_map(|(jail, host)| [jail.clone(), host.clone()])
        .chain(input.extra_rw.iter().cloned())
        .collect();
    if macos {
        writable.extend(MACOS_WRITABLE.iter().map(PathBuf::from));
        writable.push(tmpdir.to_path_buf());
        writable.push(home.join("Library/Caches"));
    } else {
        for system in LINUX_SYSTEM_SHOWN {
            shown.push((PathBuf::from(system), PathBuf::from(system)));
            read_only.push(PathBuf::from(system));
        }
    }
    let named_and_led = |paths: Vec<PathBuf>| {
        let mut out = paths.clone();
        for path in paths {
            let led = real(&path);
            if !out.contains(&led) {
                out.push(led);
            }
        }
        out
    };
    let mut guard = vec![iw_binary.to_path_buf()];
    guard.extend(agent_command.map(Path::to_path_buf));
    guard.extend(AGENT_SETTINGS.iter().map(|name| home.join(name)));
    guard.extend(
        Path::new(innerwarden_agent_guard::profiles::SYSTEM_PROFILES_PATH)
            .parent()
            .map(Path::to_path_buf),
    );
    let mut work = named_and_led(
        std::iter::once(input.project.clone())
            .chain(input.extra_ro.iter().cloned())
            .collect(),
    );
    work.extend(SYSTEM_FOLDERS.iter().map(PathBuf::from));
    PlaceFacts {
        home: home.to_path_buf(),
        shown,
        read_only,
        own,
        own_read_only,
        writable,
        guard: named_and_led(guard),
        work,
        project: vec![input.project.clone()],
        macos,
    }
}

/// PURE. The link through which a program in the jail can change where a
/// place leads: the first link on the way (`links`, each as found on the
/// host) that sits in a folder the jail writes (`writable`). `own_entry`
/// is the place's own entry where the jail hides it as named (a dotdir,
/// InnerWarden's folder), which the jail cannot change; every other link
/// counts.
pub fn steering_link<'a>(
    links: &'a [PathBuf],
    own_entry: Option<&Path>,
    writable: &[PathBuf],
) -> Option<&'a PathBuf> {
    links
        .iter()
        .filter(|link| Some(link.as_path()) != own_entry)
        .find(|link| {
            link.parent()
                .is_some_and(|folder| writable.iter().any(|w| folder.starts_with(w)))
        })
}

/// A place the host reaches by name (a dotdir the jail never shows,
/// InnerWarden's own folder, the launcher's records) through a link that
/// sits in a folder the jail writes refuses the launch, as InnerWarden's
/// folder kept as a link does on Linux ([`iw_folder_link_refused`]): no
/// mount or deny pins a link, so a program in the jail could replace it on
/// the host with a folder of its own, and the host's `ssh`, `gpg`, `aws` or
/// guard would read what it put there (an `ssh` config's `Match exec`, a
/// `credential_process`). The remedy is to take that link off the way.
pub fn steered_link_refused(nominal: &Path, link: &Path) -> ContainError {
    ContainError::Unsupported(format!(
        "{} goes through {}, a link in a folder a program in the jail can write: that program \
         could replace the link on the host, and the host would then find its files at {}. \
         Replace the link with what it leads to, or link {} straight to its place, and start \
         the jail again",
        printable(nominal),
        printable(link),
        printable(nominal),
        printable(nominal)
    ))
}

/// The launcher's records folder reached through a link in a folder the
/// jail writes (`~/.local/state` a link) refuses an identified Linux jail:
/// a program in it could replace that link with a folder of its own, and
/// the launcher and the dashboard would then read the records it put
/// there. A mount pins a folder, never a link, so this protection cannot be
/// built at that place, and the words say so. The only remedy is the
/// folder itself in place of the link: a link to the records folder would
/// sit in the same folder the jail writes.
pub fn records_link_refused(records: &Path, link: &Path) -> ContainError {
    ContainError::Unsupported(format!(
        "the launcher keeps its records of identified jails in {}, and the way there goes \
         through {}, a link in a folder a program in the jail can write: that program could \
         replace the link with a folder of its own, and the launcher and the dashboard would \
         then read records it made. A link cannot be held in place the way a folder can, so \
         the identified jail does not start. Replace {} with the folder it leads to, and \
         start the jail again",
        printable(records),
        printable(link),
        printable(link)
    ))
}

/// A profile's hidden home path reached through a link in a folder the
/// jail writes (`~/.cache/git` a link, for `.cache/git/credential`)
/// refuses a Linux jail: the jail covers where the path leads, and a mount
/// pins a folder, never a link, so a program in the jail could replace the
/// link with a folder of its own. The host's programs would then read what
/// it put there, and write there what the path was hidden for (a
/// credential cache's socket, a token), at the path's own name. The only
/// remedy is the folder itself in place of the link: a link to it would sit
/// in the same folder the jail writes.
pub fn hidden_home_link_refused(nominal: &Path, link: &Path) -> ContainError {
    ContainError::Unsupported(format!(
        "the hidden home path '{}' goes through {}, a link in a folder a program in the jail \
         can write: that program could replace the link with a folder of its own, and the \
         programs on the host would then read and write that folder at '{}'. A link cannot \
         be held in place the way a folder can, so the jail does not start. Replace {} with \
         the folder it leads to, and start the jail again",
        printable(nominal),
        printable(link),
        printable(nominal),
        printable(link)
    ))
}

/// Said of a hidden place that a link a program in the jail can change
/// leads outside the person's own places.
fn left_steered(nominal: &Path, leads_to: &Path) -> String {
    format!(
        "{} leads outside your home, to {}, through a link a program in the jail can change: \
         the jail does not hide that place; to hide it, keep it in your home",
        printable(nominal),
        printable(leads_to)
    )
}

/// Said of a hidden place that leads onto what the jail needs.
fn left_needed(nominal: &Path, leads_to: &Path) -> String {
    format!(
        "{} leads to {}, where the jail keeps what it needs (the project, the guard, \
         the agent's settings, a read-only path or the system): the jail does not hide it \
         there; to hide it, keep it apart from those",
        printable(nominal),
        printable(leads_to)
    )
}

/// Said of a dotdir the jail never shows whose links the launcher looked
/// for only so far ([`INNER_WALK_ENTRIES`], [`INNER_WALK_DEPTH`]).
pub fn left_unwalked(dotdir: &Path) -> String {
    format!(
        "{} holds more than {INNER_WALK_ENTRIES} entries, folders more than \
         {INNER_WALK_DEPTH} deep, or a folder the launcher cannot read: the jail looked \
         for links in it only so far, and one past them that leads where the jail shows \
         is not hidden there",
        printable(dotdir)
    )
}

/// The most entries the launcher looks at inside one dotdir the jail never
/// shows, for the links in it.
pub const INNER_WALK_ENTRIES: usize = 100_000;

/// The deepest folder the launcher looks in inside one such dotdir.
pub const INNER_WALK_DEPTH: usize = 32;

/// A link inside a dotdir the jail never shows ([`HiddenPlace::inner`])
/// that leads to nothing yet, where a Linux jail shows that place
/// read-write: a program in the jail could make it, and the host's `ssh`
/// or `gpg` would read it through the link. What it should be, a file or a
/// folder, is the person's to say, so the launch is refused.
pub fn inner_link_to_nothing_refused(nominal: &Path, leads_to: &Path) -> ContainError {
    ContainError::Unsupported(format!(
        "{} is a link to {}, which is not there, in a folder a program in the jail can write: \
         that program could make it, and the host would read it as {}. Make it (an empty file \
         or folder), or remove the link, and start the jail again",
        printable(nominal),
        printable(leads_to),
        printable(nominal)
    ))
}

/// Said of a hidden place whose links loop.
fn left_loop(nominal: &Path) -> String {
    format!(
        "{} is a link that loops: the jail hides nothing through it; to hide it, fix the link",
        printable(nominal)
    )
}

/// Said of a dotdir the jail never shows that a link leads into the project.
fn said_in_project(nominal: &Path, leads_to: &Path) -> String {
    format!(
        "{} leads into your project, to {}: the jail hides it there too (the agent \
         cannot read it, nor change what you keep there)",
        printable(nominal),
        printable(leads_to)
    )
}

/// A path as the launcher prints it: a character that would steer the
/// terminal (a control character such as a line break or an escape, or one
/// that reorders text) is printed as its escape, so a name a program in
/// the jail picks cannot erase or forge what is said.
pub(crate) fn printable(path: &Path) -> String {
    let mut out = String::new();
    for c in path.to_string_lossy().chars() {
        if c.is_control()
            || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// PURE. The places a jail hides, `places`, at every other place a Linux
/// jail shows where each really is on the host, and where each leads for
/// the macOS sandbox (`facts.macos`).
///
/// A place the jail never shows can be a link into a folder it shows
/// (`~/.ssh` a link to `.config/ssh`, `~/.config` bound): the jail covers
/// `~/.ssh` as named, and showed the key through `~/.config/ssh`. Each
/// place is taken where it leads, every link on the way followed (any
/// number, `leads_to`), and covered at each place a folder the jail shows
/// holds it (`facts.shown`), at any depth, also where that folder is itself
/// a link to a folder above the place. Besides the place as named, and
/// those in `covered`, which are covered already. On macOS it is denied
/// where it leads, also outside the home.
///
/// A refusal only for a place the host reaches by name (`from_deny_read`
/// false: a dotdir, InnerWarden's folder) through a link a program in the
/// jail can change ([`HiddenPlace::steered_by`], [`steered_link_refused`]),
/// wherever that link leads, loops included: no mount or deny pins a link.
/// Otherwise a link a person keeps never stops the jail. A place that
/// leads onto what the jail needs ([`PlaceFacts::needs`]: the guard, the
/// agent's settings, the folder of the system profiles, in or above them;
/// the project, a read-only path or the system, above them) is left as it
/// is, and so is one whose links loop. Each is said (`LinkedPlan::left`).
/// A place not there yet is covered only where the jail shows it
/// read-write, and made first ([`LinkedPlan::missing`]). A dotdir hidden
/// inside the project (`from_deny_read` false) is said too. A `deny_read`
/// place a link the agent can change leads where a mask could land on what
/// the jail runs on was left before ([`plan_denied_paths`]).
///
/// A place with no link on the way and no folder shown above it gives
/// nothing: in every common layout the jail is the one it was.
pub fn plan_linked_places(
    places: &[HiddenPlace],
    facts: &PlaceFacts,
    covered: &[PathBuf],
    from_deny_read: bool,
) -> Result<LinkedPlan, ContainError> {
    let mut plan = LinkedPlan::default();
    for place in places {
        if let (false, Some(link)) = (from_deny_read, &place.steered_by) {
            return Err(steered_link_refused(&place.nominal, link));
        }
        let Some(leads_to) = &place.leads_to else {
            plan.left.push(left_loop(&place.nominal));
            continue;
        };
        let linked = *leads_to != place.nominal;
        if linked && facts.needs(leads_to) {
            plan.left.push(left_needed(&place.nominal, leads_to));
            continue;
        }
        if linked && !from_deny_read {
            plan.hidden.push((place.nominal.clone(), leads_to.clone()));
        }
        if facts.macos {
            if linked {
                if !plan.denies.contains(leads_to) {
                    plan.denies.push(leads_to.clone());
                }
                if !from_deny_read && facts.in_project(leads_to) {
                    plan.left.push(said_in_project(&place.nominal, leads_to));
                }
            }
            continue;
        }
        let mut needs = false;
        let mut views: Vec<PathBuf> = Vec::new();
        for (jail, host) in &facts.shown {
            let Ok(rest) = leads_to.strip_prefix(host) else {
                continue;
            };
            let view = jail.join(rest);
            if view == place.nominal
                || covered.contains(&view)
                || views.contains(&view)
                || plan.masks.iter().any(|mask| mask.abs == view)
                || (!place.there && facts.read_only.contains(jail))
            {
                continue;
            }
            if linked && facts.needs(&view) {
                needs = true;
                continue;
            }
            views.push(view);
        }
        if needs {
            plan.left.push(left_needed(&place.nominal, leads_to));
        }
        if place.inner && !place.there && !views.is_empty() {
            return Err(inner_link_to_nothing_refused(&place.nominal, leads_to));
        }
        if linked && !from_deny_read && views.iter().any(|view| facts.in_project(view)) {
            plan.left.push(said_in_project(&place.nominal, leads_to));
        }
        if !place.there && !views.is_empty() {
            plan.missing.push((leads_to.clone(), views.clone()));
        }
        plan.masks.extend(views.into_iter().map(|abs| DenyPath {
            abs,
            is_dir: place.is_dir || !place.there,
        }));
    }
    Ok(plan)
}

/// PURE. The project paths `deny_read` names (`found`), as the jail hides
/// them: each where it leads (`DenyPath::abs`, as before: a mask on Linux,
/// a deny on macOS), and at every other place a Linux jail shows it
/// ([`plan_linked_places`]). One that a link leads onto what the jail needs
/// is left as it is and said, and so is one that a link a program in the
/// jail can change (every link in the project) leads where a mask or a
/// deny could land on what the jail runs on: on Linux outside the person's
/// own places, on macOS a place of the system. A path the person names
/// outside the project (absolute, or with `..`) with no such link on the
/// way is hidden where it leads, as it always was. One with no link on the
/// way is masked where it is, as it always was. A path that is not there
/// is not masked.
pub fn plan_denied_paths(found: &[HiddenPlace], facts: &PlaceFacts) -> (Vec<DenyPath>, LinkedPlan) {
    let mut masks: Vec<DenyPath> = Vec::new();
    let mut kept: Vec<HiddenPlace> = Vec::new();
    let mut left: Vec<String> = Vec::new();
    for place in found.iter().filter(|place| place.there) {
        let Some(leads_to) = &place.leads_to else {
            continue;
        };
        if *leads_to != place.nominal {
            if facts.needs(leads_to) {
                left.push(left_needed(&place.nominal, leads_to));
                continue;
            }
            if place.steered_by.is_some() && facts.leaves_steered(leads_to, true) {
                left.extend(facts.said_steered(&place.nominal, leads_to));
                continue;
            }
        }
        if masks.iter().any(|mask| mask.abs == *leads_to) {
            continue;
        }
        masks.push(DenyPath {
            abs: leads_to.clone(),
            is_dir: place.is_dir,
        });
        kept.push(place.clone());
    }
    let covered: Vec<PathBuf> = masks.iter().map(|mask| mask.abs.clone()).collect();
    // `deny_read` places never refuse: the project is the agent's to write.
    let mut linked = plan_linked_places(&kept, facts, &covered, true).unwrap_or_default();
    left.append(&mut linked.left);
    linked.left = left;
    (masks, linked)
}

/// PURE. The home paths a jail never shows, each OS's own: on Linux the
/// dotdirs it never binds ([`DOTDIR_DENY`]); on macOS those its sandbox
/// denies ([`MACOS_DOTDIR_DENY`], [`MACOS_HOME_DENY`]).
pub fn never_shown_home_paths(home: &Path, macos: bool) -> Vec<PathBuf> {
    let names: Vec<&str> = if macos {
        MACOS_DOTDIR_DENY
            .iter()
            .chain(MACOS_HOME_DENY)
            .copied()
            .collect()
    } else {
        DOTDIR_DENY.to_vec()
    };
    names.into_iter().map(|name| home.join(name)).collect()
}

/// Linux: InnerWarden's own folder kept as a link (a dotfiles manager's
/// `~/.config/innerwarden`) refuses the launch. The link is an entry in
/// `~/.config`, which the jail binds read-write, and no mount can pin a
/// link in place: a program in the jail could replace it with a folder of
/// its own on the host, whose files the host's guard reads. The remedy is
/// to make it the folder it leads to.
pub fn iw_folder_link_refused(named: &Path, leads_to: &Path) -> ContainError {
    ContainError::Unsupported(format!(
        "{} is a link (to {}), and on Linux a program in the jail could replace that link \
         on the host: replace the link with the folder it leads to (remove the link, then \
         move {} to {}), and start the jail again",
        printable(named),
        printable(leads_to),
        printable(leads_to),
        printable(named)
    ))
}

/// Where the home folder a hidden path is in leads on the host, when the
/// jail binds that folder read-write ([`writable_home_dirs`]) and shows it
/// (`shown`, [`shown_host_folders`]): what is below that place is what the
/// jail shows below the folder.
fn writable_folder_target<'a>(
    nominal: &Path,
    home: &Path,
    shown: &'a [(PathBuf, PathBuf)],
) -> Option<&'a Path> {
    let first = nominal.strip_prefix(home).ok()?.components().next()?;
    let name = first.as_os_str().to_str()?;
    if !DOTDIR_RW.contains(&name) || DOTDIR_DENY.contains(&name) {
        return None;
    }
    let folder = home.join(name);
    shown
        .iter()
        .find(|(jail, _)| *jail == folder)
        .map(|(_, host)| host.as_path())
}

/// PURE. The host folders (and files) a jail shows under their own names,
/// each as `(where the jail shows it, where its host path resolves)`: the
/// home's dotdirs and dotfiles it binds that exist (`existing`), the
/// project, the worktree's folders and the read-only paths. `real`
/// resolves a host path's links.
pub fn shown_host_folders(
    input: &ContainArgs,
    home: &Path,
    worktree: Option<&Worktree>,
    existing: &[PathBuf],
    real: impl Fn(&Path) -> PathBuf,
) -> Vec<(PathBuf, PathBuf)> {
    let mut shown: Vec<(PathBuf, PathBuf)> = DOTDIR_RW
        .iter()
        .chain(DOTFILE_RO)
        .filter(|name| !DOTDIR_DENY.contains(name))
        .map(|name| home.join(name))
        .filter(|path| existing.contains(path))
        .map(|path| {
            let host = real(&path);
            (path, host)
        })
        .collect();
    let mut same = vec![input.project.clone()];
    if let Some(worktree) = worktree {
        same.push(worktree.git_dir.clone());
        same.push(worktree.common_dir.clone());
    }
    same.extend(input.extra_ro.iter().cloned());
    shown.extend(same.into_iter().map(|path| (path.clone(), path)));
    shown
}

/// The home's folders a jail binds read-write, where a hidden path that is
/// not there yet is made (empty, 0700) before the jail starts, so what a
/// host program makes there later is under the mask too.
pub fn writable_home_dirs() -> &'static [&'static str] {
    DOTDIR_RW
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
    /// Linux: every other place the jail shows that secret dir, through a
    /// home folder it binds that is a link ([`other_jail_views`]), each
    /// covered like the dir itself. Empty where the dir is shown only as
    /// named or as it resolves (every common layout), and on macOS, where
    /// the sandbox matches the resolved path.
    pub iw_config_shown: Vec<PathBuf>,
    /// The secret dir as named is itself a link (a dotfiles manager's
    /// `~/.config/innerwarden`): `iw_config_real` is where it leads. On
    /// Linux such a launch is refused ([`iw_folder_link_refused`]): the link
    /// is an entry in the `~/.config` the jail binds read-write, which no
    /// mount can pin, so a program in the jail could replace it on the
    /// host. On macOS the sandbox denies writing the folder as named, the
    /// link with it, and denies where it leads.
    pub iw_config_link: bool,
    /// The place that link leads to is left as it is ([`plan_linked_places`]:
    /// onto what the jail needs, round in a loop, or, through a link a
    /// program in the jail can change, onto what the jail runs on): it is
    /// neither covered nor denied there, and the launcher says so
    /// ([`JailInputs::left`]). A project or path that overlaps it is still
    /// refused.
    pub iw_config_left: bool,
    /// Linux: every other place the jail shows a place it hides that a link
    /// leads somewhere else, a dotdir it never shows or a `deny_read` path
    /// ([`plan_linked_places`]), each covered like the place itself, after
    /// every other mask. Empty in every common layout.
    pub linked_masks: Vec<DenyPath>,
    /// Linux: each of those places not there yet, with its masks, made by
    /// the real run before the jail starts ([`LinkedPlan::missing`]).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub linked_missing: Vec<(PathBuf, Vec<PathBuf>)>,
    /// macOS: where each dotdir the sandbox denies leads, when a link leads
    /// it somewhere else, denied read and write like the dotdir itself.
    pub linked_denies: Vec<PathBuf>,
    /// Each dotdir the jail never shows that a link leads somewhere else,
    /// with the place it leads to, where the jail hides it there
    /// ([`LinkedPlan::hidden`]): a worktree, writable or read-only path that
    /// overlaps that place is refused, as one over the dotdir as named is.
    pub hidden_targets: Vec<(PathBuf, PathBuf)>,
    /// What the launcher says of each place it hides and leaves as it is
    /// (onto what the jail needs, round in a loop, or through a link a
    /// program in the jail can change), and of each dotdir it hides inside
    /// the project.
    pub left: Vec<String>,
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
    /// The descriptor bwrap reads the key of Active Defence on this host from
    /// and mounts, read-only, at [`JAIL_SPKI_PIN_PATH`] (`--ro-bind-data`).
    /// The launcher read it from the host's file with the host's real owners;
    /// inside the jail's user namespace the owners cannot be told apart.
    /// `None` without a key the launcher believes, and unless the launch asked
    /// for an identity record.
    ///
    /// [`JAIL_SPKI_PIN_PATH`]: innerwarden_agent_guard::identity::JAIL_SPKI_PIN_PATH
    pub key_fd: Option<i32>,
    /// The descriptor bwrap reads the launcher's marker from and mounts,
    /// read-only, at [`SYSTEM_PROFILES_MARKER_PATH`] (`--ro-bind-data`): the
    /// launcher proved, with the host's real owners, that the way to the
    /// system profiles file is root's alone. Only for a jail with no launch
    /// record, and only when that file exists; `None` otherwise, so a host
    /// without the file runs the jail it always did.
    ///
    /// [`SYSTEM_PROFILES_MARKER_PATH`]: crate::agent_profiles::SYSTEM_PROFILES_MARKER_PATH
    pub profiles_marker_fd: Option<i32>,
    /// The launcher's own records directory, as named and as resolved, and
    /// on Linux at every other place the jail shows it
    /// ([`other_jail_views`]), hidden inside an identified jail: the agent
    /// works in a home that holds it. Empty unless the launch asked for an
    /// identity record.
    pub records_dirs: Vec<PathBuf>,
    /// Variables the launcher keeps out of the programs it runs to start the
    /// jail, handed to the jail's command as they were ([`launch_env`]).
    /// Empty unless the launch asked for an identity record.
    pub child_env: Vec<(String, String)>,
    /// The jail was started under the identified filter, so its programs
    /// cannot make user namespaces of their own: the fact the launch record
    /// carries (`jail.userns_closed`). Decided by the launcher before the jail
    /// is built ([`launch::filter_plan`]); `false` unless the launch asked
    /// for an identity record. It puts nothing in the argv: the filter is
    /// [`JailInputs::seccomp_fd`]. Read by the Linux launcher only.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub close_userns: bool,
    /// The descriptor bwrap reads the jail's seccomp filter from
    /// (`--seccomp`, [`innerwarden_agent_guard::seccomp`]): the terminal
    /// filter for a plain jail, the identified one with `--identity` (or the
    /// terminal one where the host takes only that). `None` where the
    /// launcher's start-up probe found this host cannot start a jail with
    /// either, and the jail then runs as it did before the filter.
    pub seccomp_fd: Option<i32>,
    /// The home paths a jail profile hides, each as the jail sees it and
    /// whether it is a folder ([`HiddenPlan::masks`]): covered by an empty
    /// mount after every writable bind (Linux). Empty without such a
    /// profile.
    pub hide_paths: Vec<DenyPath>,
    /// The same paths as the sandbox denies them, as named and as they
    /// resolve ([`HiddenPlan::denies`], macOS). Empty without such a
    /// profile.
    pub hide_denies: Vec<PathBuf>,
    /// What of the host's resolver `/etc/resolv.conf` leads to where it is a
    /// link into `/run` ([`launch::resolv_conf_target`]): the file, or a
    /// folder of resolver data alone ([`launch::resolv_conf_bind`]), bound
    /// read-only at that same place over the jail's empty `/run`, so the
    /// host's name resolution works in the jail and nothing else of the
    /// host's `/run` is shown. `None` where `/etc/resolv.conf` is a file of
    /// its own, or names nothing there.
    pub resolv_conf: Option<PathBuf>,
    /// The instance whose record the jail must hold before its command
    /// starts ([`launch::gated_child`]): set by the launcher only under a
    /// profile that starts the jail once the host admitted it. `None`
    /// otherwise, and the command is the jail's child as it always was.
    pub gate_instance: Option<String>,
    /// Where an identified jail can keep Claude Code's own state
    /// ([`ClaudeState`]). Both `false` unless the launch asked for an
    /// identity record, and then nothing of it reaches the argv.
    pub claude_state: ClaudeState,
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
/// The agent's own settings under the home, which carry the guard's hook.
const AGENT_SETTINGS: &[&str] = &[".claude", ".claude.json"];
/// Claude Code's own settings file, in the home. A Linux jail's home is an
/// empty folder of the jail's own, so the file Claude Code keeps there is
/// gone when the jail ends.
pub(crate) const CLAUDE_SETTINGS: &str = ".claude.json";
/// Where an identified jail keeps that file instead: under the same name in
/// `~/.claude`, the folder the jail already shares with the host (the place
/// Claude Code itself keeps it when `~/.claude` is named as its
/// configuration folder).
pub(crate) const CLAUDE_SETTINGS_KEPT: &str = ".claude/.claude.json";
/// Claude Code's folders in `~/.claude` of what each of its runs keeps to
/// itself: the list of its running sessions, one file per process id (and
/// Claude Code is process 2 in every jail), and the copies of its settings
/// file it saves before it changes the file. An identified jail covers each
/// with an empty folder of its own.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) const CLAUDE_RUN_FOLDERS: [&str; 2] = ["sessions", "backups"];

/// What the launcher found on the host of the places an identified jail
/// keeps Claude Code's own state in ([`build_linux_jail`]). Read only for an
/// `--identity` launch on Linux: without the flag nothing is read, and the
/// jail is the one it was.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaudeState {
    /// `~/.claude` is a folder, [`CLAUDE_SETTINGS_KEPT`] in it is a file or
    /// is not there yet (never a link, a folder or anything else), and the
    /// person's own `~/.claude.json` is not that file nor leads into
    /// `~/.claude`: the jail's `~/.claude.json` can lead to it.
    pub settings_kept: bool,
    /// Each place the jail shows one of [`CLAUDE_RUN_FOLDERS`] (a folder of
    /// its own in `~/.claude`, no link, made empty and 0700 by the launcher
    /// where it was not there), as the jail sees it
    /// ([`plan_claude_folders`]): each is covered by an empty folder of the
    /// jail's own after every bind that shows it.
    pub own_folders: Vec<PathBuf>,
    /// One of [`CLAUDE_RUN_FOLDERS`] cannot be the jail's own (a link is
    /// there, a path the jail shows is in it, or it could not be made): the
    /// jail shares it with the host, and the launcher says so.
    pub shared: bool,
}
/// Dotdirs that must stay INVISIBLE (never re-bound → absent under the HOME tmpfs).
const DOTDIR_DENY: &[&str] = &[".ssh", ".gnupg", ".aws", ".mozilla", ".thunderbird"];
/// The dotdirs the macOS sandbox denies.
const MACOS_DOTDIR_DENY: &[&str] = &[".ssh", ".aws", ".gnupg"];
const MACOS_HOME_DENY: &[&str] = &["Library/Mail", "Library/Messages", "Library/Safari"];

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn protected_host_paths(input: &JailInputs) -> Vec<PathBuf> {
    let mut paths = vec![input.iw_config_dir(), input.iw_config_real.clone()];
    paths.extend(input.iw_config_shown.iter().cloned());
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
    let iw_named = input.iw_config_dir();
    // `hidden`: a bind the agent can name (a worktree's folders, named by
    // the project's `.git`) or a profile's path, which may not show where a
    // hidden dotdir leads either. The project is not held to that: a
    // dotdir that leads into it is hidden there, and said.
    let validate_bind = |kind: &str, path: &Path, hidden: bool| {
        let normalized_absolute = path.is_absolute()
            && path.components().all(|component| {
                matches!(
                    component,
                    std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                        | std::path::Component::Normal(_)
                )
            });
        let secret = protected.iter().find(|secret| paths_overlap(path, secret));
        if !normalized_absolute
            || path == input.home
            || input.home.starts_with(path)
            || secret.is_some()
        {
            // Where InnerWarden's folder leads, not where it is named
            // (a link on the way): say so, or nothing names the cause.
            let led =
                secret.filter(|secret| **secret == input.iw_config_real && **secret != iw_named);
            return Err(ContainError::Unsupported(match led {
                Some(led) => format!(
                    "unsafe {kind} path '{}': it overlaps '{}', where InnerWarden's own folder \
                     {} leads (a protected policy directory)",
                    printable(path),
                    printable(led),
                    printable(&iw_named)
                ),
                None => format!(
                    "unsafe {kind} path '{}': it overlaps the home or a protected credential/policy directory",
                    printable(path)
                ),
            }));
        }
        if let Some((nominal, target)) = input
            .hidden_targets
            .iter()
            .find(|(_, target)| hidden && paths_overlap(path, target))
        {
            return Err(ContainError::Unsupported(format!(
                "unsafe {kind} path '{}': it overlaps '{}', where {} leads, which the jail hides",
                printable(path),
                printable(target),
                printable(nominal)
            )));
        }
        Ok(())
    };

    validate_bind("project", &input.args.project, false)?;
    if let Some(worktree) = &input.worktree {
        validate_bind("worktree git", &worktree.git_dir, true)?;
        validate_bind("worktree common", &worktree.common_dir, true)?;
    }
    for path in &input.args.extra_rw {
        validate_bind("extra writable", path, true)?;
    }
    // A read-only bind exposes the same as a writable one to a reader, so it
    // is held to the same places: never the home, an ancestor of it, or a
    // protected directory (the masks are re-applied after it anyway).
    for path in &input.args.extra_ro {
        validate_bind("extra read-only", path, true)?;
    }
    // A hidden home path covers what is under it: never what the jail
    // needs. Not the project, or the agent would work in an empty folder;
    // not the guard's binary, whose hook would then fail to run and every
    // command go unscreened; not a read-only path the profile shows; not
    // the agent's own settings, which carry the hook.
    let needed = std::iter::once(("the project", input.args.project.clone()))
        .chain(std::iter::once(("the guard", input.iw_binary.clone())))
        .chain(
            input
                .args
                .extra_ro
                .iter()
                .map(|path| ("a read-only path", path.clone())),
        )
        .chain(
            AGENT_SETTINGS
                .iter()
                .map(|name| ("the agent's settings", input.home.join(name))),
        );
    for (what, path) in needed {
        let covered = input
            .hide_paths
            .iter()
            .map(|hidden| hidden.abs.as_path())
            .chain(input.hide_denies.iter().map(PathBuf::as_path))
            .find(|hidden| path.starts_with(hidden));
        if let Some(hidden) = covered {
            return Err(ContainError::Unsupported(format!(
                "the hidden home path '{}' holds {what} '{}'",
                printable(hidden),
                printable(&path)
            )));
        }
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
                printable(path)
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

/// The namespaces the jail unshares. The start-up probe of
/// [`launch::filter_probe_argv`] asks for the same ones.
pub const JAIL_NAMESPACES: [&str; 3] = ["--unshare-pid", "--unshare-uts", "--unshare-ipc"];

/// The bwrap option that hands it the jail's seccomp filter on a descriptor.
pub const SECCOMP_OPTION: &str = "--seccomp";

/// What an identified jail asks bwrap for after the filter: no capability at
/// all for its programs. bwrap keeps every capability of a caller whose uid
/// is 0 unless told otherwise, and it runs such a jail in the host's user
/// namespace, where those capabilities make namespaces and mounts the filter
/// does not refuse. For any other caller bwrap drops them anyway, so this
/// changes nothing there. In every bwrap since 0.2.0.
pub const CAP_DROP_ALL: [&str; 2] = ["--cap-drop", "ALL"];

/// Which writable bind of a Linux jail holds a pinned folder
/// ([`linux_pins`]): the pin is laid right after that bind, so every later
/// bind and mask lands on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRoot {
    /// A home folder the jail binds read-write ([`DOTDIR_RW`]).
    Home,
    /// The project.
    Project,
    /// A worktree's folder.
    Worktree,
}

/// What shows a host folder in a Linux jail ([`linux_pins`]): a bind that
/// lets the jail write there (and which one, so a pin is laid right after
/// it), a read-only bind, or a folder of the jail's own (the home's, `/tmp`
/// and `/run`'s empty mounts), where nothing of the host can be renamed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shows {
    Writable(PinRoot),
    ReadOnly,
    Own,
}

/// PURE. Where a profile's read-only path lies in the folders the jail
/// writes as its work: below a worktree's folder (`Some(Worktree)`), else
/// below the project (`Some(Project)`), never either folder itself. A
/// read-only bind laid before the bind of that folder is covered by it, and
/// the jail wrote through it (`extra_ro = ~/code/app/vendor` with the
/// project `~/code/app`), so the jail lays it right after that folder's
/// bind and its pins ([`build_linux_jail`]), and macOS denies it after the
/// write that folder's allow gives ([`build_macos_profile`]). `None` for
/// any other path, the one that holds the project among them, which is
/// laid before the project as before, so the project stays writable in it.
fn read_only_in_the_work(input: &JailInputs, path: &Path) -> Option<PinRoot> {
    let below = |folder: &Path| path != folder && path.starts_with(folder);
    if input
        .worktree
        .as_ref()
        .is_some_and(|wt| below(&wt.git_dir) || below(&wt.common_dir))
    {
        Some(PinRoot::Worktree)
    } else if below(&input.args.project) {
        Some(PinRoot::Project)
    } else {
        None
    }
}

/// PURE. A profile's read-only paths that [`read_only_in_the_work`] puts
/// at `root` (`None`: laid before the project).
fn read_only_at(input: &JailInputs, root: Option<PinRoot>) -> Vec<PathBuf> {
    input
        .args
        .extra_ro
        .iter()
        .filter(|path| read_only_in_the_work(input, path) == root)
        .cloned()
        .collect()
}

/// PURE. Linux: every folder between the home (or the top of whatever bind
/// shows it) and a place the jail covers that the host reaches by name,
/// that a program in the jail could rename, each bound onto itself so it is
/// a mount point. A mount moves with the folder it is in: a program in the
/// jail that renamed a folder above a covered place (`~/.config/keys`
/// above `~/.config/keys/ssh`, where `~/.ssh` leads; `~/.local/state`
/// above the launcher's records; `~/.cache/work`, above a project in it
/// that a link leads into) took the cover away with it, made a folder of
/// its own at the old name, and the host's link, or the launcher, read
/// there. Linux refuses to rename or remove a mount point. A folder is
/// looked at as the jail shows it, by the last bind laid over it: one the
/// jail writes is pinned, one a read-only bind shows cannot be renamed, a
/// bind is a mount point already (and the folder above it is still looked
/// at, since a rename there would take that mount away too), and a folder
/// of the jail's own ends the way. Only the places the host reaches by
/// name: InnerWarden's folder where it leads and wherever the jail shows
/// it, the launcher's records (`--identity`), the profile's hidden home
/// paths, every place a hidden dotdir or a `deny_read` path is covered at
/// through a link (`linked_masks`), and the profile's read-only paths. In
/// every common layout there is none but the records' folders.
pub fn linux_pins(input: &JailInputs) -> Vec<(PinRoot, PathBuf)> {
    // In the order the jail lays them ([`build_linux_jail`]): a later one
    // over a folder is what the jail shows there.
    let mut binds: Vec<(Shows, PathBuf)> = LINUX_SYSTEM_SHOWN
        .iter()
        .map(|path| (Shows::ReadOnly, PathBuf::from(path)))
        .collect();
    binds.extend(["/tmp", "/run"].map(|path| (Shows::Own, PathBuf::from(path))));
    binds.push((Shows::Own, input.home.clone()));
    binds.extend(
        DOTDIR_RW
            .iter()
            .filter(|name| !DOTDIR_DENY.contains(name))
            .map(|name| input.home.join(name))
            .filter(|path| input.exists(path))
            .map(|path| (Shows::Writable(PinRoot::Home), path)),
    );
    let read_only = DOTFILE_RO
        .iter()
        .map(|name| input.home.join(name))
        .filter(|path| input.exists(path))
        .chain(
            input
                .agent_binary
                .iter()
                .flat_map(|bin| [bin.link.clone(), bin.target_dir.clone()]),
        )
        .chain(std::iter::once(input.iw_binary.clone()))
        .chain(read_only_at(input, None));
    binds.extend(read_only.map(|path| (Shows::ReadOnly, path)));
    binds.push((
        Shows::Writable(PinRoot::Project),
        input.args.project.clone(),
    ));
    binds.extend(
        read_only_at(input, Some(PinRoot::Project))
            .into_iter()
            .map(|path| (Shows::ReadOnly, path)),
    );
    if let Some(worktree) = &input.worktree {
        for dir in [&worktree.git_dir, &worktree.common_dir] {
            binds.push((Shows::Writable(PinRoot::Worktree), dir.clone()));
        }
    }
    binds.extend(
        read_only_at(input, Some(PinRoot::Worktree))
            .into_iter()
            .map(|path| (Shows::ReadOnly, path)),
    );
    let shown_by = |folder: &Path| {
        binds
            .iter()
            .rev()
            .find(|(_, bind)| folder.starts_with(bind))
    };
    let mut places: Vec<&Path> = vec![input.iw_config_real.as_path()];
    places.extend(input.iw_config_shown.iter().map(PathBuf::as_path));
    if input.args.identity {
        places.extend(input.records_dirs.iter().map(PathBuf::as_path));
    }
    places.extend(input.hide_paths.iter().map(|hidden| hidden.abs.as_path()));
    places.extend(input.linked_masks.iter().map(|mask| mask.abs.as_path()));
    // A profile's read-only path: a rename of a folder above it took the
    // read-only bind away with it, and the host's programs then found a
    // folder of the jail's at its name.
    places.extend(input.args.extra_ro.iter().map(PathBuf::as_path));
    // A place is walked by its spelling, so only a plain one: above a
    // place spelled through `..`, `<home>/.local/state/../..` is the home
    // itself, and a pin there would bind the host's home over the jail's
    // own. Every place is plain ([`launch::records_dir`]); this keeps a
    // later one from undoing the home's cover. Nor is the home, or a folder
    // above it, ever pinned.
    let plain = |path: &Path| {
        path.components().all(|step| {
            matches!(
                step,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    };
    let mut pins: Vec<(PinRoot, PathBuf)> = Vec::new();
    for place in places.into_iter().filter(|place| plain(place)) {
        for folder in place.ancestors().skip(1) {
            if input.home.starts_with(folder) {
                break;
            }
            let Some((shows, bind)) = shown_by(folder) else {
                break;
            };
            match shows {
                Shows::Own => break,
                // A bind is a mount point of its own; a read-only folder
                // cannot be renamed. The folders above are still looked at.
                _ if bind == folder => {}
                Shows::ReadOnly => {}
                Shows::Writable(kind) => {
                    if !pins.iter().any(|(_, seen)| seen == folder) {
                        pins.push((*kind, folder.to_path_buf()));
                    }
                }
            }
        }
    }
    // A folder before the folders in it: a later bind of a folder would
    // cover the pins below it.
    pins.sort_by_key(|(_, folder)| folder.components().count());
    pins
}

/// The home folders the macOS sandbox lets the jail write.
const MACOS_HOME_WRITABLE: &[&str] = &[
    ".claude", ".cache", ".local", ".cargo", ".npm", ".rustup", ".config",
];

/// PURE. macOS: the project, and every folder above a place the sandbox
/// denies that the sandbox lets the jail write, each to be denied writing
/// as itself. The sandbox denies by path, and lets a program in the jail
/// rename a folder it may write, and what was denied under it is not
/// denied at the new name: a program that moved `~/.config` away read
/// InnerWarden's model key, one that moved the project (or a folder
/// between the project and a `deny_read` path) read the secret, and one
/// that put a link of its own at `~/.config` had the host's guard read the
/// suppressions it planted there. The same for a folder above where a link
/// leads a hidden dotdir (`~/.config/keys` above `~/.config/keys/ssh`,
/// where `~/.ssh` leads): the host's link led to a folder of the jail's.
/// Keeping the folder itself in place, never what is in it
/// ([`macos_pin_rule`]), closes that rename and removal; the jail still
/// writes in it. The places: InnerWarden's folder as named and where it
/// leads, every `deny_read` path, every hidden home path as named and as
/// it resolves, where a link leads a dotdir the sandbox denies, and a
/// profile's read-only paths. In
/// every layout that is `~/.config` and the project at least, and the
/// launcher makes each that is not there yet before the sandbox starts, so
/// the jail never has to, and says so.
pub fn macos_pins(input: &JailInputs) -> Vec<PathBuf> {
    let mut writable: Vec<PathBuf> = vec![input.args.project.clone()];
    if let Some(worktree) = &input.worktree {
        writable.push(worktree.git_dir.clone());
        writable.push(worktree.common_dir.clone());
    }
    writable.extend(MACOS_HOME_WRITABLE.iter().map(|name| input.home.join(name)));
    writable.extend(MACOS_WRITABLE.iter().map(PathBuf::from));
    writable.push(input.tmpdir.clone());
    writable.push(input.home.join("Library/Caches"));
    let iw_named = input.iw_config_dir();
    let mut places: Vec<PathBuf> = vec![iw_named.clone()];
    if input.iw_config_real != iw_named && !input.iw_config_left {
        places.push(input.iw_config_real.clone());
    }
    places.extend(input.deny_paths.iter().map(|denied| denied.abs.clone()));
    places.extend(
        input
            .linked_denies
            .iter()
            .chain(&input.hide_denies)
            .chain(&input.args.extra_ro)
            .cloned(),
    );
    let mut pins: Vec<PathBuf> = vec![input.args.project.clone()];
    for place in &places {
        for folder in place.ancestors().skip(1) {
            if writable.iter().any(|w| folder.starts_with(w)) && !pins.iter().any(|p| p == folder) {
                pins.push(folder.to_path_buf());
            }
        }
    }
    pins.sort_by_key(|folder| folder.components().count());
    pins
}

/// PURE. The macOS sandbox rule that keeps one folder of [`macos_pins`] in
/// place: it refuses only removing the folder's own entry (a rename away, a
/// removal, a swap) and making an entry at its name (a rename or a link
/// onto it), measured on macOS. Nothing else of writing: a program in the
/// jail still writes in the folder, finds it writable (`access(W_OK)`,
/// `[ -w . ]`, the check `create-next-app` makes) and sets its mode and
/// times (`rsync -a`, `cp -a`, `tar -x` into it). A rule on all of writing
/// (`file-write*`) refused those too.
pub fn macos_pin_rule(folder: &Path) -> String {
    format!(
        "(deny file-write-unlink file-write-create (literal \"{}\"))\n",
        sbpl_escape(&folder.to_string_lossy())
    )
}

/// Build the ordered bwrap argument vector. Order is load-bearing (bwrap is
/// last-wins): system RO → dev/proc/tmpfs → HOME tmpfs → dotdir re-binds → their
/// pins ([`linux_pins`]) → shadow innerwarden → Claude Code's settings file
/// (`--identity` only) → binary binds → the profile's read-only paths →
/// project (late) → its pins → the read-only paths inside it → worktree →
/// its pins → the read-only paths inside it → Claude Code's folders of its runs
/// (`--identity` only) → nested secret masks → every other place the jail
/// shows a hidden place a link leads somewhere else (`linked_masks`) →
/// the host's key and the launch record (`--identity` only) → namespaces and the
/// seccomp filter → child. `DOTDIR_DENY`
/// entries are never emitted, so they vanish under the HOME tmpfs.
pub fn build_linux_jail(input: &JailInputs) -> Result<LinuxJailPlan, ContainError> {
    validate_jail_inputs(input)?;
    let pins = linux_pins(input);
    let pins_of = |kind: PinRoot| -> Vec<String> {
        pins.iter()
            .filter(|(root, _)| *root == kind)
            .flat_map(|(_, folder)| {
                let folder = folder.to_string_lossy().to_string();
                ["--bind".to_string(), folder.clone(), folder]
            })
            .collect()
    };
    // InnerWarden's own folder kept as a link: no mount pins a link, and a
    // program in the jail could replace it on the host.
    if input.iw_config_link {
        return Err(iw_folder_link_refused(
            &input.iw_config_dir(),
            &input.iw_config_real,
        ));
    }
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
    // Where `/etc/resolv.conf` is a link into `/run` (systemd-resolved), the
    // file it names, alone, read-only at its own place (or the folder of
    // resolver data alone that holds it, `launch::resolv_conf_bind`): the
    // host's name resolution keeps working in the jail and the rest of the
    // host's `/run`, its sockets included, stays out. Never a file of the
    // jail's own: the jail resolves names exactly as the host does.
    if let Some(target) = &input.resolv_conf {
        let target = target.to_string_lossy().to_string();
        push(&["--ro-bind-try", &target, &target]);
    }

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
    // Each folder in them between a place the host reaches by name and
    // its bind, a mount point of its own ([`linux_pins`]): never renamed
    // away from under its cover. Empty in every common layout.
    let home_pins = pins_of(PinRoot::Home);
    push(&home_pins.iter().map(String::as_str).collect::<Vec<_>>());
    // Shadow the InnerWarden secret dir IMMEDIATELY after the `.config` bind
    // (last-wins). The 0600 llm-key is now absent inside the jail. Shadow BOTH the
    // nominal path and its symlink-resolved real path (a symlinked ~/.config would
    // otherwise leave the real dir reachable). The dir as named is never a
    // link here: such a launch was refused above.
    let iw_cfg = input.iw_config_dir().to_string_lossy().to_string();
    let iw_cfg_real = input.iw_config_real.to_string_lossy().to_string();
    push(&["--tmpfs", &iw_cfg]);
    if iw_cfg_real != iw_cfg {
        push(&["--tmpfs", &iw_cfg_real]);
    }
    // And at every other place a home folder the jail binds shows it
    // (`~/.config` a link into a `~/.cache` that leads off the home).
    for view in &input.iw_config_shown {
        push(&["--tmpfs", &view.to_string_lossy()]);
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

    // --- Claude Code's settings file, where the jail shares `~/.claude`
    // with the host (`--identity` only). The jail's home is an empty folder
    // of its own, so the settings file Claude Code keeps in it,
    // `~/.claude.json`, was gone at every launch: it is a link to the same
    // name in `~/.claude` instead, and Claude Code writes through it (a
    // temporary file beside the target, then a rename in that folder; a
    // rename onto a mount would fail). The person's own `~/.claude.json` is
    // not shown, and the launcher takes no kept file that is it or that it
    // leads to ([`ClaudeState::settings_kept`]). No link where a hidden or
    // denied path covers the kept file, or where a read-only path of the
    // profile shows it or `~/.claude.json` (a later mount there would make
    // bwrap abort, and a read-only file cannot be saved): Claude Code then
    // keeps its file in the jail's own home, as before. Before every mask,
    // so a hidden path still covers it. ---
    if input.args.identity && input.exists(&input.home.join(".claude")) {
        let kept = input.home.join(CLAUDE_SETTINGS_KEPT);
        let link = input.home.join(CLAUDE_SETTINGS);
        let covered = input
            .hide_paths
            .iter()
            .chain(&input.deny_paths)
            .map(|hidden| hidden.abs.as_path())
            .chain(input.args.extra_ro.iter().map(PathBuf::as_path))
            .any(|other| kept.starts_with(other) || paths_overlap(other, &link));
        if input.claude_state.settings_kept && !covered {
            let target = kept.to_string_lossy().to_string();
            push(&["--symlink", &target, &link.to_string_lossy()]);
        }
    }

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
    // a profile named some, so a jail without one is what it was. One inside
    // the project or a worktree's folder is laid right after that folder's
    // bind instead, or the bind would cover it ([`read_only_in_the_work`]). ---
    let read_only_binds = |root: Option<PinRoot>| -> Vec<String> {
        read_only_at(input, root)
            .iter()
            .flat_map(|p| {
                let s = p.to_string_lossy().to_string();
                ["--ro-bind-try".to_string(), s.clone(), s]
            })
            .collect()
    };
    let outer_read_only = read_only_binds(None);
    push(
        &outer_read_only
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );

    // --- project (rw, same path), LATE so it wins over the HOME tmpfs ---
    let proj = input.args.project.to_string_lossy().to_string();
    push(&["--bind", &proj, &proj]);
    push(&["--chdir", &proj]);
    // The pins in the project ([`linux_pins`]): a dotdir a link leads into
    // it is covered there, and the folders above that cover are pinned.
    let project_pins = pins_of(PinRoot::Project);
    push(&project_pins.iter().map(String::as_str).collect::<Vec<_>>());
    let project_read_only = read_only_binds(Some(PinRoot::Project));
    push(
        &project_read_only
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );

    // --- git worktree admin dirs, AFTER the project bind ---
    if let Some(wt) = &input.worktree {
        for p in [&wt.git_dir, &wt.common_dir] {
            let s = p.to_string_lossy().to_string();
            push(&["--bind", &s, &s]);
        }
    }
    let worktree_pins = pins_of(PinRoot::Worktree);
    push(&worktree_pins.iter().map(String::as_str).collect::<Vec<_>>());
    let worktree_read_only = read_only_binds(Some(PinRoot::Worktree));
    push(
        &worktree_read_only
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );

    // --- Claude Code's folders of its runs, where the jail shares
    // `~/.claude` (`--identity` only). Claude Code is process 2 in every
    // jail and lists each running session by its process id, and it keeps
    // copies of its settings file beside them, so each jail covers both
    // with an empty folder of its own at every place it shows them
    // ([`ClaudeState::own_folders`]): two jails at once do not write the
    // same session file, and none sees the host's sessions or the copies of
    // the person's own settings file. After every bind that can show them (the
    // dotdirs, the read-only paths, the project, the worktree) and before
    // every mask, so a hidden path still covers them. ---
    if input.args.identity && input.exists(&input.home.join(".claude")) {
        for folder in &input.claude_state.own_folders {
            push(&["--tmpfs", &folder.to_string_lossy()]);
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

    // --- the home paths a jail profile hides that exist (`hide_home`),
    // after every writable bind, so none of them brings one back: a folder
    // under an empty tmpfs, a file under /dev/null. Empty unless a profile
    // names some. ---
    for hidden in &input.hide_paths {
        let dest = hidden.abs.to_string_lossy().to_string();
        if hidden.is_dir {
            push(&["--tmpfs", &dest]);
        } else {
            push(&["--ro-bind", "/dev/null", &dest]);
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

    // --- every other place the jail shows a place it hides that a link
    // leads somewhere else: a dotdir it never shows (`~/.ssh` a link to
    // `.config/ssh`, shown by the `.config` bind) or a `deny_read` path.
    // Covered like the place itself, after every other mount that can show
    // it. Empty in every common layout. ---
    for d in &input.linked_masks {
        let dest = d.abs.to_string_lossy().to_string();
        if d.is_dir {
            push(&["--tmpfs", &dest]);
        } else {
            push(&["--ro-bind", "/dev/null", &dest]);
        }
    }

    // --- the launcher's marker that the way to the system profiles file is
    // root's, read-only (a jail with no record, on a host with that file).
    // It lands on the `/run` tmpfs, among the last mounts, so nothing the
    // agent can write covers it. ---
    if let Some(fd) = input.profiles_marker_fd {
        push(&[
            "--ro-bind-data",
            &fd.to_string(),
            crate::agent_profiles::SYSTEM_PROFILES_MARKER_PATH,
        ]);
    }

    // --- the key of Active Defence on this host, read-only, just before the
    // record (`--identity` and a key only). Like the record it lands on the
    // `/run` tmpfs and no later option mounts anything, so it stays the
    // launcher's copy of the host's file. ---
    if let (true, Some(fd)) = (input.args.identity, input.key_fd) {
        push(&[
            "--ro-bind-data",
            &fd.to_string(),
            innerwarden_agent_guard::identity::JAIL_SPKI_PIN_PATH,
        ]);
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
    push(&JAIL_NAMESPACES);
    // After the record and every mount, like the rest of this block: the
    // seccomp filter bwrap applies to the jail's programs before the command
    // runs, where the launcher's start-up probe found the host takes it. In
    // every jail it refuses keystroke injection into a terminal and new
    // btrfs or bcachefs subvolumes and snapshots; with `--identity` also new
    // user namespaces and joining one, so the jail cannot rebuild what it was
    // refused. A defence in depth; it never changes the trust of the
    // instance.
    if let Some(fd) = input.seccomp_fd {
        push(&[SECCOMP_OPTION, &fd.to_string()]);
    }
    // An identified jail, filter or not: no capability for its programs, so
    // a launcher run as root does not hand them root's (`CAP_DROP_ALL`).
    // The plain jail is left as it was.
    if input.args.identity {
        push(&CAP_DROP_ALL);
    }
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

    // --- terminator + child: through the gate where the jail starts only
    // once admitted, so the jail itself refuses to start its command
    // without the record the launcher hands in after the admission ---
    push(&["--"]);
    match &input.gate_instance {
        Some(instance) => a.extend(launch::gated_child(
            &input.iw_binary,
            instance,
            &input.args.child,
        )),
        None => a.extend(input.args.child.iter().cloned()),
    }

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
    for d in MACOS_DOTDIR_DENY {
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
    // Where it leads, unless the jail leaves that place as it is
    // (`iw_config_left`, said by the launcher): onto what the jail needs,
    // the agent's settings among them, it must not be denied.
    let iw_cfg_real = input.iw_config_real.to_string_lossy().to_string();
    let deny_iw_real = iw_cfg_real != iw_cfg && !input.iw_config_left;
    if deny_iw_real {
        p.push_str(&format!(
            "(deny file-read* (subpath \"{}\"))\n",
            e(&iw_cfg_real)
        ));
    }
    // project secrets (glob-expanded + statted by the I/O layer into deny_paths),
    // the home paths a jail profile hides, as named and as they resolve, and
    // where a link leads a dotdir the sandbox denies (`~/.ssh` a link to
    // `.config/ssh`: the sandbox matches the place a link leads to, so the
    // deny of `~/.ssh` alone left `~/.config/ssh` readable and writable):
    for path in input
        .deny_paths
        .iter()
        .map(|d| d.abs.as_path())
        .chain(input.hide_denies.iter().map(PathBuf::as_path))
        .chain(input.linked_denies.iter().map(PathBuf::as_path))
    {
        p.push_str(&format!(
            "(deny file-read* (subpath \"{}\"))\n",
            e(&path.to_string_lossy())
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
    // dir stays unreadable/unwritable, and `~/.config` itself is closed to
    // renaming, removal and replacement ([`macos_pins`]).
    for w in MACOS_HOME_WRITABLE {
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
    // A profile's read-only paths (`extra_ro`), as the Linux jail lays
    // them: one outside the work, then the project's write again where
    // such a path holds it, then one inside the project, then a worktree's
    // folder's write again where a path holds it, then one inside it
    // ([`read_only_in_the_work`]). The sandbox lets the jail write whatever
    // the allows above name, the project among them, so without these a
    // read-only path in a folder the jail writes was written. Empty
    // unless a profile named some, so a jail without one is what it was.
    let deny_writing = |paths: Vec<PathBuf>, p: &mut String| {
        for path in paths {
            p.push_str(&format!(
                "(deny file-write* (subpath \"{}\"))\n",
                e(&path.to_string_lossy())
            ));
        }
    };
    let allow_again = |folder: &Path, under: &[PathBuf], p: &mut String| {
        if under.iter().any(|ro| folder.starts_with(ro)) {
            p.push_str(&format!(
                "(allow file-write* (subpath \"{}\"))\n",
                e(&folder.to_string_lossy())
            ));
        }
    };
    let outer_read_only = read_only_at(input, None);
    deny_writing(outer_read_only.clone(), &mut p);
    allow_again(&input.args.project, &outer_read_only, &mut p);
    let project_read_only = read_only_at(input, Some(PinRoot::Project));
    deny_writing(project_read_only.clone(), &mut p);
    if let Some(wt) = &input.worktree {
        let before: Vec<PathBuf> = outer_read_only
            .iter()
            .chain(&project_read_only)
            .cloned()
            .collect();
        allow_again(&wt.git_dir, &before, &mut p);
        allow_again(&wt.common_dir, &before, &mut p);
    }
    deny_writing(read_only_at(input, Some(PinRoot::Worktree)), &mut p);
    // write-denies LAST (nominal + resolved secret dir; then project secrets):
    p.push_str(&format!(
        "(deny file-write* (subpath \"{}\"))\n",
        e(&iw_cfg)
    ));
    if deny_iw_real {
        p.push_str(&format!(
            "(deny file-write* (subpath \"{}\"))\n",
            e(&iw_cfg_real)
        ));
    }
    for path in input
        .deny_paths
        .iter()
        .map(|d| d.abs.as_path())
        .chain(input.hide_denies.iter().map(PathBuf::as_path))
        .chain(input.linked_denies.iter().map(PathBuf::as_path))
    {
        p.push_str(&format!(
            "(deny file-write* (subpath \"{}\"))\n",
            e(&path.to_string_lossy())
        ));
    }
    // The project and the folders above a denied place that the jail may
    // write, `~/.config` among them, each kept in place as itself (never
    // what is in it): never renamed or removed from above a deny, nor
    // replaced by a link ([`macos_pins`], [`macos_pin_rule`]).
    for folder in macos_pins(input) {
        p.push_str(&macos_pin_rule(&folder));
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

/// Where the hook in a jail reads the person's suppressions: nothing. The
/// person's own file lives in the `~/.config/innerwarden` the jail hides,
/// and on Linux the jail's own folder there is an empty one it can write: a
/// `suppress.toml` a program in the jail planted there would lift the hook's
/// verdicts for the agent. `/dev/null` reads empty, and no program in the
/// jail can replace it.
pub const JAIL_SUPPRESS_CONFIG: &str = "/dev/null";

/// Where the hook in a jail reads the LLM second opinion's and the
/// notifications' config: nothing. An empty value is no value to either
/// reader, which then reads `~/.config/innerwarden/llm.toml` and
/// `notify.toml` in the jail's home, where on Linux a program in the jail
/// can write them: an `llm.toml` planted there sent every command the hook
/// reviews to an endpoint of the agent's choosing, and stalled the hook on
/// it, and a `notify.toml` fired webhooks of its choosing. `/dev/null`
/// reads empty, which configures neither, and no program in the jail can
/// replace it.
pub const JAIL_NO_CONFIG: &str = "/dev/null";

/// What the launcher says of InnerWarden's own folder as the jail starts:
/// that it is not visible, the API key with it, unless the jail leaves the
/// place a link leads it to as it is ([`JailInputs::iw_config_left`], said
/// before).
pub fn iw_folder_said(input: &JailInputs) -> &'static str {
    if input.iw_config_left {
        "  the agent's ~/.config/innerwarden is not visible inside the jail as named; the \
         place its link leads to is not hidden (said above)."
    } else {
        "  the agent's ~/.config/innerwarden (incl. the API key) is not visible inside the jail."
    }
}

/// The in-jail environment: redirect the graph to a jail-local writable file and
/// DISABLE the LLM second-opinion + notify inside the jail (their config lives in
/// the shadowed `~/.config/innerwarden`, so they must not be reached - blocking
/// still works from the embedded rules): both read their config from nothing
/// ([`JAIL_NO_CONFIG`]), never from the jail's home. `IW_GUARD_SESSION` groups
/// the narrative. The person's suppressions are read from nothing
/// ([`JAIL_SUPPRESS_CONFIG`]): a `suppress.toml` a program in the jail writes
/// never lifts a verdict.
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
        ("IW_LLM_CONFIG".to_string(), JAIL_NO_CONFIG.to_string()),
        ("IW_NOTIFY_CONFIG".to_string(), JAIL_NO_CONFIG.to_string()),
        ("IW_GUARD_SESSION".to_string(), JAIL_SESSION.to_string()),
        (
            "IW_SUPPRESS_CONFIG".to_string(),
            JAIL_SUPPRESS_CONFIG.to_string(),
        ),
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
        RESTRICTION_ADVICE_END.into(),
    ])
}

/// The last line of [`userns_restriction_advice`]: what `contain` says to
/// do once the profile is in place.
pub const RESTRICTION_ADVICE_END: &str = "  Then run this command again. Nothing was run.";

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
        INITIAL_PID_NS_INODE, LAUNCHER_RECORD_DIR, LAUNCH_SCHEMA, LAUNCH_SCHEMA_V1,
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

    /// The key descriptor a dry run shows, when the host has a key the
    /// launcher believes. A real run uses the pipe's own.
    pub const DRY_RUN_KEY_FD: i32 = 11;

    /// The profiles marker descriptor a dry run of a plain jail shows, when
    /// the host has a system profiles file. A real run uses the pipe's own.
    pub const DRY_RUN_MARKER_FD: i32 = 12;

    /// The seccomp filter descriptor a dry run shows, when the host takes the
    /// filter. A real run uses the pipe's own.
    pub const DRY_RUN_SECCOMP_FD: i32 = 13;

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
    // be refused by such a policy and kill the jail, so the jail uses none:
    // its seccomp filter (`--seccomp`, applied by bwrap after it built the
    // root, before the command runs) makes no namespace at all. Whether the
    // host takes the filter is learned before step 1, by a throwaway jail
    // (`filter_probe_argv`), and a launch is never started over: a failure at
    // step 3 comes after the jail reported its pid. Nothing here arms
    // anything. On Ubuntu 24.04 bwrap itself needs the AppArmor profile that
    // grants it `userns` (`userns_restriction_advice`, `flags=(unconfined)`).

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

    // -- the seccomp filter of the jail ---------------------------------------
    //
    // Every jail starts its programs under a seccomp filter
    // (`innerwarden_agent_guard::seccomp`): the terminal one, and with
    // `--identity` the identified one, which also closes user namespaces.
    // bwrap has taken a filter on a descriptor (`--seccomp`) since its first
    // releases, sets `no_new_privs` itself and applies the filter after it
    // built the jail, a setuid bwrap included. What can still stop it is the
    // host: a kernel without seccomp filters, a binary run under another
    // architecture's emulation (the filter would kill the jail's first
    // call), or a build for an architecture this one has no numbers for.
    // That is learned BEFORE the jail is built, by starting a throwaway jail
    // with the filter, and a launch is never started over. A host that cannot
    // take it runs the jail as it did before the filter, and says so. An
    // identified launch whose host does not take the identified filter falls
    // back to the terminal one, and says what it lost.
    //
    // Before Linux 4.8 the kernel ran the filter before a tracer could change
    // the call it was about to run: a program in the jail that traces another
    // (which the jail allows) could turn an allowed call into one the filter
    // refuses. On such a kernel the identified filter is never used, so no
    // record says user namespaces are closed, and the terminal one is said
    // to be weaker. A release that does not read as a version, or that could
    // not be read at all, is taken the same way, and said as unknown rather
    // than as older.

    /// The first kernel that runs the filter after a tracer's change of a
    /// call (`seccomp: run after ptrace`, 4.8, on x86_64 and aarch64 alike).
    pub const TRACER_SAFE_KERNEL: (u32, u32) = (4, 8);

    /// What a kernel's release says of the order of the filter and a
    /// tracer's change of a call.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TracerOrder {
        /// [`TRACER_SAFE_KERNEL`] or later: the filter runs after it.
        After,
        /// Older: the filter runs before it.
        Before,
        /// The release does not read as a version. Taken as [`Before`], the
        /// answer that claims nothing, and said as unknown.
        ///
        /// [`Before`]: TracerOrder::Before
        Unknown,
    }

    /// PURE. The order a kernel release (`uname -r`, as `6.12.10-orbstack`
    /// or `3.10.0-1160.el7.x86_64`) runs the filter and a tracer in.
    pub fn tracer_order(release: &str) -> TracerOrder {
        let mut parts = release.trim().split(['.', '-']);
        let number = |part: Option<&str>| -> Option<u32> {
            let part = part?;
            if part.is_empty() || part.len() > 6 || !part.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        };
        match (number(parts.next()), number(parts.next())) {
            (Some(major), Some(minor)) if (major, minor) >= TRACER_SAFE_KERNEL => {
                TracerOrder::After
            }
            (Some(_), Some(_)) => TracerOrder::Before,
            _ => TracerOrder::Unknown,
        }
    }

    /// Why an identified launch keeps user namespaces open in the jail.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum UsernsWhy {
        /// The throwaway jail with the identified filter did not exit 0.
        ProbeFailed,
        /// The kernel is older than [`TRACER_SAFE_KERNEL`].
        KernelTooOld,
        /// The kernel's release could not be read as a version: it is not
        /// one, or it was hidden (no `/proc`, and a `UNAME26` personality
        /// that rewrites `uname`).
        KernelUnknown,
        /// This build has no filter for the architecture it runs as.
        NotBuilt,
        /// The launcher could not hand the filter to bubblewrap, for its
        /// start-up probe or after it: it could not make the pipe, or start
        /// bwrap for want of its own descriptors, processes or memory
        /// ([`spawn_failed_answer`]). No bwrap ran under it.
        NotHanded,
    }

    impl UsernsWhy {
        /// The word the dry run and the launcher share.
        pub fn word(self) -> &'static str {
            match self {
                UsernsWhy::ProbeFailed => "userns_probe_failed",
                UsernsWhy::KernelTooOld => "userns_kernel_too_old",
                UsernsWhy::KernelUnknown => "userns_kernel_unknown",
                UsernsWhy::NotBuilt => "userns_filter_not_built",
                UsernsWhy::NotHanded => "userns_filter_not_handed",
            }
        }

        pub fn sentence(self) -> &'static str {
            match self {
                UsernsWhy::ProbeFailed => "Bubblewrap here could not start a jail with user namespaces closed, so the jail runs without that.",
                UsernsWhy::KernelTooOld => "This kernel is older than 4.8, where a program that traces another could get a call past the filter, so the jail runs without closing them.",
                UsernsWhy::KernelUnknown => "This kernel's release could not be read as a version (it is not one, or there is no /proc and a personality such as setarch --uname-2.6 hides it from uname), so it is taken as older than 4.8 and the jail runs without closing them.",
                UsernsWhy::NotBuilt => "This build has no sandbox filter for this architecture, so the jail runs without closing them.",
                UsernsWhy::NotHanded => "The launcher could not hand the sandbox filter to bubblewrap, so the jail runs without closing them.",
            }
        }
    }

    /// What else an identified jail runs without when its filter is not the
    /// identified one: the identified filter adds the namespace rules and
    /// the end of 32-bit programs to the plain jail's, and nothing more
    /// (a test of `innerwarden_agent_guard::seccomp` holds it), so with the
    /// user namespace line this names all it loses.
    pub const USERNS_OPEN_ALSO: &str =
        "Joining other namespaces stays open too, and a 32-bit program runs in the jail.";

    /// The line `contain --identity` prints (and a dry run shows) when user
    /// namespaces stay open, with the rest of what the identified filter
    /// would have refused ([`USERNS_OPEN_ALSO`]).
    pub fn userns_open_sentence(why: UsernsWhy) -> String {
        format!(
            "innerwarden contain: user namespaces stay open ({}): {} {USERNS_OPEN_ALSO}",
            why.word(),
            why.sentence()
        )
    }

    /// Why a jail runs without the terminal filter, or with a weaker one.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FilterWhy {
        /// The throwaway jail with the terminal filter did not exit 0: no
        /// filter.
        ProbeFailed,
        /// This build has no filter for the architecture it runs as: no
        /// filter.
        NotBuilt,
        /// The filter is in, and the kernel is older than
        /// [`TRACER_SAFE_KERNEL`].
        KernelTooOld,
        /// The filter is in, and the kernel's release could not be read as
        /// a version (as [`UsernsWhy::KernelUnknown`]): taken as older.
        KernelUnknown,
        /// The launcher could not hand the filter to bubblewrap, for its
        /// start-up probe or after it: it could not make the pipe, or start
        /// bwrap for want of its own descriptors, processes or memory
        /// ([`spawn_failed_answer`]). No filter.
        NotHanded,
    }

    impl FilterWhy {
        pub fn word(self) -> &'static str {
            match self {
                FilterWhy::ProbeFailed => "filter_probe_failed",
                FilterWhy::NotBuilt => "filter_not_built",
                FilterWhy::KernelTooOld => "filter_kernel_too_old",
                FilterWhy::KernelUnknown => "filter_kernel_unknown",
                FilterWhy::NotHanded => "filter_not_handed",
            }
        }

        pub fn sentence(self) -> &'static str {
            match self {
                FilterWhy::ProbeFailed => "Bubblewrap here could not start a jail with the sandbox filter, so programs in the jail can still inject keystrokes into your terminal and make new btrfs or bcachefs subvolumes or snapshots (a snapshot shows the files the jail hides).",
                FilterWhy::NotBuilt => "This build has no sandbox filter for this architecture, so programs in the jail can still inject keystrokes into your terminal and make new btrfs or bcachefs subvolumes or snapshots (a snapshot shows the files the jail hides).",
                FilterWhy::KernelTooOld => "This kernel is older than 4.8, where a program that traces another can get a call past the filter, so programs in the jail may still inject keystrokes into your terminal or make new btrfs or bcachefs subvolumes or snapshots (a snapshot shows the files the jail hides).",
                FilterWhy::KernelUnknown => "This kernel's release could not be read as a version (it is not one, or there is no /proc and a personality such as setarch --uname-2.6 hides it from uname), so it is taken as older than 4.8, where a program that traces another can get a call past the filter: programs in the jail may still inject keystrokes into your terminal or make new btrfs or bcachefs subvolumes or snapshots (a snapshot shows the files the jail hides).",
                FilterWhy::NotHanded => "The launcher could not hand the sandbox filter to bubblewrap, so programs in the jail can still inject keystrokes into your terminal and make new btrfs or bcachefs subvolumes or snapshots (a snapshot shows the files the jail hides).",
            }
        }
    }

    /// The line a launch prints (and its dry run shows) when its jail runs
    /// without the plain jail's filter (the terminal rule and the subvolume
    /// one), or with a weaker one.
    pub fn filter_sentence(why: FilterWhy) -> String {
        let what = match why {
            FilterWhy::ProbeFailed | FilterWhy::NotBuilt | FilterWhy::NotHanded => {
                "no sandbox filter"
            }
            FilterWhy::KernelTooOld | FilterWhy::KernelUnknown => "a weaker sandbox filter",
        };
        format!(
            "innerwarden contain: {what} ({}): {}",
            why.word(),
            why.sentence()
        )
    }

    /// What a throwaway jail under a filter (the start-up probe) answered.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ProbeAnswer {
        /// It ran under the filter and exited 0.
        Ran,
        /// bwrap did not start it, or it did not exit 0 in time.
        Failed,
        /// The launcher could not make the pipe that hands the filter in,
        /// or could not start bwrap for want of its own descriptors,
        /// processes or memory ([`spawn_failed_answer`]): no bwrap ran, the
        /// launcher's failure, not bubblewrap's.
        NotHanded,
    }

    /// PURE. What a start-up probe answers when the launcher could not
    /// start bwrap at all. Out of descriptors (`EMFILE`, `ENFILE`: the
    /// launcher opens `/dev/null` and a pipe of its own to start a
    /// program), of processes (`EAGAIN`) or of memory (`ENOMEM`), the
    /// launcher is what failed, and bwrap never ran: `NotHanded`. Any other
    /// error (bwrap not found, not permitted, not a program this kernel
    /// runs) is bubblewrap's side: `Failed`. Only the words differ: the
    /// jail runs without the filter either way.
    #[cfg(unix)]
    pub fn spawn_failed_answer(error: &std::io::Error) -> ProbeAnswer {
        match error.raw_os_error() {
            Some(libc::EMFILE | libc::ENFILE | libc::EAGAIN | libc::ENOMEM) => {
                ProbeAnswer::NotHanded
            }
            _ => ProbeAnswer::Failed,
        }
    }

    /// What the launcher reads of the host before it plans the filter.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FilterHost {
        /// This build has the call numbers of the architecture it runs as.
        pub built: bool,
        /// The order the kernel runs the filter and a tracer in
        /// ([`tracer_order`]).
        pub tracer: TracerOrder,
    }

    /// The filter a launch hands bwrap, and the lines it says about it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FilterPlan {
        /// `None`: the jail runs without a filter.
        pub filter: Option<innerwarden_agent_guard::seccomp::Rules>,
        /// What the launch says (and its dry run shows as comments), in
        /// order: the user namespace line, then the terminal one.
        pub said: Vec<String>,
    }

    impl FilterPlan {
        /// The record may say the jail's user namespaces are closed: only
        /// under the identified filter.
        pub fn close_userns(&self) -> bool {
            self.filter == Some(innerwarden_agent_guard::seccomp::Rules::Identified)
        }
    }

    /// PURE. The filter of a launch, from the host's facts and a throwaway
    /// jail under a filter (`probe`, which starts a process, so it is asked
    /// only where its answer decides something).
    ///
    /// * No numbers for this architecture: no filter, and no probe.
    /// * `--identity`: the identified filter, where the kernel is
    ///   [`TRACER_SAFE_KERNEL`] or later and its probe passed. Otherwise the
    ///   user namespace line, and the terminal filter as below.
    /// * The terminal filter where its probe passed (said to be weaker on a
    ///   kernel before 4.8), no filter otherwise, and the line that says it.
    /// * A probe whose filter could not be handed in, or whose bwrap the
    ///   launcher had not the means to start, ran no bwrap: its lines name
    ///   the launcher (`NotHanded`), never bubblewrap.
    pub fn filter_plan(
        identity: bool,
        host: FilterHost,
        mut probe: impl FnMut(innerwarden_agent_guard::seccomp::Rules) -> ProbeAnswer,
    ) -> FilterPlan {
        use innerwarden_agent_guard::seccomp::Rules;
        let mut said = Vec::new();
        if identity {
            let why = if !host.built {
                UsernsWhy::NotBuilt
            } else if host.tracer == TracerOrder::Before {
                UsernsWhy::KernelTooOld
            } else if host.tracer == TracerOrder::Unknown {
                UsernsWhy::KernelUnknown
            } else {
                match probe(Rules::Identified) {
                    ProbeAnswer::Ran => {
                        return FilterPlan {
                            filter: Some(Rules::Identified),
                            said,
                        }
                    }
                    ProbeAnswer::Failed => UsernsWhy::ProbeFailed,
                    ProbeAnswer::NotHanded => UsernsWhy::NotHanded,
                }
            };
            said.push(userns_open_sentence(why));
        }
        let filter = if !host.built {
            said.push(filter_sentence(FilterWhy::NotBuilt));
            None
        } else {
            match probe(Rules::Terminal) {
                ProbeAnswer::Ran => {
                    match host.tracer {
                        TracerOrder::After => {}
                        TracerOrder::Before => said.push(filter_sentence(FilterWhy::KernelTooOld)),
                        TracerOrder::Unknown => {
                            said.push(filter_sentence(FilterWhy::KernelUnknown))
                        }
                    }
                    Some(Rules::Terminal)
                }
                ProbeAnswer::Failed => {
                    said.push(filter_sentence(FilterWhy::ProbeFailed));
                    None
                }
                ProbeAnswer::NotHanded => {
                    said.push(filter_sentence(FilterWhy::NotHanded));
                    None
                }
            }
        };
        FilterPlan { filter, said }
    }

    /// The lines a launch says when the filter it planned could not be
    /// handed in after all (its pipe could not be made): the jail then runs
    /// without one. The cause is the launcher's, not bubblewrap's: the host
    /// had just started a jail under that filter.
    pub fn filter_lost_sentences(planned: innerwarden_agent_guard::seccomp::Rules) -> Vec<String> {
        let mut said = Vec::new();
        if planned == innerwarden_agent_guard::seccomp::Rules::Identified {
            said.push(userns_open_sentence(UsernsWhy::NotHanded));
        }
        said.push(filter_sentence(FilterWhy::NotHanded));
        said
    }

    /// What a dry run says about the jail's filter.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DryRunFilter {
        /// The host restricts unprivileged user namespaces and bwrap has no
        /// profile that grants it one ([`super::userns_restriction_advice`]):
        /// the real run stops there with this advice, so an identified dry
        /// run says it and a plain one says nothing. The probe, which could
        /// only fail for that same reason, is not run.
        Restricted(Vec<String>),
        /// What the real run would do.
        Plan(FilterPlan),
    }

    impl DryRunFilter {
        /// The filter the dry run shows in the argument list.
        pub fn filter(&self) -> Option<innerwarden_agent_guard::seccomp::Rules> {
            match self {
                DryRunFilter::Restricted(_) => None,
                DryRunFilter::Plan(plan) => plan.filter,
            }
        }

        /// The comment lines the dry run prints, none when the filter it
        /// would use is the one asked for, on a kernel that keeps it whole.
        pub fn lines(&self, identity: bool) -> Vec<String> {
            match self {
                DryRunFilter::Restricted(lines) if identity => lines
                    .iter()
                    .map(|line| format!("# {line}").trim_end().to_string())
                    .collect(),
                DryRunFilter::Restricted(_) => Vec::new(),
                DryRunFilter::Plan(plan) => {
                    plan.said.iter().map(|line| format!("# {line}")).collect()
                }
            }
        }
    }

    /// PURE. The restriction's advice first: where it applies, the dry run
    /// says that (or, without `--identity`, nothing) and never starts the
    /// probe, whose failure would name a cause that is not the one.
    /// Otherwise what the plan decides.
    pub fn dry_run_filter(
        advice: Option<Vec<String>>,
        plan: impl FnOnce() -> FilterPlan,
    ) -> DryRunFilter {
        match advice {
            Some(lines) => DryRunFilter::Restricted(lines),
            None => DryRunFilter::Plan(plan()),
        }
    }

    /// The arguments of the throwaway jail that tells whether the host takes
    /// the filter on descriptor `fd`: the filter, the namespaces the real
    /// jail unshares, for an identified launch the capabilities it drops,
    /// the host's root read-only, and a command that does nothing (run under
    /// the filter, so a filter that kills its first call fails the probe).
    pub fn filter_probe_argv(fd: i32, identity: bool) -> Vec<String> {
        let mut argv = vec![super::SECCOMP_OPTION.to_string(), fd.to_string()];
        argv.extend(super::JAIL_NAMESPACES.iter().map(|s| s.to_string()));
        if identity {
            argv.extend(super::CAP_DROP_ALL.iter().map(|s| s.to_string()));
        }
        argv.extend(["--ro-bind", "/", "/", "true"].map(String::from));
        argv
    }

    // -- the host's agent profiles, as the jail sees them --------------------
    //
    // Inside the jail's user namespace (a bwrap that is not setuid maps only
    // the user) the host's owners cannot be told apart: root's files and
    // every other account's show with the one overflow uid. The hook still
    // reads the system profiles file live, through the jail's read-only
    // `/etc`, so a revocation written on the host reaches a running jail, and
    // where the launcher proved the way to it takes that uid as root's
    // (`agent_profiles::system_owner_is_root`): an identified jail's record,
    // or the marker a plain jail gets. That is sound only for a way to the
    // file the launcher proved root's, with the real owners, before the jail
    // started: this check, which refuses the launch otherwise. Before every
    // identified jail, and before a plain one where the file exists; a plain
    // jail on a host without the file checks nothing and is today's.

    /// One entry on the way from `/` to the system profiles file, as the
    /// launcher reads it on the host (`symlink_metadata`: never followed).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum HostEntry {
        /// Not there, or in a folder closed to this user (the hook inside
        /// cannot look it up either).
        Absent,
        /// There, and its facts could not be read.
        Unreadable,
        Found {
            symlink: bool,
            dir: bool,
            file: bool,
            uid: u32,
            /// `st_mode`, so the permission bits are its low twelve.
            mode: u32,
        },
    }

    /// The way to the system profiles file, from `/` down to the file.
    pub fn system_profiles_chain() -> Vec<PathBuf> {
        let mut chain: Vec<PathBuf> =
            Path::new(innerwarden_agent_guard::profiles::SYSTEM_PROFILES_PATH)
                .ancestors()
                .map(Path::to_path_buf)
                .collect();
        chain.reverse();
        chain
    }

    /// What the launcher does about the system profiles file before a jail.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ProfilesChain {
        /// A plain jail on a host without the file: nothing is checked and
        /// nothing handed in, the jail is today's.
        NotAsked,
        /// The way to the file is root's alone; `file`: the file is there.
        Proven { file: bool },
        /// The launch stops, with this sentence.
        Refused(String),
    }

    impl ProfilesChain {
        /// A jail with no record gets the marker: the file is there and the
        /// way to it was proven.
        pub fn marks(&self) -> bool {
            matches!(self, ProfilesChain::Proven { file: true })
        }
    }

    /// PURE. What the launcher does about the way to the system profiles file
    /// ([`system_profiles_chain`], read on the host). An identified launch
    /// always checks it; a plain one only where the file is there (an entry
    /// that could not be inspected counts as there), so without the file a
    /// plain jail is what it always was.
    pub fn profiles_chain(identity: bool, chain: &[(PathBuf, HostEntry)]) -> ProfilesChain {
        let file = !matches!(chain.last(), None | Some((_, HostEntry::Absent)));
        if !identity && !file {
            return ProfilesChain::NotAsked;
        }
        match system_profiles_refusal(chain) {
            Some(why) => ProfilesChain::Refused(why),
            None => ProfilesChain::Proven { file },
        }
    }

    /// PURE. The one sentence that refuses a launch when the way
    /// to the system profiles file is not root's alone, or `None`. `chain` is
    /// each entry from `/` down to the file ([`system_profiles_chain`]). The
    /// walk ends at the first entry that is absent: only the owner of the
    /// folder above can make it, and that folder was root's.
    pub fn system_profiles_refusal(chain: &[(PathBuf, HostEntry)]) -> Option<String> {
        let last = chain.len().checked_sub(1)?;
        for (index, (path, entry)) in chain.iter().enumerate() {
            let path = path.display();
            let what = match *entry {
                HostEntry::Absent => return None,
                HostEntry::Unreadable => format!("{path} could not be inspected"),
                HostEntry::Found {
                    symlink: true, uid, ..
                } => {
                    format!("{path} is a symbolic link (owned by uid {uid})")
                }
                HostEntry::Found { uid, .. } if uid != 0 => {
                    format!("{path} is owned by uid {uid}, not root")
                }
                HostEntry::Found { mode, uid, .. } if mode & 0o022 != 0 => {
                    format!("{path} (owned by uid {uid}) can be written by its group or by others")
                }
                HostEntry::Found { file, uid, .. } if index == last && !file => {
                    format!("{path} (owned by uid {uid}) is not a regular file")
                }
                HostEntry::Found { dir, uid, .. } if index < last && !dir => {
                    format!("{path} (owned by uid {uid}) is not a folder")
                }
                HostEntry::Found { .. } => continue,
            };
            return Some(format!(
                "innerwarden contain: {what}, and a jail reads this host's agent profiles \
                 through it, so nothing was started."
            ));
        }
        None
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

    /// PURE. The parent pid in a `/proc/<pid>/stat` line: the field after
    /// the state, read after the last `)` (the command name may hold any
    /// byte, a `)` included).
    pub fn parse_parent_pid(stat: &str) -> Option<u32> {
        let (_, rest) = stat.rsplit_once(')')?;
        let mut fields = rest.split_whitespace();
        fields.next()?;
        fields.next()?.parse().ok()
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

    /// What the launcher says, and exits 2 on, when a profile starts the
    /// jail only once the host has admitted it and the host has not.
    pub const NOT_ADMITTED: &str = "Active Defence on this host did not admit this jail, and \
         its profile starts it only when admitted.";

    /// PURE. Whether Active Defence on this host admitted the jail: its
    /// answer, as the launcher believed it (no answer, or one not held to
    /// the host's key, is [`SystemScopeAdmission::NONE`]), says so, and the
    /// kernel shows the jail in its system scope. The answer alone is a
    /// claim; the scope is the fact the admission was made over.
    ///
    /// [`SystemScopeAdmission::NONE`]: innerwarden_agent_guard::identity::SystemScopeAdmission::NONE
    pub fn admitted_here(
        answer: &innerwarden_agent_guard::identity::SystemScopeAdmission,
        system_scope: Option<&Scope>,
    ) -> bool {
        answer.admitted && system_scope.is_some()
    }

    /// PURE. Whether the launcher hands the jail its record and lets the
    /// command start: always, unless the profile starts the jail only when
    /// admitted ([`JailStart::OnlyWhenAdmitted`]); then only when
    /// `admitted` ([`admitted_here`]). A jail it does not start is ended
    /// before the command runs, and the launcher exits 2 ([`NOT_ADMITTED`]).
    ///
    /// [`JailStart::OnlyWhenAdmitted`]: innerwarden_agent_guard::profiles::JailStart::OnlyWhenAdmitted
    pub fn starts(start: innerwarden_agent_guard::profiles::JailStart, admitted: bool) -> bool {
        use innerwarden_agent_guard::profiles::JailStart;
        match start {
            JailStart::Always => true,
            JailStart::OnlyWhenAdmitted => admitted,
        }
    }

    /// PURE. Whether the launcher hands the jail its record and lets its
    /// command start, from what it learned of the jail: for a record it
    /// made, the host's answer and the system scope the kernel showed;
    /// `None` when no record was made ([`starts`] of [`admitted_here`]).
    pub fn launch_starts(
        start: innerwarden_agent_guard::profiles::JailStart,
        made: Option<(
            &innerwarden_agent_guard::identity::SystemScopeAdmission,
            Option<&Scope>,
        )>,
    ) -> bool {
        starts(
            start,
            made.is_some_and(|(answer, scope)| admitted_here(answer, scope)),
        )
    }

    /// PURE. What the launcher reads of the answer to its request for a
    /// system scope held to the host's key: whether the host took it (and,
    /// when not, why, in words a person can act on), and the admission a
    /// `202` says. Any other answer admits nothing.
    pub fn scope_answer(
        result: Result<(u16, Vec<u8>), crate::host_decide_io::NoAnswer>,
    ) -> (
        Result<(), String>,
        innerwarden_agent_guard::identity::SystemScopeAdmission,
    ) {
        use innerwarden_agent_guard::identity::{SystemScopeAdmission, SYSTEM_SCOPE_TAKEN};
        match result {
            Ok((SYSTEM_SCOPE_TAKEN, answer)) => (Ok(()), SystemScopeAdmission::read(&answer)),
            Ok((status, _)) if (200..300).contains(&status) => (Ok(()), SystemScopeAdmission::NONE),
            Ok((status, _)) => (Err(format!("HTTP {status}")), SystemScopeAdmission::NONE),
            Err(why) => (Err(why.to_string()), SystemScopeAdmission::NONE),
        }
    }

    /// Why the launcher could not believe what the host answered about the
    /// jail ([`answer_unbelieved`]).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Unbelieved {
        /// It holds no key of Active Defence on this host.
        NoKey,
        /// The local agent's address (`url`) is not one a connection is held
        /// to the host's key over.
        Address(String),
    }

    /// PURE. Why the launcher could not believe the host's answer to its
    /// request for a system scope, or `None` when it could: it holds the
    /// host's key (`key_held`) and the local agent's address (`url`, `None`
    /// when the route is off and nothing was asked) is one a connection is
    /// held to it over. Without both, the answer's body is never read and
    /// nothing is admitted.
    pub fn answer_unbelieved(key_held: bool, url: Option<&str>) -> Option<Unbelieved> {
        let url = url?;
        if !key_held {
            return Some(Unbelieved::NoKey);
        }
        (!crate::host_decide_io::pinnable(url)).then(|| Unbelieved::Address(url.to_string()))
    }

    /// PURE. The line the launcher says, before [`NOT_ADMITTED`], when it
    /// could not believe the host's answer.
    pub fn unbelieved_sentence(why: &Unbelieved) -> String {
        match why {
            Unbelieved::NoKey => format!(
                "the host's answer about this jail cannot be believed without its key, and this \
                 launcher holds none ({} is not there, or not root's in folders only root can \
                 write)",
                innerwarden_agent_guard::identity::AGENT_TLS_SPKI_PATH
            ),
            Unbelieved::Address(url) => format!(
                "the host's answer about this jail cannot be believed: it is held to the host's \
                 key only at https://127.0.0.1, and the local agent's address is {url}"
            ),
        }
    }

    /// PURE. What the launcher says after [`NOT_ADMITTED`]: what to check,
    /// and which file makes the jail wait for the host (`files`, by path;
    /// both places when it could not tell). `unbelieved`: the launcher
    /// could not believe the host's answer ([`answer_unbelieved`]), so
    /// what to check is its key or the agent's address, not whether Active
    /// Defence runs.
    pub fn not_admitted_remedy(files: &[String], unbelieved: Option<&Unbelieved>) -> String {
        let place = if files.is_empty() {
            format!(
                "{} or ~/{}",
                innerwarden_agent_guard::profiles::SYSTEM_PROFILES_PATH,
                innerwarden_agent_guard::profiles::USER_PROFILES_PATH
            )
        } else {
            files.join(" and ")
        };
        let check = match unbelieved {
            None => "Check that Active Defence is running (systemctl status innerwarden-agent)"
                .to_string(),
            Some(Unbelieved::NoKey) => format!(
                "Check that Active Defence on this host publishes its key at {}, root's, in \
                 folders only root can write (an older Active Defence does not)",
                innerwarden_agent_guard::identity::AGENT_TLS_SPKI_PATH
            ),
            Some(Unbelieved::Address(_)) => format!(
                "Unset {}, or point it at https://127.0.0.1",
                crate::agent_report::AGENT_URL_VAR
            ),
        };
        format!(
            "{check}, then try again. The jail waits for it because of start = \
             \"only_when_admitted\" in {place}."
        )
    }

    /// The verb the jail's command starts through under a profile that
    /// starts the jail only once the host admitted it ([`gated_child`]).
    pub const GATE_VERB: &str = "contain-gate";

    /// What the gate says, and exits 2 on, when the jail holds no record of
    /// its admission.
    pub const GATE_REFUSED: &str = "this jail holds no record that the host admitted it, so \
         its command does not start.";

    /// PURE. The instance whose record the jail must hold before its command
    /// starts: only under a profile that starts the jail once the host
    /// admitted it ([`JailStart::OnlyWhenAdmitted`]).
    ///
    /// [`JailStart::OnlyWhenAdmitted`]: innerwarden_agent_guard::profiles::JailStart::OnlyWhenAdmitted
    pub fn gate_for(
        start: innerwarden_agent_guard::profiles::JailStart,
        instance_id: &str,
    ) -> Option<String> {
        (start == innerwarden_agent_guard::profiles::JailStart::OnlyWhenAdmitted)
            .then(|| instance_id.to_string())
    }

    /// PURE. The jail's command line through the gate: the launcher's own
    /// binary, bound read-only in the jail, starts the command only when
    /// the jail holds a record naming this instance ([`gate_opens`]). The
    /// launcher hands the record in only after the host admitted the jail,
    /// so a launcher that ends the jail, or dies (killed, Ctrl-C, the OOM
    /// killer) before the host answered, leaves an empty record, and the
    /// command never starts.
    pub fn gated_child(iw_binary: &Path, instance_id: &str, child: &[String]) -> Vec<String> {
        let mut argv = vec![
            iw_binary.to_string_lossy().into_owned(),
            GATE_VERB.to_string(),
            "--instance".to_string(),
            instance_id.to_string(),
            "--".to_string(),
        ];
        argv.extend(child.iter().cloned());
        argv
    }

    /// PURE. The gate's arguments, `--instance <id> -- <command...>`: the
    /// instance and the command, or `None` for anything else.
    pub fn parse_gate_args(args: &[String]) -> Option<(&str, &[String])> {
        match args {
            [flag, instance, end, command @ ..]
                if flag == "--instance" && end == "--" && !instance.is_empty() =>
            {
                (!command.is_empty()).then_some((instance.as_str(), command))
            }
            _ => None,
        }
    }

    /// PURE. Whether the gate starts the command: the record the jail holds
    /// reads as a launch record of this build and names `instance_id`. An
    /// empty record is the launcher's word that the host did not admit the
    /// jail, or that the launcher is gone.
    pub fn gate_opens(record: &[u8], instance_id: &str) -> bool {
        innerwarden_agent_guard::identity::parse_launch_record(record)
            .is_ok_and(|record| record.instance_id == instance_id)
    }

    /// PURE. The processes to end with a jail whose command must not run,
    /// in order: the jail's first process as bwrap reported it
    /// (`reported`), then those `/proc` lists as bwrap's (`listed`), each
    /// once and only while its parent is still `bwrap`. The reported one
    /// does not depend on the kernel listing children
    /// (`CONFIG_PROC_CHILDREN`), which a kernel built without
    /// `CHECKPOINT_RESTORE` does not.
    pub fn jail_processes_to_end(
        bwrap: u32,
        reported: Option<u32>,
        listed: &[u32],
        parent_of: impl Fn(u32) -> Option<u32>,
    ) -> Vec<u32> {
        let mut out = Vec::new();
        for pid in reported.into_iter().chain(listed.iter().copied()) {
            if !out.contains(&pid) && parent_of(pid) == Some(bwrap) {
                out.push(pid);
            }
        }
        out
    }

    /// PURE. The file `/etc/resolv.conf` names when it is a link into
    /// `/run` (`link` is what the link holds, as `readlink` reads it): the
    /// path it names, made absolute against `/etc` with its `.` and `..`
    /// steps worked out, when that is below `/run`. `None` for any other
    /// target: the jail's `/run` is empty, and only a file there would be
    /// lost.
    pub fn resolv_conf_target(link: &Path) -> Option<PathBuf> {
        use std::path::Component;
        let mut out = PathBuf::from("/");
        let joined = Path::new("/etc").join(link);
        for component in joined.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(name) => out.push(name),
                Component::Prefix(_) => return None,
            }
        }
        (out.starts_with("/run") && out != Path::new("/run")).then_some(out)
    }

    /// The folders under `/run` that hold a resolver file and nothing but
    /// resolver data: bound whole, so a file the resolver writes anew (by
    /// rename, as resolvconf does) reaches a running jail. Bound only while
    /// they hold no socket ([`resolv_conf_bind`]).
    pub const RESOLVER_ONLY_FOLDERS: &[&str] = &["/run/resolvconf"];

    /// PURE. What the jail binds read-only for the resolver file `target`
    /// ([`resolv_conf_target`]): its folder, where that is one of
    /// [`RESOLVER_ONLY_FOLDERS`] and `holds_sockets` says it holds no socket,
    /// so the jail follows the host's file when it is replaced; otherwise the
    /// file alone. A file bind keeps the file the jail started with: a
    /// resolver that replaces it (systemd-resolved, NetworkManager, whose
    /// folders hold sockets or connection files the jail must not see)
    /// leaves the jail with the names it had until the agent is restarted.
    pub fn resolv_conf_bind(target: &Path, holds_sockets: impl Fn(&Path) -> bool) -> PathBuf {
        match target.parent() {
            Some(folder)
                if RESOLVER_ONLY_FOLDERS
                    .iter()
                    .any(|only| folder == Path::new(only))
                    && !holds_sockets(folder) =>
            {
                folder.to_path_buf()
            }
            _ => target.to_path_buf(),
        }
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
    /// or not a plain absolute path (the XDG rule: a relative value is
    /// ignored). A value with a `..` in it is ignored too: the jail covers
    /// and pins the records folder by its spelling, and a folder above it
    /// spelled through `..` (`~/.local/state/../..`, the home itself) would
    /// be bound read-write over the jail's empty home. The value is taken
    /// as its plain steps, so `/var/./state` is `/var/state`.
    pub fn records_dir(xdg_state_home: Option<&str>, home: &Path) -> PathBuf {
        use std::path::Component;
        let plain = |dir: &Path| {
            dir.is_absolute()
                && dir
                    .components()
                    .all(|step| matches!(step, Component::RootDir | Component::Normal(_)))
        };
        match xdg_state_home.map(Path::new) {
            Some(dir) if plain(dir) => dir
                .components()
                .collect::<PathBuf>()
                .join(LAUNCHER_RECORD_DIR),
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
        /// The jail was started with user namespaces closed
        /// (`JailInputs::close_userns`). Writes schema 2; `false` writes the
        /// record an earlier build wrote.
        pub userns_closed: bool,
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
            // The newest schema only when the record needs what it added.
            schema: if facts.userns_closed {
                LAUNCH_SCHEMA
            } else {
                LAUNCH_SCHEMA_V1
            },
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
                userns_closed: facts.userns_closed.then_some(true),
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
            start: innerwarden_agent_guard::profiles::JailStart::Always,
            hide_home: vec![],
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
            iw_config_shown: vec![],
            iw_config_link: false,
            iw_config_left: false,
            linked_masks: vec![],
            linked_missing: vec![],
            linked_denies: vec![],
            hidden_targets: vec![],
            left: vec![],
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
            key_fd: None,
            profiles_marker_fd: None,
            records_dirs: vec![],
            child_env: vec![],
            close_userns: false,
            // A plain jail on a host that takes the terminal filter.
            seccomp_fd: Some(launch::DRY_RUN_SECCOMP_FD),
            hide_paths: vec![],
            hide_denies: vec![],
            // A host whose `/etc/resolv.conf` is a file of its own.
            resolv_conf: None,
            gate_instance: None,
            claude_state: ClaudeState::default(),
        }
    }

    /// The whole bwrap argument vector of today's jail, one token per line.
    /// Written before the identity flag existed: a jail launched without the
    /// flag must stay byte for byte this. One change since, on purpose: the
    /// terminal filter every jail starts under (`--seccomp`), pinned by
    /// [`the_plain_jail_moved_only_by_its_terminal_filter`].
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
        // M30C-5: never empty. An empty value is no value to the readers,
        // which then read the config in the jail's home, where a program in
        // the jail writes it.
        assert_eq!(env["IW_LLM_CONFIG"], "/dev/null");
        assert_eq!(env["IW_NOTIFY_CONFIG"], "/dev/null");
        assert_eq!(env["IW_SUPPRESS_CONFIG"], "/dev/null");
        let read_by_notify = |value: &str| {
            innerwarden_notify::config_path(|key| match key {
                "IW_NOTIFY_CONFIG" => Some(value.to_string()),
                "HOME" => Some("/home/dev".to_string()),
                _ => None,
            })
        };
        assert_eq!(
            read_by_notify(&env["IW_NOTIFY_CONFIG"]),
            Some(PathBuf::from("/dev/null"))
        );
        assert_eq!(
            read_by_notify(""),
            Some(PathBuf::from("/home/dev/.config/innerwarden/notify.toml")),
            "why the value is never empty"
        );
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

    /// The parent is read after the last `)`, so a command name that holds
    /// one cannot name another parent: the launcher signals only a process
    /// whose parent is its own bwrap.
    #[test]
    fn the_parent_pid_is_read_after_the_last_parenthesis() {
        use launch::parse_parent_pid;
        for comm in ["bwrap", "b) S 1 (x", ") R 4242", "("] {
            let stat = format!("2779 ({comm}) S 2778 2779 2779 0 -1");
            assert_eq!(parse_parent_pid(&stat), Some(2778), "comm {comm:?}");
        }
        assert_eq!(parse_parent_pid("2779 (bwrap) S"), None);
        assert_eq!(parse_parent_pid("2779 (bwrap) S x"), None);
        assert_eq!(parse_parent_pid("no parenthesis"), None);
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

    /// JP-1 (JAIL-PINS fixes): an `XDG_STATE_HOME` with a `..` in it was
    /// kept as spelled, so the records folder was
    /// `~/.local/state/../../.cache/st/innerwarden/instances`. The Linux
    /// jail pinned each folder above it by that spelling, and
    /// `~/.local/state/../..`, the home itself, counted as a folder of the
    /// `~/.local` bind: `--bind <home>/.local/state/../..` bound the host's
    /// home read-write over the jail's empty home (measured with bwrap 0.9:
    /// `~/.bashrc` and `~/.netrc` read and written from the jail). Such a
    /// value is ignored now, as a relative one is, and a plain one is taken
    /// as its plain steps.
    ///
    /// FAILS ON REVERT: keep any absolute value as spelled and the records
    /// folder holds the `..`.
    #[test]
    fn a_state_home_with_a_parent_step_is_ignored() {
        use launch::records_dir;
        let home = Path::new("/home/dev");
        let fallback = PathBuf::from("/home/dev/.local/state/innerwarden/instances");
        for odd in [
            "/home/dev/.local/state/../../.cache/st",
            "/home/dev/.local/state/..",
            "/..",
            "/var/state/../../home/dev",
        ] {
            assert_eq!(records_dir(Some(odd), home), fallback, "{odd}");
        }
        assert_eq!(
            records_dir(Some("/var/./state/"), home),
            PathBuf::from("/var/state/innerwarden/instances")
        );
        assert_eq!(
            records_dir(Some("/var/./state/"), home)
                .to_string_lossy()
                .as_ref(),
            "/var/state/innerwarden/instances"
        );
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
            userns_closed: false,
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

    // ---- the seccomp filter: user namespaces and the terminal ----

    /// A host that has every fact the identified filter needs.
    const WHOLE_HOST: launch::FilterHost = launch::FilterHost {
        built: true,
        tracer: launch::TracerOrder::After,
    };

    /// The probes a plan asked, in order, answering from `takes`.
    fn plan_with(
        identity: bool,
        host: launch::FilterHost,
        takes: &[innerwarden_agent_guard::seccomp::Rules],
    ) -> (
        launch::FilterPlan,
        Vec<innerwarden_agent_guard::seccomp::Rules>,
    ) {
        let mut asked = Vec::new();
        let plan = launch::filter_plan(identity, host, |rules| {
            asked.push(rules);
            if takes.contains(&rules) {
                launch::ProbeAnswer::Ran
            } else {
                launch::ProbeAnswer::Failed
            }
        });
        (plan, asked)
    }

    /// The identified filter, and with it `close_userns`, needs
    /// `--identity`, a build for this architecture, a kernel that runs the
    /// filter after a tracer, and a throwaway jail under it that exited 0.
    /// No version or mode of the bwrap file is read: every bwrap takes a
    /// filter on a descriptor, a setuid one included. A plain launch never
    /// probes the identified filter.
    ///
    /// FAILS ON REVERT: let the plan answer without the probe, use the
    /// identified filter on a kernel before 4.8, or probe it without
    /// `--identity`.
    #[test]
    fn user_namespaces_close_only_with_identity_a_safe_kernel_and_a_probe_that_passed() {
        use innerwarden_agent_guard::seccomp::Rules::{Identified, Terminal};
        let (plan, asked) = plan_with(true, WHOLE_HOST, &[Identified, Terminal]);
        assert_eq!(plan.filter, Some(Identified));
        assert!(plan.close_userns());
        assert!(plan.said.is_empty(), "{:?}", plan.said);
        assert_eq!(asked, [Identified]);

        let (plain, asked) = plan_with(false, WHOLE_HOST, &[Identified, Terminal]);
        assert_eq!(plain.filter, Some(Terminal));
        assert!(!plain.close_userns());
        assert!(plain.said.is_empty());
        assert_eq!(asked, [Terminal], "no identified probe without --identity");

        let old_kernel = launch::FilterHost {
            built: true,
            tracer: launch::TracerOrder::Before,
        };
        let (old, asked) = plan_with(true, old_kernel, &[Identified, Terminal]);
        assert_eq!(old.filter, Some(Terminal));
        assert!(!old.close_userns());
        assert_eq!(asked, [Terminal], "the identified probe is never asked");
    }

    /// An identified launch whose host does not take the identified filter
    /// keeps the keystroke rule where the host takes the terminal one, and
    /// says each thing it runs without: the user namespace line, then the
    /// keystroke line when no filter is left. A plain launch says only its
    /// own line. A build with no filter for its architecture probes nothing
    /// and says that, not that bubblewrap failed.
    ///
    /// FAILS ON REVERT: run an identified jail with no filter where the
    /// terminal one is taken, drop the keystroke line from an identified
    /// launch, or blame bubblewrap for a build with no numbers.
    #[test]
    fn a_launch_says_each_thing_its_jail_runs_without() {
        use innerwarden_agent_guard::seccomp::Rules::{Identified, Terminal};
        use launch::{
            filter_sentence, userns_open_sentence, FilterHost, FilterWhy, TracerOrder, UsernsWhy,
        };

        let (fallback, asked) = plan_with(true, WHOLE_HOST, &[Terminal]);
        assert_eq!(fallback.filter, Some(Terminal));
        assert!(!fallback.close_userns());
        assert_eq!(asked, [Identified, Terminal]);
        assert_eq!(
            fallback.said,
            [userns_open_sentence(UsernsWhy::ProbeFailed)]
        );

        let (none, _) = plan_with(true, WHOLE_HOST, &[]);
        assert_eq!(none.filter, None);
        assert_eq!(
            none.said,
            [
                userns_open_sentence(UsernsWhy::ProbeFailed),
                filter_sentence(FilterWhy::ProbeFailed)
            ]
        );
        let (plain_none, _) = plan_with(false, WHOLE_HOST, &[]);
        assert_eq!(plain_none.filter, None);
        assert_eq!(plain_none.said, [filter_sentence(FilterWhy::ProbeFailed)]);

        let old_kernel = FilterHost {
            built: true,
            tracer: TracerOrder::Before,
        };
        let (old, _) = plan_with(true, old_kernel, &[Identified, Terminal]);
        assert_eq!(
            old.said,
            [
                userns_open_sentence(UsernsWhy::KernelTooOld),
                filter_sentence(FilterWhy::KernelTooOld)
            ]
        );
        let (old_plain, _) = plan_with(false, old_kernel, &[Terminal]);
        assert_eq!(old_plain.filter, Some(Terminal));
        assert_eq!(old_plain.said, [filter_sentence(FilterWhy::KernelTooOld)]);

        let unbuilt = FilterHost {
            built: false,
            tracer: TracerOrder::After,
        };
        for identity in [true, false] {
            let (plan, asked) = plan_with(identity, unbuilt, &[Identified, Terminal]);
            assert_eq!(plan.filter, None);
            assert!(asked.is_empty(), "nothing to probe: {asked:?}");
            let mut said = Vec::new();
            if identity {
                said.push(userns_open_sentence(UsernsWhy::NotBuilt));
            }
            said.push(filter_sentence(FilterWhy::NotBuilt));
            assert_eq!(plan.said, said);
            assert!(plan.said.iter().all(|l| !l.contains("Bubblewrap")));
        }
    }

    /// Whoever turns a rule off says so. An identified launch that falls back
    /// from the identified filter, for any cause, names everything that
    /// filter adds to the plain one (`seccomp` holds that it adds nothing
    /// else): user namespaces, joining other namespaces and the end of
    /// 32-bit programs. A launch whose jail runs without the plain filter,
    /// or with a weaker one, names both of its rules: keystrokes into the
    /// terminal, and new btrfs or bcachefs subvolumes and snapshots.
    ///
    /// FAILS ON REVERT: drop [`launch::USERNS_OPEN_ALSO`] from the user
    /// namespace line, or the subvolume words from any line of a jail that
    /// runs without the plain filter.
    #[test]
    fn every_fallback_line_names_all_the_jail_runs_without() {
        use innerwarden_agent_guard::seccomp::Rules;
        use launch::{FilterHost, ProbeAnswer, TracerOrder};
        let hosts = [
            (true, TracerOrder::After),
            (true, TracerOrder::Before),
            (true, TracerOrder::Unknown),
            (false, TracerOrder::After),
        ];
        let answers = [
            ProbeAnswer::Ran,
            ProbeAnswer::Failed,
            ProbeAnswer::NotHanded,
        ];
        let mut fallbacks = 0;
        for (built, tracer) in hosts {
            for identified in answers {
                for terminal in answers {
                    for identity in [true, false] {
                        let plan =
                            launch::filter_plan(identity, FilterHost { built, tracer }, |rules| {
                                if rules == Rules::Identified {
                                    identified
                                } else {
                                    terminal
                                }
                            });
                        let mut said = plan.said.clone();
                        if let Some(rules) = plan.filter {
                            said.extend(launch::filter_lost_sentences(rules));
                        }
                        for line in &said {
                            if line.contains("user namespaces stay open") {
                                fallbacks += 1;
                                assert!(identity, "{line}");
                                for words in [
                                    "Joining other namespaces stays open too",
                                    "a 32-bit program runs in the jail",
                                ] {
                                    assert!(line.contains(words), "{words:?}: {line}");
                                }
                            } else {
                                assert!(line.contains("sandbox filter ("), "{line}");
                                for words in [
                                    "inject keystrokes into your terminal",
                                    "make new btrfs or bcachefs subvolumes or snapshots",
                                    "a snapshot shows the files the jail hides",
                                ] {
                                    assert!(line.contains(words), "{words:?}: {line}");
                                }
                            }
                        }
                        if identity && plan.filter != Some(Rules::Identified) {
                            assert!(
                                plan.said
                                    .iter()
                                    .any(|l| l.contains("user namespaces stay open")),
                                "{plan:?}"
                            );
                        }
                    }
                }
            }
        }
        assert!(fallbacks > 20, "{fallbacks}");
    }

    /// Two causes a launch names as what they are, not as another one. A
    /// kernel release that does not read as a version is taken as older
    /// than 4.8 (the terminal filter, said weaker; user namespaces left
    /// open) and said as unknown, never as "older than 4.8". A planned
    /// filter whose pipe could not be made, after bubblewrap had just
    /// started a jail under it, is the launcher's failure, never
    /// bubblewrap's: both losses for an identified one, the keystroke one
    /// for the terminal one. So is the same pipe lost for the start-up
    /// probe, which then started no bwrap.
    ///
    /// FAILS ON REVERT: take an unread release as an older kernel's words
    /// (`userns_kernel_too_old`), or say `filter_probe_failed` for a lost
    /// pipe, after the probe or for it.
    #[test]
    fn a_launch_names_an_unread_kernel_and_a_lost_pipe_as_what_they_are() {
        use innerwarden_agent_guard::seccomp::Rules::{Identified, Terminal};
        use launch::{
            filter_sentence, userns_open_sentence, FilterHost, FilterWhy, TracerOrder, UsernsWhy,
        };
        let unknown = FilterHost {
            built: true,
            tracer: TracerOrder::Unknown,
        };
        let (plan, asked) = plan_with(true, unknown, &[Identified, Terminal]);
        assert_eq!(plan.filter, Some(Terminal));
        assert!(!plan.close_userns());
        assert_eq!(asked, [Terminal], "the identified probe is never asked");
        assert_eq!(
            plan.said,
            [
                userns_open_sentence(UsernsWhy::KernelUnknown),
                filter_sentence(FilterWhy::KernelUnknown)
            ]
        );
        let (plain, _) = plan_with(false, unknown, &[Terminal]);
        assert_eq!(plain.filter, Some(Terminal));
        assert_eq!(plain.said, [filter_sentence(FilterWhy::KernelUnknown)]);
        for line in plan.said.iter().chain(&plain.said) {
            assert!(!line.contains("This kernel is older"), "{line}");
            assert!(line.contains("_kernel_unknown)"), "{line}");
        }

        let lost = launch::filter_lost_sentences(Identified);
        assert_eq!(
            lost,
            [
                userns_open_sentence(UsernsWhy::NotHanded),
                filter_sentence(FilterWhy::NotHanded)
            ]
        );
        assert_eq!(
            launch::filter_lost_sentences(Terminal),
            [filter_sentence(FilterWhy::NotHanded)]
        );
        for line in &lost {
            assert!(!line.contains("Bubblewrap here could not"), "{line}");
            assert!(!line.contains("_probe_failed"), "{line}");
            assert!(line.contains("The launcher could not hand"), "{line}");
        }

        // The same pipe lost for the start-up probe: no bwrap ran, so the
        // probe answers `NotHanded`, and the lines are the launcher's.
        for identity in [true, false] {
            let mut asked = Vec::new();
            let plan = launch::filter_plan(identity, WHOLE_HOST, |rules| {
                asked.push(rules);
                launch::ProbeAnswer::NotHanded
            });
            assert_eq!(plan.filter, None);
            let mut said = Vec::new();
            if identity {
                said.push(userns_open_sentence(UsernsWhy::NotHanded));
            }
            said.push(filter_sentence(FilterWhy::NotHanded));
            assert_eq!(plan.said, said, "identity {identity}");
            let probes: &[_] = if identity {
                &[Identified, Terminal]
            } else {
                &[Terminal]
            };
            assert_eq!(asked, probes);
            for line in &plan.said {
                assert!(!line.contains("Bubblewrap here could not"), "{line}");
                assert!(!line.contains("_probe_failed"), "{line}");
            }
        }
    }

    /// A bwrap the launcher could not start for want of its own means (out
    /// of descriptors, processes or memory) never ran, so the probe answers
    /// as the launcher's failure; one that is not there, not permitted or
    /// not a program is bubblewrap's side, as is an error with no number.
    ///
    /// FAILS ON REVERT: answer every failed start `Failed` (an `EMFILE`
    /// start is then said as "Bubblewrap here could not start a jail"), or
    /// every one `NotHanded` (a missing bwrap is said as the launcher's).
    #[cfg(unix)]
    #[test]
    fn a_bwrap_the_launcher_could_not_start_is_said_as_the_launchers() {
        use launch::{spawn_failed_answer, ProbeAnswer};
        let answer = |errno| spawn_failed_answer(&std::io::Error::from_raw_os_error(errno));
        for errno in [libc::EMFILE, libc::ENFILE, libc::EAGAIN, libc::ENOMEM] {
            assert_eq!(answer(errno), ProbeAnswer::NotHanded, "errno {errno}");
        }
        for errno in [libc::ENOENT, libc::EACCES, libc::ENOEXEC, libc::ETXTBSY] {
            assert_eq!(answer(errno), ProbeAnswer::Failed, "errno {errno}");
        }
        assert_eq!(
            spawn_failed_answer(&std::io::Error::other("no number")),
            ProbeAnswer::Failed
        );
    }

    /// The kernel's release, as `uname -r` gives it: 4.8 or later runs the
    /// filter after a tracer changed the call, an older one before it, and
    /// a release that does not read as a version is unknown (taken as
    /// older, said as unknown).
    ///
    /// FAILS ON REVERT: compare the major number alone (4.4 passes), take
    /// a release that does not read as safe, or as an older kernel.
    #[test]
    fn a_kernel_from_4_8_runs_the_filter_after_a_tracer() {
        use launch::{tracer_order, TracerOrder};
        for release in [
            "4.8.0",
            "4.8",
            "4.15.0-20-generic",
            "5.4.0-42-generic\n",
            "6.12.10-orbstack-00297-gf8f6e015b993",
            "7.0.0-1011-azure",
            "10.0.1",
        ] {
            assert_eq!(tracer_order(release), TracerOrder::After, "{release}");
        }
        for release in [
            "4.7.10",
            "4.4.0-210-generic",
            "3.10.0-1160.el7.x86_64",
            "2.6.32",
        ] {
            assert_eq!(tracer_order(release), TracerOrder::Before, "{release}");
        }
        for release in ["", "4", "v6.1", "6.x", "99999999.1", "-6.1", "\n"] {
            assert_eq!(tracer_order(release), TracerOrder::Unknown, "{release:?}");
        }
    }

    /// The sentences the launcher and the dry run say, word for word; the
    /// dashboard's line for a jail that closed them names the filter, and no
    /// word of the bwrap version or mode is left anywhere.
    #[test]
    fn the_filter_words_are_the_closed_table() {
        use launch::{filter_sentence, userns_open_sentence, FilterWhy, UsernsWhy};
        let why = UsernsWhy::ProbeFailed;
        assert_eq!(why.word(), "userns_probe_failed");
        assert_eq!(
            why.sentence(),
            "Bubblewrap here could not start a jail with user namespaces closed, so the jail runs without that."
        );
        assert_eq!(
            userns_open_sentence(why),
            "innerwarden contain: user namespaces stay open (userns_probe_failed): Bubblewrap here could not start a jail with user namespaces closed, so the jail runs without that. Joining other namespaces stays open too, and a 32-bit program runs in the jail."
        );
        assert_eq!(
            userns_open_sentence(UsernsWhy::KernelTooOld),
            "innerwarden contain: user namespaces stay open (userns_kernel_too_old): This kernel is older than 4.8, where a program that traces another could get a call past the filter, so the jail runs without closing them. Joining other namespaces stays open too, and a 32-bit program runs in the jail."
        );
        assert_eq!(
            userns_open_sentence(UsernsWhy::NotBuilt),
            "innerwarden contain: user namespaces stay open (userns_filter_not_built): This build has no sandbox filter for this architecture, so the jail runs without closing them. Joining other namespaces stays open too, and a 32-bit program runs in the jail."
        );
        assert_eq!(
            userns_open_sentence(UsernsWhy::KernelUnknown),
            "innerwarden contain: user namespaces stay open (userns_kernel_unknown): This kernel's release could not be read as a version (it is not one, or there is no /proc and a personality such as setarch --uname-2.6 hides it from uname), so it is taken as older than 4.8 and the jail runs without closing them. Joining other namespaces stays open too, and a 32-bit program runs in the jail."
        );
        assert_eq!(
            userns_open_sentence(UsernsWhy::NotHanded),
            "innerwarden contain: user namespaces stay open (userns_filter_not_handed): The launcher could not hand the sandbox filter to bubblewrap, so the jail runs without closing them. Joining other namespaces stays open too, and a 32-bit program runs in the jail."
        );
        assert_eq!(
            filter_sentence(FilterWhy::ProbeFailed),
            "innerwarden contain: no sandbox filter (filter_probe_failed): Bubblewrap here could not start a jail with the sandbox filter, so programs in the jail can still inject keystrokes into your terminal and make new btrfs or bcachefs subvolumes or snapshots (a snapshot shows the files the jail hides)."
        );
        assert_eq!(
            filter_sentence(FilterWhy::NotBuilt),
            "innerwarden contain: no sandbox filter (filter_not_built): This build has no sandbox filter for this architecture, so programs in the jail can still inject keystrokes into your terminal and make new btrfs or bcachefs subvolumes or snapshots (a snapshot shows the files the jail hides)."
        );
        assert_eq!(
            filter_sentence(FilterWhy::KernelTooOld),
            "innerwarden contain: a weaker sandbox filter (filter_kernel_too_old): This kernel is older than 4.8, where a program that traces another can get a call past the filter, so programs in the jail may still inject keystrokes into your terminal or make new btrfs or bcachefs subvolumes or snapshots (a snapshot shows the files the jail hides)."
        );
        assert_eq!(
            filter_sentence(FilterWhy::KernelUnknown),
            "innerwarden contain: a weaker sandbox filter (filter_kernel_unknown): This kernel's release could not be read as a version (it is not one, or there is no /proc and a personality such as setarch --uname-2.6 hides it from uname), so it is taken as older than 4.8, where a program that traces another can get a call past the filter: programs in the jail may still inject keystrokes into your terminal or make new btrfs or bcachefs subvolumes or snapshots (a snapshot shows the files the jail hides)."
        );
        assert_eq!(
            filter_sentence(FilterWhy::NotHanded),
            "innerwarden contain: no sandbox filter (filter_not_handed): The launcher could not hand the sandbox filter to bubblewrap, so programs in the jail can still inject keystrokes into your terminal and make new btrfs or bcachefs subvolumes or snapshots (a snapshot shows the files the jail hides)."
        );
        let words = include_str!("../../dashboard-kit/web/src/community/words.ts");
        assert!(words.contains(
            "export const USERNS_CLOSED_WORDS = \"User namespaces closed inside the jail (sandbox filter).\";"
        ));
        for gone in [
            "bwrap_too_old",
            "bwrap_setuid",
            "older than 0.8",
            "runs setuid",
        ] {
            assert!(!words.contains(gone), "words.ts still says {gone}");
        }
        let lines = [
            UsernsWhy::ProbeFailed,
            UsernsWhy::KernelTooOld,
            UsernsWhy::KernelUnknown,
            UsernsWhy::NotBuilt,
            UsernsWhy::NotHanded,
        ]
        .map(userns_open_sentence)
        .into_iter()
        .chain(
            [
                FilterWhy::ProbeFailed,
                FilterWhy::NotBuilt,
                FilterWhy::KernelTooOld,
                FilterWhy::KernelUnknown,
                FilterWhy::NotHanded,
            ]
            .map(filter_sentence),
        );
        for line in lines {
            assert!(!line.contains('\u{2014}'), "{line}");
        }
    }

    /// On a host whose kernel restricts unprivileged user namespaces, with no
    /// profile for bwrap, a dry run of an identified launch says the real
    /// cause (the advice the real run stops with) and never starts the probe,
    /// which there could only fail and name `userns_probe_failed` instead. A
    /// plain dry run probes nothing there either, and says nothing.
    ///
    /// FAILS ON REVERT: run the probe before the advice is looked at.
    #[test]
    fn a_dry_run_says_the_restriction_and_never_probes_where_it_applies() {
        use innerwarden_agent_guard::seccomp::Rules::{Identified, Terminal};
        use launch::{dry_run_filter, DryRunFilter};
        let advice = userns_restriction_advice(Some("1\n"), false, Path::new("/usr/bin/bwrap"));
        let said = dry_run_filter(advice.clone(), || {
            panic!("the probe is not started where the advice applies")
        });
        assert_eq!(said, DryRunFilter::Restricted(advice.clone().unwrap()));
        assert_eq!(said.filter(), None);
        let lines = said.lines(true);
        assert_eq!(lines.len(), advice.unwrap().len());
        assert!(lines.iter().all(|line| line.starts_with('#')), "{lines:?}");
        assert!(lines[0].starts_with(
            "# innerwarden contain: this kernel restricts unprivileged user namespaces"
        ));
        assert!(!lines
            .iter()
            .any(|line| line.contains("userns_probe_failed")));
        assert!(said.lines(false).is_empty(), "a plain dry run says nothing");

        // No restriction: what the plan says, as comments.
        let (plan, _) = plan_with(true, WHOLE_HOST, &[]);
        let open = dry_run_filter(None, || plan.clone());
        assert_eq!(
            open.lines(true),
            plan.said
                .iter()
                .map(|l| format!("# {l}"))
                .collect::<Vec<_>>()
        );
        assert_eq!(open.lines(true).len(), 2);
        assert_eq!(open.filter(), None);
        let (taken, _) = plan_with(true, WHOLE_HOST, &[Identified]);
        let closed = dry_run_filter(None, || taken);
        assert_eq!(closed.filter(), Some(Identified));
        assert!(closed.lines(true).is_empty());
        let (terminal, _) = plan_with(false, WHOLE_HOST, &[Terminal]);
        assert_eq!(dry_run_filter(None, || terminal).filter(), Some(Terminal));
    }

    /// The start-up probe starts a jail under the filter on its descriptor,
    /// with the namespaces the jail unshares, for an identified launch with
    /// the capabilities dropped as its jail drops them, and runs nothing; the
    /// jail puts the filter right after those namespaces.
    ///
    /// FAILS ON REVERT: probe without the filter, or drop a namespace from
    /// `JAIL_NAMESPACES`' use in the probe, or probe an identified launch
    /// without its capability drop.
    #[test]
    fn the_probe_starts_a_jail_under_the_filter_with_the_jails_namespaces() {
        let argv = launch::filter_probe_argv(21, false);
        assert_eq!(&argv[..2], ["--seccomp", "21"]);
        assert_eq!(&argv[2..5], JAIL_NAMESPACES);
        assert_eq!(&argv[5..], ["--ro-bind", "/", "/", "true"]);
        let identified = launch::filter_probe_argv(21, true);
        assert_eq!(&identified[..5], &argv[..5]);
        assert_eq!(&identified[5..7], CAP_DROP_ALL);
        assert_eq!(&identified[7..], &argv[5..]);
        for mut input in [inputs(&["claude", "--print"]), identified_inputs()] {
            input.seccomp_fd = Some(21);
            let jail = build_linux_jail(&input).unwrap().bwrap_args;
            let at = jail
                .windows(JAIL_NAMESPACES.len())
                .position(|w| w == JAIL_NAMESPACES)
                .expect("the jail unshares these");
            assert_eq!(&jail[at + 3..at + 5], ["--seccomp", "21"]);
            assert_eq!(jail.iter().filter(|a| *a == "--seccomp").count(), 1);
        }
    }

    /// Every identified jail drops every capability, under a filter or not,
    /// so a launcher run as root hands its programs none of root's (bwrap
    /// keeps them for uid 0 and runs that jail in the host's user
    /// namespace). A plain jail never asks for it: it moved by its terminal
    /// filter only.
    ///
    /// FAILS ON REVERT: drop `--cap-drop ALL` from the identified jail (as
    /// root, `unshare -n` and a mount over the record then work inside it),
    /// or emit it in the plain one.
    #[test]
    fn every_identified_jail_drops_every_capability_and_no_plain_one_does() {
        let mut cases = Vec::new();
        for filter in [None, Some(launch::DRY_RUN_SECCOMP_FD)] {
            let mut identified = identified_inputs();
            identified.seccomp_fd = filter;
            identified.close_userns = filter.is_some();
            cases.push((identified, true));
            let mut plain = inputs(&["claude", "--print"]);
            plain.seccomp_fd = filter;
            cases.push((plain, false));
        }
        for (input, identity) in cases {
            let got = build_linux_jail(&input).unwrap().bwrap_args;
            let drops = got.windows(2).filter(|w| w == &CAP_DROP_ALL).count();
            assert_eq!(drops, usize::from(identity), "{got:?}");
            assert_eq!(
                got.iter().filter(|a| *a == "--cap-drop").count(),
                usize::from(identity)
            );
            assert!(!got.iter().any(|a| a == "--cap-add"));
            if identity {
                let at = got.windows(2).position(|w| w == CAP_DROP_ALL).unwrap();
                let terminator = got.iter().position(|a| a == "--").unwrap();
                assert!(at < terminator, "before the command");
            }
        }
        assert_eq!(CAP_DROP_ALL, ["--cap-drop", "ALL"]);
    }

    /// With `--identity` and a host that takes the identified filter, the
    /// filter follows the namespaces, then the capability drop, and nothing
    /// of the user namespace option that came before it is left: no second
    /// user namespace.
    ///
    /// FAILS ON REVERT: emit `--unshare-user --disable-userns` again.
    #[test]
    fn golden_argv_of_an_identified_jail_with_user_namespaces_closed() {
        let mut input = identified_inputs();
        input.close_userns = true;
        input.seccomp_fd = Some(launch::DRY_RUN_SECCOMP_FD);
        let got = build_linux_jail(&input).unwrap().bwrap_args.join("\n");
        assert_eq!(
            got,
            GOLDEN_ARGV_IDENTIFIED.replace("--unshare-ipc\n", "--unshare-ipc\n--seccomp\n13\n")
        );
        assert!(got.contains("--unshare-ipc\n--seccomp\n13\n--cap-drop\nALL\n--hostname\n"));
        assert_ne!(got, GOLDEN_ARGV_IDENTIFIED);
        assert!(!got.contains("--disable-userns") && !got.contains("--unshare-user"));
    }

    /// `close_userns` is the record's fact and puts nothing in the argv; the
    /// filter is the descriptor. An identified jail whose host did not take
    /// the filter is the jail the previous build made with its probe
    /// failing, plus the capability drop, Claude Code's own state
    /// ([`CLAUDE_STATE_LINES`], [`CLAUDE_FOLDER_LINES`]) and the pins of the
    /// records' folders ([`RECORDS_PIN_LINES`]) and nothing else (the hash
    /// is of the golden at 4ded5fea), and a plain one without the filter is
    /// that build's, byte for byte.
    ///
    /// FAILS ON REVERT: emit anything for `close_userns`, or emit the filter
    /// without a descriptor, or move anything else in the identified jail.
    #[test]
    fn the_filter_needs_its_descriptor_and_otherwise_the_argv_is_the_previous_builds() {
        use crate::observe::sha256_hex;
        let mut plain = inputs(&["claude", "--print"]);
        plain.close_userns = true;
        assert_eq!(
            build_linux_jail(&plain).unwrap().bwrap_args.join("\n"),
            GOLDEN_ARGV_PLAIN
        );
        // Identified, the probe failed: the 4ded5fea golden, the drop and
        // Claude Code's own state.
        let old = identified_inputs();
        let got = build_linux_jail(&old).unwrap().bwrap_args.join("\n");
        assert_eq!(got, GOLDEN_ARGV_IDENTIFIED);
        assert_eq!(got.matches("--cap-drop\nALL\n").count(), 1);
        assert_eq!(got.matches(CLAUDE_STATE_LINES).count(), 1);
        assert_eq!(got.matches(CLAUDE_FOLDER_LINES).count(), 1);
        assert_eq!(got.matches(RECORDS_PIN_LINES).count(), 1);
        let before = got
            .replacen("--unshare-ipc\n--cap-drop\nALL\n", "--unshare-ipc\n", 1)
            .replacen(CLAUDE_STATE_LINES, "", 1)
            .replacen(CLAUDE_FOLDER_LINES, "", 1)
            .replacen(RECORDS_PIN_LINES, "", 1);
        assert_eq!(
            sha256_hex(before.as_bytes()),
            "648f991ed81d228baa0f4c080f5eb53c6fe864d6e4c5be6f3660da6bffbb5044"
        );
        let mut said_closed = identified_inputs();
        said_closed.close_userns = true;
        assert_eq!(
            build_linux_jail(&said_closed)
                .unwrap()
                .bwrap_args
                .join("\n"),
            GOLDEN_ARGV_IDENTIFIED
        );
    }

    /// The plain jail's argument vector moved by one pair since the build
    /// before the filter, the terminal filter, on purpose, and by nothing
    /// else. Without the filter (a host whose probe failed) it is
    /// that build's, to the byte (the hashes are of the goldens at 4ded5fea).
    ///
    /// FAILS ON REVERT: move or add anything else in the plain jail.
    #[test]
    fn the_plain_jail_moved_only_by_its_terminal_filter() {
        use crate::observe::sha256_hex;
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
        for (mut input, golden, before) in [
            (
                inputs(&["claude", "--print"]),
                GOLDEN_ARGV_PLAIN,
                "d431bc2766d7a4d45b4bd7cd773e64ba5990b9f6b7967e99165f527f5316dff1",
            ),
            (
                rich,
                GOLDEN_ARGV_RICH,
                "0aa4fbb5a6c3452d3d68997c66f488e545c70e767268c6cfa5c37fe9fade3200",
            ),
        ] {
            assert_eq!(golden.matches("--seccomp").count(), 1);
            let without = golden.replacen("\n--seccomp\n13\n", "\n", 1);
            assert_eq!(sha256_hex(without.as_bytes()), before);
            input.seccomp_fd = None;
            assert_eq!(
                build_linux_jail(&input).unwrap().bwrap_args.join("\n"),
                without
            );
        }
    }

    /// The record names `userns_closed` only when the option was used, and
    /// then is schema 2. Every other record is the schema 1 an earlier build
    /// wrote, to the byte.
    ///
    /// FAILS ON REVERT: write schema 2 always, or write the field without the
    /// fact.
    #[test]
    fn a_record_says_userns_closed_only_when_the_option_was_used() {
        use innerwarden_agent_guard::identity::parse_launch_record;
        let (mode, launcher, project) = (
            Mode::Enforce,
            Path::new("/usr/local/bin/innerwarden"),
            Path::new("/home/dev/work/my-app"),
        );
        let old = launch::assemble_record(launch_facts(&mode, launcher, project)).unwrap();
        assert_eq!(old.schema, 1);
        assert_eq!(old.jail.userns_closed, None);
        let json = String::from_utf8(serde_json::to_vec(&old).unwrap()).unwrap();
        assert_eq!(
            json,
            r#"{"schema":1,"instance_id":"07070707070707070707070707070707","agent_type":"claude-code","launcher":{"path":"/usr/local/bin/innerwarden","version":"1.5.5","root_owned":true},"uid":1000,"project":"my-app","mode":"enforce","started_at":"2026-10-16T12:00:00Z","jail":{"backend":"bwrap","pid":2778,"start_ticks":123456,"pid_ns":4026532220,"mnt_ns":4026532218}}"#,
            "the record an earlier build wrote, to the byte"
        );
        let mut closed_facts = launch_facts(&mode, launcher, project);
        closed_facts.userns_closed = true;
        let closed = launch::assemble_record(closed_facts).unwrap();
        assert_eq!(closed.schema, 2);
        assert_eq!(closed.jail.userns_closed, Some(true));
        let json2 = String::from_utf8(serde_json::to_vec(&closed).unwrap()).unwrap();
        assert_eq!(
            json2,
            json.replacen(r#""schema":1"#, r#""schema":2"#, 1).replacen(
                r#""mnt_ns":4026532218}"#,
                r#""mnt_ns":4026532218,"userns_closed":true}"#,
                1
            )
        );
        assert_eq!(parse_launch_record(json2.as_bytes()).unwrap(), closed);
        assert_eq!(parse_launch_record(json.as_bytes()).unwrap(), old);
    }

    /// What this build assembles without the option is a record this build's
    /// own reader (and the writer's `validate`) accepts: a reader that took
    /// only the newest schema would refuse every record the build still
    /// writes at 1.
    ///
    /// FAILS ON REVERT: make `validate` compare the schema to `LAUNCH_SCHEMA`
    /// again.
    #[test]
    fn a_v1_assembled_by_this_build_validates() {
        let (mode, launcher, project) = (
            Mode::Monitor,
            Path::new("/usr/local/bin/innerwarden"),
            Path::new("/home/dev/work/my-app"),
        );
        let record = launch::assemble_record(launch_facts(&mode, launcher, project)).unwrap();
        assert_eq!(
            record.schema,
            innerwarden_agent_guard::identity::LAUNCH_SCHEMA_V1
        );
        assert!(record.validate().is_ok());
        let mut v2 = launch_facts(&mode, launcher, project);
        v2.userns_closed = true;
        assert!(launch::assemble_record(v2).unwrap().validate().is_ok());
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
        "--seccomp",
        "--cap-drop",
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
        // Each jail twice: without the filter (a host whose probe failed) and
        // with the identified one. Only the second proves where it goes.
        let mut cases = Vec::new();
        for (input, golden) in [
            (inputs(&["claude", "--print"]), GOLDEN_ARGV_PLAIN),
            (rich, GOLDEN_ARGV_RICH),
        ] {
            for close in [false, true] {
                cases.push((input.clone(), golden, close));
            }
        }
        for (mut input, golden, close) in cases {
            input.args.identity = true;
            input.close_userns = close;
            input.seccomp_fd = close.then_some(launch::DRY_RUN_SECCOMP_FD);
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
            // Without its additions the jail is exactly today's.
            let mut without = got.clone();
            without.drain(at..at + 3);
            let info = without.iter().position(|a| a == "--info-fd").unwrap();
            without.drain(info..info + 2);
            if close {
                // The filter comes after the record and every mount, and
                // only with its descriptor.
                let filter = got
                    .windows(2)
                    .position(|w| w[0] == "--seccomp" && w[1] == "13")
                    .expect("--seccomp 13");
                assert!(at + 3 <= filter, "the filter follows the record");
                assert!(
                    got[filter + 2..terminator]
                        .iter()
                        .all(|a| a != "--bind" && a != "--ro-bind" && a != "--tmpfs"),
                    "no mount follows the filter"
                );
            } else {
                assert!(!got.iter().any(|a| a == "--seccomp"));
            }
            assert!(!got
                .iter()
                .any(|a| a == "--disable-userns" || a == "--unshare-user"));
            // Without the record, its descriptor, the filter and the
            // capability drop, the jail is the plain one without its filter.
            if let Some(at_filter) = without.iter().position(|a| a == "--seccomp") {
                without.drain(at_filter..at_filter + 2);
            }
            let drop = without
                .windows(2)
                .position(|w| w == CAP_DROP_ALL)
                .expect("an identified jail drops every capability");
            without.drain(drop..drop + 2);
            assert_eq!(
                without.join("\n"),
                golden.replacen("\n--seccomp\n13\n", "\n", 1)
            );
        }
    }

    /// The key the launcher read on the host is mounted read-only beside the
    /// record: after the `/run` tmpfs, just before the record, which stays
    /// last of the mounts. Only with `--identity` and a key: without a key the
    /// argv is today's identified jail, byte for byte, and without the flag a
    /// descriptor changes nothing.
    ///
    /// FAILS ON REVERT: drop the key mount (the hook in a jail whose bwrap is
    /// not setuid has no key it may believe, so it never asks), or mount it
    /// with `--bind-data`, or after the record.
    #[test]
    fn the_key_is_mounted_read_only_beside_the_record_only_with_identity_and_a_key() {
        let mut keyed = identified_inputs();
        keyed.key_fd = Some(11);
        let got = build_linux_jail(&keyed).unwrap().bwrap_args;
        let key = [
            "--ro-bind-data".to_string(),
            "11".to_string(),
            innerwarden_agent_guard::identity::JAIL_SPKI_PIN_PATH.to_string(),
        ];
        let at = got
            .windows(3)
            .position(|w| w == key.as_slice())
            .expect("the key is mounted");
        let record = got
            .windows(3)
            .position(|w| w == record_mount("8").as_slice())
            .expect("the record is mounted");
        let run_tmpfs = got
            .windows(2)
            .position(|w| w[0] == "--tmpfs" && w[1] == "/run")
            .unwrap();
        assert!(run_tmpfs < at, "the key lands on the /run tmpfs");
        assert_eq!(at + 3, record, "the key is just before the record");
        assert!(!got.iter().any(|a| a == "--bind-data"));
        assert_eq!(
            got.join("\n"),
            GOLDEN_ARGV_IDENTIFIED.replace(
                "--ro-bind-data\n8\n",
                "--ro-bind-data\n11\n/run/innerwarden/agent-tls.spki\n--ro-bind-data\n8\n"
            )
        );

        // No key: today's identified jail.
        assert_eq!(
            build_linux_jail(&identified_inputs())
                .unwrap()
                .bwrap_args
                .join("\n"),
            GOLDEN_ARGV_IDENTIFIED
        );
        // No flag: a descriptor changes nothing.
        let mut off = identified_inputs();
        off.args.identity = false;
        off.info_fd = None;
        off.record_fd = None;
        off.key_fd = Some(11);
        off.existing_paths.pop();
        off.seccomp_fd = Some(launch::DRY_RUN_SECCOMP_FD);
        assert_eq!(
            build_linux_jail(&off).unwrap().bwrap_args.join("\n"),
            GOLDEN_ARGV_PLAIN
        );
    }

    fn found(uid: u32, mode: u32, dir: bool) -> launch::HostEntry {
        launch::HostEntry::Found {
            symlink: false,
            dir,
            file: !dir,
            uid,
            mode,
        }
    }

    /// The way to the system profiles file, as the launcher reads it.
    fn chain(entries: [launch::HostEntry; 4]) -> Vec<(PathBuf, launch::HostEntry)> {
        launch::system_profiles_chain()
            .into_iter()
            .zip(entries)
            .collect()
    }

    #[test]
    fn the_way_to_the_system_profiles_file_is_slash_etc_and_its_folder() {
        assert_eq!(
            launch::system_profiles_chain(),
            [
                "/",
                "/etc",
                "/etc/innerwarden",
                "/etc/innerwarden/agent-profiles.toml"
            ]
            .map(PathBuf::from)
        );
    }

    /// The marker mount, as a plain jail gets it.
    const MARKER_MOUNT: &str = "--ro-bind-data\n12\n/run/innerwarden/system-profiles-root\n";

    /// A plain jail on a host with a system profiles file whose way the
    /// launcher proved root's gets the marker, read-only, after the `/run`
    /// tmpfs and last of the mounts; without the file (no descriptor) the
    /// jail is today's, byte for byte, plain and rich.
    ///
    /// FAILS ON REVERT: drop the marker mount (every call in a plain jail on
    /// a host whose bwrap is not setuid is refused while the file exists), or
    /// mount it with `--bind-data`.
    #[test]
    fn golden_argv_of_a_plain_jail_with_and_without_the_system_profiles_file() {
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
            // Without the file: no descriptor, today's jail.
            assert_eq!(
                build_linux_jail(&input).unwrap().bwrap_args.join("\n"),
                golden
            );
            // With it: the marker, just before the namespaces.
            input.profiles_marker_fd = Some(launch::DRY_RUN_MARKER_FD);
            let got = build_linux_jail(&input).unwrap().bwrap_args;
            assert_eq!(
                got.join("\n"),
                golden.replacen(
                    "\n--die-with-parent\n",
                    &format!("\n{MARKER_MOUNT}--die-with-parent\n"),
                    1
                )
            );
            let marker = [
                "--ro-bind-data".to_string(),
                "12".to_string(),
                crate::agent_profiles::SYSTEM_PROFILES_MARKER_PATH.to_string(),
            ];
            let at = got
                .windows(3)
                .position(|w| w == marker.as_slice())
                .expect("the marker is mounted");
            let run_tmpfs = got
                .windows(2)
                .position(|w| w[0] == "--tmpfs" && w[1] == "/run")
                .unwrap();
            assert!(run_tmpfs < at, "the marker lands on the /run tmpfs");
            assert!(!got.iter().any(|a| a == "--bind-data"));
            let terminator = got.iter().position(|a| a == "--").unwrap();
            for option in got[at + 3..terminator]
                .iter()
                .filter(|a| a.starts_with("--"))
            {
                assert!(
                    AFTER_THE_RECORD.contains(&option.as_str()),
                    "{option} comes after the marker and may cover it"
                );
            }
        }
    }

    fn entries(file: launch::HostEntry, dir_uid: u32) -> Vec<(PathBuf, launch::HostEntry)> {
        chain([
            found(0, 0o40755, true),
            found(0, 0o40755, true),
            found(dir_uid, 0o40755, true),
            file,
        ])
    }

    /// A plain launch checks the way to the system profiles file only where
    /// the file is there, and marks the jail only then; an identified one
    /// always checks it and never needs the marker (its record says the
    /// same). Without the file a plain launch checks nothing, so a host
    /// without one is today's.
    ///
    /// FAILS ON REVERT: let a plain launch skip the check where the file is
    /// there, and a jail believes a file another account could have written.
    #[test]
    fn a_plain_launch_checks_the_way_to_the_profiles_only_where_the_file_is() {
        use launch::{profiles_chain, HostEntry, ProfilesChain};
        let file = found(0, 0o100644, false);
        // A plain jail, no file: nothing, even under a folder of another's.
        for dir_uid in [0, 1001] {
            assert_eq!(
                profiles_chain(false, &entries(HostEntry::Absent, dir_uid)),
                ProfilesChain::NotAsked
            );
        }
        // A plain jail, the file there: checked, and marked when proven.
        let proven = profiles_chain(false, &entries(file, 0));
        assert_eq!(proven, ProfilesChain::Proven { file: true });
        assert!(proven.marks());
        assert!(matches!(
            profiles_chain(false, &entries(file, 1001)),
            ProfilesChain::Refused(why) if why.starts_with("innerwarden contain: /etc/innerwarden is owned by uid 1001, not root, ")
        ));
        assert!(matches!(
            profiles_chain(false, &entries(found(1001, 0o100644, false), 0)),
            ProfilesChain::Refused(_)
        ));
        assert!(matches!(
            profiles_chain(false, &entries(HostEntry::Unreadable, 0)),
            ProfilesChain::Refused(_)
        ));
        // Identified: always checked; proven without the file marks nothing.
        let identified = profiles_chain(true, &entries(HostEntry::Absent, 0));
        assert_eq!(identified, ProfilesChain::Proven { file: false });
        assert!(!identified.marks());
        assert!(matches!(
            profiles_chain(true, &entries(HostEntry::Absent, 1001)),
            ProfilesChain::Refused(_)
        ));
        assert!(profiles_chain(true, &entries(file, 0)).marks());
    }

    /// A way to the system profiles file that is root's alone starts the
    /// jail: the file there or not, its folder there or not.
    #[test]
    fn a_root_chain_to_the_system_profiles_starts_the_jail() {
        let dir = |uid| found(uid, 0o40755, true);
        assert_eq!(
            launch::system_profiles_refusal(&chain([
                dir(0),
                dir(0),
                dir(0),
                found(0, 0o100644, false)
            ])),
            None
        );
        assert_eq!(
            launch::system_profiles_refusal(&chain([
                dir(0),
                dir(0),
                dir(0),
                launch::HostEntry::Absent
            ])),
            None
        );
        // No folder: only root can make one in a root `/etc`.
        assert_eq!(
            launch::system_profiles_refusal(&chain([
                dir(0),
                dir(0),
                launch::HostEntry::Absent,
                launch::HostEntry::Absent
            ])),
            None
        );
    }

    /// Inside the jail every account's file shows with one uid, so a folder
    /// or a file of another account there would read as root's. The launcher
    /// sees the real owner and refuses, naming the path and the owner.
    ///
    /// FAILS ON REVERT: let `system_profiles_refusal` pass any chain, and the
    /// jail believes profiles another account wrote.
    #[test]
    fn a_chain_another_account_owns_or_can_write_refuses_the_launch() {
        let dir = |uid, mode| found(uid, mode, true);
        let file = found(0, 0o100644, false);
        let cases = [
            (
                chain([dir(0, 0o40755), dir(0, 0o40755), dir(1001, 0o40755), file]),
                "/etc/innerwarden is owned by uid 1001, not root",
            ),
            (
                chain([
                    dir(0, 0o40755),
                    dir(0, 0o40755),
                    dir(0, 0o40755),
                    found(1001, 0o100644, false),
                ]),
                "/etc/innerwarden/agent-profiles.toml is owned by uid 1001, not root",
            ),
            (
                chain([dir(0, 0o40755), dir(0, 0o40755), dir(0, 0o40775), file]),
                "/etc/innerwarden (owned by uid 0) can be written by its group or by others",
            ),
            (
                chain([
                    dir(0, 0o40755),
                    dir(0, 0o40755),
                    dir(0, 0o40755),
                    found(0, 0o100666, false),
                ]),
                "/etc/innerwarden/agent-profiles.toml (owned by uid 0) can be written by its group or by others",
            ),
            (
                chain([
                    dir(0, 0o40755),
                    dir(0, 0o40755),
                    launch::HostEntry::Found {
                        symlink: true,
                        dir: false,
                        file: false,
                        uid: 0,
                        mode: 0o120777,
                    },
                    launch::HostEntry::Absent,
                ]),
                "/etc/innerwarden is a symbolic link (owned by uid 0)",
            ),
            (
                chain([dir(0, 0o40755), dir(0, 0o40755), dir(0, 0o40755), dir(0, 0o40755)]),
                "/etc/innerwarden/agent-profiles.toml (owned by uid 0) is not a regular file",
            ),
            (
                chain([dir(0, 0o40755), dir(0, 0o40755), file, launch::HostEntry::Absent]),
                "/etc/innerwarden (owned by uid 0) is not a folder",
            ),
            (
                chain([dir(0, 0o40755), dir(0, 0o40755), launch::HostEntry::Unreadable, file]),
                "/etc/innerwarden could not be inspected",
            ),
            (
                chain([dir(0, 0o40755), dir(1000, 0o40755), dir(0, 0o40755), file]),
                "/etc is owned by uid 1000, not root",
            ),
        ];
        for (entries, said) in cases {
            let why = launch::system_profiles_refusal(&entries)
                .unwrap_or_else(|| panic!("refused: {said}"));
            assert!(
                why.starts_with(&format!("innerwarden contain: {said}, ")),
                "{why}"
            );
            assert!(why.ends_with("so nothing was started."), "{why}");
            assert_eq!(why.matches(". ").count(), 0, "one sentence: {why}");
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
        // A host whose throwaway jail under the identified filter failed:
        // the jail an identified launch made before the filter, byte for
        // byte. The filter's own case sets these two.
        input.seccomp_fd = None;
        input.close_userns = false;
        // A home whose `~/.claude` holds no settings file of the jail's yet,
        // and a sessions and a backups folder of its own.
        input.claude_state = ClaudeState {
            settings_kept: true,
            own_folders: CLAUDE_RUN_FOLDERS
                .map(|name| PathBuf::from("/home/dev/.claude").join(name))
                .to_vec(),
            shared: false,
        };
        input
    }

    /// The lines Claude Code's settings file adds to the identified jail of
    /// [`identified_inputs`], after the dotdir binds and before the guard's
    /// binary.
    const CLAUDE_STATE_LINES: &str = "\
        --symlink\n\
        /home/dev/.claude/.claude.json\n\
        /home/dev/.claude.json\n";

    /// The lines Claude Code's folders of its runs add to the identified
    /// jail of [`identified_inputs`], after the project and before every
    /// mask.
    const CLAUDE_FOLDER_LINES: &str = "\
        --tmpfs\n\
        /home/dev/.claude/sessions\n\
        --tmpfs\n\
        /home/dev/.claude/backups\n";

    /// The lines the pins of the launcher's records' folders add to the
    /// identified jail of [`identified_inputs`], right after the dotdir
    /// binds (M30C-4): `~/.local/state` and `~/.local/state/innerwarden`
    /// are mount points, so no program in the jail renames them away from
    /// under the records' cover.
    const RECORDS_PIN_LINES: &str = "\
        --bind\n\
        /home/dev/.local/state\n\
        /home/dev/.local/state\n\
        --bind\n\
        /home/dev/.local/state/innerwarden\n\
        /home/dev/.local/state/innerwarden\n";

    /// The whole argv of an identified jail, one token per line.
    ///
    /// FAILS ON REVERT: drop the records folder `--tmpfs` (the agent can
    /// rewrite the launcher's records through the `.local` bind), or move it
    /// before the project and dotdir binds, or drop the `--setenv` lines, or
    /// drop the link to the kept settings file or the jail's own sessions
    /// or backups folder, or the pins of the records' folders.
    #[test]
    fn golden_argv_of_an_identified_jail() {
        let plan = build_linux_jail(&identified_inputs()).unwrap();
        assert_eq!(plan.bwrap_args.join("\n"), GOLDEN_ARGV_IDENTIFIED);
    }

    /// Where an identified jail keeps Claude Code's own state: the jail's
    /// `~/.claude.json` leads to the same name in the shared `~/.claude`,
    /// after the `.claude` bind it sits in, and the jail covers
    /// `~/.claude/sessions` and `~/.claude/backups` with empty folders of
    /// its own after the project, which can show `~/.claude` too. All before
    /// every mask, so a hidden or denied path still wins.
    ///
    /// FAILS ON REVERT: drop the link (Claude Code's settings file is the
    /// jail's empty home's again, gone at every launch) or a folder (two
    /// jails at once write the same `2.json`; the host's copies of the
    /// person's settings file are in the jail), or put the folders before
    /// the project, where `--project ~/.claude` brings the host's back.
    #[test]
    fn an_identified_jail_keeps_claude_codes_state_in_the_folder_it_shares() {
        let mut input = identified_inputs();
        input.hide_paths = vec![DenyPath {
            abs: PathBuf::from("/home/dev/.claude/sessions/hidden"),
            is_dir: true,
        }];
        let got = build_linux_jail(&input).unwrap().bwrap_args;
        let at = |w: &[&str]| {
            got.windows(w.len())
                .position(|x| x == w)
                .unwrap_or_else(|| panic!("{w:?} in {got:?}"))
        };
        let claude = at(&["--bind", "/home/dev/.claude", "/home/dev/.claude"]);
        let link = at(&[
            "--symlink",
            "/home/dev/.claude/.claude.json",
            "/home/dev/.claude.json",
        ]);
        let sessions = at(&["--tmpfs", "/home/dev/.claude/sessions"]);
        let backups = at(&["--tmpfs", "/home/dev/.claude/backups"]);
        let project = at(&["--bind", "/home/dev/proj", "/home/dev/proj"]);
        let hidden = at(&["--tmpfs", "/home/dev/.claude/sessions/hidden"]);
        let denied = at(&["--ro-bind", "/dev/null", "/home/dev/proj/.env"]);
        let protected = at(&["--tmpfs", "/home/dev/.aws"]);
        assert!(claude < link && link < project, "{got:?}");
        assert!(project < sessions && project < backups, "{got:?}");
        assert!(sessions < protected && backups < protected, "{got:?}");
        assert!(sessions < hidden && link < denied, "{got:?}");
        assert_eq!(got.iter().filter(|a| *a == "--symlink").count(), 5);
        // Nothing of the person's own settings file is bound in.
        assert!(!got
            .windows(2)
            .any(|w| w[0].ends_with("bind") && w[1] == "/home/dev/.claude.json"));
    }

    /// The link is never made to a kept settings file that a hidden home
    /// path or a denied path covers: Claude Code then keeps its file in the
    /// jail's own home, as before, and the mask stays where it was. The
    /// jail's own folders do not depend on it.
    ///
    /// FAILS ON REVERT: make the link whatever covers the file, and the jail's
    /// `~/.claude.json` leads to the hidden place.
    #[test]
    fn the_kept_settings_file_is_never_led_to_where_a_hidden_path_covers_it() {
        let kept = PathBuf::from("/home/dev/.claude/.claude.json");
        let mut hidden = identified_inputs();
        hidden.hide_paths = vec![DenyPath {
            abs: kept.clone(),
            is_dir: false,
        }];
        let mut denied = identified_inputs();
        denied.deny_paths.push(DenyPath {
            abs: kept.clone(),
            is_dir: false,
        });
        for input in [hidden, denied] {
            let got = build_linux_jail(&input).unwrap().bwrap_args;
            assert!(
                !got.windows(2)
                    .any(|w| w[0] == "--symlink" && w[1] == "/home/dev/.claude/.claude.json"),
                "{got:?}"
            );
            assert!(got
                .windows(3)
                .any(|w| w == ["--ro-bind", "/dev/null", "/home/dev/.claude/.claude.json"]));
            assert!(got
                .windows(2)
                .any(|w| w == ["--tmpfs", "/home/dev/.claude/sessions"]));
        }
    }

    /// No link where a read-only path of the profile shows the person's own
    /// `~/.claude.json`, the kept file, or the `~/.claude` that holds it.
    /// Measured with bwrap 0.9.0: a read-only bind of `~/.claude.json` after
    /// the link aborts the jail ("Can't create file at .../.claude.json"),
    /// so every identified launch under such a profile died; and a link into
    /// a read-only folder leads to a file Claude Code cannot save. The
    /// profile's view wins, as it did before the link. A path beside them
    /// keeps the link.
    ///
    /// FAILS ON REVERT: check only the hidden and denied paths before the
    /// link, and the read-only `~/.claude.json` comes after a link to it.
    #[test]
    fn no_link_where_a_read_only_path_shows_the_settings_file() {
        for shown in [
            "/home/dev/.claude.json",
            "/home/dev/.claude/.claude.json",
            "/home/dev/.claude",
        ] {
            let mut input = identified_inputs();
            input.args.extra_ro = vec![PathBuf::from(shown)];
            let got = build_linux_jail(&input).unwrap().bwrap_args;
            assert!(
                !(got.join("\n") + "\n").contains(CLAUDE_STATE_LINES),
                "{shown}: {got:?}"
            );
            assert!(
                got.windows(3).any(|w| w == ["--ro-bind-try", shown, shown]),
                "{shown}: {got:?}"
            );
        }
        let mut beside = identified_inputs();
        beside.args.extra_ro = vec![PathBuf::from("/home/dev/.local/share/claude/versions")];
        let got = build_linux_jail(&beside).unwrap().bwrap_args.join("\n");
        assert_eq!(got.matches(CLAUDE_STATE_LINES).count(), 1, "{got}");
    }

    /// Nothing of Claude Code's state is made where the jail does not share
    /// `~/.claude` (the home has none), or where the launcher found the
    /// kept file or the folders to be something else (a link, a folder in
    /// place of the file): the jail is the identified jail it was.
    ///
    /// FAILS ON REVERT: make the link or a folder without the `.claude`
    /// bind, or whatever the launcher found.
    #[test]
    fn nothing_of_claude_codes_state_is_made_where_the_jail_does_not_share_its_folder() {
        let claude_free = |got: &[String]| {
            !got.iter().any(|a| {
                a.starts_with("/home/dev/.claude.json")
                    || a.contains("/sessions")
                    || a.contains("/backups")
            })
        };
        let mut no_folder = identified_inputs();
        no_folder
            .existing_paths
            .retain(|p| p != Path::new("/home/dev/.claude"));
        let got = build_linux_jail(&no_folder).unwrap().bwrap_args;
        assert!(claude_free(&got), "{got:?}");

        let mut found_other = identified_inputs();
        found_other.claude_state = ClaudeState::default();
        let got = build_linux_jail(&found_other)
            .unwrap()
            .bwrap_args
            .join("\n");
        assert!(claude_free(
            &got.lines().map(String::from).collect::<Vec<_>>()
        ));
        assert_eq!(
            got,
            GOLDEN_ARGV_IDENTIFIED
                .replacen(CLAUDE_STATE_LINES, "", 1)
                .replacen(CLAUDE_FOLDER_LINES, "", 1)
        );

        let mut only_folders = identified_inputs();
        only_folders.claude_state.settings_kept = false;
        let got = build_linux_jail(&only_folders)
            .unwrap()
            .bwrap_args
            .join("\n");
        assert_eq!(
            got,
            GOLDEN_ARGV_IDENTIFIED.replacen(CLAUDE_STATE_LINES, "", 1)
        );
    }

    /// Claude Code's folders of its runs are covered at every place the jail
    /// shows them. `~/.claude` a link to `~/.config/claude` is shown by the
    /// `.claude` bind and by the `.config` bind, and a mount on one is not
    /// seen through the other (measured with bwrap 0.9.0: the host's
    /// sessions were listed, and written, through `~/.config/claude`), so
    /// both are covered. A project or a read-only path that is `~/.claude`
    /// shows them once more, at the same place. A place that holds the
    /// project or a read-only path is never covered (the agent would work in
    /// an empty folder): it stays shared, and that is said.
    ///
    /// FAILS ON REVERT: cover only the place the most specific bind shows
    /// (`jail_views` taking one), and the host's sessions are listed through
    /// `~/.config/claude`; or cover a place that holds the project.
    #[test]
    fn claude_codes_folders_are_covered_at_every_place_the_jail_shows_them() {
        let real = CLAUDE_RUN_FOLDERS
            .map(|name| PathBuf::from("/home/dev/.config/claude").join(name))
            .to_vec();
        let mut input = identified_inputs();
        let linked = shown_host_folders(
            &input.args,
            &input.home,
            None,
            &input.existing_paths,
            |path| {
                if path == Path::new("/home/dev/.claude") {
                    PathBuf::from("/home/dev/.config/claude")
                } else {
                    path.to_path_buf()
                }
            },
        );
        let needed = [input.args.project.clone(), input.iw_binary.clone()];
        let (folders, left) = plan_claude_folders(&real, &linked, &needed);
        assert_eq!(
            folders,
            [
                "/home/dev/.claude/sessions",
                "/home/dev/.config/claude/sessions",
                "/home/dev/.claude/backups",
                "/home/dev/.config/claude/backups",
            ]
            .map(PathBuf::from)
        );
        assert!(!left);
        input.claude_state.own_folders = folders;
        let got = build_linux_jail(&input).unwrap().bwrap_args;
        let last_bind = got.iter().rposition(|a| a == "--bind").unwrap();
        for folder in [
            "/home/dev/.claude/sessions",
            "/home/dev/.config/claude/sessions",
        ] {
            let at = got
                .windows(2)
                .position(|w| w == ["--tmpfs", folder])
                .unwrap_or_else(|| panic!("{folder}: {got:?}"));
            assert!(at > last_bind, "{folder}: {got:?}");
        }

        // `--project ~/.claude`: the project shows the same folders at the
        // same places, covered once, after it.
        let real = CLAUDE_RUN_FOLDERS
            .map(|name| PathBuf::from("/home/dev/.claude").join(name))
            .to_vec();
        let mut project = identified_inputs();
        project.args.project = PathBuf::from("/home/dev/.claude");
        let shown = shown_host_folders(
            &project.args,
            &project.home,
            None,
            &project.existing_paths,
            Path::to_path_buf,
        );
        let needed = [project.args.project.clone(), project.iw_binary.clone()];
        let (folders, left) = plan_claude_folders(&real, &shown, &needed);
        assert_eq!(folders, real);
        assert!(!left);
        project.claude_state.own_folders = folders;
        let got = build_linux_jail(&project).unwrap().bwrap_args;
        let bind = got
            .windows(3)
            .rposition(|w| w == ["--bind", "/home/dev/.claude", "/home/dev/.claude"])
            .unwrap();
        let sessions = got
            .windows(2)
            .position(|w| w == ["--tmpfs", "/home/dev/.claude/sessions"])
            .unwrap();
        assert!(bind < sessions, "{got:?}");

        // A project inside the sessions folder: never under an empty mount.
        let inside = [PathBuf::from("/home/dev/.claude/sessions/work")];
        let (folders, left) = plan_claude_folders(&real, &shown, &inside);
        assert_eq!(folders, [PathBuf::from("/home/dev/.claude/backups")]);
        assert!(left);
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

    /// M30CW-C3: a home folder the jail binds that is a link off the home
    /// shows InnerWarden's folder, and the launcher's records, at a place
    /// that is neither the folder as named nor as it resolves. `~/.cache`
    /// leads to `/data/cache`, `~/.config` to `~/.cache/cfg` and `~/.local`
    /// to `~/.cache/local`: InnerWarden's folder is
    /// `/data/cache/cfg/innerwarden`, which nothing in the jail shows at that
    /// place, and the `.cache` bind shows it at `~/.cache/cfg/innerwarden`
    /// (the records at `~/.cache/local/state/...`). Each is covered there
    /// too: the secret folder right after the dotdir binds and again after
    /// the last writable bind, the records after every writable bind, and a
    /// project at that place is refused.
    ///
    /// FAILS ON REVERT: cover only the folder as named and as it resolves
    /// (`other_jail_views` left out), and the jail reads the key at
    /// `~/.cache/cfg/innerwarden` and writes the launcher's records at
    /// `~/.cache/local/state/innerwarden/instances`.
    #[test]
    fn the_secret_folder_and_the_records_are_covered_at_every_place_the_jail_shows_them() {
        let resolve = |path: &Path| match path.to_str() {
            Some("/home/dev/.cache") => PathBuf::from("/data/cache"),
            Some("/home/dev/.config") => PathBuf::from("/data/cache/cfg"),
            Some("/home/dev/.local") => PathBuf::from("/data/cache/local"),
            _ => path.to_path_buf(),
        };
        let mut input = identified_inputs();
        let shown = shown_host_folders(
            &input.args,
            &input.home,
            None,
            &input.existing_paths,
            resolve,
        );
        let real = PathBuf::from("/data/cache/cfg/innerwarden");
        let views = other_jail_views(
            &real,
            &[PathBuf::from("/home/dev/.config/innerwarden"), real.clone()],
            &shown,
        );
        assert_eq!(views, [PathBuf::from("/home/dev/.cache/cfg/innerwarden")]);
        let records_real = PathBuf::from("/data/cache/local/state/innerwarden/instances");
        let named = vec![
            PathBuf::from("/home/dev/.local/state/innerwarden/instances"),
            records_real.clone(),
        ];
        let records_views = other_jail_views(&records_real, &named, &shown);
        assert_eq!(
            records_views,
            [PathBuf::from(
                "/home/dev/.cache/local/state/innerwarden/instances"
            )]
        );

        input.iw_config_real = real;
        input.iw_config_shown = views;
        input.records_dirs = named.into_iter().chain(records_views).collect();
        let got = build_linux_jail(&input).unwrap().bwrap_args;
        let cache_bind = got
            .windows(3)
            .position(|w| w == ["--bind", "/home/dev/.cache", "/home/dev/.cache"])
            .unwrap();
        let project = got
            .windows(3)
            .position(|w| w == ["--bind", "/home/dev/proj", "/home/dev/proj"])
            .unwrap();
        let last_bind = got.iter().rposition(|a| a == "--bind").unwrap();
        let masks: Vec<usize> = got
            .windows(2)
            .enumerate()
            .filter(|(_, w)| *w == ["--tmpfs", "/home/dev/.cache/cfg/innerwarden"])
            .map(|(at, _)| at)
            .collect();
        assert_eq!(masks.len(), 2, "{got:?}");
        assert!(cache_bind < masks[0] && masks[0] < project, "{got:?}");
        assert!(last_bind < masks[1], "{got:?}");
        let records = got
            .windows(2)
            .position(|w| {
                w == [
                    "--tmpfs",
                    "/home/dev/.cache/local/state/innerwarden/instances",
                ]
            })
            .unwrap_or_else(|| panic!("{got:?}"));
        assert!(last_bind < records, "{got:?}");

        let mut there = input.clone();
        there.args.project = PathBuf::from("/home/dev/.cache/cfg");
        let refused = validate_jail_inputs(&there).unwrap_err().to_string();
        assert!(refused.contains("unsafe project path"), "{refused}");
    }

    /// In every common layout InnerWarden's folder and the records are
    /// shown only as named or as they resolve: `other_jail_views` adds
    /// nothing, so such a jail is byte for byte the one it was. A home
    /// whose folders are its own, and one whose `~/.config` and `~/.local`
    /// lead off the home (a dotfiles manager's), alike.
    ///
    /// FAILS ON REVERT: take every view, the named one included, and the
    /// argv of these jails gains a mask it did not have.
    #[test]
    fn no_other_place_is_covered_in_a_common_layout() {
        let own = |path: &Path| path.to_path_buf();
        let off_home = |path: &Path| match path.to_str() {
            Some("/home/dev/.config") => PathBuf::from("/data/cfg"),
            Some("/home/dev/.local") => PathBuf::from("/data/local"),
            _ => path.to_path_buf(),
        };
        let input = identified_inputs();
        for (config_real, records_real, resolve) in [
            (
                "/home/dev/.config/innerwarden",
                "/home/dev/.local/state/innerwarden/instances",
                &own as &dyn Fn(&Path) -> PathBuf,
            ),
            (
                "/data/cfg/innerwarden",
                "/data/local/state/innerwarden/instances",
                &off_home,
            ),
        ] {
            let shown = shown_host_folders(
                &input.args,
                &input.home,
                None,
                &input.existing_paths,
                resolve,
            );
            let real = PathBuf::from(config_real);
            let named = [PathBuf::from("/home/dev/.config/innerwarden"), real.clone()];
            assert_eq!(
                other_jail_views(&real, &named, &shown),
                Vec::<PathBuf>::new()
            );
            let real = PathBuf::from(records_real);
            let named = [
                PathBuf::from("/home/dev/.local/state/innerwarden/instances"),
                real.clone(),
            ];
            assert_eq!(
                other_jail_views(&real, &named, &shown),
                Vec::<PathBuf>::new()
            );
        }
    }

    /// Without `--identity` neither the records folder, the command's
    /// variables nor Claude Code's own state reach the argv, whatever the
    /// inputs carry.
    #[test]
    fn without_identity_the_records_folder_and_variables_change_nothing() {
        let mut off = identified_inputs();
        off.args.identity = false;
        off.info_fd = None;
        off.record_fd = None;
        off.existing_paths.pop();
        off.seccomp_fd = Some(launch::DRY_RUN_SECCOMP_FD);
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
            ..Default::default()
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

    /// JP-1 (JAIL-PINS fixes, the read-only path): a profile's `extra_ro`
    /// inside the project (`extra_ro = ~/code/app/vendor`, the project
    /// `~/code/app`) was bound before the project, whose later bind covered
    /// it: the jail wrote it (measured with bwrap 0.9: the host file read
    /// `orig,jail`). On macOS nothing denied writing it at all. Such a path
    /// is laid right after the bind of the folder that holds it, the
    /// project's or a worktree's, and its pins; one that holds the project
    /// stays before it, so the project is writable in it. macOS denies
    /// each after the allow of the folder that holds it, in the same order.
    /// A folder above such a path that the jail writes is pinned on both,
    /// or a rename took the read-only bind away from its name.
    ///
    /// FAILS ON REVERT: lay every read-only path before the project (or
    /// drop the macOS denies, or the read-only paths from the pins' places)
    /// and the path is written through, or the folder above it moves.
    #[test]
    fn a_read_only_path_inside_the_project_or_a_worktree_stays_read_only() {
        let mut input = inputs(&["claude"]);
        input.worktree = Some(Worktree {
            git_dir: PathBuf::from("/home/dev/main/.git/worktrees/proj"),
            common_dir: PathBuf::from("/home/dev/main/.git"),
        });
        input.args.extra_ro = vec![
            PathBuf::from("/opt/sdk"),
            PathBuf::from("/home/dev/proj/vendor"),
            PathBuf::from("/home/dev/proj/third/lib"),
            PathBuf::from("/home/dev/main/.git/hooks"),
        ];
        assert!(validate_jail_inputs(&input).is_ok());
        let a = build_linux_jail(&input).unwrap().bwrap_args;
        let at = |w: &[&str]| {
            a.windows(w.len())
                .position(|x| x == w)
                .unwrap_or_else(|| panic!("{w:?} in {a:?}"))
        };
        let ro = |path: &str| at(&["--ro-bind-try", path, path]);
        let project = at(&["--bind", "/home/dev/proj", "/home/dev/proj"]);
        let third = at(&["--bind", "/home/dev/proj/third", "/home/dev/proj/third"]);
        let common = at(&["--bind", "/home/dev/main/.git", "/home/dev/main/.git"]);
        assert!(ro("/opt/sdk") < project, "{a:?}");
        assert!(
            project < third && third < ro("/home/dev/proj/third/lib"),
            "{a:?}"
        );
        assert!(project < ro("/home/dev/proj/vendor"), "{a:?}");
        assert!(ro("/home/dev/proj/vendor") < common, "{a:?}");
        assert!(common < ro("/home/dev/main/.git/hooks"), "{a:?}");
        // The folder above a read-only path is pinned, never one in it.
        let mut hidden = input.clone();
        hidden.hide_paths = vec![mask("/home/dev/proj/vendor/x/y", true)];
        let pins = linux_pins(&hidden);
        assert!(
            pins.contains(&(PinRoot::Project, PathBuf::from("/home/dev/proj/third"))),
            "{pins:?}"
        );
        assert!(
            !pins
                .iter()
                .any(|(_, folder)| folder.starts_with("/home/dev/proj/vendor")),
            "{pins:?}"
        );
        // One that holds the project is laid before it, so the project
        // stays writable in it.
        let mut around = inputs(&["claude"]);
        around.args.project = PathBuf::from("/home/dev/.cache/root/app");
        around.deny_paths.clear();
        around.args.extra_ro = vec![PathBuf::from("/home/dev/.cache/root")];
        let a = build_linux_jail(&around).unwrap().bwrap_args;
        let ro_at = a
            .windows(3)
            .position(|w| w[0] == "--ro-bind-try" && w[1] == "/home/dev/.cache/root")
            .unwrap();
        let project_at = a
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == "/home/dev/.cache/root/app")
            .unwrap();
        assert!(ro_at < project_at, "{a:?}");
        // macOS: each denied after the allow of the folder that holds it.
        let profile = build_macos_profile(&input).unwrap().profile;
        let find = |rule: &str| {
            profile
                .find(rule)
                .unwrap_or_else(|| panic!("{rule} in {profile}"))
        };
        let deny = |path: &str| find(&format!("(deny file-write* (subpath \"{path}\"))"));
        let allow = |path: &str| find(&format!("(allow file-write* (subpath \"{path}\"))"));
        assert!(allow("/home/dev/proj") < deny("/home/dev/proj/vendor"));
        assert!(allow("/home/dev/main/.git") < deny("/home/dev/main/.git/hooks"));
        deny("/opt/sdk");
        deny("/home/dev/proj/third/lib");
        assert!(macos_pins(&input).contains(&PathBuf::from("/home/dev/proj/third")));
        let profile = build_macos_profile(&around).unwrap().profile;
        let denied = profile
            .find("(deny file-write* (subpath \"/home/dev/.cache/root\"))")
            .expect("the read-only path is denied");
        let again = profile
            .rfind("(allow file-write* (subpath \"/home/dev/.cache/root/app\"))")
            .expect("the project's write again");
        assert!(denied < again, "{profile}");
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

    /// A path the account was trusted to run from, inside a folder of the
    /// home the jail may write (`~/.local`), is read-only in the jail: its
    /// read-only bind comes after the read-write bind of that folder, and no
    /// later bind or mount covers it.
    ///
    /// FAILS ON REVERT: move the `extra_ro` binds before the dotdir binds and
    /// the read-write `.local` bind covers the versions again.
    #[test]
    fn an_extra_ro_path_inside_a_rw_dotdir_is_read_only() {
        let versions = "/home/dev/.local/share/claude/versions";
        let mut input = identified_inputs();
        let mut args = input.args.clone();
        apply_jail_profile(
            &mut args,
            &jail_profile(
                None,
                &[innerwarden_agent_guard::profiles::runtime_versions_dir("claude-code").unwrap()],
                &[],
            ),
            JailFlagsGiven::default(),
            Path::new("/home/dev"),
        );
        assert_eq!(args.extra_ro, [PathBuf::from(versions)]);
        input.args = args;
        assert!(validate_jail_inputs(&input).is_ok());
        let a = build_linux_jail(&input).unwrap().bwrap_args;
        let local = a
            .windows(3)
            .position(|w| {
                w[0] == "--bind" && w[1] == "/home/dev/.local" && w[2] == "/home/dev/.local"
            })
            .expect("the read-write .local bind");
        let ro = a
            .windows(3)
            .position(|w| w[0] == "--ro-bind-try" && w[1] == versions && w[2] == versions)
            .expect("the read-only bind of the versions");
        assert!(
            local < ro,
            "the read-only bind must come after the read-write one"
        );
        // Nothing after it mounts over the versions or a folder above them.
        for (at, w) in a.windows(3).enumerate().skip(ro + 1) {
            if matches!(
                w[0].as_str(),
                "--bind" | "--tmpfs" | "--ro-bind" | "--bind-try"
            ) {
                let dest = if w[0] == "--tmpfs" { &w[1] } else { &w[2] };
                assert!(
                    !Path::new(versions).starts_with(dest),
                    "{} at {at} covers the versions",
                    w[0]
                );
            }
        }
    }

    /// A profile's hidden home paths are joined to the home, and its `start`
    /// is the stricter of what the launch had and what it says.
    #[test]
    fn a_jail_profile_says_when_the_jail_starts_and_what_of_the_home_it_hides() {
        use innerwarden_agent_guard::profiles::JailStart;
        let home = Path::new("/home/dev");
        let profile = innerwarden_agent_guard::profiles::JailProfile {
            start: Some(JailStart::OnlyWhenAdmitted),
            hide_home: vec![".cache/git/credential".into()],
            ..Default::default()
        };
        let mut launch = args(&["claude"]);
        assert_eq!(launch.start, JailStart::Always);
        apply_jail_profile(&mut launch, &profile, JailFlagsGiven::default(), home);
        assert_eq!(launch.start, JailStart::OnlyWhenAdmitted);
        assert_eq!(
            launch.hide_home,
            [PathBuf::from("/home/dev/.cache/git/credential")]
        );
        // Applied twice, nothing is added twice; a profile that says
        // `always` does not open what another one closed.
        apply_jail_profile(&mut launch, &profile, JailFlagsGiven::default(), home);
        assert_eq!(launch.hide_home.len(), 1);
        let always = innerwarden_agent_guard::profiles::JailProfile {
            start: Some(JailStart::Always),
            ..Default::default()
        };
        apply_jail_profile(&mut launch, &always, JailFlagsGiven::default(), home);
        assert_eq!(launch.start, JailStart::OnlyWhenAdmitted);
    }

    /// A hidden home path, as found on the host.
    fn hidden(nominal: &str, real: Option<&str>, is_dir: bool) -> HiddenHomePath {
        HiddenHomePath {
            nominal: PathBuf::from(nominal),
            real: real.map(PathBuf::from),
            resolved: PathBuf::from(real.unwrap_or(nominal)),
            is_dir,
            dangling_link: false,
            steered_by: None,
        }
    }

    /// The host folders `identified_inputs` shows, with `.config` a link
    /// into a dotfiles folder.
    fn shown_with_linked_config() -> Vec<(PathBuf, PathBuf)> {
        let input = identified_inputs();
        shown_host_folders(
            &input.args,
            &input.home,
            None,
            &input.existing_paths,
            |path| {
                if path == Path::new("/home/dev/.config") {
                    PathBuf::from("/home/dev/dotfiles/config")
                } else {
                    path.to_path_buf()
                }
            },
        )
    }

    /// A hidden home path is covered where the jail shows what it leads to:
    /// a folder by an empty tmpfs, a file by /dev/null, after every writable
    /// bind so none brings it back. A path that is not there gets no mount
    /// (bwrap would make it); the sandbox denies it anyway, so a file made
    /// there later is denied too. A jail without such a profile is the jail
    /// it was.
    ///
    /// FAILS ON REVERT: mount a path that is not there in
    /// `plan_hidden_home`, and the missing one is mounted over; deny only
    /// what is there and the missing one is not denied; move the masks
    /// before the dotdir binds and the read-write `.cache` bind brings the
    /// folder back.
    #[test]
    fn hide_home_masks_what_is_there_and_denies_what_may_come() {
        let folder = "/home/dev/.cache/git/credential";
        let file = "/home/dev/.config/app/token";
        let missing = "/home/dev/.cache/nothing-here";
        let mut input = identified_inputs();
        let shown = shown_host_folders(
            &input.args,
            &input.home,
            None,
            &input.existing_paths,
            Path::to_path_buf,
        );
        let plan = plan_hidden_home(
            &[
                hidden(folder, Some(folder), true),
                hidden(missing, None, false),
                hidden(file, Some(file), false),
                hidden(folder, Some(folder), true),
            ],
            &input.home,
            &shown,
        )
        .unwrap();
        assert_eq!(
            plan.masks,
            [
                DenyPath {
                    abs: PathBuf::from(folder),
                    is_dir: true
                },
                DenyPath {
                    abs: PathBuf::from(file),
                    is_dir: false
                },
            ]
        );
        assert_eq!(
            plan.denies,
            [folder, missing, file].map(PathBuf::from).to_vec()
        );
        input.hide_paths = plan.masks;
        input.hide_denies = plan.denies;
        let a = build_linux_jail(&input).unwrap().bwrap_args;
        let tmpfs = a
            .windows(2)
            .position(|w| w[0] == "--tmpfs" && w[1] == folder)
            .expect("the folder under an empty tmpfs");
        let null = a
            .windows(3)
            .position(|w| w[0] == "--ro-bind" && w[1] == "/dev/null" && w[2] == file)
            .expect("the file under /dev/null");
        assert!(!a.iter().any(|w| w == missing));
        let last_writable = a
            .windows(2)
            .rposition(|w| w[0] == "--bind")
            .expect("writable binds");
        assert!(tmpfs > last_writable && null > last_writable);
        // macOS has no mount to lay: the paths are denied, read and write,
        // as a project secret is, the missing one too.
        let profile = build_macos_profile(&input).unwrap().profile;
        for path in [folder, file, missing] {
            for access in ["read", "write"] {
                let rule = format!("(deny file-{access}* (subpath \"{path}\"))");
                assert!(profile.contains(&rule), "{rule}");
            }
        }
        // None: the identified golden, byte for byte.
        assert_eq!(
            build_linux_jail(&identified_inputs())
                .unwrap()
                .bwrap_args
                .join("\n"),
            GOLDEN_ARGV_IDENTIFIED
        );
    }

    /// A link on the way of a hidden home path is followed, never mounted
    /// on. Measured with bwrap 0.9.0 and 0.12.0: a mount on a link aborts
    /// the jail ("Can't mount tmpfs on ... No such file or directory"), and
    /// sandbox-exec denies only the path a link resolves to.
    /// - `.config/gh` a link to `~/dotfiles/gh`, which the jail does not
    ///   show: nothing is mounted (the link dangles in the jail); macOS
    ///   denies both paths.
    /// - `.config/gh3` a link to `~/.local/share/gh3`, which the jail shows
    ///   through `.local`: that is covered.
    /// - `.config` itself a link to `~/dotfiles/config`: the jail shows it
    ///   at `~/.config`, so `~/.config/gh` is covered there, and macOS
    ///   denies `~/dotfiles/config/gh`, the path it matches.
    ///
    /// FAILS ON REVERT: mount the path as named (the plan before this one)
    /// and the first line mounts on a link; deny only the path as named and
    /// macOS leaves the real one readable.
    #[test]
    fn a_link_on_the_way_of_a_hidden_home_path_is_followed() {
        let input = identified_inputs();
        let shown = shown_with_linked_config();
        let plan = plan_hidden_home(
            &[
                hidden("/home/dev/.config/gh", Some("/home/dev/dotfiles/gh"), true),
                hidden(
                    "/home/dev/.config/gh3",
                    Some("/home/dev/.local/share/gh3"),
                    true,
                ),
                hidden(
                    "/home/dev/.config/token",
                    Some("/home/dev/dotfiles/config/token"),
                    false,
                ),
            ],
            &input.home,
            &shown,
        )
        .unwrap();
        assert_eq!(
            plan.masks,
            [
                DenyPath {
                    abs: PathBuf::from("/home/dev/.local/share/gh3"),
                    is_dir: true
                },
                DenyPath {
                    abs: PathBuf::from("/home/dev/.config/token"),
                    is_dir: false
                },
            ]
        );
        for denied in [
            "/home/dev/.config/gh",
            "/home/dev/dotfiles/gh",
            "/home/dev/.config/gh3",
            "/home/dev/.local/share/gh3",
            "/home/dev/.config/token",
            "/home/dev/dotfiles/config/token",
        ] {
            assert!(
                plan.denies.contains(&PathBuf::from(denied)),
                "{denied}: {:?}",
                plan.denies
            );
        }
    }

    /// A hidden home path is covered at every place the jail shows what it
    /// leads to: with `~/.claude` a link to `~/.config/claude`, both the
    /// `.claude` bind and the `.config` bind show it, and a mount on one is
    /// not seen through the other, so `~/.config/claude/token` is covered
    /// too.
    ///
    /// FAILS ON REVERT: cover only the place the most specific bind shows,
    /// and the token is read through `~/.config/claude`.
    #[test]
    fn a_hidden_home_path_is_covered_at_every_place_the_jail_shows_it() {
        let input = identified_inputs();
        let shown = shown_host_folders(
            &input.args,
            &input.home,
            None,
            &input.existing_paths,
            |path| {
                if path == Path::new("/home/dev/.claude") {
                    PathBuf::from("/home/dev/.config/claude")
                } else {
                    path.to_path_buf()
                }
            },
        );
        let plan = plan_hidden_home(
            &[hidden(
                "/home/dev/.claude/token",
                Some("/home/dev/.config/claude/token"),
                false,
            )],
            &input.home,
            &shown,
        )
        .unwrap();
        assert_eq!(
            plan.masks,
            ["/home/dev/.claude/token", "/home/dev/.config/claude/token"].map(|abs| DenyPath {
                abs: PathBuf::from(abs),
                is_dir: false
            })
        );
    }

    /// JP-2 (JAIL-PINS fixes): on Linux a hidden home path reached through
    /// a link in a folder the jail writes (`.cache/git/credential`, with
    /// `~/.cache/git` a link to `~/.local/git`) was covered only where it
    /// leads, and no mount pins a link: a program in the jail removed the
    /// link, made `~/.cache/git/credential` a folder of its own, and the
    /// host read what it put there, and would have written there its
    /// credential cache's socket (measured with bwrap 0.9). Such a path
    /// refuses the launch now, with the one remedy that works there; the
    /// launcher finds the link only on Linux ([`HiddenHomePath::steered_by`]),
    /// since macOS keeps it in place. Names are printed escaped.
    ///
    /// FAILS ON REVERT: drop the `steered_by` check in `plan_hidden_home`
    /// and the path is planned, masked only where it leads.
    #[test]
    fn a_hidden_home_path_behind_a_link_the_jail_can_replace_is_refused() {
        let input = identified_inputs();
        let shown = shown_with_linked_config();
        let mut behind = hidden(
            "/home/dev/.cache/git/credential",
            Some("/home/dev/.local/git/credential"),
            true,
        );
        behind.steered_by = Some(PathBuf::from("/home/dev/.cache/git"));
        let said = plan_hidden_home(&[behind], &input.home, &shown)
            .unwrap_err()
            .to_string();
        assert!(
            said.starts_with(
                "the hidden home path '/home/dev/.cache/git/credential' goes through \
                 /home/dev/.cache/git, a link in a folder a program in the jail can write"
            ),
            "{said}"
        );
        assert!(said.contains("the jail does not start"), "{said}");
        assert!(
            said.ends_with(
                "Replace /home/dev/.cache/git with the folder it leads to, and start the jail again"
            ),
            "{said}"
        );
        assert!(!said.contains("straight to its place"), "{said}");
        let odd =
            hidden_home_link_refused(Path::new("/home/dev/a\nb"), Path::new("/home/dev/a\nb"))
                .to_string();
        assert!(!odd.contains('\n'), "{odd}");
        // The same path with no such link is planned, as before.
        let plan = plan_hidden_home(
            &[hidden(
                "/home/dev/.cache/git/credential",
                Some("/home/dev/.local/git/credential"),
                true,
            )],
            &input.home,
            &shown,
        )
        .unwrap();
        assert!(!plan.masks.is_empty(), "{plan:?}");
    }

    /// A hidden home path that leads outside the home is refused, whatever
    /// the link is: one the agent planted in a folder it can write would
    /// otherwise move the empty mount onto anything the jail shows. What it
    /// leads to inside the home that the jail needs is refused by the
    /// inputs' check ([`validate_jail_inputs`]).
    ///
    /// FAILS ON REVERT: drop the home check in `plan_hidden_home` and the
    /// jail's `/etc/innerwarden` is emptied.
    #[test]
    fn a_hidden_home_path_that_leads_outside_the_home_is_refused() {
        let input = identified_inputs();
        let shown = shown_with_linked_config();
        for (real, exists) in [("/etc/innerwarden", true), ("/srv/other/secret", false)] {
            let path = HiddenHomePath {
                nominal: PathBuf::from("/home/dev/.cache/git/credential"),
                real: exists.then(|| PathBuf::from(real)),
                resolved: PathBuf::from(real),
                is_dir: true,
                dangling_link: false,
                steered_by: None,
            };
            let refused = plan_hidden_home(&[path], &input.home, &shown).unwrap_err();
            assert!(
                refused.to_string().contains("outside the home"),
                "{refused}"
            );
        }
        // A link that leads to nothing is refused: where a file made
        // through it would land is not known.
        let mut dangling = hidden("/home/dev/.cache/git/credential", None, false);
        dangling.dangling_link = true;
        assert!(plan_hidden_home(&[dangling], &input.home, &shown)
            .unwrap_err()
            .to_string()
            .contains("leads to nothing"));
        // A planted link to the project is planned, then refused before
        // anything is installed or started.
        let plan = plan_hidden_home(
            &[hidden(
                "/home/dev/.cache/git/credential",
                Some("/home/dev/proj"),
                true,
            )],
            &input.home,
            &shown,
        )
        .unwrap();
        let mut planted = identified_inputs();
        planted.hide_paths = plan.masks;
        planted.hide_denies = plan.denies;
        assert!(validate_jail_inputs(&planted)
            .unwrap_err()
            .to_string()
            .contains("holds the project"));
    }

    /// A hidden home path never covers what the jail needs: the guard's
    /// binary (its hook would fail and every command go unscreened), a
    /// read-only path the profile shows (the agent's own runtime), the
    /// agent's settings that carry the hook. A path beside them is fine.
    ///
    /// FAILS ON REVERT: check only the project in `validate_jail_inputs`
    /// and each line here but the last is taken.
    #[test]
    fn a_hidden_home_path_never_covers_what_the_jail_needs() {
        for (hide, what) in [
            ("/home/dev/.local", "the guard"),
            ("/home/dev/.local/bin", "the guard"),
            ("/home/dev/.local/share", "a read-only path"),
            ("/home/dev/.claude", "the agent's settings"),
            ("/home/dev/.claude.json", "the agent's settings"),
        ] {
            for denies in [false, true] {
                let mut input = identified_inputs();
                input.args.extra_ro = vec![PathBuf::from("/home/dev/.local/share/claude/versions")];
                if denies {
                    input.hide_denies = vec![PathBuf::from(hide)];
                } else {
                    input.hide_paths = vec![DenyPath {
                        abs: PathBuf::from(hide),
                        is_dir: true,
                    }];
                }
                let refused = validate_jail_inputs(&input).unwrap_err().to_string();
                assert!(refused.contains(what), "{hide}: {refused}");
            }
        }
        let mut fine = identified_inputs();
        fine.args.extra_ro = vec![PathBuf::from("/home/dev/.local/share/claude/versions")];
        fine.hide_paths = vec![DenyPath {
            abs: PathBuf::from("/home/dev/.cache/git/credential"),
            is_dir: true,
        }];
        fine.hide_denies = vec![PathBuf::from("/home/dev/.local/share/gh")];
        assert!(validate_jail_inputs(&fine).is_ok());
    }

    /// A hidden home path never holds the project: the agent would work in
    /// an empty folder.
    #[test]
    fn a_hidden_home_path_that_holds_the_project_is_refused() {
        for holds in ["/home/dev/proj", "/home/dev"] {
            let mut input = identified_inputs();
            input.hide_paths = vec![DenyPath {
                abs: PathBuf::from(holds),
                is_dir: true,
            }];
            assert!(validate_jail_inputs(&input).is_err(), "{holds}");
        }
        let mut inside = identified_inputs();
        inside.hide_paths = vec![DenyPath {
            abs: PathBuf::from("/home/dev/proj/cache"),
            is_dir: true,
        }];
        assert!(validate_jail_inputs(&inside).is_ok());
    }

    /// A home folder the jail binds read-write is taken where it leads, as
    /// the jail binds it: with `~/.cache` a link to `/data/cache` (a person's
    /// own, which the agent cannot replace in the jail, where it is a mount
    /// point), `~/.cache/git/credential` is planned at
    /// `/data/cache/git/credential` and covered where the jail shows it, at
    /// `~/.cache/git/credential`. A link below the folder that leaves where
    /// it leads is still refused, and so is a folder the jail does not bind
    /// read-write.
    ///
    /// FAILS ON REVERT: take only the home for the jail's home in
    /// `plan_hidden_home` (the check before this one) and the first plan is
    /// refused "outside the home", so every jail whose profile hides
    /// `.cache/git/credential` never starts for this person.
    #[test]
    fn a_home_folder_linked_outside_the_home_is_taken_where_it_leads() {
        let input = identified_inputs();
        let shown = shown_host_folders(
            &input.args,
            &input.home,
            None,
            &input.existing_paths,
            |path| {
                if path == Path::new("/home/dev/.cache") {
                    PathBuf::from("/data/cache")
                } else {
                    path.to_path_buf()
                }
            },
        );
        let plan = plan_hidden_home(
            &[
                hidden(
                    "/home/dev/.cache/git/credential",
                    Some("/data/cache/git/credential"),
                    true,
                ),
                hidden("/home/dev/.cache/nothing-here", None, false),
            ],
            &input.home,
            &shown,
        )
        .unwrap();
        assert_eq!(
            plan.masks,
            [DenyPath {
                abs: PathBuf::from("/home/dev/.cache/git/credential"),
                is_dir: true
            }]
        );
        for denied in [
            "/home/dev/.cache/git/credential",
            "/data/cache/git/credential",
            "/home/dev/.cache/nothing-here",
        ] {
            assert!(
                plan.denies.contains(&PathBuf::from(denied)),
                "{denied}: {:?}",
                plan.denies
            );
        }
        // A link below the folder that leaves where the folder leads: the
        // mask would move onto what the jail shows elsewhere.
        for real in ["/data/other/secret", "/etc/innerwarden", "/data/cachex/x"] {
            let refused = plan_hidden_home(
                &[hidden("/home/dev/.cache/git/credential", Some(real), true)],
                &input.home,
                &shown,
            )
            .unwrap_err();
            assert!(
                refused.to_string().contains("outside the home"),
                "{real}: {refused}"
            );
        }
        // A path in another folder leads into `/data/cache`: that folder's
        // place, not its own.
        assert!(plan_hidden_home(
            &[hidden("/home/dev/.config/gh", Some("/data/cache/gh"), true)],
            &input.home,
            &shown,
        )
        .is_err());
        // A home folder the jail does not bind read-write is not the jail's.
        let ssh_linked = shown_host_folders(
            &input.args,
            &input.home,
            None,
            &[
                input.existing_paths.clone(),
                vec![PathBuf::from("/home/dev/.ssh")],
            ]
            .concat(),
            |path| {
                if path == Path::new("/home/dev/.ssh") {
                    PathBuf::from("/data/ssh")
                } else {
                    path.to_path_buf()
                }
            },
        );
        assert!(plan_hidden_home(
            &[hidden("/home/dev/.ssh/key", Some("/data/ssh/key"), false)],
            &input.home,
            &ssh_linked,
        )
        .is_err());
    }

    /// The launcher starts the command of a jail whose profile starts it only
    /// when admitted only once the host said it admitted the jail AND the
    /// kernel shows the jail in its system scope. No answer, an answer that
    /// admitted nothing, or an admission without the scope: not started. A
    /// jail with no such profile starts as it always did.
    ///
    /// FAILS ON REVERT: start whatever `admitted` says in `starts`, or take
    /// the answer alone in `admitted_here`, and a jail the host did not
    /// admit starts.
    #[test]
    fn only_when_admitted_refuses_without_the_host() {
        use innerwarden_agent_guard::identity::SystemScopeAdmission;
        use innerwarden_agent_guard::profiles::JailStart;
        use launch::{admitted_here, starts, NOT_ADMITTED};
        let scope = innerwarden_agent_guard::identity::Scope {
            unit: UNIT.to_string(),
            cgroup_path: format!("/system.slice/{UNIT}"),
        };
        let yes = SystemScopeAdmission {
            admitted: true,
            note: None,
        };
        let no = SystemScopeAdmission {
            admitted: false,
            note: Some("Kernel protection is not in effect for this session.".into()),
        };
        assert!(admitted_here(&yes, Some(&scope)));
        for (answer, seen) in [
            (&SystemScopeAdmission::NONE, Some(&scope)),
            (&SystemScopeAdmission::NONE, None),
            (&no, Some(&scope)),
            (&yes, None),
        ] {
            let admitted = admitted_here(answer, seen);
            assert!(!admitted, "{answer:?} {seen:?}");
            assert!(!starts(JailStart::OnlyWhenAdmitted, admitted));
            assert!(starts(JailStart::Always, admitted));
        }
        assert!(starts(JailStart::OnlyWhenAdmitted, true));
        assert_eq!(
            NOT_ADMITTED,
            "Active Defence on this host did not admit this jail, and its profile starts it \
             only when admitted."
        );
        // A launch with no profile starts as it always did.
        assert_eq!(args(&["claude"]).start, JailStart::Always);
        assert_eq!(
            parse_contain_args(&["--identity".into(), "claude".into()])
                .unwrap()
                .start,
            JailStart::Always
        );
    }

    /// The launcher's decision is one pure function of what it learned: the
    /// record it made, the host's answer and the system scope the kernel
    /// showed. A host that placed the jail and said it did not admit it
    /// does not start it; neither does an admission without the scope, nor
    /// a record that could not be made.
    ///
    /// FAILS ON REVERT: take the scope alone for the admission in
    /// `launch_starts` (the reading before the answer was read) and the
    /// placed-but-not-admitted line starts.
    #[test]
    fn the_launch_starts_only_on_an_admission_over_the_scope() {
        use innerwarden_agent_guard::identity::SystemScopeAdmission;
        use innerwarden_agent_guard::profiles::JailStart;
        use launch::launch_starts;
        let scope = innerwarden_agent_guard::identity::Scope {
            unit: UNIT.to_string(),
            cgroup_path: format!("/system.slice/{UNIT}"),
        };
        let yes = SystemScopeAdmission {
            admitted: true,
            note: None,
        };
        let no = SystemScopeAdmission {
            admitted: false,
            note: Some("Kernel protection is not in effect for this session.".into()),
        };
        let wait = JailStart::OnlyWhenAdmitted;
        assert!(launch_starts(wait, Some((&yes, Some(&scope)))));
        assert!(!launch_starts(wait, Some((&no, Some(&scope)))));
        assert!(!launch_starts(wait, Some((&yes, None))));
        assert!(!launch_starts(
            wait,
            Some((&SystemScopeAdmission::NONE, Some(&scope)))
        ));
        assert!(!launch_starts(wait, None));
        for made in [None, Some((&no, None)), Some((&yes, Some(&scope)))] {
            assert!(launch_starts(JailStart::Always, made));
        }
    }

    /// The answer to the request for a system scope: a `202` is read for the
    /// admission, any other success admits nothing, and a request that got
    /// no answer says why. After "did not admit", the launcher says what to
    /// check and which file makes the jail wait.
    #[test]
    fn the_launcher_says_why_the_host_did_not_admit_and_what_to_do() {
        use crate::host_decide_io::NoAnswer;
        let (taken, admission) = launch::scope_answer(Ok((202, br#"{"admitted":true}"#.to_vec())));
        assert!(taken.is_ok() && admission.admitted);
        let (taken, admission) = launch::scope_answer(Ok((200, br#"{"admitted":true}"#.to_vec())));
        assert!(taken.is_ok() && !admission.admitted);
        assert_eq!(
            launch::scope_answer(Ok((500, Vec::new()))).0,
            Err("HTTP 500".into())
        );
        let (taken, admission) = launch::scope_answer(Err(NoAnswer::Refused));
        assert!(!admission.admitted);
        assert!(taken.unwrap_err().contains("Active Defence is not running"));
        assert_eq!(
            launch::not_admitted_remedy(
                &["/home/dev/.config/innerwarden/agent-profiles.toml".into()],
                None
            ),
            "Check that Active Defence is running (systemctl status innerwarden-agent), then try \
             again. The jail waits for it because of start = \"only_when_admitted\" in \
             /home/dev/.config/innerwarden/agent-profiles.toml."
        );
        assert!(launch::not_admitted_remedy(&[], None).ends_with(
            "in /etc/innerwarden/agent-profiles.toml or ~/.config/innerwarden/agent-profiles.toml."
        ));
    }

    /// A launcher that holds no key of the host's (an older Active Defence
    /// that publishes none), or that asks the host at an address its key
    /// is not held over, never reads the answer, so nothing is admitted.
    /// It says so, naming the key's file or the address, and its remedy is
    /// that, not "check that Active Defence is running": the same launch
    /// has just printed the system scope Active Defence placed the jail in.
    ///
    /// FAILS ON REVERT: answer `None` in `answer_unbelieved` (the launcher
    /// before this one) and a launcher with no key says nothing of it and
    /// sends the person to check that Active Defence runs.
    #[test]
    fn a_launcher_that_cannot_believe_the_host_says_why() {
        use launch::{answer_unbelieved, not_admitted_remedy, unbelieved_sentence, Unbelieved};
        let pinned = "https://127.0.0.1:8787/api/agent/contain-scope";
        assert_eq!(answer_unbelieved(true, Some(pinned)), None);
        // Nothing was asked: nothing to believe or not.
        assert_eq!(answer_unbelieved(false, None), None);
        assert_eq!(
            answer_unbelieved(false, Some(pinned)),
            Some(Unbelieved::NoKey)
        );
        let elsewhere = "http://127.0.0.1:8787/api/agent/contain-scope";
        assert_eq!(
            answer_unbelieved(true, Some(elsewhere)),
            Some(Unbelieved::Address(elsewhere.into()))
        );
        let no_key = unbelieved_sentence(&Unbelieved::NoKey);
        assert!(
            no_key.contains("cannot be believed without its key"),
            "{no_key}"
        );
        assert!(
            no_key.contains(innerwarden_agent_guard::identity::AGENT_TLS_SPKI_PATH),
            "{no_key}"
        );
        let remedy = not_admitted_remedy(&[], Some(&Unbelieved::NoKey));
        assert!(
            remedy.starts_with("Check that Active Defence on this host publishes its key at "),
            "{remedy}"
        );
        assert!(!remedy.contains("systemctl status"), "{remedy}");
        assert!(
            remedy.contains("start = \"only_when_admitted\""),
            "{remedy}"
        );
        let address = unbelieved_sentence(&Unbelieved::Address(elsewhere.into()));
        assert!(address.contains(elsewhere), "{address}");
        let remedy = not_admitted_remedy(&[], Some(&Unbelieved::Address(elsewhere.into())));
        assert!(
            remedy.starts_with("Unset INNERWARDEN_AGENT_URL"),
            "{remedy}"
        );
    }

    /// Under a profile that starts the jail only once the host admitted it,
    /// the jail's command starts through the gate: the launcher's own
    /// binary, bound read-only, with the instance it waits for. Without such
    /// a profile the argv is the golden, byte for byte.
    ///
    /// FAILS ON REVERT: hand the child to bwrap as it is in
    /// `build_linux_jail`, or return the instance for `always` in
    /// `gate_for`, and the lines below that say otherwise fail.
    #[test]
    fn a_jail_that_starts_only_once_admitted_runs_its_command_through_the_gate() {
        use innerwarden_agent_guard::profiles::JailStart;
        let instance = launch::instance_id_from([7; 16]);
        assert_eq!(launch::gate_for(JailStart::Always, &instance), None);
        assert_eq!(
            launch::gate_for(JailStart::OnlyWhenAdmitted, &instance),
            Some(instance.clone())
        );
        let mut input = identified_inputs();
        input.gate_instance = launch::gate_for(JailStart::OnlyWhenAdmitted, &instance);
        let a = build_linux_jail(&input).unwrap().bwrap_args;
        let end = a.iter().rposition(|w| w == "--").unwrap();
        let iw = input.iw_binary.to_string_lossy().to_string();
        let child = &a[a.iter().position(|w| w == "--").unwrap() + 1..];
        let mut expected = vec![
            iw.clone(),
            launch::GATE_VERB.to_string(),
            "--instance".to_string(),
            instance.clone(),
            "--".to_string(),
        ];
        expected.extend(input.args.child.iter().cloned());
        assert_eq!(child, expected.as_slice());
        assert_eq!(a[end + 1..], input.args.child[..]);
        // The gate is the launcher's own binary, bound read-only.
        assert!(a
            .windows(3)
            .any(|w| w[0] == "--ro-bind" && w[1] == iw && w[2] == iw));
        assert_eq!(
            build_linux_jail(&identified_inputs())
                .unwrap()
                .bwrap_args
                .join("\n"),
            GOLDEN_ARGV_IDENTIFIED
        );
        assert_eq!(
            launch::parse_gate_args(&expected[2..]),
            Some((instance.as_str(), &input.args.child[..]))
        );
        for bad in [
            vec![],
            vec!["--instance".to_string(), instance.clone(), "--".to_string()],
            vec![
                "--instance".to_string(),
                String::new(),
                "--".to_string(),
                "x".to_string(),
            ],
            vec![
                "--other".to_string(),
                instance.clone(),
                "--".to_string(),
                "x".to_string(),
            ],
            vec!["--instance".to_string(), instance.clone(), "x".to_string()],
        ] {
            assert_eq!(launch::parse_gate_args(&bad), None, "{bad:?}");
        }
    }

    /// The gate starts the command only on a record that names its own
    /// instance. An empty record (the launcher ended the jail, or died
    /// before the host answered), one that is not a record, and one of
    /// another instance keep the command from starting.
    ///
    /// FAILS ON REVERT: open on any record, or on a record of any instance,
    /// in `gate_opens`, and the empty or the other-instance line opens.
    #[test]
    fn the_gate_starts_the_command_only_on_a_record_naming_its_instance() {
        let (mode, launcher, project) = (
            Mode::Monitor,
            Path::new("/usr/local/bin/innerwarden"),
            Path::new("/home/dev/proj"),
        );
        let record = launch::assemble_record(launch_facts(&mode, launcher, project)).unwrap();
        let json = serde_json::to_vec(&record).unwrap();
        assert!(launch::gate_opens(&json, &record.instance_id));
        let other = launch::instance_id_from([8; 16]);
        assert!(!launch::gate_opens(&json, &other));
        for refused in [
            &b""[..],
            b"   ",
            b"{}",
            b"not json",
            &json[..json.len() / 2],
        ] {
            assert!(
                !launch::gate_opens(refused, &record.instance_id),
                "{:?}",
                String::from_utf8_lossy(refused)
            );
        }
        assert_eq!(
            launch::GATE_REFUSED,
            "this jail holds no record that the host admitted it, so its command does not start."
        );
    }

    /// A jail is ended by the pid bwrap reported for its first process,
    /// whether or not the kernel lists bwrap's children (a kernel built
    /// without `CHECKPOINT_RESTORE` has no `/proc/<pid>/task/*/children`).
    /// Each pid once, and only while its parent is still bwrap.
    ///
    /// FAILS ON REVERT: end only the listed children in
    /// `jail_processes_to_end` and the first line, a kernel that lists none,
    /// ends nothing.
    #[test]
    fn a_jail_is_ended_by_the_pid_bwrap_reported_even_where_proc_lists_no_children() {
        use launch::jail_processes_to_end;
        let parent = |pid: u32| match pid {
            101 | 102 => Some(100),
            201 => Some(1),
            _ => None,
        };
        assert_eq!(jail_processes_to_end(100, Some(101), &[], parent), [101]);
        assert_eq!(
            jail_processes_to_end(100, Some(101), &[101, 102], parent),
            [101, 102]
        );
        assert_eq!(jail_processes_to_end(100, None, &[102], parent), [102]);
        // A pid that ended and was handed to someone else is not signalled.
        assert!(jail_processes_to_end(100, Some(201), &[201, 999], parent).is_empty());
    }

    /// Where `/etc/resolv.conf` is a link into `/run`, the jail gets the
    /// file it names, read-only, at the same place, and nothing else of the
    /// host's `/run`: never the folder that holds the resolver's sockets,
    /// never a file of the jail's own, never one that names another
    /// resolver. Any other link, or none, changes nothing.
    ///
    /// FAILS ON REVERT: bind the link target's folder where it holds
    /// sockets (systemd-resolved's), or keep a target outside `/run`, and
    /// the lines below that say otherwise fail.
    #[test]
    fn the_jail_never_points_at_a_private_resolver() {
        use launch::resolv_conf_target;
        for (link, target) in [
            (
                "../run/systemd/resolve/stub-resolv.conf",
                "/run/systemd/resolve/stub-resolv.conf",
            ),
            (
                "/run/systemd/resolve/resolv.conf",
                "/run/systemd/resolve/resolv.conf",
            ),
            ("/run/resolvconf/resolv.conf", "/run/resolvconf/resolv.conf"),
            (
                "./../run/./NetworkManager/resolv.conf",
                "/run/NetworkManager/resolv.conf",
            ),
        ] {
            assert_eq!(
                resolv_conf_target(Path::new(link)),
                Some(PathBuf::from(target)),
                "{link}"
            );
        }
        for elsewhere in [
            "/run",
            "../run",
            "/etc/resolvconf/run/resolv.conf",
            "resolv.conf.real",
            "/var/run/NetworkManager/resolv.conf",
            "../run/../etc/shadow",
            "/runner/resolv.conf",
        ] {
            assert_eq!(
                resolv_conf_target(Path::new(elsewhere)),
                None,
                "{elsewhere}"
            );
        }
        let stub = "/run/systemd/resolve/stub-resolv.conf";
        for identity in [false, true] {
            let mut input = if identity {
                identified_inputs()
            } else {
                inputs(&["claude", "--print"])
            };
            input.resolv_conf =
                resolv_conf_target(Path::new("../run/systemd/resolve/stub-resolv.conf"));
            let a = build_linux_jail(&input).unwrap().bwrap_args;
            let run = a
                .windows(2)
                .position(|w| w[0] == "--tmpfs" && w[1] == "/run")
                .unwrap();
            let bind = a
                .windows(3)
                .position(|w| w[0] == "--ro-bind-try" && w[1] == stub && w[2] == stub)
                .expect("the host's own file, at its own place");
            assert_eq!(bind, run + 2, "right over the jail's empty /run");
            assert!(
                !a.iter()
                    .any(|w| w == "/run/systemd/resolve" || w == "/run/systemd"),
                "the folder of the resolver's sockets is never shown"
            );
            assert!(
                !a.iter().any(|w| w.ends_with("resolv.conf") && w != stub),
                "no other resolver file, and none of the jail's own"
            );
            assert!(!a.iter().any(|w| w == "/etc/resolv.conf"));
        }
    }

    /// The resolver file a jail binds goes stale when the host replaces it
    /// by rename (a bind holds the file it started with). Where it lives in
    /// a folder of resolver data alone (resolvconf's), with no socket in it,
    /// the folder is bound instead, so the jail follows the host. Any other
    /// folder (systemd-resolved's sockets, NetworkManager's connection
    /// files), or one that holds a socket, keeps the file alone.
    ///
    /// FAILS ON REVERT: bind the file alone in `resolv_conf_bind` and
    /// resolvconf's line binds the file; bind every folder and the stub's
    /// and NetworkManager's lines bind theirs.
    #[test]
    fn a_resolver_folder_of_data_alone_is_bound_whole() {
        use launch::resolv_conf_bind;
        let no_socket = |_: &Path| false;
        let socket = |_: &Path| true;
        for (target, bound) in [
            ("/run/resolvconf/resolv.conf", "/run/resolvconf"),
            (
                "/run/systemd/resolve/stub-resolv.conf",
                "/run/systemd/resolve/stub-resolv.conf",
            ),
            (
                "/run/systemd/resolve/resolv.conf",
                "/run/systemd/resolve/resolv.conf",
            ),
            (
                "/run/NetworkManager/resolv.conf",
                "/run/NetworkManager/resolv.conf",
            ),
            (
                "/run/resolvconf/interface/eth0",
                "/run/resolvconf/interface/eth0",
            ),
        ] {
            assert_eq!(
                resolv_conf_bind(Path::new(target), no_socket),
                PathBuf::from(bound),
                "{target}"
            );
        }
        assert_eq!(
            resolv_conf_bind(Path::new("/run/resolvconf/resolv.conf"), socket),
            PathBuf::from("/run/resolvconf/resolv.conf")
        );
        let mut input = inputs(&["claude", "--print"]);
        input.resolv_conf = Some(resolv_conf_bind(
            Path::new("/run/resolvconf/resolv.conf"),
            no_socket,
        ));
        let a = build_linux_jail(&input).unwrap().bwrap_args;
        assert!(a.windows(3).any(|w| w[0] == "--ro-bind-try"
            && w[1] == "/run/resolvconf"
            && w[2] == "/run/resolvconf"));
    }

    /// O15, the one deliberate change to the plain jail's argv beside its
    /// filter: on a host whose `/etc/resolv.conf` is a link into `/run`, one
    /// read-only bind of the file it names, right after the jail's `/run`.
    /// On any other host the plain jail is its golden, byte for byte.
    #[test]
    fn the_plain_jail_moved_only_by_the_resolver_file_on_a_resolved_host() {
        let mut input = inputs(&["claude", "--print"]);
        input.resolv_conf = Some(PathBuf::from("/run/systemd/resolve/stub-resolv.conf"));
        let got = build_linux_jail(&input).unwrap().bwrap_args.join("\n");
        assert_eq!(
            got,
            GOLDEN_ARGV_PLAIN.replace(
                "--tmpfs\n/run\n",
                "--tmpfs\n/run\n--ro-bind-try\n/run/systemd/resolve/stub-resolv.conf\n\
                 /run/systemd/resolve/stub-resolv.conf\n"
            )
        );
        assert_ne!(got, GOLDEN_ARGV_PLAIN);
        assert_eq!(
            build_linux_jail(&inputs(&["claude", "--print"]))
                .unwrap()
                .bwrap_args
                .join("\n"),
            GOLDEN_ARGV_PLAIN
        );
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
                ("IW_LLM_CONFIG", "/dev/null"),
                ("IW_NOTIFY_CONFIG", "/dev/null"),
                ("IW_GUARD_SESSION", "contain"),
                ("IW_SUPPRESS_CONFIG", "/dev/null"),
            ]
            .map(|(k, v)| (k.to_string(), v.to_string()))
        );
    }

    /// A place the jail hides, as found on the host: `leads_to` where every
    /// link on the way leads (`None`: they loop), with no link on the way a
    /// program in the jail can change.
    fn place(nominal: &str, leads_to: Option<&str>, there: bool, is_dir: bool) -> HiddenPlace {
        HiddenPlace {
            nominal: PathBuf::from(nominal),
            leads_to: leads_to.map(PathBuf::from),
            there,
            is_dir,
            steered_by: None,
            inner: false,
        }
    }

    /// [`place`], a link found inside a dotdir the jail never shows.
    fn inner(nominal: &str, leads_to: &str, there: bool, is_dir: bool) -> HiddenPlace {
        HiddenPlace {
            inner: true,
            ..place(nominal, Some(leads_to), there, is_dir)
        }
    }

    /// [`place`], through a link a program in the jail can change: the
    /// place's own entry (every `deny_read` link in the project is one).
    fn steered(nominal: &str, leads_to: &str, there: bool, is_dir: bool) -> HiddenPlace {
        HiddenPlace {
            steered_by: Some(PathBuf::from(nominal)),
            ..place(nominal, Some(leads_to), there, is_dir)
        }
    }

    /// [`place`], through `link`, a link a program in the jail can change.
    fn steered_through(nominal: &str, link: &str, leads_to: Option<&str>) -> HiddenPlace {
        HiddenPlace {
            steered_by: Some(PathBuf::from(link)),
            ..place(nominal, leads_to, true, true)
        }
    }

    fn mask(abs: &str, is_dir: bool) -> DenyPath {
        DenyPath {
            abs: PathBuf::from(abs),
            is_dir,
        }
    }

    /// What the planner knows of `input`'s jail on Linux or macOS, `real`
    /// resolving each host path.
    fn facts_of(input: &JailInputs, macos: bool, real: impl Fn(&Path) -> PathBuf) -> PlaceFacts {
        place_facts(
            &input.args,
            &input.home,
            input.worktree.as_ref(),
            &input.existing_paths,
            &input.iw_binary,
            None,
            &input.tmpdir,
            macos,
            real,
        )
    }

    /// `plan_linked_places` for the dotdirs a jail never shows, on Linux
    /// and on macOS.
    fn dotdir_plans(
        places: &[HiddenPlace],
        input: &JailInputs,
        real: impl Fn(&Path) -> PathBuf + Copy,
    ) -> (LinkedPlan, LinkedPlan) {
        (
            plan_linked_places(places, &facts_of(input, false, real), &[], false).unwrap(),
            plan_linked_places(places, &facts_of(input, true, real), &[], false).unwrap(),
        )
    }

    fn paths(list: &[&str]) -> Vec<PathBuf> {
        list.iter().map(PathBuf::from).collect()
    }

    /// M30-CW-link: a dotdir the jail never shows that is a link into a
    /// folder it shows (`~/.ssh` a link to `.config/ssh`, with `~/.config`
    /// bound) showed the key through that folder: the jail covered `~/.ssh`
    /// only as named. Each such place is covered where the jail shows it, a
    /// folder by an empty tmpfs and a file by /dev/null, after every
    /// writable bind and every other mask; macOS denies where it leads,
    /// read and write (the sandbox matches the place a link leads to, and
    /// `~/.config` is writable there).
    ///
    /// FAILS ON REVERT: drop the `linked_masks` loop from
    /// `build_linux_jail` and `~/.config/ssh` is not covered; drop
    /// `linked_denies` from the macOS profile and it is not denied.
    #[test]
    fn a_dotdir_linked_into_a_folder_the_jail_shows_is_covered_there() {
        let mut input = inputs(&["claude", "--print"]);
        let places = [
            place("/home/dev/.ssh", Some("/home/dev/.config/ssh"), true, true),
            place(
                "/home/dev/.gnupg",
                Some("/home/dev/.cache/keys/gnupg"),
                true,
                true,
            ),
            place(
                "/home/dev/.aws",
                Some("/home/dev/.config/aws-credentials"),
                true,
                false,
            ),
        ];
        let (linux, macos) = dotdir_plans(&places, &input, Path::to_path_buf);
        let led = [
            "/home/dev/.config/ssh",
            "/home/dev/.cache/keys/gnupg",
            "/home/dev/.config/aws-credentials",
        ];
        assert_eq!(
            linux.masks,
            [mask(led[0], true), mask(led[1], true), mask(led[2], false),]
        );
        assert!(linux.denies.is_empty() && macos.masks.is_empty());
        assert_eq!(macos.denies, paths(&led));
        for plan in [&linux, &macos] {
            assert!(plan.left.is_empty() && plan.missing.is_empty(), "{plan:?}");
            let hidden: Vec<PathBuf> = plan.hidden.iter().map(|(_, to)| to.clone()).collect();
            assert_eq!(hidden, paths(&led));
        }
        input.linked_masks = linux.masks;
        input.linked_denies = macos.denies;
        let a = build_linux_jail(&input).unwrap().bwrap_args;
        let ssh = a
            .windows(2)
            .position(|w| w[0] == "--tmpfs" && w[1] == "/home/dev/.config/ssh")
            .expect("~/.config/ssh under an empty tmpfs");
        let aws = a
            .windows(3)
            .position(|w| {
                w[0] == "--ro-bind"
                    && w[1] == "/dev/null"
                    && w[2] == "/home/dev/.config/aws-credentials"
            })
            .expect("the credentials file under /dev/null");
        let last_writable = a.windows(2).rposition(|w| w[0] == "--bind").unwrap();
        let last_deny = a
            .windows(2)
            .rposition(|w| w[1] == "/home/dev/proj/secrets")
            .unwrap();
        assert!(ssh > last_writable && ssh > last_deny && aws > last_deny);
        let profile = build_macos_profile(&input).unwrap().profile;
        for path in led {
            for access in ["read", "write"] {
                let rule = format!("(deny file-{access}* (subpath \"{path}\"))");
                assert!(profile.contains(&rule), "{rule}");
            }
        }
    }

    /// A folder the jail shows that is itself a link to a folder above a
    /// place it hides shows that place below it: `~/.cache` a link to the
    /// home's `dots` folder, where `~/.ssh` leads, shows the key at
    /// `~/.cache/ssh`; `~/.cache` a link to the home shows an ordinary
    /// `~/.ssh` folder at `~/.cache/.ssh`. Each is covered there; the
    /// ordinary folder needs no deny on macOS beyond the one as named.
    ///
    /// FAILS ON REVERT: take only the places a folder shows under its own
    /// name (skip each shown folder whose host path is not its name) and
    /// neither is covered.
    #[test]
    fn a_shown_folder_that_leads_above_a_hidden_place_shows_it_and_it_is_covered() {
        let input = inputs(&["claude", "--print"]);
        for (cache, ssh, view, deny) in [
            (
                "/home/dev/dots",
                Some("/home/dev/dots/ssh"),
                "/home/dev/.cache/ssh",
                true,
            ),
            ("/home/dev", None, "/home/dev/.cache/.ssh", false),
        ] {
            let real = |path: &Path| {
                if path == Path::new("/home/dev/.cache") {
                    PathBuf::from(cache)
                } else {
                    path.to_path_buf()
                }
            };
            let places = [place(
                "/home/dev/.ssh",
                Some(ssh.unwrap_or("/home/dev/.ssh")),
                true,
                true,
            )];
            let (linux, macos) = dotdir_plans(&places, &input, real);
            assert_eq!(linux.masks, [mask(view, true)], "{cache}");
            assert_eq!(macos.denies.len(), usize::from(deny), "{cache}");
            assert!(linux.left.is_empty() && macos.left.is_empty(), "{cache}");
        }
    }

    /// Never a mask or deny laid by a link onto what the jail needs: a
    /// dotdir that leads onto the agent's settings, the project or the
    /// folder that holds the guard is left as it is, as is one whose links
    /// loop; each is said, and the jail starts. A person's own link out of
    /// the home (no link on the way a program in the jail can change) is
    /// denied there on macOS, where the jail reads everywhere else; on Linux
    /// that place is not in the jail, and nothing is said of it. A dotdir
    /// that leads into the project is hidden there, and said.
    ///
    /// FAILS ON REVERT: drop the needed check from `plan_linked_places` and
    /// the jail's `~/.claude` (its hook) and the project are covered; deny
    /// no place outside the home on macOS and `/srv/keys/ssh` is readable.
    #[test]
    fn a_hidden_place_a_link_leads_out_of_the_home_or_onto_what_the_jail_needs_is_left_and_said() {
        let input = inputs(&["claude", "--print"]);
        let places = [
            place("/home/dev/.ssh", Some("/srv/keys/ssh"), true, true),
            place("/home/dev/.gnupg", Some("/home/dev/.claude"), true, true),
            place("/home/dev/.aws", Some("/home/dev/proj"), true, true),
            place("/home/dev/.mozilla", Some("/home/dev/.local"), true, true),
            place("/home/dev/.thunderbird", None, false, false),
        ];
        let (linux, macos) = dotdir_plans(&places, &input, Path::to_path_buf);
        let needed = [
            left_needed(
                Path::new("/home/dev/.gnupg"),
                Path::new("/home/dev/.claude"),
            ),
            left_needed(Path::new("/home/dev/.aws"), Path::new("/home/dev/proj")),
            left_needed(
                Path::new("/home/dev/.mozilla"),
                Path::new("/home/dev/.local"),
            ),
            "/home/dev/.thunderbird is a link that loops: the jail hides nothing through it; \
             to hide it, fix the link"
                .to_string(),
        ];
        assert!(linux.masks.is_empty(), "{:?}", linux.masks);
        assert_eq!(linux.left, needed);
        assert_eq!(macos.denies, paths(&["/srv/keys/ssh"]));
        assert_eq!(macos.left, needed);
        assert!(needed[0].contains("where the jail keeps what it needs"));
        for plan in [&linux, &macos] {
            assert_eq!(
                plan.hidden,
                [(
                    PathBuf::from("/home/dev/.ssh"),
                    PathBuf::from("/srv/keys/ssh")
                )]
            );
        }
        // A project outside the home is the person's own: a dotdir that
        // leads into it is covered there, and said.
        let mut elsewhere = input.clone();
        elsewhere.args.project = PathBuf::from("/srv/work");
        let (linux, macos) = dotdir_plans(
            &[place("/home/dev/.ssh", Some("/srv/work/keys"), true, true)],
            &elsewhere,
            Path::to_path_buf,
        );
        let into = "/home/dev/.ssh leads into your project, to /srv/work/keys: the jail hides it \
                    there too (the agent cannot read it, nor change what you keep there)";
        assert_eq!(linux.masks, [mask("/srv/work/keys", true)]);
        assert_eq!(linux.left, [into]);
        assert_eq!(macos.denies, paths(&["/srv/work/keys"]));
        assert_eq!(macos.left, [into]);
    }

    /// M30C-1: a dotdir the jail never shows whose way goes through a link
    /// in a folder the jail writes (`~/.aws` a link to `~/.cache/aws-link`,
    /// itself a link to `~/.cache/aws`). The jail hid `~/.cache/aws`, but a
    /// program in it could replace `~/.cache/aws-link` with a folder of its
    /// own, on the host, and the host's `aws` then ran its
    /// `credential_process`. No mount or deny pins a link, so such a launch
    /// is refused, on Linux and macOS, wherever the link leads (the person's
    /// own places, outside the home, onto what the jail needs, round in a
    /// loop), naming the link. A link the jail cannot change, the dotdir's
    /// own entry, is no refusal.
    ///
    /// FAILS ON REVERT: drop the refusal from `plan_linked_places` and the
    /// jail covers `~/.cache/aws` and starts.
    #[test]
    fn a_dotdir_through_a_link_the_jail_can_change_is_refused() {
        let input = inputs(&["claude", "--print"]);
        for macos in [false, true] {
            let facts = facts_of(&input, macos, Path::to_path_buf);
            for leads_to in [
                Some("/home/dev/.cache/aws"),
                Some("/srv/aws"),
                Some("/home/dev/.claude"),
                None,
            ] {
                let place =
                    steered_through("/home/dev/.aws", "/home/dev/.cache/aws-link", leads_to);
                let refused = plan_linked_places(&[place], &facts, &[], false)
                    .unwrap_err()
                    .to_string();
                assert_eq!(
                    refused,
                    "/home/dev/.aws goes through /home/dev/.cache/aws-link, a link in a folder a \
                     program in the jail can write: that program could replace the link on the \
                     host, and the host would then find its files at /home/dev/.aws. Replace the \
                     link with what it leads to, or link /home/dev/.aws straight to its place, \
                     and start the jail again",
                    "macos={macos} {leads_to:?}"
                );
            }
            // A `deny_read` place: the project is the agent's to write.
            let deny = steered("/home/dev/proj/.env", "/home/dev/.cache/env", true, false);
            assert!(plan_linked_places(&[deny], &facts, &[], true).is_ok());
            // The dotdir's own link, in the home, is the person's.
            let own = place("/home/dev/.aws", Some("/home/dev/.cache/aws"), true, true);
            assert!(plan_linked_places(&[own], &facts, &[], false).is_ok());
        }
    }

    /// M30-SEC-1: the guard's own files are what the jail needs in either
    /// direction. A link that leads INTO the agent's settings folder (a
    /// `.env` link to `~/.claude/settings.json`, the file that carries the
    /// hook) was masked with /dev/null at the next launch: the check only
    /// looked for a needed path below where the link led. It is left and
    /// said now, a `deny_read` link and a dotdir alike, also where the
    /// settings folder is itself a link and the jail shows it at a second
    /// place, and so is a link onto the guard or the system profiles.
    ///
    /// FAILS ON REVERT: check only `need.starts_with(place)` in
    /// `PlaceFacts::needs` and `settings.json` is masked, the argv binds
    /// /dev/null over it, and `~/dots/app` is covered at `~/.claude/app`.
    #[test]
    fn a_link_into_the_agents_settings_or_the_guard_is_never_hidden() {
        let mut input = inputs(&["claude", "--print"]);
        let linux = facts_of(&input, false, Path::to_path_buf);
        let found = [
            steered(
                "/home/dev/proj/.env",
                "/home/dev/.claude/settings.json",
                true,
                false,
            ),
            steered(
                "/home/dev/proj/.env.guard",
                "/home/dev/.local/bin/innerwarden",
                true,
                false,
            ),
            steered(
                "/home/dev/proj/.env.profiles",
                "/etc/innerwarden/agent-profiles.toml",
                true,
                false,
            ),
        ];
        let (masks, linked) = plan_denied_paths(&found, &linux);
        assert!(masks.is_empty() && linked.masks.is_empty(), "{masks:?}");
        assert_eq!(
            linked.left,
            [
                left_needed(
                    Path::new("/home/dev/proj/.env"),
                    Path::new("/home/dev/.claude/settings.json")
                ),
                left_needed(
                    Path::new("/home/dev/proj/.env.guard"),
                    Path::new("/home/dev/.local/bin/innerwarden")
                ),
                left_needed(
                    Path::new("/home/dev/proj/.env.profiles"),
                    Path::new("/etc/innerwarden/agent-profiles.toml")
                ),
            ]
        );
        let (macos_masks, macos_linked) =
            plan_denied_paths(&found, &facts_of(&input, true, Path::to_path_buf));
        assert!(macos_masks.is_empty() && macos_linked.left.len() == 3);
        input.deny_paths = masks;
        let a = build_linux_jail(&input).unwrap().bwrap_args.join(" ");
        assert!(!a.contains("/home/dev/.claude/settings.json"), "{a}");
        // `~/.claude` a link to `~/dots`: the jail shows that folder at
        // both names, and nothing in it is hidden, as named or as shown.
        let dots = |path: &Path| {
            if path == Path::new("/home/dev/.claude") {
                PathBuf::from("/home/dev/dots")
            } else {
                path.to_path_buf()
            }
        };
        let (masks, linked) = plan_denied_paths(
            &[steered(
                "/home/dev/proj/secrets",
                "/home/dev/dots/app",
                true,
                true,
            )],
            &facts_of(&input, false, dots),
        );
        assert!(masks.is_empty() && linked.masks.is_empty(), "{linked:?}");
        let (linux, macos) = dotdir_plans(
            &[place(
                "/home/dev/.ssh",
                Some("/home/dev/dots/ssh"),
                true,
                true,
            )],
            &input,
            dots,
        );
        assert!(linux.masks.is_empty() && macos.denies.is_empty());
        assert_eq!(linux.left.len(), 1, "{:?}", linux.left);
        assert!(linux.left[0].contains("where the jail keeps what it needs"));
    }

    /// M30-SEC-2: the worktree's folders come from the project's `.git`,
    /// which the agent writes. They are neither what the jail needs nor the
    /// person's own: a planted `gitdir` that names where `~/.ssh` leads no
    /// longer leaves that place shown (it is covered after the worktree's
    /// bind, and the worktree is refused), and one that names `/etc` does
    /// not make `/etc` a place a `.env` link covers.
    ///
    /// FAILS ON REVERT: put the worktree's folders back in `guard`/`work`
    /// or in `own` and `~/.config/ssh` is left shown, or `/etc/app/env` is
    /// masked; drop the hidden-target check from `validate_jail_inputs` and
    /// the worktree is taken.
    #[test]
    fn a_worktree_the_agent_names_never_unhides_a_place_or_makes_one_its_own() {
        let mut input = inputs(&["claude", "--print"]);
        input.worktree = Some(Worktree {
            git_dir: PathBuf::from("/home/dev/.config/ssh"),
            common_dir: PathBuf::from("/home/dev/.config/ssh"),
        });
        let (linux, macos) = dotdir_plans(
            &[place(
                "/home/dev/.ssh",
                Some("/home/dev/.config/ssh"),
                true,
                true,
            )],
            &input,
            Path::to_path_buf,
        );
        assert_eq!(linux.masks, [mask("/home/dev/.config/ssh", true)]);
        assert_eq!(macos.denies, paths(&["/home/dev/.config/ssh"]));
        assert!(linux.left.is_empty(), "{:?}", linux.left);
        input.linked_masks = linux.masks.clone();
        let a = build_linux_jail(&input).unwrap().bwrap_args;
        let bound = a
            .windows(3)
            .rposition(|w| w[0] == "--bind" && w[1] == "/home/dev/.config/ssh")
            .expect("the worktree's bind");
        let covered = a
            .windows(2)
            .rposition(|w| w[0] == "--tmpfs" && w[1] == "/home/dev/.config/ssh")
            .expect("covered");
        assert!(covered > bound);
        input.hidden_targets = linux.hidden;
        let refused = validate_jail_inputs(&input).unwrap_err().to_string();
        assert!(
            refused.contains("unsafe worktree git path '/home/dev/.config/ssh'")
                && refused.contains("where /home/dev/.ssh leads"),
            "{refused}"
        );
        // A `gitdir` of `/etc` is not the person's own place.
        let mut etc = inputs(&["claude", "--print"]);
        etc.worktree = Some(Worktree {
            git_dir: PathBuf::from("/etc"),
            common_dir: PathBuf::from("/etc"),
        });
        let (masks, linked) = plan_denied_paths(
            &[steered("/home/dev/proj/.env", "/etc/app/env", true, false)],
            &facts_of(&etc, false, Path::to_path_buf),
        );
        assert!(masks.is_empty() && linked.masks.is_empty(), "{masks:?}");
        assert_eq!(linked.left.len(), 1, "{:?}", linked.left);
    }

    /// M30-SEC-3: on macOS the jail reads everywhere it is not denied, so a
    /// dotdir (or InnerWarden's own folder) that a person's own link leads
    /// outside the home is denied where it leads, read and write; the deny
    /// of the name alone closed only the way through the link. (Through a
    /// link a program in the jail can change, the launch is refused,
    /// M30C-1.)
    ///
    /// FAILS ON REVERT: leave every place outside the home on macOS and
    /// `/Volumes/keys/ssh` and `/srv/iw` are not denied.
    #[test]
    fn on_macos_a_place_a_persons_link_leads_outside_the_home_is_denied_there() {
        let mut input = inputs(&["claude", "--print"]);
        let macos = plan_linked_places(
            &[
                place("/home/dev/.ssh", Some("/Volumes/keys/ssh"), true, true),
                place("/home/dev/.aws", Some("/Volumes/aws"), true, true),
            ],
            &facts_of(&input, true, Path::to_path_buf),
            &[],
            false,
        )
        .unwrap();
        assert_eq!(macos.denies, paths(&["/Volumes/keys/ssh", "/Volumes/aws"]));
        assert!(macos.left.is_empty(), "{:?}", macos.left);
        input.linked_denies = macos.denies;
        input.iw_config_link = true;
        input.iw_config_real = PathBuf::from("/srv/iw");
        let profile = build_macos_profile(&input).unwrap().profile;
        for path in [
            "/Volumes/keys/ssh",
            "/srv/iw",
            "/home/dev/.config/innerwarden",
        ] {
            for access in ["read", "write"] {
                let rule = format!("(deny file-{access}* (subpath \"{path}\"))");
                assert!(profile.contains(&rule), "{rule}");
            }
        }
    }

    /// M30-SEC-4: a profile's read-only path that holds where a dotdir the
    /// jail never shows leads (`extra_ro=/data`, `~/.ssh` a link to
    /// `/data/keys/ssh`) is refused, as one that holds `~/.ssh` itself is,
    /// naming the dotdir. A `deny_read` link into a read-only path that is
    /// there is covered there (the read-only paths are the person's own for
    /// a place that is there), as before the links were taken.
    ///
    /// FAILS ON REVERT: drop the hidden-target check for read-only paths and
    /// the jail shows the key through `/data`; drop `own_read_only` and
    /// `/data/app/.env` is left shown.
    #[test]
    fn a_read_only_path_over_where_a_dotdir_leads_is_refused_and_a_secret_there_is_covered() {
        let mut input = inputs(&["claude", "--print"]);
        input.args.extra_ro = vec![PathBuf::from("/data")];
        let (linux, _) = dotdir_plans(
            &[place("/home/dev/.ssh", Some("/data/keys/ssh"), true, true)],
            &input,
            Path::to_path_buf,
        );
        input.hidden_targets = linux.hidden;
        let refused = validate_jail_inputs(&input).unwrap_err().to_string();
        assert_eq!(
            refused,
            "unsafe extra read-only path '/data': it overlaps '/data/keys/ssh', where \
             /home/dev/.ssh leads, which the jail hides"
        );
        let (masks, linked) = plan_denied_paths(
            &[steered(
                "/home/dev/proj/.env",
                "/data/app/.env",
                true,
                false,
            )],
            &facts_of(&input, false, Path::to_path_buf),
        );
        assert_eq!(masks, [mask("/data/app/.env", false)]);
        assert!(linked.left.is_empty(), "{:?}", linked.left);
    }

    /// M30-R3: a dotdir that a link leads into the project (GNU stow's
    /// `~/.ssh` a link to `dotfiles/ssh/.ssh`, the agent at work in
    /// `~/dotfiles`) is hidden there, and the launcher says so: the folder
    /// is empty in the jail, and nothing the agent writes there is kept.
    ///
    /// FAILS ON REVERT: drop the line from `plan_linked_places` and the
    /// project's folder is emptied without a word.
    #[test]
    fn a_dotdir_a_link_leads_into_the_project_is_hidden_there_and_said() {
        let mut input = inputs(&["claude", "--print"]);
        input.args.project = PathBuf::from("/home/dev/dotfiles");
        let led = "/home/dev/dotfiles/ssh/.ssh";
        let (linux, macos) = dotdir_plans(
            &[place("/home/dev/.ssh", Some(led), true, true)],
            &input,
            Path::to_path_buf,
        );
        let said = said_in_project(Path::new("/home/dev/.ssh"), Path::new(led));
        assert_eq!(linux.masks, [mask(led, true)]);
        assert_eq!(linux.left, std::slice::from_ref(&said));
        assert_eq!(macos.denies, paths(&[led]));
        assert_eq!(macos.left, [said]);
        // A `deny_read` path in the project is there by design: not said.
        let (_, linked) = plan_denied_paths(
            &[steered(
                "/home/dev/dotfiles/.env",
                "/home/dev/dotfiles/env/real",
                true,
                false,
            )],
            &facts_of(&input, false, Path::to_path_buf),
        );
        assert!(linked.left.is_empty(), "{:?}", linked.left);
    }

    /// M30C-2: a mount moves with the folder it is in, and Linux renames
    /// any folder that is not itself a mount point. A cover two or more
    /// folders below its bind (GNU stow's `~/.ssh` a link to
    /// `dotfiles/ssh/.ssh`, the agent at work in `~/dotfiles`; `~/.ssh` a
    /// link to `~/.config/keys/ssh`) was taken away by renaming the folder
    /// between, and a folder of the agent's took its name, which the host's
    /// link leads to. Each folder between is bound onto itself, right after
    /// the bind that holds it and before every mask; one right below its
    /// bind needs none, nor one a read-only path holds. macOS denies
    /// writing each folder above the place, as itself, that the jail may
    /// write: the project included. In a common layout there is none, and
    /// the identified jail pins only its records' folders.
    ///
    /// FAILS ON REVERT: drop the pins from `build_linux_jail` or the
    /// literal denies from `build_macos_profile` and the folder between is
    /// neither a mount point nor closed.
    #[test]
    fn the_folders_above_a_cover_the_host_reaches_by_name_are_pinned() {
        let mut stow = inputs(&["claude", "--print"]);
        stow.args.project = PathBuf::from("/home/dev/dotfiles");
        stow.deny_paths.clear();
        let led = "/home/dev/dotfiles/ssh/.ssh";
        let (linux, macos) = dotdir_plans(
            &[place("/home/dev/.ssh", Some(led), true, true)],
            &stow,
            Path::to_path_buf,
        );
        stow.linked_masks = linux.masks;
        assert_eq!(
            linux_pins(&stow),
            [(PinRoot::Project, PathBuf::from("/home/dev/dotfiles/ssh"))]
        );
        let a = build_linux_jail(&stow).unwrap().bwrap_args;
        let project = a
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == "/home/dev/dotfiles")
            .unwrap();
        let pin = a
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == "/home/dev/dotfiles/ssh" && w[2] == w[1])
            .expect("the folder between is a mount point");
        let cover = a
            .windows(2)
            .position(|w| w[0] == "--tmpfs" && w[1] == led)
            .unwrap();
        assert!(project < pin && pin < cover, "{a:?}");
        stow.linked_denies = macos.denies;
        let profile = build_macos_profile(&stow).unwrap().profile;
        for folder in ["/home/dev/dotfiles/ssh", "/home/dev/dotfiles"] {
            let rule = macos_pin_rule(Path::new(folder));
            assert!(profile.contains(&rule), "{rule}");
        }
        assert!(!profile.contains(&macos_pin_rule(Path::new("/home/dev"))));
        // In a home folder the jail binds: pinned right after that bind.
        let mut keys = inputs(&["claude", "--print"]);
        keys.args.extra_ro = vec![PathBuf::from("/home/dev/.cache/ro")];
        let (linux, macos) = dotdir_plans(
            &[place(
                "/home/dev/.ssh",
                Some("/home/dev/.config/keys/ssh"),
                true,
                true,
            )],
            &keys,
            Path::to_path_buf,
        );
        keys.linked_masks = linux.masks;
        keys.hide_paths = vec![
            mask("/home/dev/.cache/ro/x/y", true),
            mask("/home/dev/.config/app", true),
        ];
        assert_eq!(
            linux_pins(&keys),
            [(PinRoot::Home, PathBuf::from("/home/dev/.config/keys"))]
        );
        let a = build_linux_jail(&keys).unwrap().bwrap_args;
        let pin = a
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == "/home/dev/.config/keys")
            .unwrap();
        let last_dotdir = a
            .windows(2)
            .position(|w| w[0] == "--bind" && w[1] == "/home/dev/.cache")
            .unwrap();
        let iw = a
            .windows(2)
            .position(|w| w[1] == "/home/dev/.config/innerwarden")
            .unwrap();
        assert!(last_dotdir < pin && pin < iw, "{a:?}");
        keys.linked_denies = macos.denies;
        let profile = build_macos_profile(&keys).unwrap().profile;
        for folder in ["/home/dev/.config/keys", "/home/dev/.config"] {
            let rule = macos_pin_rule(Path::new(folder));
            assert!(profile.contains(&rule), "{rule}");
        }
        // A common layout: none on Linux; on macOS the project and
        // `~/.config` ([`a_macos_jail_never_moves_a_folder_above_what_it_denies`]).
        let plain = inputs(&["claude", "--print"]);
        assert!(linux_pins(&plain).is_empty());
        assert_eq!(
            macos_pins(&plain),
            [
                PathBuf::from("/home/dev/proj"),
                PathBuf::from("/home/dev/.config")
            ]
        );
        assert_eq!(
            linux_pins(&identified_inputs()),
            [
                (PinRoot::Home, PathBuf::from("/home/dev/.local/state")),
                (
                    PinRoot::Home,
                    PathBuf::from("/home/dev/.local/state/innerwarden")
                ),
            ]
        );
    }

    /// JAIL-PINS: a project two folders inside a home folder the jail binds
    /// (`~/.cache/work/proj`), and `~/.ssh` a link into it. The pins started
    /// at the nearest bind, the project's, so `~/.cache/work`, between the
    /// `~/.cache` bind and the project's, could be renamed (measured in a
    /// plain and an identified jail): the project's mount and the cover in
    /// it moved with it, the folder the jail made at the old name was where
    /// the host's `~/.ssh` led, and a planted `authorized_keys` reached it.
    /// Every folder the jail writes between the home and the place is pinned
    /// now, right after the bind that shows it: `~/.cache/work` after the
    /// home folders and before the project, `keys` after the project. A
    /// folder a read-only bind shows is never pinned; the folder above that
    /// bind still is. macOS closes the same folders, and the project.
    ///
    /// FAILS ON REVERT: pin only below the nearest bind and `~/.cache/work`
    /// is neither pinned nor a mount point.
    #[test]
    fn every_folder_the_jail_writes_between_the_home_and_a_cover_is_pinned() {
        let mut nested = inputs(&["claude", "--print"]);
        nested.args.project = PathBuf::from("/home/dev/.cache/work/proj");
        nested.deny_paths.clear();
        let led = "/home/dev/.cache/work/proj/keys/ssh";
        let (linux, macos) = dotdir_plans(
            &[place("/home/dev/.ssh", Some(led), true, true)],
            &nested,
            Path::to_path_buf,
        );
        nested.linked_masks = linux.masks;
        nested.linked_denies = macos.denies;
        assert_eq!(
            linux_pins(&nested),
            [
                (PinRoot::Home, PathBuf::from("/home/dev/.cache/work")),
                (
                    PinRoot::Project,
                    PathBuf::from("/home/dev/.cache/work/proj/keys")
                ),
            ]
        );
        let a = build_linux_jail(&nested).unwrap().bwrap_args;
        let at = |w: &[&str]| {
            a.windows(w.len())
                .position(|x| x == w)
                .unwrap_or_else(|| panic!("{w:?} in {a:?}"))
        };
        let cache = at(&["--bind", "/home/dev/.cache", "/home/dev/.cache"]);
        let work = at(&["--bind", "/home/dev/.cache/work", "/home/dev/.cache/work"]);
        let project = at(&[
            "--bind",
            "/home/dev/.cache/work/proj",
            "/home/dev/.cache/work/proj",
        ]);
        let keys = at(&[
            "--bind",
            "/home/dev/.cache/work/proj/keys",
            "/home/dev/.cache/work/proj/keys",
        ]);
        let cover = at(&["--tmpfs", led]);
        assert!(
            cache < work && work < project && project < keys && keys < cover,
            "{a:?}"
        );
        // A read-only bind in between: nothing in it is pinned, and the
        // folder above it still is.
        let mut read_only = inputs(&["claude", "--print"]);
        read_only.args.extra_ro = vec![PathBuf::from("/home/dev/.cache/work/ro")];
        read_only.hide_paths = vec![mask("/home/dev/.cache/work/ro/x/y", true)];
        assert_eq!(
            linux_pins(&read_only),
            [(PinRoot::Home, PathBuf::from("/home/dev/.cache/work"))]
        );
        // A place the jail shows only in its own empty home is nobody's to
        // rename: nothing.
        let mut own = inputs(&["claude", "--print"]);
        own.hide_paths = vec![mask("/home/dev/notes/a/b", true)];
        assert!(linux_pins(&own).is_empty());
        let profile = build_macos_profile(&nested).unwrap().profile;
        for folder in [
            "/home/dev/.cache",
            "/home/dev/.cache/work",
            "/home/dev/.cache/work/proj",
            "/home/dev/.cache/work/proj/keys",
        ] {
            let rule = macos_pin_rule(Path::new(folder));
            assert!(profile.contains(&rule), "{rule}");
        }
    }

    /// JP-1 (JAIL-PINS fixes): the pins walk a place by its spelling, so a
    /// place spelled through `..` (the records folder of an
    /// `XDG_STATE_HOME=~/.local/state/../../.cache/st`) gave the pin
    /// `~/.local/state/../..`, which bwrap took for the host's home and
    /// bound read-write over the jail's empty one. Such a place is never
    /// walked, and the home, or a folder above it, is never pinned; the
    /// records folder itself is never spelled so
    /// ([`a_state_home_with_a_parent_step_is_ignored`]).
    ///
    /// FAILS ON REVERT: walk every place as spelled and the home is pinned
    /// as `/home/dev/.local/state/../..`.
    #[test]
    fn a_place_spelled_through_a_parent_step_never_pins_the_home() {
        let mut input = identified_inputs();
        input.records_dirs = vec![PathBuf::from(
            "/home/dev/.local/state/../../.cache/st/innerwarden/instances",
        )];
        let plain = |path: &Path| {
            path.components().all(|step| {
                matches!(
                    step,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        };
        let pins = linux_pins(&input);
        assert!(
            pins.iter()
                .all(|(_, folder)| plain(folder) && !input.home.starts_with(folder)),
            "{pins:?}"
        );
        // No bind in the whole jail is spelled through `..` or is the home.
        let a = build_linux_jail(&input).unwrap().bwrap_args;
        for bind in a.windows(3).filter(|w| w[0] == "--bind") {
            let at = Path::new(&bind[1]);
            assert!(plain(at) && at != input.home, "{bind:?} in {a:?}");
        }
        // Not even under a bind that holds the home (a project above it,
        // which the jail refuses anyway): the walk stops at the home.
        let mut above = inputs(&["claude", "--print"]);
        above.args.project = PathBuf::from("/home");
        above.deny_paths.clear();
        above.hide_paths = vec![mask("/home/dev/notes/a", true)];
        let pins = linux_pins(&above);
        assert!(
            pins.contains(&(PinRoot::Project, PathBuf::from("/home/dev/notes")))
                && pins
                    .iter()
                    .all(|(_, folder)| !above.home.starts_with(folder)),
            "{pins:?}"
        );
        // A plain place keeps its pins.
        assert_eq!(
            linux_pins(&identified_inputs()),
            [
                (PinRoot::Home, PathBuf::from("/home/dev/.local/state")),
                (
                    PinRoot::Home,
                    PathBuf::from("/home/dev/.local/state/innerwarden")
                ),
            ]
        );
    }

    /// JAIL-PINS: an identified Linux jail with the launcher's records behind
    /// a link in a folder the jail writes cannot be protected (a mount pins a
    /// folder, never a link), so it is refused, and the words say why and
    /// give the one remedy that works there. The remedy of the other places
    /// ("link it straight to its place") would put a link to the records in
    /// that same folder, refused again. Names are printed escaped.
    ///
    /// FAILS ON REVERT: refuse with `steered_link_refused` and the remedy
    /// cannot be followed.
    #[test]
    fn the_records_behind_a_link_are_refused_with_the_one_remedy_that_works() {
        let said = records_link_refused(
            Path::new("/home/dev/.local/state/innerwarden/instances"),
            Path::new("/home/dev/.local/state"),
        )
        .to_string();
        assert!(
            said.starts_with(
                "the launcher keeps its records of identified jails in \
                 /home/dev/.local/state/innerwarden/instances, and the way there goes through \
                 /home/dev/.local/state, a link in a folder a program in the jail can write"
            ),
            "{said}"
        );
        assert!(
            said.contains("the identified jail does not start"),
            "{said}"
        );
        assert!(
            said.ends_with(
                "Replace /home/dev/.local/state with the folder it leads to, and start the jail again"
            ),
            "{said}"
        );
        assert!(!said.contains("straight to its place"), "{said}");
        let odd = records_link_refused(Path::new("/home/dev/a\nb"), Path::new("/home/dev/a\nb"))
            .to_string();
        assert!(!odd.contains('\n'), "{odd}");
    }

    /// JAIL-PINS (macOS): the sandbox denies by path, and lets a program in
    /// the jail rename a folder it may write; what was denied under it is
    /// not denied at the new name. Measured on macOS with every default
    /// profile: `mv ~/.config` read InnerWarden's model key, `mv` of the
    /// project read its `.env`, `mv` of a folder between the project and a
    /// `deny_read` path read that secret, and a link of the jail's own put at
    /// `~/.config` had the host's guard read the `suppress.toml` planted
    /// there. Every macOS profile now closes, each as itself, the project,
    /// `~/.config`, every folder between the project and each denied path,
    /// and every folder above where InnerWarden's folder leads that the jail
    /// may write. Never the home, never what is in them.
    ///
    /// FAILS ON REVERT: pin only the folders above a linked place (the pins
    /// of #211) and none of these is closed; drop the project and it moves.
    #[test]
    fn a_macos_jail_never_moves_a_folder_above_what_it_denies() {
        let mut input = inputs(&["claude", "--print"]);
        input
            .deny_paths
            .push(mask("/home/dev/proj/sub/dir/.env", false));
        input
            .deny_paths
            .push(mask("/home/dev/.cache/tool/token", false));
        assert_eq!(
            macos_pins(&input),
            paths(&[
                "/home/dev/proj",
                "/home/dev/.config",
                "/home/dev/.cache",
                "/home/dev/proj/sub",
                "/home/dev/.cache/tool",
                "/home/dev/proj/sub/dir",
            ])
        );
        let profile = build_macos_profile(&input).unwrap().profile;
        let last_deny = profile
            .rfind("(deny file-write* (subpath")
            .expect("the write denies");
        for folder in macos_pins(&input) {
            let rule = macos_pin_rule(&folder);
            let at = profile.find(&rule).unwrap_or_else(|| panic!("{rule}"));
            assert!(at > last_deny, "{rule} before a deny it guards");
        }
        assert!(!profile.contains(&macos_pin_rule(Path::new("/home/dev"))));
        // Only renaming, removal and replacement: a rule on all of writing
        // also made the folder read as not writable (`access(W_OK)`) and
        // refused its mode and times, which `create-next-app`, `rsync -a`
        // and `cp -a` into the project need.
        assert!(
            !profile.contains("(deny file-write* (literal"),
            "a pin denies all of writing: {profile}"
        );
        // A project with nothing denied in it is closed too: the sandbox
        // must never let it move from under the name the jail works at.
        let mut bare = inputs(&["claude", "--print"]);
        bare.deny_paths.clear();
        assert_eq!(
            macos_pins(&bare),
            paths(&["/home/dev/proj", "/home/dev/.config"])
        );
        // Where `~/.config` is a link into a folder the jail writes: the
        // folders above where it leads are closed too.
        let mut linked = inputs(&["claude", "--print"]);
        linked.iw_config_real = PathBuf::from("/home/dev/.local/cfg/innerwarden");
        let pins = macos_pins(&linked);
        for folder in [
            "/home/dev/.config",
            "/home/dev/.local",
            "/home/dev/.local/cfg",
        ] {
            assert!(pins.contains(&PathBuf::from(folder)), "{folder}: {pins:?}");
        }
        // Left as it is (onto what the jail needs): not denied, so not
        // closed either.
        linked.iw_config_left = true;
        assert!(!macos_pins(&linked).contains(&PathBuf::from("/home/dev/.local/cfg")));
        // The whole profile of the common layout, byte for byte.
        assert_eq!(
            build_macos_profile(&inputs(&["claude", "--print"]))
                .unwrap()
                .profile,
            GOLDEN_MACOS_PROFILE
        );
    }

    /// M30C-3: a link inside a dotdir the jail never shows (`~/.ssh` a
    /// folder of its own, `~/.ssh/config` and `~/.ssh/id_ed25519` links
    /// into `~/.config/dotfiles/ssh`, as GNU stow and chezmoi make them
    /// where `~/.ssh` is there) is hidden where it leads, as a dotdir that
    /// is a link is: on Linux under /dev/null where the jail shows it, on
    /// macOS denied there, the folders above it pinned. One that leads to
    /// nothing yet is never made (a file or a folder?): where a Linux jail
    /// shows that place, the launch is refused; where it does not, or on
    /// macOS (the deny covers what is not there), it is not.
    ///
    /// FAILS ON REVERT: drop the refusal of an inner link to nothing from
    /// `plan_linked_places` and the jail starts with the place free to make.
    #[test]
    fn a_link_inside_a_dotdir_the_jail_never_shows_is_hidden_where_it_leads() {
        let mut input = inputs(&["claude", "--print"]);
        let key = "/home/dev/.config/dotfiles/ssh/id_ed25519";
        let config = "/home/dev/.config/dotfiles/ssh/config";
        let places = [
            inner("/home/dev/.ssh/id_ed25519", key, true, false),
            inner("/home/dev/.ssh/config", config, true, false),
        ];
        let (linux, macos) = dotdir_plans(&places, &input, Path::to_path_buf);
        assert_eq!(linux.masks, [mask(key, false), mask(config, false)]);
        assert!(
            linux.missing.is_empty() && linux.left.is_empty(),
            "{linux:?}"
        );
        assert_eq!(macos.denies, paths(&[key, config]));
        input.linked_masks = linux.masks;
        input.linked_denies = macos.denies;
        let a = build_linux_jail(&input).unwrap().bwrap_args;
        assert!(a
            .windows(3)
            .any(|w| w[0] == "--ro-bind" && w[1] == "/dev/null" && w[2] == key));
        assert_eq!(
            linux_pins(&input),
            [
                (PinRoot::Home, PathBuf::from("/home/dev/.config/dotfiles")),
                (
                    PinRoot::Home,
                    PathBuf::from("/home/dev/.config/dotfiles/ssh")
                ),
            ]
        );
        let profile = build_macos_profile(&input).unwrap().profile;
        for rule in [
            format!("(deny file-read* (subpath \"{key}\"))"),
            format!("(deny file-write* (subpath \"{config}\"))"),
            macos_pin_rule(Path::new("/home/dev/.config/dotfiles/ssh")),
        ] {
            assert!(profile.contains(&rule), "{rule}");
        }
        // Leads to nothing yet, where the Linux jail writes: refused.
        let nothing = [inner("/home/dev/.ssh/config", config, false, false)];
        let refused = plan_linked_places(
            &nothing,
            &facts_of(&input, false, Path::to_path_buf),
            &[],
            false,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            refused,
            "/home/dev/.ssh/config is a link to /home/dev/.config/dotfiles/ssh/config, which is \
             not there, in a folder a program in the jail can write: that program could make \
             it, and the host would read it as /home/dev/.ssh/config. Make it (an empty file or \
             folder), or remove the link, and start the jail again"
        );
        let macos = plan_linked_places(
            &nothing,
            &facts_of(&input, true, Path::to_path_buf),
            &[],
            false,
        )
        .unwrap();
        assert_eq!(macos.denies, paths(&[config]));
        let elsewhere = [inner(
            "/home/dev/.ssh/config",
            "/srv/ssh/config",
            false,
            false,
        )];
        assert!(plan_linked_places(
            &elsewhere,
            &facts_of(&input, false, Path::to_path_buf),
            &[],
            false
        )
        .is_ok_and(|plan| plan.masks.is_empty()));
    }

    /// M30C-6: on macOS a project kept under a place of the system (a
    /// temporary folder, `/Applications/MAMP/htdocs`) is still the project.
    /// A `deny_read` link to a folder of that same project is denied where
    /// it leads, as before links were planned; it was left readable, and
    /// said to lead outside the home. A link out of the project onto a
    /// place of the system is still left.
    ///
    /// FAILS ON REVERT: drop the project check from `leaves_steered` and
    /// `config/keys` is left readable.
    #[test]
    fn on_macos_a_deny_read_link_inside_a_project_under_a_system_place_is_denied() {
        for project in ["/private/tmp/app", "/Applications/MAMP/htdocs/app"] {
            let mut input = inputs(&["claude", "--print"]);
            input.args.project = PathBuf::from(project);
            let macos = facts_of(&input, true, Path::to_path_buf);
            let keys = format!("{project}/config/keys");
            let (masks, linked) = plan_denied_paths(
                &[steered(&format!("{project}/secrets"), &keys, true, true)],
                &macos,
            );
            assert_eq!(masks, [mask(&keys, true)], "{project}");
            assert!(linked.left.is_empty(), "{project}: {:?}", linked.left);
            let (masks, linked) = plan_denied_paths(
                &[steered(
                    &format!("{project}/.env"),
                    "/private/etc/hosts",
                    true,
                    false,
                )],
                &macos,
            );
            assert!(masks.is_empty(), "{project}: {masks:?}");
            assert_eq!(linked.left.len(), 1, "{project}: {:?}", linked.left);
        }
    }

    /// A link that leads to nothing yet (`~/.ssh` a link to `.config/ssh`,
    /// not made): what the jail's programs make through the folder it shows
    /// would land where the host's `~/.ssh` leads (a key the host's `sshd`
    /// trusts). The place is covered where the jail shows it read-write,
    /// and the real run makes it first ([`LinkedPlan::missing`]); never
    /// through a folder it shows read-only, where bwrap could not make the
    /// mount point and nothing can be made from the jail.
    ///
    /// FAILS ON REVERT: skip a place that is not there in
    /// `plan_linked_places` and nothing covers `~/.config/ssh`; cover it
    /// through the read-only folder too and the second mask is laid where
    /// bwrap cannot make it.
    #[test]
    fn a_place_a_link_leads_to_that_is_not_there_yet_is_covered_where_the_jail_writes() {
        let mut input = inputs(&["claude", "--print"]);
        input.args.extra_ro = vec![PathBuf::from("/data/ro")];
        let (linux, _) = dotdir_plans(
            &[
                place(
                    "/home/dev/.ssh",
                    Some("/home/dev/.config/ssh"),
                    false,
                    false,
                ),
                place("/home/dev/.gnupg", Some("/data/ro/gnupg"), false, false),
            ],
            &input,
            |path| {
                if path == Path::new("/home/dev/.cache") {
                    PathBuf::from("/data/ro")
                } else {
                    path.to_path_buf()
                }
            },
        );
        assert_eq!(
            linux.masks,
            [
                mask("/home/dev/.config/ssh", true),
                mask("/home/dev/.cache/gnupg", true)
            ]
        );
        assert_eq!(
            linux.missing,
            [
                (
                    PathBuf::from("/home/dev/.config/ssh"),
                    vec![PathBuf::from("/home/dev/.config/ssh")]
                ),
                (
                    PathBuf::from("/data/ro/gnupg"),
                    vec![PathBuf::from("/home/dev/.cache/gnupg")]
                ),
            ]
        );
    }

    /// A `deny_read` path is hidden where it leads, as before, and on Linux
    /// at every other place the jail shows it. Every link in the project is
    /// one a program in the jail can change: one that leads onto the
    /// agent's settings or the project itself is left and said, and so is
    /// one that leads where a mount (Linux: out of the person's own places,
    /// `/etc/hostname`) or a deny (macOS: a place of the system) could land
    /// on what the jail runs on. One out of the home that the Linux jail
    /// does not show is not in the jail: nothing is said of it; macOS
    /// denies it there (M30-SEC-5, M30L-DOC-1). One with no link on the way
    /// is masked where it is, as it always was; one that is not there is
    /// not masked. A path the person names outside the project with no
    /// such link (absolute, or with `..`) is hidden where it leads.
    ///
    /// FAILS ON REVERT: drop the needed or the steered check from
    /// `plan_denied_paths` and `/etc/hostname`, `~/.claude` or the project
    /// is masked; leave every steered place on macOS and
    /// `/srv/shared/app.env` is readable there.
    #[test]
    fn a_deny_read_path_is_masked_where_it_leads_and_never_moved_onto_the_system_or_the_hook() {
        let input = inputs(&["claude", "--print"]);
        let home_cache = |path: &Path| {
            if path == Path::new("/home/dev/.cache") {
                PathBuf::from("/home/dev")
            } else {
                path.to_path_buf()
            }
        };
        let found = [
            place(
                "/home/dev/proj/.env",
                Some("/home/dev/proj/.env"),
                true,
                false,
            ),
            steered(
                "/home/dev/proj/secrets",
                "/home/dev/.config/app",
                true,
                true,
            ),
            steered("/home/dev/proj/.env.local", "/etc/hostname", true, false),
            steered("/home/dev/proj/.env.prod", "/home/dev/.claude", true, true),
            steered("/home/dev/proj/.env.self", "/home/dev/proj", true, true),
            steered("/home/dev/proj/.env.gone", "/home/dev/gone", false, false),
            steered(
                "/home/dev/proj/.env.far",
                "/srv/shared/app.env",
                true,
                false,
            ),
            place(
                "/home/dev/proj/../shared/.env",
                Some("/home/dev/shared/.env"),
                true,
                false,
            ),
            place("/etc/hosts", Some("/private/etc/hosts"), true, false),
        ];
        let (masks, linked) = plan_denied_paths(&found, &facts_of(&input, false, home_cache));
        assert_eq!(
            masks,
            [
                mask("/home/dev/proj/.env", false),
                mask("/home/dev/.config/app", true),
                mask("/home/dev/shared/.env", false),
                mask("/private/etc/hosts", false),
            ]
        );
        // `~/.cache` leads to the home: each is shown there too.
        assert_eq!(
            linked.masks,
            [
                mask("/home/dev/.cache/proj/.env", false),
                mask("/home/dev/.cache/.config/app", true),
                mask("/home/dev/.cache/shared/.env", false),
            ]
        );
        assert_eq!(linked.left.len(), 3, "{:?}", linked.left);
        assert!(linked.left[0].contains(
            "to /etc/hostname, through a link a program in the jail can change: the jail does \
             not hide that place"
        ));
        assert!(linked.left[1].contains("leads to /home/dev/.claude, where the jail keeps"));
        assert!(linked.left[2].contains("leads to /home/dev/proj, where the jail keeps"));
        // macOS: the system's file is left, and the secret out of the home
        // is denied where it leads.
        let (masks, linked) = plan_denied_paths(&found, &facts_of(&input, true, home_cache));
        assert_eq!(
            masks,
            [
                mask("/home/dev/proj/.env", false),
                mask("/home/dev/.config/app", true),
                mask("/srv/shared/app.env", false),
                mask("/home/dev/shared/.env", false),
                mask("/private/etc/hosts", false),
            ]
        );
        assert!(linked.masks.is_empty());
        assert_eq!(linked.left.len(), 3, "{:?}", linked.left);
        assert!(linked.left[0].contains("to /etc/hostname, through a link"));
    }

    /// M30L-DOC-2: where InnerWarden's own folder is a link onto what the
    /// jail needs (`~/.config/innerwarden` a link to `~/.claude`), the
    /// launcher says the jail does not hide that place, and the macOS
    /// profile keeps its word: no deny there (one would close the agent's
    /// settings, and with them its hook).
    ///
    /// FAILS ON REVERT: deny where the folder leads whenever that is not
    /// its name (`deny_iw_real` without `iw_config_left`) and the profile
    /// denies `~/.claude`.
    #[test]
    fn innerwardens_folder_that_leads_onto_what_the_jail_needs_is_left_on_macos_too() {
        let mut input = inputs(&["claude", "--print"]);
        let plan = plan_linked_places(
            &[place(
                "/home/dev/.config/innerwarden",
                Some("/home/dev/.claude"),
                true,
                true,
            )],
            &facts_of(&input, true, Path::to_path_buf),
            &[],
            false,
        )
        .unwrap();
        assert!(plan.denies.is_empty() && plan.hidden.is_empty(), "{plan:?}");
        assert_eq!(plan.left.len(), 1);
        input.iw_config_link = true;
        input.iw_config_real = PathBuf::from("/home/dev/.claude");
        input.iw_config_left = true;
        let profile = build_macos_profile(&input).unwrap().profile;
        assert!(
            !profile.contains("(deny file-read* (subpath \"/home/dev/.claude\"))")
                && !profile.contains("(deny file-write* (subpath \"/home/dev/.claude\"))"),
            "{profile}"
        );
        assert!(profile.contains("(deny file-read* (subpath \"/home/dev/.config/innerwarden\"))"));
    }

    /// M30-TL-3: what the launcher says of a place prints its name, which a
    /// program in the jail picks for a link in the project. A line break,
    /// an escape or a character that reorders text is printed as its
    /// escape, so the name cannot erase or forge the line.
    ///
    /// FAILS ON REVERT: print the paths with `display()` and the line holds
    /// a raw carriage return and escape.
    #[test]
    fn what_is_said_of_a_place_never_carries_a_control_character() {
        let input = inputs(&["claude", "--print"]);
        let name =
            "/home/dev/proj/.env.x\r\u{1b}[2Kinnerwarden contain: all hidden\u{1b}[8m\u{202e}";
        let (_, linked) = plan_denied_paths(
            &[
                steered(name, "/etc/hostname", true, false),
                steered(name, "/home/dev/.claude", true, true),
            ],
            &facts_of(&input, false, Path::to_path_buf),
        );
        assert_eq!(linked.left.len(), 2);
        for line in &linked.left {
            assert!(
                !line.chars().any(|c| c.is_control() || c == '\u{202e}'),
                "{line:?}"
            );
            assert!(line.starts_with(
                "/home/dev/proj/.env.x\\u{d}\\u{1b}[2Kinnerwarden contain: all hidden\\u{1b}[8m\\u{202e} leads"
            ));
        }
        assert!(left_loop(Path::new("/a\u{7}b")).starts_with("/a\\u{7}b is a link"));
        assert_eq!(printable(Path::new("/home/dev/ü é")), "/home/dev/ü é");
        // M30C-7: the refusals print the names they hold the same way. A
        // `hide_home` path the agent links out of the home (`/srv/w` its
        // project), one through a link to nothing, one that holds what the
        // jail needs, and a worktree over a sealed tree.
        let planted = "/srv/w/\u{1b}[2K\rok";
        let hidden = |real: Option<&str>, dangling: bool| HiddenHomePath {
            nominal: PathBuf::from("/home/dev/.cache/x\u{1b}[8m"),
            real: real.map(PathBuf::from),
            resolved: PathBuf::from(real.unwrap_or(planted)),
            is_dir: true,
            dangling_link: dangling,
            steered_by: None,
        };
        let mut refusals: Vec<String> = [hidden(Some(planted), false), hidden(None, true)]
            .into_iter()
            .map(|path| {
                plan_hidden_home(&[path], Path::new("/home/dev"), &[])
                    .unwrap_err()
                    .to_string()
            })
            .collect();
        let mut holds = inputs(&["claude", "--print"]);
        holds.args.project = PathBuf::from("/home/dev/.cache/x\u{1b}[8m/p\u{202e}");
        holds.hide_denies = vec![PathBuf::from("/home/dev/.cache/x\u{1b}[8m")];
        refusals.push(validate_jail_inputs(&holds).unwrap_err().to_string());
        let mut sealed = inputs(&["claude", "--print"]);
        sealed.args.identity = true;
        sealed.worktree = Some(Worktree {
            git_dir: PathBuf::from("/run/\u{1b}[2Kok"),
            common_dir: PathBuf::from("/run/\u{1b}[2Kok"),
        });
        refusals.push(validate_jail_inputs(&sealed).unwrap_err().to_string());
        for refusal in &refusals {
            assert!(
                !refusal.chars().any(|c| c.is_control() || c == '\u{202e}'),
                "{refusal:?}"
            );
            assert!(refusal.contains("\\u{1b}"), "{refusal:?}");
        }
        assert!(refusals[0].contains("leads to '/srv/w/\\u{1b}[2K\\u{d}ok'"));
        assert!(
            refusals[2].contains("holds the project"),
            "{:?}",
            refusals[2]
        );
        assert!(refusals[3].contains("for --identity"), "{:?}", refusals[3]);
    }

    /// M30-R1, M30-TL-1: InnerWarden's folder that is itself a link (a
    /// dotfiles manager's `~/.config/innerwarden`). On Linux the link is an
    /// entry in the `~/.config` the jail binds read-write, and no mount can
    /// pin a link: a program in the jail removed it and made a folder of its
    /// own there, on the host, whose `suppress.toml` the host's hook then
    /// read. Such a launch is refused, with what to do. On macOS the sandbox
    /// denies writing the folder as named (the link with it) and denies
    /// where it leads, read and write; where the jail leaves that place, it
    /// is not denied there. A project there is refused, naming the folder.
    ///
    /// FAILS ON REVERT: drop the `iw_config_link` refusal from
    /// `build_linux_jail` and the Linux jail is built.
    #[test]
    fn innerwardens_folder_that_is_a_link_is_refused_on_linux_and_denied_where_it_leads_on_macos() {
        let named = "/home/dev/.config/innerwarden";
        let mut input = inputs(&["claude", "--print"]);
        input.iw_config_link = true;
        input.iw_config_real = PathBuf::from("/home/dev/.cache/iw");
        assert_eq!(
            build_linux_jail(&input).unwrap_err().to_string(),
            "/home/dev/.config/innerwarden is a link (to /home/dev/.cache/iw), and on Linux a \
             program in the jail could replace that link on the host: replace the link with the \
             folder it leads to (remove the link, then move /home/dev/.cache/iw to \
             /home/dev/.config/innerwarden), and start the jail again"
        );
        let mut project_there = input.clone();
        project_there.args.project = PathBuf::from("/home/dev/.cache/iw/x");
        assert_eq!(
            validate_jail_inputs(&project_there)
                .unwrap_err()
                .to_string(),
            "unsafe project path '/home/dev/.cache/iw/x': it overlaps '/home/dev/.cache/iw', \
             where InnerWarden's own folder /home/dev/.config/innerwarden leads (a protected \
             policy directory)"
        );
        let profile = build_macos_profile(&input).unwrap().profile;
        for path in [named, "/home/dev/.cache/iw"] {
            for access in ["read", "write"] {
                let rule = format!("(deny file-{access}* (subpath \"{path}\"))");
                assert!(profile.contains(&rule), "{rule}");
            }
        }
        // Left: no deny where it leads; a project there is still refused.
        input.iw_config_real = PathBuf::from("/srv/iw");
        input.iw_config_left = true;
        let profile = build_macos_profile(&input).unwrap().profile;
        assert!(profile.contains(&format!("(deny file-read* (subpath \"{named}\"))")));
        assert!(!profile.contains("/srv/iw"));
        let mut project_there = input.clone();
        project_there.args.project = PathBuf::from("/srv/iw");
        assert!(validate_jail_inputs(&project_there).is_err());
        // Without a link the jail is the one it was.
        assert!(build_linux_jail(&inputs(&["claude", "--print"])).is_ok());
    }

    /// M30L-DOC-3: the launcher says InnerWarden's folder, the API key with
    /// it, is not visible in the jail only where that holds; where the jail
    /// leaves the place the folder's link leads to (said before), it says
    /// so instead.
    ///
    /// FAILS ON REVERT: print the API-key line whatever the jail left and
    /// the left folder is said to be hidden.
    #[test]
    fn the_launcher_says_the_api_key_is_hidden_only_where_it_is() {
        let mut input = inputs(&["claude"]);
        assert_eq!(
            iw_folder_said(&input),
            "  the agent's ~/.config/innerwarden (incl. the API key) is not visible inside the jail."
        );
        input.iw_config_link = true;
        input.iw_config_left = true;
        let said = iw_folder_said(&input);
        assert!(!said.contains("API key"), "{said}");
        assert!(said.contains("is not hidden (said above)"), "{said}");
    }

    /// In every common layout nothing is added: a dotdir that is an
    /// ordinary folder (or not there), with no folder shown above it, and a
    /// `deny_read` path with no link on the way, give the masks they always
    /// gave, and the jail is byte for byte the one it was. The never-shown
    /// paths are each OS's own list.
    #[test]
    fn ordinary_hidden_places_add_nothing_and_the_jail_is_the_one_it_was() {
        let input = inputs(&["claude", "--print"]);
        for macos in [false, true] {
            let facts = facts_of(&input, macos, Path::to_path_buf);
            let dotdirs: Vec<HiddenPlace> = never_shown_home_paths(&input.home, macos)
                .iter()
                .map(|path| {
                    let there = path.ends_with(".ssh");
                    place(path.to_str().unwrap(), path.to_str(), there, there)
                })
                .collect();
            let plan = plan_linked_places(&dotdirs, &facts, &[], false).unwrap();
            assert_eq!(plan, LinkedPlan::default(), "macos={macos}");
            let found = [
                place(
                    "/home/dev/proj/.env",
                    Some("/home/dev/proj/.env"),
                    true,
                    false,
                ),
                place(
                    "/home/dev/proj/secrets",
                    Some("/home/dev/proj/secrets"),
                    true,
                    true,
                ),
            ];
            let (masks, linked) = plan_denied_paths(&found, &facts);
            assert_eq!(masks, input.deny_paths, "macos={macos}");
            assert_eq!(linked, LinkedPlan::default(), "macos={macos}");
        }
        assert_eq!(
            never_shown_home_paths(Path::new("/h"), false),
            [".ssh", ".gnupg", ".aws", ".mozilla", ".thunderbird"].map(|n| Path::new("/h").join(n))
        );
        assert_eq!(
            never_shown_home_paths(Path::new("/h"), true),
            [
                ".ssh",
                ".aws",
                ".gnupg",
                "Library/Mail",
                "Library/Messages",
                "Library/Safari"
            ]
            .map(|n| Path::new("/h").join(n))
        );
        assert_eq!(
            build_linux_jail(&input).unwrap().bwrap_args.join("\n"),
            GOLDEN_ARGV_PLAIN
        );
        assert_eq!(
            build_linux_jail(&identified_inputs())
                .unwrap()
                .bwrap_args
                .join("\n"),
            GOLDEN_ARGV_IDENTIFIED
        );
    }

    /// What the planner knows of a jail: the guard's own files (its binary,
    /// the agent's command, the agent's settings, the folder of the system
    /// profiles) and what the jail works in (the project, the read-only
    /// paths, the system's folders), each as named and as it leads; the
    /// person's own places (never the worktree's folders, which the
    /// project's `.git` names); the folders the jail writes (macOS adds its
    /// temporary folders); on Linux the system folders it shows.
    #[test]
    fn what_the_planner_knows_of_a_jail_is_named_and_led() {
        let mut input = inputs(&["claude"]);
        input.args.extra_ro = vec![PathBuf::from("/opt/tool")];
        input.worktree = Some(Worktree {
            git_dir: PathBuf::from("/srv/repo/.git/worktrees/w"),
            common_dir: PathBuf::from("/srv/repo/.git"),
        });
        let real = |path: &Path| {
            if path == Path::new("/home/dev/.claude") {
                PathBuf::from("/home/dev/dots/claude")
            } else {
                path.to_path_buf()
            }
        };
        let facts = place_facts(
            &input.args,
            &input.home,
            input.worktree.as_ref(),
            &input.existing_paths,
            &input.iw_binary,
            Some(Path::new("/home/dev/.local/bin/claude")),
            &input.tmpdir,
            false,
            real,
        );
        assert_eq!(
            facts.guard,
            paths(&[
                "/home/dev/.local/bin/innerwarden",
                "/home/dev/.local/bin/claude",
                "/home/dev/.claude",
                "/home/dev/.claude.json",
                "/etc/innerwarden",
                "/home/dev/dots/claude",
            ])
        );
        assert_eq!(&facts.work[..2], paths(&["/home/dev/proj", "/opt/tool"]));
        assert!(facts.work.contains(&PathBuf::from("/usr")));
        assert!(!facts
            .work
            .iter()
            .chain(&facts.guard)
            .any(|p| p.starts_with("/srv/repo")));
        assert_eq!(
            facts.own,
            paths(&[
                "/home/dev",
                "/home/dev/dots/claude",
                "/home/dev/.config",
                "/home/dev/.cache",
                "/home/dev/proj",
            ])
        );
        assert_eq!(
            facts.own_read_only,
            paths(&["/home/dev/.gitconfig", "/opt/tool"])
        );
        assert!(facts.writable.contains(&PathBuf::from("/srv/repo/.git")));
        assert!(!facts.writable.contains(&PathBuf::from("/opt/tool")));
        assert_eq!(facts.project, paths(&["/home/dev/proj"]));
        assert!(facts
            .shown
            .contains(&(PathBuf::from("/etc"), PathBuf::from("/etc"))));
        assert!(facts.read_only.contains(&PathBuf::from("/etc")));
        assert!(!facts.macos);
        let macos = place_facts(
            &input.args,
            &input.home,
            None,
            &input.existing_paths,
            &input.iw_binary,
            None,
            Path::new("/private/var/folders/x/T"),
            true,
            Path::to_path_buf,
        );
        assert!(macos
            .writable
            .contains(&PathBuf::from("/private/var/folders/x/T")));
        assert!(macos.writable.contains(&PathBuf::from("/private/tmp")));
        assert!(!macos
            .shown
            .iter()
            .any(|(jail, _)| jail == Path::new("/etc")));
    }

    /// The link through which a program in the jail can change where a
    /// place leads: the first on the way that sits in a folder the jail
    /// writes; never the place's own entry where the jail hides it as
    /// named, nor a link in a folder it does not write.
    #[test]
    fn a_place_is_steered_by_a_link_in_a_folder_the_jail_writes() {
        let writable = paths(&["/home/dev/.config", "/home/dev/proj"]);
        let links = |list: &[&str]| paths(list);
        let found = |list: &[&str], own: Option<&str>| {
            steering_link(&links(list), own.map(Path::new), &writable).cloned()
        };
        assert_eq!(
            found(&["/home/dev/proj/.env"], None),
            Some(PathBuf::from("/home/dev/proj/.env"))
        );
        assert_eq!(
            found(
                &[
                    "/home/dev/.ssh",
                    "/home/dev/.config/ssh",
                    "/home/dev/proj/k"
                ],
                Some("/home/dev/.ssh")
            ),
            Some(PathBuf::from("/home/dev/.config/ssh"))
        );
        assert_eq!(found(&["/home/dev/.ssh"], Some("/home/dev/.ssh")), None);
        assert_eq!(found(&["/home/dev/.ssh", "/etc"], None), None);
        assert_eq!(
            found(
                &["/home/dev/.config/innerwarden"],
                Some("/home/dev/.config/innerwarden")
            ),
            None
        );
        assert_eq!(found(&[], None), None);
    }

    /// The whole macOS profile of a jail on a common layout, byte for byte.
    /// Its last two lines are new, on purpose, in every macOS profile: they
    /// close the project and `~/.config` to renaming, removal and
    /// replacement, and to nothing else of writing
    /// ([`a_macos_jail_never_moves_a_folder_above_what_it_denies`]).
    const GOLDEN_MACOS_PROFILE: &str = r##"(version 1)
(deny default)

(allow process-exec)
(allow process-fork)
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))
(allow sysctl-read)
(allow mach-lookup)
(allow mach-register)
(allow mach-host*)
(allow ipc-posix-shm*)
(allow ipc-posix-sem)
(allow pseudo-tty)
(allow file-ioctl)
(allow iokit-open)
(allow file-read* file-write* (literal "/dev/ptmx"))
(allow file-read* file-write* (regex #"^/dev/ttys[0-9]+"))
(allow file-read* file-write* (literal "/dev/null"))
(allow file-read* file-write* (literal "/dev/zero"))
(allow file-read* (literal "/dev/random"))
(allow file-read* (literal "/dev/urandom"))

(allow network*)
(allow system-socket)

(allow file-read*)
(deny file-read* (subpath "/home/dev/.ssh"))
(deny file-read* (subpath "/home/dev/.aws"))
(deny file-read* (subpath "/home/dev/.gnupg"))
(deny file-read* (subpath "/home/dev/Library/Mail"))
(deny file-read* (subpath "/home/dev/Library/Messages"))
(deny file-read* (subpath "/home/dev/Library/Safari"))
(deny file-read* (subpath "/home/dev/.config/innerwarden"))
(deny file-read* (subpath "/home/dev/proj/.env"))
(deny file-read* (subpath "/home/dev/proj/secrets"))

(allow file-write* (subpath "/home/dev/proj"))
(allow file-write* (subpath "/home/dev/.claude"))
(allow file-write* (subpath "/home/dev/.cache"))
(allow file-write* (subpath "/home/dev/.local"))
(allow file-write* (subpath "/home/dev/.cargo"))
(allow file-write* (subpath "/home/dev/.npm"))
(allow file-write* (subpath "/home/dev/.rustup"))
(allow file-write* (subpath "/home/dev/.config"))
(allow file-write* (subpath "/tmp"))
(allow file-write* (subpath "/private/tmp"))
(allow file-write* (subpath "/private/var/tmp"))
(allow file-write* (subpath "/private/var/folders"))
(allow file-write* (subpath "/tmp"))
(allow file-write* (subpath "/home/dev/Library/Caches"))
(allow file-write* (literal "/home/dev/.claude.json"))
(allow file-write* (regex #"^/home/dev/\.claude\.json(\.tmp\.[0-9]+\.[0-9a-f]+|\.lock)$"))
(deny file-write* (subpath "/home/dev/.config/innerwarden"))
(deny file-write* (subpath "/home/dev/proj/.env"))
(deny file-write* (subpath "/home/dev/proj/secrets"))
(deny file-write-unlink file-write-create (literal "/home/dev/proj"))
(deny file-write-unlink file-write-create (literal "/home/dev/.config"))
"##;

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
        --bind\n\
        /home/dev/.local/state\n\
        /home/dev/.local/state\n\
        --bind\n\
        /home/dev/.local/state/innerwarden\n\
        /home/dev/.local/state/innerwarden\n\
        --tmpfs\n\
        /home/dev/.config/innerwarden\n\
        --ro-bind\n\
        /home/dev/.gitconfig\n\
        /home/dev/.gitconfig\n\
        --symlink\n\
        /home/dev/.claude/.claude.json\n\
        /home/dev/.claude.json\n\
        --ro-bind\n\
        /home/dev/.local/bin/innerwarden\n\
        /home/dev/.local/bin/innerwarden\n\
        --bind\n\
        /home/dev/proj\n\
        /home/dev/proj\n\
        --chdir\n\
        /home/dev/proj\n\
        --tmpfs\n\
        /home/dev/.claude/sessions\n\
        --tmpfs\n\
        /home/dev/.claude/backups\n\
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
        --cap-drop\n\
        ALL\n\
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
        --seccomp\n\
        13\n\
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
        --seccomp\n\
        13\n\
        --hostname\n\
        ai-sandbox\n\
        --new-session\n\
        --\n\
        /bin/sh\n\
        -c\n\
        true";
}
