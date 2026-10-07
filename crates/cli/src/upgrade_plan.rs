//! Which release asset this build should download, and where to put it.
//!
//! Split out from `upgrade` so the platform mapping and the replace strategy are
//! testable on any host, without network or a real binary swap. The I/O shell in
//! `upgrade` stays thin on purpose: everything that can be decided from pure
//! inputs is decided here.

use std::path::{Path, PathBuf};

/// Base URL of the rolling release the free channel publishes to.
pub const RELEASE_BASE: &str =
    "https://github.com/InnerWarden/innerwarden-releases/releases/download/iw-guard";

/// The release asset name for an (os, arch) pair, matching what the release
/// workflow publishes.
///
/// `None` for a platform the free channel does not publish, so the updater can
/// say so instead of 404ing on a guessed name.
pub fn asset_name(os: &str, arch: &str) -> Option<String> {
    let arch = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => return None,
    };
    Some(match os {
        "linux" => format!("innerwarden-linux-{arch}"),
        "macos" => format!("innerwarden-macos-{arch}"),
        "windows" => format!("innerwarden-windows-{arch}.exe"),
        _ => return None,
    })
}

/// The asset for the host this binary is running on.
pub fn asset_for_this_host() -> Option<String> {
    asset_name(std::env::consts::OS, std::env::consts::ARCH)
}

/// The download URL for an asset under a base, plus its two sidecars.
///
/// The sidecars are not optional: [`super::release_verify::verify_release`]
/// needs both, and a missing one is a failure rather than a skipped check.
///
/// The base is a parameter so a test can point the whole download-and-verify
/// path at a local server. Before that, every test of that path either hit the
/// real internet or asserted the order of substrings in the source, and the
/// latter is what shipped `upgrade --check` performing a real upgrade.
///
/// Production has exactly one caller and it passes [`RELEASE_BASE`].
pub fn urls_from(base: &str, asset: &str) -> (String, String, String) {
    (
        format!("{base}/{asset}"),
        format!("{base}/{asset}.sha256"),
        format!("{base}/{asset}.sig"),
    )
}

/// The asset that names the version the rolling release currently carries.
///
/// It is the Scoop manifest, which the release workflow regenerates from the
/// built binary's own `--version` and uploads alongside the binaries. That makes
/// it the honest answer to "what would I get?": it is derived from the artifact
/// rather than from the tag it was cut from, and the workflow refuses to publish
/// when the two disagree.
pub const VERSION_MANIFEST_ASSET: &str = "innerwarden.json";

/// URL of the version manifest under an arbitrary base. Split for the same
/// reason as [`urls_from`]: so a test can serve one.
pub fn manifest_url_from(base: &str) -> String {
    format!("{base}/{VERSION_MANIFEST_ASSET}")
}

/// The version the published release carries, or `None` if the manifest did not
/// say.
///
/// Fails closed into `None` on anything unexpected. A caller must not turn "did
/// not say" into "an upgrade is available": that is the failure this whole
/// change exists to remove.
pub fn published_version(manifest_json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(manifest_json).ok()?;
    let raw = v.get("version")?.as_str()?.trim();
    if raw.is_empty() {
        return None;
    }
    Some(raw.to_string())
}

/// What `innerwarden upgrade --check` established.
///
/// A value rather than a printed sentence, so the decision is testable without
/// a network and without capturing stdout. The previous implementation had no
/// decision to test: it fetched the `.sha256` sidecar, discarded it, and printed
/// "Run `innerwarden upgrade` to install it" on any HTTP success, which it said
/// on 1.3.7 while 1.3.7 was the published release.
///
/// The third variant is the point. `--check` must never report an upgrade
/// because it could not tell, which is the rule [`crate::status`] exists to
/// enforce: never report "off" when you mean "could not tell".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The published build is the one already installed.
    UpToDate { version: String },
    /// A different build is published, and `upgrade` would install it.
    Available {
        published: String,
        installed: String,
    },
    /// The release answered and did not name a version. Never rendered as an
    /// available upgrade.
    Undetermined,
}

/// Decide what to report from the installed version and the published manifest.
pub fn check_outcome(installed: &str, manifest_json: &str) -> CheckOutcome {
    match published_version(manifest_json) {
        None => CheckOutcome::Undetermined,
        Some(published) if published == installed => CheckOutcome::UpToDate { version: published },
        Some(published) => CheckOutcome::Available {
            published,
            installed: installed.to_string(),
        },
    }
}

/// `upgrade` without `--yes` replaces nothing when the published build is the
/// one already installed. Only that outcome: an unreadable manifest is
/// `Undetermined` and must not stop an upgrade, it just cannot short-circuit it.
pub fn nothing_to_do(outcome: &CheckOutcome) -> bool {
    matches!(outcome, CheckOutcome::UpToDate { .. })
}

/// The lines `--check` prints, given what it established.
///
/// `managed` is taken into account because telling an npm user to run
/// `innerwarden upgrade` is the same lie in a different place: that command now
/// refuses, so pointing them at it would waste the round trip. The same goes
/// for a copy the `.deb` or `.rpm` installed. `arch` names the package file.
pub fn check_lines(
    outcome: &CheckOutcome,
    asset: &str,
    managed: &Managed,
    arch: &str,
) -> Vec<String> {
    match outcome {
        CheckOutcome::UpToDate { version } => vec![
            format!("InnerWarden Community {version}"),
            format!("  Already on the latest build: the published release carries {version} too."),
            "  Nothing to do.".into(),
        ],
        CheckOutcome::Available {
            published,
            installed,
        } => {
            let mut out = vec![
                format!("InnerWarden Community {installed}"),
                format!("  The published release carries {published} ({asset})."),
            ];
            match managed {
                Managed::System(owner) => {
                    out.push(format!(
                        "  This copy came from {}, so upgrade it with the package:",
                        owner.describe()
                    ));
                    out.extend(
                        upgrade_commands(managed, arch)
                            .into_iter()
                            .map(|c| format!("      {c}")),
                    );
                    out.push(format!("  {PACKAGE_NOTE}"));
                }
                Managed::Npm | Managed::Direct => out.push(format!(
                    "  Run `{}` to install {published}.",
                    upgrade_commands(managed, arch).join(" && ")
                )),
            }
            out
        }
        CheckOutcome::Undetermined => vec![
            "InnerWarden Community: could not determine the published version.".into(),
            "  The release answered but did not name a version, so there is nothing".into(),
            "  to compare against. Not reporting an upgrade on a guess.".into(),
            "  Nothing was downloaded. The installed binary is untouched.".into(),
        ],
    }
}

/// Where to stage the download: beside the binary being replaced, never in a
/// world-writable temp directory.
///
/// Staging in `/tmp` would open the window an attacker needs: the verified bytes
/// sit there between verification and the rename, and on a shared machine anyone
/// can swap them in that window. Staging in the destination directory also keeps
/// the final step a same-filesystem rename, which is atomic; a cross-device move
/// is a copy, and a copy can be interrupted half-written.
/// Where a running Windows image is parked while the staged one lands: a
/// running exe cannot be replaced by a rename over it, but it can itself be
/// renamed. Beside the target, so both moves are same-directory renames.
pub fn parked_path(target: &Path) -> PathBuf {
    let file = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "innerwarden".to_string());
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    dir.join(format!("{file}.old"))
}

/// The names an install lays down for one binary, all in one directory: the
/// `iw` and `iw-guard` shortcuts and `innerwarden` itself.
///
/// The shell installer links `iw` and `iw-guard` to `innerwarden` beside it
/// (relative links, or copies where a link cannot be made); the Windows
/// installer copies all three with an `.exe` suffix.
const INSTALLED_NAMES: [&str; 3] = ["iw", "iw-guard", "innerwarden"];

/// The other installed names beside `target`, with `suffix` appended (`.exe`
/// on Windows, nothing elsewhere). The target's own name is excluded, so a
/// binary run as `iw` lists `iw-guard` and `innerwarden`.
pub fn siblings_named(target: &Path, suffix: &str) -> Vec<PathBuf> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let own = target.file_name().map(|n| n.to_string_lossy().to_string());
    INSTALLED_NAMES
        .iter()
        .map(|n| format!("{n}{suffix}"))
        .filter(|n| own.as_deref() != Some(n.as_str()))
        .map(|n| dir.join(n))
        .collect()
}

/// The Windows installer lays `iw.exe` and `iw-guard.exe` beside
/// `innerwarden.exe` as COPIES (Unix gets symlinks). An upgrade that replaced
/// only the target left `iw --version` on the old build. These are the
/// siblings to refresh after the target lands; the target itself is excluded.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn sibling_copies(target: &Path) -> Vec<PathBuf> {
    siblings_named(target, ".exe")
}

/// Is `name` one of the names an install lays down, with `suffix` appended
/// (`.exe` on Windows, nothing elsewhere)?
fn is_installed_name(name: &str, suffix: &str) -> bool {
    INSTALLED_NAMES
        .iter()
        .any(|n| name.strip_suffix(suffix) == Some(*n))
}

/// What is at one of the installed names beside the binary, as the caller
/// found it. Read once, before anything is removed or replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasEntry {
    /// A symbolic link, and the canonical path it leads to (`None` when it
    /// leads to nothing that exists).
    Link { resolves_to: Option<PathBuf> },
    /// A regular file: whether its bytes are this binary's bytes, and whether
    /// it is a build of this program at all (see [`is_innerwarden_build`]),
    /// which an installer copy that an earlier upgrade left on the old build
    /// still is.
    File {
        same_bytes: bool,
        innerwarden_build: bool,
    },
    /// It could not be read, or it is neither a link nor a regular file.
    Unreadable,
}

/// Is this file a build of InnerWarden Community?
///
/// The installer lays `iw` and `iw-guard` as copies where it cannot make a
/// link, and `upgrade` used to replace only the binary, so those copies stayed
/// on whichever build was installed first. Comparing bytes with the running
/// binary cannot recognise them, and running a file to ask its version is not
/// something a removal or an upgrade may do. What every build carries is the
/// release key it verifies upgrades against (`release_verify`), compiled in
/// as text since 1.1.0: an executable that carries it is one of ours, older or
/// newer. `key` is handed in so the decision stays pure.
///
/// The executable header is required too, so a text that quotes the key (the
/// shell installer pins the same key) is not taken for a build. Somebody who
/// writes a file that passes this into the binary's directory could as well
/// have deleted or replaced what is there, so nothing is gained by forging it.
pub fn is_innerwarden_build(bytes: &[u8], key: &[u8]) -> bool {
    const HEADERS: [&[u8]; 6] = [
        b"\x7fELF",          // Linux
        b"\xcf\xfa\xed\xfe", // Mach-O, 64-bit
        b"\xce\xfa\xed\xfe", // Mach-O, 32-bit
        b"\xca\xfe\xba\xbe", // Mach-O, universal
        b"\xbe\xba\xfe\xca", // Mach-O, universal, other byte order
        b"MZ",               // Windows
    ];
    !key.is_empty()
        && HEADERS.iter().any(|h| bytes.starts_with(h))
        && bytes.windows(key.len()).any(|w| w == key)
}

/// One installed name that exists beside the binary. Names that are not there
/// are not listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasFact {
    pub path: PathBuf,
    pub entry: AliasEntry,
}

/// Which of the names beside the binary a full uninstall removes, and which it
/// leaves, with the reason in words.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AliasPlan {
    pub remove: Vec<PathBuf>,
    pub keep: Vec<(PathBuf, &'static str)>,
}

/// Decide which shortcuts go with the binary.
///
/// Uninstall removed the one file it ran from and left `iw` and `iw-guard`
/// behind, two links to a file that no longer existed. A name is removed only
/// when it is provably this program: a link that resolves to `exe` (canonical,
/// resolved by the caller), a regular file with `exe`'s exact bytes (the
/// installer's copy where a link could not be made), or a regular file that is
/// another build of it (that copy, left on an older build by an upgrade that
/// did not refresh it). Anything else carrying the name is somebody else's and
/// is left where it is: a link to another program, a dangling link, a file
/// that is not InnerWarden, or something unreadable. Removing a link never
/// touches what it points to.
pub fn plan_alias_removal(facts: &[AliasFact], exe: &Path) -> AliasPlan {
    let mut plan = AliasPlan::default();
    for fact in facts {
        if fact.path == exe {
            // The binary is the binary's own removal, never an alias of itself.
            continue;
        }
        match &fact.entry {
            AliasEntry::Link {
                resolves_to: Some(to),
            } if to == exe => plan.remove.push(fact.path.clone()),
            AliasEntry::Link {
                resolves_to: Some(_),
            } => plan
                .keep
                .push((fact.path.clone(), "it links to another program")),
            AliasEntry::Link { resolves_to: None } => plan
                .keep
                .push((fact.path.clone(), "it links to nothing that exists")),
            AliasEntry::File {
                same_bytes,
                innerwarden_build,
            } if *same_bytes || *innerwarden_build => plan.remove.push(fact.path.clone()),
            AliasEntry::File { .. } => plan.keep.push((
                fact.path.clone(),
                "it is a different file, another program or an older copy",
            )),
            AliasEntry::Unreadable => plan.keep.push((fact.path.clone(), "it could not be read")),
        }
    }
    plan
}

/// Is one of the names beside the binary provably this very binary: a link
/// that resolves to it, or a copy with its exact bytes?
///
/// That is the shell installer's mark: it lays `iw` and `iw-guard` beside
/// `innerwarden` in whatever directory it was pointed at. Another build of the
/// program does not count here, only this one does.
pub fn a_shortcut_is_this_binary(facts: &[AliasFact], exe: &Path) -> bool {
    facts.iter().any(|fact| {
        fact.path != exe
            && match &fact.entry {
                AliasEntry::Link {
                    resolves_to: Some(to),
                } => to == exe,
                AliasEntry::File { same_bytes, .. } => *same_bytes,
                _ => false,
            }
    })
}

/// The installer's copies beside `target` that an upgrade must replace too.
///
/// Where the shell installer could not make a link it copies the binary to
/// `iw` and `iw-guard`, and an upgrade that replaced only `target` left both
/// running the old build (and `uninstall` then kept them as somebody else's).
/// A copy follows the binary when it is this build's bytes or another build of
/// the program. A link already follows it, and anything else is not ours to
/// overwrite. Decided BEFORE `target` is replaced: afterwards "the same bytes"
/// would mean the new ones.
#[cfg_attr(windows, allow(dead_code))]
pub fn copies_to_refresh(facts: &[AliasFact], target: &Path) -> Vec<PathBuf> {
    facts
        .iter()
        .filter(|fact| fact.path != target)
        .filter(|fact| {
            matches!(
                fact.entry,
                AliasEntry::File {
                    same_bytes: true,
                    ..
                } | AliasEntry::File {
                    innerwarden_build: true,
                    ..
                }
            )
        })
        .map(|fact| fact.path.clone())
        .collect()
}

/// Where a binary that no package manager records came from, as far as its
/// location tells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyOrigin {
    /// Laid down by the InnerWarden installer: under one of its names, and
    /// either in its default directory for this account or with an `iw` /
    /// `iw-guard` beside it that is this binary.
    Installer,
    /// `cargo install`, which records it under `.cargo`.
    Cargo,
    /// Scoop, which keeps it under `scoop\apps\innerwarden`.
    Scoop,
    /// None of these: a copy another program keeps for itself, a build tree,
    /// or a file moved by hand.
    Unrecognised,
}

/// Classify a binary that npm, dpkg and rpm do not record.
///
/// Being able to delete a file is not the same as it being ours to delete, and
/// as root it says nothing at all: root can delete any of them. So `uninstall`
/// removes only what the installer laid down, recognised by the names it uses
/// and either the directory it installs to by default (`in_installer_dir`,
/// compared by the caller with both paths resolved) or the shortcut it lays
/// beside the binary wherever it was pointed (`a_shortcut_is_this_binary`). A
/// copy another product pins for itself (`/usr/local/lib/<product>/guard-cli`,
/// a lone `innerwarden` in its own directory) has neither, and is left to it.
pub fn copy_origin(
    exe: &Path,
    suffix: &str,
    in_installer_dir: bool,
    a_shortcut_is_this_binary: bool,
) -> CopyOrigin {
    let installed_name = exe
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| is_installed_name(n, suffix));
    if installed_name && (in_installer_dir || a_shortcut_is_this_binary) {
        return CopyOrigin::Installer;
    }
    let names: Vec<String> = exe
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect();
    let n = names.len();
    if n >= 3 && names[n - 2] == "bin" && names[n - 3] == ".cargo" {
        return CopyOrigin::Cargo;
    }
    let scoop_app = names
        .iter()
        .position(|c| c == "scoop")
        .is_some_and(|i| names[i..].windows(2).any(|w| w == ["apps", "innerwarden"]));
    if scoop_app {
        return CopyOrigin::Scoop;
    }
    CopyOrigin::Unrecognised
}

/// What decides whether this account can delete the binary, read from
/// metadata alone (see `unlink_permitted`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
pub struct UnlinkFacts {
    /// `access(dir, W_OK | X_OK)` succeeded: the kernel's own answer, which
    /// already says no on a read-only mount or an immutable directory.
    pub dir_writable: bool,
    /// `access(file, W_OK)` failed with `EPERM`, which is how the kernel
    /// refuses a write to an immutable file whoever asks.
    pub file_immutable: bool,
    /// The directory carries the sticky bit (`/tmp`).
    pub sticky_dir: bool,
    pub euid: u32,
    pub dir_uid: u32,
    pub file_uid: u32,
}

/// Could this account unlink the binary? Pure.
///
/// Answered without writing anything, so `uninstall --dry-run` can ask it: the
/// preview used to find out by creating and deleting a file beside the binary.
/// It is also the question an unlink actually asks, which creating a file is
/// not: on a full disk a create fails while an unlink works, and in a sticky
/// directory a create works while unlinking another account's file does not.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn unlink_permitted(f: &UnlinkFacts) -> bool {
    if !f.dir_writable || f.file_immutable {
        return false;
    }
    !f.sticky_dir || f.euid == 0 || f.euid == f.file_uid || f.euid == f.dir_uid
}

/// Which system package database records the installed file, as read by the
/// caller from `dpkg-query -S` or `rpm -qf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageOwner {
    /// The `.deb`: dpkg records the file under this package.
    Dpkg { package: String },
    /// The `.rpm`: rpm records the file under this package.
    Rpm { package: String },
}

impl PackageOwner {
    fn package(&self) -> &str {
        match self {
            PackageOwner::Dpkg { package } | PackageOwner::Rpm { package } => package,
        }
    }

    /// The front end the install page uses for this package type.
    fn tool(&self) -> &'static str {
        match self {
            PackageOwner::Dpkg { .. } => "apt",
            PackageOwner::Rpm { .. } => "dnf",
        }
    }

    /// "the .deb package `innerwarden`".
    fn describe(&self) -> String {
        let kind = match self {
            PackageOwner::Dpkg { .. } => ".deb",
            PackageOwner::Rpm { .. } => ".rpm",
        };
        format!("the {kind} package `{}`", self.package())
    }

    fn remove_command(&self) -> String {
        format!("sudo {} remove {}", self.tool(), self.package())
    }
}

/// The package owner named by `dpkg-query -S <target>`, if one owns exactly
/// `target`.
///
/// Lines read `pkg: /path`, `pkg:arch: /path` for a multi-arch package, or
/// `a, b: /path` when several share it; a `diversion by` line is not ownership.
/// Only a line naming `target` itself counts.
pub fn dpkg_owner(stdout: &str, target: &Path) -> Option<String> {
    let want = target.to_str()?;
    stdout.lines().find_map(|line| {
        if line.starts_with("diversion by") {
            return None;
        }
        let (packages, path) = line.split_once(": ")?;
        if path.trim_end() != want {
            return None;
        }
        let first = packages.split(',').next()?.trim();
        let name = first.split(':').next()?.trim();
        package_name(name)
    })
}

/// The package named by `rpm -qf --queryformat '%{NAME}\n' <target>`.
pub fn rpm_owner(stdout: &str) -> Option<String> {
    package_name(stdout.lines().map(str::trim).find(|l| !l.is_empty())?)
}

/// A package name is one token. Anything with a space in it is a message
/// ("file ... is not owned by any package"), not a name.
fn package_name(name: &str) -> Option<String> {
    (!name.is_empty() && !name.contains(char::is_whitespace)).then(|| name.to_string())
}

/// The architecture as the `.deb` file names it on the release.
fn deb_arch(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("amd64"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

/// The architecture as the `.rpm` file names it on the release.
fn rpm_arch(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("x86_64"),
        "aarch64" => Some("aarch64"),
        _ => None,
    }
}

/// The commands that upgrade this copy the way it was installed.
///
/// There is no apt or dnf repository: the `.deb` and `.rpm` are files on the
/// release, installed by path, so `apt upgrade innerwarden` would answer that
/// nothing is newer. The fixed-name packages on the rolling release always
/// carry the current build, which is what the install page links.
///
/// A package is installed as root, maintainer scripts included, so it is
/// fetched into a directory only this account can write (`mktemp -d`, never
/// the current directory, which may be `/tmp`), checked against the checksum
/// the release publishes beside it, and installed only if the check passes:
/// the steps are ONE command chained with `&&`, so a failed check stops it.
/// Never `dnf install <URL>`: dnf checks no signature on a URL or a local
/// file by default. The packages are not signed, so the checksum proves the
/// download arrived whole, not who published it; [`PACKAGE_NOTE`] says so.
pub fn upgrade_commands(managed: &Managed, arch: &str) -> Vec<String> {
    match managed {
        Managed::Npm => vec!["npm install -g innerwarden@latest".into()],
        Managed::Direct => vec!["innerwarden upgrade".into()],
        Managed::System(PackageOwner::Dpkg { .. }) => match deb_arch(arch) {
            Some(a) => fetched_and_checked(&format!("innerwarden_{a}.deb"), "sudo apt install"),
            None => vec![format!(
                "sudo apt install <the newer .deb for {arch} from {RELEASE_BASE}, checked against its .sha256>"
            )],
        },
        Managed::System(PackageOwner::Rpm { .. }) => match rpm_arch(arch) {
            Some(a) => fetched_and_checked(&format!("innerwarden.{a}.rpm"), "sudo dnf install"),
            None => vec![format!(
                "sudo dnf install <the newer .rpm for {arch} from {RELEASE_BASE}, checked against its .sha256>"
            )],
        },
    }
}

/// What the checksum in [`upgrade_commands`] does and does not prove.
pub const PACKAGE_NOTE: &str = "The checksum proves the download arrived whole, not who \
     published it: the packages are not signed, unlike the release binaries.";

/// One shell command, as lines continued with `\`: fetch `file` and its
/// `.sha256` into a fresh private directory, check it, and install it with
/// `install` only if the check passed.
fn fetched_and_checked(file: &str, install: &str) -> Vec<String> {
    vec![
        "dir=\"$(mktemp -d)\" \\".into(),
        format!("  && curl -fsSL -o \"$dir/{file}\" {RELEASE_BASE}/{file} \\"),
        format!("  && curl -fsSL -o \"$dir/{file}.sha256\" {RELEASE_BASE}/{file}.sha256 \\"),
        format!("  && (cd \"$dir\" && sha256sum -c {file}.sha256) \\"),
        format!("  && {install} \"$dir/{file}\""),
    ]
}

pub fn staging_path(target: &Path) -> PathBuf {
    let file = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "innerwarden".to_string());
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    dir.join(format!(".{file}.upgrade"))
}

/// Who owns the installed binary, which decides what "upgrade" even means.
///
/// `upgrade` replaces the file it is running from. That is right for the
/// installer's own copy and wrong for a copy another package manager put
/// there: overwriting npm's file leaves npm believing it still ships the old
/// version, and the next `npm install -g` silently reverts the upgrade. The
/// `.deb` and `.rpm` are the same hazard one level down: dpkg or rpm goes on
/// recording the old version over a file that is no longer it, and the next
/// install of that package puts the old binary back.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Managed {
    /// Installed by `npm install -g innerwarden`.
    Npm,
    /// Installed from the `.deb` or `.rpm`: the system package database
    /// records this file.
    System(PackageOwner),
    /// Installed by the shell installer, or built locally.
    Direct,
}

impl Managed {
    /// Who to name in a refusal: "npm", or "apt (the .deb package `x`)".
    fn manager(&self) -> String {
        match self {
            Managed::Npm => "npm".into(),
            Managed::System(owner) => format!("{} ({})", owner.tool(), owner.describe()),
            Managed::Direct => "nothing but this binary".into(),
        }
    }
}

/// Classify an install from the path the binary runs from and from what the
/// system package database said about that path.
///
/// `owner` is the package database's own answer, gathered by the caller
/// (`dpkg-query -S`, `rpm -qf`), so the decision stays pure. It is consulted
/// FIRST: a file a package records belongs to that package wherever it sits,
/// and `/usr/bin/innerwarden`, where the `.deb` and `.rpm` put it, says nothing
/// by itself (`sudo IW_GUARD_DIR=/usr/bin` puts the installer's copy there too).
///
/// Otherwise npm's global layout puts the real binary under `node_modules`,
/// the one marker that is stable across npm versions, prefixes, and platforms.
pub fn managed_by(target: &Path, owner: Option<&PackageOwner>) -> Managed {
    if let Some(owner) = owner {
        return Managed::System(owner.clone());
    }
    if target.components().any(|c| c.as_os_str() == "node_modules") {
        Managed::Npm
    } else {
        Managed::Direct
    }
}

/// Must this invocation stop before anything is downloaded?
///
/// Pure, and consulted by `upgrade` BEFORE the first byte is fetched. Until now
/// `managed_by` had two callers and both were on the failure path, so the npm
/// hazard was only ever announced to people whose upgrade had already failed for
/// an unrelated reason. The case it was written for, a user-owned npm prefix,
/// upgrades successfully and is reverted by the next `npm install -g`. A copy
/// the `.deb` or `.rpm` installed refuses for the same reason.
///
/// `check_only` never refuses: reporting a version changes nothing, and the
/// report names the package manager's own command instead. `forced` is the user
/// saying they know.
pub fn managed_refusal_applies(managed: &Managed, check_only: bool, forced: bool) -> bool {
    !check_only && !forced && *managed != Managed::Direct
}

/// Everything `upgrade` prints when it refuses a managed copy: why, the way
/// it was installed, and the override for someone who knows what it costs.
pub fn managed_refusal_lines(
    target: &Path,
    managed: &Managed,
    is_root: bool,
    os: &str,
    arch: &str,
) -> Vec<String> {
    let mut out = vec![
        format!(
            "innerwarden upgrade: REFUSED, this copy is managed by {}.",
            managed.manager()
        ),
        "  Nothing was downloaded. The installed binary is untouched.".into(),
        String::new(),
    ];
    out.extend(cannot_replace_advice_on(target, managed, is_root, os, arch));
    out.push(String::new());
    match managed {
        Managed::System(owner) => {
            out.push(format!(
                "  To replace the package's file anyway, knowing {} goes on recording",
                owner.tool()
            ));
            out.push("  the old version:  sudo innerwarden upgrade --yes".into());
        }
        Managed::Npm | Managed::Direct => {
            out.push("  To replace npm's file anyway, knowing the next `npm install -g`".into());
            out.push("  will undo it:  innerwarden upgrade --yes".into());
        }
    }
    out
}

/// What to tell someone whose binary could not be replaced.
///
/// A beginner reading "Permission denied" has no way to know whether the fix is
/// `sudo`, their package manager, or a reinstall. Worse, on an npm install the
/// obvious guess is the wrong one: `sudo innerwarden upgrade` would succeed and
/// then be undone by the next `npm install -g`. Name the actual next command.
///
/// `is_root` is passed in rather than read here so the decision stays pure and
/// the root case is testable on any host.
pub fn cannot_replace_advice(target: &Path, managed: &Managed, is_root: bool) -> Vec<String> {
    cannot_replace_advice_on(
        target,
        managed,
        is_root,
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
}

/// The advice by platform. `sudo` is a Unix word: on Windows the usual reason
/// is another InnerWarden process holding the file, or a folder that needs
/// an elevated PowerShell. Read on a stock Windows Server 2022 on 2026-09-08,
/// where a failed replace told the operator to run `sudo innerwarden upgrade`.
pub fn cannot_replace_advice_on(
    target: &Path,
    managed: &Managed,
    is_root: bool,
    os: &str,
    arch: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    if os == "windows" && *managed == Managed::Direct {
        out.push(format!("{} could not be replaced.", target.display()));
        out.push(
            "Close every other InnerWarden process (a dashboard, an agent's hook still \
             running) and re-run `innerwarden upgrade`."
                .into(),
        );
        out.push(
            "If the folder itself is not writable, run PowerShell as Administrator and \
             re-run it there."
                .into(),
        );
        return out;
    }
    match managed {
        Managed::Npm => {
            out.push(format!(
                "This copy is managed by npm ({}).",
                target.display()
            ));
            out.push("Upgrade it the way it was installed:".into());
            out.push("    npm install -g innerwarden@latest".into());
            out.push(String::new());
            out.push(
                "Do not use sudo for this. Replacing npm's file by hand leaves npm \
                 believing it still ships the old version, and the next \
                 `npm install -g` puts the old one back."
                    .into(),
            );
        }
        Managed::System(owner) => {
            out.push(format!(
                "This copy came from {} ({}).",
                owner.describe(),
                target.display()
            ));
            out.push("Upgrade it the way it was installed:".into());
            for command in upgrade_commands(managed, arch) {
                out.push(format!("    {command}"));
            }
            out.push(PACKAGE_NOTE.into());
            out.push(String::new());
            out.push(format!(
                "Replacing the file by hand leaves {} recording the old version over \
                 a file that is no longer it, and the next install of that package \
                 puts the old binary back.",
                owner.tool()
            ));
        }
        Managed::Direct if !is_root => {
            out.push(format!(
                "{} is not writable by this user.",
                target.display()
            ));
            out.push("Re-run with elevated privileges:".into());
            out.push("    sudo innerwarden upgrade".into());
        }
        Managed::Direct => {
            out.push(format!(
                "{} could not be replaced even as root.",
                target.display()
            ));
            out.push(
                "The filesystem is most likely read-only, or the file is immutable \
                 (`lsattr`). Reinstall instead:"
                    .into(),
            );
            out.push("    curl -fsSL https://innerwarden.com/free | sh".into());
        }
    }
    out
}

/// What `uninstall` should do about the binary it is running from.
///
/// Separate from the doing so the decision can be made BEFORE anything is
/// destroyed. The old order removed the config, the key and the hooks first and
/// only then discovered it could not remove the binary, which is the worst of
/// both: the recoverable state is gone and the thing you wanted gone is still
/// there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryRemoval {
    /// This copy belongs to npm. Do not unlink it: npm also owns the `innerwarden`
    /// and `iw` launchers, and removing the file by hand leaves both behind
    /// pointing at nothing while npm still believes it ships the version. The
    /// same reasoning `cannot_replace_advice` already applies to `upgrade`.
    LeaveToNpm,
    /// The `.deb` or `.rpm` installed this file. Its package manager removes
    /// it, and its record of it with it; unlinking it here, which root can do,
    /// leaves dpkg or rpm recording a package whose file is gone.
    LeaveToPackage(PackageOwner),
    /// `cargo install` put it there, and `cargo uninstall` removes it along
    /// with cargo's record of it.
    LeaveToCargo,
    /// Scoop put it there, and `scoop uninstall` removes it with the `iw` and
    /// `iw-guard` shims Scoop made for it.
    LeaveToScoop,
    /// Not a copy the installer laid down (see [`copy_origin`]), so it may be
    /// another program's. Left where it is, whoever could delete it.
    LeaveUnrecognised,
    /// The installer's copy, and we can delete it, so remove it here.
    RemoveHere,
    /// The installer's copy, and this account cannot delete it. Say so before
    /// touching anything else.
    CannotRemove,
}

/// Decide what to do about the binary, from facts gathered by the caller.
///
/// Pure on purpose: `origin` and `writable` are gathered by the caller, so the
/// decision is testable on any host. `writable` is read from metadata
/// ([`unlink_permitted`]) and never by writing beside the binary, because the
/// same decision answers `uninstall --dry-run`, which must change nothing.
pub fn plan_binary_removal(
    managed: &Managed,
    origin: &CopyOrigin,
    writable: bool,
) -> BinaryRemoval {
    match managed {
        // Checked FIRST and independently of `writable`. A user-owned npm prefix
        // IS writable, so a writability-first branch would delete npm's file
        // exactly in the case the product already documents as the wrong move.
        Managed::Npm => BinaryRemoval::LeaveToNpm,
        // The same for a package: `sudo innerwarden uninstall` can write
        // `/usr/bin`, and that is exactly when it must not unlink dpkg's file.
        Managed::System(owner) => BinaryRemoval::LeaveToPackage(owner.clone()),
        // And for every other copy that is not the installer's: run as root,
        // `writable` is true of any of them, so it cannot be what decides.
        Managed::Direct => match origin {
            CopyOrigin::Cargo => BinaryRemoval::LeaveToCargo,
            CopyOrigin::Scoop => BinaryRemoval::LeaveToScoop,
            CopyOrigin::Unrecognised => BinaryRemoval::LeaveUnrecognised,
            CopyOrigin::Installer if writable => BinaryRemoval::RemoveHere,
            CopyOrigin::Installer => BinaryRemoval::CannotRemove,
        },
    }
}

/// What to print about the binary, and whether anything is being left behind.
///
/// The bool is the half that was missing: the old code printed a line either way
/// and returned `ExitCode::SUCCESS` unconditionally, so "InnerWarden Community
/// removed" was said over a machine that still had InnerWarden on it.
pub fn binary_removal_lines(plan: &BinaryRemoval, target: &Path) -> (Vec<String>, bool) {
    match plan {
        BinaryRemoval::LeaveToNpm => (
            vec![
                "  binary  : managed by npm, so npm removes it:".into(),
                "                npm uninstall -g innerwarden".into(),
                "            That also removes the `innerwarden` and `iw` launchers and".into(),
                "            npm's record of them. Deleting the file by hand leaves all three."
                    .into(),
            ],
            true,
        ),
        BinaryRemoval::LeaveToPackage(owner) => (
            vec![
                format!(
                    "  binary  : installed by {}, so {} removes it:",
                    owner.describe(),
                    owner.tool()
                ),
                format!("                {}", owner.remove_command()),
                format!(
                    "            Deleting the file by hand leaves {} recording a package",
                    owner.tool()
                ),
                "            whose file is gone.".into(),
            ],
            true,
        ),
        BinaryRemoval::LeaveToCargo => (
            vec![
                "  binary  : installed by cargo, so cargo removes it:".into(),
                "                cargo uninstall innerwarden".into(),
                "            Deleting the file by hand leaves cargo recording an install".into(),
                "            whose file is gone.".into(),
            ],
            true,
        ),
        BinaryRemoval::LeaveToScoop => (
            vec![
                "  binary  : installed by Scoop, so Scoop removes it:".into(),
                "                scoop uninstall innerwarden".into(),
                "            That also removes the `iw` and `iw-guard` shims Scoop made".into(),
                "            for it, which deleting the file by hand leaves behind.".into(),
            ],
            true,
        ),
        BinaryRemoval::LeaveUnrecognised => (
            vec![
                format!("  binary  : kept {}", target.display()),
                "            It is not a copy the InnerWarden installer laid down: it is not"
                    .into(),
                "            in the installer's directory, and no `iw` or `iw-guard` beside".into(),
                "            it is this binary. Another program may run this copy, so it is".into(),
                "            left for whoever put it there.".into(),
            ],
            true,
        ),
        BinaryRemoval::CannotRemove => (
            vec![
                format!("  binary  : cannot remove {}", target.display()),
                "            This account cannot delete it (no write access to its".into(),
                "            directory, or the file is immutable). Re-run with the".into(),
                "            privileges that installed it, or remove it by hand.".into(),
            ],
            true,
        ),
        BinaryRemoval::RemoveHere => (Vec::new(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The case that cost a real user a broken install: an npm copy is left to
    /// npm even when the process could unlink it, because being able to is not
    /// the same as it being right.
    ///
    /// FAILS ON REVERT: order the match on `writable` first and this returns
    /// `RemoveHere` for a user-owned npm prefix.
    #[test]
    fn an_npm_copy_is_left_to_npm_even_when_writable() {
        assert_eq!(
            plan_binary_removal(&Managed::Npm, &CopyOrigin::Installer, true),
            BinaryRemoval::LeaveToNpm
        );
        assert_eq!(
            plan_binary_removal(&Managed::Npm, &CopyOrigin::Installer, false),
            BinaryRemoval::LeaveToNpm
        );
    }

    /// The other side, so this is not a guard that refuses everything: a direct
    /// install we own is still removed here, and still exits clean.
    #[test]
    fn a_writable_direct_install_is_removed_here_and_leaves_nothing() {
        let plan = plan_binary_removal(&Managed::Direct, &CopyOrigin::Installer, true);
        assert_eq!(plan, BinaryRemoval::RemoveHere);
        let (lines, left_behind) =
            binary_removal_lines(&plan, Path::new("/usr/local/bin/innerwarden"));
        assert!(lines.is_empty(), "nothing to announce when nothing is left");
        assert!(!left_behind);
    }

    #[test]
    fn an_unwritable_direct_install_cannot_be_removed() {
        assert_eq!(
            plan_binary_removal(&Managed::Direct, &CopyOrigin::Installer, false),
            BinaryRemoval::CannotRemove
        );
    }

    /// Every branch that leaves the binary where it is.
    const LEAVING: [BinaryRemoval; 5] = [
        BinaryRemoval::LeaveToNpm,
        BinaryRemoval::LeaveToCargo,
        BinaryRemoval::LeaveToScoop,
        BinaryRemoval::LeaveUnrecognised,
        BinaryRemoval::CannotRemove,
    ];

    /// REGRESSION ANCHOR. `sudo innerwarden uninstall` run from a copy the
    /// installer did not lay down (one another product pins for itself) deleted
    /// it, because the only facts consulted were npm, dpkg/rpm and whether the
    /// file could be deleted, and as root every file can be.
    ///
    /// FAILS ON REVERT: decide a direct copy by `writable` alone and this is
    /// `RemoveHere`.
    #[test]
    fn a_copy_the_installer_did_not_lay_down_is_kept_even_when_deletable() {
        for (origin, expected) in [
            (CopyOrigin::Unrecognised, BinaryRemoval::LeaveUnrecognised),
            (CopyOrigin::Cargo, BinaryRemoval::LeaveToCargo),
            (CopyOrigin::Scoop, BinaryRemoval::LeaveToScoop),
        ] {
            assert_eq!(
                plan_binary_removal(&Managed::Direct, &origin, true),
                expected,
                "{origin:?}"
            );
            assert_eq!(
                plan_binary_removal(&Managed::Direct, &origin, false),
                expected,
                "{origin:?} is not ours whether or not it could be deleted"
            );
        }
    }

    /// Where a copy came from, from its path and the two facts the caller
    /// gathers. The installer is recognised by its names AND by its directory
    /// or its shortcut; a copy that only has the name, or only the place, is
    /// somebody else's. (Windows paths are written with `/`, which Windows
    /// reads as a separator too, so this runs on every host.)
    ///
    /// FAILS ON REVERT: drop the name check and `guard-cli` in the installer's
    /// directory is `Installer`; drop the directory and shortcut check and the
    /// lone `innerwarden` another product keeps is `Installer`.
    #[test]
    fn only_the_installers_names_in_its_place_are_the_installers() {
        let home_bin = Path::new("/h/.local/bin/innerwarden");
        assert_eq!(
            copy_origin(home_bin, "", true, false),
            CopyOrigin::Installer
        );
        assert_eq!(
            copy_origin(Path::new("/usr/local/bin/innerwarden"), "", false, true),
            CopyOrigin::Installer,
            "IW_GUARD_DIR anywhere, recognised by the shortcut beside it"
        );
        assert_eq!(
            copy_origin(Path::new("/usr/local/bin/iw"), "", false, true),
            CopyOrigin::Installer,
            "run as a copied shortcut"
        );
        // Another product's pinned copy: its own name, or ours alone.
        for (exe, in_dir, shortcut) in [
            ("/usr/local/lib/product/guard-cli", false, false),
            ("/h/.local/bin/guard-cli", true, false),
            ("/h/.local/bin/guard-cli", false, true),
            ("/opt/product/bin/innerwarden", false, false),
            ("/home/dev/src/target/release/innerwarden", false, false),
        ] {
            assert_eq!(
                copy_origin(Path::new(exe), "", in_dir, shortcut),
                CopyOrigin::Unrecognised,
                "{exe} in_dir={in_dir} shortcut={shortcut}"
            );
        }
        assert_eq!(
            copy_origin(Path::new("/h/.cargo/bin/innerwarden"), "", false, false),
            CopyOrigin::Cargo
        );
        assert_eq!(
            copy_origin(
                Path::new("C:/Users/a/scoop/apps/innerwarden/current/innerwarden.exe"),
                ".exe",
                false,
                false
            ),
            CopyOrigin::Scoop
        );
        assert_eq!(
            copy_origin(
                Path::new("C:/Users/a/AppData/Local/Programs/InnerWarden/innerwarden.exe"),
                ".exe",
                true,
                false
            ),
            CopyOrigin::Installer
        );
        assert_eq!(
            copy_origin(
                Path::new("C:/Program Files/InnerWarden/iw-guard.exe"),
                ".exe",
                false,
                false
            ),
            CopyOrigin::Unrecognised,
            "a copy pinned beside another product's binaries"
        );
    }

    /// cargo and Scoop keep a record of what they installed; their branch
    /// names their own command, and the unrecognised branch says why the file
    /// stays and names it.
    #[test]
    fn each_leaving_branch_names_who_removes_it() {
        let exe = Path::new("/opt/product/bin/innerwarden");
        for (plan, want) in [
            (BinaryRemoval::LeaveToCargo, "cargo uninstall innerwarden"),
            (BinaryRemoval::LeaveToScoop, "scoop uninstall innerwarden"),
            (
                BinaryRemoval::LeaveUnrecognised,
                "It is not a copy the InnerWarden installer laid down",
            ),
        ] {
            let (lines, left) = binary_removal_lines(&plan, exe);
            let text = lines.join("\n");
            assert!(text.contains(want), "{plan:?}:\n{text}");
            assert!(left, "{plan:?}");
        }
        let (lines, _) = binary_removal_lines(&BinaryRemoval::LeaveUnrecognised, exe);
        assert_eq!(lines[0], "  binary  : kept /opt/product/bin/innerwarden");
    }

    fn unlink_facts() -> UnlinkFacts {
        UnlinkFacts {
            dir_writable: true,
            file_immutable: false,
            sticky_dir: false,
            euid: 1000,
            dir_uid: 1000,
            file_uid: 1000,
        }
    }

    /// Whether the binary can be deleted, decided from metadata. The kernel's
    /// answer about the directory comes first; an immutable file cannot be
    /// deleted even by root; in a sticky directory only the file's owner, the
    /// directory's owner or root may delete it.
    #[test]
    fn deletion_is_decided_from_metadata() {
        let ok = unlink_facts();
        assert!(unlink_permitted(&ok));
        assert!(!unlink_permitted(&UnlinkFacts {
            dir_writable: false,
            ..ok
        }));
        assert!(!unlink_permitted(&UnlinkFacts {
            file_immutable: true,
            euid: 0,
            ..ok
        }));
        let sticky_other = UnlinkFacts {
            sticky_dir: true,
            dir_uid: 0,
            file_uid: 1001,
            ..ok
        };
        assert!(!unlink_permitted(&sticky_other));
        assert!(unlink_permitted(&UnlinkFacts {
            euid: 0,
            ..sticky_other
        }));
        assert!(unlink_permitted(&UnlinkFacts {
            file_uid: 1000,
            ..sticky_other
        }));
    }

    /// The remedy the old code printed needed the very root the uninstall did not
    /// have, and this repo already documents that hand-deleting npm's file is
    /// wrong (`cannot_replace_advice`). Neither branch may hand out `rm`.
    ///
    /// FAILS ON REVERT: the old line was
    /// "binary  : remove it with `rm {path}` ({e})".
    #[test]
    fn neither_branch_tells_the_user_to_rm_the_binary() {
        for plan in LEAVING {
            let (lines, _) = binary_removal_lines(&plan, Path::new("/x/bin/innerwarden"));
            let text = lines.join("\n");
            assert!(
                !text.contains("rm "),
                "{plan:?} must not hand out a bare rm:\n{text}"
            );
        }
    }

    /// npm's branch must name npm's own command, because that is the one that
    /// removes the launchers too.
    #[test]
    fn the_npm_branch_names_npms_own_uninstall() {
        let (lines, left) = binary_removal_lines(&BinaryRemoval::LeaveToNpm, Path::new("/x"));
        let text = lines.join("\n");
        assert!(text.contains("npm uninstall -g innerwarden"), "{text}");
        assert!(
            text.contains("launchers"),
            "the reason must travel with it:\n{text}"
        );
        assert!(left, "npm's copy is still on the machine when we finish");
    }

    /// Anything left behind must be reported as left behind, whatever the reason.
    #[test]
    fn every_branch_that_leaves_something_says_so() {
        for plan in LEAVING {
            let (lines, left) = binary_removal_lines(&plan, Path::new("/x/innerwarden"));
            assert!(left, "{plan:?} leaves the binary and must report it");
            assert!(!lines.is_empty(), "{plan:?} must explain what is left");
        }
    }

    /// npm's global install is the case where the obvious fix is the wrong one.
    #[test]
    fn an_npm_install_is_recognised_from_its_path() {
        let p = Path::new(
            "/usr/local/lib/node_modules/innerwarden/node_modules/@innerwarden/cli-linux-x64/bin/innerwarden",
        );
        assert_eq!(managed_by(p, None), Managed::Npm);
        let advice = cannot_replace_advice(p, &managed_by(p, None), false).join("\n");
        assert!(
            advice.contains("npm install -g innerwarden@latest"),
            "an npm install must be pointed at npm, got:\n{advice}"
        );
        assert!(
            advice.contains("Do not use sudo"),
            "sudo works here and is exactly what makes the upgrade revert later:\n{advice}"
        );
    }

    /// Being root does not make overwriting npm's file the right move.
    #[test]
    fn root_does_not_change_the_advice_for_an_npm_install() {
        let p = Path::new("/usr/lib/node_modules/innerwarden/bin/innerwarden");
        let advice = cannot_replace_advice(p, &managed_by(p, None), true).join("\n");
        assert!(
            advice.contains("npm install -g innerwarden@latest"),
            "{advice}"
        );
        assert!(
            !advice.contains("sudo innerwarden upgrade"),
            "escalating would overwrite npm's file, which is the bug:\n{advice}"
        );
    }

    /// The ordinary case: installer copy, unprivileged user.
    #[test]
    fn a_direct_install_that_is_not_writable_asks_for_sudo() {
        let p = Path::new("/usr/local/bin/innerwarden");
        let advice = cannot_replace_advice(p, &managed_by(p, None), false).join("\n");
        assert!(advice.contains("sudo innerwarden upgrade"), "{advice}");
        assert!(!advice.contains("npm install"), "{advice}");
    }

    /// Already root and still refused: sudo is not the answer, so do not say it.
    #[test]
    fn a_direct_install_failing_as_root_does_not_suggest_sudo() {
        let p = Path::new("/usr/local/bin/innerwarden");
        let advice = cannot_replace_advice(p, &managed_by(p, None), true).join("\n");
        assert!(
            !advice.contains("sudo innerwarden upgrade"),
            "telling root to use sudo sends them round the same loop:\n{advice}"
        );
        assert!(advice.contains("read-only"), "{advice}");
    }

    /// REGRESSION ANCHOR. The npm hazard was detected and documented, and the
    /// only two callers of `managed_by` were on the FAILURE path.
    ///
    /// So the warning appeared only when the replace had also failed, which
    /// needs a root-owned npm prefix. The install page recommends
    /// `npm config set prefix ~/.npm-global`, which is user-owned, so the
    /// replace succeeds: "Upgrade complete", and the next `npm install -g`
    /// silently puts the old binary back. The one case the advice existed for
    /// was the one case that never saw it.
    ///
    /// FAILS ON REVERT: return `false` unconditionally, i.e. stop consulting
    /// `managed_by` before the download, and the npm case stops refusing.
    #[test]
    fn an_npm_install_is_refused_before_anything_is_downloaded() {
        let npm = Path::new("/home/lab/.npm-global/lib/node_modules/innerwarden/bin/innerwarden");
        assert_eq!(managed_by(npm, None), Managed::Npm, "precondition");
        assert!(
            managed_refusal_applies(&managed_by(npm, None), false, false),
            "a plain `innerwarden upgrade` on an npm copy must refuse"
        );
    }

    /// The three ways the refusal must NOT fire, so it cannot become a blanket
    /// "upgrade is broken".
    #[test]
    fn the_npm_refusal_spares_check_forced_and_direct_installs() {
        let npm = Path::new("/usr/local/lib/node_modules/innerwarden/bin/innerwarden");
        let direct = Path::new("/usr/local/bin/innerwarden");

        assert!(
            !managed_refusal_applies(&managed_by(npm, None), true, false),
            "--check changes nothing, so it reports rather than refusing"
        );
        assert!(
            !managed_refusal_applies(&managed_by(npm, None), false, true),
            "--yes is the user saying they know what it costs"
        );
        assert!(
            !managed_refusal_applies(&managed_by(direct, None), false, false),
            "an installer copy is exactly what upgrade is for"
        );
        assert!(
            !managed_refusal_applies(&managed_by(direct, None), true, false),
            "{}",
            direct.display()
        );
    }

    #[test]
    fn a_plain_path_is_not_mistaken_for_npm() {
        assert_eq!(
            managed_by(Path::new("/usr/local/bin/innerwarden"), None),
            Managed::Direct
        );
        assert_eq!(
            managed_by(Path::new("/home/lab/.local/bin/innerwarden"), None),
            Managed::Direct
        );
    }

    #[test]
    fn every_published_platform_maps_to_its_asset() {
        assert_eq!(
            asset_name("linux", "x86_64").as_deref(),
            Some("innerwarden-linux-x86_64")
        );
        assert_eq!(
            asset_name("macos", "aarch64").as_deref(),
            Some("innerwarden-macos-aarch64")
        );
        assert_eq!(
            asset_name("windows", "x86_64").as_deref(),
            Some("innerwarden-windows-x86_64.exe"),
            "the Windows asset carries the .exe suffix"
        );
    }

    /// An unpublished platform must be named as such, not guessed into a 404.
    #[test]
    fn an_unpublished_platform_has_no_asset() {
        assert_eq!(asset_name("freebsd", "x86_64"), None);
        assert_eq!(asset_name("linux", "riscv64"), None);
    }

    /// The host running the tests is one this project publishes for, so the
    /// mapping cannot silently lose a supported platform.
    #[test]
    fn this_host_resolves_to_a_published_asset() {
        assert!(
            asset_for_this_host().is_some(),
            "no asset for {}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
    }

    #[test]
    fn both_sidecars_are_derived_from_the_asset() {
        let (bin, sha, sig) = urls_from(RELEASE_BASE, "innerwarden-linux-x86_64");
        assert!(bin.ends_with("/innerwarden-linux-x86_64"));
        assert_eq!(sha, format!("{bin}.sha256"));
        assert_eq!(sig, format!("{bin}.sig"));
        assert!(bin.starts_with("https://"), "never plain http");
    }

    /// The manifest shape the release actually publishes, trimmed to the field
    /// this reads. Kept verbatim so a change to the published layout shows up
    /// here rather than as a silent `Undetermined` on every host.
    const REAL_MANIFEST: &str = r#"{
      "version": "1.3.7",
      "description": "InnerWarden Community Edition",
      "homepage": "https://innerwarden.com",
      "architecture": { "64bit": { "hash": "f5cb" } }
    }"#;

    /// REGRESSION ANCHOR. `upgrade --check` could not answer the one question it
    /// is asked.
    ///
    /// It fetched the `.sha256` sidecar, threw it away, and printed "Run
    /// `innerwarden upgrade` to install it" whenever the HTTP call succeeded. On
    /// 1.3.7, with 1.3.7 published, it still said an upgrade was waiting. A check
    /// that answers "yes" unconditionally is not a check, and users who notice
    /// stop running it.
    ///
    /// FAILS ON REVERT: return `Available` regardless of the versions, which is
    /// what the old code effectively printed.
    #[test]
    fn a_check_on_the_published_version_reports_no_upgrade() {
        let outcome = check_outcome("1.3.7", REAL_MANIFEST);
        assert_eq!(
            outcome,
            CheckOutcome::UpToDate {
                version: "1.3.7".into()
            },
            "1.3.7 installed against 1.3.7 published is not an upgrade"
        );

        let lines = check_lines(
            &outcome,
            "innerwarden-linux-x86_64",
            &Managed::Direct,
            "x86_64",
        )
        .join("\n");
        assert!(
            lines.contains("Already on the latest build"),
            "the report must say so in words: {lines}"
        );
        assert!(
            !lines.contains("Run `innerwarden upgrade`"),
            "there is nothing to install, so do not send anyone to install it: {lines}"
        );
    }

    /// The other half: when a newer build IS published, name the version that
    /// would be installed rather than saying "a build exists".
    #[test]
    fn a_check_behind_the_release_names_the_version_it_would_install() {
        let outcome = check_outcome("1.3.4", REAL_MANIFEST);
        assert_eq!(
            outcome,
            CheckOutcome::Available {
                published: "1.3.7".into(),
                installed: "1.3.4".into()
            }
        );

        let lines = check_lines(
            &outcome,
            "innerwarden-linux-x86_64",
            &Managed::Direct,
            "x86_64",
        )
        .join("\n");
        assert!(lines.contains("1.3.7"), "name what would arrive: {lines}");
        assert!(
            lines.contains("1.3.4"),
            "name what is installed, or there is nothing to compare: {lines}"
        );
        assert!(lines.contains("Run `innerwarden upgrade`"), "{lines}");
    }

    /// A manifest that does not name a version must not become "an upgrade is
    /// available". Never report a verdict when you mean "could not tell".
    #[test]
    fn a_manifest_that_names_no_version_is_undetermined_not_available() {
        for manifest in [
            "{}",
            r#"{"version": ""}"#,
            r#"{"version": 137}"#,
            "not json at all",
            "",
        ] {
            assert_eq!(
                check_outcome("1.3.7", manifest),
                CheckOutcome::Undetermined,
                "{manifest:?} says nothing about a version"
            );
        }

        let lines = check_lines(
            &CheckOutcome::Undetermined,
            "innerwarden-linux-x86_64",
            &Managed::Direct,
            "x86_64",
        )
        .join("\n");
        assert!(
            !lines.to_lowercase().contains("run `innerwarden upgrade`"),
            "an unknown state must not be rendered as an available upgrade: {lines}"
        );
        assert!(lines.contains("could not determine"), "{lines}");
    }

    /// An npm-managed install must not be told to run a command that now
    /// refuses. The check and the upgrade have to agree about what to do next.
    #[test]
    fn a_check_on_an_npm_install_points_at_npm() {
        let outcome = check_outcome("1.3.4", REAL_MANIFEST);
        let lines = check_lines(
            &outcome,
            "innerwarden-linux-x86_64",
            &Managed::Npm,
            "x86_64",
        )
        .join("\n");
        assert!(
            lines.contains("npm install -g innerwarden@latest"),
            "{lines}"
        );
        assert!(
            !lines.contains("Run `innerwarden upgrade`"),
            "that command refuses on an npm copy, so do not recommend it: {lines}"
        );
    }

    #[test]
    fn the_version_manifest_sits_beside_the_binaries() {
        let url = manifest_url_from(RELEASE_BASE);
        assert_eq!(url, format!("{RELEASE_BASE}/innerwarden.json"));
        assert!(url.starts_with("https://"), "never plain http");
    }

    /// REGRESSION ANCHOR. Staging must be beside the target, not in a shared
    /// temp directory: the verified bytes are swappable between verification and
    /// rename, and only a same-filesystem rename is atomic.
    ///
    /// FAILS ON REVERT: stage in `std::env::temp_dir()` and the parent check
    /// trips.
    #[test]
    fn staging_is_beside_the_target_and_hidden() {
        let target = Path::new("/usr/local/bin/innerwarden");
        let staged = staging_path(target);
        assert_eq!(
            staged.parent(),
            target.parent(),
            "same directory, so the rename is atomic"
        );
        assert_ne!(
            staged, target,
            "never write the target before it is verified"
        );
        assert!(
            staged
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with('.'),
            "hidden, so a half-finished upgrade is not mistaken for a binary"
        );
        assert!(
            !staged.starts_with(std::env::temp_dir()),
            "never a shared temp dir"
        );
    }

    /// A bare filename has an empty parent, which must still resolve to the
    /// current directory rather than to the filesystem root.
    #[test]
    fn staging_handles_a_bare_filename() {
        let staged = staging_path(Path::new("innerwarden"));
        assert_eq!(staged.file_name().unwrap(), ".innerwarden.upgrade");
        assert!(
            staged == Path::new(".innerwarden.upgrade")
                || staged == Path::new("./.innerwarden.upgrade"),
            "unexpected staging path: {}",
            staged.display()
        );
        assert!(staged.is_relative(), "must not escape to an absolute path");
    }

    #[test]
    fn upgrade_stops_only_when_the_published_build_is_the_installed_one() {
        assert!(nothing_to_do(&CheckOutcome::UpToDate {
            version: "1.4.5".into()
        }));
        assert!(!nothing_to_do(&CheckOutcome::Available {
            published: "1.4.6".into(),
            installed: "1.4.5".into()
        }));
        assert!(!nothing_to_do(&CheckOutcome::Undetermined));
    }

    #[test]
    fn a_parked_image_sits_beside_its_target() {
        let p = parked_path(Path::new(
            r"C:\Users\me\AppData\Local\Programs\InnerWarden\innerwarden.exe",
        ));
        assert!(
            p.to_string_lossy().ends_with("innerwarden.exe.old"),
            "{}",
            p.display()
        );
        assert_eq!(
            p.parent(),
            Path::new(r"C:\Users\me\AppData\Local\Programs\InnerWarden\innerwarden.exe").parent()
        );
    }

    #[test]
    fn the_sibling_copies_are_the_other_names_beside_the_target() {
        let sib = sibling_copies(Path::new("/p/InnerWarden/innerwarden.exe"));
        let names: Vec<String> = sib
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["iw.exe", "iw-guard.exe"]);
        let sib = sibling_copies(Path::new("/p/InnerWarden/iw.exe"));
        let names: Vec<String> = sib
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["iw-guard.exe", "innerwarden.exe"]);
    }

    /// `sudo` must never be the advice on Windows; the Unix advice is unchanged.
    #[test]
    fn the_cannot_replace_advice_speaks_the_platform() {
        let t = Path::new("/home/me/.local/bin/innerwarden");
        let win =
            cannot_replace_advice_on(t, &Managed::Direct, false, "windows", "x86_64").join("\n");
        assert!(!win.contains("sudo"), "{win}");
        assert!(win.contains("Administrator"), "{win}");
        assert!(win.contains("other InnerWarden process"), "{win}");
        let unix =
            cannot_replace_advice_on(t, &Managed::Direct, false, "linux", "x86_64").join("\n");
        assert!(unix.contains("sudo innerwarden upgrade"), "{unix}");
    }

    // ── packages and shortcuts (todo P23) ──────────────────────────────────────

    fn deb() -> PackageOwner {
        PackageOwner::Dpkg {
            package: "innerwarden".into(),
        }
    }

    fn rpm() -> PackageOwner {
        PackageOwner::Rpm {
            package: "innerwarden".into(),
        }
    }

    /// Where the `.deb` and `.rpm` put the binary (packaging/nfpm.yaml).
    const PACKAGED: &str = "/usr/bin/innerwarden";

    /// REGRESSION ANCHOR. Ownership comes from the package database's answer,
    /// and the same path with no owner is the shell installer's copy
    /// (`sudo IW_GUARD_DIR=/usr/bin`), which `upgrade` is exactly for.
    ///
    /// FAILS ON REVERT: ignore `owner` and a `.deb` install classifies as
    /// `Direct`, so `upgrade` replaces dpkg's file and `uninstall` as root
    /// unlinks it.
    #[test]
    fn a_file_the_package_database_records_is_managed_by_that_package() {
        let p = Path::new(PACKAGED);
        assert_eq!(managed_by(p, Some(&deb())), Managed::System(deb()));
        assert_eq!(managed_by(p, Some(&rpm())), Managed::System(rpm()));
        assert_eq!(managed_by(p, None), Managed::Direct);
    }

    /// `upgrade` refuses a packaged copy before anything is downloaded, as it
    /// does npm's, and the same two things spare it: `--check` and `--yes`.
    ///
    /// FAILS ON REVERT: refuse only `Managed::Npm` and the packaged copy is
    /// replaced, leaving dpkg or rpm recording the old version.
    #[test]
    fn a_packaged_copy_is_refused_like_npm_and_spared_by_check_and_yes() {
        for owner in [deb(), rpm()] {
            let m = Managed::System(owner);
            assert!(managed_refusal_applies(&m, false, false), "{m:?}");
            assert!(!managed_refusal_applies(&m, true, false), "{m:?}");
            assert!(!managed_refusal_applies(&m, false, true), "{m:?}");
        }
    }

    /// `--check` on a `.deb` install names the package file and apt. Never
    /// `innerwarden upgrade`, which refuses there, and never `apt upgrade`:
    /// there is no apt repository, so it would find nothing newer.
    ///
    /// FAILS ON REVERT: the old report said "Run `innerwarden upgrade`" for
    /// every copy that was not npm's.
    #[test]
    fn a_check_on_a_deb_install_names_the_package_file_and_apt() {
        let outcome = check_outcome("1.3.4", REAL_MANIFEST);
        let lines = check_lines(
            &outcome,
            "innerwarden-linux-x86_64",
            &Managed::System(deb()),
            "x86_64",
        )
        .join("\n");
        assert!(
            lines.contains(&format!(
                "curl -fsSL -o \"$dir/innerwarden_amd64.deb\" {RELEASE_BASE}/innerwarden_amd64.deb"
            )),
            "{lines}"
        );
        assert!(
            lines.contains("&& sudo apt install \"$dir/innerwarden_amd64.deb\""),
            "{lines}"
        );
        assert!(lines.contains(PACKAGE_NOTE), "{lines}");
        assert!(lines.contains("the .deb package `innerwarden`"), "{lines}");
        assert!(
            !lines.contains("innerwarden upgrade"),
            "that command refuses a packaged copy: {lines}"
        );
        assert!(!lines.contains("apt upgrade"), "{lines}");
    }

    /// The `.rpm` names dnf and the release's fixed-name package for this
    /// architecture, and an architecture the release has no package for gets
    /// no invented file name.
    #[test]
    fn a_check_on_an_rpm_install_names_dnf_and_the_package_for_this_arch() {
        let outcome = check_outcome("1.3.4", REAL_MANIFEST);
        let lines = check_lines(
            &outcome,
            "innerwarden-linux-aarch64",
            &Managed::System(rpm()),
            "aarch64",
        )
        .join("\n");
        assert!(
            lines.contains("&& sudo dnf install \"$dir/innerwarden.aarch64.rpm\""),
            "{lines}"
        );
        assert!(
            !lines.contains("dnf install https"),
            "dnf checks no signature on a URL: {lines}"
        );

        let unknown = upgrade_commands(&Managed::System(deb()), "riscv64").join("\n");
        assert!(!unknown.contains("innerwarden_riscv64.deb"), "{unknown}");
        assert!(unknown.contains("sudo apt install"), "{unknown}");
        assert!(unknown.contains(".sha256"), "{unknown}");
    }

    /// A package is installed as root, maintainer scripts included. The
    /// advice used to download it into the current directory (which may be
    /// `/tmp`, where another account can swap it before the install) and to
    /// run `dnf install <URL>`, with no check at all. Now every packaged
    /// install is fetched into a fresh private directory, checked against the
    /// release's checksum, and installed only if the check passed: ONE command
    /// chained with `&&`, each line continued, so a failed check stops it.
    ///
    /// FAILS ON REVERT: the old commands fetch into `.` and never check.
    #[test]
    fn a_package_is_fetched_privately_and_checked_before_it_is_installed() {
        for (owner, arch, file, install) in [
            (deb(), "x86_64", "innerwarden_amd64.deb", "sudo apt install"),
            (
                deb(),
                "aarch64",
                "innerwarden_arm64.deb",
                "sudo apt install",
            ),
            (
                rpm(),
                "x86_64",
                "innerwarden.x86_64.rpm",
                "sudo dnf install",
            ),
            (
                rpm(),
                "aarch64",
                "innerwarden.aarch64.rpm",
                "sudo dnf install",
            ),
        ] {
            let lines = upgrade_commands(&Managed::System(owner), arch);
            assert_eq!(lines[0], "dir=\"$(mktemp -d)\" \\", "{lines:?}");
            let (last, rest) = lines.split_last().expect("lines");
            assert!(
                rest.iter().all(|line| line.ends_with(" \\")),
                "one command: {lines:?}"
            );
            assert!(
                lines[1..]
                    .iter()
                    .all(|line| line.trim_start().starts_with("&& ")),
                "{lines:?}"
            );
            let check = lines
                .iter()
                .position(|line| line.contains(&format!("sha256sum -c {file}.sha256")))
                .unwrap_or_else(|| panic!("no checksum check: {lines:?}"));
            let fetch_sum = lines
                .iter()
                .position(|line| line.contains(&format!("{RELEASE_BASE}/{file}.sha256")))
                .expect("the checksum is fetched");
            assert!(fetch_sum < check, "{lines:?}");
            assert_eq!(*last, format!("  && {install} \"$dir/{file}\""));
            assert!(
                !lines
                    .iter()
                    .any(|line| line.contains("-O ") || line.contains("-fsSLO")),
                "nothing is saved into the current directory: {lines:?}"
            );
        }
    }

    /// The checksum each command checks is the sidecar the release workflow
    /// writes beside the fixed-name copy, as `sha256sum -c` reads it: made in
    /// the package directory, so it names the bare file.
    ///
    /// FAILS ON DRIFT: write the sidecars before the fixed-name copies, or
    /// from outside `out`, and `sha256sum -c` finds no file to check.
    #[test]
    fn the_checksums_checked_are_the_ones_the_release_uploads() {
        let workflow = include_str!("../../../.github/workflows/linux-packages.yml");
        let copies = workflow
            .find("cp \"$src\" \"$dst\"")
            .expect("fixed-name copies");
        let sums = workflow
            .find("for f in *.deb *.rpm; do sha256sum \"$f\" > \"$f.sha256\"; done")
            .expect("sidecars for every package file");
        assert!(copies < sums, "the sidecars cover the fixed-name copies");
        assert!(workflow[..sums]
            .rfind("cd out")
            .is_some_and(|cd| cd > copies));
        assert!(workflow.contains("out/*.sha256"), "and they are uploaded");
    }

    /// The package files the advice names are the fixed-name copies the
    /// release workflow uploads, for every architecture the packages are built
    /// for. A hand-written name that drifts from the workflow sends a packaged
    /// install to a 404.
    ///
    /// FAILS ON DRIFT: rename a fixed-name copy in `linux-packages.yml`, or
    /// spell an architecture differently here.
    #[test]
    fn the_package_files_named_are_the_ones_the_release_uploads() {
        let workflow = include_str!("../../../.github/workflows/linux-packages.yml");
        for arch in ["x86_64", "aarch64"] {
            for owner in [deb(), rpm()] {
                let commands = upgrade_commands(&Managed::System(owner.clone()), arch).join("\n");
                let file = commands
                    .split(&format!("{RELEASE_BASE}/"))
                    .nth(1)
                    .and_then(|rest| rest.split_whitespace().next())
                    .unwrap_or_else(|| {
                        panic!("no release file named for {owner:?}/{arch}:\n{commands}")
                    });
                assert!(
                    workflow.contains(&format!(":{file}\"")),
                    "{file} ({owner:?}, {arch}) is not a fixed-name copy linux-packages.yml uploads"
                );
            }
        }
    }

    /// What `upgrade` prints when it refuses a packaged copy: who manages it,
    /// the way it was installed, and the override.
    #[test]
    fn the_refusal_for_a_deb_names_apt_the_package_file_and_the_override() {
        let lines = managed_refusal_lines(
            Path::new(PACKAGED),
            &Managed::System(deb()),
            false,
            "linux",
            "aarch64",
        )
        .join("\n");
        assert!(
            lines.contains("REFUSED, this copy is managed by apt (the .deb package `innerwarden`)"),
            "{lines}"
        );
        assert!(
            lines.contains("&& sudo apt install \"$dir/innerwarden_arm64.deb\""),
            "{lines}"
        );
        assert!(lines.contains(PACKAGE_NOTE), "{lines}");
        assert!(lines.contains("sudo innerwarden upgrade --yes"), "{lines}");
        assert!(!lines.contains("npm"), "nothing here is npm's: {lines}");
    }

    /// npm's refusal reads as it did; `tests/upgrade_npm_guard.rs` pins the
    /// same words from outside, through the real binary.
    #[test]
    fn the_refusal_for_npm_still_names_npm_and_its_override() {
        let p = Path::new("/usr/local/lib/node_modules/innerwarden/bin/innerwarden");
        let lines =
            managed_refusal_lines(p, &managed_by(p, None), false, "linux", "x86_64").join("\n");
        assert!(
            lines.contains("REFUSED, this copy is managed by npm."),
            "{lines}"
        );
        assert!(
            lines.contains("npm install -g innerwarden@latest"),
            "{lines}"
        );
        assert!(lines.contains("innerwarden upgrade --yes"), "{lines}");
    }

    /// `uninstall` leaves a packaged binary to its package manager even when
    /// it could unlink it, which as root it can.
    ///
    /// FAILS ON REVERT: classify the packaged copy by writability alone and
    /// `sudo innerwarden uninstall` deletes dpkg's file.
    #[test]
    fn a_packaged_binary_is_left_to_its_package_manager_even_as_root() {
        for (owner, remove) in [
            (deb(), "sudo apt remove innerwarden"),
            (rpm(), "sudo dnf remove innerwarden"),
        ] {
            let plan = plan_binary_removal(
                &Managed::System(owner.clone()),
                &CopyOrigin::Installer,
                true,
            );
            assert_eq!(plan, BinaryRemoval::LeaveToPackage(owner));
            let (lines, left) = binary_removal_lines(&plan, Path::new(PACKAGED));
            let text = lines.join("\n");
            assert!(text.contains(remove), "{text}");
            assert!(!text.contains("rm "), "{text}");
            assert!(left, "the binary is still there when we finish: {text}");
        }
    }

    /// `dpkg-query -S` names the owner of exactly this path, and nothing else
    /// it prints counts as ownership.
    #[test]
    fn dpkg_query_output_names_the_owner_of_exactly_this_path() {
        let t = Path::new(PACKAGED);
        assert_eq!(
            dpkg_owner("innerwarden: /usr/bin/innerwarden\n", t).as_deref(),
            Some("innerwarden")
        );
        assert_eq!(
            dpkg_owner("innerwarden:amd64: /usr/bin/innerwarden\n", t).as_deref(),
            Some("innerwarden"),
            "a multi-arch name carries its architecture after a colon"
        );
        assert_eq!(
            dpkg_owner("first, second: /usr/bin/innerwarden\n", t).as_deref(),
            Some("first")
        );
        assert_eq!(
            dpkg_owner(
                "diversion by other from: /usr/bin/innerwarden\n\
                 diversion by other to: /usr/bin/innerwarden.real\n",
                t
            ),
            None,
            "a diversion is not ownership"
        );
        assert_eq!(dpkg_owner("other: /usr/bin/innerwarden-ctl\n", t), None);
        assert_eq!(dpkg_owner("", t), None);
    }

    /// `rpm -qf` prints a name on success; its "not owned" sentence is not one.
    #[test]
    fn rpm_query_output_is_a_name_or_nothing() {
        assert_eq!(rpm_owner("innerwarden\n").as_deref(), Some("innerwarden"));
        assert_eq!(
            rpm_owner("file /usr/bin/innerwarden is not owned by any package\n"),
            None
        );
        assert_eq!(rpm_owner(""), None);
    }

    /// The names the shell installer lays beside the binary, whichever of
    /// them the binary was run as.
    #[test]
    fn the_names_beside_a_unix_binary_are_its_shortcuts() {
        assert_eq!(
            siblings_named(Path::new("/h/.local/bin/innerwarden"), ""),
            vec![
                PathBuf::from("/h/.local/bin/iw"),
                PathBuf::from("/h/.local/bin/iw-guard")
            ]
        );
        assert_eq!(
            siblings_named(Path::new("/h/.local/bin/iw"), ""),
            vec![
                PathBuf::from("/h/.local/bin/iw-guard"),
                PathBuf::from("/h/.local/bin/innerwarden")
            ]
        );
    }

    fn link(path: &str, to: Option<&str>) -> AliasFact {
        AliasFact {
            path: PathBuf::from(path),
            entry: AliasEntry::Link {
                resolves_to: to.map(PathBuf::from),
            },
        }
    }

    fn file(path: &str, same_bytes: bool) -> AliasFact {
        AliasFact {
            path: PathBuf::from(path),
            entry: AliasEntry::File {
                same_bytes,
                innerwarden_build: same_bytes,
            },
        }
    }

    /// REGRESSION ANCHOR. `uninstall` removed the binary and left `iw` and
    /// `iw-guard` as links to a file that no longer existed. The installer's
    /// links, and its copies where a link could not be made, go with it.
    ///
    /// FAILS ON REVERT: an empty plan, which is what uninstall did.
    #[test]
    fn the_shortcuts_that_are_this_binary_go_with_it() {
        let exe = "/h/.local/bin/innerwarden";
        let plan = plan_alias_removal(
            &[
                link("/h/.local/bin/iw", Some(exe)),
                file("/h/.local/bin/iw-guard", true),
            ],
            Path::new(exe),
        );
        assert_eq!(
            plan.remove,
            vec![
                PathBuf::from("/h/.local/bin/iw"),
                PathBuf::from("/h/.local/bin/iw-guard")
            ]
        );
        assert!(plan.keep.is_empty(), "{:?}", plan.keep);
    }

    /// Never unlink a name that is somebody else's: a link to another program,
    /// a link to nothing, a file with other bytes (another tool's `iw`, or an
    /// older copy), or something that could not be read. Each is kept and says
    /// why. And the binary is never its own alias.
    ///
    /// FAILS ON REVERT: remove every installed name that exists, and each of
    /// these lands in `remove`.
    #[test]
    fn a_name_that_is_not_this_binary_is_left_where_it_is() {
        let exe = "/h/.local/bin/innerwarden";
        let facts = [
            link("/h/.local/bin/iw", Some("/opt/other/bin/iw")),
            link("/h/a/iw-guard", None),
            file("/h/b/iw", false),
            AliasFact {
                path: PathBuf::from("/h/c/iw-guard"),
                entry: AliasEntry::Unreadable,
            },
            file(exe, true),
        ];
        let plan = plan_alias_removal(&facts, Path::new(exe));
        assert!(plan.remove.is_empty(), "{:?}", plan.remove);
        let reasons: Vec<(&str, &str)> = plan
            .keep
            .iter()
            .map(|(p, why)| (p.to_str().unwrap(), *why))
            .collect();
        assert_eq!(
            reasons,
            vec![
                ("/h/.local/bin/iw", "it links to another program"),
                ("/h/a/iw-guard", "it links to nothing that exists"),
                (
                    "/h/b/iw",
                    "it is a different file, another program or an older copy"
                ),
                ("/h/c/iw-guard", "it could not be read"),
            ]
        );
    }

    fn older_build(path: &str) -> AliasFact {
        AliasFact {
            path: PathBuf::from(path),
            entry: AliasEntry::File {
                same_bytes: false,
                innerwarden_build: true,
            },
        }
    }

    const KEY: &[u8] = b"vR3bZQMGNQ7tfoKirl4mbBCE6DekmmEFADL5g984PC4=";

    fn with_header(header: &[u8], body: &[u8]) -> Vec<u8> {
        let mut out = header.to_vec();
        out.extend_from_slice(b"\0\0padding ");
        out.extend_from_slice(body);
        out.extend_from_slice(b" trailing");
        out
    }

    /// A build of this program is an executable carrying the release key it
    /// pins. The key quoted in a text (the shell installer pins it too), an
    /// executable without it, or a file too short to hold it, are not.
    ///
    /// FAILS ON REVERT: drop the header check and the installer's own text is
    /// taken for a build; drop the key check and any executable is.
    #[test]
    fn a_build_of_this_program_is_an_executable_carrying_its_release_key() {
        for header in [
            &b"\x7fELF"[..],
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"MZ",
        ] {
            assert!(is_innerwarden_build(&with_header(header, KEY), KEY));
        }
        assert!(!is_innerwarden_build(&with_header(b"#!/bin/sh", KEY), KEY));
        assert!(!is_innerwarden_build(
            &with_header(b"\x7fELF", b"another program"),
            KEY
        ));
        assert!(!is_innerwarden_build(b"\x7fELF", KEY));
        assert!(!is_innerwarden_build(&with_header(b"\x7fELF", KEY), b""));
    }

    /// An installer copy that an earlier upgrade left on the old build is
    /// still this program's, and goes with it. A file that is not a build of
    /// it stays.
    ///
    /// FAILS ON REVERT: remove only `same_bytes` copies and the older build is
    /// kept as "a different file", which is how uninstall left them.
    #[test]
    fn an_older_build_left_beside_the_binary_goes_with_it() {
        let exe = "/h/.local/bin/innerwarden";
        let plan = plan_alias_removal(
            &[
                older_build("/h/.local/bin/iw"),
                file("/h/.local/bin/iw-guard", false),
            ],
            Path::new(exe),
        );
        assert_eq!(plan.remove, vec![PathBuf::from("/h/.local/bin/iw")]);
        assert_eq!(
            plan.keep,
            vec![(
                PathBuf::from("/h/.local/bin/iw-guard"),
                "it is a different file, another program or an older copy"
            )]
        );
    }

    /// The installer's mark is a shortcut that is THIS binary. Another build
    /// beside it, a link elsewhere, or the binary itself listed among the
    /// names, are not that mark.
    #[test]
    fn the_installers_mark_is_a_shortcut_that_is_this_binary() {
        let exe = "/opt/p/bin/innerwarden";
        assert!(a_shortcut_is_this_binary(
            &[link("/opt/p/bin/iw", Some(exe))],
            Path::new(exe)
        ));
        assert!(a_shortcut_is_this_binary(
            &[file("/opt/p/bin/iw-guard", true)],
            Path::new(exe)
        ));
        assert!(!a_shortcut_is_this_binary(
            &[
                older_build("/opt/p/bin/iw"),
                link("/opt/p/bin/iw-guard", Some("/opt/q/iw")),
                link("/opt/p/bin/x", None),
                file(exe, true),
            ],
            Path::new(exe)
        ));
    }

    /// `upgrade` refreshes the installer's copies: this build's bytes, or an
    /// older build an earlier upgrade did not refresh. A link follows the
    /// binary already, and a file that is not a build of it is not ours to
    /// overwrite.
    ///
    /// FAILS ON REVERT: an empty list, which is what upgrade did on Unix.
    #[test]
    fn upgrade_refreshes_only_the_installers_copies() {
        let target = "/h/.local/bin/innerwarden";
        let facts = [
            file("/h/.local/bin/iw", true),
            older_build("/h/.local/bin/iw-guard"),
            link("/h/a/iw", Some(target)),
            file("/h/b/iw", false),
            AliasFact {
                path: PathBuf::from("/h/c/iw"),
                entry: AliasEntry::Unreadable,
            },
            file(target, true),
        ];
        assert_eq!(
            copies_to_refresh(&facts, Path::new(target)),
            vec![
                PathBuf::from("/h/.local/bin/iw"),
                PathBuf::from("/h/.local/bin/iw-guard")
            ]
        );
    }
}
