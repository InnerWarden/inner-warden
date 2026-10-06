//! `innerwarden uninstall` must not claim it removed a product it left behind.
//!
//! # The defect this pins
//!
//! Observed on a real host. `uninstall` ran without root against an npm install
//! and printed:
//!
//! ```text
//!   binary  : remove it with `rm /usr/local/lib/node_modules/.../bin/innerwarden` (Permission denied (os error 13))
//!
//! InnerWarden Community removed. Restart your agent to drop the hook.
//! ```
//!
//! Three things are wrong at once and they compound.
//!
//! The ORDER: the hook, the config directory and the API key were destroyed
//! first, and the one step that can fail ran last. So the failure mode is the
//! worst available one, the recoverable state gone and the unwanted thing still
//! present.
//!
//! The REMEDY: `rm` needs exactly the root the run had just proven it did not
//! have. And on an npm copy it is the move this crate already documents as
//! wrong, in `upgrade_plan::cannot_replace_advice`: npm owns the `innerwarden`
//! and `iw` launchers too, so unlinking the file by hand leaves both pointing at
//! nothing while npm still believes it ships the version.
//!
//! The EXIT CODE: `ExitCode::SUCCESS`, unconditionally. The next `innerwarden`
//! call then answered "linux-x64 IS supported, but its binary is not installed",
//! so the product reported itself broken one command after reporting success.
//!
//! # Why this runs the real binary
//!
//! `upgrade_plan`'s unit tests cover the decision directly. What they cannot
//! show is that `cmd_uninstall_self` CONSULTS it, that it does so before the
//! destructive steps, and that the exit code follows. So this copies the real
//! binary into npm's layout and runs it: the binary reads its own location
//! through `current_exe`, so the copy classifies itself as an npm install
//! exactly the way a real one does.
//!
//! `HOME` is redirected to a temporary directory, so nothing outside the test's
//! own tempdir is read or written.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

mod fork_safe;
use fork_safe::{copy_the_binary, spawn_without_racing_a_copy};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

/// Install the real binary at `<root>/lib/node_modules/innerwarden/bin/<name>`,
/// mirroring npm's global layout. `node_modules` is the marker `managed_by`
/// keys on, and it is stable across npm versions and platforms.
fn as_an_npm_install(root: &Path) -> PathBuf {
    let source = Path::new(bin());
    let name = source.file_name().expect("the test binary has a name");
    let dir = root
        .join("lib")
        .join("node_modules")
        .join("innerwarden")
        .join("bin");
    std::fs::create_dir_all(&dir).expect("npm layout");
    let target = dir.join(name);
    copy_the_binary(source, &target);
    target
}

/// A direct install: the binary somewhere ordinary, with no `node_modules`
/// anywhere in its path.
fn as_a_direct_install(root: &Path) -> PathBuf {
    let source = Path::new(bin());
    let name = source.file_name().expect("the test binary has a name");
    let dir = root.join("usr").join("local").join("bin");
    std::fs::create_dir_all(&dir).expect("direct layout");
    let target = dir.join(name);
    copy_the_binary(source, &target);
    target
}

/// Seed the state a real uninstall destroys, so the test can tell whether the
/// run got far enough to destroy it.
fn seed_home(home: &Path) {
    std::fs::create_dir_all(home.join(".config/innerwarden")).expect("config dir");
    std::fs::write(
        home.join(".config/innerwarden/llm-key"),
        b"sk-not-a-real-key",
    )
    .expect("seed a key");
}

fn run_uninstall(exe: &Path, home: &Path, extra: &[&str]) -> Output {
    let mut cmd = Command::new(exe);
    cmd.arg("uninstall");
    cmd.args(extra);
    cmd.env("HOME", home);
    // Keep the run offline and non-interactive whatever the environment holds.
    cmd.env_remove("INNERWARDEN_CONFIG_DIR");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // The guard is dropped before the wait, so a slow child never blocks
    // another test's copy. See `fork_safe` for why the fork needs covering.
    spawn_without_racing_a_copy(&mut cmd)
        .wait_with_output()
        .expect("run uninstall")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// REGRESSION ANCHOR. An npm-managed copy must name npm's own uninstall, must
/// never hand out `rm`, and must not exit 0 while the binary is still there.
///
/// FAILS ON REVERT: the old code printed "remove it with `rm <path>`" and
/// returned `ExitCode::SUCCESS`, so the `rm ` assertion and the exit-code
/// assertion both fail.
#[test]
fn an_npm_copy_names_npms_uninstall_and_does_not_report_success() {
    let root = tempfile::tempdir().expect("tempdir");
    let home = tempfile::tempdir().expect("home");
    seed_home(home.path());
    let exe = as_an_npm_install(root.path());

    let out = run_uninstall(&exe, home.path(), &[]);
    let said = text(&out);

    assert!(
        said.contains("npm uninstall -g innerwarden"),
        "an npm copy must be handed npm's own command:\n{said}"
    );
    assert!(
        !said.contains("rm "),
        "uninstall must never hand out a bare `rm` for its own binary:\n{said}"
    );
    assert_ne!(
        out.status.code(),
        Some(0),
        "the binary is still on the machine, so this is not a clean uninstall:\n{said}"
    );
    assert!(
        exe.exists(),
        "an npm-managed binary must be left for npm to remove"
    );
}

/// The npm branch must be announced BEFORE the destructive steps, not after.
/// The order is the defect; a run that prints the right words in the wrong place
/// still destroys the recoverable state before saying anything useful.
///
/// FAILS ON REVERT: with the old order the binary line appears after the config
/// line, so the index comparison flips.
#[test]
fn the_binary_verdict_is_announced_before_anything_is_destroyed() {
    let root = tempfile::tempdir().expect("tempdir");
    let home = tempfile::tempdir().expect("home");
    seed_home(home.path());
    let exe = as_an_npm_install(root.path());

    let said = text(&run_uninstall(&exe, home.path(), &[]));

    let binary_at = said
        .find("binary  :")
        .unwrap_or_else(|| panic!("no binary line:\n{said}"));
    let config_at = said
        .find("config  :")
        .unwrap_or_else(|| panic!("no config line:\n{said}"));
    assert!(
        binary_at < config_at,
        "the verdict about the binary must come before the config is removed, \
         so the operator learns it while the machine is still intact:\n{said}"
    );
}

/// The other side, so this is not a guard that refuses everything: a direct
/// install the process owns is removed, reports removal, and exits 0.
///
/// Without this, "never exit 0" would pass the test above and be a regression.
#[test]
fn a_writable_direct_install_is_removed_and_exits_clean() {
    let root = tempfile::tempdir().expect("tempdir");
    let home = tempfile::tempdir().expect("home");
    seed_home(home.path());
    let exe = as_a_direct_install(root.path());

    let out = run_uninstall(&exe, home.path(), &[]);
    let said = text(&out);

    assert_eq!(
        out.status.code(),
        Some(0),
        "a complete uninstall must exit 0:\n{said}"
    );
    assert!(
        said.contains("removed"),
        "a complete uninstall may say removed:\n{said}"
    );
    assert!(
        !exe.exists(),
        "a writable direct install must actually be gone:\n{said}"
    );
}

/// `--dry-run` must preview the same decision the real run makes. Listing the
/// path unconditionally was the preview's own version of this defect: on an npm
/// install it named a file uninstall must not touch.
///
/// FAILS ON REVERT: the old `uninstall_plan_lines` pushed `binary  : <path>`
/// whatever the install channel, so the npm command never appeared.
#[test]
fn dry_run_previews_the_same_verdict_and_changes_nothing() {
    let root = tempfile::tempdir().expect("tempdir");
    let home = tempfile::tempdir().expect("home");
    seed_home(home.path());
    let exe = as_an_npm_install(root.path());

    let said = text(&run_uninstall(&exe, home.path(), &["--dry-run"]));

    assert!(
        said.contains("npm uninstall -g innerwarden"),
        "the preview must name what the real run will name:\n{said}"
    );
    assert!(
        exe.exists() && home.path().join(".config/innerwarden/llm-key").exists(),
        "--dry-run must not remove anything:\n{said}"
    );
}

// ── the shortcuts the installer lays beside the binary (todo P23) ────────────

/// A direct install laid the way the shell installer lays it: the binary, and
/// `iw` and `iw-guard` beside it as the relative links `ln -sf innerwarden`
/// makes.
#[cfg(unix)]
fn as_an_installer_layout(root: &Path) -> PathBuf {
    let exe = as_a_direct_install(root);
    let dir = exe.parent().expect("the binary has a directory");
    for alias in ["iw", "iw-guard"] {
        std::os::unix::fs::symlink(exe.file_name().expect("a name"), dir.join(alias))
            .expect("link a shortcut");
    }
    exe
}

/// Is anything at this path, a dangling link included?
#[cfg(unix)]
fn present(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// REGRESSION ANCHOR. `uninstall` removed the one file it ran from and left
/// `iw` and `iw-guard` behind, two links to a file that no longer existed, and
/// said "removed" over them.
///
/// FAILS ON REVERT: drop the shortcut removal from `cmd_uninstall_self` and
/// both links are still present after a run that exits 0.
#[cfg(unix)]
#[test]
fn the_installers_shortcuts_go_with_the_binary() {
    let root = tempfile::tempdir().expect("tempdir");
    let home = tempfile::tempdir().expect("home");
    seed_home(home.path());
    let exe = as_an_installer_layout(root.path());
    let dir = exe.parent().unwrap().to_path_buf();

    let out = run_uninstall(&exe, home.path(), &[]);
    let said = text(&out);

    assert_eq!(out.status.code(), Some(0), "{said}");
    for path in [exe.clone(), dir.join("iw"), dir.join("iw-guard")] {
        assert!(
            !present(&path),
            "{} must go with the binary:\n{said}",
            path.display()
        );
    }
    assert!(said.contains("alias   : removed"), "{said}");
}

/// macOS reports the path a program was started by, so `iw uninstall` saw the
/// `iw` link as the binary: it unlinked the link, said "removed", and left
/// `innerwarden` and `iw-guard` on the machine. The binary removed is the file
/// the link leads to. (Linux reports the resolved file already; this pins it
/// on both.)
///
/// FAILS ON REVERT (macOS): use `current_exe` unresolved and `innerwarden` is
/// removed as a copy while `iw-guard` is kept as a link to "another program".
#[cfg(unix)]
#[test]
fn uninstalling_through_a_shortcut_removes_the_binary_it_leads_to() {
    let root = tempfile::tempdir().expect("tempdir");
    let home = tempfile::tempdir().expect("home");
    seed_home(home.path());
    let exe = as_an_installer_layout(root.path());
    let dir = exe.parent().unwrap().to_path_buf();

    let out = run_uninstall(&dir.join("iw"), home.path(), &[]);
    let said = text(&out);

    assert_eq!(out.status.code(), Some(0), "{said}");
    for path in [exe.clone(), dir.join("iw"), dir.join("iw-guard")] {
        assert!(
            !present(&path),
            "{} must be gone after `iw uninstall`:\n{said}",
            path.display()
        );
    }
}

/// A name the installer would use, carrying something that is not this
/// binary, is somebody else's: a link to another program, or a file with other
/// bytes. Both are left exactly as they were, and the run says why.
///
/// FAILS ON REVERT: remove every installed name that exists, and the other
/// program's link and the unrelated file are gone.
#[cfg(unix)]
#[test]
fn a_shortcut_name_that_is_another_program_is_left_alone() {
    let root = tempfile::tempdir().expect("tempdir");
    let home = tempfile::tempdir().expect("home");
    seed_home(home.path());
    let exe = as_a_direct_install(root.path());
    let dir = exe.parent().unwrap().to_path_buf();

    let other_dir = root.path().join("opt").join("other").join("bin");
    std::fs::create_dir_all(&other_dir).expect("another tool's dir");
    let other = other_dir.join("iw");
    std::fs::write(&other, b"#!/bin/sh\necho another tool\n").expect("another tool");
    std::os::unix::fs::symlink(&other, dir.join("iw")).expect("its link");
    std::fs::write(dir.join("iw-guard"), b"not innerwarden").expect("an unrelated file");

    let out = run_uninstall(&exe, home.path(), &[]);
    let said = text(&out);

    assert!(
        !present(&exe),
        "the binary itself is still removed:\n{said}"
    );
    assert_eq!(
        std::fs::read_link(dir.join("iw")).expect("the link is still there"),
        other,
        "{said}"
    );
    assert_eq!(
        std::fs::read(&other).expect("the other program is untouched"),
        b"#!/bin/sh\necho another tool\n"
    );
    assert_eq!(
        std::fs::read(dir.join("iw-guard")).expect("the file is still there"),
        b"not innerwarden"
    );
    assert!(said.contains("it links to another program"), "{said}");
    assert!(
        said.contains("it is a different file, another program or an older copy"),
        "{said}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "nothing of InnerWarden's is left, so this is a clean uninstall:\n{said}"
    );
}

/// `--dry-run` names the shortcuts the run will remove, and removes nothing.
#[cfg(unix)]
#[test]
fn dry_run_names_the_shortcuts_and_removes_nothing() {
    let root = tempfile::tempdir().expect("tempdir");
    let home = tempfile::tempdir().expect("home");
    seed_home(home.path());
    let exe = as_an_installer_layout(root.path());
    let dir = exe.parent().unwrap().to_path_buf();
    // The run prints resolved paths (a macOS tempdir sits behind /var -> /private/var).
    let resolved = std::fs::canonicalize(&dir).expect("resolve the dir");

    let said = text(&run_uninstall(&exe, home.path(), &["--dry-run"]));

    for alias in ["iw", "iw-guard"] {
        assert!(
            said.contains(&format!("alias   : {}", resolved.join(alias).display())),
            "the preview must name {alias}:\n{said}"
        );
        assert!(
            present(&dir.join(alias)),
            "--dry-run removed {alias}:\n{said}"
        );
    }
    assert!(exe.exists(), "--dry-run removed the binary:\n{said}");
}
