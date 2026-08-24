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
use std::process::{Command, Output};

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
    // `copy` carries the mode across on Unix, so the copy stays executable.
    std::fs::copy(source, &target).expect("copy the binary into npm's layout");
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
    std::fs::copy(source, &target).expect("copy the binary");
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
    cmd.output().expect("run uninstall")
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
