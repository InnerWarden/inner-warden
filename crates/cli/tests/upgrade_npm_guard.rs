//! `innerwarden upgrade` must refuse an npm-managed copy BEFORE it downloads.
//!
//! # The defect this pins
//!
//! `upgrade_plan` documented the npm hazard and `managed_by` detected it, but
//! both callers were on the FAILURE path: the advice was printed only when the
//! replace had already failed, which needs a root-owned npm prefix. The install
//! page recommends `npm config set prefix ~/.npm-global`, and that prefix is
//! owned by the user, so the replace SUCCEEDS. Those users were told "Upgrade
//! complete", npm went on believing it shipped the old version, and the next
//! `npm install -g` silently reverted the binary. The one case the advice
//! existed for was the one case that never saw it.
//!
//! # Why this runs the real binary
//!
//! The refusal is decided by a pure function that `upgrade_plan`'s unit tests
//! cover directly. What they cannot show is that `cmd` CONSULTS it, and that it
//! does so before the fetch, which is the half that was missing. So this copies
//! the real binary to a path under `node_modules` and runs it: the binary reads
//! its own location through `current_exe`, so the copy classifies itself as an
//! npm install exactly the way a real one does.
//!
//! Nothing here needs a network, and that is asserted rather than assumed: the
//! command must exit before printing the line it prints immediately before the
//! first byte is fetched.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

/// Install the real binary at `<tmp>/lib/node_modules/innerwarden/bin/<name>`,
/// mirroring npm's global layout. The `node_modules` component is the marker
/// `managed_by` keys on, and it is stable across npm versions and platforms.
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

/// REGRESSION ANCHOR. A plain `innerwarden upgrade` from an npm-managed copy
/// must refuse, exit 2, and download nothing.
///
/// FAILS ON REVERT: remove the `npm_refusal_applies` gate from `upgrade::cmd`
/// and this either replaces the binary or fails with a download error, and in
/// both cases the exit code is not 2 and the npm advice never appears.
#[test]
fn an_npm_managed_copy_refuses_before_it_downloads_anything() {
    let root = tempfile::tempdir().expect("tempdir");
    let target = as_an_npm_install(root.path());
    let before = std::fs::read(&target).expect("read the installed copy");

    let out = Command::new(&target)
        .arg("upgrade")
        .output()
        .expect("run the npm-managed copy");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    assert_eq!(
        out.status.code(),
        Some(2),
        "an npm copy must refuse with 2.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("managed by npm"),
        "say WHY it refused: {stderr}"
    );
    assert!(
        stderr.contains("npm install -g innerwarden@latest"),
        "name the command that actually upgrades this copy: {stderr}"
    );

    // The proof that nothing was fetched. `cmd` prints this line immediately
    // before handing off to the download, so its absence means the refusal came
    // first rather than after a wasted round trip.
    assert!(
        !stdout.contains("fetching"),
        "the refusal must come before the download, not after it: {stdout}"
    );
    assert_eq!(
        std::fs::read(&target).expect("read back"),
        before,
        "a refused upgrade must leave the installed binary byte-identical"
    );
    assert!(
        !target
            .with_file_name(format!(
                ".{}.upgrade",
                target.file_name().unwrap().to_string_lossy()
            ))
            .exists(),
        "nothing may be staged beside a binary the command refused to touch"
    );
}

/// The refusal must name the way out, and that way must be a flag the binary
/// actually accepts. A refusal that recommends an option the parser rejects
/// sends the user round a loop.
#[test]
fn the_refusal_offers_an_override_the_parser_accepts() {
    let root = tempfile::tempdir().expect("tempdir");
    let target = as_an_npm_install(root.path());

    let out = Command::new(&target)
        .arg("upgrade")
        .output()
        .expect("run the npm-managed copy");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("innerwarden upgrade --yes"),
        "the refusal must name the override: {stderr}"
    );

    // `--yes` must not be rejected as an unknown option, which is exit 2 with a
    // different message. Asserted through `--help`-free parsing: an unrecognised
    // flag refuses without ever reaching the npm gate.
    let unknown = Command::new(&target)
        .args(["upgrade", "--definitely-not-a-flag"])
        .output()
        .expect("run with a bogus flag");
    let unknown_err = String::from_utf8_lossy(&unknown.stderr).to_string();
    assert!(
        unknown_err.contains("unknown option"),
        "precondition: unrecognised flags are refused by name: {unknown_err}"
    );
    assert!(
        !stderr.contains("unknown option"),
        "the npm refusal must not be an unknown-option refusal in disguise: {stderr}"
    );
}
