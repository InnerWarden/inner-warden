//! The release pipeline's promises, checked against the pipeline.
//!
//! A release cannot be exercised from a test: cutting one publishes binaries to
//! real users. So the next best thing is to read the workflow and assert the
//! properties a customer depends on, which is enough to catch the failure this
//! file exists for.
//!
//! That failure, found in the 2026-08-22 technical due-diligence audit (S3): the
//! rolling `iw-guard` release body advertised `IW_GUARD_TAG=guard-vX.Y.Z`, and
//! the live installer really does honour that variable
//! (`RELEASE_TAG="${IW_GUARD_TAG:-iw-guard}"`), but no `guard-vX.Y.Z` release
//! was ever created. `gh release view guard-v1.3.7` returned "release not
//! found". A documented capability did nothing; reproducible installs were
//! impossible; and because the rolling tag's binaries are replaced on every cut,
//! undoing a bad release meant re-running the whole pipeline from an older
//! commit, since the previous binaries no longer existed anywhere.

const WORKFLOW: &str = include_str!("../../../.github/workflows/release-guard.yml");

/// Every cut must publish an immutable per-version tag.
///
/// FAILS ON REVERT: delete the versioned publish step and the pin the release
/// body advertises has nothing to resolve to again.
#[test]
fn a_release_publishes_an_immutable_versioned_tag() {
    assert!(
        WORKFLOW.contains("tag_name: guard-v${{ steps.version.outputs.guard_version }}"),
        "no step publishes a guard-vX.Y.Z release, so IW_GUARD_TAG has nothing \
         to pin to and there is no artefact to roll back to"
    );
}

/// And the rolling tag must survive, because that is what the install command
/// on the website resolves to.
#[test]
fn the_rolling_tag_is_still_published() {
    assert!(
        WORKFLOW.contains("tag_name: iw-guard"),
        "the documented one-line install pulls from the rolling tag; removing it \
         breaks every default install"
    );
}

/// Both releases must carry the SAME bytes.
///
/// A versioned release built or signed separately would be a different artefact
/// wearing the same version number, which is worse than not having one: a
/// rollback would restore something nobody tested.
#[test]
fn both_releases_ship_the_same_signed_artefacts() {
    let uploads: Vec<&str> = WORKFLOW
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("files:"))
        .collect();

    assert!(
        uploads.len() >= 2,
        "expected an upload for the versioned release and one for the rolling \
         release, found {}: {uploads:?}",
        uploads.len()
    );
    assert!(
        uploads.iter().all(|f| *f == "files: dist/*"),
        "every release must upload the same staged, signed directory: {uploads:?}"
    );
}

/// A published version is never overwritten.
///
/// This is the property that makes rollback real. Without it, re-running the
/// pipeline on an old tag would replace the bytes a customer pinned to, and the
/// thing they pinned to in order to be safe would move under them.
///
/// FAILS ON REVERT: remove the guard step and a re-run silently republishes.
#[test]
fn a_published_version_cannot_be_republished() {
    assert!(
        WORKFLOW.contains("Refuse to overwrite a published version"),
        "nothing stops a second publish onto an existing guard-vX.Y.Z tag"
    );

    let guard_at = WORKFLOW
        .find("Refuse to overwrite a published version")
        .expect("guard step present");
    let publish_at = WORKFLOW
        .find("Publish immutable guard-vX.Y.Z release")
        .expect("versioned publish step present");
    assert!(
        guard_at < publish_at,
        "the overwrite check has to run BEFORE the publish, or it is checking a \
         tag the step above it just created"
    );
}

/// The version in the tag comes from the binary, not from the tag or a manifest.
///
/// The workflow already refuses a tag that disagrees with the built binary. The
/// versioned release has to use that same measured value, or `guard-v1.3.7`
/// could end up containing a binary that reports something else, which is
/// exactly the class of defect the existing check was written for.
#[test]
fn the_published_version_is_measured_from_the_binary() {
    assert!(
        WORKFLOW.contains("ver=\"$(./dist/innerwarden-linux-x86_64 --version"),
        "the version must be read from the built binary"
    );
    assert!(
        WORKFLOW.contains("echo \"guard_version=$ver\" >> \"$GITHUB_OUTPUT\""),
        "and the versioned release must reuse that measured value rather than \
         deriving its own"
    );
}

/// A published cut must be traceable to the commit it was built from.
///
/// 1.5.2 shipped binaries, npm and deb/rpm from d98eabd by `workflow_dispatch`
/// and the `guard-v1.5.2` source tag was never pushed; nothing in the run
/// noticed. The publish job now checks this repository for the tag at the
/// built commit and ends red without it.
///
/// FAILS ON REVERT: remove the step and nothing compares the source tag with
/// the built commit again.
#[test]
fn a_release_checks_its_source_tag_names_the_built_commit() {
    let step = WORKFLOW
        .split("- name: ")
        .find(|s| s.starts_with("The source carries guard-vX.Y.Z at the commit that was built"))
        .expect("no step checks the source tag of the published cut");
    for needed in [
        "git ls-remote",
        "refs/tags/${tag}",
        "refs/tags/${tag}^{}",
        "github.sha",
        "exit 1",
    ] {
        assert!(step.contains(needed), "the tag check lost `{needed}`:\n{step}");
    }
    let publish = WORKFLOW
        .find("- name: Publish rolling iw-guard release")
        .expect("rolling publish");
    let check = WORKFLOW
        .find("- name: The source carries guard-vX.Y.Z")
        .expect("tag check");
    assert!(check > publish, "the check runs once the cut is published");
}
