//! Whether the local record is actually recording, and for how long it has not.
//!
//! # Why this exists
//!
//! On 2026-08-05 an install stopped recording for six hours. The graph had
//! reached 16,777,528 bytes, 312 past the reader limit applied to it, so every
//! write failed at its verification read. The failure path was a single
//! `eprintln!` into hook stderr, which nobody reads, so the only symptom the
//! operator ever saw was a dashboard whose newest entry was six hours old. They
//! had to ask "where are the current ones?" to find out.
//!
//! The size bug is fixed. This module fixes the worse half: a guardrail that
//! stops recording must say so somewhere a human will look. The record file
//! itself cannot carry the signal, because the thing that failed IS writing it,
//! so the state lives in a small sibling file that the CLI and the dashboard
//! both read.
//!
//! Best-effort throughout. This is health reporting for a telemetry path; it
//! must never be able to change a verdict or fail a command.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// The health record's file name, beside the graph.
const HEALTH_FILE: &str = "record-health.json";

/// The guard event sink's file name, beside the graph.
const SINK_FILE: &str = "guard-events.jsonl";

/// Sibling of the graph file. Never inside it: the write that failed is the one
/// that would have carried the news.
fn health_path(graph: &Path) -> PathBuf {
    graph.with_file_name(HEALTH_FILE)
}

/// Why a file the recorder writes IN PLACE (the guard event sink, this health
/// record) is refused, from the metadata of the name itself, never followed.
/// PURE: the metadata is handed in.
///
/// The directory is shared with the guarded agent's account and this CLI also
/// runs as root, so a writer refuses a link at the name, a file with a second
/// name (a hard link: writing it would write the other name's file), and
/// anything that is not a plain file. Each refusal drops the write, so it has
/// to be reported, or one `ln` by the agent's account silences the sink for
/// good while every surface reads as healthy.
pub(crate) fn refusal(metadata: &std::fs::Metadata) -> Option<&'static str> {
    if innerwarden_safe_io::is_reparse_or_symlink(metadata) {
        Some("is_a_link")
    } else if !innerwarden_safe_io::is_regular_file(metadata) {
        Some("not_a_plain_file")
    } else if !innerwarden_safe_io::is_regular_file_with_one_name(metadata) {
        Some("has_a_second_name")
    } else {
        None
    }
}

/// A [`refusal`] in words, after the file's name: "guard-events.jsonl has a
/// second name (a hard link)".
pub(crate) fn refusal_words(why: &str) -> &'static str {
    match why {
        "is_a_link" => "is a link",
        "has_a_second_name" => "has a second name (a hard link)",
        _ => "is not a plain file",
    }
}

/// The outage a refused or unwritable sink or health record is, if either is.
///
/// A probe, not a marker: the health record may be the very file that is
/// refused, and a sink refusal is noted on every append while the graph write
/// that follows it succeeds and clears any marker. The condition lasts exactly
/// as long as the file stands as it is, so asking is the accurate answer. Its
/// age is the name's own modification time: a refused file is no longer
/// written, so that is when the last write landed (or the link was made).
fn refused_file(graph: &Path) -> Option<Outage> {
    for (name, code) in [(SINK_FILE, "guard_events"), (HEALTH_FILE, "record_health")] {
        let path = graph.with_file_name(name);
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        let why = refusal(&metadata).or_else(|| {
            // A plain file this account cannot append to (one an older release
            // created as root, `0644`) drops every line the same way.
            let mut append = std::fs::OpenOptions::new();
            append.append(true);
            innerwarden_safe_io::harden(&mut append);
            append.open(&path).err().map(|_| "not_writable")
        });
        if let Some(why) = why {
            return Some(Outage {
                code: format!("{code}_{why}"),
                since_unix: metadata
                    .modified()
                    .ok()
                    .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or_else(now_unix, |at| at.as_secs()),
                lost: 0,
            });
        }
    }
    None
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A recording outage in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outage {
    /// Stable, path-free error code, so a health report cannot echo local data.
    pub code: String,
    /// Unix seconds of the FIRST failure in this episode. Kept across repeats
    /// because "failing since 17:43" is the fact that matters, not "failed 4s
    /// ago", which is what a last-failure timestamp would have shown after six
    /// hours of silence.
    pub since_unix: u64,
    /// How many writes have been lost in this episode.
    pub lost: u64,
}

impl Outage {
    pub fn seconds(&self) -> u64 {
        now_unix().saturating_sub(self.since_unix)
    }

    /// What to do about an outage whose cause is a file standing wrong, in
    /// words. `None` for a code that names no such file.
    fn remedy(&self) -> Option<String> {
        let (file, why) = [
            ("guard_events_", SINK_FILE),
            ("record_health_", HEALTH_FILE),
        ]
        .into_iter()
        .find_map(|(prefix, file)| self.code.strip_prefix(prefix).map(|why| (file, why)))?;
        let remedy = match why {
            "is_a_link" => format!("A link stands where {file} should be, and nothing is written through it. Remove the link."),
            "has_a_second_name" => format!("{file} has a second name (a hard link), and nothing is written to it while it does. Remove the other name, or move the file aside so a new one is made."),
            "not_a_plain_file" => format!("{file} is not a plain file. Move it aside so a new one is made."),
            "not_writable" => format!("This account cannot write {file}. Give it to the group of its folder with write for the group, or move it aside so a new one is made."),
            _ => return None,
        };
        Some(remedy)
    }

    /// How long the episode has lasted, in words.
    fn lasted(&self) -> String {
        let secs = self.seconds();
        if secs >= 7200 {
            format!("{} hours", secs / 3600)
        } else if secs >= 120 {
            format!("{} minutes", secs / 60)
        } else {
            format!("{secs} seconds")
        }
    }

    /// One line, safe to print anywhere: no paths, no command text.
    pub fn summary(&self) -> String {
        let ago = self.lasted();
        if self.code == SINK_NOT_WRITTEN {
            return format!(
                "InnerWarden has not added to guard-events.jsonl for {ago} ({} guard event(s) lost, {}). \
                 Screening still ran and the local record keeps the decisions, but InnerWarden's host \
                 install reads that file and has not seen these. Check the disk's free space and the \
                 file's size limit; the count is written into the file once it can be written again.",
                self.lost, self.code
            );
        }
        let lost = if self.lost == 0 {
            "actions lost".to_string()
        } else {
            format!("{} action(s) lost", self.lost)
        };
        match self.remedy() {
            Some(remedy) => format!(
                "InnerWarden has not recorded for {ago} ({lost}, {}). \
                 Screening still ran; only the local record is affected. {remedy}",
                self.code
            ),
            None => format!(
                "InnerWarden has not recorded for {ago} ({lost}, {}). \
                 Screening still ran; only the local record is affected. \
                 Run `innerwarden graph --stats` after the next command to confirm recovery.",
                self.code
            ),
        }
    }

    /// The line that tells an episode ended, as plainly as [`Self::summary`]
    /// told it began. No paths, no command text.
    pub fn recovered_summary(&self) -> String {
        let (what, unit) = if self.code == SINK_NOT_WRITTEN {
            (
                "InnerWarden is adding to guard-events.jsonl again",
                "guard event(s)",
            )
        } else {
            ("InnerWarden is recording again", "action(s)")
        };
        format!(
            "{what}, after {} ({} {unit} lost, {}).",
            self.lasted(),
            self.lost,
            self.code
        )
    }
}

fn parse(bytes: &str) -> Option<Outage> {
    let v: Value = serde_json::from_str(bytes).ok()?;
    Some(Outage {
        code: v.get("code")?.as_str()?.to_string(),
        since_unix: v.get("since_unix")?.as_u64()?,
        lost: v.get("lost").and_then(Value::as_u64).unwrap_or(1),
    })
}

/// The persisted outage for this graph path, if any: beside the graph, else
/// where it is kept when the graph's folder cannot be written
/// ([`fallback_path`]). Never read through a link at the name: the
/// directory is shared with the agent's account, and a root run would read
/// whatever it points at.
pub fn read_at(graph: &Path) -> Option<Outage> {
    read_marker(&health_path(graph))
}

/// The outage to REPORT for this graph path: the graph's own
/// ([`report_graph_at`]), else lines of `guard-events.jsonl` lost
/// ([`note_sink_failure_in`]).
pub fn report_at(graph: &Path) -> Option<Outage> {
    report_graph_at(graph).or_else(|| read_sink_marker(&graph.with_file_name(SINK_HEALTH_FILE)))
}

/// The outage of the graph's own record.
///
/// A marker file cannot cover every fault: the commonest one, a graph directory
/// that is not writable, also stops the marker being written beside it (it is
/// then kept in [`fallback_path`], when the home can be written). So when
/// there is no marker, probe. The graph's own mtime dates the episode, which
/// is the precise fact the operator wanted ("the newest entry is six hours
/// old").
pub fn report_graph_at(graph: &Path) -> Option<Outage> {
    // First: the health record may itself be the refused file, and then what
    // it holds is not to be believed.
    if let Some(refused) = refused_file(graph) {
        return Some(refused);
    }
    if let Some(persisted) = read_at(graph) {
        return Some(persisted);
    }
    if directory_is_writable(graph) {
        return None;
    }
    Some(Outage {
        code: "graph_directory_unwritable".into(),
        since_unix: last_write_unix(graph).unwrap_or_else(now_unix),
        lost: 0,
    })
}

/// Can this process still write beside the graph? Probes rather than inspecting
/// mode bits, which say nothing about ACLs, read-only mounts, or a full disk.
///
/// # A directory that does not exist yet is not a fault
///
/// This used to answer `false` the moment the store directory was absent, and
/// [`report_at`] turns `false` into an outage. On a brand-new install nothing
/// has been recorded, so the store has never been created, so the first
/// `innerwarden graph` a new user ran told them:
///
/// ```text
/// InnerWarden has not recorded for 0 seconds (actions lost, graph_directory_unwritable)
/// ```
///
/// and the dashboard served the same sentence. A fresh box is not a broken one:
/// this is the mistake [`crate::status`] was written to forbid, reproduced in a
/// different module. "Not there yet" is not "cannot be written".
///
/// So walk up to the nearest ancestor that DOES exist and probe that instead: if
/// a file can be created there, the store can be created there too, and there is
/// nothing to report. Asking the question must not create the directory as a
/// side effect, so nothing here calls `create_dir_all`; the recording path
/// creates the store when it has something to record.
fn directory_is_writable(graph: &Path) -> bool {
    let Some(dir) = graph.parent() else {
        return false;
    };
    // A bare filename has an empty parent, which means the current directory
    // rather than the filesystem root.
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let Some(existing) = nearest_existing_ancestor(dir) else {
        return false;
    };
    // Something is there and it is not a directory: a file standing where the
    // store must go can never become the store, and no amount of waiting fixes
    // it. That IS a fault, and it is reported as one.
    if !existing.is_dir() {
        return false;
    }
    probe_writable(existing)
}

/// The closest ancestor of `dir` (including `dir`) that exists on disk.
///
/// `None` only when the walk runs out of components without finding anything,
/// which on a real filesystem means the root itself is unreadable.
fn nearest_existing_ancestor(dir: &Path) -> Option<&Path> {
    let mut candidate = dir;
    loop {
        // `symlink_metadata` rather than `exists()`: a dangling symlink standing
        // where the store must go exists as an entry, and treating it as "not
        // there yet" would have us probe its parent and report health while
        // every write to it fails.
        if std::fs::symlink_metadata(candidate).is_ok() {
            return Some(candidate);
        }
        candidate = match candidate.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => return None,
        };
    }
}

/// Write and remove a file in `dir`. The same permissions creating the store
/// needs, exercised rather than inferred.
///
/// Created EXCLUSIVELY: the name is predictable and the directory may be one
/// another account writes, so a link planted there must make the probe fail,
/// never be followed. `std::fs::write` truncated whatever it pointed at, as
/// whoever ran the CLI, root included.
fn probe_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".iw-write-probe.{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    innerwarden_safe_io::harden(&mut options);
    match options.open(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Write the health record beside the graph without following a link.
///
/// The graph's directory is shared with the guarded agent's uid when Active
/// Defence is installed, and this CLI also runs as root. `std::fs::write`
/// opened the name with `O_CREAT|O_TRUNC` and followed whatever was there, so a
/// link the agent's uid put at `record-health.json` made root truncate and
/// rewrite its target the next time a record failed, and the guarded uid can
/// make a record fail at will by holding the graph lock. A new file takes the
/// mode and group its directory implies, like every other file this product
/// creates there, so whoever records next can update it.
///
/// The open refuses a symbolic link. A HARD link opens fine, so the file is
/// truncated and rewritten only when its link count says this name is its only
/// one; the existing file is opened without `O_TRUNC` so nothing is cut before
/// that is known. Whether the record was written.
fn write_health(path: &Path, body: &[u8]) -> bool {
    use std::io::Write;
    let mut create = std::fs::OpenOptions::new();
    create.write(true).create_new(true);
    innerwarden_safe_io::harden(&mut create);
    let file = match create.open(path) {
        Ok(file) => {
            #[cfg(unix)]
            if let Some(directory) = path.parent() {
                let _ = innerwarden_agent_guard::file_update::apply_new_file_ownership(
                    &file, directory,
                );
            }
            file
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut existing = std::fs::OpenOptions::new();
            existing.write(true);
            innerwarden_safe_io::harden(&mut existing);
            match existing.open(path) {
                Ok(file) => file,
                Err(_) => return false,
            }
        }
        Err(_) => return false,
    };
    if !file
        .metadata()
        .is_ok_and(|metadata| innerwarden_safe_io::is_regular_file_with_one_name(&metadata))
    {
        return false;
    }
    let mut file = file;
    file.set_len(0).is_ok() && file.write_all(body).is_ok()
}

fn last_write_unix(graph: &Path) -> Option<u64> {
    std::fs::metadata(graph)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// The outage in progress for the configured graph path, if any.
///
/// Resolved through [`crate::graph_io::graph_path`] and NOT by calling the model
/// crate a second time. A second resolver is how a path fix ships doing nothing:
/// this call site had its own copy of "env override, else `$HOME`", so it would
/// have gone on reporting the health of a file in the operator home while every
/// write went to the location `/etc/innerwarden/guard.toml` declares.
pub fn current() -> Option<Outage> {
    report_at(&crate::graph_io::graph_path()?)
}

/// One lost write noted, and whether it is the one to tell someone about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Noted {
    pub outage: Outage,
    /// True when this failure opened a new episode and the episode was kept
    /// where the next failure reads it. Repeats within an episode stay quiet
    /// or a broken install would send a notification per command; and an
    /// episode kept nowhere cannot tell its next failure from its first, so
    /// it is not told either (stderr says each failure, and `status` and
    /// `innerwarden graph --stats` probe the folder).
    pub first_of_episode: bool,
}

/// Record one lost write, preserving the episode's start time.
///
/// Returns the resulting state and whether this failure opened the episode,
/// and so is worth an out-of-band notification.
pub fn note_failure_at(graph: &Path, code: &str) -> Noted {
    note_failures_at(graph, code, 1)
}

/// [`note_failure_at`] for `lost` writes at once (at least one): a writer
/// that counts losses as they happen and notes them in batches, so a flood
/// of them costs one write of the health file, not one each.
pub fn note_failures_at(graph: &Path, code: &str, lost: u64) -> Noted {
    note_in(&health_path(graph), code, lost)
}

/// Clear the outage after a write succeeds. Returns the episode that just
/// ended, so recovery can be reported as plainly as the failure was.
pub fn note_success_at(graph: &Path) -> Option<Outage> {
    clear_in(&health_path(graph))
}

/// The guard event sink's own outage record, in the sink's folder: lines of
/// `guard-events.jsonl` that could not be appended. Apart from
/// [`HEALTH_FILE`], which every graph write that works clears: the two fail
/// apart (a size limit or a full disk can refuse an append and leave the
/// graph's rewrite room), and one must not end the other's episode.
const SINK_HEALTH_FILE: &str = "guard-events-health.json";

/// The code of a sink outage: lines of `guard-events.jsonl` not written.
pub(crate) const SINK_NOT_WRITTEN: &str = "guard_events_not_written";

/// One line of `guard-events.jsonl` lost (an append that failed or was
/// refused), noted in the sink's own outage record for the folder `dir`.
pub fn note_sink_failure_in(dir: &Path) -> Noted {
    note_in(&dir.join(SINK_HEALTH_FILE), SINK_NOT_WRITTEN, 1)
}

/// The sink's outage for the folder `dir`, if one is open.
pub fn sink_outage_in(dir: &Path) -> Option<Outage> {
    read_sink_marker(&dir.join(SINK_HEALTH_FILE))
}

/// The sink's outage record, only as this module writes it. The folder is
/// one the guarded agent's account may write, and what is read here goes
/// into `guard-events.jsonl` itself: a record it planted with words of its
/// own is not read.
fn read_sink_marker(beside: &Path) -> Option<Outage> {
    read_marker(beside).filter(|outage| outage.code == SINK_NOT_WRITTEN)
}

/// Clear the sink's outage after an append works. Returns the episode that
/// ended, whose count the caller writes into the sink.
pub fn note_sink_success_in(dir: &Path) -> Option<Outage> {
    clear_in(&dir.join(SINK_HEALTH_FILE)).filter(|outage| outage.code == SINK_NOT_WRITTEN)
}

/// The folder an outage record is kept in when its own folder cannot be
/// written: `.local/state/innerwarden` in the account's own home
/// ([`crate::graph_io::config_home`]), never a folder the caller's
/// environment names. Without it, a record folder that cannot be written
/// could not keep the episode either, and no outage of that kind was ever
/// told to anyone.
const STATE_DIR: &str = ".local/state/innerwarden";

/// [`STATE_DIR`] under a scratch home of this test process's own.
#[cfg(test)]
fn fallback_dir() -> Option<PathBuf> {
    Some(
        std::env::temp_dir()
            .join(format!("iw-record-health-{}", std::process::id()))
            .join(STATE_DIR),
    )
}

/// [`STATE_DIR`] in the account's home. A debug build run by a test with no
/// test account home keeps it under the `HOME` the test gave it, so a test
/// that breaks a record folder never writes the real home's.
#[cfg(not(test))]
fn fallback_dir() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    if std::env::var_os(crate::graph_io::TEST_ACCOUNT_HOME_ENV).is_none() {
        if let Some(home) = std::env::var_os("HOME") {
            return Some(PathBuf::from(home).join(STATE_DIR));
        }
    }
    crate::graph_io::config_home().map(|home| home.join(STATE_DIR))
}

/// Where the record `beside` is kept when its folder cannot be written: one
/// file per folder and kind, named by a digest of the folder, so two records
/// never share an episode.
fn fallback_path(beside: &Path) -> Option<PathBuf> {
    use sha2::{Digest, Sha256};
    let name = beside.file_name()?.to_str()?;
    let stem = name.strip_suffix(".json").unwrap_or(name);
    let folder = beside.parent().unwrap_or_else(|| Path::new(""));
    let digest = Sha256::digest(folder.to_string_lossy().as_bytes());
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    Some(fallback_dir()?.join(format!("{stem}-{hex}.json")))
}

/// The places an outage record is kept, in the order they are tried.
fn places(beside: &Path) -> impl Iterator<Item = PathBuf> {
    std::iter::once(beside.to_path_buf()).chain(fallback_path(beside))
}

/// The outage a record holds, never read through a link at the name: the
/// directory is shared with the agent's account, and a root run would read
/// whatever it points at.
fn read_outage(path: &Path) -> Option<Outage> {
    use std::io::Read;
    let mut body = String::new();
    innerwarden_safe_io::open_no_follow(path)
        .ok()?
        .take(64 * 1024)
        .read_to_string(&mut body)
        .ok()?;
    parse(&body)
}

/// The outage the record `beside` holds, or its fallback.
fn read_marker(beside: &Path) -> Option<Outage> {
    places(beside).find_map(|place| read_outage(&place))
}

/// Note `lost` failures of `code` in the first place that takes the write:
/// beside the record, else its fallback ([`fallback_path`]). The episode
/// is read from the place written, so a stale record left in a folder that
/// can no longer be written never makes every failure the first.
fn note_in(beside: &Path, code: &str, lost: u64) -> Noted {
    let lost = lost.max(1);
    for place in places(beside) {
        let previous = read_outage(&place);
        // A new fault opens a new episode, so it may notify again. Only a
        // REPEAT of the same fault must stay quiet, or a broken install sends
        // one message per command.
        let first_of_episode = previous.as_ref().is_none_or(|p| p.code != code);
        let outage = match previous {
            Some(p) if p.code == code => Outage {
                lost: p.lost.saturating_add(lost),
                ..p
            },
            // A DIFFERENT failure code restarts the episode: it is a new
            // fault, and carrying the old start time forward would misreport
            // how long this one has been happening.
            _ => Outage {
                code: code.to_string(),
                since_unix: now_unix(),
                lost,
            },
        };
        let body = json!({
            "code": outage.code,
            "since_unix": outage.since_unix,
            "lost": outage.lost,
            "first_of_episode": first_of_episode,
        });
        if place != beside {
            make_state_dir(&place);
        }
        if write_health(&place, body.to_string().as_bytes()) {
            return Noted {
                outage,
                first_of_episode,
            };
        }
    }
    Noted {
        outage: Outage {
            code: code.to_string(),
            since_unix: now_unix(),
            lost,
        },
        first_of_episode: false,
    }
}

/// The fallback's folder, owner only.
fn make_state_dir(place: &Path) {
    let Some(dir) = place.parent() else {
        return;
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    let _ = builder.create(dir);
}

/// Clear every place the record `beside` is kept. The episode that ended
/// is returned only when its record is gone, so one recovery is told once.
fn clear_in(beside: &Path) -> Option<Outage> {
    let mut ended = None;
    for place in places(beside) {
        let Some(outage) = read_outage(&place) else {
            continue;
        };
        if forget(&place) {
            ended.get_or_insert(outage);
        }
    }
    ended
}

/// Remove a record, or empty it where its folder no longer lets it be
/// removed. Whether it no longer holds an outage.
fn forget(path: &Path) -> bool {
    match std::fs::remove_file(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => write_health(path, b""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph_in(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("graph.json")
    }

    /// REGRESSION ANCHOR. Six hours of lost recording were reported only on
    /// stderr. A failure must leave state a human-facing surface can read.
    ///
    /// FAILS ON REVERT: drop the write in `note_failure_at` and nothing persists.
    #[test]
    fn a_failed_write_leaves_a_readable_outage() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        assert!(read_at(&g).is_none(), "healthy install reports nothing");

        let noted = note_failure_at(&g, "write_failed");
        assert_eq!(noted.outage.lost, 1);
        assert!(noted.first_of_episode);

        let read_back = read_at(&g).expect("outage is durable");
        assert_eq!(read_back.code, "write_failed");
        assert_eq!(read_back.lost, 1);
    }

    /// The start time is what makes the report useful. Overwriting it on every
    /// repeat would have reported "failing for 4 seconds" after six hours.
    #[test]
    fn repeats_accumulate_losses_and_keep_the_first_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        let first = note_failure_at(&g, "write_failed").outage;
        let third = {
            note_failure_at(&g, "write_failed");
            note_failure_at(&g, "write_failed")
        };
        assert_eq!(third.outage.lost, 3);
        assert_eq!(
            third.outage.since_unix, first.since_unix,
            "the episode start must not move"
        );
        assert!(
            !third.first_of_episode,
            "only the first failure may notify, or a broken install spams"
        );
    }

    /// A new fault is a new episode; inheriting the old start time would
    /// misreport its duration.
    #[test]
    fn a_different_failure_starts_a_new_episode() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        note_failure_at(&g, "write_failed");
        note_failure_at(&g, "write_failed");
        let other = note_failure_at(&g, "lock_timed_out");
        assert_eq!(other.outage.code, "lock_timed_out");
        assert_eq!(other.outage.lost, 1, "losses belong to their own episode");
        assert!(other.first_of_episode, "a new fault may notify again");
    }

    #[test]
    fn a_successful_write_clears_the_outage_and_reports_what_ended() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        note_failure_at(&g, "write_failed");
        note_failure_at(&g, "write_failed");
        let ended = note_success_at(&g).expect("the ended episode is returned");
        assert_eq!(ended.lost, 2);
        assert!(read_at(&g).is_none(), "recovery must clear the state");
        assert!(
            note_success_at(&g).is_none(),
            "a healthy install reports no recovery"
        );
    }

    /// The summary is printed to terminals and may reach a notification
    /// transport, so it must carry no local detail.
    #[test]
    fn the_summary_names_the_impact_without_leaking_anything() {
        let outage = Outage {
            code: "write_failed".into(),
            since_unix: now_unix().saturating_sub(6 * 3600),
            lost: 1414,
        };
        let s = outage.summary();
        assert!(s.contains("6 hours"), "duration must be legible: {s}");
        assert!(s.contains("1414"), "the loss count must be there: {s}");
        assert!(
            s.contains("Screening still ran"),
            "must not read as 'you were unprotected': {s}"
        );
        assert!(!s.contains('/'), "no paths in a health line: {s}");
    }

    /// The commonest recording fault, an unwritable graph directory, also stops
    /// the marker being written. A file-only signal would be silent for exactly
    /// the case it exists to catch, so the report probes as well.
    ///
    /// FAILS ON REVERT: point `report_at` back at `read_at` and this reports a
    /// healthy install while nothing is being recorded.
    #[cfg(unix)]
    #[test]
    fn an_unwritable_directory_is_reported_even_though_no_marker_can_be_written() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir(&store).unwrap();
        let g = store.join("graph.json");
        std::fs::write(&g, "{}").unwrap();
        assert!(report_at(&g).is_none(), "writable means healthy");

        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o500)).unwrap();
        let outage = report_at(&g).expect("an unwritable store is an outage");
        assert_eq!(outage.code, "graph_directory_unwritable");
        assert!(
            outage.since_unix > 0,
            "the last successful write dates the episode"
        );
        assert!(outage.summary().contains("has not recorded"));

        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(report_at(&g).is_none(), "recovery must clear the report");
    }

    /// A persisted marker wins over the probe: it carries the real error code
    /// and the real loss count, which a probe cannot know.
    #[test]
    fn a_persisted_marker_is_preferred_over_the_probe() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        note_failure_at(&g, "graph_write_failed");
        let reported = report_at(&g).expect("marker is reported");
        assert_eq!(reported.code, "graph_write_failed");
        assert_eq!(reported.lost, 1);
    }

    /// REGRESSION ANCHOR. A brand-new install reported itself broken.
    ///
    /// Nothing has been recorded yet, so the store directory has never been
    /// created, so `directory_is_writable` answered false and `report_at` turned
    /// that into "InnerWarden has not recorded for 0 seconds (actions lost,
    /// graph_directory_unwritable)" on the first `innerwarden graph` and on the
    /// dashboard. A fresh box is not a broken one.
    ///
    /// FAILS ON REVERT: put back `if !dir.exists() { return false; }` and this
    /// reports an outage on a directory nothing is wrong with.
    #[test]
    fn a_store_directory_that_does_not_exist_yet_is_not_an_outage() {
        let dir = tempfile::tempdir().unwrap();
        // Two levels deep and absent, exactly as a fresh install finds it before
        // its first recorded action.
        let store = dir.path().join("innerwarden").join("store");
        let g = store.join("graph.json");
        assert!(!store.exists(), "precondition: the store is not there yet");

        assert!(
            report_at(&g).is_none(),
            "a fresh install has recorded nothing; that is not an outage"
        );
        assert!(
            !store.exists(),
            "asking whether the store could be written must not create it"
        );
    }

    /// The other half of the same question: "could be created" is established by
    /// probing the nearest existing ancestor, so an absent store under an
    /// ancestor that CANNOT be written is still reported.
    ///
    /// Without this the fix would be indistinguishable from deleting the check.
    ///
    /// FAILS ON REVERT: return `true` for any absent directory instead of
    /// probing, and a store that can never be created reads as healthy.
    #[cfg(unix)]
    #[test]
    fn an_absent_store_under_an_unwritable_parent_is_still_an_outage() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("locked");
        std::fs::create_dir(&parent).unwrap();
        let g = parent.join("store").join("graph.json");
        assert!(
            report_at(&g).is_none(),
            "precondition: creatable while the parent is writable"
        );

        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).unwrap();
        let outage = report_at(&g).expect("a store that cannot be created is an outage");
        assert_eq!(outage.code, "graph_directory_unwritable");

        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(report_at(&g).is_none(), "recovery must clear the report");
    }

    /// A plain file standing where the store must go can never become the store.
    /// Unlike an absent directory, waiting does not fix it, so it is a fault.
    #[test]
    fn a_file_standing_where_the_store_belongs_is_an_outage() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::write(&store, b"not a directory").unwrap();
        let g = store.join("graph.json");

        let outage = report_at(&g).expect("a file in the way is a real fault");
        assert_eq!(outage.code, "graph_directory_unwritable");
    }

    #[test]
    fn corrupt_health_state_reads_as_healthy_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        std::fs::write(health_path(&g), "{not json").unwrap();
        assert!(read_at(&g).is_none());
        assert!(note_success_at(&g).is_none());
    }

    /// The health record sits in a directory the guarded agent's uid writes,
    /// and this CLI also runs as root. A link planted at its name must never
    /// be written through: the guarded uid can make a record fail at will (it
    /// only has to hold the graph lock), and `std::fs::write` then truncated
    /// and rewrote whatever the link named, as root.
    ///
    /// FAILS ON REVERT: write it with `std::fs::write` again and the victim is
    /// overwritten.
    #[cfg(unix)]
    #[test]
    fn a_link_at_the_health_record_is_never_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let victim = elsewhere.path().join("sudoers");
        std::fs::write(&victim, "root ALL=(ALL) ALL\n").unwrap();
        let g = graph_in(&dir);
        std::os::unix::fs::symlink(&victim, health_path(&g)).unwrap();

        let _ = note_failure_at(&g, "graph_lock_timeout");

        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "root ALL=(ALL) ALL\n",
            "the file the link named was written"
        );
        assert!(std::fs::symlink_metadata(health_path(&g))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// A HARD link at the health record's name is not refused by the open, so
    /// the link count decides: a file with a second name is never truncated or
    /// rewritten, and an ordinary record still is.
    ///
    /// FAILS ON REVERT: check the handle with `is_regular_file` again and the
    /// victim is truncated and rewritten.
    #[cfg(unix)]
    #[test]
    fn a_hard_link_at_the_health_record_is_never_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let victim = elsewhere.path().join("sudoers");
        std::fs::write(&victim, "root ALL=(ALL) ALL\n").unwrap();
        let g = graph_in(&dir);
        std::fs::hard_link(&victim, health_path(&g)).unwrap();

        let _ = note_failure_at(&g, "graph_lock_timeout");

        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "root ALL=(ALL) ALL\n",
            "the file behind the second name was written"
        );

        // Not a refusal of every existing record: once the second name is gone
        // the same file is this record's own again and is updated.
        std::fs::remove_file(&victim).unwrap();
        let _ = note_failure_at(&g, "graph_lock_timeout");
        assert_eq!(
            read_at(&g).expect("the record's own file is updated").code,
            "graph_lock_timeout"
        );
    }

    /// Same rule for the write probe, whose name is predictable.
    ///
    /// FAILS ON REVERT: probe with `std::fs::write` and the victim is truncated.
    #[cfg(unix)]
    #[test]
    fn a_link_at_the_write_probe_is_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let victim = elsewhere.path().join("shadow");
        std::fs::write(&victim, "root:x:0:0\n").unwrap();
        let probe = dir
            .path()
            .join(format!(".iw-write-probe.{}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &probe).unwrap();

        let _ = probe_writable(dir.path());

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "root:x:0:0\n");
    }

    /// A health record the first writer created in a shared directory is one
    /// the next writer, another member of the group, can update.
    #[cfg(unix)]
    #[test]
    fn a_new_health_record_in_a_shared_directory_takes_its_group_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o2770)).unwrap();
        let g = graph_in(&dir);
        let _ = note_failure_at(&g, "graph_write_failed");
        assert_eq!(
            std::fs::metadata(health_path(&g))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o660
        );
        assert_eq!(read_at(&g).expect("readable").code, "graph_write_failed");
    }

    /// A refused sink drops every guard event, and the drop used to be
    /// silent: one `ln` by the guarded agent's account (which can write the
    /// shared sink, so Linux's `protected_hardlinks` allows it) and every block
    /// and attempt was discarded while the dashboard read as a quiet, healthy
    /// host. Each way the sink can stand wrong is now an outage, with the fix.
    ///
    /// FAILS ON REVERT: drop the `refused_file` probe from `report_at` and a
    /// hard-linked sink reports nothing.
    #[cfg(unix)]
    #[test]
    fn a_refused_guard_event_sink_is_an_outage() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        let sink = dir.path().join(SINK_FILE);
        std::fs::write(&sink, "{}\n").unwrap();
        assert_eq!(report_at(&g), None, "a plain sink is healthy");

        let second = elsewhere.path().join("k");
        std::fs::hard_link(&sink, &second).unwrap();
        let outage = report_at(&g).expect("a sink with a second name is an outage");
        assert_eq!(outage.code, "guard_events_has_a_second_name");
        assert!(
            outage.summary().contains("Remove the other name"),
            "{}",
            outage.summary()
        );
        std::fs::remove_file(&second).unwrap();
        assert_eq!(
            report_at(&g),
            None,
            "and it ends when the other name is gone"
        );

        std::fs::remove_file(&sink).unwrap();
        std::os::unix::fs::symlink(elsewhere.path().join("victim"), &sink).unwrap();
        assert_eq!(report_at(&g).unwrap().code, "guard_events_is_a_link");
        std::fs::remove_file(&sink).unwrap();
        std::fs::create_dir(&sink).unwrap();
        assert_eq!(report_at(&g).unwrap().code, "guard_events_not_a_plain_file");
    }

    /// A sink this account cannot append to (an older release created it as
    /// root, `0644`) drops every line the same way.
    ///
    /// FAILS ON REVERT: drop the append probe and it reads as healthy.
    #[cfg(unix)]
    #[test]
    fn a_sink_this_account_cannot_write_is_an_outage() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: reads the process credentials, cannot fail.
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "running as root, which writes any file, so the case cannot be constructed; \
             run the suite as an ordinary account"
        );
        let dir = tempfile::tempdir().unwrap();
        let sink = dir.path().join(SINK_FILE);
        std::fs::write(&sink, "").unwrap();
        std::fs::set_permissions(&sink, std::fs::Permissions::from_mode(0o444)).unwrap();
        let outage = report_at(&graph_in(&dir)).expect("an unwritable sink is an outage");
        assert_eq!(outage.code, "guard_events_not_writable");
        assert!(outage.summary().contains("cannot write guard-events.jsonl"));
    }

    /// The health record is the file that would carry the news, so a link at
    /// its name reports itself, and what it points at is never read: a root
    /// run would otherwise read a file the agent's account chose.
    ///
    /// FAILS ON REVERT: read the marker before the probe, through the link,
    /// and the planted outage is reported instead.
    #[cfg(unix)]
    #[test]
    fn a_refused_health_record_reports_itself_and_is_never_read_through() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        let planted = elsewhere.path().join("planted.json");
        std::fs::write(&planted, r#"{"code":"planted","since_unix":1}"#).unwrap();
        std::os::unix::fs::symlink(&planted, dir.path().join(HEALTH_FILE)).unwrap();
        assert_eq!(read_at(&g), None, "never read through a link");
        assert_eq!(report_at(&g).unwrap().code, "record_health_is_a_link");

        std::fs::remove_file(dir.path().join(HEALTH_FILE)).unwrap();
        note_failure_at(&g, "write_failed");
        std::fs::hard_link(dir.path().join(HEALTH_FILE), elsewhere.path().join("k")).unwrap();
        assert_eq!(
            report_at(&g).unwrap().code,
            "record_health_has_a_second_name"
        );
    }

    /// REGRESSION ANCHOR (record folder that cannot be written). The
    /// episode could not be kept beside the graph, so every failure read as
    /// "not the first" and the outage was never told to anyone. It is kept
    /// in the account's own state folder instead: told once, counted, read
    /// back by `report_at`, and ended once the folder takes writes again.
    ///
    /// FAILS ON REVERT: take the fallback out of `places` and the first
    /// failure is kept nowhere, so it is never the one told.
    #[cfg(unix)]
    #[test]
    fn a_folder_that_cannot_be_written_keeps_its_episode_elsewhere_and_tells_it_once() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir(&store).unwrap();
        let g = store.join("graph.json");
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o500)).unwrap();
        if probe_writable(&store) {
            // Root writes any folder: nothing to prove here.
            std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let first = note_failure_at(&g, "graph_lock_unavailable");
        let second = note_failure_at(&g, "graph_lock_unavailable");
        assert!(first.first_of_episode, "the first failure is told");
        assert!(!second.first_of_episode, "a repeat is not");
        assert!(!health_path(&g).exists());
        let reported = report_at(&g).expect("the kept episode is reported");
        assert_eq!(reported.code, "graph_lock_unavailable");
        assert_eq!(reported.lost, 2);

        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ended = note_success_at(&g).expect("the episode ends");
        assert_eq!(ended.lost, 2);
        assert!(ended.recovered_summary().contains("recording again"));
        assert!(read_at(&g).is_none(), "both places are cleared");
        assert!(note_success_at(&g).is_none(), "one end, told once");
    }

    /// A record of an earlier fault left in a folder that no longer takes
    /// writes is read, but the episode is kept where it is written, so a
    /// repeat of the new fault is not told again.
    ///
    /// FAILS ON REVERT: read the episode beside the graph whatever place took
    /// the write, and every failure differs from the stale code and is told.
    #[cfg(unix)]
    #[test]
    fn a_stale_record_beside_never_makes_every_failure_the_first() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir(&store).unwrap();
        let g = store.join("graph.json");
        note_failure_at(&g, "graph_write_failed");
        std::fs::set_permissions(health_path(&g), std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o500)).unwrap();
        if probe_writable(&store) {
            std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        assert!(note_failure_at(&g, "graph_lock_unavailable").first_of_episode);
        assert!(!note_failure_at(&g, "graph_lock_unavailable").first_of_episode);
        assert!(!note_failure_at(&g, "graph_lock_unavailable").first_of_episode);
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(health_path(&g), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(note_success_at(&g).is_some());
        assert!(read_at(&g).is_none());
    }

    /// Lines of `guard-events.jsonl` lost are counted in a record of their
    /// own: a graph write that works does not end them, they are reported
    /// when the graph has nothing to report, and their end is returned once.
    ///
    /// FAILS ON REVERT: keep the sink's losses in the graph's record and the
    /// graph write that works clears them uncounted.
    #[test]
    fn lost_sink_lines_are_an_episode_of_their_own() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        let first = note_sink_failure_in(dir.path());
        assert!(first.first_of_episode);
        let again = note_sink_failure_in(dir.path());
        assert!(!again.first_of_episode);
        assert_eq!(again.outage.lost, 2);
        assert!(note_success_at(&g).is_none(), "the graph's record is apart");
        let reported = report_at(&g).expect("the sink's loss is reported");
        assert_eq!(reported.code, SINK_NOT_WRITTEN);
        assert_eq!(reported.lost, 2);
        let said = reported.summary();
        assert!(
            said.contains("guard-events.jsonl") && said.contains("2 guard event(s) lost"),
            "{said}"
        );
        assert!(!said.contains('/'), "no paths in a health line: {said}");
        let ended = note_sink_success_in(dir.path()).expect("the episode ends");
        assert_eq!(ended.lost, 2);
        assert!(ended
            .recovered_summary()
            .contains("adding to guard-events.jsonl again"));
        assert!(sink_outage_in(dir.path()).is_none());
        assert!(report_at(&g).is_none());

        // A record planted with words of its own is never read back.
        std::fs::write(
            dir.path().join(SINK_HEALTH_FILE),
            r#"{"code":"see http://x.example","since_unix":1,"lost":9}"#,
        )
        .unwrap();
        assert!(sink_outage_in(dir.path()).is_none());
        assert!(report_at(&g).is_none());
        assert!(note_sink_success_in(dir.path()).is_none());
    }
}
