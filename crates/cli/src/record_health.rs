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
        in_words(self.seconds())
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
}

/// A span of seconds, in words.
fn in_words(secs: u64) -> String {
    if secs >= 7200 {
        format!("{} hours", secs / 3600)
    } else if secs >= 120 {
        format!("{} minutes", secs / 60)
    } else {
        format!("{secs} seconds")
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
/// ([`fallback_path`]), on the terms of [`open_at`]. Never read through a
/// link at the name: the directory is shared with the agent's account, and
/// a root run would read whatever it points at.
pub fn read_at(graph: &Path) -> Option<Outage> {
    open_at(&health_path(graph), graph, None)
}

/// The outage to REPORT for this graph path: the graph's own
/// ([`report_graph_at`]), else lines of `guard-events.jsonl` lost
/// ([`note_sink_failure_in`]).
pub fn report_at(graph: &Path) -> Option<Outage> {
    report_graph_at(graph).or_else(|| {
        open_at(
            &graph.with_file_name(SINK_HEALTH_FILE),
            &graph.with_file_name(SINK_FILE),
            Some(SINK_NOT_WRITTEN),
        )
    })
}

/// The outage in progress that the record `beside` holds about `covered`
/// (the graph, or `guard-events.jsonl`): an episode that is closing (a
/// write has worked since its last failure) is not one.
///
/// What is kept OUTSIDE the folder ([`fallback_path`]) never says there is
/// an outage on its own: that folder is not one InnerWarden guards, and a
/// record planted there in a healthy home painted an outage that never
/// happened. It is read only when a write beside `covered` fails right now
/// (the probe of [`directory_is_writable`]), and only when the kernel says
/// it was written after the folder and `covered` last changed
/// ([`kept_since`]). Only an episode of the code `only` is read, when one is
/// named.
fn open_at(beside: &Path, covered: &Path, only: Option<&str>) -> Option<Outage> {
    let open = |held: Held| {
        held.record
            .episode
            .filter(|e| e.ended_unix.is_none() && only.is_none_or(|code| e.outage.code == code))
            .map(|e| e.outage)
    };
    if let Some(here) = read_held(beside) {
        if here.record.episode.is_some() {
            return open(here);
        }
    }
    let outside = read_held(&fallback_path(beside)?)?;
    if directory_is_writable(covered) || !kept_since(outside.changed, &Before::of(covered)) {
        return None;
    }
    open(outside)
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

/// How long recording has to keep working after an outage before its end
/// is told: ten minutes. A failure of the same fault inside that window is
/// the same outage come back, reopened without a new alert; told at once,
/// a fault that came and went (a folder whose mode flipped, a disk filled
/// and emptied by another writer) was two alerts a turn, twenty in a
/// second. The end is told by the first write that works once the window
/// has passed with no failure.
pub const QUIET_SECS: u64 = 600;

/// At most this many outages of one fault are told in [`CAP_PERIOD_SECS`].
/// The ones held back are counted, and the next alert about that fault
/// says how many there were.
const CAP_TOLD: u64 = 3;

/// The period [`CAP_TOLD`] counts in: an hour.
const CAP_PERIOD_SECS: u64 = 3600;

/// Shortens [`QUIET_SECS`], in seconds, in a DEBUG build only: the test
/// suites run the binary and cannot wait ten minutes for an end. A release
/// build does not read it.
#[cfg(debug_assertions)]
pub const TEST_QUIET_ENV: &str = "IW_TEST_RECORD_QUIET_SECS";

fn quiet_secs() -> u64 {
    #[cfg(debug_assertions)]
    if let Some(secs) = std::env::var(TEST_QUIET_ENV)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
    {
        return secs.min(QUIET_SECS);
    }
    QUIET_SECS
}

/// The time a change of state is decided at, and the quiet window.
#[derive(Debug, Clone, Copy)]
struct Clock {
    now: u64,
    quiet: u64,
}

impl Clock {
    fn real() -> Clock {
        Clock {
            now: now_unix(),
            quiet: quiet_secs(),
        }
    }
}

/// When the record's folder and the file it covers (the graph, or
/// `guard-events.jsonl`) last changed, as the kernel keeps it, read before
/// a call writes anything. What is kept outside the folder
/// ([`fallback_path`]) is checked against it ([`kept_since`],
/// [`unanswered`]): that folder is not one InnerWarden guards, so the
/// presence of a record there decides nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Before {
    folder: Option<i128>,
    covered: Option<i128>,
}

impl Before {
    /// How `covered` and its folder stand now.
    pub fn of(covered: &Path) -> Before {
        let folder = match covered.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir,
            _ => Path::new("."),
        };
        Before {
            folder: changed_at(folder),
            covered: changed_at(covered),
        }
    }
}

fn changed_at(path: &Path) -> Option<i128> {
    std::fs::symlink_metadata(path)
        .ok()
        .as_ref()
        .and_then(changed_ns)
}

/// When a file last changed, in nanoseconds: the inode's change time,
/// which the kernel sets at every write, rename, link and mode change and
/// which no call lets a program choose (`touch` sets the modification
/// time, never this one).
fn changed_ns(metadata: &std::fs::Metadata) -> Option<i128> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec()))
    }
    #[cfg(not(unix))]
    {
        let since = metadata
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        i128::try_from(since.as_nanos()).ok()
    }
}

/// Whether a record kept outside the folder, read at a failure, may
/// continue an episode (and so keep the failure from being told): only
/// when it was written after the folder and the file it covers last
/// changed. A record planted there with the code of a fault that had not
/// happened yet held back the alert of that fault when it came (a folder
/// made `0500` after it was planted: 3 failures, 0 alerts). The change of
/// mode is newer than the planted record, so it is not believed, and the
/// failure is told; what this module keeps there itself is written after
/// that change.
fn kept_since(changed: Option<i128>, before: &Before) -> bool {
    changed.is_some_and(|at| {
        before.folder.is_none_or(|folder| at > folder)
            && before.covered.is_none_or(|covered| at > covered)
    })
}

/// Whether a record kept outside the folder, read at a write that works,
/// is an episode that write ends: only when no write had worked since it
/// was written.
fn unanswered(changed: Option<i128>, before: &Before) -> bool {
    changed.is_some_and(|at| before.covered.is_none_or(|covered| at > covered))
}

/// An outage as a record keeps it, with how it is going.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Episode {
    outage: Outage,
    /// When a write first worked after the last failure: the episode is
    /// closing, and ends once that has lasted the quiet window.
    ended_unix: Option<u64>,
    /// How many times it failed again inside the quiet window.
    returns: u64,
    /// Whether its start was told: the cap may have held it back, and then
    /// its end is not told either.
    told: bool,
    /// Lines of `guard-events.jsonl` lost that were already counted into
    /// it (the sink's episodes only).
    written: u64,
}

/// What was told about one fault in the period [`CAP_TOLD`] counts in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Tally {
    /// When the period began.
    from: u64,
    /// Outages told in it.
    told: u64,
    /// Outages held back since the last one told.
    untold: u64,
}

/// What a health record holds: the episode, if one is going, and what was
/// told about each fault.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Record {
    episode: Option<Episode>,
    ledger: std::collections::BTreeMap<String, Tally>,
}

fn count(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

impl Record {
    fn parse(text: &str) -> Option<Record> {
        let value: Value = serde_json::from_str(text).ok()?;
        let episode = parse(text).map(|outage| Episode {
            outage,
            ended_unix: value.get("ended_unix").and_then(Value::as_u64),
            returns: count(&value, "returns"),
            told: value.get("told").and_then(Value::as_bool).unwrap_or(true),
            written: count(&value, "written"),
        });
        let ledger = value
            .get("ledger")
            .and_then(Value::as_object)
            .map(|codes| {
                codes
                    .iter()
                    .filter_map(|(code, tally)| {
                        Some((
                            code.clone(),
                            Tally {
                                from: tally.get("from")?.as_u64()?,
                                told: count(tally, "told"),
                                untold: count(tally, "untold"),
                            },
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Record { episode, ledger })
    }

    fn to_json(&self) -> Value {
        let mut body = serde_json::Map::new();
        if let Some(episode) = &self.episode {
            body.insert("code".into(), json!(episode.outage.code));
            body.insert("since_unix".into(), json!(episode.outage.since_unix));
            body.insert("lost".into(), json!(episode.outage.lost));
            if let Some(ended) = episode.ended_unix {
                body.insert("ended_unix".into(), json!(ended));
            }
            body.insert("returns".into(), json!(episode.returns));
            body.insert("told".into(), json!(episode.told));
            body.insert("written".into(), json!(episode.written));
        }
        if !self.ledger.is_empty() {
            let ledger: serde_json::Map<String, Value> = self
                .ledger
                .iter()
                .map(|(code, tally)| {
                    (
                        code.clone(),
                        json!({"from": tally.from, "told": tally.told, "untold": tally.untold}),
                    )
                })
                .collect();
            body.insert("ledger".into(), Value::Object(ledger));
        }
        Value::Object(body)
    }

    /// Drop what the cap no longer needs: a fault told longer ago than its
    /// period, with nothing held back.
    fn prune(&mut self, now: u64) {
        self.ledger.retain(|_, tally| {
            now.saturating_sub(tally.from) < CAP_PERIOD_SECS || tally.untold > 0
        });
    }

    /// `lost` writes failed with `code`. PURE. Whether to tell it, and how
    /// many outages of that fault were held back since the last one told.
    fn failed(&mut self, code: &str, lost: u64, clock: Clock) -> (bool, u64) {
        if let Some(episode) = self.episode.as_mut().filter(|e| e.outage.code == code) {
            let within = episode
                .ended_unix
                .is_none_or(|ended| clock.now.saturating_sub(ended) < clock.quiet);
            if within {
                episode.outage.lost = episode.outage.lost.saturating_add(lost);
                if episode.ended_unix.take().is_some() {
                    episode.returns = episode.returns.saturating_add(1);
                }
                return (false, 0);
            }
        }
        // A new episode: none was going, it had held for the quiet window,
        // or this is another fault (carrying the old start time forward
        // would misreport how long this one has been happening).
        let tally = self.ledger.entry(code.to_string()).or_default();
        if clock.now.saturating_sub(tally.from) >= CAP_PERIOD_SECS {
            tally.from = clock.now;
            tally.told = 0;
        }
        let tell = tally.told < CAP_TOLD;
        let untold = if tell {
            tally.told += 1;
            std::mem::take(&mut tally.untold)
        } else {
            tally.untold = tally.untold.saturating_add(1);
            0
        };
        self.episode = Some(Episode {
            outage: Outage {
                code: code.to_string(),
                since_unix: clock.now,
                lost,
            },
            ended_unix: None,
            returns: 0,
            told: tell,
            written: 0,
        });
        (tell, untold)
    }

    /// A write worked, after `written` lost lines were counted into the
    /// sink with it. PURE. The episode that ends, when its end is to be
    /// told.
    fn worked(&mut self, written: u64, clock: Clock) -> Option<Ended> {
        let episode = self.episode.as_mut()?;
        episode.written = episode
            .written
            .saturating_add(written)
            .min(episode.outage.lost);
        let ended = *episode.ended_unix.get_or_insert(clock.now);
        if clock.now.saturating_sub(ended) < clock.quiet {
            return None;
        }
        let episode = self.episode.take()?;
        episode.told.then_some(Ended {
            outage: episode.outage,
            ended_unix: ended,
            returns: episode.returns,
        })
    }
}

/// One lost write noted, and whether it is the one to tell someone about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Noted {
    pub outage: Outage,
    /// True when this failure opened a new episode that the cap lets be
    /// told, and the episode was kept where the next failure reads it.
    /// Repeats within an episode stay quiet or a broken install would send
    /// a notification per command; and an episode kept nowhere cannot tell
    /// its next failure from its first, so it is not told either (stderr
    /// says each failure, and `status` and `innerwarden graph --stats` probe
    /// the folder).
    pub tell: bool,
    /// Outages of the same fault held back by the cap since the last one
    /// told, said in this one's alert.
    pub untold: u64,
}

impl Noted {
    /// The alert this failure sends, when it is one to send. No paths, no
    /// command text.
    pub fn alert(&self) -> Option<String> {
        if !self.tell {
            return None;
        }
        let mut line = self.outage.summary();
        if self.untold > 0 {
            line.push_str(&format!(
                " The same fault also stopped and came back {} more time(s) since the last alert \
                 about it; at most {CAP_TOLD} of those are told an hour.",
                self.untold
            ));
        }
        Some(line)
    }
}

/// An episode whose end is to be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ended {
    pub outage: Outage,
    /// When writes started to work again for good.
    pub ended_unix: u64,
    /// How many times it failed again before they did.
    pub returns: u64,
}

impl Ended {
    /// The line that tells an episode ended, as plainly as
    /// [`Outage::summary`] told it began. No paths, no command text.
    pub fn summary(&self) -> String {
        let (what, unit) = if self.outage.code == SINK_NOT_WRITTEN {
            (
                "InnerWarden is adding to guard-events.jsonl again",
                "guard event(s)",
            )
        } else {
            ("InnerWarden is recording again", "action(s)")
        };
        let mut line = format!(
            "{what}, after {} ({} {unit} lost, {}).",
            in_words(self.ended_unix.saturating_sub(self.outage.since_unix)),
            self.outage.lost,
            self.outage.code
        );
        if self.returns > 0 {
            line.push_str(&format!(
                " It stopped again {} time(s) before it held.",
                self.returns
            ));
        }
        line
    }
}

/// Record one lost write, preserving the episode's start time.
///
/// Returns the resulting state and whether this failure is to be told
/// ([`Noted::alert`]).
#[cfg(test)]
pub fn note_failure_at(graph: &Path, code: &str) -> Noted {
    note_failures_at(graph, code, 1)
}

/// [`note_failure_at`] for `lost` writes at once (at least one): a writer
/// that counts losses as they happen and notes them in batches, so a flood
/// of them costs one write of the health file, not one each.
pub fn note_failures_at(graph: &Path, code: &str, lost: u64) -> Noted {
    note_failures_after(graph, code, lost, &Before::of(graph))
}

/// [`note_failures_at`] for a writer that read [`Before`] ahead of the
/// write that failed, since the write itself may change the folder.
pub fn note_failures_after(graph: &Path, code: &str, lost: u64, before: &Before) -> Noted {
    note_in(&health_path(graph), code, lost, before, Clock::real(), None)
}

/// A write worked: the episode going, if any, starts to close, and ends
/// once writes have worked for the quiet window ([`QUIET_SECS`]). Returns
/// the episode whose end is to be told now, so recovery can be reported as
/// plainly as the failure was. `before` was read ahead of the write.
pub fn note_success_at(graph: &Path, before: &Before) -> Option<Ended> {
    worked_in(&health_path(graph), before, 0, Clock::real(), None)
}

/// The guard event sink's own outage record, in the sink's folder: lines of
/// `guard-events.jsonl` that could not be appended. Apart from
/// [`HEALTH_FILE`], which every graph write that works clears: the two fail
/// apart (a size limit or a full disk can refuse an append and leave the
/// graph's rewrite room), and one must not end the other's episode.
const SINK_HEALTH_FILE: &str = "guard-events-health.json";

/// The code of a sink outage: lines of `guard-events.jsonl` not written.
pub(crate) const SINK_NOT_WRITTEN: &str = "guard_events_not_written";

/// How `guard-events.jsonl` in the folder `dir` and the folder stand, read
/// ahead of an append ([`Before`]).
pub fn sink_before(dir: &Path) -> Before {
    Before::of(&dir.join(SINK_FILE))
}

/// One line of `guard-events.jsonl` lost (an append that failed or was
/// refused), noted in the sink's own outage record for the folder `dir`.
pub fn note_sink_failure_in(dir: &Path, before: &Before) -> Noted {
    note_in(
        &dir.join(SINK_HEALTH_FILE),
        SINK_NOT_WRITTEN,
        1,
        before,
        Clock::real(),
        Some(SINK_NOT_WRITTEN),
    )
}

/// The sink's outage for the folder `dir`, if one is open.
#[cfg(test)]
pub fn sink_outage_in(dir: &Path) -> Option<Outage> {
    open_at(
        &dir.join(SINK_HEALTH_FILE),
        &dir.join(SINK_FILE),
        Some(SINK_NOT_WRITTEN),
    )
}

/// The sink's episode an append that works would end, if there is one
/// (open or closing), with `lost` the lines lost that are not yet counted
/// into the sink (possibly none). The folder is one the guarded agent's
/// account may write, and what is read here goes into `guard-events.jsonl`
/// itself: a record it planted with words of its own is not read.
pub fn sink_pending_in(dir: &Path, before: &Before) -> Option<Outage> {
    let (record, _) = ending(&dir.join(SINK_HEALTH_FILE), before, Some(SINK_NOT_WRITTEN));
    record.episode.map(|episode| Outage {
        lost: episode.outage.lost.saturating_sub(episode.written),
        ..episode.outage
    })
}

/// An append worked, with `written` lost lines counted into the sink ahead
/// of its own. Returns the episode whose end is to be told now.
pub fn note_sink_success_in(dir: &Path, before: &Before, written: u64) -> Option<Ended> {
    worked_in(
        &dir.join(SINK_HEALTH_FILE),
        before,
        written,
        Clock::real(),
        Some(SINK_NOT_WRITTEN),
    )
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

/// A record as read, with when the kernel says it was last written.
struct Held {
    record: Record,
    changed: Option<i128>,
}

/// What a record holds, never read through a link at the name: the
/// directory is shared with the agent's account, and a root run would read
/// whatever it points at.
fn read_held(path: &Path) -> Option<Held> {
    use std::io::Read;
    let file = innerwarden_safe_io::open_no_follow(path).ok()?;
    let changed = file.metadata().ok().as_ref().and_then(changed_ns);
    let mut body = String::new();
    file.take(64 * 1024).read_to_string(&mut body).ok()?;
    Some(Held {
        record: Record::parse(&body)?,
        changed,
    })
}

/// An episode of another code than `only` is none: what a record of the
/// sink holds goes into `guard-events.jsonl`.
fn keep_only(record: &mut Record, only: Option<&str>) {
    if let Some(code) = only {
        if record
            .episode
            .as_ref()
            .is_some_and(|e| e.outage.code != code)
        {
            record.episode = None;
        }
    }
}

/// Note `lost` failures of `code` for the record `beside`. The episode is
/// the one beside it, or the one kept outside its folder
/// ([`fallback_path`]) when that is the newer and [`kept_since`] believes
/// it (beside could not take the write then); a stale record left beside
/// in a folder that can no longer be written never makes every failure
/// the first. What was told about each fault (the cap) is only ever read
/// from beside: what is kept outside cannot hold an alert back.
fn note_in(
    beside: &Path,
    code: &str,
    lost: u64,
    before: &Before,
    clock: Clock,
    only: Option<&str>,
) -> Noted {
    let lost = lost.max(1);
    let here = read_held(beside);
    let outside = fallback_path(beside)
        .and_then(|place| read_held(&place))
        .filter(|held| kept_since(held.changed, before));
    let mut record = here
        .as_ref()
        .map(|held| held.record.clone())
        .unwrap_or_default();
    let newer_outside = match (&here, &outside) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(here), Some(outside)) => {
            here.record.episode.is_none() || outside.changed > here.changed
        }
    };
    if newer_outside {
        record.episode = outside.and_then(|held| held.record.episode);
    }
    keep_only(&mut record, only);
    let (tell, untold) = record.failed(code, lost, clock);
    let kept = store(beside, &record, clock.now);
    let outage = record.episode.map_or_else(
        || Outage {
            code: code.to_string(),
            since_unix: clock.now,
            lost,
        },
        |episode| episode.outage,
    );
    Noted {
        outage,
        tell: tell && kept,
        untold,
    }
}

/// The record a write that works ends an episode in: the one beside, and
/// the one kept outside the folder only when there is no record beside at
/// all and no write had worked since it was kept ([`unanswered`]). Whether
/// the episode came from outside.
///
/// A record beside, once there, is written in place by the next failure,
/// even in a folder that no longer takes new files ([`worked_in`] makes
/// it): an outage is kept outside only while there is none. One planted
/// outside beside a record of its own is not an outage that happened, and
/// a write that worked told its end (a planted record, then one call: one
/// "recording again" for an outage that never was).
fn ending(beside: &Path, before: &Before, only: Option<&str>) -> (Record, bool) {
    let here = read_held(beside);
    let mut record = here
        .as_ref()
        .map(|held| held.record.clone())
        .unwrap_or_default();
    keep_only(&mut record, only);
    let none_beside = here.is_none()
        && std::fs::symlink_metadata(beside)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
    let outside = fallback_path(beside)
        .filter(|_| none_beside)
        .and_then(|place| read_held(&place))
        .filter(|held| unanswered(held.changed, before))
        .filter(|held| {
            held.record
                .episode
                .as_ref()
                .is_some_and(|e| only.is_none_or(|code| e.outage.code == code))
        });
    let newer_outside = match (&outside, record.episode.is_some()) {
        (None, _) => false,
        (Some(_), false) => true,
        (Some(outside), true) => outside.changed > here.as_ref().and_then(|held| held.changed),
    };
    if newer_outside {
        record.episode = outside.and_then(|held| held.record.episode);
    }
    (record, newer_outside)
}

/// A write worked: close the episode of the record `beside`, and end it
/// once it has held for the quiet window. A record outside the folder that
/// is not believed is removed. The episode whose end is to be told now.
///
/// A record beside that is not there yet is made, empty: a folder that
/// stops taking new files (made `0500`) still lets one that is there be
/// written, so the next outage, and what was told about it, is kept where
/// InnerWarden guards it and not outside the folder, where what was told
/// cannot be kept (each turn of a folder made `0500` and `0700` was told
/// again, the cap never counting it).
fn worked_in(
    beside: &Path,
    before: &Before,
    written: u64,
    clock: Clock,
    only: Option<&str>,
) -> Option<Ended> {
    let (mut record, moved) = ending(beside, before, only);
    if record.episode.is_none() {
        if let Some(outside) = fallback_path(beside) {
            if std::fs::symlink_metadata(&outside).is_ok() {
                forget(&outside);
            }
        }
        if std::fs::symlink_metadata(beside)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            write_health(beside, b"{}");
        }
        return None;
    }
    let was = record.clone();
    let ended = record.worked(written, clock);
    if moved || record != was {
        store(beside, &record, clock.now);
    }
    ended
}

/// Keep `record` beside, else outside the folder ([`fallback_path`]),
/// where only its episode is kept: what is kept there is never trusted to
/// hold an alert back. A record with nothing left in it stays beside,
/// empty ([`worked_in`] says why). Whether it was kept.
fn store(beside: &Path, record: &Record, now: u64) -> bool {
    let mut record = record.clone();
    record.prune(now);
    let outside = fallback_path(beside);
    if write_health(beside, record.to_json().to_string().as_bytes()) {
        if let Some(outside) = &outside {
            let _ = std::fs::remove_file(outside);
        }
        return true;
    }
    let (Some(outside), Some(episode)) = (outside, record.episode) else {
        return false;
    };
    make_state_dir(&outside);
    let kept = Record {
        episode: Some(episode),
        ledger: std::collections::BTreeMap::new(),
    };
    write_health(&outside, kept.to_json().to_string().as_bytes())
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

    fn at(now: u64) -> Clock {
        Clock {
            now,
            quiet: QUIET_SECS,
        }
    }

    /// A write of the graph `g` failed with `code` at `now`.
    fn fail(g: &Path, code: &str, now: u64) -> Noted {
        note_in(&health_path(g), code, 1, &Before::of(g), at(now), None)
    }

    /// A write of the graph `g` worked at `now`.
    fn work(g: &Path, now: u64) -> Option<Ended> {
        worked_in(&health_path(g), &Before::of(g), 0, at(now), None)
    }

    /// A write of the graph `g` worked, with no quiet window to wait.
    fn work_now(g: &Path) -> Option<Ended> {
        let clock = Clock {
            now: now_unix(),
            quiet: 0,
        };
        worked_in(&health_path(g), &Before::of(g), 0, clock, None)
    }

    /// Long enough that the next change falls on a later tick of the
    /// clock the kernel stamps a change with.
    fn tick() {
        std::thread::sleep(std::time::Duration::from_millis(20));
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
        assert!(noted.tell);

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
            !third.tell,
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
        assert!(other.tell, "a new fault may notify again");
    }

    /// A write that works closes the outage at once (nothing reports it
    /// any more), and its end is told by the first write that works once
    /// the quiet window has passed with no failure, once.
    #[test]
    fn a_write_that_works_ends_the_outage_after_the_quiet_window_once() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        let t = now_unix();
        fail(&g, "write_failed", t);
        fail(&g, "write_failed", t);
        assert!(work(&g, t + 1).is_none(), "not before the window");
        assert!(read_at(&g).is_none(), "a closing outage is not reported");
        assert!(work(&g, t + QUIET_SECS).is_none(), "the window is not over");
        let ended = work(&g, t + 1 + QUIET_SECS).expect("the end, after the window");
        assert_eq!(ended.outage.lost, 2);
        assert_eq!(ended.returns, 0);
        assert!(ended.summary().contains("recording again"));
        assert!(work(&g, t + 2 + QUIET_SECS).is_none(), "told once");
        assert!(read_at(&g).is_none());
    }

    /// REGRESSION ANCHOR (an outage that came and went flooded the
    /// channels: a record folder made `0500` and `0700` in turn ten times
    /// sent 20 alerts in a second). A failure of the same fault inside the
    /// quiet window reopens the episode without an alert; its end is told
    /// once the window passes, with how many times it came back.
    ///
    /// FAILS ON REVERT: end the episode at the first write that works
    /// (drop the window from `Record::worked`) and every turn tells a start
    /// and an end.
    #[test]
    fn a_fault_that_comes_and_goes_is_one_outage_told_once_with_its_end() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        let t = now_unix();
        let mut told = 0;
        for turn in 0..10 {
            told += usize::from(fail(&g, "graph_write_failed", t + turn).tell);
            told += usize::from(work(&g, t + turn).is_some());
        }
        assert_eq!(told, 1, "the start, once");
        let ended = work(&g, t + 9 + QUIET_SECS).expect("then the end, once");
        assert_eq!(ended.outage.lost, 10);
        assert_eq!(ended.returns, 9);
        assert!(
            ended.summary().contains("It stopped again 9 time(s)"),
            "{}",
            ended.summary()
        );
    }

    /// Outages that each held past the quiet window are each one: at most
    /// [`CAP_TOLD`] of one fault are told an hour (start and end), the rest
    /// are counted, and the next alert about that fault says how many.
    /// Another fault is counted apart.
    ///
    /// FAILS ON REVERT: tell every new episode (drop the cap from
    /// `Record::failed`) and all six are told.
    #[test]
    fn at_most_three_outages_of_a_fault_are_told_an_hour_and_the_next_counts_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        let t = now_unix();
        let turn = QUIET_SECS + 2;
        let (mut starts, mut ends) = (0, 0);
        for n in 0..6 {
            let at = t + n * turn;
            starts += usize::from(fail(&g, "graph_write_failed", at).tell);
            ends += usize::from(work(&g, at + 1).is_some());
            ends += usize::from(work(&g, at + 1 + QUIET_SECS).is_some());
        }
        assert_eq!((starts, ends), (3, 3));
        let next = fail(&g, "graph_write_failed", t + CAP_PERIOD_SECS + 100);
        assert!(next.tell, "a new hour tells again");
        assert_eq!(next.untold, 3);
        let alert = next.alert().expect("told");
        assert!(alert.contains("came back 3 more time(s)"), "{alert}");
        assert!(
            fail(&g, "graph_lock_unavailable", t + CAP_PERIOD_SECS + 101).tell,
            "another fault is counted apart"
        );
    }

    /// REGRESSION ANCHOR (a record planted where an outage is kept when the
    /// record's folder cannot be written, a folder InnerWarden does not
    /// guard). Planted with the code of the fault, it held back the alert of
    /// that fault when it came: folder `0500`, 3 failures, 0 alerts. The
    /// change of mode is newer than the planted record, so the record is not
    /// believed and the failure is told; the episode this module keeps
    /// there itself is written after it, and keeps the repeats quiet.
    ///
    /// FAILS ON REVERT: believe any record kept outside the folder
    /// (`kept_since` returning true) and the planted one holds the alert
    /// back.
    #[cfg(unix)]
    #[test]
    fn a_record_planted_outside_the_folder_never_holds_an_alert_back() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir(&store).unwrap();
        let g = store.join("graph.json");
        std::fs::write(&g, "{}").unwrap();
        let outside = fallback_path(&health_path(&g)).unwrap();
        make_state_dir(&outside);
        tick();
        std::fs::write(
            &outside,
            format!(
                r#"{{"code":"graph_write_failed","since_unix":{},"lost":1}}"#,
                now_unix()
            ),
        )
        .unwrap();
        tick();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o500)).unwrap();
        if probe_writable(&store) {
            std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        tick();
        let first = note_failure_at(&g, "graph_write_failed");
        let second = note_failure_at(&g, "graph_write_failed");
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(first.tell, "the planted record held the alert back");
        assert!(!second.tell, "the episode kept there by this module is");
    }

    /// The other half: planted in a healthy home, it painted an outage that
    /// never happened. A record outside a folder that takes writes reports
    /// nothing (the probe decides), and a write that works after it was
    /// planted removes it without telling the end of an outage.
    ///
    /// FAILS ON REVERT: read the record outside the folder without the probe
    /// (`open_at`) and the healthy home reports `graph_write_failed`; take
    /// the record beside, or `unanswered`, out of `ending` and its end is
    /// told.
    #[test]
    fn a_record_planted_outside_a_healthy_folder_paints_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        std::fs::write(&g, "{}").unwrap();
        let outside = fallback_path(&health_path(&g)).unwrap();
        make_state_dir(&outside);
        let plant = || {
            std::fs::write(
                &outside,
                r#"{"code":"graph_write_failed","since_unix":1,"lost":9}"#,
            )
            .unwrap();
        };
        // An install that has recorded: its record beside the graph is
        // there, and an outage would have been kept in it.
        assert!(store(&health_path(&g), &Record::default(), now_unix()));
        plant();
        assert_eq!(report_at(&g), None, "{:?}", report_at(&g));
        assert_eq!(read_at(&g), None);
        assert_eq!(work_now(&g), None, "the end of an outage that never was");
        assert!(!outside.exists(), "and the planted record is gone");

        // None beside yet: a write that worked after it was planted.
        std::fs::remove_file(health_path(&g)).unwrap();
        plant();
        assert_eq!(report_at(&g), None, "{:?}", report_at(&g));
        tick();
        std::fs::write(&g, "{}").unwrap();
        assert_eq!(work_now(&g), None, "the end of an outage that never was");
        assert!(!outside.exists(), "and the planted record is gone");
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
        assert!(note_success_at(&g, &Before::of(&g)).is_none());
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
        tick();
        let first = note_failure_at(&g, "graph_lock_unavailable");
        let second = note_failure_at(&g, "graph_lock_unavailable");
        assert!(first.tell, "the first failure is told");
        assert!(!second.tell, "a repeat is not");
        assert!(!health_path(&g).exists());
        let reported = report_at(&g).expect("the kept episode is reported");
        assert_eq!(reported.code, "graph_lock_unavailable");
        assert_eq!(reported.lost, 2);

        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ended = work_now(&g).expect("the episode ends");
        assert_eq!(ended.outage.lost, 2);
        assert!(ended.summary().contains("recording again"));
        assert!(read_at(&g).is_none(), "both places are cleared");
        assert!(work_now(&g).is_none(), "one end, told once");
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
        tick();
        assert!(note_failure_at(&g, "graph_lock_unavailable").tell);
        assert!(!note_failure_at(&g, "graph_lock_unavailable").tell);
        assert!(!note_failure_at(&g, "graph_lock_unavailable").tell);
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(health_path(&g), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(work_now(&g).is_some(), "the episode ends");
        assert!(read_at(&g).is_none());
        assert!(work_now(&g).is_none(), "once");
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
        let before = sink_before(dir.path());
        let first = note_sink_failure_in(dir.path(), &before);
        assert!(first.tell);
        let again = note_sink_failure_in(dir.path(), &before);
        assert!(!again.tell);
        assert_eq!(again.outage.lost, 2);
        assert!(
            note_success_at(&g, &Before::of(&g)).is_none(),
            "the graph's record is apart"
        );
        let reported = report_at(&g).expect("the sink's loss is reported");
        assert_eq!(reported.code, SINK_NOT_WRITTEN);
        assert_eq!(reported.lost, 2);
        let said = reported.summary();
        assert!(
            said.contains("guard-events.jsonl") && said.contains("2 guard event(s) lost"),
            "{said}"
        );
        assert!(!said.contains('/'), "no paths in a health line: {said}");
        let pending = sink_pending_in(dir.path(), &before).expect("the count to write");
        assert_eq!(pending.lost, 2);
        let clock = Clock {
            now: now_unix(),
            quiet: 0,
        };
        let sink_health = dir.path().join(SINK_HEALTH_FILE);
        let ended = worked_in(&sink_health, &before, 2, clock, Some(SINK_NOT_WRITTEN))
            .expect("the episode ends");
        assert_eq!(ended.outage.lost, 2);
        assert!(ended
            .summary()
            .contains("adding to guard-events.jsonl again"));
        assert!(sink_outage_in(dir.path()).is_none());
        assert!(sink_pending_in(dir.path(), &before).is_none());
        assert!(report_at(&g).is_none());

        // A record planted with words of its own is never read back.
        std::fs::write(
            dir.path().join(SINK_HEALTH_FILE),
            r#"{"code":"see http://x.example","since_unix":1,"lost":9}"#,
        )
        .unwrap();
        assert!(sink_outage_in(dir.path()).is_none());
        assert!(report_at(&g).is_none());
        assert!(sink_pending_in(dir.path(), &before).is_none());
        assert!(note_sink_success_in(dir.path(), &before, 0).is_none());
    }
}
