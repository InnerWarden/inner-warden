//! What the person asked for, kept per agent session, so the MCP proxy can
//! tell a value the person typed from one the model wrote.
//!
//! # Why
//!
//! The proxy sees a tool call and the values in it. Without the person's own
//! words it cannot tell "send the report to ana@example.com", typed by the
//! person, from the same address written by a model that read it in a web
//! page: both reach the policy as the same call. Claude Code runs a hook on
//! every prompt the person submits (`UserPromptSubmit`), before the model
//! sees it. `innerwarden install` wires that hook to this module, which keeps
//! the prompt, and [`user_asked_for`] answers the one question the proxy
//! needs: does this value appear in what the person asked, this session?
//!
//! # Information, never a pass
//!
//! The answer never lowers a refusal. An agent with a shell on the same
//! account can write a record of its own: it runs `innerwarden hook` with a
//! `UserPromptSubmit` payload it made up, and the record then says the person
//! asked for whatever the agent wrote (a test shows it,
//! `an_agent_with_a_shell_can_forge_a_record`). The rule that stops an agent
//! running the guard's own hook reads the command's text, and a copy of the
//! binary or a variable gets past it. So "yes" is never a reason to let a call
//! through. What the answer is for is information: an alert that a value in a
//! call is not in what the person asked. Nothing here may become a pass until
//! the record has a writer the agent cannot imitate.
//!
//! What is kept is what was submitted: text the person pasted into the prompt
//! counts as theirs, wherever it came from. The session the proxy reads comes
//! from a variable of its environment, which a process between Claude Code
//! and the proxy can change: a wrong id reads another session's words or
//! none, never writes anything.
//!
//! # What is kept, where, for how long
//!
//! - One file per session under `~/.config/innerwarden/prompts/`, a folder
//!   the guard already holds against the agent's own writes. The folder is
//!   created 0700 and each file is written 0600, in one rename.
//! - Each prompt is masked first ([`crate::redact::redact_secrets`], the same
//!   masking the guard's record uses): an obvious secret is never kept.
//! - At most [`MAX_PROMPT_CHARS`] of one prompt (its start), at most
//!   [`MAX_SESSION_CHARS`] per session (the oldest prompts go first), and at
//!   most [`MAX_SESSIONS`] session files (the least recently written go
//!   first).
//! - A prompt is kept for [`PROMPT_TTL_MS`] (24 hours). An older one is never
//!   read. It is dropped when its session is written or read; a session file
//!   with nothing left is removed then, or when any session is written, or at
//!   most once a minute when the proxy reads ([`forget_expired_in`]). With no
//!   prompt and no read after it, an expired file stays on disk, unread, until
//!   the next one.
//! - The guard refuses an agent's reads of the folder (file tools and shell),
//!   as it refuses its writes there.
//! - Deleting the folder forgets everything; nothing else reads it.
//!
//! # The id both sides know
//!
//! The hook reads `session_id` from Claude Code's payload. Claude Code sets
//! `CLAUDE_CODE_SESSION_ID` to the same id in the environment of the
//! processes it starts, so a proxy it started reads it there
//! ([`proxy_session`]). No other agent is known to hand its MCP servers a
//! session id, so for them the answer is always "unknown".
//!
//! # The answer
//!
//! Three answers, never two: [`UserAsked::Yes`], [`UserAsked::No`] and
//! [`UserAsked::Unknown`] with the reason. No session, no record, a record
//! of another session, a value too short to tell, a value that would be
//! masked in the record: each of those is "unknown", never "no". What the
//! proxy does with the answer is its own policy; this module only keeps the
//! words and reads them.
//!
//! Everything here is best effort on the writing side: a prompt that cannot
//! be kept is dropped and the person's prompt goes on to the model as it
//! would without the guard.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The event Claude Code (and Codex, by the same name) runs a hook on when
/// the person submits a prompt.
pub const PROMPT_EVENT: &str = "UserPromptSubmit";

/// The environment variable Claude Code sets to its session id in the
/// processes it starts, an MCP server and so the proxy among them.
pub const CLAUDE_CODE_SESSION_ENV: &str = "CLAUDE_CODE_SESSION_ID";

/// The folder under the home directory the prompts are kept in.
pub const PROMPTS_DIR: &str = ".config/innerwarden/prompts";

/// How long a prompt is kept and read: 24 hours.
pub const PROMPT_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// The most of one prompt kept, in characters: its start.
pub const MAX_PROMPT_CHARS: usize = 16 * 1024;

/// The most kept for one session, in characters; the oldest prompts go first.
pub const MAX_SESSION_CHARS: usize = 64 * 1024;

/// The most session files kept; the least recently written go first.
pub const MAX_SESSIONS: usize = 64;

/// A value shorter than this, in characters, is not looked up: "ok" or "1"
/// appear in almost any request, so finding them says nothing.
pub const MIN_VALUE_CHARS: usize = 4;

/// The longest session id kept; a longer one is not an agent's.
const MAX_SESSION_ID_CHARS: usize = 256;

/// The word at the end of the prompt hook's line. It tells the hook, before
/// it reads anything, that it runs on the person's prompt: every way that
/// run can end (a panic, stdin it cannot read, the deadline, a fault) ends
/// with 0 and says nothing, so the hook never drops the person's prompt. A
/// tool call that arrives on such a line is screened as on any other.
pub const PROMPT_LINE_FLAG: &str = "--prompt";

/// How often, at most, a read under `$HOME` sweeps every session file for
/// what has expired ([`forget_expired_in`]).
const SWEEP_EVERY_MS: i64 = 60 * 1000;

/// The answer to "does this value appear in what the person asked?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserAsked {
    /// The value appears in a prompt the person submitted in this session.
    Yes,
    /// The session has a record, and no prompt in it holds the value.
    No,
    /// Nothing here can tell: the reason says why.
    Unknown(&'static str),
}

/// Why the answer is unknown.
pub mod why {
    pub const NO_SESSION: &str = "the call names no agent session";
    pub const NO_HOME: &str = "no home directory to read the record from";
    pub const NO_RECORD: &str = "no prompt is recorded for this session";
    pub const UNREADABLE: &str = "the record of this session could not be read";
    pub const OTHER_SESSION: &str = "the record found belongs to another session";
    pub const TOO_SHORT: &str = "the value is too short to tell";
    pub const MASKED: &str = "the value is a secret, which the record keeps masked";
    pub const LOST: &str = "this session lost or cut a prompt (past the length cap, the \
         session cap or its day), so the value may have been in what is gone";
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Record {
    /// The session id, whole, so a file is never read for another session.
    session: String,
    /// The agent the hook line named, when it named one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent: Option<String>,
    #[serde(default)]
    prompts: Vec<Prompt>,
    /// The session lost words: a prompt cut to [`MAX_PROMPT_CHARS`], one
    /// dropped for [`MAX_SESSION_CHARS`] or past its day, or one past the
    /// hook's cap that was never kept. A value not found is then "unknown",
    /// never "no".
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    lost: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Prompt {
    /// When the hook kept it, in milliseconds since the epoch.
    at_ms: i64,
    /// The prompt, masked and cut to [`MAX_PROMPT_CHARS`].
    text: String,
}

/// The folder the prompts are kept in, under `home`.
pub fn dir_in(home: &Path) -> PathBuf {
    home.join(PROMPTS_DIR)
}

/// The folder the prompts are kept in, under `$HOME`.
pub fn default_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").filter(|home| !home.is_empty())?;
    Some(dir_in(Path::new(&home)))
}

/// The session id the proxy runs in: the one Claude Code hands the
/// processes it starts. `None` for any other agent.
pub fn proxy_session() -> Option<String> {
    std::env::var(CLAUDE_CODE_SESSION_ENV)
        .ok()
        .and_then(|session| usable_session(&session).map(str::to_string))
}

fn usable_session(session: &str) -> Option<&str> {
    let session = session.trim();
    (!session.is_empty()
        && session.chars().count() <= MAX_SESSION_ID_CHARS
        && !session.chars().any(char::is_control))
    .then_some(session)
}

/// The file of one session: a hash of its id, so no id can name a path.
fn file_for(dir: &Path, session: &str) -> PathBuf {
    let digest = Sha256::digest(session.as_bytes());
    let name: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    dir.join(format!("{name}.json"))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// What is kept of one prompt: masked, then cut to its first
/// [`MAX_PROMPT_CHARS`]. Masked before the cut, so a secret the cut would
/// split is still found whole.
pub fn kept_text(prompt: &str) -> String {
    kept_text_and_cut(prompt).0
}

/// [`kept_text`], and whether the cut took anything off.
fn kept_text_and_cut(prompt: &str) -> (String, bool) {
    let masked = crate::redact::redact_secrets(prompt).text;
    match masked.char_indices().nth(MAX_PROMPT_CHARS) {
        Some((at, _)) => (masked[..at].to_string(), true),
        None => (masked, false),
    }
}

/// How long a write waits for the update lock of a record.
const UPDATE_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// How many times a write reads the record again when another writer
/// changed it between the read and the write, or held the lock for the
/// whole of [`UPDATE_LOCK_WAIT`]. Inside the hook's own deadline.
const UPDATE_ATTEMPTS: usize = 8;

/// Read the record of `session`, change it, and write it back under the
/// guard's update lock (`crate::file_update::replace_owned_store_no_symlinks`,
/// the lock and the compare-and-replace the guard's own record uses): the
/// write lands only if the file still holds what was read, and is tried again
/// from a fresh read otherwise, so two hook runs of one session never lose a
/// prompt. A record that cannot be read is started again.
fn update_record(
    dir: &Path,
    session: &str,
    change: impl Fn(&mut Record),
) -> std::io::Result<PathBuf> {
    use crate::file_update::{replace_owned_store_no_symlinks, ReplaceError};
    make_dir(dir)?;
    let path = file_for(dir, session);
    let mut last = String::from("the record kept changing under the write");
    for _ in 0..UPDATE_ATTEMPTS {
        let expected = match fs::symlink_metadata(&path) {
            Ok(meta) if !meta.is_file() => {
                return Err(std::io::Error::other("the record is not a plain file"));
            }
            Ok(_) => Some(fs::read(&path)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        let mut record = expected
            .as_deref()
            .and_then(|bytes| serde_json::from_slice::<Record>(bytes).ok())
            .filter(|record| record.session == session)
            .unwrap_or_else(|| Record {
                session: session.to_string(),
                ..Record::default()
            });
        change(&mut record);
        let body = serde_json::to_vec(&record).map_err(std::io::Error::other)?;
        match replace_owned_store_no_symlinks(
            dir,
            &path,
            expected.as_deref(),
            &body,
            UPDATE_LOCK_WAIT,
        ) {
            Ok(()) => return Ok(path),
            Err(ReplaceError::LockBusy { .. }) => {
                last = String::from("the record's update lock was busy");
            }
            Err(ReplaceError::Failed(why)) => last = why,
        }
    }
    Err(std::io::Error::other(last))
}

/// The update lock [`update_record`] leaves beside a record.
fn lock_for(record: &Path) -> PathBuf {
    let name = record
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    record.with_file_name(format!(".{name}.innerwarden.lock"))
}

/// Remove a record and its update lock.
fn remove_record(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(lock_for(path));
}

/// Say, in the record of `session` under `$HOME`, that one of its prompts
/// was not kept (past the hook's cap): from then on a value not found is
/// "unknown", never "no". Best effort, like [`record`].
pub fn record_lost(session: Option<&str>) -> std::io::Result<()> {
    let dir = default_dir().ok_or_else(|| std::io::Error::other(why::NO_HOME))?;
    record_lost_in(&dir, session)
}

/// [`record_lost`] with the folder handed in.
pub fn record_lost_in(dir: &Path, session: Option<&str>) -> std::io::Result<()> {
    let Some(session) = session.and_then(usable_session) else {
        return Ok(());
    };
    update_record(dir, session, |record| record.lost = true).map(|_| ())
}

/// Keep `prompt`, the person's words, for `session`, under `$HOME`.
/// Best effort: an error is returned for the caller to drop, never to
/// refuse the prompt with.
pub fn record(session: Option<&str>, agent: Option<&str>, prompt: &str) -> std::io::Result<()> {
    let dir = default_dir().ok_or_else(|| std::io::Error::other(why::NO_HOME))?;
    record_in(&dir, session, agent, prompt, now_ms())
}

/// [`record`] with the folder and the clock handed in.
pub fn record_in(
    dir: &Path,
    session: Option<&str>,
    agent: Option<&str>,
    prompt: &str,
    now_ms: i64,
) -> std::io::Result<()> {
    let Some(session) = session.and_then(usable_session) else {
        return Ok(());
    };
    if prompt.trim().is_empty() {
        return Ok(());
    }
    let (text, cut) = kept_text_and_cut(prompt);
    let path = update_record(dir, session, |record| {
        if let Some(agent) = agent {
            record.agent = Some(agent.to_string());
        }
        let before = record.prompts.len();
        record.prompts.retain(|p| fresh(p.at_ms, now_ms));
        let mut lost = cut || record.prompts.len() != before;
        record.prompts.push(Prompt {
            at_ms: now_ms,
            text: text.clone(),
        });
        let mut total: usize = record.prompts.iter().map(|p| p.text.chars().count()).sum();
        while total > MAX_SESSION_CHARS && record.prompts.len() > 1 {
            total -= record.prompts.remove(0).text.chars().count();
            lost = true;
        }
        record.lost |= lost;
    })?;
    prune(dir, now_ms, Some(&path));
    Ok(())
}

fn fresh(at_ms: i64, now_ms: i64) -> bool {
    now_ms.saturating_sub(at_ms) < PROMPT_TTL_MS
}

/// Create the folder 0700 when it is missing. A folder that is a link is
/// refused: the record is written only where it was meant to be.
fn make_dir(dir: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => Err(std::io::Error::other(
            "the prompts folder is a link; nothing is written through it",
        )),
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(std::io::Error::other("the prompts folder is not a folder")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(dir)
        }
        Err(e) => Err(e),
    }
}

/// Write `body` to `path` in one rename, the file 0600 from its creation:
/// the tests' way to put a record in place by hand.
#[cfg(test)]
fn write_private(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let _ = fs::remove_file(&tmp);
    let written = options.open(&tmp).and_then(|mut file| {
        file.write_all(body)?;
        file.sync_all()
    });
    if let Err(e) = written.and_then(|()| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Drop the session files past [`MAX_SESSIONS`] (least recently written
/// first) and those whose every prompt is past [`PROMPT_TTL_MS`]. `keep` is
/// the file just written, when there is one.
fn prune(dir: &Path, now_ms: i64, keep: Option<&Path>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if Some(path.as_path()) == keep || path.extension().and_then(|e| e.to_str()) != Some("json")
        {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let modified = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
        let stale = match read_record(&path) {
            Ok(Some(record)) => !record.prompts.iter().any(|p| fresh(p.at_ms, now_ms)),
            _ => true,
        };
        if stale {
            remove_record(&path);
        } else {
            files.push((modified, path));
        }
    }
    // The file just written, when there is one, is one of the sessions kept.
    let kept = files.len() + usize::from(keep.is_some());
    if kept > MAX_SESSIONS {
        files.sort();
        let over = kept - MAX_SESSIONS;
        for (_, path) in files.into_iter().take(over) {
            remove_record(&path);
        }
    }
}

fn read_record(path: &Path) -> std::io::Result<Option<Record>> {
    read_record_bytes(path).map(|read| read.map(|(_, record)| record))
}

/// [`read_record`], with the bytes it was read from.
fn read_record_bytes(path: &Path) -> std::io::Result<Option<(Vec<u8>, Record)>> {
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() => {
            return Err(std::io::Error::other("the record is not a plain file"));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    }
    let bytes = fs::read(path)?;
    let record = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
    Ok(Some((bytes, record)))
}

/// Drop the expired prompts of a record that was just read, writing it back
/// without them, or removing the file when nothing is left. Only when the
/// file still holds the bytes it was read from: a prompt the hook wrote in
/// between is never lost to the read.
fn drop_expired(path: &Path, read_from: &[u8], record: &Record, now_ms: i64) {
    if record.prompts.iter().all(|p| fresh(p.at_ms, now_ms)) {
        return;
    }
    let kept: Vec<Prompt> = record
        .prompts
        .iter()
        .filter(|p| fresh(p.at_ms, now_ms))
        .map(|p| Prompt {
            at_ms: p.at_ms,
            text: p.text.clone(),
        })
        .collect();
    if kept.is_empty() {
        // Nothing fresh: the file goes, if it still holds what was read.
        if fs::read(path).ok().as_deref() == Some(read_from) {
            remove_record(path);
        }
        return;
    }
    let left = Record {
        session: record.session.clone(),
        agent: record.agent.clone(),
        prompts: kept,
        lost: true,
    };
    if let (Ok(body), Some(dir)) = (serde_json::to_vec(&left), path.parent()) {
        // Written only over the bytes that were read, under the update lock.
        let _ = crate::file_update::replace_owned_store_no_symlinks(
            dir,
            path,
            Some(read_from),
            &body,
            UPDATE_LOCK_WAIT,
        );
    }
}

/// Remove every session file in `dir` whose prompts have all expired, and
/// those past [`MAX_SESSIONS`]. Called by a write, and by a read under
/// `$HOME` at most once every [`SWEEP_EVERY_MS`].
pub fn forget_expired_in(dir: &Path, now_ms: i64) {
    prune(dir, now_ms, None);
}

/// A character a value is made of: a run of them is one value
/// (`ana@example.com.au`, `release-7`, `https://x.example/a?b=c`).
fn value_char(c: char) -> bool {
    c.is_alphanumeric() || "@._-+/:%~=#&".contains(c)
}

/// What may end a sentence right after a value: `ana@example.com.` still
/// names `ana@example.com`.
const SENTENCE_END: &str = ".,;:!?";

/// Whether `needle` stands in `hay` as a whole value: no character a value
/// is made of right before it or right after it, so `ana@example.com` is
/// not found in `joana@example.com` nor in `ana@example.com.au`, and
/// `issue 4512` is not found in `issue 45123`. A mark that ends a sentence
/// after it is not part of it. Both are already folded ([`folded`]).
fn holds_whole(hay: &str, needle: &str) -> bool {
    let (Some(first), Some(last)) = (needle.chars().next(), needle.chars().next_back()) else {
        return false;
    };
    let mut from = 0;
    while let Some(at) = hay[from..].find(needle) {
        let start = from + at;
        let end = start + needle.len();
        let before_ok = !value_char(first)
            || hay[..start]
                .chars()
                .next_back()
                .is_none_or(|c| !value_char(c));
        let after_ok = !value_char(last) || ends_a_value(&hay[end..]);
        if before_ok && after_ok {
            return true;
        }
        from = start + hay[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// Whether the text right after a value ends it: nothing, a character no
/// value is made of, or a mark that ends a sentence followed by either.
fn ends_a_value(after: &str) -> bool {
    let mut chars = after.chars();
    match chars.next() {
        None => true,
        Some(c) if !value_char(c) => true,
        Some(c) if SENTENCE_END.contains(c) => chars.next().is_none_or(|n| !value_char(n)),
        Some(_) => false,
    }
}

/// How a value and a prompt are compared: lowercase, every run of blanks
/// one space, the ends trimmed.
fn folded(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Does `value` appear in what the person asked in `session`? Read under
/// `$HOME`, at the current time.
pub fn user_asked_for(session: Option<&str>, value: &str) -> UserAsked {
    use std::sync::atomic::{AtomicI64, Ordering};
    static LAST_SWEEP_MS: AtomicI64 = AtomicI64::new(i64::MIN);
    let Some(dir) = default_dir() else {
        return UserAsked::Unknown(why::NO_HOME);
    };
    let now = now_ms();
    let last = LAST_SWEEP_MS.load(Ordering::SeqCst);
    if now.saturating_sub(last) >= SWEEP_EVERY_MS
        && LAST_SWEEP_MS
            .compare_exchange(last, now, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    {
        forget_expired_in(&dir, now);
    }
    user_asked_for_in(&dir, session, value, now)
}

/// [`user_asked_for`] for the session the proxy runs in ([`proxy_session`]).
pub fn user_asked_for_in_this_session(value: &str) -> UserAsked {
    user_asked_for(proxy_session().as_deref(), value)
}

/// [`user_asked_for`] with the folder and the clock handed in.
pub fn user_asked_for_in(dir: &Path, session: Option<&str>, value: &str, now_ms: i64) -> UserAsked {
    let Some(session) = session.and_then(usable_session) else {
        return UserAsked::Unknown(why::NO_SESSION);
    };
    let needle = folded(value);
    if needle.chars().count() < MIN_VALUE_CHARS {
        return UserAsked::Unknown(why::TOO_SHORT);
    }
    // The record keeps secrets masked, so a secret is never found in it:
    // "no" would be a lie.
    if crate::redact::redact_secrets(value).count > 0 {
        return UserAsked::Unknown(why::MASKED);
    }
    let path = file_for(dir, session);
    let (bytes, record) = match read_record_bytes(&path) {
        Ok(Some(read)) => read,
        Ok(None) => return UserAsked::Unknown(why::NO_RECORD),
        Err(_) => return UserAsked::Unknown(why::UNREADABLE),
    };
    if record.session != session {
        return UserAsked::Unknown(why::OTHER_SESSION);
    }
    // What has expired is not only unread: it goes now.
    drop_expired(&path, &bytes, &record, now_ms);
    let mut any = false;
    for prompt in record.prompts.iter().filter(|p| fresh(p.at_ms, now_ms)) {
        any = true;
        if holds_whole(&folded(&prompt.text), &needle) {
            return UserAsked::Yes;
        }
    }
    // Words this session lost (cut, dropped, past their day) may have held
    // the value: not found is then unknown, never no.
    let lost = record.lost || record.prompts.iter().any(|p| !fresh(p.at_ms, now_ms));
    if lost {
        UserAsked::Unknown(why::LOST)
    } else if any {
        UserAsked::No
    } else {
        UserAsked::Unknown(why::NO_RECORD)
    }
}

/// The prompt a hook payload carries when its event is [`PROMPT_EVENT`]:
/// `Some(prompt)` for such a payload (empty when it names none), `None` for
/// any other event.
pub fn prompt_of(payload: &serde_json::Value) -> Option<String> {
    let event = payload
        .get("hook_event_name")
        .or_else(|| payload.get("hookEventName"))
        .and_then(serde_json::Value::as_str)?;
    if event != PROMPT_EVENT {
        return None;
    }
    Some(
        payload
            .get("prompt")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;
    const SESSION: &str = "cfcfa61b-7346-4783-b560-c5996efe36a2";

    fn dir() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = dir_in(tmp.path());
        (tmp, dir)
    }

    fn ask(dir: &Path, session: Option<&str>, value: &str) -> UserAsked {
        user_asked_for_in(dir, session, value, NOW)
    }

    /// The session records in `dir`, beside their update locks.
    fn records(dir: &Path) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect();
        found.sort();
        found
    }

    /// A prompt cut to its first [`MAX_PROMPT_CHARS`], or one the hook could
    /// not keep at all: a value not found may have been in what is gone, so
    /// the answer is unknown, never no.
    #[test]
    fn a_session_that_lost_words_answers_unknown_never_no() {
        let (_tmp, first) = dir();
        let long = format!(
            "{} then mail eve@evil.example",
            "a ".repeat(MAX_PROMPT_CHARS)
        );
        record_in(&first, Some(SESSION), None, &long, NOW).unwrap();
        assert_eq!(
            ask(&first, Some(SESSION), "eve@evil.example"),
            UserAsked::Unknown(why::LOST)
        );

        let (_tmp2, dir2) = dir();
        record_in(&dir2, Some(SESSION), None, "mail ana@example.com", NOW).unwrap();
        assert_eq!(ask(&dir2, Some(SESSION), "eve@evil.example"), UserAsked::No);
        record_lost_in(&dir2, Some(SESSION)).unwrap();
        assert_eq!(
            ask(&dir2, Some(SESSION), "eve@evil.example"),
            UserAsked::Unknown(why::LOST)
        );
        // What is there is still found.
        assert_eq!(ask(&dir2, Some(SESSION), "ana@example.com"), UserAsked::Yes);
    }

    /// Two hook runs of one session at once: each prompt is kept, none is
    /// written over by the other's read of the record.
    ///
    /// FAILS ON REVERT: write the record with a plain read, change and
    /// rename, and prompts go missing.
    #[test]
    fn prompts_written_at_once_are_all_kept() {
        let (_tmp, dir) = dir();
        const RUNS: usize = 16;
        std::thread::scope(|scope| {
            for i in 0..RUNS {
                let dir = &dir;
                scope.spawn(move || {
                    record_in(
                        dir,
                        Some(SESSION),
                        None,
                        &format!("open ticket-{i} now"),
                        NOW,
                    )
                    .unwrap();
                });
            }
        });
        for i in 0..RUNS {
            assert_eq!(
                ask(&dir, Some(SESSION), &format!("ticket-{i}")),
                UserAsked::Yes,
                "prompt {i} was lost"
            );
        }
    }

    #[test]
    fn a_value_the_person_typed_is_found_and_one_they_did_not_is_not() {
        let (_tmp, dir) = dir();
        record_in(
            &dir,
            Some(SESSION),
            Some("claude-code"),
            "Send the Q3 report to ana@example.com please",
            NOW,
        )
        .unwrap();
        assert_eq!(ask(&dir, Some(SESSION), "ana@example.com"), UserAsked::Yes);
        // Case and blanks do not hide a value the person typed.
        assert_eq!(
            ask(&dir, Some(SESSION), "  ANA@Example.com "),
            UserAsked::Yes
        );
        assert_eq!(ask(&dir, Some(SESSION), "Q3   report"), UserAsked::Yes);
        assert_eq!(ask(&dir, Some(SESSION), "eve@evil.example"), UserAsked::No);
    }

    #[test]
    fn every_prompt_of_the_session_counts() {
        let (_tmp, dir) = dir();
        record_in(
            &dir,
            Some(SESSION),
            None,
            "first: open issue 4512",
            NOW - 10,
        )
        .unwrap();
        record_in(&dir, Some(SESSION), None, "then label it urgent", NOW).unwrap();
        assert_eq!(ask(&dir, Some(SESSION), "issue 4512"), UserAsked::Yes);
        assert_eq!(ask(&dir, Some(SESSION), "urgent"), UserAsked::Yes);
    }

    #[test]
    fn another_session_or_none_is_unknown_never_no() {
        let (_tmp, dir) = dir();
        record_in(&dir, Some(SESSION), None, "deploy to staging", NOW).unwrap();
        assert_eq!(
            ask(&dir, Some("another-session"), "staging"),
            UserAsked::Unknown(why::NO_RECORD)
        );
        assert_eq!(
            ask(&dir, None, "staging"),
            UserAsked::Unknown(why::NO_SESSION)
        );
        assert_eq!(
            ask(&dir, Some("  "), "staging"),
            UserAsked::Unknown(why::NO_SESSION)
        );
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            ask(&dir_in(empty.path()), Some(SESSION), "staging"),
            UserAsked::Unknown(why::NO_RECORD)
        );
    }

    #[test]
    fn a_file_holding_another_sessions_record_is_not_read_for_this_one() {
        let (_tmp, dir) = dir();
        record_in(&dir, Some("other"), None, "wire money to acct 998877", NOW).unwrap();
        // The other session's record, put where this session's would be.
        fs::rename(file_for(&dir, "other"), file_for(&dir, SESSION)).unwrap();
        assert_eq!(
            ask(&dir, Some(SESSION), "acct 998877"),
            UserAsked::Unknown(why::OTHER_SESSION)
        );
    }

    #[test]
    fn a_short_value_or_a_secret_is_unknown() {
        let (_tmp, dir) = dir();
        record_in(
            &dir,
            Some(SESSION),
            None,
            "use key AKIA1234567890ABCDEF ok",
            NOW,
        )
        .unwrap();
        assert_eq!(
            ask(&dir, Some(SESSION), "ok"),
            UserAsked::Unknown(why::TOO_SHORT)
        );
        assert_eq!(
            ask(&dir, Some(SESSION), "AKIA1234567890ABCDEF"),
            UserAsked::Unknown(why::MASKED)
        );
    }

    #[test]
    fn an_obvious_secret_is_never_kept() {
        let (_tmp, dir) = dir();
        record_in(
            &dir,
            Some(SESSION),
            None,
            "log in with password=hunter2secret and key AKIA1234567890ABCDEF",
            NOW,
        )
        .unwrap();
        let raw = fs::read_to_string(file_for(&dir, SESSION)).unwrap();
        assert!(!raw.contains("hunter2secret"), "{raw}");
        assert!(!raw.contains("AKIA1234567890ABCDEF"), "{raw}");
        assert!(raw.contains("[REDACTED]"), "{raw}");
    }

    #[cfg(unix)]
    #[test]
    fn the_folder_is_the_persons_alone_and_each_file_too() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, dir) = dir();
        record_in(&dir, Some(SESSION), None, "hello there", NOW).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&file_for(&dir, SESSION)), 0o600);
        // Nothing but the record (and its update lock) is left in the folder.
        assert_eq!(records(&dir), vec![file_for(&dir, SESSION)]);
        let others: Vec<PathBuf> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| *p != file_for(&dir, SESSION) && *p != lock_for(&file_for(&dir, SESSION)))
            .collect();
        assert!(others.is_empty(), "{others:?}");
    }

    #[cfg(unix)]
    #[test]
    fn nothing_is_written_through_a_folder_that_is_a_link() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let dir = dir_in(tmp.path());
        fs::create_dir_all(dir.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();
        assert!(record_in(&dir, Some(SESSION), None, "hello there", NOW).is_err());
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    #[test]
    fn a_prompt_past_its_day_is_not_read_and_is_dropped_on_the_next_write() {
        let (_tmp, dir) = dir();
        let old = NOW - PROMPT_TTL_MS - 1;
        record_in(
            &dir,
            Some(SESSION),
            None,
            "rotate the db password tonight",
            old,
        )
        .unwrap();
        // Past its day the prompt is gone, and the value may have been in
        // it: unknown, never no.
        assert_eq!(
            ask(&dir, Some(SESSION), "rotate the db"),
            UserAsked::Unknown(why::LOST)
        );
        record_in(&dir, Some(SESSION), None, "now something else", NOW).unwrap();
        let raw = fs::read_to_string(file_for(&dir, SESSION)).unwrap();
        assert!(!raw.contains("rotate"), "{raw}");
    }

    #[test]
    fn one_prompt_and_one_session_are_bounded() {
        let (_tmp, dir) = dir();
        let long = "a".repeat(MAX_PROMPT_CHARS + 500);
        assert_eq!(kept_text(&long).chars().count(), MAX_PROMPT_CHARS);
        record_in(
            &dir,
            Some(SESSION),
            None,
            "the first request names zebra42",
            NOW,
        )
        .unwrap();
        for i in 0..(MAX_SESSION_CHARS / MAX_PROMPT_CHARS + 2) {
            record_in(&dir, Some(SESSION), None, &long, NOW + 1 + i as i64).unwrap();
        }
        let raw = fs::read_to_string(file_for(&dir, SESSION)).unwrap();
        let record: Record = serde_json::from_str(&raw).unwrap();
        let total: usize = record.prompts.iter().map(|p| p.text.chars().count()).sum();
        assert!(total <= MAX_SESSION_CHARS, "{total}");
        // The oldest prompt went first, and the record says words were lost:
        // a value it no longer holds is unknown, never no.
        assert_eq!(
            ask(&dir, Some(SESSION), "zebra42"),
            UserAsked::Unknown(why::LOST)
        );
    }

    #[test]
    fn the_number_of_sessions_kept_is_bounded() {
        let (_tmp, dir) = dir();
        for i in 0..(MAX_SESSIONS + 5) {
            record_in(&dir, Some(&format!("s{i}")), None, "hello there", NOW).unwrap();
        }
        let files = records(&dir).len();
        assert!(files <= MAX_SESSIONS, "{files}");
        // A record removed takes its update lock with it.
        let locks = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .ends_with(".innerwarden.lock")
            })
            .count();
        assert!(locks <= MAX_SESSIONS, "{locks}");
        // The session written last is kept.
        let last = format!("s{}", MAX_SESSIONS + 4);
        assert_eq!(ask(&dir, Some(&last), "hello"), UserAsked::Yes);
    }

    #[test]
    fn an_id_cannot_name_a_path() {
        let (_tmp, dir) = dir();
        record_in(&dir, Some("../../escape"), None, "hello there", NOW).unwrap();
        let names: Vec<String> = records(&dir)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 1);
        assert!(
            names[0].ends_with(".json") && !names[0].contains(".."),
            "{names:?}"
        );
    }

    #[test]
    fn an_unreadable_record_is_unknown() {
        let (_tmp, dir) = dir();
        fs::create_dir_all(&dir).unwrap();
        fs::write(file_for(&dir, SESSION), b"not json").unwrap();
        assert_eq!(
            ask(&dir, Some(SESSION), "hello"),
            UserAsked::Unknown(why::UNREADABLE)
        );
        // A write over it starts the record again.
        record_in(&dir, Some(SESSION), None, "hello there", NOW).unwrap();
        assert_eq!(ask(&dir, Some(SESSION), "hello"), UserAsked::Yes);
    }

    /// A value is found whole or not at all: a piece of a longer value the
    /// person typed proves nothing about the value in the call.
    #[test]
    fn a_piece_of_a_longer_value_is_not_the_value() {
        let (_tmp, dir) = dir();
        record_in(
            &dir,
            Some(SESSION),
            None,
            "write to ana@example.com.au and joana@example.com about issue 45123",
            NOW,
        )
        .unwrap();
        for piece in [
            "ana@example.com",
            "issue 4512",
            "example.co",
            "ana@example",
            "example.com.au",
        ] {
            assert_eq!(ask(&dir, Some(SESSION), piece), UserAsked::No, "{piece}");
        }
        for whole in ["ana@example.com.au", "joana@example.com", "issue 45123"] {
            assert_eq!(ask(&dir, Some(SESSION), whole), UserAsked::Yes, "{whole}");
        }
    }

    /// A mark that ends a sentence, or brackets around it, are not part of
    /// the value.
    #[test]
    fn a_value_at_the_end_of_a_sentence_or_in_brackets_is_whole() {
        let (_tmp, dir) = dir();
        record_in(
            &dir,
            Some(SESSION),
            None,
            "Mail it to ana@example.com. Then ping <bob@example.org>, and tag release-7!",
            NOW,
        )
        .unwrap();
        for value in ["ana@example.com", "bob@example.org", "release-7"] {
            assert_eq!(ask(&dir, Some(SESSION), value), UserAsked::Yes, "{value}");
        }
        assert_eq!(ask(&dir, Some(SESSION), "release-"), UserAsked::No);
    }

    #[test]
    fn an_expired_prompt_is_deleted_when_its_session_is_read() {
        let (_tmp, dir) = dir();
        record_in(
            &dir,
            Some(SESSION),
            None,
            "rotate the db password tonight",
            NOW - PROMPT_TTL_MS - 1,
        )
        .unwrap();
        // A write drops it already: write both back to see the read do it.
        let path = file_for(&dir, SESSION);
        let both = Record {
            session: SESSION.into(),
            agent: None,
            prompts: vec![
                Prompt {
                    at_ms: NOW - PROMPT_TTL_MS - 1,
                    text: "rotate the db password tonight".into(),
                },
                Prompt {
                    at_ms: NOW - 1,
                    text: "and open issue 7781".into(),
                },
            ],
            lost: false,
        };
        write_private(&path, &serde_json::to_vec(&both).unwrap()).unwrap();
        assert_eq!(ask(&dir, Some(SESSION), "issue 7781"), UserAsked::Yes);
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("rotate"), "{raw}");
        assert!(raw.contains("issue 7781"), "{raw}");
    }

    #[test]
    fn a_session_with_nothing_fresh_is_removed_when_it_is_read() {
        let (_tmp, dir) = dir();
        record_in(
            &dir,
            Some(SESSION),
            None,
            "rotate the db password tonight",
            NOW - PROMPT_TTL_MS - 1,
        )
        .unwrap();
        let path = file_for(&dir, SESSION);
        assert!(path.exists());
        assert_eq!(
            ask(&dir, Some(SESSION), "rotate the db"),
            UserAsked::Unknown(why::LOST)
        );
        assert!(!path.exists(), "an expired record outlived its read");
        assert!(!lock_for(&path).exists(), "its update lock outlived it");
    }

    #[test]
    fn the_sweep_removes_every_expired_session_and_keeps_the_fresh() {
        let (_tmp, dir) = dir();
        let old = NOW - PROMPT_TTL_MS - 1;
        record_in(&dir, Some("old-1"), None, "hello there", old).unwrap();
        record_in(&dir, Some("old-2"), None, "hello there", old).unwrap();
        record_in(&dir, Some(SESSION), None, "hello there", NOW).unwrap();
        // Write the old ones back: the last write already swept them.
        for session in ["old-1", "old-2"] {
            let record = Record {
                session: session.into(),
                agent: None,
                prompts: vec![Prompt {
                    at_ms: old,
                    text: "hello there".into(),
                }],
                lost: false,
            };
            write_private(
                &file_for(&dir, session),
                &serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
        }
        assert_eq!(records(&dir).len(), 3);
        forget_expired_in(&dir, NOW);
        assert_eq!(records(&dir), vec![file_for(&dir, SESSION)]);
    }

    #[test]
    fn the_prompt_is_read_only_from_the_prompt_event() {
        let claude = serde_json::json!({
            "session_id": SESSION,
            "hook_event_name": "UserPromptSubmit",
            "prompt": "fix the build",
        });
        assert_eq!(prompt_of(&claude).as_deref(), Some("fix the build"));
        let tool = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "prompt": "not a prompt",
            "tool_name": "Bash",
        });
        assert_eq!(prompt_of(&tool), None);
        let no_event = serde_json::json!({"prompt": "x"});
        assert_eq!(prompt_of(&no_event), None);
    }
}
