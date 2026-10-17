//! Thin I/O for `innerwarden agents approve|profile|allow|revoke`: read the
//! file of profiles the verb writes and the other one, the launcher's
//! records of this user's instances, ask the person at the terminal, write
//! the file, and report the outcome. The decisions are in `agent_decisions`.
//!
//! Every read is one open of a regular file that is not a link, of the right
//! owner and of a bounded size; the write is a replace of exactly the bytes
//! read (or the creation of a file that is not there yet), so a concurrent
//! change is never overwritten. A file is never written that does not load.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use innerwarden_agent_guard::identity::{
    judge_trust_in_jail, parse_launch_record, InJailFacts, RecordRead, Trust, MAX_RECORD_BYTES,
};
use innerwarden_agent_guard::profiles::{self, AgentProfiles, SYSTEM_PROFILES_PATH};

use crate::agent_decisions::{
    self, audit_line, effect, plan, response, Confirm, DashboardFacts, Effect, Facts,
    LocalInstance, Refusal, Request,
};
use crate::agent_profiles::{FileRead, ProfilesState};
use crate::agent_profiles_io::{self, Owner};
use crate::dashboard_identity::InstanceFacts;

/// The most records read from the launcher's directory.
const MAX_RECORDS: usize = 256;
/// The most entries looked at in it: a record and the project path beside it.
const MAX_RECORD_ENTRIES: usize = 2 * MAX_RECORDS;

/// Run one verb. `rest` starts with the verb.
pub fn cmd(rest: &[String]) -> ExitCode {
    let request = match agent_decisions::parse(rest) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("innerwarden agents: {error}\n{}", agent_decisions::usage());
            return ExitCode::from(1);
        }
    };
    let by = operator_name();
    match run(&request, &by) {
        Outcome::Done {
            effect,
            after,
            note,
        } => {
            record(&request, &by, Some(&effect), "success");
            if request.json {
                println!("{}", response(&request, Ok(&effect), Some(&after)));
            } else {
                println!("{}", effect.done);
                if let Some(note) = note {
                    println!("{note}");
                }
            }
            ExitCode::SUCCESS
        }
        Outcome::Refused(refusal, effect) => {
            record(
                &request,
                &by,
                effect.as_ref(),
                &format!("failure: {}", refusal.code),
            );
            eprintln!(
                "innerwarden agents: refused ({}): {}",
                refusal.code, refusal.sentence
            );
            if request.json {
                println!("{}", response(&request, Err(&refusal), None));
            }
            ExitCode::from(1)
        }
        Outcome::NoTerminal => {
            eprintln!(
                "innerwarden agents: This change needs you at a terminal: run it yourself, not \
                 from an agent. Nothing was changed."
            );
            ExitCode::from(2)
        }
    }
}

enum Outcome {
    Done {
        effect: Effect,
        after: AgentProfiles,
        note: Option<String>,
    },
    Refused(Refusal, Option<Effect>),
    NoTerminal,
}

fn refused(code: &'static str, sentence: impl Into<String>) -> Outcome {
    Outcome::Refused(
        Refusal {
            code,
            sentence: sentence.into(),
        },
        None,
    )
}

/// Parse one file's bytes as it is found, `None` for no file.
fn parsed(read: &FileRead, label: &str) -> Result<Option<AgentProfiles>, String> {
    match read {
        FileRead::Absent => Ok(None),
        FileRead::Refused(why) => Err(format!("{label}: {why}")),
        FileRead::Bytes(bytes) => profiles::parse(bytes)
            .map(Some)
            .map_err(|error| format!("{label}: {error}")),
    }
}

fn run(request: &Request, by: &str) -> Outcome {
    let is_root = euid() == 0;
    if is_root && !request.system {
        // Root writing into a user's folder would leave a file there the
        // user's own account does not own.
        return refused(
            "bad_request",
            "As root, a decision goes in the system file: add --system.",
        );
    }
    let system_read = agent_profiles_io::read(Path::new(SYSTEM_PROFILES_PATH), Owner::Root);
    let Some((user_path, user_owner)) = user_file() else {
        return refused("profiles_unreadable", "The home folder is not known.");
    };
    let user_label = user_path.to_string_lossy().into_owned();
    let user_read = agent_profiles_io::read(&user_path, user_owner);
    // Both files must be usable: what is in force before and after the
    // change is both of them together.
    let system = match parsed(&system_read, SYSTEM_PROFILES_PATH) {
        Ok(p) => p,
        Err(why) => return refused("profiles_unreadable", why),
    };
    let user = match parsed(&user_read, &user_label).and_then(|p| match &p {
        Some(checked) => profiles::check_user_file(checked)
            .map(|()| p.clone())
            .map_err(|e| format!("{user_label}: {e}")),
        None => Ok(None),
    }) {
        Ok(p) => p,
        Err(why) => return refused("profiles_unreadable", why),
    };
    let (path, target_read) = if request.system {
        (PathBuf::from(SYSTEM_PROFILES_PATH), &system_read)
    } else {
        (user_path, &user_read)
    };
    let expected = match target_read {
        FileRead::Bytes(bytes) => Some(bytes.clone()),
        _ => None,
    };
    let empty = AgentProfiles::default();
    let target = if request.system {
        system.as_ref()
    } else {
        user.as_ref()
    }
    .unwrap_or(&empty);
    let before = profiles::merge(system.as_ref(), user.as_ref());
    let instances = local_instances_for_operator();
    let known_agent = innerwarden_agent_guard::agents::KNOWN
        .iter()
        .any(|known| known.name == request.agent)
        || before.agents.contains_key(&request.agent)
        || before.types.contains_key(&request.agent);
    let facts = Facts {
        target,
        merged: &before,
        known_agent,
        is_root,
        instances: &instances,
    };
    let edit = match plan(request, &facts, by) {
        Ok(edit) => edit,
        Err(refusal) => return Outcome::Refused(refusal, None),
    };
    let at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let stamp = profiles::Stamp { by, at: &at };
    let text = expected
        .as_deref()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    let new_text = match agent_decisions::apply(&text, request, &edit, stamp) {
        Ok(text) => text,
        Err(why) => return refused("bad_request", why),
    };
    // Never write a file that would not load.
    let written = match profiles::parse(new_text.as_bytes()) {
        Ok(p) => p,
        Err(error) => return refused("bad_request", error.to_string()),
    };
    if !request.system && profiles::check_user_file(&written).is_err() {
        return refused(
            "needs_system_file",
            format!(
                "Only {SYSTEM_PROFILES_PATH} may relax a rule, so a relaxation is never in a \
                 file an agent's account can write: run it with sudo and --system."
            ),
        );
    }
    let after = if request.system {
        profiles::merge(Some(&written), user.as_ref())
    } else {
        profiles::merge(system.as_ref(), Some(&written))
    };
    let effect = effect(request, &edit, &before, &after, &instances, by);
    match confirm(request, &effect) {
        Confirmed::Yes => {}
        Confirmed::No => {
            return Outcome::Refused(
                Refusal {
                    code: "confirm_mismatch",
                    sentence: "Not confirmed. Nothing was changed.".into(),
                },
                Some(effect),
            )
        }
        Confirmed::NoTerminal => return Outcome::NoTerminal,
    }
    let mode = if request.system { 0o644 } else { 0o600 };
    match write_profiles(
        &path,
        expected.as_deref(),
        new_text.as_bytes(),
        mode,
        request.system,
    ) {
        Ok(()) => {}
        Err(WriteError::Changed) => {
            return Outcome::Refused(
                Refusal {
                    code: "changed_meanwhile",
                    sentence: format!(
                        "{} changed while this change was being confirmed; nothing was written. \
                         Run it again.",
                        path.display()
                    ),
                },
                Some(effect),
            )
        }
        Err(WriteError::Failed(why)) => {
            return Outcome::Refused(
                Refusal {
                    code: "write_failed",
                    sentence: format!("{} was not written: {why}", path.display()),
                },
                Some(effect),
            )
        }
    }
    let note = (!request.system && request.verb == agent_decisions::Verb::Revoke).then(|| {
        format!(
            "Your own hooks refuse it from their next call. A jail reads only \
             {SYSTEM_PROFILES_PATH}: to reach the instances in one, run it again with sudo and \
             --system."
        )
    });
    Outcome::Done {
        effect,
        after,
        note,
    }
}

enum Confirmed {
    Yes,
    No,
    NoTerminal,
}

/// Ask the person. `--yes` stands for `y` outside an AI agent's shell, and
/// never for a typed name; a relaxation is never confirmed from an agent's
/// shell, even one that has found a terminal.
fn confirm(request: &Request, effect: &Effect) -> Confirmed {
    let agent_shell = crate::suppress_io::in_agent_shell();
    if effect.confirm == Confirm::YesNo && request.yes && !agent_shell {
        return Confirmed::Yes;
    }
    if agent_shell {
        return Confirmed::NoTerminal;
    }
    let Ok(mut tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    else {
        return Confirmed::NoTerminal;
    };
    let prompt = match effect.confirm {
        Confirm::YesNo => format!("{}\nProceed? [y/N] ", effect.before),
        Confirm::TypedName => format!("{}\nType the agent name to confirm: ", effect.before),
    };
    if tty
        .write_all(prompt.as_bytes())
        .and_then(|()| tty.flush())
        .is_err()
    {
        return Confirmed::NoTerminal;
    }
    let mut answer = Vec::new();
    let mut byte = [0u8; 1];
    while answer.len() < 256 {
        match tty.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => break,
            Ok(1) => answer.push(byte[0]),
            _ => break,
        }
    }
    let answer = String::from_utf8_lossy(&answer);
    let answer = answer.trim();
    let yes = match effect.confirm {
        Confirm::YesNo => matches!(answer, "y" | "Y" | "yes"),
        Confirm::TypedName => answer == request.agent,
    };
    if yes {
        Confirmed::Yes
    } else {
        Confirmed::No
    }
}

/// Write the `guard.agent_decision` line. Best-effort, like every line of
/// the guard's event stream.
fn record(request: &Request, by: &str, effect: Option<&Effect>, result: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    crate::graph_io::append_guard_event(&audit_line(
        ts,
        request,
        by,
        effect,
        result,
        Some(crate::graph_io::session_id(None)),
    ));
}

fn euid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: geteuid takes no arguments and cannot fail.
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        u32::MAX
    }
}

/// The person deciding, for the record: the account that ran `sudo` when
/// this runs as root through it, else this account's name. A name, never
/// proof of who typed it.
fn operator_name() -> String {
    let valid = |name: String| profiles::is_person_name(&name).then_some(name);
    if euid() == 0 {
        if let Some(name) = std::env::var("SUDO_USER").ok().and_then(valid) {
            return name;
        }
    }
    std::env::var("USER")
        .ok()
        .and_then(valid)
        .or_else(|| std::env::var("LOGNAME").ok().and_then(valid))
        .unwrap_or_else(|| format!("uid {}", euid()))
}

// ---------------------------------------------------------------------------
// The launcher's records
// ---------------------------------------------------------------------------

/// The user's file the hooks of the person running the verb read, and who
/// must own it: under `sudo`, the account that ran it, not root's.
fn user_file() -> Option<(PathBuf, Owner)> {
    #[cfg(unix)]
    if euid() == 0 {
        if let Some(uid) = sudo_uid() {
            return home_of(uid)
                .map(|home| (home.join(profiles::USER_PROFILES_PATH), Owner::Account(uid)));
        }
    }
    agent_profiles_io::user_path().map(|path| (path, Owner::Me))
}

fn sudo_uid() -> Option<u32> {
    std::env::var("SUDO_UID").ok().and_then(|v| v.parse().ok())
}

/// The records of the person running the verb: under `sudo`, the account
/// that ran it, not root's.
fn local_instances_for_operator() -> Vec<LocalInstance> {
    #[cfg(unix)]
    if euid() == 0 {
        if let Some(uid) = sudo_uid() {
            return home_of(uid)
                .map(|home| local_instances(&crate::contain::launch::records_dir(None, &home), uid))
                .unwrap_or_default();
        }
    }
    let Ok(home) = innerwarden_agent_guard::hook::home_dir() else {
        return Vec::new();
    };
    let dir =
        crate::contain::launch::records_dir(std::env::var("XDG_STATE_HOME").ok().as_deref(), &home);
    local_instances(&dir, real_uid())
}

fn real_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: getuid takes no arguments and cannot fail.
        unsafe { libc::getuid() }
    }
    #[cfg(not(unix))]
    {
        u32::MAX
    }
}

/// The home of `uid` from the account database.
#[cfg(unix)]
fn home_of(uid: u32) -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: a zeroed passwd is a valid out-parameter for getpwuid_r.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is to memory owned here and sized as passed; the
    // result is read only when the call says it filled `entry`.
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        )
    };
    if status != 0 || found.is_null() || entry.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` points into `buffer`, NUL-terminated by the call.
    let dir = unsafe { CStr::from_ptr(entry.pw_dir) };
    let dir = Path::new(std::ffi::OsStr::from_bytes(dir.to_bytes()));
    dir.is_absolute().then(|| dir.to_path_buf())
}

/// The instances recorded in `dir`, as the verbs and the dashboard count
/// them. See [`local_records`].
pub(crate) fn local_instances(dir: &Path, uid: u32) -> Vec<LocalInstance> {
    local_records(dir, uid)
        .into_iter()
        .map(|facts| LocalInstance {
            instance_id: facts.record.instance_id,
            agent_type: facts.record.agent_type,
            live: facts.live,
            trust: facts.judged.map_or(Trust::Declared, |(trust, _)| trust),
        })
        .collect()
}

/// Whether `dir` is a directory of `uid`'s own, not a link: the launcher's
/// records are read only from there.
fn own_directory(dir: &Path, uid: u32) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    if !metadata.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.uid() == uid
    }
    #[cfg(not(unix))]
    {
        let _ = uid;
        true
    }
}

/// The records in `dir`: each `<instance id>.json` that is a regular file
/// owned by `uid`, not a link, no larger than a record, that parses, names
/// `uid` and its own id, in a directory of `uid`'s own that is not a link.
/// Live means the jail's pid runs with the start time recorded (a pid is
/// never enough); for a live jail the judgment is what the hook inside it
/// would make of the record and the jail's namespaces. A missing directory
/// is one `stat` and an empty list.
pub(crate) fn local_records(dir: &Path, uid: u32) -> Vec<InstanceFacts> {
    if !own_directory(dir, uid) {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten().take(MAX_RECORD_ENTRIES) {
        if out.len() == MAX_RECORDS {
            break;
        }
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".json")) else {
            continue;
        };
        if !innerwarden_agent_guard::identity::is_instance_id(id) {
            continue;
        }
        let Some(bytes) = read_record(&entry.path(), uid) else {
            continue;
        };
        let Ok(record) = parse_launch_record(&bytes) else {
            continue;
        };
        if record.uid != uid || record.instance_id != id {
            continue;
        }
        let jail_ns = jail_namespace(record.jail.pid, record.jail.start_ticks);
        let judged = jail_ns.map(|(own_pid_ns, own_mnt_ns)| {
            judge_trust_in_jail(InJailFacts {
                record: RecordRead::Present {
                    record: &record,
                    read_only: true,
                },
                own_pid_ns,
                own_mnt_ns,
            })
        });
        // The project path beside the record, read with the record's care
        // and taken only as a plain path of the record's own project.
        let project_dir = crate::contain::launch::project_path_file(id)
            .and_then(|name| read_record(&dir.join(name), uid))
            .and_then(|bytes| crate::contain::launch::parse_project_path(&bytes, &record.project));
        out.push(InstanceFacts {
            live: jail_ns.is_some(),
            judged,
            record,
            user: None,
            project_dir,
        });
    }
    out.sort_by(|a, b| a.record.instance_id.cmp(&b.record.instance_id));
    out
}

/// The account name of `uid`, from the account database.
#[cfg(unix)]
fn user_name(uid: u32) -> Option<String> {
    use std::ffi::CStr;
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: a zeroed passwd is a valid out-parameter for getpwuid_r.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is to memory owned here and sized as passed; the
    // result is read only when the call says it filled `entry`.
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        )
    };
    if status != 0 || found.is_null() || entry.pw_name.is_null() {
        return None;
    }
    // SAFETY: `pw_name` points into `buffer`, NUL-terminated by the call.
    let name = unsafe { CStr::from_ptr(entry.pw_name) };
    let name = name.to_str().ok()?;
    (!name.is_empty() && name.len() <= 64).then(|| name.to_string())
}

#[cfg(not(unix))]
fn user_name(_uid: u32) -> Option<String> {
    None
}

fn read_record(path: &Path, uid: u32) -> Option<Vec<u8>> {
    let file = innerwarden_safe_io::open_no_follow(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !innerwarden_safe_io::is_regular_file(&metadata) {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != uid {
            return None;
        }
    }
    #[cfg(not(unix))]
    let _ = uid;
    if metadata.len() > MAX_RECORD_BYTES as u64 {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= MAX_RECORD_BYTES).then_some(bytes)
}

/// `Some` when the jail process `pid` runs with start time `ticks` (read
/// before and after its namespace, so a reused pid is not taken for it):
/// `Some((pid, mnt))` with its PID and mount namespaces, each `None` when it
/// could not be read.
#[cfg(target_os = "linux")]
fn jail_namespace(pid: u32, ticks: u64) -> Option<(Option<u64>, Option<u64>)> {
    let start = || {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| crate::contain::launch::parse_start_ticks(&s))
    };
    if ticks == 0 || start() != Some(ticks) {
        return None;
    }
    let ns = std::fs::read_link(format!("/proc/{pid}/ns/pid"))
        .ok()
        .and_then(|link| crate::contain::launch::parse_ns_link(&link.to_string_lossy()));
    let mnt = std::fs::read_link(format!("/proc/{pid}/ns/mnt"))
        .ok()
        .and_then(|link| crate::contain::launch::parse_mnt_ns_link(&link.to_string_lossy()));
    (start() == Some(ticks)).then_some((ns, mnt))
}

/// No `/proc` to check a jail against: nothing is live.
#[cfg(not(target_os = "linux"))]
fn jail_namespace(_pid: u32, _ticks: u64) -> Option<(Option<u64>, Option<u64>)> {
    None
}

// ---------------------------------------------------------------------------
// The dashboard
// ---------------------------------------------------------------------------

/// What the dashboard shows of the decisions and the instances, or `None`
/// when the identity features are off here: no profiles file, and no
/// instance ever started in a jail (the launcher's directory is not there,
/// one `stat`). A file that cannot be used turns them on with its problem:
/// the hook refuses every call while it is, and that is never silence.
pub fn dashboard_facts(home: &Path) -> Option<DashboardFacts> {
    let dir =
        crate::contain::launch::records_dir(std::env::var("XDG_STATE_HOME").ok().as_deref(), home);
    let uid = real_uid();
    facts_from(
        agent_profiles_io::state(),
        || std::fs::symlink_metadata(&dir).is_ok(),
        || {
            let user = user_name(uid);
            let mut records = local_records(&dir, uid);
            for facts in &mut records {
                facts.user = user.clone();
            }
            records
        },
    )
}

/// Add, for each instance whose launcher wrote its project path, what the
/// graph the jail's hook keeps in that project holds about it (sessions, the
/// newest activity, the hook's label), where the user's graph holds nothing
/// for it. Each project's graph is read once, with the same hardened read as
/// the launcher's own after a run: a real folder and file of this user, one
/// open that follows no link and waits on no FIFO, no more than a graph's cap,
/// read only. Nothing is copied from it but that summary, and a graph that
/// is missing or refused adds nothing.
pub fn add_project_activity(facts: &mut DashboardFacts) {
    let uid = real_uid();
    let mut graphs: std::collections::BTreeMap<
        PathBuf,
        Option<std::collections::BTreeMap<String, innerwarden_graph::InstanceActivity>>,
    > = std::collections::BTreeMap::new();
    for record in &facts.records {
        let id = &record.record.instance_id;
        let Some(dir) = &record.project_dir else {
            continue;
        };
        if facts.activity.contains_key(id) {
            continue;
        }
        let found = graphs
            .entry(dir.clone())
            .or_insert_with(|| project_graph_activity(dir, uid))
            .as_mut()
            .and_then(|by_id| by_id.remove(id));
        crate::dashboard_identity::merge_project_activity(&mut facts.activity, id, found);
    }
}

/// What the graph in `project` holds about each instance, or `None` when it
/// is missing or refused.
#[cfg(unix)]
fn project_graph_activity(
    project: &Path,
    uid: u32,
) -> Option<std::collections::BTreeMap<String, innerwarden_graph::InstanceActivity>> {
    match crate::contain_io::read_jail_graph(project, uid) {
        crate::contain::launch::JailGraph::Read(graph) => {
            Some(graph.instance_activity(crate::dashboard_identity::MAX_SESSIONS))
        }
        _ => None,
    }
}

/// No jail on this platform keeps a graph to read.
#[cfg(not(unix))]
fn project_graph_activity(
    _project: &Path,
    _uid: u32,
) -> Option<std::collections::BTreeMap<String, innerwarden_graph::InstanceActivity>> {
    None
}

/// [`dashboard_facts`] from what was found: the profiles, whether the
/// launcher's directory is there (asked only with no profiles file), and its
/// records (read only when the features are on).
fn facts_from(
    state: ProfilesState,
    records_dir_exists: impl FnOnce() -> bool,
    records: impl FnOnce() -> Vec<InstanceFacts>,
) -> Option<DashboardFacts> {
    let (profiles, profiles_problem) = match state {
        ProfilesState::On(profiles) => (profiles, None),
        ProfilesState::Invalid(why) => (AgentProfiles::default(), Some(why)),
        ProfilesState::Off if !records_dir_exists() => return None,
        ProfilesState::Off => (AgentProfiles::default(), None),
    };
    let records = records();
    let instances = records
        .iter()
        .map(|facts| LocalInstance {
            instance_id: facts.record.instance_id.clone(),
            agent_type: facts.record.agent_type.clone(),
            live: facts.live,
            trust: facts.judged.map_or(Trust::Declared, |(trust, _)| trust),
        })
        .collect();
    Some(DashboardFacts {
        profiles,
        instances,
        records,
        activity: std::collections::BTreeMap::new(),
        profiles_problem,
    })
}

// ---------------------------------------------------------------------------
// The write
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WriteError {
    /// The file is not what was read any more.
    Changed,
    Failed(String),
}

/// Put `body` at `path`, only if the file still holds `expected` (`None`:
/// there is no file yet). A new file is created whole with `mode`, by a link
/// that fails if another file appeared meanwhile; an existing one is
/// replaced keeping its owner and mode. What is written is read back as the
/// loader reads it.
pub(crate) fn write_profiles(
    path: &Path,
    expected: Option<&[u8]>,
    body: &[u8],
    mode: u32,
    system: bool,
) -> Result<(), WriteError> {
    let parent = path
        .parent()
        .ok_or_else(|| WriteError::Failed("the file has no folder".into()))?;
    match expected {
        None => create_new(parent, path, body, mode, system)?,
        Some(expected) => {
            if let Err(error) =
                innerwarden_agent_guard::file_update::replace_if_unchanged_no_symlinks(
                    parent,
                    path,
                    Some(expected),
                    body,
                )
            {
                let now = agent_profiles_io::read(path, owner(system));
                return Err(if now == FileRead::Bytes(expected.to_vec()) {
                    WriteError::Failed(error)
                } else {
                    WriteError::Changed
                });
            }
        }
    }
    match agent_profiles_io::read(path, owner(system)) {
        FileRead::Bytes(bytes) if bytes == body => Ok(()),
        FileRead::Refused(why) => Err(WriteError::Failed(format!("read back: {why}"))),
        _ => Err(WriteError::Changed),
    }
}

fn owner(system: bool) -> Owner {
    if system {
        Owner::Root
    } else {
        Owner::Me
    }
}

fn create_new(
    parent: &Path,
    path: &Path,
    body: &[u8],
    mode: u32,
    system: bool,
) -> Result<(), WriteError> {
    let created_parent = !parent.exists();
    std::fs::create_dir_all(parent)
        .map_err(|e| WriteError::Failed(format!("creating {}: {e}", parent.display())))?;
    #[cfg(unix)]
    if created_parent && !system {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = (created_parent, system);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp = parent.join(format!(
        ".{}.{}.{nanos}.tmp",
        profiles::PROFILES_FILE,
        std::process::id()
    ));
    let result = (|| -> Result<(), WriteError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        innerwarden_safe_io::harden(&mut options);
        let mut file = options
            .open(&temp)
            .map_err(|e| WriteError::Failed(format!("creating {}: {e}", temp.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(mode))
                .map_err(|e| WriteError::Failed(format!("setting its mode: {e}")))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        file.write_all(body)
            .and_then(|()| file.sync_all())
            .map_err(|e| WriteError::Failed(format!("writing {}: {e}", temp.display())))?;
        drop(file);
        match std::fs::hard_link(&temp, path) {
            Ok(()) => {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(WriteError::Changed),
            Err(e) => Err(WriteError::Failed(format!(
                "creating {}: {e}",
                path.display()
            ))),
        }
    })();
    let _ = std::fs::remove_file(&temp);
    result
}

#[cfg(test)]
mod facts_tests {
    use super::*;

    /// With no profiles file and no launcher's directory the dashboard reads
    /// nothing more (no record is listed) and shows nothing new.
    ///
    /// A file that cannot be used turns them on with its problem: the hook
    /// refuses every call while it is, and the page says so.
    ///
    /// FAILS ON REVERT: return `Some` for `Off` without asking about the
    /// directory and the first row is `Some`; return `None` for `Invalid`
    /// and the unusable file is silence.
    #[test]
    fn with_the_features_off_the_dashboard_reads_and_shows_nothing_new() {
        let listed = std::cell::Cell::new(false);
        let list = || {
            listed.set(true);
            Vec::new()
        };
        assert_eq!(facts_from(ProfilesState::Off, || false, list), None);
        assert!(!listed.get(), "no record is read when off");
        assert_eq!(
            facts_from(ProfilesState::Off, || true, Vec::new),
            Some(DashboardFacts::default())
        );
        let invalid = facts_from(ProfilesState::Invalid("x".into()), || false, Vec::new)
            .expect("an unusable file is said, never silence");
        assert_eq!(invalid.profiles_problem.as_deref(), Some("x"));
        assert!(facts_from(
            ProfilesState::On(AgentProfiles::default()),
            || false,
            Vec::new
        )
        .is_some());
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn me() -> u32 {
        unsafe { libc::geteuid() }
    }

    #[test]
    fn a_new_file_is_created_whole_with_its_mode_and_never_over_another() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg/agent-profiles.toml");
        let body = b"schema_version = 1\n";
        write_profiles(&path, None, body, 0o644, false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), body);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        // No temporary file is left behind.
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        // Expecting no file when one is there: refused, the file untouched.
        assert_eq!(
            write_profiles(&path, None, b"schema_version = 1\n# x\n", 0o644, false),
            Err(WriteError::Changed)
        );
        assert_eq!(std::fs::read(&path).unwrap(), body);
    }

    /// A change made between the read and the write is never overwritten.
    #[test]
    fn a_file_changed_since_it_was_read_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent-profiles.toml");
        std::fs::write(&path, b"schema_version = 1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let read = b"schema_version = 1\n# what was read\n";
        assert_eq!(
            write_profiles(&path, Some(read), b"x", 0o600, false),
            Err(WriteError::Changed)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"schema_version = 1\n");
        write_profiles(
            &path,
            Some(b"schema_version = 1\n"),
            b"schema_version = 1\n# next\n",
            0o600,
            false,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"schema_version = 1\n# next\n"
        );
    }

    fn record(id: &str, uid: u32) -> String {
        format!(
            r#"{{"schema":1,"instance_id":"{id}","agent_type":"claude-code","launcher":{{"path":"/usr/local/bin/innerwarden","version":"1","root_owned":true}},"uid":{uid},"project":"p","mode":"enforce","started_at":"2026-10-17T09:00:00Z","jail":{{"backend":"bwrap","pid":999999999,"start_ticks":1,"pid_ns":4026532220,"mnt_ns":4026532218}}}}"#
        )
    }

    /// Only this user's own plain records are read, and a record whose pid
    /// does not run (with its start time) is not live.
    #[test]
    fn the_launchers_records_are_read_as_labels_and_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let id = "3f9a0c1e5b7d42a8c6e1f0b2d4a69c87";
        std::fs::write(dir.path().join(format!("{id}.json")), record(id, me())).unwrap();
        let other = "0000000000000000000000000000beef";
        std::fs::write(
            dir.path().join(format!("{other}.json")),
            record(other, me() + 1),
        )
        .unwrap();
        let wrong = "1111111111111111111111111111aaaa";
        std::fs::write(dir.path().join(format!("{wrong}.json")), record(id, me())).unwrap();
        std::os::unix::fs::symlink(
            dir.path().join(format!("{id}.json")),
            dir.path().join("2222222222222222222222222222bbbb.json"),
        )
        .unwrap();
        std::fs::write(dir.path().join("notes.txt"), "x").unwrap();
        let got = local_instances(dir.path(), me());
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].instance_id, id);
        assert_eq!(got[0].agent_type, "claude-code");
        assert!(!got[0].live, "pid 999999999 does not run");
        assert_eq!(got[0].trust, Trust::Declared);
        assert!(local_instances(&dir.path().join("none"), me()).is_empty());
        let facts = local_records(dir.path(), me());
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].judged, None, "an ended jail is not judged");
    }

    /// A graph the jail's hook kept in a project, with one labelled command
    /// for each `(instance, session)`.
    fn project_graph(project: &Path, runs: &[(&str, &str)]) {
        use innerwarden_graph::{
            DecisionChannel, DecisionContext, DecisionMode, DecisionOrigin, DecisionOutcome, Graph,
        };
        let mut graph = Graph::new();
        for (seq, &(id, session)) in runs.iter().enumerate() {
            graph.ingest_verdict_with_origin(
                "contain",
                seq,
                "git status",
                &serde_json::json!({"recommendation": "allow", "explanation": "no rule matched"}),
                DecisionContext {
                    mode: DecisionMode::Enforce,
                    outcome: DecisionOutcome::Allowed,
                    recorded_at_ms: Some(1_760_607_651_000),
                },
                &DecisionOrigin {
                    channel: Some(DecisionChannel::Hook),
                    agent: Some("claude-code".into()),
                    instance_id: Some(id.into()),
                    session_id: Some(session.into()),
                    trust: Some("confined".into()),
                    trust_reason: Some("confined_by_namespace".into()),
                    ..DecisionOrigin::default()
                },
            );
        }
        let dir = crate::contain::jail_graph_dir(project);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(crate::contain::JAIL_GRAPH_NAME), graph.to_json()).unwrap();
    }

    /// An instance whose launcher wrote its project path shows the sessions
    /// and the newest activity the jail's hook kept in that project's graph,
    /// read as a label (its `confined` reads `observed`). A record with no
    /// project path, a path of another folder, or a project graph that is a
    /// link adds nothing.
    ///
    /// FAILS ON REVERT: skip `add_project_activity` (or read no
    /// `.project` file) and the instance has no session.
    #[test]
    fn an_instance_shows_the_sessions_its_projects_graph_holds() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("instances");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let project = root.path().join("p");
        let id = "3f9a0c1e5b7d42a8c6e1f0b2d4a69c87";
        let bare = "0000000000000000000000000000beef";
        let other = "1111111111111111111111111111aaaa";
        let linked = "2222222222222222222222222222bbbb";
        for each in [id, bare, other, linked] {
            std::fs::write(dir.join(format!("{each}.json")), record(each, me())).unwrap();
        }
        std::fs::write(
            dir.join(format!("{id}.project")),
            format!("{}\n", project.display()),
        )
        .unwrap();
        // Another folder's path, beside a record of project `p`: not taken.
        std::fs::write(
            dir.join(format!("{other}.project")),
            format!("{}\n", root.path().join("q").display()),
        )
        .unwrap();
        project_graph(
            &project,
            &[(id, "a1b2c3d4e5f6-session"), (other, "ffff0000-session")],
        );
        project_graph(&root.path().join("q"), &[(other, "ffff0000-session")]);
        // A project whose graph folder is a link: refused, never followed.
        let elsewhere = root.path().join("elsewhere");
        project_graph(&elsewhere, &[(linked, "eeee0000-session")]);
        let linked_project = root.path().join("lp");
        std::fs::create_dir(&linked_project).unwrap();
        std::os::unix::fs::symlink(
            crate::contain::jail_graph_dir(&elsewhere),
            crate::contain::jail_graph_dir(&linked_project),
        )
        .unwrap();
        std::fs::write(
            dir.join(format!("{linked}.project")),
            format!("{}\n", root.path().join("p").display()),
        )
        .unwrap();
        let mut records = local_records(&dir, me());
        // `linked` names the project `p` by its folder; point it at the link.
        for facts in &mut records {
            if facts.record.instance_id == linked {
                facts.project_dir = Some(linked_project.clone());
            }
        }
        let by_id = |records: &[InstanceFacts], want: &str| {
            records
                .iter()
                .find(|f| f.record.instance_id == want)
                .and_then(|f| f.project_dir.clone())
        };
        assert_eq!(by_id(&records, id), Some(project.clone()));
        assert_eq!(by_id(&records, bare), None, "no .project file");
        assert_eq!(by_id(&records, other), None, "another folder's path");
        let mut facts = DashboardFacts {
            records,
            ..DashboardFacts::default()
        };
        add_project_activity(&mut facts);
        assert_eq!(
            facts.activity.keys().collect::<Vec<_>>(),
            vec![id],
            "{:?}",
            facts.activity
        );
        let seen = &facts.activity[id];
        assert_eq!(seen.last_at_ms, Some(1_760_607_651_000));
        assert_eq!(seen.sessions[0].session_id, "a1b2c3d4e5f6-session");
        let record = facts
            .records
            .iter()
            .find(|f| f.record.instance_id == id)
            .unwrap();
        let view = crate::dashboard_identity::instance_view(record, Some(seen));
        assert_eq!(view.trust, "observed");
        assert_eq!(view.sessions.len(), 1);
    }

    /// The records directory itself is read only when it is a directory of
    /// the user's own: a link to one elsewhere lists nothing.
    ///
    /// FAILS ON REVERT: drop the `own_directory` check and the linked
    /// directory's record is listed.
    #[test]
    fn a_records_directory_that_is_a_link_lists_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let id = "3f9a0c1e5b7d42a8c6e1f0b2d4a69c87";
        std::fs::write(real.join(format!("{id}.json")), record(id, me())).unwrap();
        assert_eq!(local_records(&real, me()).len(), 1);
        let link = dir.path().join("instances");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(local_records(&link, me()).is_empty());
        assert!(
            local_records(&real, me() + 1).is_empty(),
            "another user's directory"
        );
    }
}
