//! The hook's view of the instance it runs in.
//!
//! Inside a jail started with `contain --identity`, the launcher mounts a
//! record read-only at a fixed place. This module reads it (one open, no link
//! followed, bounded, owner checked), reads the hook's own PID and mount
//! namespaces and the agent the launcher started the jail for, asks
//! the pure judge in `agent-guard` what level that earns, and returns LABELS
//! for the decision record: instance id, the session id the agent sent, the
//! level and the reason for it.
//!
//! With no record there, the answer is `None` and the hook is exactly what it
//! was: no field is added anywhere. A record that is there and cannot be used
//! is `declared` with a reason; a failed read never stops a tool call.
//!
//! The labels are labels. The level is the hook's own opinion from inside the
//! jail, never above `observed` (the agent can build what the hook reads), and
//! a reader that needs more than that has to find it elsewhere.

// The jail record exists on Linux only; the decisions and their tests run everywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use innerwarden_agent_guard::identity::{
    judge_agent_claim, judge_trust_in_jail, parse_launch_record, InJailFacts, Reason, RecordRead,
    Trust,
};

/// What the hook found at the record's place, before it is parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawRecord {
    /// Nothing there that could be a record.
    Absent,
    /// Something there, and not usable: a link, not a regular file, not the
    /// user's, too large, unreadable.
    Unreadable,
    Bytes {
        bytes: Vec<u8>,
        /// The file sits on a read-only mount.
        read_only: bool,
    },
}

/// Everything the decision reads, handed in by whoever read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JailFacts {
    pub record: RawRecord,
    /// Inode of the hook's own PID namespace.
    pub own_pid_ns: Option<u64>,
    /// Inode of the hook's own mount namespace.
    pub own_mnt_ns: Option<u64>,
    /// The agent the launcher started the jail for, from its environment
    /// ([`HOOK_AGENT_ENV`]). A label, like the hook line's `--agent`: it can
    /// only hold a record's type to the hook, never raise a level.
    ///
    /// [`HOOK_AGENT_ENV`]: innerwarden_agent_guard::identity::HOOK_AGENT_ENV
    pub launcher_agent: Option<String>,
}

/// The labels a decision gets when a record was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Set only when the hook's own namespace is the recorded one. A record
    /// copied from another jail, or one that cannot be used, names no instance.
    pub instance_id: Option<String>,
    /// The session id the agent put in its payload. The agent chose it.
    pub session_id: Option<String>,
    pub trust: Trust,
    pub reason: Reason,
    /// The kind of agent the record names, set with `instance_id` only: the
    /// type whose profile a confined instance gets.
    pub agent_type: Option<String>,
}

impl Identity {
    /// The key the behavioural window is kept under. For an instance whose
    /// jail reading held in full ([`Reason::ConfinedByNamespace`]) it is the
    /// instance, so a session id the agent invents cannot start a fresh
    /// window; otherwise it is the session id, as before. Keying by the
    /// instance only ever joins calls into one window, so a record the agent
    /// wrote for itself gains nothing from it.
    pub fn behaviour_key(&self, payload_session: Option<&str>) -> Option<String> {
        match (&self.instance_id, self.reason) {
            (Some(id), Reason::ConfinedByNamespace) => Some(format!("instance:{id}")),
            _ => payload_session.map(str::to_string),
        }
    }

    /// Put the labels on a decision's origin.
    pub fn apply(&self, origin: &mut innerwarden_graph::DecisionOrigin) {
        origin.instance_id = self.instance_id.clone();
        origin.session_id = self.session_id.clone();
        origin.trust = Some(self.trust.as_str().to_string());
        origin.trust_reason = Some(self.reason.as_str().to_string());
    }

    /// The `instance` and `trust` fields of a block report to the local agent.
    pub fn report_fields(&self) -> (Option<&str>, &'static str) {
        (self.instance_id.as_deref(), self.trust.as_str())
    }
}

/// The key for the behavioural window: the instance when its jail reading
/// held in full, else the session id the payload carried.
pub fn behaviour_key(identity: Option<&Identity>, payload_session: Option<&str>) -> Option<String> {
    match identity {
        Some(identity) => identity.behaviour_key(payload_session),
        None => payload_session.map(str::to_string),
    }
}

/// PURE. The labels for `facts`, or `None` when there is no record.
///
/// `hook_agent` is the agent the hook line was wired for; `payload_session`
/// the session id the agent sent.
pub fn resolve(
    facts: &JailFacts,
    hook_agent: Option<&str>,
    payload_session: Option<&str>,
) -> Option<Identity> {
    let session_id = payload_session
        .map(crate::graph_io::bounded_session)
        .filter(|s| !s.is_empty());
    let (bytes, read_only) = match &facts.record {
        RawRecord::Absent => return None,
        RawRecord::Unreadable => {
            return Some(Identity {
                instance_id: None,
                session_id,
                trust: Trust::Declared,
                reason: Reason::RecordUnreadable,
                agent_type: None,
            })
        }
        RawRecord::Bytes { bytes, read_only } => (bytes, *read_only),
    };
    let Ok(record) = parse_launch_record(bytes) else {
        return Some(Identity {
            instance_id: None,
            session_id,
            trust: Trust::Declared,
            reason: Reason::RecordUnreadable,
            agent_type: None,
        });
    };
    let judged = judge_trust_in_jail(InJailFacts {
        record: RecordRead::Present {
            record: &record,
            read_only,
        },
        own_pid_ns: facts.own_pid_ns,
        own_mnt_ns: facts.own_mnt_ns,
    });
    // The hook line and the launcher may both name the agent: two names for
    // one hook are no name, and the line is never let to pick the record's.
    let launcher_agent = facts.launcher_agent.as_deref();
    let (trust, reason) = match (hook_agent, launcher_agent) {
        (Some(line), Some(launcher)) if line != launcher => {
            let by_line = judge_agent_claim(judged, &record.agent_type, Some(line));
            let by_launcher = judge_agent_claim(judged, &record.agent_type, Some(launcher));
            if by_line.0 <= by_launcher.0 {
                by_line
            } else {
                by_launcher
            }
        }
        (line, launcher) => judge_agent_claim(judged, &record.agent_type, line.or(launcher)),
    };
    let matched = trust > Trust::Declared;
    Some(Identity {
        instance_id: matched.then(|| record.instance_id.clone()),
        session_id,
        trust,
        reason,
        agent_type: matched.then(|| record.agent_type.clone()),
    })
}

/// Read the facts at `path`, from `/proc/self` and from the environment.
#[cfg(target_os = "linux")]
pub fn read_facts(path: &std::path::Path) -> JailFacts {
    let record = read_raw(path);
    // Without a record nothing else is read: the hook is what it was.
    if record == RawRecord::Absent {
        return JailFacts {
            record,
            own_pid_ns: None,
            own_mnt_ns: None,
            launcher_agent: None,
        };
    }
    JailFacts {
        record,
        own_pid_ns: std::fs::read_link("/proc/self/ns/pid")
            .ok()
            .and_then(|link| crate::contain::launch::parse_ns_link(&link.to_string_lossy())),
        own_mnt_ns: std::fs::read_link("/proc/self/ns/mnt")
            .ok()
            .and_then(|link| crate::contain::launch::parse_mnt_ns_link(&link.to_string_lossy())),
        launcher_agent: launcher_agent(
            std::env::var(innerwarden_agent_guard::identity::HOOK_AGENT_ENV)
                .ok()
                .as_deref(),
        ),
    }
}

/// PURE. The launcher's word for the agent, if it is a plain agent id. A value
/// that is not one is kept as a name no record carries, so it can only ever
/// lower a level.
pub fn launcher_agent(value: Option<&str>) -> Option<String> {
    let value = value?;
    if innerwarden_agent_guard::hook::is_agent_id(value) {
        Some(value.to_string())
    } else {
        Some(String::new())
    }
}

/// One open of the record: no link followed, no wait on a pipe, the facts read
/// from the open descriptor, no more than the cap read.
///
/// A path that cannot be opened for any reason but a planted link is `Absent`:
/// on a host that has a folder of that name for another purpose, the hook must
/// not start reporting.
#[cfg(target_os = "linux")]
fn read_raw(path: &std::path::Path) -> RawRecord {
    use innerwarden_agent_guard::identity::MAX_RECORD_BYTES;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    let file = match innerwarden_safe_io::open_no_follow(path) {
        Ok(file) => file,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return RawRecord::Unreadable,
        Err(_) => return RawRecord::Absent,
    };
    let Ok(meta) = file.metadata() else {
        return RawRecord::Unreadable;
    };
    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if !innerwarden_safe_io::is_regular_file(&meta)
        || meta.uid() != euid
        || meta.len() > MAX_RECORD_BYTES as u64
    {
        return RawRecord::Unreadable;
    }
    // SAFETY: an all-zero statvfs is a valid value for the kernel to fill, and
    // the descriptor stays open for the call. The two fields have different
    // integer types on different libcs, hence the casts.
    #[allow(clippy::unnecessary_cast)]
    let read_only = unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        libc::fstatvfs(file.as_raw_fd(), &mut st) == 0
            && (st.f_flag as u64) & (libc::ST_RDONLY as u64) != 0
    };
    let mut bytes = Vec::new();
    if file
        .take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > MAX_RECORD_BYTES
    {
        return RawRecord::Unreadable;
    }
    RawRecord::Bytes { bytes, read_only }
}

/// The hook's labels from the real record and the real `/proc`. Other systems
/// have no jail record: `None`.
pub fn current(hook_agent: Option<&str>, payload_session: Option<&str>) -> Option<Identity> {
    #[cfg(target_os = "linux")]
    {
        let path = std::path::Path::new(innerwarden_agent_guard::identity::JAIL_RECORD_PATH);
        resolve(&read_facts(path), hook_agent, payload_session)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (hook_agent, payload_session);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWN_NS: u64 = 4026532871;
    const OWN_MNT: u64 = 4026532869;

    const RECORD: &str = r#"{
  "schema": 1,
  "instance_id": "7f3a9c1e42b84d0e9a6c5f1b2d3e4a59",
  "agent_type": "claude-code",
  "launcher": { "path": "/usr/local/bin/innerwarden", "version": "1.6.0", "root_owned": true },
  "uid": 1000,
  "project": "my-app",
  "mode": "enforce",
  "started_at": "2026-10-16T09:30:00Z",
  "jail": { "backend": "bwrap", "pid": 48211, "start_ticks": 9120344, "pid_ns": 4026532871, "mnt_ns": 4026532869 },
  "scope": {
    "user": {
      "unit": "innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope",
      "cgroup_path": "/user.slice/user-1000.slice/user@1000.service/app.slice/innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope"
    }
  }
}"#;

    /// The facts of a hook in a jail the launcher started for `claude-code`.
    fn facts(record: &str, read_only: bool, own: Option<u64>) -> JailFacts {
        JailFacts {
            record: RawRecord::Bytes {
                bytes: record.as_bytes().to_vec(),
                read_only,
            },
            own_pid_ns: own,
            own_mnt_ns: Some(OWN_MNT),
            launcher_agent: Some("claude-code".into()),
        }
    }

    /// A forged version 2 record, field and all, reads exactly as the version
    /// 1 record: `observed`, never more. A record of a version this build does
    /// not know reads as unreadable (`declared`), not as anything above.
    ///
    /// FAILS ON REVERT: let the hook's reading use `userns_closed` to raise
    /// the level, or read a schema it does not know.
    #[test]
    fn a_record_that_says_user_namespaces_are_closed_is_still_only_observed() {
        let v2 = RECORD.replace("\"schema\": 1", "\"schema\": 2").replace(
            "\"mnt_ns\": 4026532869 }",
            "\"mnt_ns\": 4026532869, \"userns_closed\": true }",
        );
        assert_ne!(v2, RECORD);
        let read = |record: &str| {
            resolve(
                &facts(record, true, Some(OWN_NS)),
                Some("claude-code"),
                None,
            )
            .unwrap()
        };
        let (with, without) = (read(&v2), read(RECORD));
        assert_eq!((with.trust, with.reason), (without.trust, without.reason));
        assert_eq!(with.trust, Trust::Observed);
        let newer = v2.replace("\"schema\": 2", "\"schema\": 3");
        let unknown = read(&newer);
        assert_eq!(
            (unknown.trust, unknown.reason),
            (Trust::Declared, Reason::RecordUnreadable)
        );
        assert_eq!(unknown.instance_id, None);
    }

    #[test]
    fn no_record_means_no_labels_at_all() {
        let none = JailFacts {
            record: RawRecord::Absent,
            own_pid_ns: Some(OWN_NS),
            own_mnt_ns: Some(OWN_MNT),
            launcher_agent: Some("claude-code".into()),
        };
        assert_eq!(resolve(&none, Some("claude-code"), Some("abc")), None);
    }

    /// The launcher's jail, read from inside, as well as a reading can go:
    /// `observed`, the instance named.
    #[test]
    fn the_recorded_namespace_on_a_read_only_record_is_observed() {
        let id = resolve(
            &facts(RECORD, true, Some(OWN_NS)),
            Some("claude-code"),
            Some("payload-session"),
        )
        .unwrap();
        assert_eq!(id.trust, Trust::Observed);
        assert_eq!(id.reason, Reason::ConfinedByNamespace);
        assert_eq!(
            id.instance_id.as_deref(),
            Some("7f3a9c1e42b84d0e9a6c5f1b2d3e4a59")
        );
        assert_eq!(id.session_id.as_deref(), Some("payload-session"));
        assert_eq!(id.agent_type.as_deref(), Some("claude-code"));
    }

    /// A record carried into another jail (or copied by the agent) is not this
    /// process's record.
    ///
    /// FAILS ON REVERT: skip comparing the namespace and this sees `observed`
    /// and the instance id.
    #[test]
    fn a_record_of_another_jail_is_declared_and_names_no_instance() {
        let id = resolve(
            &facts(RECORD, true, Some(OWN_NS + 1)),
            Some("claude-code"),
            None,
        )
        .unwrap();
        assert_eq!(id.trust, Trust::Declared);
        assert_eq!(id.reason, Reason::NamespaceMismatch);
        assert_eq!(id.instance_id, None);
        assert_eq!(
            id.agent_type, None,
            "a record of another jail names no type"
        );
    }

    #[test]
    fn a_record_the_agent_could_write_is_declared() {
        let id = resolve(&facts(RECORD, false, Some(OWN_NS)), None, None).unwrap();
        assert_eq!(
            (id.trust, id.reason),
            (Trust::Declared, Reason::RecordWritable)
        );
        assert_eq!(id.instance_id, None);
    }

    #[test]
    fn a_record_that_cannot_be_used_is_declared_with_the_reason() {
        for raw in [
            RawRecord::Unreadable,
            RawRecord::Bytes {
                bytes: b"not json".to_vec(),
                read_only: true,
            },
        ] {
            let id = resolve(
                &JailFacts {
                    record: raw,
                    own_pid_ns: Some(OWN_NS),
                    own_mnt_ns: Some(OWN_MNT),
                    launcher_agent: None,
                },
                None,
                Some("s"),
            )
            .unwrap();
            assert_eq!(
                (id.trust, id.reason, id.instance_id),
                (Trust::Declared, Reason::RecordUnreadable, None)
            );
        }
    }

    /// The hook line and the record must agree on the kind of agent.
    ///
    /// FAILS ON REVERT: skip `judge_agent_claim` and this sees `observed`.
    #[test]
    fn a_hook_wired_for_another_agent_than_the_record_is_declared() {
        let id = resolve(&facts(RECORD, true, Some(OWN_NS)), Some("cursor"), None).unwrap();
        assert_eq!(
            (id.trust, id.reason),
            (Trust::Declared, Reason::AgentMismatch)
        );
        assert_eq!(id.instance_id, None);
    }

    /// A process in the jail's PID namespace that made a mount namespace of its
    /// own (`unshare -Urm`, then a record of its choosing mounted read-only at
    /// the record's place) is not in the launcher's jail.
    ///
    /// FAILS ON REVERT: hand `own_mnt_ns` to the judge as the recorded one (or
    /// drop the mount namespace rows) and this sees `observed`.
    #[test]
    fn a_hook_in_another_mount_namespace_is_declared_and_names_no_instance() {
        let mut nested = facts(RECORD, true, Some(OWN_NS));
        nested.own_mnt_ns = Some(OWN_MNT + 3);
        let id = resolve(&nested, Some("claude-code"), None).unwrap();
        assert_eq!(
            (id.trust, id.reason),
            (Trust::Declared, Reason::MountNamespaceMismatch)
        );
        assert_eq!((id.instance_id, id.agent_type), (None, None));
        nested.own_mnt_ns = None;
        let id = resolve(&nested, Some("claude-code"), None).unwrap();
        assert_eq!(
            (id.trust, id.reason),
            (Trust::Declared, Reason::OwnMountNamespaceUnreadable)
        );
    }

    /// A nested PID namespace (`unshare -Upf`) reads another PID namespace
    /// than the recorded one, even with the jail's mount namespace.
    #[test]
    fn a_hook_in_a_nested_pid_namespace_is_declared() {
        let id = resolve(
            &facts(RECORD, true, Some(OWN_NS + 11)),
            Some("claude-code"),
            None,
        )
        .unwrap();
        assert_eq!(
            (id.trust, id.reason),
            (Trust::Declared, Reason::NamespaceMismatch)
        );
    }

    /// The launcher's word for the agent holds the record's type to the hook:
    /// a line wired for another agent, a launcher word for another, or two
    /// different names are `declared`; with no name at all nothing ties the
    /// record to this hook.
    ///
    /// FAILS ON REVERT: ignore `launcher_agent` in `resolve` and the second
    /// and third cases see `observed`.
    #[test]
    fn the_launchers_agent_must_be_the_records_type() {
        let mut other = facts(RECORD, true, Some(OWN_NS));
        other.launcher_agent = Some("cursor".into());
        let cases = [
            (other.clone(), None, Reason::AgentMismatch),
            (other.clone(), Some("claude-code"), Reason::AgentMismatch),
            (
                facts(RECORD, true, Some(OWN_NS)),
                Some("cursor"),
                Reason::AgentMismatch,
            ),
            (
                JailFacts {
                    launcher_agent: Some(String::new()),
                    ..facts(RECORD, true, Some(OWN_NS))
                },
                None,
                Reason::AgentMismatch,
            ),
            (
                JailFacts {
                    launcher_agent: None,
                    ..facts(RECORD, true, Some(OWN_NS))
                },
                None,
                Reason::AgentNotNamed,
            ),
        ];
        for (facts, line, reason) in cases {
            let id = resolve(&facts, line, None).unwrap();
            assert_eq!(
                (id.trust, id.reason, id.instance_id.as_deref()),
                (Trust::Declared, reason, None),
                "{:?} {line:?}",
                facts.launcher_agent
            );
        }
        // The launcher's word alone, or with the same line, keeps the level.
        for line in [None, Some("claude-code")] {
            let id = resolve(&facts(RECORD, true, Some(OWN_NS)), line, None).unwrap();
            assert_eq!(
                (id.trust, id.reason),
                (Trust::Observed, Reason::ConfinedByNamespace),
                "{line:?}"
            );
        }
        // A hook line alone, with the launcher's word absent, still holds.
        let line_only = JailFacts {
            launcher_agent: None,
            ..facts(RECORD, true, Some(OWN_NS))
        };
        assert_eq!(
            resolve(&line_only, Some("claude-code"), None)
                .unwrap()
                .reason,
            Reason::ConfinedByNamespace
        );
    }

    #[test]
    fn the_launchers_agent_is_read_as_an_agent_id_or_as_no_type() {
        assert_eq!(launcher_agent(None), None);
        assert_eq!(
            launcher_agent(Some("claude-code")).as_deref(),
            Some("claude-code")
        );
        for bad in ["", "Claude", "a b", "../x"] {
            assert_eq!(launcher_agent(Some(bad)).as_deref(), Some(""), "{bad:?}");
        }
    }

    #[test]
    fn a_per_user_launcher_is_observed_at_most() {
        let user_install = RECORD.replace("\"root_owned\": true", "\"root_owned\": false");
        let id = resolve(&facts(&user_install, true, Some(OWN_NS)), None, None).unwrap();
        assert_eq!(
            (id.trust, id.reason),
            (Trust::Observed, Reason::LauncherNotTrusted)
        );
        assert_eq!(
            id.instance_id.as_deref(),
            Some("7f3a9c1e42b84d0e9a6c5f1b2d3e4a59")
        );
    }

    /// A session id the agent invents must not start a fresh behavioural
    /// window for an instance whose jail reading held.
    ///
    /// FAILS ON REVERT: key by the payload session always and the two keys
    /// differ.
    #[test]
    fn a_jailed_instance_keeps_one_window_whatever_session_it_claims() {
        let id = resolve(&facts(RECORD, true, Some(OWN_NS)), None, Some("a")).unwrap();
        assert_eq!(
            behaviour_key(Some(&id), Some("a")),
            behaviour_key(Some(&id), Some("a-forged-new-one"))
        );
        assert_eq!(
            behaviour_key(Some(&id), None).as_deref(),
            Some("instance:7f3a9c1e42b84d0e9a6c5f1b2d3e4a59")
        );
    }

    #[test]
    fn a_partial_reading_and_no_record_key_the_window_as_before() {
        let declared = resolve(&facts(RECORD, false, Some(OWN_NS)), None, None).unwrap();
        assert_eq!(
            behaviour_key(Some(&declared), Some("s")).as_deref(),
            Some("s")
        );
        assert_eq!(behaviour_key(Some(&declared), None), None);
        assert_eq!(behaviour_key(None, Some("s")).as_deref(), Some("s"));
        let user_install = RECORD.replace("\"root_owned\": true", "\"root_owned\": false");
        let observed = resolve(&facts(&user_install, true, Some(OWN_NS)), None, None).unwrap();
        assert_eq!(
            behaviour_key(Some(&observed), Some("s")).as_deref(),
            Some("s")
        );
    }

    #[test]
    fn a_session_id_is_bounded_and_empty_is_dropped() {
        let long = "x".repeat(500);
        let id = resolve(&facts(RECORD, true, Some(OWN_NS)), None, Some(&long)).unwrap();
        assert_eq!(id.session_id.unwrap().chars().count(), 120);
        let id = resolve(&facts(RECORD, true, Some(OWN_NS)), None, Some("   ")).unwrap();
        assert_eq!(id.session_id, None);
    }

    // -- the reads, on a real folder (Linux) ---------------------------------

    #[cfg(target_os = "linux")]
    mod io {
        use super::super::*;
        use std::os::unix::fs::symlink;

        #[test]
        fn a_missing_file_or_folder_is_absent_and_nothing_is_created() {
            let dir = tempfile::tempdir().unwrap();
            assert_eq!(
                read_raw(&dir.path().join("nope/instance.json")),
                RawRecord::Absent
            );
            assert_eq!(
                read_raw(&dir.path().join("instance.json")),
                RawRecord::Absent
            );
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        }

        #[test]
        fn a_planted_link_is_refused_and_not_followed() {
            let dir = tempfile::tempdir().unwrap();
            let real = dir.path().join("real.json");
            std::fs::write(&real, super::RECORD).unwrap();
            let link = dir.path().join("instance.json");
            symlink(&real, &link).unwrap();
            assert_eq!(read_raw(&link), RawRecord::Unreadable);
        }

        #[test]
        fn a_folder_or_an_oversize_file_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let folder = dir.path().join("instance.json");
            std::fs::create_dir(&folder).unwrap();
            assert_eq!(read_raw(&folder), RawRecord::Unreadable);
            let big = dir.path().join("big.json");
            std::fs::write(&big, vec![b' '; 16 * 1024 + 1]).unwrap();
            assert_eq!(read_raw(&big), RawRecord::Unreadable);
        }

        #[test]
        fn a_fifo_does_not_hang_the_hook() {
            let dir = tempfile::tempdir().unwrap();
            let fifo = dir.path().join("instance.json");
            let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            assert_eq!(read_raw(&fifo), RawRecord::Unreadable);
        }

        /// A record on an ordinary folder is read and is NOT on a read-only
        /// mount, so it can never be more than `declared`.
        #[test]
        fn a_file_on_a_writable_folder_is_not_read_only() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("instance.json");
            std::fs::write(&path, super::RECORD).unwrap();
            match read_raw(&path) {
                RawRecord::Bytes { bytes, read_only } => {
                    assert_eq!(bytes, super::RECORD.as_bytes());
                    assert!(!read_only);
                }
                other => panic!("{other:?}"),
            }
        }
    }
}
