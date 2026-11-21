//! Places a tool call that deletes, moves or writes must never reach, read
//! from the path it names (`AG-PROTECTED-TARGET`).
//!
//! A call whose tool's name says it deletes, moves or writes, and whose
//! target is the root, a folder of the system, a whole home or a store of
//! keys, is refused in every posture that refuses (`guard`, `strict`,
//! `kill`); the monitor modes record it. It is a builtin rule, never one
//! the default posture makes a warning: `delete_directory {"path": "/etc"}`
//! was refused by nothing, only the non-blocking ATR-2026-099 matched it.
//!
//! What counts, after `file://`, `.`, `..` and `/private` (macOS's real
//! `/etc` and `/var`) are taken out, case folded:
//!
//! * the root: `/`, `C:\\`;
//! * a folder of the operating system, at any depth: `/etc`, `/usr` (but
//!   below `/usr/local/<dir>`), `/bin`, `/sbin`, `/lib*`, `/boot`,
//!   `/sys`, `/proc`, `/dev`, `/System`, `C:\\Windows`;
//! * a folder at the top of the system tree, or one level in: `/var`,
//!   `/var/lib`, `/opt`, `/opt/app`, `/srv`, `/mnt/backup`, `/media`,
//!   `/run`, `/snap`, `/Library`, `/Applications`, `/Volumes/disk`,
//!   `C:\\Program Files\\App`. Deeper is ordinary work (`/var/www/site/x`,
//!   `/opt/app/logs/x`, `/var/tmp/x`);
//! * a whole home: `~`, `$HOME`, `/home/u`, `/Users/u`, `/root`,
//!   `/var/home/u`, `/home`, `C:\\Users\\u`;
//! * a store of keys, or anything in it, in any home or the system's:
//!   `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`, `.pki`,
//!   `.password-store`, `.config/gcloud`, `.local/share/keyrings`,
//!   `Library/Keychains`.
//!
//! A relative path is not judged: where it lands depends on a folder this
//! check does not know. Links are not followed. Pure.

/// The rule a refusal by this module is reported under.
pub const PROTECTED_TARGET_RULE: &str = "AG-PROTECTED-TARGET";

/// Words of a tool's name that say it deletes, moves or writes. The forms a
/// verb takes as a word (`writes`, `writer`, `editor`) count; its past
/// (`created`) does not.
const CHANGE_VERBS: &[&str] = &[
    "delete",
    "del",
    "remove",
    "rm",
    "rmdir",
    "unlink",
    "trash",
    "erase",
    "wipe",
    "destroy",
    "purge",
    "move",
    "mv",
    "rename",
    "write",
    "overwrite",
    "create",
    "mkdir",
    "edit",
    "save",
    "append",
    "truncate",
    "replace",
    "copy",
    "cp",
    "put",
    "upload",
];

/// Top folders of the operating system: one of them, or anything under it.
const SYSTEM_ANY_DEPTH: &[&str] = &[
    "bin", "sbin", "etc", "boot", "lib", "lib32", "lib64", "libx32", "sys", "proc", "dev", "system",
];

/// Top folders that hold the system's and its users' data: one of them, or
/// a folder right in it.
const SYSTEM_SHALLOW: &[&str] = &[
    "var",
    "opt",
    "srv",
    "mnt",
    "media",
    "run",
    "snap",
    "library",
    "applications",
    "cores",
    "volumes",
    "nix",
];

/// Stores of keys, as the path from a home (or from the root, for the
/// system's own keychains).
const KEY_STORES: &[&[&str]] = &[
    &[".ssh"],
    &[".gnupg"],
    &[".aws"],
    &[".azure"],
    &[".kube"],
    &[".docker"],
    &[".pki"],
    &[".password-store"],
    &[".config", "gcloud"],
    &[".local", "share", "keyrings"],
    &["library", "keychains"],
];

/// The lowercase words of a tool's name, split at anything that is not a
/// letter or a digit and at lower-to-upper case changes.
fn name_words(name: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut previous_lower = false;
    for c in name.chars() {
        if !c.is_alphanumeric() {
            words.extend((!word.is_empty()).then(|| std::mem::take(&mut word)));
            previous_lower = false;
            continue;
        }
        if c.is_uppercase() && previous_lower {
            words.push(std::mem::take(&mut word));
        }
        previous_lower = c.is_lowercase() || c.is_ascii_digit();
        word.extend(c.to_lowercase());
    }
    words.extend((!word.is_empty()).then_some(word));
    words
}

/// Whether a tool's name says it deletes, moves or writes ([`CHANGE_VERBS`]).
pub(crate) fn name_says_it_changes(tool_name: &str) -> bool {
    name_words(tool_name).iter().any(|word| {
        CHANGE_VERBS.iter().any(|verb| {
            word.strip_prefix(verb)
                .is_some_and(|rest| matches!(rest, "" | "s" | "r" | "or" | "er"))
        })
    })
}

/// What a path names, when it is a place this module protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protected {
    Root,
    SystemFolder,
    Home,
    KeyStore,
}

impl Protected {
    fn what(self) -> &'static str {
        match self {
            Protected::Root => "the root of the file system",
            Protected::SystemFolder => "a folder of the system",
            Protected::Home => "a whole home",
            Protected::KeyStore => "a store of keys",
        }
    }
}

/// Whether `parts` (from a home) is or is in a store of keys.
fn in_key_store(parts: &[&str]) -> bool {
    KEY_STORES
        .iter()
        .any(|store| parts.len() >= store.len() && parts[..store.len()] == **store)
}

/// What `text`, read as an absolute or home path, names, if it is a place
/// this module protects. See the module documentation.
pub(crate) fn protected_target(text: &str) -> Option<Protected> {
    let raw = text.trim().trim_matches(|c| c == '"' || c == '\'');
    let raw = match raw.get(..7) {
        Some(scheme) if scheme.eq_ignore_ascii_case("file://") => &raw[7..],
        _ => raw,
    };
    let raw = match raw.get(..9) {
        Some(host) if host.eq_ignore_ascii_case("localhost") => &raw[9..],
        _ => raw,
    };
    if raw.is_empty() || raw.contains(['\n', '\0']) {
        return None;
    }
    let lower = raw.replace('\\', "/").to_lowercase();
    let bytes = lower.as_bytes();
    // A Windows drive.
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        if bytes.len() > 2 && bytes[2] != b'/' {
            return None;
        }
        let parts = collapse(&lower[2..], true)?;
        return match parts.as_slice() {
            [] => Some(Protected::Root),
            ["windows", ..] => Some(Protected::SystemFolder),
            [top] | [top, _]
                if ["program files", "program files (x86)", "programdata"].contains(top) =>
            {
                Some(Protected::SystemFolder)
            }
            ["users"] | ["users", _] => Some(Protected::Home),
            ["users", _, rest @ ..] if in_key_store(rest) => Some(Protected::KeyStore),
            _ => None,
        };
    }
    // From a home.
    let home_body = if let Some(rest) = lower.strip_prefix('~') {
        match rest.split_once('/') {
            Some((_, after)) => Some(after.to_string()),
            None => Some(String::new()),
        }
    } else {
        ["$home", "${home}"]
            .iter()
            .find_map(|name| lower.strip_prefix(name))
            .filter(|rest| rest.is_empty() || rest.starts_with('/'))
            .map(str::to_string)
    };
    if let Some(body) = home_body {
        let parts = collapse(&body, true)?;
        return if parts.is_empty() {
            Some(Protected::Home)
        } else if in_key_store(&parts) {
            Some(Protected::KeyStore)
        } else {
            None
        };
    }
    if !lower.starts_with('/') {
        return None;
    }
    let mut parts = collapse(&lower, true)?;
    // macOS: /private/etc is /etc, /private/var is /var, /private/tmp is /tmp.
    if parts.first() == Some(&"private") {
        if parts.len() == 1 {
            return Some(Protected::SystemFolder);
        }
        parts.remove(0);
    }
    let Some(&first) = parts.first() else {
        return Some(Protected::Root);
    };
    // A home: its root folder, a home itself, or a store of keys in it.
    let home_at = match parts.as_slice() {
        ["home" | "users", ..] => Some(1),
        ["var", "home", ..] => Some(2),
        ["root", ..] => Some(0),
        _ => None,
    };
    if let Some(at) = home_at {
        if first == "root" {
            return if parts.len() == 1 {
                Some(Protected::Home)
            } else if in_key_store(&parts[1..]) {
                Some(Protected::KeyStore)
            } else {
                None
            };
        }
        return if parts.len() <= at + 1 {
            Some(Protected::Home)
        } else if in_key_store(&parts[at + 1..]) {
            Some(Protected::KeyStore)
        } else {
            None
        };
    }
    if in_key_store(&parts) {
        return Some(Protected::KeyStore);
    }
    if first == "usr" {
        // /usr/local/<dir>/... is where a person installs by hand.
        let installed_by_hand = parts.get(1) == Some(&"local") && parts.len() > 3;
        return (!installed_by_hand).then_some(Protected::SystemFolder);
    }
    if SYSTEM_ANY_DEPTH.contains(&first) {
        return Some(Protected::SystemFolder);
    }
    if SYSTEM_SHALLOW.contains(&first) && parts.len() <= 2 {
        return Some(Protected::SystemFolder);
    }
    if first == "tmp" && parts.len() == 1 {
        return Some(Protected::SystemFolder);
    }
    None
}

/// The parts of an absolute path with `.` and `..` taken out; `None` for a
/// path that climbs above its start when `rooted` is false (never, here:
/// every caller passes a rooted path, where `..` at the top stays there).
fn collapse(path: &str, rooted: bool) -> Option<Vec<&str>> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() && !rooted {
                    return None;
                }
            }
            other => parts.push(other.trim_end_matches([' ', '.'])),
        }
    }
    Some(parts.into_iter().filter(|part| !part.is_empty()).collect())
}

/// Arguments whose strings are what is written, never where.
const CONTENT_KEYS: &[&str] = &[
    "content",
    "contents",
    "text",
    "body",
    "data",
    "message",
    "oldtext",
    "newtext",
    "oldstr",
    "newstr",
    "oldstring",
    "newstring",
    "filetext",
    "patch",
    "diff",
    "description",
    "title",
    "comment",
    "query",
];

fn canonical_key(key: &str) -> String {
    key.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Argument names that say where a call acts, compared lower case with
/// letters and digits only (`file_path` is `filepath`).
const TARGET_KEYS: &[&str] = &[
    "path",
    "paths",
    "file",
    "files",
    "filename",
    "filepath",
    "source",
    "sources",
    "src",
    "sourcepath",
    "destination",
    "dest",
    "dst",
    "destpath",
    "target",
    "targets",
    "targetpath",
    "to",
    "from",
    "old",
    "new",
    "oldpath",
    "newpath",
    "dir",
    "dirpath",
    "directory",
    "folder",
    "folderpath",
    "location",
    "uri",
    "output",
    "outputpath",
];

/// The first protected place a string of the call names as a whole, at any
/// depth outside [`CONTENT_KEYS`]. Only a whole string counts: a sentence
/// that mentions `/etc` is not a target. A string with a space in it counts
/// only under an argument that says where the call acts ([`TARGET_KEYS`]):
/// `"/Volumes/Macintosh HD"` there is a path, and `"/usr/bin/python3 is the
/// default interpreter"` in a note is a sentence.
fn first_protected(args: &serde_json::Value) -> Option<(String, Protected)> {
    let mut pending = vec![(args, false)];
    while let Some((value, at_target)) = pending.pop() {
        match value {
            serde_json::Value::String(text) => {
                if !at_target && text.trim().contains(char::is_whitespace) {
                    continue;
                }
                if let Some(found) = protected_target(text) {
                    return Some((text.clone(), found));
                }
            }
            serde_json::Value::Array(items) => {
                pending.extend(items.iter().map(|item| (item, at_target)));
            }
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    let key_name = canonical_key(key);
                    if CONTENT_KEYS.contains(&key_name.as_str()) {
                        continue;
                    }
                    // A map held where a call writes may key its paths.
                    if !key.trim().contains(char::is_whitespace) {
                        if let Some(found) = protected_target(key) {
                            return Some((key.clone(), found));
                        }
                    }
                    pending.push((value, at_target || TARGET_KEYS.contains(&key_name.as_str())));
                }
            }
            _ => {}
        }
    }
    None
}

/// The `AG-PROTECTED-TARGET` refusal of a call that deletes, moves or
/// writes the root, a folder of the system, a whole home or a store of keys.
/// `None` for any other call, and for one whose name does not say it
/// changes anything.
pub(crate) fn protected_target_alert(
    tool_name: &str,
    args: &serde_json::Value,
) -> Option<crate::mcp::VerdictAlert> {
    if !name_says_it_changes(tool_name) {
        return None;
    }
    let (path, found) = first_protected(args)?;
    let shown: String = crate::redact::redact_secrets(&path)
        .text
        .chars()
        .take(160)
        .collect();
    Some(crate::mcp::VerdictAlert::builtin(
        PROTECTED_TARGET_RULE,
        format!(
            "{tool_name} would delete, move or write `{shown}`, {}: refused in every posture that refuses",
            found.what()
        ),
        true,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_places_named_by_the_card_are_protected() {
        for (path, want) in [
            ("/", Protected::Root),
            ("C:\\", Protected::Root),
            ("/etc", Protected::SystemFolder),
            ("/etc/", Protected::SystemFolder),
            ("/ETC/passwd", Protected::SystemFolder),
            ("/private/etc", Protected::SystemFolder),
            ("/private", Protected::SystemFolder),
            ("/usr/lib", Protected::SystemFolder),
            ("/usr/local/bin", Protected::SystemFolder),
            ("/var", Protected::SystemFolder),
            ("/var/lib", Protected::SystemFolder),
            ("/tmp", Protected::SystemFolder),
            ("/home/../etc", Protected::SystemFolder),
            ("file:///etc", Protected::SystemFolder),
            ("C:\\Windows\\System32", Protected::SystemFolder),
            ("/home", Protected::Home),
            ("/home/alice", Protected::Home),
            ("/home/alice/", Protected::Home),
            ("/Users/alice", Protected::Home),
            ("/var/home/alice", Protected::Home),
            ("/root", Protected::Home),
            ("~", Protected::Home),
            ("~/", Protected::Home),
            ("$HOME", Protected::Home),
            ("${HOME}/", Protected::Home),
            ("C:\\Users\\alice", Protected::Home),
            ("~/.ssh", Protected::KeyStore),
            ("~/.ssh/id_ed25519", Protected::KeyStore),
            ("/home/alice/.gnupg", Protected::KeyStore),
            ("/Users/alice/Library/Keychains", Protected::KeyStore),
            ("/root/.aws/credentials", Protected::KeyStore),
            ("$HOME/.config/gcloud", Protected::KeyStore),
            ("C:\\Users\\alice\\.ssh", Protected::KeyStore),
        ] {
            assert_eq!(protected_target(path), Some(want), "{path}");
        }
    }

    #[test]
    fn ordinary_work_is_not_protected() {
        for path in [
            "notes.txt",
            "./build",
            "../etc",
            "/tmp/x",
            "/tmp/build/out",
            "/var/tmp/cache.bin",
            "/var/www/site/old.html",
            "/opt/app/logs/x.log",
            "/usr/local/bin/mytool",
            "/home/alice/project",
            "/home/alice/project/src/main.rs",
            "/Users/alice/Documents/report.md",
            "~/project/out",
            "~/.bashrc.bak2/x",
            "/root/build/x",
            "C:\\Users\\alice\\project",
            "https://example.com/etc",
            "etc",
            "",
        ] {
            assert_eq!(protected_target(path), None, "{path}");
        }
    }

    #[test]
    fn a_change_to_a_protected_place_is_refused() {
        for (tool, args) in [
            ("delete_directory", json!({"path": "/etc"})),
            ("delete_file", json!({"path": "/etc/passwd"})),
            ("remove", json!({"target": "/"})),
            (
                "move_file",
                json!({"source": "/home/alice", "destination": "/tmp/x"}),
            ),
            ("moveFile", json!({"from": "/tmp/x", "to": "/usr/bin/ls"})),
            (
                "write_file",
                json!({"path": "~/.ssh/authorized_keys", "content": "x"}),
            ),
            ("trash", json!({"paths": ["/tmp/a", "/Users/alice"]})),
            ("fs.rmdir", json!({"dir": "/var"})),
            ("rename", json!({"old": "~/.gnupg", "new": "~/g"})),
            ("delete_directory", json!({"path": "/Volumes/Macintosh HD"})),
        ] {
            let alert = protected_target_alert(tool, &args)
                .unwrap_or_else(|| panic!("{tool} {args} not refused"));
            assert_eq!(alert.rule, PROTECTED_TARGET_RULE);
            assert!(alert.block);
        }
    }

    #[test]
    fn a_read_or_ordinary_change_is_not_refused() {
        for (tool, args) in [
            ("read_file", json!({"path": "/etc/hosts"})),
            ("list_directory", json!({"path": "/"})),
            ("delete_file", json!({"path": "/tmp/build/out.o"})),
            ("delete_file", json!({"file_id": "13"})),
            (
                "write_file",
                json!({"path": "notes.txt", "content": "/etc"}),
            ),
            ("create_issue", json!({"title": "/etc", "body": "/"})),
            (
                "send_email",
                json!({"recipients": ["a@b.c"], "body": "rm /etc"}),
            ),
            (
                "move_file",
                json!({"source": "a.txt", "destination": "b.txt"}),
            ),
            ("created_list", json!({"path": "/etc"})),
            (
                "create_entities",
                json!({"entities": [{"name": "env", "observations": ["/usr/bin/python3 is the default interpreter"]}]}),
            ),
        ] {
            assert!(
                protected_target_alert(tool, &args).is_none(),
                "{tool} {args} refused"
            );
        }
    }
}
