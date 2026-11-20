//! Whether Codex CLI will run a hook this crate installed.
//!
//! Codex runs a command hook only after the person has trusted that exact
//! hook. The trust is one record in `~/.codex/config.toml`, keyed by where the
//! hook sits and holding a hash of its command and timeout:
//!
//! ```toml
//! [hooks.state."/home/me/.codex/hooks.json:pre_tool_use:0:0"]
//! trusted_hash = "sha256:..."
//! ```
//!
//! A hook with no record, or whose command or timeout changed after the record
//! was written, is skipped without a word, and the tool call runs unscreened.
//! So an entry in `hooks.json` is not a hook that is on. Two things live here:
//!
//! - [`offline`] reads the record the way Codex does, for `status` and the
//!   listing: no process is started. The hash is the one Codex CLI 0.167.2
//!   computes. A later Codex that hashes differently makes this answer "not
//!   trusted" for a hook that is, never the reverse.
//! - [`grant`] asks Codex itself, through its app-server, to trust the hook.
//!   `agents connect` runs it: the person ran that command to turn the hook
//!   on. Codex names the hash it stores, so nothing here writes a record
//!   Codex does not accept. Its answer is not the proof that the hook runs:
//!   the program started is the first `codex` on the PATH, and another
//!   program placed in front of it can answer "trusted" and write nothing.
//!   `agents connect` reads the record with [`offline`] afterwards and
//!   only that decides.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use toml_edit::{DocumentMut, Item};

/// The event as a key under `hooks.state` spells it.
const EVENT_KEY: &str = "pre_tool_use";

/// The same event as the app-server lists it.
const EVENT_LISTED: &str = "preToolUse";

/// How long [`grant`] gives Codex for the whole exchange: start, three
/// answers and one write. One bound for all of it, so a Codex that hangs
/// costs `agents connect` this long once and never longer.
pub const GRANT_WAIT: Duration = Duration::from_secs(15);

/// The most [`grant`] reads of what Codex prints. A listing of hooks is a few
/// kilobytes; past this the reading stops and the exchange ends unanswered.
const MAX_ANSWER_BYTES: u64 = 4 * 1024 * 1024;

/// The hash Codex stores when a `PreToolUse` command hook with no matcher is
/// trusted, for this command and this timeout in seconds.
///
/// The text hashed is written out by hand because the text is the contract:
/// these keys in this order, no spaces, the command as a JSON string.
pub fn hook_hash(command: &str, timeout_seconds: u64) -> String {
    let command = Value::String(command.to_string());
    let text = format!(
        "{{\"event_name\":\"{EVENT_KEY}\",\"hooks\":[{{\"async\":false,\"command\":{command},\
         \"timeout\":{timeout_seconds},\"type\":\"command\"}}]}}"
    );
    let hex: String = Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("sha256:{hex}")
}

/// One hook as Codex identifies it: the file it is in, where it sits under
/// `PreToolUse`, and the two values the trusted hash covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Place<'a> {
    /// The hooks file, as an absolute path.
    pub file: &'a Path,
    /// The position of the hook's group in the `PreToolUse` list.
    pub group: usize,
    /// The position of the hook inside that group.
    pub index: usize,
    /// The command line of the hook, exactly as the file holds it.
    pub command: &'a str,
    /// Its timeout, in seconds.
    pub timeout: u64,
}

/// What Codex's config says about one hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Trusted with this command and timeout, and not switched off.
    Trusted,
    /// Codex skips it.
    Skipped(Skip),
}

/// Why Codex skips a hook that is in its hooks file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// No record of trust for it, or no config to hold one.
    NotTrusted,
    /// Trusted once, with another command or timeout.
    Changed,
    /// Its record says `enabled = false`.
    SwitchedOff,
    /// `[features]` switches hooks off for every hook.
    HooksOff,
}

impl Skip {
    /// The reason in words, to follow "Codex skips it: ".
    pub fn words(self) -> &'static str {
        match self {
            Self::NotTrusted => "it is not trusted yet",
            Self::Changed => "it changed after it was trusted",
            Self::SwitchedOff => "it is switched off (`enabled = false`)",
            Self::HooksOff => "hooks are switched off under [features]",
        }
    }
}

/// Read, without starting Codex, whether it runs the hook at `place`.
///
/// `config` is `~/.codex/config.toml`, `None` when it is missing or does not
/// parse. Everything that cannot be established is "skipped": a hook reported
/// off that runs costs a second `agents connect`, and a hook reported on that
/// Codex skips costs every tool call it was meant to screen.
///
/// Not read here, because it is not in this file: `codex --disable hooks` on
/// the command line, and a switch inside a profile the person selects.
pub fn offline(config: Option<&DocumentMut>, place: Place<'_>) -> Trust {
    let Some(config) = config else {
        return Trust::Skipped(Skip::NotTrusted);
    };
    if hooks_switched_off(config) {
        return Trust::Skipped(Skip::HooksOff);
    }
    let Some(record) = record(config, place) else {
        return Trust::Skipped(Skip::NotTrusted);
    };
    if record.enabled == Some(false) {
        return Trust::Skipped(Skip::SwitchedOff);
    }
    match record.trusted_hash {
        None => Trust::Skipped(Skip::NotTrusted),
        Some(hash) if hash == hook_hash(place.command, place.timeout) => Trust::Trusted,
        Some(_) => Trust::Skipped(Skip::Changed),
    }
}

/// Take the record of trust for the hook at `place` out of Codex's config,
/// when it is the record for this command and timeout. Run when the hook
/// itself is removed, so a disconnect leaves nothing of ours behind. A record
/// holding any other hash is not provably ours and stays. Returns whether the
/// config changed.
pub fn forget(config: &mut DocumentMut, place: Place<'_>) -> bool {
    let ours = hook_hash(place.command, place.timeout);
    let Some(state) = config
        .get_mut("hooks")
        .and_then(|hooks| hooks.get_mut("state"))
        .and_then(Item::as_table_like_mut)
    else {
        return false;
    };
    let key = state
        .iter()
        .find(|(key, record)| {
            names(key, place)
                && record.get("trusted_hash").and_then(Item::as_str) == Some(ours.as_str())
        })
        .map(|(key, _)| key.to_string());
    key.is_some_and(|key| state.remove(&key).is_some())
}

/// The two values of a hook's record that decide whether it runs.
struct Record {
    enabled: Option<bool>,
    trusted_hash: Option<String>,
}

fn record(config: &DocumentMut, place: Place<'_>) -> Option<Record> {
    let state = config.get("hooks")?.get("state")?.as_table_like()?;
    let (_, record) = state.iter().find(|(key, _)| names(key, place))?;
    Some(Record {
        enabled: record.get("enabled").and_then(Item::as_bool),
        trusted_hash: record
            .get("trusted_hash")
            .and_then(Item::as_str)
            .map(str::to_string),
    })
}

/// Either of the two switches that turn every hook off.
fn hooks_switched_off(config: &DocumentMut) -> bool {
    config.get("features").is_some_and(|features| {
        ["hooks", "codex_hooks"]
            .iter()
            .any(|switch| features.get(*switch).and_then(Item::as_bool) == Some(false))
    })
}

/// Whether a key under `hooks.state` names `place`. Read from the right,
/// because the first part is a path and a path may hold a colon.
fn names(key: &str, place: Place<'_>) -> bool {
    let mut parts = key.rsplitn(4, ':');
    let (Some(index), Some(group), Some(event), Some(file)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    event == EVENT_KEY
        && group.parse::<usize>().ok() == Some(place.group)
        && index.parse::<usize>().ok() == Some(place.index)
        && same_file(Path::new(file), place.file)
}

/// Two spellings of one file: equal as written, or equal once both resolve.
/// Codex writes the path it resolved, which need not be the spelling the
/// home directory was given in (`/var` and `/private/var` on macOS).
fn same_file(one: &Path, other: &Path) -> bool {
    one == other
        || matches!(
            (one.canonicalize(), other.canonicalize()),
            (Ok(one), Ok(other)) if one == other
        )
}

/// Why [`grant`] did not end with a hook Codex runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    /// The `codex` program could not be started.
    NotStarted,
    /// It started and did not answer within the wait.
    NoAnswer,
    /// It closed the exchange before answering.
    Stopped,
    /// It answered a request with an error, or with something else than "ok".
    Refused,
    /// It serves a Codex home other than the one the hook was written in.
    OtherHome,
    /// It does not list the hook.
    NotListed,
    /// The key it gave the hook cannot be written as a config path.
    Unnameable,
    /// It was asked, and still does not trust the hook.
    NotTrusted,
    /// It trusts the hook, and the person has it switched off.
    SwitchedOff,
}

impl GrantError {
    /// The reason in words, to finish "it is NOT active: ".
    pub fn words(self) -> &'static str {
        match self {
            Self::NotStarted => "the `codex` program could not be started",
            Self::NoAnswer => "Codex did not answer in time",
            Self::Stopped => "Codex stopped before it answered",
            Self::Refused => "Codex refused the request",
            Self::OtherHome => "Codex keeps its settings in another folder",
            Self::NotListed => "Codex does not list the hook",
            Self::Unnameable => "the place of the hook cannot be written in Codex's config",
            Self::NotTrusted => "Codex still does not trust it",
            Self::SwitchedOff => "it is switched off in Codex",
        }
    }
}

/// Ask Codex to trust the hook that runs `command` from `hooks_file`, and
/// confirm that it then runs it.
///
/// `codex` is the program to start and any arguments that go before
/// `app-server`. The exchange is the one Codex's own screens use: list the
/// hooks, write the hash Codex names for ours under the key Codex names for
/// it, list again. `Ok` only when the second listing says trusted and
/// enabled. A hook already trusted is confirmed and nothing is written. A
/// hook the person switched off is left off.
///
/// Bounded by `wait` in total, and the process is ended on every path.
pub fn grant(
    codex: &[OsString],
    home: &Path,
    hooks_file: &Path,
    command: &str,
    wait: Duration,
) -> Result<(), GrantError> {
    let (program, leading) = codex.split_first().ok_or(GrantError::NotStarted)?;
    let mut child = Command::new(program)
        .args(leading)
        .args(["app-server", "--listen", "stdio://"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| GrantError::NotStarted)?;
    let outcome = exchange(&mut child, home, hooks_file, command, wait);
    let _ = child.kill();
    let _ = child.wait();
    outcome
}

/// The requests in order, over the pipes of a started app-server.
fn exchange(
    child: &mut Child,
    home: &Path,
    hooks_file: &Path,
    command: &str,
    wait: Duration,
) -> Result<(), GrantError> {
    let stdin = child.stdin.take().ok_or(GrantError::NotStarted)?;
    let stdout = child.stdout.take().ok_or(GrantError::NotStarted)?;
    let (send, replies) = mpsc::channel();
    // Lines are read on a thread so every wait below can end on the clock. It
    // is never joined: it ends when the process does and its pipe closes.
    std::thread::spawn(move || {
        for line in BufReader::new(stdout.take(MAX_ANSWER_BYTES)).lines() {
            let Ok(line) = line else { break };
            let Ok(message) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if send.send(message).is_err() {
                break;
            }
        }
    });
    let mut talk = Talk {
        stdin,
        replies,
        deadline: Instant::now() + wait,
    };

    let hello = talk.ask(
        0,
        "initialize",
        json!({
            "clientInfo": {"name": "innerwarden", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {"experimentalApi": true},
        }),
    )?;
    // A person whose Codex keeps its home elsewhere (`CODEX_HOME`) does not
    // read the file the hook was written in. Trusting it there would be true
    // of a file their Codex never opens.
    let serves_this_home = hello
        .get("codexHome")
        .and_then(Value::as_str)
        .zip(hooks_file.parent())
        .is_some_and(|(serves, written)| same_file(Path::new(serves), written));
    if !serves_this_home {
        return Err(GrantError::OtherHome);
    }
    talk.tell(&json!({"method": "initialized"}))?;

    let scope = json!({"cwds": [home.to_string_lossy()]});
    let mut listed = find_listed(
        &talk.ask(1, "hooks/list", scope.clone())?,
        hooks_file,
        command,
    )
    .ok_or(GrantError::NotListed)?;
    if !listed.trusted {
        // The key goes inside a quoted part of a config path. One that holds
        // a quote or a backslash cannot be written there as it stands.
        if listed.key.contains(['"', '\\']) {
            return Err(GrantError::Unnameable);
        }
        let saved = talk.ask(
            2,
            "config/batchWrite",
            json!({
                "edits": [{
                    "keyPath": format!("hooks.state.\"{}\".trusted_hash", listed.key),
                    "mergeStrategy": "upsert",
                    "value": listed.hash,
                }],
                "reloadUserConfig": true,
            }),
        )?;
        if saved.get("status").and_then(Value::as_str) != Some("ok") {
            return Err(GrantError::Refused);
        }
        listed = find_listed(&talk.ask(3, "hooks/list", scope)?, hooks_file, command)
            .ok_or(GrantError::NotListed)?;
    }
    match (listed.trusted, listed.enabled) {
        (true, true) => Ok(()),
        (true, false) => Err(GrantError::SwitchedOff),
        (false, _) => Err(GrantError::NotTrusted),
    }
}

/// Our hook as one listing reports it.
struct Listed {
    key: String,
    hash: String,
    trusted: bool,
    enabled: bool,
}

/// Find our hook in the result of `hooks/list`: the `PreToolUse` hook with our
/// command that comes from our file.
fn find_listed(result: &Value, hooks_file: &Path, command: &str) -> Option<Listed> {
    let hook = result
        .get("data")?
        .as_array()?
        .iter()
        .filter_map(|scope| scope.get("hooks").and_then(Value::as_array))
        .flatten()
        .find(|hook| {
            hook.get("eventName").and_then(Value::as_str) == Some(EVENT_LISTED)
                && hook.get("command").and_then(Value::as_str) == Some(command)
                && hook
                    .get("sourcePath")
                    .and_then(Value::as_str)
                    .is_some_and(|source| same_file(Path::new(source), hooks_file))
        })?;
    Some(Listed {
        key: hook.get("key")?.as_str()?.to_string(),
        hash: hook.get("currentHash")?.as_str()?.to_string(),
        trusted: hook.get("trustStatus").and_then(Value::as_str) == Some("trusted"),
        enabled: hook.get("enabled").and_then(Value::as_bool) == Some(true),
    })
}

/// One side of the exchange: lines out, answers in, one deadline for all.
struct Talk {
    stdin: ChildStdin,
    replies: Receiver<Value>,
    deadline: Instant,
}

impl Talk {
    /// Send one message that expects no answer.
    fn tell(&mut self, message: &Value) -> Result<(), GrantError> {
        let mut line = message.to_string();
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .and_then(|()| self.stdin.flush())
            .map_err(|_| GrantError::Stopped)
    }

    /// Send one request and wait for the answer that carries its id. What the
    /// server sends on its own in between (notifications, its own requests)
    /// is passed over.
    fn ask(&mut self, id: u64, method: &str, params: Value) -> Result<Value, GrantError> {
        self.tell(&json!({"id": id, "method": method, "params": params}))?;
        loop {
            let left = self.deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(GrantError::NoAnswer);
            }
            let reply = match self.replies.recv_timeout(left) {
                Ok(reply) => reply,
                Err(RecvTimeoutError::Timeout) => return Err(GrantError::NoAnswer),
                Err(RecvTimeoutError::Disconnected) => return Err(GrantError::Stopped),
            };
            if reply.get("method").is_some() || reply.get("id").and_then(Value::as_u64) != Some(id)
            {
                continue;
            }
            return reply.get("result").cloned().ok_or(GrantError::Refused);
        }
    }
}

/// A stand-in for `codex app-server`, as a script for `/bin/sh`. A test runs
/// it through the shell, with the folder its answers are in as the one
/// argument, and never executes it itself.
///
/// It answers `initialize` with the home in `home`, the n-th `hooks/list`
/// with `list<n>` (an error when there is no such file), and a write with the
/// status in `write` ("ok" when there is no such file), keeping the request in
/// `asked` and copying the file `config`, when there is one, to `config.toml`
/// in the home it serves, as Codex writes its record there. One notification goes out first, as the real server sends one.
#[cfg(all(test, unix))]
pub(crate) const FAKE_APP_SERVER: &str = r##"dir="$1"
q='"'
printf '%s\n' '{"method":"remoteControl/status/changed","params":{}}'
lists=0
while IFS= read -r line; do
  id=${line#*${q}id${q}:}
  id=${id%%,*}
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"id":%s,"result":{"codexHome":"%s"}}\n' "$id" "$(cat "$dir/home")"
      ;;
    *'"method":"hooks/list"'*)
      lists=$((lists + 1))
      if [ -f "$dir/list$lists" ]; then
        printf '{"id":%s,"result":%s}\n' "$id" "$(cat "$dir/list$lists")"
      else
        printf '{"id":%s,"error":{"code":-32601,"message":"unknown"}}\n' "$id"
      fi
      ;;
    *'"method":"config/batchWrite"'*)
      printf '%s\n' "$line" > "$dir/asked"
      if [ -f "$dir/config" ]; then cp "$dir/config" "$(cat "$dir/home")/config.toml"; fi
      if [ -f "$dir/write" ]; then
        printf '{"id":%s,"result":{"status":"%s"}}\n' "$id" "$(cat "$dir/write")"
      else
        printf '{"id":%s,"result":{"status":"ok"}}\n' "$id"
      fi
      ;;
  esac
done
"##;

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "/home/me/.codex/hooks.json";
    const COMMAND: &str = "\"/usr/local/bin/innerwarden\" hook --agent codex";
    const MONITOR: &str = "\"/usr/local/bin/innerwarden\" hook --monitor --agent codex";
    const HASH_60: &str = "sha256:a1ba20a72bd8ae96cbb446b75d7de54376b07103437698e301e8971b24b9c92f";
    const HASH_MONITOR_60: &str =
        "sha256:93321d982831e4dacdd461d98a13d128663dd653b07aa54fc38f6ccc09d4f086";
    const HASH_30: &str = "sha256:b9df8c141eaccb93d0ba7555093712db70f46dbfd00bb166dc6cd47f7ca2c63d";

    fn place(file: &Path) -> Place<'_> {
        Place {
            file,
            group: 0,
            index: 0,
            command: COMMAND,
            timeout: 60,
        }
    }

    fn config(body: &str) -> DocumentMut {
        body.parse().expect("test config parses")
    }

    /// A config holding one record, under `key`, with these lines.
    fn with_record(key: &str, lines: &str) -> DocumentMut {
        config(&format!("[hooks.state.\"{key}\"]\n{lines}\n"))
    }

    fn judged(config: &DocumentMut) -> Trust {
        offline(Some(config), place(Path::new(FILE)))
    }

    /// Known answers, computed apart from this code over the text Codex CLI
    /// 0.167.2 hashes. A change of one key, of the order or of the spacing
    /// changes all three.
    #[test]
    fn the_hash_is_the_one_codex_stores() {
        assert_eq!(hook_hash(COMMAND, 60), HASH_60);
        assert_eq!(hook_hash(MONITOR, 60), HASH_MONITOR_60);
        assert_eq!(hook_hash(COMMAND, 30), HASH_30);
    }

    #[test]
    fn a_record_with_the_hash_of_this_hook_is_trusted() {
        let config = with_record(
            &format!("{FILE}:pre_tool_use:0:0"),
            &format!("trusted_hash = \"{HASH_60}\""),
        );
        assert_eq!(judged(&config), Trust::Trusted);
    }

    #[test]
    fn no_config_and_no_record_are_both_not_trusted() {
        assert_eq!(
            offline(None, place(Path::new(FILE))),
            Trust::Skipped(Skip::NotTrusted)
        );
        assert_eq!(
            judged(&config("model = \"gpt\"\n")),
            Trust::Skipped(Skip::NotTrusted)
        );
        // A record that holds no hash trusts nothing.
        assert_eq!(
            judged(&with_record(
                &format!("{FILE}:pre_tool_use:0:0"),
                "enabled = true"
            )),
            Trust::Skipped(Skip::NotTrusted)
        );
    }

    /// The mode flag is part of the command and the timeout is part of the
    /// hash, so trust given to either other form is trust for another hook.
    #[test]
    fn trust_for_another_command_or_timeout_is_a_changed_hook() {
        for other in [HASH_MONITOR_60, HASH_30] {
            let config = with_record(
                &format!("{FILE}:pre_tool_use:0:0"),
                &format!("trusted_hash = \"{other}\""),
            );
            assert_eq!(judged(&config), Trust::Skipped(Skip::Changed), "{other}");
        }
    }

    #[test]
    fn a_record_for_another_place_is_not_this_hooks() {
        for key in [
            format!("{FILE}:pre_tool_use:1:0"),
            format!("{FILE}:pre_tool_use:0:1"),
            format!("{FILE}:post_tool_use:0:0"),
            "/home/other/.codex/hooks.json:pre_tool_use:0:0".to_string(),
            "pre_tool_use:0:0".to_string(),
        ] {
            let config = with_record(&key, &format!("trusted_hash = \"{HASH_60}\""));
            assert_eq!(judged(&config), Trust::Skipped(Skip::NotTrusted), "{key}");
        }
    }

    #[test]
    fn a_trusted_hook_with_enabled_false_is_switched_off() {
        let config = with_record(
            &format!("{FILE}:pre_tool_use:0:0"),
            &format!("trusted_hash = \"{HASH_60}\"\nenabled = false"),
        );
        assert_eq!(judged(&config), Trust::Skipped(Skip::SwitchedOff));
    }

    #[test]
    fn either_feature_switch_turns_a_trusted_hook_off() {
        let record =
            format!("[hooks.state.\"{FILE}:pre_tool_use:0:0\"]\ntrusted_hash = \"{HASH_60}\"\n");
        for switch in ["hooks", "codex_hooks"] {
            let off = config(&format!("[features]\n{switch} = false\n\n{record}"));
            assert_eq!(judged(&off), Trust::Skipped(Skip::HooksOff), "{switch}");
            let on = config(&format!("[features]\n{switch} = true\n\n{record}"));
            assert_eq!(judged(&on), Trust::Trusted, "{switch}");
        }
    }

    /// Codex keys the record by the path it resolved. A home reached through
    /// a link is the same file under another spelling.
    #[cfg(unix)]
    #[test]
    fn a_key_spelled_through_a_link_names_the_same_file() {
        let root = tempfile::TempDir::new().unwrap();
        let real = root.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("hooks.json"), "{}").unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let config = with_record(
            &format!("{}:pre_tool_use:0:0", link.join("hooks.json").display()),
            &format!("trusted_hash = \"{HASH_60}\""),
        );
        assert_eq!(
            offline(Some(&config), place(&real.join("hooks.json"))),
            Trust::Trusted
        );
    }

    #[test]
    fn forget_takes_out_the_record_of_this_hook_and_no_other() {
        let mut config = config(&format!(
            "[mcp_servers.files]\ncommand = \"npx\"\n\n\
             [hooks.state.\"{FILE}:pre_tool_use:0:0\"]\ntrusted_hash = \"{HASH_60}\"\n\n\
             [hooks.state.\"{FILE}:pre_tool_use:1:0\"]\ntrusted_hash = \"{HASH_30}\"\n"
        ));
        assert!(forget(&mut config, place(Path::new(FILE))));
        assert_eq!(judged(&config), Trust::Skipped(Skip::NotTrusted));
        // The person's other record and their servers are where they were.
        let other = Place {
            group: 1,
            timeout: 30,
            ..place(Path::new(FILE))
        };
        assert_eq!(offline(Some(&config), other), Trust::Trusted);
        assert_eq!(
            config["mcp_servers"]["files"]["command"].as_str(),
            Some("npx")
        );
        assert!(!forget(&mut config, place(Path::new(FILE))));
    }

    /// A record at this place that holds another hash was not written for
    /// this hook. It stays, and the file is not touched.
    #[test]
    fn forget_leaves_a_record_that_holds_another_hash() {
        let mut config = with_record(
            &format!("{FILE}:pre_tool_use:0:0"),
            &format!("trusted_hash = \"{HASH_30}\""),
        );
        let before = config.to_string();
        assert!(!forget(&mut config, place(Path::new(FILE))));
        assert_eq!(config.to_string(), before);
    }

    /// The exchange, against a stand-in for `codex app-server` that answers
    /// from files. It is run through `/bin/sh`, never executed itself, so a
    /// test never starts a file it has just written.
    #[cfg(unix)]
    /// Our hook in Codex's listing is the one with our event, our command
    /// and our file: a hook of the person's listed before it, or one with our
    /// command under another event, is not taken for it.
    ///
    /// FAILS ON REVERT: read the first `&&` in `find_listed` as `||` and the
    /// person's hook listed first is taken for ours.
    #[test]
    fn the_listed_hook_is_ours_by_its_event_command_and_file() {
        let file = Path::new("/home/me/.codex/hooks.json");
        let hook = |key: &str, event: &str, command: &str| {
            json!({
                "key": key,
                "eventName": event,
                "command": command,
                "sourcePath": file.display().to_string(),
                "enabled": true,
                "currentHash": format!("sha256:{key}"),
                "trustStatus": "trusted",
            })
        };
        let result = json!({"data": [{"cwd": "/", "hooks": [
            hook("theirs", EVENT_LISTED, "/usr/local/bin/their-hook"),
            hook("later", "postToolUse", "ours"),
            hook("ours", EVENT_LISTED, "ours"),
        ]}]});
        let listed = find_listed(&result, file, "ours").expect("ours is listed");
        assert_eq!(
            (listed.key.as_str(), listed.hash.as_str()),
            ("ours", "sha256:ours")
        );
    }

    // Every case runs the stand-in through `/bin/sh` ([`FAKE_APP_SERVER`]).
    #[cfg(unix)]
    mod asking_codex {
        use super::*;
        use std::path::PathBuf;

        /// The stand-in that answers from the files of its folder.
        const ANSWERS: &str = FAKE_APP_SERVER;

        /// Reads every request and answers none.
        const SILENT: &str = "while IFS= read -r line; do :; done\n";

        /// Ends at once.
        const GONE: &str = "exit 0\n";

        struct Fake {
            dir: tempfile::TempDir,
        }

        impl Fake {
            fn new(script: &str) -> Self {
                let dir = tempfile::TempDir::new().unwrap();
                let codex_home = dir.path().join(".codex");
                std::fs::create_dir_all(&codex_home).unwrap();
                std::fs::write(codex_home.join("hooks.json"), "{}").unwrap();
                std::fs::write(dir.path().join("codex.sh"), script).unwrap();
                std::fs::write(dir.path().join("home"), codex_home.display().to_string()).unwrap();
                Self { dir }
            }

            fn hooks_file(&self) -> PathBuf {
                self.dir.path().join(".codex/hooks.json")
            }

            /// What the n-th `hooks/list` answers: our hook in this state.
            fn lists(self, answers: &[(&str, bool)]) -> Self {
                let key = self.key();
                self.lists_under(&key, answers)
            }

            /// [`Self::lists`], with the hook under a key of the caller's.
            fn lists_under(self, key: &str, answers: &[(&str, bool)]) -> Self {
                for (n, (status, enabled)) in answers.iter().enumerate() {
                    let listing = json!({
                        "data": [{
                            "cwd": "/",
                            "hooks": [{
                                "key": key,
                                "eventName": "preToolUse",
                                "handlerType": "command",
                                "command": COMMAND,
                                "sourcePath": self.hooks_file().display().to_string(),
                                "enabled": enabled,
                                "currentHash": "sha256:feed",
                                "trustStatus": status,
                            }],
                            "warnings": [],
                            "errors": [],
                        }]
                    });
                    std::fs::write(
                        self.dir.path().join(format!("list{}", n + 1)),
                        listing.to_string(),
                    )
                    .unwrap();
                }
                self
            }

            fn key(&self) -> String {
                format!("{}:pre_tool_use:0:0", self.hooks_file().display())
            }

            fn grant_within(&self, wait: Duration) -> Result<(), GrantError> {
                let codex = [
                    OsString::from("/bin/sh"),
                    self.dir.path().join("codex.sh").into_os_string(),
                    self.dir.path().as_os_str().to_os_string(),
                ];
                grant(&codex, self.dir.path(), &self.hooks_file(), COMMAND, wait)
            }

            fn grant(&self) -> Result<(), GrantError> {
                self.grant_within(Duration::from_secs(30))
            }

            /// The write request the stand-in received, when it received one.
            fn asked(&self) -> Option<Value> {
                std::fs::read(self.dir.path().join("asked"))
                    .ok()
                    .map(|line| serde_json::from_slice(&line).expect("the request is JSON"))
            }
        }

        #[test]
        fn an_untrusted_hook_is_trusted_with_the_hash_and_key_codex_names() {
            let fake = Fake::new(ANSWERS).lists(&[("untrusted", true), ("trusted", true)]);
            assert_eq!(fake.grant(), Ok(()));
            assert_eq!(
                fake.asked(),
                Some(json!({
                    "id": 2,
                    "method": "config/batchWrite",
                    "params": {
                        "edits": [{
                            "keyPath": format!("hooks.state.\"{}\".trusted_hash", fake.key()),
                            "mergeStrategy": "upsert",
                            "value": "sha256:feed",
                        }],
                        "reloadUserConfig": true,
                    },
                }))
            );
        }

        /// Trust given to an earlier form of the line is renewed the same way.
        #[test]
        fn a_changed_hook_is_trusted_again() {
            let fake = Fake::new(ANSWERS).lists(&[("modified", true), ("trusted", true)]);
            assert_eq!(fake.grant(), Ok(()));
            assert!(fake.asked().is_some());
        }

        /// A listing as long as a large set of hooks and warnings makes is
        /// read whole: what is read of Codex is bounded in megabytes.
        ///
        /// FAILS ON REVERT: read either `*` of `MAX_ANSWER_BYTES` as `+`
        /// and the reading stops inside the first listing, so no grant ends
        /// `Ok`.
        #[test]
        fn a_long_listing_is_read_whole() {
            let fake = Fake::new(ANSWERS).lists(&[("untrusted", true), ("trusted", true)]);
            let first = fake.dir.path().join("list1");
            let mut listing: Value =
                serde_json::from_slice(&std::fs::read(&first).unwrap()).unwrap();
            listing["data"][0]["warnings"] = json!(["w".repeat(2 * 1024 * 1024)]);
            std::fs::write(&first, listing.to_string()).unwrap();
            assert_eq!(fake.grant(), Ok(()));
            assert!(fake.asked().is_some());
        }

        /// An answer to another request is not the answer to this one.
        ///
        /// FAILS ON REVERT: read `||` as `&&` in the test of a reply in
        /// `Talk::ask` and a stray answer, which names another home, is
        /// taken for the answer to `initialize`.
        #[test]
        fn an_answer_to_another_request_is_passed_over() {
            let stray = "printf '%s\\n' '{\"id\":7,\"result\":{\"codexHome\":\"/somewhere/else/.codex\"}}'\n";
            let fake = Fake::new(&format!("{stray}{ANSWERS}"))
                .lists(&[("untrusted", true), ("trusted", true)]);
            assert_eq!(fake.grant(), Ok(()));
        }

        #[test]
        fn a_hook_already_trusted_is_confirmed_and_nothing_is_written() {
            let fake = Fake::new(ANSWERS).lists(&[("trusted", true)]);
            assert_eq!(fake.grant(), Ok(()));
            assert_eq!(fake.asked(), None);
        }

        #[test]
        fn a_hook_codex_still_does_not_trust_is_an_error() {
            let fake = Fake::new(ANSWERS).lists(&[("untrusted", true), ("untrusted", true)]);
            assert_eq!(fake.grant(), Err(GrantError::NotTrusted));
        }

        /// Codex answered the write and did not say it was saved. The listing
        /// that follows is not taken as the proof that it was.
        ///
        /// FAILS ON REVERT: take the check of `status` on the answer to
        /// `config/batchWrite` out of `exchange` and the second listing makes
        /// this `Ok`.
        #[test]
        fn a_write_codex_does_not_confirm_is_refused() {
            let fake = Fake::new(ANSWERS).lists(&[("untrusted", true), ("trusted", true)]);
            std::fs::write(fake.dir.path().join("write"), "error").unwrap();
            assert_eq!(fake.grant(), Err(GrantError::Refused));
            assert!(fake.asked().is_some());
        }

        /// A key that holds a backslash or a quote cannot go inside the quoted
        /// part of the config path, and nothing is written under it.
        ///
        /// FAILS ON REVERT: take the `listed.key.contains(['"', '\\'])` check
        /// out of `exchange`: the write goes out and the grant ends `Ok`.
        #[test]
        fn a_key_that_cannot_be_quoted_is_not_written() {
            for key in [
                r"C:\Users\me\.codex\hooks.json:pre_tool_use:0:0",
                r#"/home/a"b/.codex/hooks.json:pre_tool_use:0:0"#,
            ] {
                let fake =
                    Fake::new(ANSWERS).lists_under(key, &[("untrusted", true), ("trusted", true)]);
                assert_eq!(fake.grant(), Err(GrantError::Unnameable), "{key}");
                assert_eq!(fake.asked(), None, "{key}");
            }
        }

        #[test]
        fn a_hook_the_person_switched_off_stays_off_and_is_an_error() {
            let fake = Fake::new(ANSWERS).lists(&[("trusted", false)]);
            assert_eq!(fake.grant(), Err(GrantError::SwitchedOff));
            assert_eq!(fake.asked(), None);
        }

        #[test]
        fn a_listing_without_the_hook_is_an_error() {
            let fake = Fake::new(ANSWERS);
            std::fs::write(
                fake.dir.path().join("list1"),
                json!({"data": [{"cwd": "/", "hooks": [], "warnings": [], "errors": []}]})
                    .to_string(),
            )
            .unwrap();
            assert_eq!(fake.grant(), Err(GrantError::NotListed));
        }

        /// A Codex that does not know the request answers with an error.
        #[test]
        fn a_request_codex_answers_with_an_error_is_refused() {
            assert_eq!(Fake::new(ANSWERS).grant(), Err(GrantError::Refused));
        }

        #[test]
        fn a_codex_that_serves_another_home_is_not_asked_to_trust() {
            let fake = Fake::new(ANSWERS).lists(&[("untrusted", true), ("trusted", true)]);
            std::fs::write(fake.dir.path().join("home"), "/somewhere/else/.codex").unwrap();
            assert_eq!(fake.grant(), Err(GrantError::OtherHome));
            assert_eq!(fake.asked(), None);
        }

        #[test]
        fn a_codex_that_never_answers_ends_at_the_wait() {
            let started = Instant::now();
            assert_eq!(
                Fake::new(SILENT).grant_within(Duration::from_millis(400)),
                Err(GrantError::NoAnswer)
            );
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        #[test]
        fn a_codex_that_ends_at_once_has_stopped() {
            assert_eq!(Fake::new(GONE).grant(), Err(GrantError::Stopped));
        }

        #[test]
        fn a_program_that_is_not_there_was_not_started() {
            let fake = Fake::new(ANSWERS);
            let missing = [fake.dir.path().join("no-such-codex").into_os_string()];
            assert_eq!(
                grant(
                    &missing,
                    fake.dir.path(),
                    &fake.hooks_file(),
                    COMMAND,
                    Duration::from_secs(5)
                ),
                Err(GrantError::NotStarted)
            );
            assert_eq!(
                grant(
                    &[],
                    fake.dir.path(),
                    &fake.hooks_file(),
                    COMMAND,
                    Duration::from_secs(5)
                ),
                Err(GrantError::NotStarted)
            );
        }
    }
}
