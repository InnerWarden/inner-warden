//! Five readings of a line the guard got wrong, measured 2026-11-25 and
//! 2026-11-26 with `analyze_command` and `analyze_command_in` on main
//! d627912 and on this branch before the change (the same verdict on both):
//!
//! - notes written by `cat` from a here-document, whose text tells how a
//!   settings file can be rewritten through `node -e` or `python3 -c`,
//!   were refused as that rewrite (`cat_notes_are_text`);
//! - the pattern `'//'` or `'/'` of a `grep` whose output feeds a reader
//!   was read as the root folder, and the search refused for reading the
//!   home's credentials (`a_search_pattern_is_no_path`);
//! - `cargo test -p acme-killswitch > ~/innerwarden-notes/x.txt` was
//!   refused as disabling the guard: the `kill` inside the package's name
//!   was read as the verb and the redirection's file as its target
//!   (`a_verb_is_a_word_and_a_redirection_is_no_target`);
//! - `mv ~/.ssh/id_ed25519 /tmp/k` was allowed where `rm` of the key and
//!   inline code renaming it away are refused
//!   (`a_key_moved_out_of_its_store_is_removed`);
//! - `rm -rf innerwarden/rules` run in `/etc` was allowed where the same
//!   line after `cd /etc &&` is refused
//!   (`a_relative_name_is_read_from_the_folder_the_hook_gave`), and `export
//!   HOME=/etc; rm -rf ~/innerwarden` was allowed
//!   (`the_tilde_reads_the_home_the_line_sets`).

use innerwarden_agent_guard::mcp::{analyze_command, analyze_command_in, WorkingContext};

const HOME: &str = "/home/dev";

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation.to_string()
}

fn verdict_in(line: &str, cwd: &str, home: &str) -> String {
    let context = WorkingContext::discover(cwd, Some(home)).expect("absolute folder");
    analyze_command_in(line, None, Some(&context))
        .recommendation
        .to_string()
}

/// FAILS ON REVERT of `cat_notes_as_text` in `mcp.rs` (or of
/// `text_written_by_cat_blanked` in `shell.rs`): the notes are refused
/// again for their text.
#[test]
fn cat_notes_are_text() {
    for line in [
        "cat <<'EOF' > NOTES.md\nnode -e can writeFileSync the .claude/settings.json file; never do that.\nEOF",
        "cat <<EOF\npython3 -c \"open('/home/u/.claude/settings.json','w')\"\nEOF",
        "cat >> docs/notes.md <<'EOF'\npython3 -c \"open('/home/u/.claude/settings.json','w').write('{}')\"\nEOF",
        "cat > ~/notes/hook.md <<'EOF'\nnode -e \"require('fs').writeFileSync(process.env.HOME+'/.claude/settings.json','{}')\"\nEOF",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
    // The same text handed to something that runs it, written to a file a
    // command of the line runs or that an agent loads, or expanded by the
    // shell, is still read.
    for line in [
        "python3 <<'EOF'\nopen('/home/u/.claude/settings.json','w').write('{}')\nEOF",
        "cat <<'EOF' | python3\nopen('/home/u/.claude/settings.json','w').write('{}')\nEOF",
        "cat <<'EOF' | bash\npython3 -c \"open('/home/u/.claude/settings.json','w').write('{}')\"\nEOF",
        "cat > run.sh <<'EOF'\nnode -e \"require('fs').writeFileSync(process.env.HOME+'/.claude/settings.json','{}')\"\nEOF",
        "cat > notes.md <<'EOF'\nnode -e \"require('fs').writeFileSync(process.env.HOME+'/.claude/settings.json','{}')\"\nEOF\nbash notes.md",
        "cat > NOTES.md <<'EOF'\nnode -e can writeFileSync the .claude/settings.json file\nEOF\nchmod +x NOTES.md",
        "cat > CLAUDE.md <<'EOF'\nnode -e \"require('fs').writeFileSync(process.env.HOME+'/.claude/settings.json','{}')\"\nEOF",
        "cat > ~/.claude/notes.md <<'EOF'\nnode -e can writeFileSync the .claude/settings.json\nEOF",
        "cat > notes.md <<EOF\n$(node -e \"require('fs').writeFileSync(process.env.HOME+'/.claude/settings.json','{}')\")\nEOF",
        "cat > ~/.claude/settings.json <<'EOF'\n{}\nEOF",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// A home with a private key and a project in it, on disk: the search
/// rules read what a whole folder holds.
fn home_with_a_key() -> (tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().expect("temporary home");
    let home = dir.path().to_string_lossy().into_owned();
    std::fs::create_dir_all(format!("{home}/.ssh")).expect("ssh folder");
    std::fs::write(format!("{home}/.ssh/id_ed25519"), "key\n").expect("key");
    std::fs::create_dir_all(format!("{home}/app/crates/a/src")).expect("project");
    std::fs::create_dir_all(format!("{home}/app/.git")).expect("repository");
    let project = format!("{home}/app");
    (dir, home, project)
}

/// FAILS ON REVERT of `search_pattern_words` in `threats.rs`: the
/// pattern is read as the root folder again, which holds the home's key.
#[test]
fn a_search_pattern_is_no_path() {
    let (_dir, home, project) = home_with_a_key();
    for line in [
        "grep -rln '//' crates | xargs sed -n 1p",
        "grep -rln '/' crates | xargs sed -n 1p",
        "grep -rln -e '//' crates | xargs sed -n 1p",
        "grep -rln --regexp='//' crates | xargs sed -n 1p",
        "grep -rln -e// crates | xargs sed -n 1p",
        "grep -rln -e '/' -e '//' crates | xargs sed -n 1p",
    ] {
        assert_eq!(verdict_in(line, &project, &home), "allow", "{line}");
    }
    // The loop reads each name the search prints through a variable, which
    // is held for review whatever the pattern ('x' as well).
    for line in [
        "grep -rn '//' crates | while IFS=: read f l rest; do sed -n 1p $f; done",
        "grep -rn 'x' crates | while IFS=: read f l rest; do sed -n 1p $f; done",
    ] {
        assert_ne!(verdict_in(line, &project, &home), "deny", "{line}");
    }
    // The folders searched, and a file of patterns, are still read.
    for line in [
        "grep -rl x / | xargs cat",
        "grep -rl -e x / | xargs cat",
        "grep -rl --regexp=x ~ | xargs cat",
        "grep -rl -f pats.txt ~ | xargs cat",
        "grep -e x -rl ~ | xargs cat",
        "grep -rl '//' / | xargs cat",
        "grep -rl x ~/.ssh | xargs cat",
        "grep -h x ~/.ssh/id_ed25519",
        // A pattern alone, or options that cannot be read, leave the word as
        // written.
        "grep -r \"-----BEGIN\" ~",
    ] {
        assert_eq!(verdict_in(line, &project, &home), "deny", "{line}");
    }
}

/// FAILS ON REVERT of `verb_is_a_word` and `in_output_redirect_target` in
/// `threats.rs`.
#[test]
fn a_verb_is_a_word_and_a_redirection_is_no_target() {
    for line in [
        "cargo test -p acme-killswitch > /home/u/innerwarden-notes/x.txt",
        "cargo build -p acme-killswitch >> /home/u/innerwarden-notes/x.log 2>&1",
        "cargo test -p skill-killer > /home/u/innerwarden-notes/x.txt",
        "cargo test --test kill_switch > /home/u/innerwarden-notes/x.txt",
        "cargo test --test kill_chain -p innerwarden-agent-guard 2>&1 | tail",
        "systemctl stop nginx > /home/u/innerwarden-notes/x.txt",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
    for line in [
        "pkill -9 innerwarden-agent",
        "systemctl stop --no-block innerwarden-agent",
        "systemctl stop innerwarden-agent > /tmp/x.txt",
        "pkill innerwarden > /home/u/innerwarden-notes/x.txt",
        "xargs kill < /run/innerwarden/pids",
        "/usr/bin/pkill -f innerwarden",
        "systemctl 'stop' innerwarden-agent",
        "kill -9 `pgrep innerwarden`",
        "sudo systemctl stop innerwarden-agent.service 2>/tmp/innerwarden-err.txt",
        "systemctl stop innerwarden-agent>/dev/null",
        "killall -9 innerwarden-agent",
        "timeout 5 kill innerwarden",
        // A D-Bus method is a verb: a capital letter, not a `-` or `_`,
        // follows it, and a `.` may come before it.
        "printf '' | xargs -0 busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager KillUnit ssi innerwarden-agent.service all 9",
        "printf '' | xargs -0 gdbus call --system --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --method org.freedesktop.systemd1.Manager.StopUnit innerwarden-agent.service replace",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// FAILS ON REVERT of `moves_credentials_out` in `threats.rs` (or of its
/// call in `mcp.rs`).
#[test]
fn a_key_moved_out_of_its_store_is_removed() {
    for line in [
        "mv ~/.ssh/id_ed25519 /tmp/k",
        "mv ~/.ssh/id_rsa /tmp/",
        "mv -f ~/.ssh/id_ed25519 ~/Downloads/k",
        "cd ~/.ssh && mv id_ed25519 /tmp/k",
        "mv /home/u/.ssh/id_ecdsa /var/tmp/x",
        "mv -t /tmp ~/.ssh/id_ed25519",
        "mv ~/.ssh/id_ed25519 $DEST",
        "mv ~/.ssh /tmp/s",
        "mv ~/.aws/credentials /tmp/c",
        "sudo mv /root/.ssh/id_rsa /tmp/",
        "mv ~/.ssh/id_ed25519 ~/.ssh/../k",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    assert_eq!(
        verdict_in("mv id_ed25519 /tmp/k", "/home/dev/.ssh", HOME),
        "deny"
    );
    // Inside the same store, or not a key.
    for line in [
        "mv ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.old",
        "mv ~/.ssh/id_ed25519{,.bak}",
        "mv ~/.ssh/id_ed25519 ~/.ssh/old/id_ed25519",
        "mv -t ~/.ssh/old ~/.ssh/id_ed25519",
        "mv ~/.aws/credentials ~/.aws/credentials.bak",
        "mv ~/.ssh/id_ed25519.pub /tmp/k.pub",
        "mv ~/.ssh/known_hosts /tmp/kh",
        "echo mv ~/.ssh/id_ed25519 /tmp/k",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
    assert_eq!(
        verdict_in("mv id_ed25519 id_ed25519.old", "/home/dev/.ssh", HOME),
        "allow"
    );
}

/// FAILS ON REVERT of `removal_reaches_guard_file_from` (its folder) in
/// `guard_file_targets.rs`, or of `guard_file_reached_in_place` in
/// `mcp.rs`.
#[test]
fn a_relative_name_is_read_from_the_folder_the_hook_gave() {
    for (line, cwd) in [
        ("rm -rf innerwarden/rules", "/etc"),
        ("rm -rf innerwarden", "/etc"),
        ("rm -f innerwarden/guard.toml", "/etc"),
        ("rm -rf rules", "/etc/innerwarden"),
        ("mv innerwarden/guard.toml /tmp/g", "/etc"),
        ("rm -rf ./innerwarden", "/etc"),
        ("rm -rf lib/innerwarden", "/var"),
        ("rm -rf ../innerwarden", "/etc/ssh"),
        ("rm -rf innerwarden/rules", "/usr/local/etc"),
        ("mv innerwarden /tmp/x", "/var/lib"),
        ("rm -rf innerwarden", "/home/dev/.config"),
    ] {
        assert_eq!(verdict_in(line, cwd, HOME), "deny", "{line} in {cwd}");
    }
    for (line, cwd) in [
        ("rm -rf innerwarden/rules", "/home/dev/src/app"),
        ("rm -rf innerwarden/rules", "/home/dev"),
        ("rm -rf innerwarden-notes/x", "/home/dev"),
        ("cd /tmp && rm -rf innerwarden/rules", "/etc"),
        ("rm -rf build", "/home/dev/src/app"),
        ("rm -rf crates/innerwarden-x/target", "/home/dev/src/app"),
    ] {
        assert_eq!(verdict_in(line, cwd, HOME), "allow", "{line} in {cwd}");
    }
    // With no folder known, a relative name is read as written, as before.
    assert_eq!(verdict("rm -rf innerwarden/rules"), "allow");
}

/// FAILS ON REVERT of the second reading of
/// `removal_reaches_guard_file_from` (`home_given`) in
/// `guard_file_targets.rs`.
#[test]
fn the_tilde_reads_the_home_the_line_sets() {
    for line in [
        "export HOME=/etc; rm -rf ~/innerwarden",
        "HOME=/etc; rm -rf ~/innerwarden",
        "export HOME=/etc && rm -rf ~/innerwarden/rules",
        "export HOME=/etc; cd; rm -rf innerwarden",
        "export {HO,}ME=/etc; rm -rf ~/innerwarden",
        "HOME=/etc; rm -rf ~/innerwarden/rules",
        "declare -x HOME=/etc; rm -rf ~/innerwarden",
        "export HOME=/etc; truncate -s0 ~/innerwarden/guard.toml",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        "export HOME=/tmp/h; rm -rf ~/build",
        "HOME=/etc rm -rf ~/innerwarden",
        "export HOME=/etc; (export HOME=/tmp; rm -rf ~/innerwarden)",
        "export HOME=/tmp/x; rm -rf ~/innerwarden",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
    // A read through the home the line set is judged as the path written
    // out: the same verdict either way.
    assert_eq!(
        verdict("export HOME=/etc; cat $HOME/innerwarden/guard.toml"),
        verdict("cat /etc/innerwarden/guard.toml")
    );
    assert_eq!(
        verdict("export HOME=/etc; cat ~/innerwarden/guard.toml"),
        verdict("cat /etc/innerwarden/guard.toml")
    );
}
