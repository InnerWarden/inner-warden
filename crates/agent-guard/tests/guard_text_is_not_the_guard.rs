//! A guard word that is part of a path, a session name or a text argument is
//! not the guard's program being run, and code an interpreter reads from a
//! here-document is judged as the same code given inline.
//!
//! Measured 2026-11-18 on the lab hosts: lines with `innerwarden` in a folder
//! name, a tmux session or an `iwt` target, beside a quoted expansion or a
//! later command, were refused as changes of the kernel protection or as
//! stopping the guard; and `python3 - <<'EOF'` that rewrites an agent's
//! settings was allowed while the same code under `python3 -c` was refused.
//! Each fix is pinned here with the lines that must stay refused.

use innerwarden_agent_guard::mcp::analyze_command;
use innerwarden_agent_guard::rules::{AtrSource, RuleEngine};

fn verdict(command: &str) -> (String, String) {
    let engine = RuleEngine::load_embedded_for(AtrSource::ShellCommand);
    let analysis = analyze_command(command, Some(&engine));
    (analysis.recommendation, analysis.explanation)
}

fn assert_allowed(cases: &[&str]) {
    for command in cases {
        let (recommendation, why) = verdict(command);
        assert_eq!(recommendation, "allow", "{command:?}: {why}");
    }
}

fn assert_denied(cases: &[&str]) {
    for command in cases {
        let (recommendation, why) = verdict(command);
        assert_eq!(recommendation, "deny", "{command:?}: {why}");
    }
}

/// The same program, given inline and fed as a quoted here-document.
fn both_ways(code: &str) -> [String; 2] {
    [
        format!("python3 -c \"{code}\""),
        format!("python3 - <<'EOF'\n{}\nEOF", code.replace("; ", "\n")),
    ]
}

/// FAILS ON REVERT of the `interpreter_input_as_inline_code` reading in
/// `analyze_command_as_read` (mcp.rs): the here-document forms were allowed.
#[test]
fn a_heredoc_program_that_rewrites_settings_is_refused_as_its_inline_form() {
    let rewrites = [
        "import json,os; p=os.path.expanduser('~/.claude/settings.json'); d=json.load(open(p)); d['hooks']={}; json.dump(d, open(p,'w'))",
        "import json; f=open('/home/u/.claude/settings.local.json','w'); json.dump({}, f)",
        "import os; open(os.path.expanduser('~/.config/innerwarden/allow.toml'),'a').write('[[allow]]')",
        "import os; os.unlink(os.path.expanduser('~/.claude/settings.json'))",
        "import os; print(open(os.path.expanduser('~/.ssh/id_rsa')).read())",
    ];
    for code in rewrites {
        for line in both_ways(code) {
            assert_denied(&[line.as_str()]);
        }
    }
    // Other interpreters and spellings of the same shape.
    assert_denied(&[
        "node - <<'EOF'\nconst fs = require('fs');\nfs.writeFileSync(process.env.HOME + '/.claude/settings.json', '{}');\nEOF",
        "python3 <<EOF\nimport json\njson.dump({}, open('/home/u/.claude/settings.json','w'))\nEOF",
        "cd /tmp && python3 - <<'EOF'\nimport json\njson.dump({}, open('/home/u/.claude/settings.json','w'))\nEOF",
    ]);
}

/// The other direction: source edited by the same shapes stays allowed.
#[test]
fn a_heredoc_program_that_edits_source_is_allowed_as_its_inline_form() {
    let edits = [
        "p='src/a.rs'; s=open(p).read(); open(p,'w').write(s.replace('old','new'))",
        "import json; d=json.load(open('package.json')); print(d['version'])",
    ];
    for code in edits {
        for line in both_ways(code) {
            assert_allowed(&[line.as_str()]);
        }
    }
}

/// The same node program, given inline and fed as a quoted here-document.
fn node_both_ways(code: &str) -> [String; 2] {
    [
        format!("node -e \"{code}\""),
        format!("node - <<'EOF'\n{}\nEOF", code.replace("; ", ";\n")),
    ]
}

/// FAILS ON REVERT of the write, remove, move and link calls added to the
/// interpreter settings rules in `guard_self_disable_patterns` and of
/// `interpreter_code_puts_file_onto_settings` (threats.rs): each was allowed
/// in both forms, because the rules read `open(..., 'w')` and little else.
#[test]
fn interpreter_code_that_writes_removes_moves_or_links_settings_is_refused() {
    let python = [
        "from pathlib import Path; Path.home().joinpath('.claude/settings.json').write_text('{}')",
        "from pathlib import Path; Path('/home/u/.claude/settings.local.json').write_bytes(b'{}')",
        "import os; os.remove('/home/u/.claude/settings.json')",
        "import os; p=os.path.expanduser('~/.claude/settings.json'); os.remove(p)",
        "from pathlib import Path; Path.home().joinpath('.claude/settings.json').unlink()",
        "import os; os.rename('/home/u/.claude/settings.json', '/home/u/.claude/off.json')",
        "import os; os.replace('/tmp/e.json', '/home/u/.claude/settings.json')",
        "import shutil; shutil.move('/home/u/.claude/settings.json', '/tmp/s')",
        "import shutil; shutil.copy('/tmp/e.json', '/home/u/.claude/settings.json')",
        "import shutil,os; p=os.path.expanduser('~/.claude/settings.json'); shutil.copyfile('/tmp/e.json', p)",
        "import os; os.symlink('/tmp/e.json', '/home/u/.claude/settings.json')",
        "from pathlib import Path; Path('/home/u/.claude/settings.json').symlink_to('/tmp/e.json')",
        "import os; os.remove(os.path.expanduser('~/.config/innerwarden/allow.toml'))",
        "from pathlib import Path; Path.home().joinpath('.config/innerwarden/suppress.toml').write_text('x')",
    ];
    for code in python {
        for line in both_ways(code) {
            assert_denied(&[line.as_str()]);
        }
    }
    let node = [
        "require('fs').unlinkSync(process.env.HOME + '/.claude/settings.json')",
        "require('fs').rmSync(process.env.HOME + '/.claude/settings.json')",
        "require('fs').renameSync(process.env.HOME + '/.claude/settings.json', '/tmp/s')",
        "require('fs').copyFileSync('/tmp/e.json', process.env.HOME + '/.claude/settings.json')",
        "require('fs').symlinkSync('/tmp/e.json', process.env.HOME + '/.claude/settings.json')",
    ];
    for code in node {
        for line in node_both_ways(code) {
            assert_denied(&[line.as_str()]);
        }
    }
}

/// The other direction: the same calls on project files, a copy of the
/// settings taken as a backup, and a read of them stay allowed.
#[test]
fn the_same_calls_on_project_files_or_reading_settings_stay_allowed() {
    let python = [
        "from pathlib import Path; Path('src/a.rs').write_text('x')",
        "from pathlib import Path; Path('out.bin').write_bytes(b'x')",
        "import os; os.remove('build/out.txt')",
        "import os; os.rename('a.txt', 'b.txt')",
        "import shutil; shutil.copy('/home/u/.claude/settings.json', 'settings-backup.json')",
        "import os; p=os.path.expanduser('~/.claude/settings.json'); print(open(p).read().replace('a','b'))",
        "import os; print(os.path.exists('/home/u/.claude/settings.json'))",
    ];
    for code in python {
        let [inline, heredoc] = both_ways(code);
        assert_allowed(&[heredoc.as_str()]);
        if code.starts_with("import os") {
            // `python3 -c "import os` is an obfuscation indicator of its own
            // (review), before and after this change; it must not become deny.
            let (recommendation, why) = verdict(&inline);
            assert_ne!(recommendation, "deny", "{inline:?}: {why}");
        } else {
            assert_allowed(&[inline.as_str()]);
        }
    }
    for code in [
        "require('fs').unlinkSync('dist/a.js')",
        "require('fs').copyFileSync(process.env.HOME + '/.claude/settings.json', 'backup.json')",
    ] {
        for line in node_both_ways(code) {
            assert_allowed(&[line.as_str()]);
        }
    }
}

/// FAILS ON REVERT of `Word::one_word` in the kernel verb search
/// (threats/words_after.rs): each was refused as a change of the kernel
/// protection.
#[test]
fn a_guard_word_beside_a_quoted_expansion_is_not_the_guard_run() {
    // Held for review since 2026-11-20, no longer allowed: a program the guard does not know is handed
    // `$N`, which the line does not set
    // (fail closed on what the guard cannot read, `src/shell/unread_parts.rs`).
    for line in [
        "iwt read test001 innerwarden \"$N\"",
        "for i in $(seq 1 3); do iwt read test001 innerwarden \"$N\" | tail -5; done",
        // `tmux send-keys` types `$X` into a shell, which runs it.
        "tmux send-keys -t innerwarden \"$X\" Enter",
    ] {
        assert_eq!(verdict(line).0, "review", "{line}");
    }
    assert_allowed(&[
        "for i in $(seq 1 3); do out=$(iwt read test001 innerwarden 80); done",
        "tmux send-keys -t innerwarden \"cd ~/innerwarden && $(echo ls)\" Enter",
        "tmux send-keys -t innerwarden \"cargo test $(echo -q)\" Enter",
    ]);
}

/// FAILS ON REVERT of `command_ends` in `check_disable_verb_reaches_target`
/// (threats.rs): each was refused as disabling the guard.
#[test]
fn a_kill_beside_a_folder_named_for_the_guard_is_not_disabling_it() {
    assert_allowed(&[
        "pkill -f x; cd ~/innerwarden/wt",
        "pkill -f cargo; cd ~/innerwarden/wt && ls",
        "kill %1 && cd /opt/innerwarden",
    ]);
    // Held for review since 2026-11-20, no longer allowed: what `kill` stops is what `pgrep` prints
    // (fail closed on what the guard cannot read, `src/shell/unread_parts.rs`).
    // `pgrep -f` matches whole command lines, and a line of the guard holds
    // the server it wraps; a pattern the guard cannot read is held too.
    assert_eq!(
        verdict("kill $(pgrep -f vite); cd ~/innerwarden/site").0,
        "review"
    );
    assert_eq!(
        verdict("kill $(pgrep -f \"$P\"); cd ~/innerwarden/site").0,
        "review"
    );
}

/// Paths, folders and text that hold the guard's name, run nothing of it.
#[test]
fn paths_and_text_that_name_the_guard_stay_allowed() {
    assert_allowed(&[
        "cd ~/innerwarden/wt-T-002 && git log --oneline -3 && echo $(git rev-parse HEAD)",
        "cd ~/innerwarden/wt && SHA=$(git rev-parse HEAD) && echo $SHA",
        "mkdir -p ~/iwt-journal && D=$(date -u +%Y-%m-%dT%H:%MZ) && SHA=$(git -C ~/innerwarden/inner-warden rev-parse --short HEAD) && echo \"$D $SHA\" >> ~/iwt-journal/T-003.md",
        "ls /opt/innerwarden/ && x=$(ls /opt/innerwarden | wc -l)",
        "sed -i 's#~/.config/innerwarden/hook.sh#X#' notes.md",
        "git commit -F - <<'MSG'\nGuard: read text as text\n\nThe at job runs at 5pm; innerwarden disarm stays refused.\nMSG",
        "git commit -m \"$(cat <<'EOF'\nGuard: schedule\n\nThe at job runs at 5pm; innerwarden disarm stays refused.\nEOF\n)\"",
        "gh pr create --title t --body \"Refuses innerwarden disarm; innerwarden monitor stays refused.\"",
        "gh pr create --title t --body \"$(cat <<'EOF'\n## Summary\n- innerwarden disarm is refused\n- systemctl stop innerwarden-agent too\nEOF\n)\"",
    ]);
    // Held for review since 2026-11-20, no longer allowed: the line `ssh` runs on the other host holds
    // `$ARGS`, the expression `sed -i` applies (which may run or write)
    // holds `$A` and `$B`, none of which the line sets
    // (fail closed on what the guard cannot read, `src/shell/unread_parts.rs`).
    assert_eq!(
        verdict("sed -i \"s/$A/$B/\" docs/innerwarden.md").0,
        "review"
    );
    assert_eq!(
        verdict("ssh test001 \"cd ~/innerwarden/wt && cargo test $ARGS\"").0,
        "review"
    );
}

/// A word not shown right after the guard's own name is still one of its
/// verbs: reading `"$X"` as one word must not loosen the guard's verbs.
/// The same word after the name given to ANOTHER program stays allowed.
#[test]
fn a_quoted_expansion_after_the_guard_name_stays_refused() {
    assert_denied(&[
        "innerwarden \"$X\"",
        "innerwarden \"$X\" monitor",
        "innerwarden allow \"$X\"",
        "innerwarden \"$(echo dry-run)\"",
        "iw \"$X\"",
        "innerwarden-ctl \"$X\"",
    ]);
    // Held for review since 2026-11-20, no longer allowed: a program the guard does not know is handed
    // `$N`, which the line does not set; still not refused
    // (fail closed on what the guard cannot read, `src/shell/unread_parts.rs`).
    assert_eq!(verdict("iwt read test001 innerwarden \"$N\"").0, "review");
}

/// What the readings above must not let through: the guard run by path, by
/// a variable or by words the shell builds, its services stopped, its
/// kernel protection changed, and here-documents a shell runs.
#[test]
fn the_guard_run_by_path_variable_or_built_words_stays_refused() {
    assert_denied(&[
        // By path.
        "~/innerwarden/bin/innerwarden dry-run",
        "/opt/innerwarden/innerwarden-ctl disarm",
        "/opt/innerwarden/innerwarden monitor",
        // By a variable, or by words the shell builds.
        "$IW monitor",
        "IW=innerwarden; $IW monitor",
        "sudo innerwarden \"$X\"",
        "nohup innerwarden \"$X\"",
        "xargs innerwarden \"$X\"",
        "innerwarden \"$@\"",
        "innerwarden $ARGS",
        "iwt read test001 innerwarden $(echo 80)",
        // The kernel protection, with one word not shown.
        "innerwarden agent kernel \"$X\"",
        "innerwarden agent \"$X\" off",
        "innerwarden \"$X\" kernel off",
        // Its services.
        "systemctl stop innerwarden-agent",
        "pkill -9 innerwarden-agent",
        "kill $(pgrep -f x | grep innerwarden)",
        "cd ~/innerwarden; systemctl stop --no-block innerwarden-agent",
        "pkill -f x; pkill -f innerwarden",
        // Text a shell runs.
        "tmux send-keys -t work \"innerwarden monitor\" Enter",
        "tmux send-keys -t innerwarden \"innerwarden monitor\" Enter",
        "cat <<EOF | sh\n$(innerwarden monitor)\nEOF",
        "git commit -F - <<MSG\n$(innerwarden monitor)\nMSG",
    ]);
}

/// A worktree kept under a project's `.worktrees`, or named through
/// `$HOME`, in a folder whose name holds the guard's, is a work folder:
/// `git worktree remove` of one is not disabling the guard. Measured
/// 2026-11-24 on main 30ce33d: each line was a deny for "disable
/// InnerWarden (flags between verb and target)"; the same worktree named
/// through `~` with no hidden folder was already a review.
///
/// FAILS ON REVERT of `hidden_part` (the `.worktrees` lines) or of
/// `home_kept` in `reads_whole` (the `$HOME` lines), mention.rs: each
/// is a deny again.
#[test]
fn a_worktree_in_a_folder_named_for_the_guard_is_not_disabling_it() {
    for line in [
        "git worktree remove --force ~/github/_innerwarden/.worktrees/t219",
        "git worktree remove ~/github/_innerwarden/.worktrees/t219",
        "cd ~/github/_innerwarden/inner-warden && git worktree remove --force ~/github/_innerwarden/.worktrees/t219 && git branch -D t219",
        "git worktree remove --force $HOME/innerwarden/wt-review",
        "git -C $HOME/innerwarden/inner-warden worktree remove --force $HOME/innerwarden/wt-review",
    ] {
        assert_eq!(verdict(line).0, "review", "{line}");
    }
    // The guard's own places, its programs and its name stay refused,
    // through `.worktrees` and through `$HOME`, and so does a `$HOME`
    // the line points somewhere else first.
    assert_denied(&[
        "git worktree remove --force ~/.config/innerwarden",
        "git worktree remove --force ~/.local/bin/innerwarden",
        "git worktree remove /etc/innerwarden",
        "git worktree remove --force /var/lib/innerwarden",
        "git worktree remove --force $HOME/.config/innerwarden",
        "git worktree remove --force $HOME/innerwarden",
        "git worktree remove --force ~/github/_innerwarden/.worktrees/innerwarden",
        "git worktree remove --force ~/github/_innerwarden/.worktrees/../../.config/innerwarden",
        "git worktree remove --force ~/.worktrees/.config/innerwarden",
        "HOME=/etc; git worktree remove --force $HOME/innerwarden/wt-review",
        "export HOME=/etc && git worktree remove --force $HOME/innerwarden/x",
        "rm -rf $HOME/.config/innerwarden",
        "systemctl --user disable --now innerwarden-agent",
        "pkill -9 innerwarden-agent",
    ]);
}
