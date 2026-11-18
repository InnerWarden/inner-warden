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

/// FAILS ON REVERT of `Word::one_word` in the kernel verb search
/// (threats/words_after.rs): each was refused as a change of the kernel
/// protection.
#[test]
fn a_guard_word_beside_a_quoted_expansion_is_not_the_guard_run() {
    assert_allowed(&[
        "iwt read test001 innerwarden \"$N\"",
        "for i in $(seq 1 3); do iwt read test001 innerwarden \"$N\" | tail -5; done",
        "for i in $(seq 1 3); do out=$(iwt read test001 innerwarden 80); done",
        "tmux send-keys -t innerwarden \"cd ~/innerwarden && $(echo ls)\" Enter",
        "tmux send-keys -t innerwarden \"cargo test $(echo -q)\" Enter",
        "tmux send-keys -t innerwarden \"$X\" Enter",
    ]);
}

/// FAILS ON REVERT of `command_ends` in `check_disable_verb_reaches_target`
/// (threats.rs): each was refused as disabling the guard.
#[test]
fn a_kill_beside_a_folder_named_for_the_guard_is_not_disabling_it() {
    assert_allowed(&[
        "pkill -f x; cd ~/innerwarden/wt",
        "pkill -f cargo; cd ~/innerwarden/wt && ls",
        "kill $(pgrep -f vite); cd ~/innerwarden/site",
        "kill %1 && cd /opt/innerwarden",
    ]);
}

/// Paths, folders and text that hold the guard's name, run nothing of it.
#[test]
fn paths_and_text_that_name_the_guard_stay_allowed() {
    assert_allowed(&[
        "cd ~/innerwarden/wt-T-002 && git log --oneline -3 && echo $(git rev-parse HEAD)",
        "cd ~/innerwarden/wt && SHA=$(git rev-parse HEAD) && echo $SHA",
        "mkdir -p ~/iwt-journal && D=$(date -u +%Y-%m-%dT%H:%MZ) && SHA=$(git -C ~/innerwarden/inner-warden rev-parse --short HEAD) && echo \"$D $SHA\" >> ~/iwt-journal/T-003.md",
        "ls /opt/innerwarden/ && x=$(ls /opt/innerwarden | wc -l)",
        "ssh test001 \"cd ~/innerwarden/wt && cargo test $ARGS\"",
        "sed -i 's#~/.config/innerwarden/hook.sh#X#' notes.md",
        "sed -i \"s/$A/$B/\" docs/innerwarden.md",
        "git commit -F - <<'MSG'\nGuard: read text as text\n\nThe at job runs at 5pm; innerwarden disarm stays refused.\nMSG",
        "git commit -m \"$(cat <<'EOF'\nGuard: schedule\n\nThe at job runs at 5pm; innerwarden disarm stays refused.\nEOF\n)\"",
        "gh pr create --title t --body \"Refuses innerwarden disarm; innerwarden monitor stays refused.\"",
        "gh pr create --title t --body \"$(cat <<'EOF'\n## Summary\n- innerwarden disarm is refused\n- systemctl stop innerwarden-agent too\nEOF\n)\"",
    ]);
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
