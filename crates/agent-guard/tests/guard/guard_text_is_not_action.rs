//! Text that speaks of the guard, or of a host's security, is no act on
//! either.
//!
//! The guard's own checks (an act on the guard, a security monitor
//! tampered with) read a line as the shell runs it: a note written by `cat`,
//! a message handed to a program that only carries it, the strings inline
//! code edits or prints, and the line `ssh` runs on another host (judged
//! there, as a line of its own) are data to them. What a line runs stays
//! read: a program that runs text, inline code's calls and the files it
//! writes to, a file the line writes and then runs, and a lowering of the
//! guard spelled out wherever it is written.
//!
//! Measured 2026-11-28 on a week of an operator's own work replayed through
//! the hook: 230 lines were still refused, after the guard's name was taken
//! out of them, for text read as an act on the guard or on the host's
//! security (a note about a lab run, a message about a password changed, a
//! script edited in place). Every line below is written with neutral names
//! and gives the verdict the operator's line gave.

use innerwarden_agent_guard::mcp::analyze_command;
use innerwarden_agent_guard::posture::{refuses, Posture};

/// The signals of the guard's own families `command` is charged with.
fn guard_findings(command: &str) -> Vec<String> {
    analyze_command(command, None)
        .signals
        .iter()
        .filter(|signal| signal.score > 0)
        .filter(|signal| {
            matches!(
                signal.signal.as_str(),
                "guard_self_disable" | "security_tooling_tamper"
            )
        })
        .map(|signal| signal.detail.clone())
        .collect()
}

/// Whether the hook refuses `command` in the default posture and in the
/// strict one.
fn refused_in_both_postures(command: &str) -> bool {
    let analysis = analyze_command(command, None);
    let strict_refuses = analysis.recommendation != "allow";
    let verdict = serde_json::to_value(&analysis).expect("a verdict serialises");
    refuses(Posture::Default, strict_refuses, &verdict)
        && refuses(Posture::Strict, strict_refuses, &verdict)
}

/// FAILS ON REVERT of the remote line's words masked for the guard's own
/// checks (`ssh_remote_words_blanked`): a search pattern on the other host
/// was refused as the tampering it searches for.
#[test]
fn a_search_on_another_host_is_read_there() {
    let line = "ssh h1 'grep -n \"chpasswd\\|LD_PRELOAD\" /srv/lab/report.txt | head'";
    assert_eq!(
        analyze_command(line, None).recommendation,
        "allow",
        "{line}"
    );
}

/// FAILS ON REVERT of the narrower doubt (`masks_are_in_doubt_for_the_guard`):
/// an interpreter elsewhere on the line made the note `cat` writes a line
/// that runs.
#[test]
fn a_note_written_by_cat_stays_a_note_beside_an_interpreter() {
    let line = "cat > notes/r1.md <<'EOF'\n# r1\nthe probe ran usermod -aG sudo u and echo root:x | chpasswd on the lab host\nEOF\npython3 -c 'print(1)'";
    assert!(guard_findings(line).is_empty(), "{line}");
    assert_eq!(
        analyze_command(line, None).recommendation,
        "allow",
        "{line}"
    );
}

/// FAILS ON REVERT of the strings of inline code taken out for the guard's
/// own checks (`Places::Kept`): text the code puts in a file was read as
/// what the code does.
#[test]
fn text_inline_code_edits_is_no_act() {
    for line in [
        "python3 - <<'EOF'\np='notes/runner.py'\ns=open(p).read()\ns=s.replace('''old text''', '''tasks that touch sudoers or chpasswd run alone\nand never two at once''')\nopen(p,'w').write(s)\nEOF",
        // A path found from the home, and an f-string, beside the text.
        "python3 - <<'EOF'\nfrom pathlib import Path\np = Path.home() / 'notes' / 'r.md'\ns = p.read_text()\nn = s.count('x')\nprint(f\"{n} lines\")\np.write_text(s.replace('x', '''the probe ran usermod -aG sudo u\non the lab host'''))\nEOF",
    ] {
        assert!(guard_findings(line).is_empty(), "{line}");
    }
}

/// FAILS ON REVERT of a message masked for the guard's own checks
/// (`mask_text_arguments_for_the_guard`): a program that only carries a
/// message was taken for one that runs it.
#[test]
fn a_message_handed_to_a_program_that_runs_none_of_it_is_data() {
    let line = "cd /srv/notes && ./notify send ops \"rotate: the probe ran echo root:x | chpasswd and usermod -aG sudo u\"";
    assert!(guard_findings(line).is_empty(), "{line}");
}

/// FAILS ON REVERT of a lone `-` read as the program from the standard
/// input (`python_code_input`): the word after it was taken for the code,
/// and the code in the here-document was never read as code.
#[test]
fn code_read_from_the_input_with_arguments_after_a_dash_is_read_as_code() {
    let line = "python3 - notes/rules.txt <<'EOF'\nimport sys\nsrc=open(sys.argv[1]).read()\nprint(src.count('echo root:x | chpasswd'))\nEOF";
    assert_eq!(
        analyze_command(line, None).recommendation,
        "allow",
        "{line}"
    );
}

/// FAILS ON REVERT of `line_may_run_a_written_file_for_the_guard`: a folder
/// changed before the interpreter made its own code a file the line runs.
#[test]
fn an_interpreter_reading_its_own_input_runs_no_written_file() {
    let line = "cd /srv/notes && python3 - <<'EOF'\np='runner.py'\ns=open(p).read()\ns=s.replace('''a''', '''the probe ran echo root:x | chpasswd and usermod -aG sudo u''')\nopen(p,'w').write(s)\nEOF";
    assert!(guard_findings(line).is_empty(), "{line}");
}

/// What a line runs, and a lowering of the guard spelled out, stay refused
/// in both postures: the lines the card names, and the ways code or a line
/// reaches an agent's settings, the account database or a security monitor
/// through what this reading takes out.
#[test]
fn an_act_stays_refused() {
    for line in [
        // The guard's own commands, run by code, by a terminal or a wrapper.
        "python3 -c \"import subprocess; subprocess.run(['innerwarden','allow','x'])\"",
        "tmux send-keys -t s 'innerwarden monitor' Enter",
        "./wrapper \"innerwarden agent kernel off\"",
        "python3 -c \"s='''innerwarden allow x'''; import os; os.system(s)\"",
        // An agent's settings and the guard's posture written.
        "cat > ~/.claude/settings.json <<'EOF'\n{\"hooks\":{}}\nEOF",
        "printf 'default\\n' > ~/.config/innerwarden/posture",
        "python3 - <<'EOF'\np='/home/u/.claude/settings.json'\nopen(p,'w').write('{}')\nEOF",
        "python3 -c \"import os; p=os.path.join('/home/u','.claude','settings.json'); open(p,'w').write('{}')\"",
        "python3 -c \"p='/home/u/.cla'+'ude/settings.json'; open(p,'w').write('{}')\"",
        "python3 - <<'EOF'\np='''x\n/home/u/.claude/settings.json'''.split()[1]\nopen(p,'w').write('{}')\nEOF",
        "python3 - <<'EOF'\nimport json\np='/home/u/.claude/settings.json'\nd=json.load(open(p))\nd['hooks']={}\njson.dump(d,open(p,'w'))\nEOF",
        "node -e \"require('fs').writeFileSync('/home/u/.claude/settings.json','{}')\"",
        // A security monitor stopped by a line that runs, here or there.
        "ssh h1 'echo root:x | chpasswd'",
        "ssh h1 'sudo systemctl stop innerwarden-agent'",
        "ssh h1 bash -s <<'EOF'\nsystemctl stop auditd\nEOF",
        "sh -c 'systemctl stop auditd'",
        "echo \"systemctl stop auditd\" | sh",
        "cat <<'EOF' | bash\nsystemctl stop auditd\nEOF",
        "cat > /tmp/s.sh <<'EOF'\nsystemctl stop auditd\nEOF\nbash /tmp/s.sh",
        "echo 'systemctl stop auditd' > /tmp/s.sh; bash /tmp/s.sh",
        "python3 -c \"import os; os.system('systemctl stop auditd')\"",
        "python3 - <<'EOF'\nimport os\nos.system(\"\"\"systemctl stop auditd\"\"\")\nEOF",
        "python3 - <<'EOF'\nimport os\nfor l in '''x\nsystemctl stop auditd'''.splitlines(): os.system(l)\nEOF",
        "python3 - <<'EOF' | sh\nprint('''systemctl stop auditd''')\nEOF",
        // `cat` that may not be the program the masks trust.
        "f(){ bash; }; alias cat=f; cat <<'EOF'\nsystemctl stop auditd\nEOF",
        "PATH=/tmp/x:$PATH; cat <<'EOF'\nsystemctl stop auditd\nEOF",
        "/tmp/x/cat <<'EOF'\nsystemctl stop auditd\nEOF",
    ] {
        assert!(refused_in_both_postures(line), "{line}");
    }
}
