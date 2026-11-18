//! Lines the review of the here-document and argv reading found let through
//! that were refused before it. Each must stay refused.

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
    let mut passed = Vec::new();
    for command in cases {
        let (recommendation, why) = verdict(command);
        if recommendation != "deny" {
            passed.push(format!("{command:?} -> {recommendation}: {why}"));
        }
    }
    assert!(passed.is_empty(), "not refused:\n{}", passed.join("\n"));
}

/// A `;` inside backquotes ends no command of the line: the stop verb and
/// its target stay one command.
#[test]
fn a_separator_inside_backquotes_does_not_split_the_command() {
    assert_denied(&["systemctl stop `echo x;` innerwarden-agent"]);
}

/// `$'...'` closes only at an unescaped quote: `\'` is a quote inside it.
#[test]
fn an_escaped_quote_inside_ansi_c_quoting_does_not_close_it() {
    assert_denied(&["systemctl stop $'x\\';' innerwarden-agent"]);
}

/// A here-document program that runs a guard command through a call the
/// run markers did not name, or through a name it builds, is read.
#[test]
fn a_heredoc_program_that_runs_the_guard_is_read() {
    assert_denied(&[
        "ruby - <<'EOF'\n%x(innerwarden allow x)\nEOF",
        "ruby - <<'EOF'\nrequire 'open3'\nOpen3.capture2('innerwarden', 'allow', 'x')\nEOF",
        "php <<'EOF'\n<?php passthru('innerwarden allow x');\nEOF",
        "python3 - <<'EOF'\nimport os\ngetattr(os,'sy'+'stem')('innerwarden allow x')\nEOF",
        "python3 - <<'EOF'\nm=__import__('o'+'s')\nm.popen2=None\nf=getattr(m,'sys'+'tem')\nf('innerwarden allow x')\nEOF",
        "ruby - <<'EOF'\nKernel.send('sys'+'tem', 'innerwarden allow x')\nEOF",
    ]);
}

/// PHP and Lua writing an agent's settings, as Python and Node do.
#[test]
fn php_and_lua_writing_settings_are_refused() {
    assert_denied(&[
        "php -r \"file_put_contents(getenv('HOME').'/.claude/settings.json', '{}');\"",
        "lua -e \"io.open(os.getenv('HOME')..'/.claude/settings.json','w'):write('{}')\"",
    ]);
}

/// Every mode that writes, and the write calls the rules did not list.
#[test]
fn every_write_mode_and_call_on_settings_is_refused() {
    assert_denied(&[
        "python3 -c \"open('/home/u/.claude/settings.json','wb').close()\"",
        "python3 -c \"open('/home/u/.claude/settings.json','w+').close()\"",
        "python3 -c \"open('/home/u/.claude/settings.json','a').writelines(['x'])\"",
        "python3 -c \"open('/home/u/.claude/settings.json','r+').truncate(0)\"",
        "node -e \"const fs=require('fs'); const fd=fs.openSync('/home/u/.claude/settings.json','a'); fs.writeSync(fd,'x')\"",
        "python3 -c \"from pathlib import Path; Path('/tmp/x.json').replace('/home/u/.claude/settings.json')\"",
        "node -e \"require('fs').promises.unlink('/home/u/.claude/settings.json')\"",
        "node -e \"require('fs').promises.rm('/home/u/.claude/settings.json')\"",
        "node -e \"require('fs').promises.writeFile('/home/u/.claude/settings.json','{}')\"",
        "python3 -c \"import os; os.truncate('/home/u/.claude/settings.json', 0)\"",
    ]);
}

/// A settings name built from pieces, or written far from where it is named.
#[test]
fn a_built_or_distant_settings_path_is_refused() {
    let filler = "x=1; ".repeat(100);
    let distant = format!(
        "python3 -c \"p='/home/u/.claude/settings.json'; {filler}open(p,'w').write('{{}}')\""
    );
    assert_denied(&[
        "python3 -c \"import os; p=os.path.expanduser('~/.claude/'+'set'+'tings.json'); open(p,'w').write('{}')\"",
        "node -e \"require('fs').writeFileSync(process.env.HOME+'/.claude/'+'settings'+'.json','{}')\"",
        distant.as_str(),
    ]);
}

/// `<<-` strips leading tabs from the delimiter line: the body ends at a
/// tab-indented delimiter and what follows is shell.
#[test]
fn a_tab_indented_delimiter_ends_the_body() {
    assert_denied(&["python3 - <<-'EOF'\n\tprint(1)\n\tEOF\ninnerwarden allow x"]);
}

/// What the wider readings must leave alone: settings read, not written,
/// in each language, and a here-document program that edits a file quoting
/// a guard command without starting a program.
#[test]
fn reading_settings_and_editing_text_about_the_guard_stay_allowed() {
    assert_allowed(&[
        "python3 -c \"print(open('/home/u/.claude/settings.json').read().replace('x','a'))\"",
        "node -e \"console.log(require('fs').readFileSync('/home/u/.claude/settings.json','utf8'))\"",
        "php -r \"echo file_get_contents(getenv('HOME').'/.claude/settings.json');\"",
        "lua -e \"print(io.open(os.getenv('HOME')..'/.claude/settings.json'):read('a'))\"",
        "python3 - <<'EOF'\nfrom pathlib import Path\np = Path('docs/guard.md')\np.write_text(p.read_text().replace('innerwarden allow x', 'innerwarden allow y'))\nEOF",
    ]);
}
