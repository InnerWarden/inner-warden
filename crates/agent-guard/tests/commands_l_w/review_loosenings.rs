//! Lines the review of the here-document and argv reading found let through
//! that were refused before it. Each must stay refused.

use innerwarden_agent_guard::mcp::{analyze_command, inspect_tool_call};
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

/// Held for review, not refused: a word of the guard that code only prints
/// or writes into a project file is a mention (decision of the operator,
/// 2026-11-21, `tests/guard/guard_word_mention_and_action.rs`).
fn assert_held(cases: &[&str]) {
    for command in cases {
        let (recommendation, why) = verdict(command);
        assert_eq!(recommendation, "review", "{command:?}: {why}");
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
        "python3 - <<'EOF'\np = 'docs/guard.md'\ns = open(p).read()\ns = s.replace('old text', 'new text')\nopen(p, 'w').write(s)\nEOF",
    ]);
}

/// The same code as a quoted here-document fed to the interpreter and as
/// its inline form (`-c`, `-e`, `-r`).
fn heredoc_and_inline(interpreter: &str, code: &str) -> [String; 2] {
    let flag = match interpreter {
        "python3" => "-c",
        "php" => "-r",
        _ => "-e",
    };
    [
        format!("{interpreter} - <<'EOF'\n{code}\nEOF"),
        format!("{interpreter} {flag} '{}'", code.replace('\'', r"'\''")),
    ]
}

/// The guard's words in interpreter code are read as shell, here-document
/// and `-c` alike, as they were before here-documents were read as
/// programs. Each of these reached a program through a name built at run
/// time, past every list of run calls the reviews tried.
///
/// FAILS ON REVERT of reading the guard's words on the line as written in
/// `analyze_command_as_read` (mcp.rs): a body blanked as "starts no
/// program" let these through.
#[test]
fn guard_words_in_interpreter_code_are_read_as_shell() {
    let cases = [
        ("php", "<?php $f='sy'; $f.='stem'; $f('innerwarden allow x');"),
        ("perl", "my $f='sy'; $f.='stem'; &$f('innerwarden allow x');"),
        ("lua", "local f='exe'..'cute'; _G['os'][f]('innerwarden allow x')"),
        (
            "node",
            "const k=Buffer.from('70726f63657373','hex').toString(); global[k].mainModule.require('child_'+'process').execSync('innerwarden allow x')",
        ),
        ("ruby", "Kernel.method(\"sys\" \"tem\").call('innerwarden allow x')"),
    ];
    let lines: Vec<String> = cases
        .iter()
        .flat_map(|(interpreter, code)| heredoc_and_inline(interpreter, code))
        .collect();
    let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
    assert_denied(&lines);
    // Code that only prints the words, with no way to call what it holds
    // (no lookup, no run call, no import), names the guard: held for
    // review since 2026-11-21, refused before.
    let printed = [
        (
            "python3",
            "f = 'sy' 'stem'; print(f, 'innerwarden allow x')",
        ),
        ("python3", "print('innerwarden allow x')"),
        ("node", "console.log('innerwarden dry-run')"),
    ];
    let lines: Vec<String> = printed
        .iter()
        .flat_map(|(interpreter, code)| heredoc_and_inline(interpreter, code))
        .collect();
    let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
    assert_held(&lines);
}

/// An edit of source that quotes a guard command, through a here-document
/// or `-c`, was refused until 2026-11-21 (the false refusal this pinned);
/// since the decision of that day it is a mention, held for review.
#[test]
fn editing_source_that_quotes_a_guard_command_inline_is_held_for_review() {
    let code = "p = 'docs/guard.md'; s = open(p).read(); open(p, 'w').write(s.replace('innerwarden allow x', 'innerwarden allow y'))";
    let lines = heredoc_and_inline("python3", code);
    assert_held(&[lines[0].as_str(), lines[1].as_str()]);
}

/// Code that edits a file and holds no guard word runs, either way.
#[test]
fn editing_source_without_a_guard_word_runs_either_way() {
    for code in [
        "p = 'src/a.rs'; s = open(p).read(); s = s.replace('a', 'b'); open(p, 'w').write(s)",
        "s=open('src/a.rs').read(); s=s.replace('a','b'); open('src/a.rs','w').write(s)",
    ] {
        let lines = heredoc_and_inline("python3", code);
        assert_allowed(&[lines[0].as_str(), lines[1].as_str()]);
    }
}

/// Writes of an agent's settings the patterns did not spell out: a Node
/// `fs` call through a name or a callback, a `Path` replaced through a name
/// or a chain, a mode or flags that are not a literal read, and the name
/// split across names.
#[test]
fn settings_written_through_a_name_or_a_callback_are_refused() {
    assert_denied(&[
        "node -e \"require('fs').writeFile('/home/u/.claude/settings.json','{}',()=>{})\"",
        "node -e \"const fsp=require('fs').promises; fsp.writeFile('/home/u/.claude/settings.json','{}')\"",
        "node -e \"require('fs/promises').rm('/home/u/.claude/settings.json')\"",
        "node -e \"const f=require('fs'); f.appendFile('/home/u/.claude/settings.json','x',()=>{})\"",
        "python3 -c \"from pathlib import Path; p=Path.home()/'.claude'/'settings.json'; Path('/tmp/x').replace(p)\"",
        "python3 -c \"from pathlib import Path; p=Path.home()/'.claude'/'settings.json'; p.replace('/tmp/x')\"",
        "python3 -c \"m='wb'; open('/home/u/.claude/settings.json',m).close()\"",
        "python3 -c \"import os; os.open('/home/u/.claude/settings.json', os.O_TRUNC|os.O_WRONLY)\"",
        "python3 -c \"import os; a='settings'; b='.json'; p=os.path.expanduser('~/.claude/')+a+b; open(p,'w').write('{}')\"",
        "python3 - <<'EOF'\nimport os\na='settings'; b='.json'\np=os.path.expanduser('~/.claude/')+a+b\nopen(p,'w').write('{}')\nEOF",
        // A `Path` built from a name that holds the settings path.
        "python3 -c \"from pathlib import Path; x='/home/u/.claude/settings.json'; p=Path(x); p.replace('/tmp/s')\"",
        // `.claude` built from pieces as well.
        "python3 -c \"import os; d='.cla'+'ude'; a='settings'; p=os.path.join(os.environ['HOME'], d, a+'.json'); open(p,'w').write('{}')\"",
        "python3 -c \"import os; d='.cl'; e='aude'; a='settings'; p=os.path.expanduser('~/'+d+e+'/'+a+'.json'); open(p,'w').write('{}')\"",
    ]);
    assert_allowed(&[
        "node -e \"require('fs').readFile('/home/u/.claude/settings.json','utf8',(e,d)=>console.log(d))\"",
        "python3 -c \"open('/home/u/.claude/settings.json','r').close()\"",
        "python3 -c \"import sys, os; os.close(os.open('/home/u/.claude/settings.json', os.O_RDONLY))\"",
        "python3 -c \"from pathlib import Path; p=Path.home()/'.claude'/'settings.json'; print(p.read_text().replace('a','b'))\"",
        "python3 -c \"a='settings'; print(open('/home/u/.claude/'+a+'.json').read())\"",
        "python3 -c \"x='notes/settings.txt'; open(x,'w').write('a')\"",
        "python3 -c \"open('app/settings.py','w').write('DEBUG = False')\"",
        "python3 -c \"from pathlib import Path; x='/home/u/.claude/settings.json'; p=Path(x); print(p.exists())\"",
    ]);
}

/// A here-document program is read as shell, as before, unless it holds
/// nothing that could start a program: no import, no run or eval call, no
/// lookup by a built name, no character built from its code. Each of these
/// reached a program through a way the earlier list of run calls missed.
#[test]
fn a_heredoc_program_that_could_start_one_is_read_as_shell() {
    assert_denied(&[
        "ruby - <<'EOF'\n%x!innerwarden allow x!\nEOF",
        "ruby - <<'EOF'\n%x\"innerwarden allow x\"\nEOF",
        "ruby - <<'EOF'\n%x|innerwarden allow x|\nEOF",
        "node <<'EOF'\nconst k = String.fromCharCode(101, 120, 101, 99);\nconsole.log(k, 'innerwarden allow x');\nEOF",
        r"node <<'EOF'
const k = '\x65xecSync';
console.log(k, 'innerwarden allow x');
EOF",
        r"python3 - <<'EOF'
import operator, os
operator.attrgetter('\x73ystem')(os)('innerwarden allow x')
EOF",
        r"python3 - <<'EOF'
f = '\163ystem'
print(f, 'innerwarden allow x')
EOF",
    ]);
    // An edit of a project file through `Path`, its text quoting a guard
    // command: a mention since 2026-11-21, held for review.
    assert_held(&[
        "python3 - <<'EOF'\nfrom pathlib import Path\np = Path('docs/guard.md')\np.write_text(p.read_text().replace('innerwarden allow x', 'innerwarden allow y'))\nEOF",
    ]);
}

/// The environment a proxied shell tool call carries is read as variables
/// exported before its command, not as an inert key: `BASH_ENV` and
/// `LD_PRELOAD` there are refused as they are on the line.
#[test]
fn a_preload_variable_in_a_tool_call_environment_is_refused() {
    for name in ["BASH_ENV", "LD_PRELOAD"] {
        let args = serde_json::json!({"command": "bash -c ls", "env": {name: "/tmp/x"}});
        let proxied = inspect_tool_call("run_command", &args, None);
        assert!(!proxied.allowed, "{name}: {proxied:?}");
        let (recommendation, why) = verdict(&format!("{name}=/tmp/x bash -c ls"));
        assert_eq!(recommendation, "deny", "{name}: {why}");
    }
}
