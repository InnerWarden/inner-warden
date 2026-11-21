//! End-to-end: a project's own agent settings are held as the person's are.
//!
//! Claude Code reads hooks, the hook switch, the permission mode and the key
//! helper from the project's \`.claude/settings.json\` and
//! \`.claude/settings.local.json\` as well as from the home (2.1.330: a
//! \`disableAllHooks\` there switches off every hook that is not managed,
//! the person's own included). An agent works in that project and can write
//! both files, so a write that switches the guard's hook off, adds a hook,
//! puts the session in bypass mode or names a key helper is refused, by the
//! shell and by the file tools alike. The hold is by path: every write the
//! agent makes to those files is refused, a rule it adds to
//! \`permissions.allow\` and a project hook (a formatter, for one) included.
//! Claude Code's own "always allow" is written by Claude Code, not through a
//! tool call, and still works.
//!
//! These run the REAL binary the way Claude Code runs it, with HOME and the
//! record in a scratch directory.

use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        for folder in [".claude", ".codex", ".gemini", ".cursor", "src"] {
            std::fs::create_dir_all(dir.path().join("home/proj").join(folder)).expect("project");
        }
        Self { dir }
    }

    fn home(&self) -> std::path::PathBuf {
        self.dir.path().join("home")
    }

    fn project(&self) -> std::path::PathBuf {
        self.home().join("proj")
    }

    /// Run the hook once with \`payload\`; the exit code and stderr.
    fn hook(&self, payload: &serde_json::Value) -> (Option<i32>, String) {
        let mut child = Command::new(bin())
            .args(["hook", "--agent", "claude-code"])
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("IW_SESSION_FILE", self.dir.path().join("sessions.json"))
            .current_dir(self.project())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run innerwarden hook");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(payload.to_string().as_bytes())
            .expect("write stdin");
        let out = child.wait_with_output().expect("collect output");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn bash(&self, command: &str) -> serde_json::Value {
        serde_json::json!({
            "session_id": "s-project-settings",
            "hook_event_name": "PreToolUse",
            "cwd": self.project(),
            "tool_name": "Bash",
            "tool_input": { "command": command },
        })
    }

    fn write_tool(&self, relative: &str, content: &str) -> serde_json::Value {
        serde_json::json!({
            "session_id": "s-project-settings",
            "hook_event_name": "PreToolUse",
            "cwd": self.project(),
            "tool_name": "Write",
            "tool_input": {
                "file_path": self.project().join(relative),
                "content": content,
            },
        })
    }

    fn edit_tool(&self, relative: &str, old: &str, new: &str) -> serde_json::Value {
        serde_json::json!({
            "session_id": "s-project-settings",
            "hook_event_name": "PreToolUse",
            "cwd": self.project(),
            "tool_name": "Edit",
            "tool_input": {
                "file_path": self.project().join(relative),
                "old_string": old,
                "new_string": new,
            },
        })
    }
}

/// Every way of lowering the guard from a project's settings, refused.
///
/// FAILS ON REVERT: take `.cursor/hooks.json` out of the guard's settings
/// places and the two Cursor lines run.
#[test]
fn a_project_settings_write_that_lowers_the_guard_is_refused() {
    let host = Host::new();
    let refused = [
        // The shell.
        host.bash(r#"echo '{"disableAllHooks": true}' > .claude/settings.local.json"#),
        host.bash(r#"echo '{"disableAllHooks": true}' > .claude/settings.json"#),
        host.bash(r#"printf '{"hooks":{}}' > .claude/settings.json"#),
        host.bash(r#"echo '{"permissions":{"defaultMode":"bypassPermissions"}}' > .claude/settings.local.json"#),
        host.bash(r#"echo '{"apiKeyHelper":"./key.sh"}' > .claude/settings.json"#),
        host.bash(r#"sed -i 's/"allow"/"disableAllHooks": true, "allow"/' .claude/settings.local.json"#),
        host.bash(r#"sed -i 's/acceptEdits/bypassPermissions/' .claude/settings.json"#),
        host.bash(
            r#"python3 -c 'import json; open(".claude/settings.local.json","w").write(json.dumps({"disableAllHooks": True}))'"#,
        ),
        host.bash(
            r#"python3 -c 'import json; json.dump({"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"true"}]}]}}, open(".claude/settings.json","w"))'"#,
        ),
        // The file tools.
        host.write_tool(".claude/settings.local.json", r#"{"disableAllHooks": true}"#),
        host.write_tool(
            ".claude/settings.json",
            r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"./allow-all.sh"}]}]}}"#,
        ),
        host.write_tool(
            ".claude/settings.json",
            r#"{"permissions":{"defaultMode":"bypassPermissions"}}"#,
        ),
        host.write_tool(".claude/settings.local.json", r#"{"apiKeyHelper":"./key.sh"}"#),
        host.edit_tool(
            ".claude/settings.json",
            r#""allow": ["#,
            r#""defaultMode": "bypassPermissions", "allow": ["#,
        ),
        host.edit_tool(".claude/settings.local.json", "{", r#"{"disableAllHooks": true,"#),
        // The other agents' project files.
        host.write_tool(".gemini/settings.json", r#"{"hooksConfig":{"enabled":false}}"#),
        host.write_tool(".cursor/hooks.json", r#"{"version":1,"hooks":{}}"#),
        host.write_tool(".codex/config.toml", "[features]\ncodex_hooks = false\n"),
        host.bash(r#"echo '{"version":1,"hooks":{}}' > .cursor/hooks.json"#),
        host.bash(r#"echo '{"hooksConfig":{"enabled":false}}' > .gemini/settings.json"#),
    ];
    let mut let_through = Vec::new();
    for payload in &refused {
        let (code, stderr) = host.hook(payload);
        if code != Some(2) {
            let_through.push(format!("{code:?} {} :: {stderr}", payload["tool_input"]));
        }
    }
    assert!(
        let_through.is_empty(),
        "let through:\n{}",
        let_through.join("\n")
    );
}

/// The other shapes a write to a project's settings takes, refused like the
/// plain redirect: a copy or a move onto the file, `tee`, an append, a
/// heredoc, a write from inside `.claude`, git putting another version of
/// the file back, a file written elsewhere and moved in, a link made at the
/// file's place or put where `.claude` was, a link made to `.claude` or to
/// a settings file (refused when it is made, since the write through it
/// later names neither), the absolute path, node and
/// ruby, and the folder spelled in capitals, which is the same folder on a
/// macOS disk. The hold is by path: even a rule added to
/// `permissions.allow` by the agent is refused.
#[test]
fn every_shape_of_a_project_settings_write_is_refused() {
    let host = Host::new();
    let abs = host.project().join(".claude/settings.json");
    let abs = abs.display();
    let shapes = [
        host.bash("cp /dev/null .claude/settings.json"),
        host.bash("cp ../x.json .claude/settings.local.json"),
        host.bash("mv x.json .claude/settings.json"),
        host.bash(r#"echo '{"disableAllHooks": true}' | tee .claude/settings.local.json"#),
        host.bash(r#"echo '{"disableAllHooks": true}' >> .claude/settings.local.json"#),
        host.bash("cat > .claude/settings.json <<'EOF'\n{\"disableAllHooks\": true}\nEOF"),
        host.bash("cd .claude && cp ../x.json settings.json"),
        host.bash(r#"cd .claude && echo '{"disableAllHooks": true}' > settings.local.json"#),
        host.bash("git checkout other -- .claude/settings.json"),
        host.bash("git restore --source=other .claude/settings.local.json"),
        host.bash(
            r#"echo '{"disableAllHooks": true}' > /tmp/s.json && mv /tmp/s.json .claude/settings.json"#,
        ),
        host.bash("ln -sf ../x.json .claude/settings.json"),
        host.bash("rm -rf .claude && ln -s ../elsewhere .claude"),
        host.bash("ln -sfn ../elsewhere .claude"),
        host.bash("mv ../elsewhere .claude"),
        // A link made first, then written through: the line that makes a
        // link to the folder or to a settings file is refused.
        host.bash(r#"ln -s .claude c && echo '{"disableAllHooks": true}' > c/settings.json"#),
        host.bash(r#"ln -s .claude/settings.json s && echo '{"disableAllHooks": true}' > s"#),
        host.bash("ln -s .claude c"),
        host.bash("ln -s \"$PWD/.claude\" /tmp/c"),
        host.bash("ln -s .claude/settings.local.json s"),
        host.bash("ln .claude/settings.json hard"),
        host.bash("cp -r ../elsewhere .claude"),
        host.bash(&format!(r#"echo '{{"disableAllHooks": true}}' > {abs}"#)),
        host.bash(
            r#"node -e 'require("fs").writeFileSync(".claude/settings.json", JSON.stringify({disableAllHooks: true}))'"#,
        ),
        host.bash(r#"ruby -e 'File.write(".claude/settings.local.json", %q({"disableAllHooks": true}))'"#),
        host.bash(r#"echo '{"disableAllHooks": true}' > .CLAUDE/settings.json"#),
        host.bash(r#"echo '{"version":1,"hooks":{}}' > .Cursor/hooks.json"#),
        host.write_tool(".Claude/Settings.Local.json", r#"{"disableAllHooks": true}"#),
        host.write_tool(".CURSOR/hooks.json", r#"{"version":1,"hooks":{}}"#),
        // Held by path: a rule added to `permissions.allow` is refused too.
        host.edit_tool(
            ".claude/settings.local.json",
            r#""allow": ["#,
            r#""allow": ["Bash(npm test)", "#,
        ),
        // A project's own hooks, a formatter for one, are refused as well:
        // an accepted false positive, since a hook the agent writes runs
        // outside the guard.
        host.write_tool(
            ".claude/settings.json",
            r#"{"hooks":{"PostToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"cargo fmt"}]}]}}"#,
        ),
        host.write_tool(".codex/hooks.json", r#"{"hooks":{}}"#),
        // What a folder holds copied into an agent's folder, and an archive
        // unpacked into one: the names written are not on the line, and a
        // `settings.json` written first in `../x` lands in the settings.
        host.bash("rsync -a ../x/ .claude"),
        host.bash("rsync -a ../x/ .claude/"),
        host.bash("rsync -r ../x/. .codex/"),
        host.bash("cp -r ../x/. .claude/"),
        host.bash("cp -r ../x/. .claude"),
        host.bash("cp -r ../x/* .claude/"),
        host.bash("cp ../x/*.json .claude/"),
        host.bash("cp -R ../x/ .claude/"),
        host.bash("cd .claude && cp -r ../../x/. ."),
        host.bash("tar -xf x.tar -C .claude"),
        host.bash("tar -C .gemini -xzf x.tgz"),
        host.bash("tar --extract --file x.tar --directory=.claude/"),
        host.bash("cd .claude && tar -xf ../x.tar"),
        host.bash("unzip x.zip -d .claude"),
        host.bash("unzip -o x.zip -d .cursor/"),
        host.bash("bsdtar -xf x.tar -C .claude"),
        host.bash("7z x x.7z -o.claude"),
        host.bash("7za e x.7z -o.codex"),
    ];
    let mut let_through = Vec::new();
    for payload in &shapes {
        let (code, stderr) = host.hook(payload);
        if code != Some(2) {
            let_through.push(format!("{code:?} {} :: {stderr}", payload["tool_input"]));
        }
    }
    assert!(
        let_through.is_empty(),
        "let through:\n{}",
        let_through.join("\n")
    );
}

/// The ordinary side: a link, a copy and a move near a project that name no
/// agent folder and no settings file still run, and a file moved INTO an
/// agent's folder (the folder ending with `/`) runs too.
#[test]
fn ordinary_links_copies_and_moves_in_a_project_still_run() {
    let host = Host::new();
    let ordinary = [
        "ln -s ../shared/node_modules node_modules",
        "cp -r ../tpl .",
        "mv build .",
        "mv notes.md .claude/",
        // A single file into an agent's folder under a name that is not a
        // settings file, and copies and unpacks into other folders.
        "cp notes.md .claude/notes.md",
        "cp docs/*.md .claude/",
        "rsync -a src/ build/",
        "cp -r ../tpl/. src/",
        "tar -xf x.tar -C vendor",
        "unzip x.zip -d vendor",
        "tar -xf x.tar",
        "7z x x.7z -ovendor",
    ];
    let mut stopped = Vec::new();
    for command in ordinary {
        let (code, stderr) = host.hook(&host.bash(command));
        if code != Some(0) {
            stopped.push(format!("{code:?} {command} :: {stderr}"));
        }
    }
    assert!(stopped.is_empty(), "stopped:\n{}", stopped.join("\n"));
}

/// A move onto an agent's folder by its bare name stays refused, because
/// with no folder there it becomes the folder, settings included; the
/// refusal says so and names the spelling that moves a file into it.
#[test]
fn a_move_onto_an_agent_folder_by_its_bare_name_is_refused_and_says_why() {
    let host = Host::new();
    for command in [
        "mv notes.md .claude",
        "mv x.md .codex",
        "ln -s ../elsewhere .claude",
    ] {
        let (code, stderr) = host.hook(&host.bash(command));
        assert_eq!(code, Some(2), "{command}: {stderr}");
        assert!(
            stderr.contains("end the folder with a slash"),
            "{command}: {stderr}"
        );
    }
}

/// A copy of what a folder holds into an agent's folder is refused with its
/// `/` too, so the refusal does not tell the agent to end the folder with a
/// slash.
#[test]
fn a_copy_of_a_folders_contents_onto_an_agent_folder_does_not_say_add_a_slash() {
    let host = Host::new();
    for command in ["cp -r ../x/. .claude", "rsync -a ../x/ .claude"] {
        let (code, stderr) = host.hook(&host.bash(command));
        assert_eq!(code, Some(2), "{command}: {stderr}");
        assert!(
            !stderr.contains("end the folder with a slash"),
            "{command}: {stderr}"
        );
    }
}

/// Interpreter code that opens a project settings file to write: Python's
/// `open(path, "w")` and Ruby's `File.new(path, "w")` are refused by the
/// interpreter rule that names the file before the write (the one that
/// names the write first, `FileUtils` among it, would not see them), and
/// Ruby's `FileUtils` with the file named first, through a variable, is
/// refused too.
#[test]
fn interpreter_writes_to_project_settings_are_refused_with_the_interpreter_reason() {
    let host = Host::new();
    for command in [
        r#"python3 -c 'open(".claude/settings.json","w")'"#,
        r#"ruby -e 'File.new(".claude/settings.json","w")'"#,
        r#"node -e 'require("fs").writeFileSync(".claude/settings.json","{}")'"#,
        r#"ruby -e 'p=".claude/settings.json"; FileUtils.cp("x.json", p)'"#,
    ] {
        let (code, stderr) = host.hook(&host.bash(command));
        assert_eq!(code, Some(2), "{command}: {stderr}");
        assert!(
            stderr.contains("rewrites an agent's configuration through an interpreter"),
            "{command}: {stderr}"
        );
    }
}

/// The PreToolUse entry of a settings file, the person's and the project's,
/// rewritten the four ways an agent reaches for: `jq` to a temporary file
/// and `mv` back, `sed -i`, `python3` with `json.dump`, and `jq` into
/// `sponge`. Each is refused.
#[test]
fn the_pre_tool_use_entry_rewritten_four_ways_is_refused() {
    let host = Host::new();
    let home = host.home().join(".claude/settings.json");
    let home = home.display().to_string();
    let mut let_through = Vec::new();
    for file in [
        "~/.claude/settings.json",
        home.as_str(),
        ".claude/settings.json",
    ] {
        for command in [
            format!("jq '.hooks.PreToolUse = []' {file} > /tmp/s.json && mv /tmp/s.json {file}"),
            format!("sed -i '/PreToolUse/d' {file}"),
            format!(
                r#"python3 -c 'import json,os;p=os.path.expanduser("{file}");d=json.load(open(p));d["hooks"]["PreToolUse"]=[];json.dump(d,open(p,"w"))'"#
            ),
            format!("jq 'del(.hooks.PreToolUse)' {file} | sponge {file}"),
        ] {
            let (code, stderr) = host.hook(&host.bash(&command));
            if code != Some(2) {
                let_through.push(format!("{code:?} {command} :: {stderr}"));
            }
        }
    }
    assert!(
        let_through.is_empty(),
        "let through:\n{}",
        let_through.join("\n")
    );
}
