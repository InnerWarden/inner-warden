//! The program the agent's settings run as the guard's hook is the guard's,
//! wherever it is: not only in a `hooks` folder or a `bin` folder.
//!
//! A test binary of its own: the settings are read once per process, from
//! the home the process starts with.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

#[test]
fn a_hook_named_in_the_settings_outside_hooks_is_the_guards() {
    let home = tempfile::tempdir().expect("a home");
    std::fs::create_dir_all(home.path().join(".claude")).expect("the settings folder");
    std::fs::write(
        home.path().join(".claude/settings.json"),
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[
            {"type":"command","command":"/opt/iw/innerwarden hook"},
            {"type":"command","command":"bash ~/tools/innerwarden-hook.sh --strict"}
        ]}]}}"#,
    )
    .expect("the settings");
    std::env::set_var("HOME", home.path());
    let absolute = format!("{}/tools/innerwarden-hook.sh", home.path().display());

    for line in [
        "rm -f /opt/iw/innerwarden".to_string(),
        "mv /opt/iw/innerwarden /tmp/x".to_string(),
        "cp /tmp/x /opt/iw/innerwarden".to_string(),
        "rm -f ~/tools/innerwarden-hook.sh".to_string(),
        "rm -f $HOME/tools/innerwarden-hook.sh".to_string(),
        format!("rm -f {absolute}"),
        "echo exit 0 > ~/tools/innerwarden-hook.sh".to_string(),
        "f=~/tools/innerwarden-hook.sh; rm $f".to_string(),
        "find ~/tools -name innerwarden-hook.sh -delete".to_string(),
    ] {
        assert_eq!(verdict(&line), "deny", "{line}");
    }
    for line in [
        "rm -f ~/tools/other.sh",
        "rm -f /opt/iw/notes.txt",
        "rm -f ~/innerwarden/ufw-product.sh",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
