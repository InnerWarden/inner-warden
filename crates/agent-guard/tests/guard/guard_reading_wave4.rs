//! The fourth pass on how the guard reads a line, each measured 2026-11-26
//! on the branch before the change (every refused line below was allowed):
//!
//! * the guard's units listed by `ls`, `find` or `printf` and handed to
//!   `xargs rm` are the units removed;
//! * a `PATH=` value is read as the shell hands it over, its backslash
//!   escapes taken out (`PATH=\/tmp/x:...` is `PATH=/tmp/x:...`);
//! * Lua reaches `require`, `pcall` and `select` by a name of its own, and
//!   luaposix's `posix.spawn` module through a name; Node's
//!   `require('fs/promises')` is `fs.promises`;
//! * an agent started with the guard's alerts or configuration named
//!   elsewhere (`IW_NOTIFY_CONFIG`, `IW_LLM_CONFIG`, `XDG_CONFIG_HOME`) is
//!   started without them;
//! * a `HOME` the line gives a value it does not show leaves `~` unknown: a
//!   removal or write under it that can be a file of the guard is held for
//!   review.
//!
//! Asserted through [`analyze_command`], the entry point the hook uses.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

/// FAILS ON REVERT of `names_ls_lists` and `files_find_lists` in
/// `lines_xargs_builds` (`shell.rs`).
#[test]
fn units_listed_into_xargs_rm_are_removed() {
    for line in [
        "ls ~/.config/systemd/user/innerwarden* | xargs rm",
        "ls /etc/systemd/system/inner* | xargs rm -f",
        "find ~/.config/systemd/user -name 'inner*' | xargs rm",
        "find ~/.config/systemd/user -name 'inner*' -print0 | xargs -0 rm -f",
        "printf '%s\\n' ~/.config/systemd/user/inner* | xargs rm",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        "ls *.log | xargs rm",
        "find . -name '*.pyc' | xargs rm -f",
        "find build -type f -name '*.o' -print0 | xargs -0 rm -f",
        "ls -l | xargs echo",
        "find ~/.config/systemd/user -name 'myapp*' | xargs rm",
        "printf '%s\\n' src/*.rs | xargs rustfmt",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// FAILS ON REVERT of `path_assignments_as_read` in `check_command_except`.
#[test]
fn a_path_value_is_read_without_its_escapes() {
    for line in [
        "export PATH=\\/tmp/x:/usr/bin:/bin",
        "PATH=\\/tmp/x:$PATH",
        "export PATH=\\/\\t\\m\\p/x:$PATH",
        "export PATH=\\/dev/shm/x:$PATH",
        "export PATH=\\/var/tmp/x:$PATH",
        "export PATH=/usr/bin:\\/tmp/x:$PATH",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        "export PATH=\\/home/dev/bin:$PATH",
        "export PATH=\\$HOME/bin:$PATH",
        "export PATH=\"$HOME/.cargo/bin:$PATH\"",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// FAILS ON REVERT of `lua_builtin_aliases` (`shell/inline_calls.rs`), of
/// `posix.spawn` as a table of process functions, and of the module path
/// of `require` in `credential_removal_by_code.rs`.
#[test]
fn lua_and_node_by_another_name_are_read() {
    for line in [
        "lua -e 'local r=require; r(\"os\").execute(\"rm -rf ~\")'",
        "lua -e 'local req=require; req\"os\".execute(\"rm -rf ~\")'",
        "lua -e 'local r=require; local o=r(\"os\"); o.execute(\"rm -rf ~\")'",
        "lua -e 'select(2,pcall(require,\"os\")).execute(\"rm -rf ~\")'",
        "lua -e 'local x=pcall; select(2,x(require,\"os\")).execute(\"rm -rf ~\")'",
        "lua -e 'require(\"posix.spawn\").spawn(\"rm -rf ~\")'",
        "lua -e 'local s=require(\"posix.spawn\"); s.spawn(\"rm -rf ~\")'",
        "lua -e 'local r=require; r(\"os\").remove(os.getenv(\"HOME\")..\"/.ssh/id_ed25519\")'",
        "node -e \"require('fs/promises').rm('/home/dev/.ssh',{recursive:true})\"",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        "lua -e 'local r=require; print(r(\"os\").clock())'",
        "lua -e 'local ok,j=pcall(require,\"cjson\"); print(ok)'",
        "node -e \"require('fs/promises').rm('dist',{recursive:true})\"",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// FAILS ON REVERT of `iw_notify_config`, `iw_llm_config` and
/// `xdg_config_home` in `AGENT_HOOK_VARIABLES`.
#[test]
fn an_agent_started_with_the_guard_config_elsewhere_is_refused() {
    for line in [
        "IW_NOTIFY_CONFIG=/dev/null claude -p 'fix the test'",
        "env IW_NOTIFY_CONFIG=/dev/null codex exec 'fix the test'",
        "export IW_NOTIFY_CONFIG=/dev/null; claude -p 'fix'",
        "IW_NOTIFY_CONFIG=/tmp/n.toml gemini -p 'fix'",
        "IW_LLM_CONFIG=/dev/null claude -p 'fix'",
        "XDG_CONFIG_HOME=/tmp/x claude -p 'fix'",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        "XDG_CONFIG_HOME=$HOME/.config claude -p 'fix'",
        "IW_NOTIFY_CONFIG=/dev/null cargo test -p innerwarden",
        "claude -p 'fix the test'",
        "echo $IW_NOTIFY_CONFIG",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// FAILS ON REVERT of `removal_may_reach_guard_file` in
/// `check_guard_takedown`: each held line is allowed.
#[test]
fn a_home_the_line_does_not_show_holds_the_guards_files_for_review() {
    for line in [
        "read -r HOME < <(echo /etc); rm -rf ~/innerwarden",
        "read -r HOME < <(echo /etc); cd ~ && rm -rf innerwarden",
        "mapfile HOME < /tmp/h; rm -rf ~/innerwarden",
        "read -r HOME; rm -rf ~/innerwarden",
        "read -r HOME < <(echo /etc); sed -i d ~/innerwarden/guard.toml",
    ] {
        assert_eq!(verdict(line), "review", "{line}");
    }
    for line in [
        "read -r HOME < <(echo /etc); rm -rf ~/build",
        "read -r HOME < <(echo /etc); ls ~/innerwarden",
        "read -r name; rm -rf ~/innerwarden",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
