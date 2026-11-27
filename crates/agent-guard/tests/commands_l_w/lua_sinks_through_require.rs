//! Lua reaches `os` and `io` by more ways than their names: `require("os")`,
//! `require "io"`, `(require 'os')`, `require(m)` with `m` given the name,
//! `package.loaded.os`, and a local name given any of them.
//!
//! Measured on main b52291b (2026-11-24) with `analyze_command`: each line
//! of the first test was allowed, while `os.execute(...)` and `io.popen(...)`
//! with the same line were refused. The reader keyed on the text
//! `os.execute`; it now reads a call by the table it reaches, whatever the
//! path to the module.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

/// FAILS ON REVERT: take `lua_required_modules`, the `require(` and
/// `package.loaded[` heads or the `package.loaded.` table out of
/// `shell/inline_calls.rs` and these lines are allowed again.
#[test]
fn a_lua_process_call_through_require_or_a_local_name_is_read() {
    for line in [
        r#"lua -e 'require("os").execute("rm -rf ~")'"#,
        r#"lua -e 'local o = require("os"); o.execute("rm -rf ~")'"#,
        r#"lua -e 'local o = require "os"; o.execute("rm -rf ~")'"#,
        r#"lua -e '(require "os").execute("rm -rf ~")'"#,
        r#"lua -e 'require [[os]].execute("rm -rf ~")'"#,
        r#"lua -e 'require ("os").execute("rm -rf ~")'"#,
        r#"lua -e 'require("os")["execute"]("rm -rf ~")'"#,
        r#"lua -e 'local e = require("os").execute; e("rm -rf ~")'"#,
        r#"lua -e 'local p = require("io").popen; p("rm -rf ~")'"#,
        r#"lua -e 'local m = "os"; require(m).execute("rm -rf ~")'"#,
        r#"lua -e 'local m = "os"; local e = require(m).execute; e("rm -rf ~")'"#,
        r#"lua -e 'package.loaded.os.execute("rm -rf ~")'"#,
        r#"lua -e 'package.loaded["os"].execute("rm -rf ~")'"#,
        r#"lua -e 'local m = "os"; package.loaded[m].execute("rm -rf ~")'"#,
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// A module named by a value the line does not write out may be `os`: a
/// process call through it is not read, so it is held for review.
#[test]
fn a_lua_process_call_through_a_module_not_read_is_held() {
    for line in [
        r#"lua -e 'local o = require(m); o.execute("rm -rf ~")'"#,
        r#"lua -e 'local e = require(m).execute; e("rm -rf ~")'"#,
    ] {
        assert_ne!(verdict(line), "allow", "{line}");
    }
}

/// The other functions of `os` and `io`, other modules, and the words in
/// a string start nothing.
#[test]
fn lua_code_that_requires_os_and_starts_nothing_is_allowed() {
    for line in [
        r#"lua -e 'print(require("os").time())'"#,
        r#"lua -e 'local o = require("os"); print(o.date())'"#,
        r#"lua -e 'print(require "os".clock())'"#,
        r#"lua -e 'local json = require("cjson"); print(json.encode({a=1}))'"#,
        r#"lua -e 'local m = "string"; print(require(m).upper("x"))'"#,
        r#"lua -e 'local p = require("io").popen("ls"); print(p:read("*a"))'"#,
        r#"lua -e 'print("require(\"os\").execute")'"#,
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
