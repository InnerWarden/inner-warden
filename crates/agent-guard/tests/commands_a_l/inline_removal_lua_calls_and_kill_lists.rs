//! Inline code that removes a key or a credential store by another spelling,
//! Lua that reaches a process call through a name it was given, and an
//! `xargs kill` whose listing the line writes over before the kill reads it.
//!
//! Measured 2026-11-25 with `analyze_command` against the branch before
//! this change: every line of the refusing tests was allowed (the kill lines
//! of the last test were allowed with the reach of `pgrep -f vite`).
//!
//! - Python reaches the call by an import alias, `from os import`,
//!   `__import__`, `getattr` or `importlib.import_module`; the key is
//!   renamed or moved instead of removed; the path is built by joining
//!   strings, a format or `'/'.join`; the code comes on a here-string.
//! - Lua reaches `os` through `pcall(require, "os")`, calls through
//!   `xpcall`, and luaposix's `exec` and `execp` of `posix` and
//!   `posix.unistd` start a program with the table of its arguments.
//! - The file `xargs kill` reads is rewritten after the listing (`> ./p`,
//!   `$PWD/p`, `cp`, `mv`, `dd of=`, `tee`, `sed -i`, `install`,
//!   `rsync`), read from another folder after `cd`, or the kill takes a
//!   second input (`-a`, `--arg-file`, two `<`).

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

/// FAILS ON REVERT: take `canonical_code`, the rename calls, the joined
/// strings or the here-string out of
/// `src/threats/credential_removal_by_code.rs` and these are allowed.
#[test]
fn inline_code_removing_a_key_by_another_spelling_is_refused() {
    for line in [
        r#"python3 -c "import os as o; o.remove('/home/u/.ssh/id_ed25519')""#,
        r#"python3 -c "from os import remove; remove('/home/u/.ssh/id_ed25519')""#,
        r#"python3 -c "from os import remove as r; r('/home/u/.ssh/id_ed25519')""#,
        r#"python3 -c "__import__('os').remove('/home/u/.ssh/id_ed25519')""#,
        r#"python3 -c "import os; getattr(os, 'remove')('/home/u/.ssh/id_ed25519')""#,
        r#"python3 -c "import os; f = getattr(os, 'unlink'); f('/home/u/.ssh/id_ed25519')""#,
        r#"python3 -c "import importlib; importlib.import_module('os').remove('/home/u/.ssh/id_ed25519')""#,
        r#"python3 -c "import os; os.rename('/home/u/.ssh/id_ed25519', '/tmp/k')""#,
        r#"python3 -c "import os; os.replace('/home/u/.ssh/id_ed25519', '/tmp/k')""#,
        r#"python3 -c "import shutil; shutil.move('/home/u/.ssh', '/tmp/x')""#,
        r#"python3 -c "from pathlib import Path; Path('/home/u/.ssh/id_rsa').rename('/tmp/k')""#,
        r#"ruby -e 'File.rename("/home/u/.ssh/id_ed25519", "/tmp/k")'"#,
        r#"ruby -e 'require "fileutils"; FileUtils.mv("/home/u/.ssh", "/tmp/x")'"#,
        r#"perl -e 'rename "/home/u/.ssh/id_ed25519", "/tmp/k"'"#,
        r#"php -r 'rename("/home/u/.ssh/id_ed25519", "/tmp/k");'"#,
        r#"node -e 'require("fs").renameSync("/home/u/.ssh/id_ed25519", "/tmp/k")'"#,
        r#"lua -e 'os.rename("/home/u/.ssh/id_ed25519", "/tmp/k")'"#,
        r#"python3 -c "import os; os.remove('/home/u/.s' + 'sh/id_rsa')""#,
        r#"python3 -c "import os; os.remove(f\"{os.environ['HOME']}/.ssh/id_rsa\")""#,
        r#"python3 -c "import os; os.remove('%s/.ssh/id_rsa' % os.environ['HOME'])""#,
        r#"python3 -c "import os; os.remove('/'.join(['/home/u', '.ssh', 'id_rsa']))""#,
        r#"lua -e 'os.remove("/home/u/.ss".."h/id_rsa")'"#,
        r#"python3 <<< "import os; os.remove('/home/u/.ssh/id_ed25519')""#,
        r#"python3 - <<< "import shutil; shutil.rmtree('/home/u/.aws')""#,
        r#"lua <<< 'os.remove("/home/u/.ssh/id_rsa")'"#,
        r#"ruby <<< 'File.delete("/home/u/.ssh/id_rsa")'"#,
        r#"perl <<< 'unlink "/home/u/.ssh/id_rsa"'"#,
        r#"node <<< 'require("fs").unlinkSync("/home/u/.ssh/id_rsa")'"#,
        r#"php <<< '<?php unlink("/home/u/.ssh/id_rsa");'"#,
        r#"lua -e 'local o = require("os"); o.remove("/home/u/.ssh/id_rsa")'"#,
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// FAILS ON REVERT: take `lua_protected_requires`, `xpcall` or the
/// luaposix `exec`/`execp` sinks out of `src/shell/inline_calls.rs` and
/// these are allowed.
#[test]
fn a_lua_process_call_through_pcall_or_luaposix_exec_is_read() {
    for line in [
        r#"lua -e 'local ok, o = pcall(require, "os"); o.execute("rm -rf ~")'"#,
        r#"lua -e 'xpcall(os.execute, print, "rm -rf ~")'"#,
        r#"lua -e 'local p = require "posix.unistd"; p.execp("rm", {"-rf", "/home/u"})'"#,
        r#"lua -e 'require("posix").execp("sh", {"-c", "rm -rf ~"})'"#,
        r#"lua -e 'posix.execp("rm", {"-rf", "/home/u"})'"#,
        r#"lua -e 'local ok, P = pcall(require, "posix"); P.spawn({"rm", "-rf", "/home/u"})'"#,
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// FAILS ON REVERT: let `file_written_by_a_lister` in
/// `src/threats/guard_lowering.rs` take the listing whatever runs between
/// it and the kill, and these are allowed again.
#[test]
fn a_listing_written_over_before_the_kill_reads_it_is_held() {
    for line in [
        r#"pgrep -f vite > p; cat ids > ./p; xargs kill < p"#,
        r#"pgrep -f vite > p; cat ids > "$PWD/p"; xargs kill < p"#,
        r#"pgrep -f vite > p; cat ids > $PWD/p; xargs kill -9 < p"#,
        r#"pgrep -f vite > /tmp/p; cp ids /tmp/p; xargs kill < /tmp/p"#,
        r#"pgrep -f vite > /tmp/p; mv ids /tmp/p; xargs kill < /tmp/p"#,
        r#"pgrep -f vite > /tmp/p; dd if=ids of=/tmp/p; xargs kill < /tmp/p"#,
        r#"pgrep -f vite > /tmp/p; cat ids | tee /tmp/p; xargs kill < /tmp/p"#,
        r#"pgrep -f vite > /tmp/p; tee /tmp/p < ids; xargs kill < /tmp/p"#,
        r#"pgrep -f vite > /tmp/p; sed -i 's/.*/1/' /tmp/p; xargs kill < /tmp/p"#,
        r#"pgrep -f vite > /tmp/p; xargs -a ids kill < /tmp/p"#,
        r#"pgrep -f vite > /tmp/p; xargs kill < /tmp/p < ids"#,
        r#"pgrep -f vite > /tmp/p; xargs --arg-file=ids kill < /tmp/p"#,
        r#"pgrep -f vite > /tmp/p; cp -f ids /tmp/p; xargs kill -9 < /tmp/p"#,
        r#"pgrep -f vite > p; cd /tmp; xargs kill < p"#,
        r#"pgrep -f vite > /tmp/p; install ids /tmp/p; xargs kill < /tmp/p"#,
        r#"pgrep -f vite > /tmp/p; ln -sf ids /tmp/p; xargs kill < /tmp/p"#,
        r#"pgrep -f vite > /tmp/p; rsync ids /tmp/p; xargs kill < /tmp/p"#,
        r#"pgrep -f vite > /tmp/p; perl -pi -e 's/.*/1/' /tmp/p; xargs kill < /tmp/p"#,
    ] {
        assert_ne!(verdict(line), "allow", "{line}");
    }
}

/// What removes no key, starts nothing harmful, or leaves the listing as it
/// was written stays allowed.
#[test]
fn cleanups_harmless_calls_and_listings_left_alone_stay_allowed() {
    for line in [
        r#"python3 -c "import os as o; o.remove('build/out.o')""#,
        r#"python3 -c "from os import remove; remove('build/out.o')""#,
        r#"python3 -c "__import__('os').remove('build/out.o')""#,
        r#"python3 -c "import os; getattr(os, 'remove')('build/out.o')""#,
        r#"python3 -c "import importlib; importlib.import_module('json').dumps({})""#,
        r#"python3 -c "import os; os.rename('a.txt', 'b.txt')""#,
        r#"python3 -c "import os; os.rename('/home/u/.ssh/id_ed25519.pub', '/tmp/k.pub')""#,
        r#"python3 -c "import shutil; shutil.move('build', 'dist')""#,
        r#"python3 -c "import os; os.remove('build/' + 'out.o')""#,
        r#"python3 -c "import os; print(os.environ['HOME'] + '/.ssh/id_rsa')""#,
        r#"python3 -c "from os import path; print(path.exists('/home/u/.ssh/id_rsa'))""#,
        r#"lua -e 'os.rename("a.txt", "b.txt")'"#,
        r#"python3 <<< "import os; os.remove('build/out.o')""#,
        r#"python3 <<< "print('/home/u/.ssh/id_rsa')""#,
        r#"lua <<< 'print(os.time())'"#,
        r#"lua -e 'pcall(print, "x")'"#,
        r#"lua -e 'local ok, o = pcall(require, "os"); print(o.time())'"#,
        r#"lua -e 'local ok, j = pcall(require, "cjson"); print(ok)'"#,
        r#"lua -e 'local p = require "posix.unistd"; print(p.getpid())'"#,
        r#"lua -e 'require("posix.unistd").execp("ls", {"-la"})'"#,
        r#"cat ids > /tmp/p; cp x y; pgrep -f vite > /tmp/p; xargs kill < /tmp/p"#,
        r#"pgrep -f vite > /tmp/p; cp /tmp/p /tmp/q; xargs kill < /tmp/p"#,
        r#"pgrep -f vite > /tmp/p; cat /tmp/p; xargs kill < /tmp/p"#,
        r#"pgrep -f vite > /tmp/p; tee /tmp/q < /tmp/p; xargs kill < /tmp/p"#,
        r#"pgrep -f vite | xargs kill"#,
        r#"python3 -c "import os; os.rename('/home/u/.ssh/config.bak', '/home/u/.ssh/config')""#,
        r#"perl -e 'rename "a.txt", "b.txt"'"#,
        r#"node -e 'const fs = require("fs"); fs.renameSync("a.txt", "b.txt")'"#,
        r#"lua -e 'local u = require "posix.unistd"; u.sleep(1)'"#,
        r#"python3 -c "import os as o; print(o.getcwd())""#,
        r#"python3 -c "import sys; print('.ssh' + '/id_rsa')""#,
        r#"python3 -c "import os; os.remove('a' + '.ssh')""#,
        r#"python3 -c "from shutil import move; move('build', 'dist')""#,
        r#"python3 -c "import importlib; m = importlib.import_module('os'); print(m.getcwd())""#,
        r#"ruby -e 'File.rename("a.txt", "b.txt")'"#,
        r#"php -r 'rename("a.txt", "b.txt");'"#,
        r#"python3 -c "import os; os.replace('tmp.json', 'out.json')""#,
        r#"python3 -c "from pathlib import Path; Path('a.txt').rename('b.txt')""#,
        r#"lua -e 'local ok, P = pcall(require, "posix"); print(P.getpid())'"#,
        r#"python3 -c "import os; os.remove(f'{os.getcwd()}/build/x.o')""#,
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// Main's verdicts that stay: a harmless `posix.exec` keeps the refusal of
/// the name, and a listing spelled otherwise than the kill reads it stays
/// held.
#[test]
fn verdicts_main_gave_by_name_or_spelling_stay() {
    for line in [
        r#"lua -e 'posix.exec("/bin/ls", {"-la"})'"#,
        r#"lua -e 'local P = require "posix"; P.exec("/bin/echo", {"hi"})'"#,
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        r#"pgrep -f vite > p; xargs kill < ./p"#,
        r#"pgrep -f vite > ./p; xargs kill < p"#,
        r#"pgrep -f vite > "$PWD/p"; xargs kill < p"#,
    ] {
        assert_eq!(verdict(line), "review", "{line}");
    }
}
