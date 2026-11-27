//! Inline code that removes or writes over the account's keys or credential
//! store is read as the shell's `rm` of the same path; an editor other than
//! `sed` that writes a file of the guard in place is refused as `sed -i` is;
//! luaposix's `spawn` is a process call.
//!
//! Measured 2026-11-24 against main b52291b and the branch on top of it:
//! each line under `refused` was allowed while `rm ~/.ssh/id_ed25519` was
//! refused.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

#[test]
fn inline_code_removing_a_key_or_a_credential_store_is_refused() {
    for line in [
        r#"lua -e 'os.remove("/home/u/.ssh/id_ed25519")'"#,
        r#"lua -e 'os.remove(os.getenv("HOME").."/.ssh/id_rsa")'"#,
        r#"python3 -c "import os; os.remove('/home/u/.ssh/id_ed25519')""#,
        r#"python3 -c "import os; os.unlink(os.path.join(os.environ['HOME'], '.ssh', 'id_rsa'))""#,
        r#"python3 -c "import os; p = os.path.expanduser('~/.aws/credentials'); os.remove(p)""#,
        r#"python3 -c "import shutil; shutil.rmtree('/home/u/.config/gcloud')""#,
        r#"python3 -c "from pathlib import Path; Path('/home/u/.ssh/id_ed25519').unlink()""#,
        r#"python3 -c "import pathlib; pathlib.Path.home().joinpath('.ssh/id_rsa').unlink()""#,
        r#"python3 -c "from pathlib import Path; (Path.home() / '.ssh' / 'id_ed25519').write_text('')""#,
        r#"ruby -e 'File.delete("/home/u/.ssh/id_ed25519")'"#,
        r#"ruby -e 'File.delete(File.join(Dir.home, ".ssh", "id_rsa"))'"#,
        r#"ruby -e 'require "fileutils"; FileUtils.rm_rf("/home/u/.ssh")'"#,
        r#"perl -e 'unlink "$ENV{HOME}/.ssh/id_ed25519"'"#,
        r#"perl -e 'unlink glob("~/.ssh/id_*")'"#,
        r#"php -r 'unlink("/home/u/.kube/config");'"#,
        r#"node -e 'require("fs").rmSync(require("os").homedir() + "/.ssh", {recursive: true})'"#,
        "python3 - <<'EOF'\nimport os\nos.remove(os.path.expanduser('~/.ssh/id_ed25519'))\nEOF",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

#[test]
fn inline_code_removing_what_holds_no_key_stays_allowed() {
    for line in [
        r#"lua -e 'os.remove("build/out.o")'"#,
        r#"python3 -c "import os; os.remove('build/out.o')""#,
        r#"python3 -c "import shutil; shutil.rmtree('build')""#,
        r#"python3 -c "import os; os.remove(os.path.expanduser('~/.ssh/known_hosts'))""#,
        r#"python3 -c "import os; print(os.path.exists('/home/u/.ssh/id_ed25519'))""#,
        r#"python3 -c "import shutil; shutil.copy('/home/u/.ssh/id_ed25519.pub', 'k.pub')""#,
        r#"ruby -e 'File.delete("tmp/cache.json")'"#,
        r#"perl -e 'unlink "out.log"'"#,
        r#"php -r 'unlink("cache/a.php");'"#,
        r#"node -e 'require("fs").unlinkSync("node_modules/.cache/x")'"#,
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

#[test]
fn an_editor_writing_a_file_of_the_guard_in_place_is_refused() {
    for line in [
        "perl -pi -e 's/a/b/' ~/.config/systemd/user/innerwarden-agent.service",
        "perl -i.bak -pe 's/a/b/' /etc/systemd/system/innerwarden-agent.service",
        "ed -s /etc/innerwarden/guard.toml",
        "ex -sc '%s/enforce/monitor/|x' /etc/innerwarden/guard.toml",
        "vim -c '%s/enforce/monitor/' -c wq /etc/innerwarden/guard.toml",
        "vim -es -c '%s/a/b/' -c wq ~/.config/systemd/user/innerwarden-agent.service",
        "awk -i inplace '{gsub(/enforce/,\"monitor\")}1' /etc/innerwarden/guard.toml",
        "gawk -i inplace '{print}' ~/.config/systemd/user/innerwarden-agent.service",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

#[test]
fn an_editor_reading_the_guard_or_editing_another_file_stays_allowed() {
    for line in [
        "perl -i -pe 's/a/b/' src/main.rs",
        "perl -ne 'print' /etc/innerwarden/guard.toml",
        "ed -s notes.txt",
        "vim -R /etc/innerwarden/guard.toml",
        "view /etc/innerwarden/guard.toml",
        "vim -c 'r /etc/innerwarden/guard.toml' notes.md",
        "awk '{print}' /etc/innerwarden/guard.toml",
        "awk -i inplace '{print}' data.txt",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

#[test]
fn luaposix_spawn_is_a_process_call() {
    for line in [
        r#"lua -e 'require("posix").spawn({"rm","-rf","/home/u"})'"#,
        r#"lua -e 'local p = require("posix"); p.spawn({"rm","-rf","/home/u"})'"#,
        r#"lua -e 'posix.spawn("rm","-rf","/home/u")'"#,
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        r#"lua -e 'require("posix").spawn("ls -la")'"#,
        r#"lua -e 'local p = require("posix"); print(p.getpid())'"#,
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
