//! The files that hand over a login, root or a stored credential, or schedule
//! jobs, are refused to every shell writer, as the direct redirection onto the
//! login keys and the sudo rules already was.
//!
//! Measured on main on 2026-11-19 with `analyze_command`: of 14 write forms
//! (`>>`, `>`, `tee -a`, `sed -i`, `cp`, `mv`, `ln -sf`, `ln`, `install`,
//! `dd of=`, `truncate`, a variable, `$HOME`, `..`) over 15 such files, 160
//! of 210 lines were not denied: `f=~/.ssh/authorized_keys; echo x >> $f`,
//! `ln -sf /tmp/c ~/.ssh/authorized_keys` and `ln -sf /tmp/c /etc/sudoers`
//! were allowed, `mv /tmp/c ~/.ssh/authorized_keys` only reviewed (30), and
//! every form onto `~/.aws/credentials`, `~/.netrc`, `~/.kube/config`,
//! `~/.docker/config.json`, `~/.config/gcloud/` and `/var/spool/cron/` was
//! allowed or reviewed. Reading them with `cat` is not changed.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

/// Every form the shell writes a file in, for one file.
fn every_write(file: &str) -> Vec<String> {
    let (dir, name) = file.rsplit_once('/').expect("a path with a folder");
    let mut lines = vec![
        format!("echo x >> {file}"),
        format!("echo x > {file}"),
        format!("printf 'x\\n' >> \"{file}\""),
        format!("tee -a {file} < /tmp/c"),
        format!("sed -i 's/a/b/' {file}"),
        format!("cp /tmp/c {file}"),
        format!("mv /tmp/c {file}"),
        format!("ln -sf /tmp/c {file}"),
        format!("ln /tmp/c {file}"),
        format!("install -m 600 /tmp/c {file}"),
        format!("dd if=/tmp/c of={file}"),
        format!("truncate -s 0 {file}"),
        format!("f={file}; echo x >> $f"),
        format!("f=\"{file}\"; cp /tmp/c \"$f\""),
        format!("echo x >> {dir}/x/../{name}"),
        format!("cd {dir} && echo x >> {name}"),
        format!("ln -s {dir} l && echo x >> l/{name}"),
        format!("sh -c 'echo x >> {file}'"),
    ];
    if let Some(rest) = file.strip_prefix("~/") {
        lines.push(format!("echo x >> $HOME/{rest}"));
        lines.push(format!("echo x >> \"${{HOME}}/{rest}\""));
        lines.push(format!("echo x >> /home/dev/{rest}"));
        lines.push(format!("echo x >> /root/{rest}"));
    }
    lines
}

fn assert_every_write_denied(files: &[&str]) {
    for file in files {
        for line in every_write(file) {
            assert_eq!(verdict(&line), "deny", "{line}");
        }
    }
}

/// The lines the task measured, one per form, as they were written.
#[test]
fn the_measured_lines_are_refused() {
    for line in [
        "f=~/.ssh/authorized_keys; echo x >> $f",
        "ln -sf /tmp/c ~/.ssh/authorized_keys",
        "mv /tmp/c ~/.ssh/authorized_keys",
        "ln -sf /tmp/c /etc/sudoers",
        "echo x >> ~/.aws/credentials",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// The login keys a server lets in.
#[test]
fn every_write_of_authorized_keys_is_refused() {
    assert_every_write_denied(&["~/.ssh/authorized_keys", "~/.ssh/authorized_keys2"]);
}

/// The sudo rules.
#[test]
fn every_write_of_the_sudo_rules_is_refused() {
    assert_every_write_denied(&["/etc/sudoers", "/etc/sudoers.d/agent"]);
}

/// The account database.
#[test]
fn every_write_of_the_account_database_is_refused() {
    assert_every_write_denied(&["/etc/passwd", "/etc/shadow"]);
}

/// The jobs the system runs on a schedule.
#[test]
fn every_write_of_the_scheduled_jobs_is_refused() {
    assert_every_write_denied(&["/etc/crontab", "/etc/cron.d/job", "/var/spool/cron/dev"]);
}

/// The stored credentials in a home.
#[test]
fn every_write_of_stored_credentials_is_refused() {
    assert_every_write_denied(&[
        "~/.aws/credentials",
        "~/.config/gcloud/credentials.db",
        "~/.kube/config",
        "~/.docker/config.json",
        "~/.netrc",
    ]);
}

/// The shell startup files stay judged by what is written into them, not by
/// their name: ordinary setup lines are allowed, as before.
#[test]
fn shell_startup_files_stay_judged_by_what_is_written() {
    for line in [
        "echo 'export PATH=$HOME/.cargo/bin:$PATH' >> ~/.bashrc",
        "echo \"export PROMPT_COMMAND='history -a'\" >> ~/.bashrc",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// Reading them is what it was: only the write changed.
#[test]
fn reading_them_is_unchanged() {
    for (line, expected) in [
        ("cat ~/.ssh/authorized_keys", "allow"),
        ("cat /etc/sudoers", "allow"),
        ("cat /etc/passwd", "allow"),
        ("cat /etc/crontab", "allow"),
        ("cat ~/.bashrc", "allow"),
        ("cat ~/.profile", "allow"),
        ("grep root /etc/passwd > out.txt", "allow"),
        ("tee /tmp/out < ~/.bashrc", "allow"),
        ("dd if=/etc/passwd of=/tmp/x", "allow"),
        ("cat ~/.aws/credentials", "deny"),
        ("cat ~/.netrc", "deny"),
    ] {
        assert_eq!(verdict(line), expected, "{line}");
    }
}

/// A file beside one of them, a project file with the same name outside a
/// home, a removal or a move away is not a write of it.
#[test]
fn beside_them_is_not_them() {
    for line in [
        "ssh-keyscan github.com >> ~/.ssh/known_hosts",
        "echo //registry.npmjs.org/:_authToken=x > .npmrc",
        "echo x > ./notes/.profile.md",
        "echo x > docs/sudoers.md",
        "sed -i s/a/b/ ./etc/passwd.txt",
        "echo x >> ~/.aws/notes.txt",
        "cp ~/.bashrc ~/.bashrc.bak",
        "mv ~/.bashrc ~/.bashrc.old",
        "rm ~/.netrc",
        "crontab -l > /tmp/cron.bak",
        "kubectl get pods > pods.txt",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
