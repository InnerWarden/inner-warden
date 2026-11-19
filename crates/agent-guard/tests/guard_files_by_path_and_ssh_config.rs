//! The guard's own files are refused by where they are, not by a word in
//! their path; and the SSH client configuration, which runs commands on the
//! next connection, is refused to every shell writer.
//!
//! Measured on main on 2026-11-19: `rm -rf <scratch>/h <scratch>/g.json
//! <scratch>/guard-events.jsonl` in a scratch folder under
//! `/tmp/claude-1000/-home-u-innerwarden/`, and `rm -f ~/innerwarden/x.rs
//! ~/innerwarden/ufw-product.sh`, were denied as "deletes the guard's hook
//! script": the rule took any path holding `innerwarden` and ending in `.sh`
//! or `.json` for the hook. And `echo .. >> ~/.ssh/config`, `printf .. >`,
//! `tee -a`, `ln -sf`, `mv` onto it, a variable, `$HOME`, a file in
//! `~/.ssh/config.d/` and a link to `~/.ssh` were allowed.

use std::path::Path;

use innerwarden_agent_guard::file_tools::{privileged_file_write, WriteContext};
use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

const SCRATCH: &str =
    "/tmp/claude-1000/-home-dev-innerwarden/281cfd49-8a58-45b3-95d8-691c03e8284f/scratchpad";

/// Files whose path only holds the word are not the guard's.
#[test]
fn a_file_named_like_the_guard_elsewhere_is_not_the_guard() {
    let scratch = format!("rm -rf {SCRATCH}/h {SCRATCH}/g.json {SCRATCH}/guard-events.jsonl");
    for line in [
        scratch.as_str(),
        "rm -f ~/innerwarden/real_ufw_netns.rs ~/innerwarden/ufw-product.sh",
        "rm -f /home/dev/innerwarden/ufw-product.sh /home/dev/innerwarden/notes.json",
        "rm -f ./innerwarden-demo.sh",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// The hook script, the configuration, the record, the state and the
/// program stay refused, by name, through a variable, a link or `..`.
#[test]
fn the_guards_real_files_stay_refused() {
    for line in [
        "rm -f .claude/hooks/pretooluse-innerwarden.sh",
        "rm -f ~/.claude/hooks/innerwarden-guard.sh",
        "rm -rf ~/.openclaw/hooks/innerwarden-attempts",
        "rm -rf ~/.config/innerwarden",
        "rm -f ~/.config/innerwarden/guard-events.jsonl",
        "rm -f ~/.config/innerwarden/config.json",
        "rm -f ~/.config/innerwarden/suppress.toml",
        "d=~/.config/innerwarden; rm -rf $d",
        "rm -rf ~/x/../.config/innerwarden",
        "ln -s ~/.config/innerwarden l && rm -rf l/",
        "rm -rf /etc/innerwarden",
        "rm -f /etc/innerwarden/../innerwarden/agent.toml",
        "rm -f /var/lib/innerwarden/state.json",
        "rm -f /usr/local/bin/innerwarden",
        "b=/usr/local/bin/innerwarden; rm -f $b",
        "rm -f ~/.claude/settings.json",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// Every shell writer of the SSH client configuration is refused.
#[test]
fn writing_the_ssh_client_configuration_is_refused() {
    for line in [
        "echo 'Host x' >> ~/.ssh/config",
        "echo '  ProxyCommand sh -c id' >> ~/.ssh/config",
        "printf 'Host *\\n LocalCommand id\\n' > ~/.ssh/config",
        "tee -a ~/.ssh/config < /tmp/c",
        "sed -i 's/a/b/' ~/.ssh/config",
        "cp /tmp/c ~/.ssh/config",
        "ln -sf /tmp/c ~/.ssh/config",
        "mv /tmp/c ~/.ssh/config",
        "f=~/.ssh/config; echo x >> $f",
        "echo x >> $HOME/.ssh/config",
        "echo x >> \"${HOME}/.ssh/config\"",
        "cd ~/.ssh && echo x >> config",
        "echo 'Include /tmp/x' > ~/.ssh/config.d/evil",
        "cp /tmp/c ~/.ssh/config.d/",
        "ln -s ~/.ssh l && echo x >> l/config",
        "echo x >> /etc/ssh/ssh_config",
        "echo x > /etc/ssh/ssh_config.d/x.conf",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    let context = WriteContext {
        cwd: Some(Path::new("/home/u/p")),
        home: Some(Path::new("/home/u")),
        guard_program: None,
    };
    for path in [
        "/home/u/.ssh/config",
        "~/.ssh/config",
        "/home/u/p/../.ssh/config",
        "/home/u/.ssh/config.d/x",
    ] {
        assert!(privileged_file_write(path, &context).is_some(), "{path}");
    }
}

/// What reads it, or writes beside it, is not a write of it.
#[test]
fn beside_the_ssh_client_configuration_is_not_it() {
    for line in [
        "ssh-keyscan github.com >> ~/.ssh/known_hosts",
        "rm -f ~/.ssh/known_hosts.old",
        "echo 'Host x' > ./ssh_config",
        "ssh -F ./ssh_config host true",
        "echo x > ~/proj/.ssh-config.md",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// A configuration from outside handed to the ssh an `rsync` runs, in the
/// long `--rsh=` form as in the short `-e`, is not use of the key.
#[test]
fn rsync_rsh_with_an_outside_configuration_is_not_key_use() {
    for line in [
        "rsync --rsh='ssh -F ./cfg -i ~/.ssh/id_rsa' -a src/ u@h:/srv/",
        "rsync --rsh=\"ssh -F ./cfg -i ~/.ssh/id_rsa\" -a src/ u@h:/srv/",
        "rsync -e 'ssh -F ./cfg -i ~/.ssh/id_rsa' -a src/ u@h:/srv/",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    assert_eq!(
        verdict("rsync --rsh='ssh -i ~/.ssh/id_rsa' -a src/ u@h:/srv/"),
        "allow"
    );
}

/// A `find` that removes, edits or writes over what is under a place of the
/// guard is that removal, filtered or not, whatever the root is spelled as.
/// Measured on main on 2026-11-19: every line here but the `-exec` ones was
/// allowed; only an unfiltered `-delete` was refused, as a bulk deletion.
#[test]
fn find_over_the_guards_places_is_their_removal() {
    for line in [
        "find ~/.config/innerwarden -name config.json -delete",
        "find /etc/innerwarden -name '*.toml' -delete",
        "find /var/lib/innerwarden -name '*.db' -delete",
        "find -L ~/.config/innerwarden -name x -delete",
        "d=~/.config/innerwarden; find $d -name '*.json' -delete",
        "cd ~/.config && find innerwarden -name config.json -delete",
        "find ~/.config -path '*innerwarden*' -delete",
        "find ~/.config/innerwarden -name suppress.toml -exec rm {} \\;",
        "find ~/.config/innerwarden -name suppress.toml -exec rm -f {} +",
        "find ~/.config/innerwarden -name '*.toml' -execdir rm {} \\;",
        "find ~/.config/innerwarden -name '*.toml' -exec sed -i s/a/b/ {} \\;",
        "find /tmp -name x -fprint ~/.config/innerwarden/suppress.toml",
        "find . -fprint /etc/innerwarden/agent.toml",
        "find ~/.claude -name settings.json -delete",
        "find /tmp -name x -fprint ~/.ssh/config",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        "find . -name '*.pyc' -delete",
        "find ~/innerwarden -name '*.orig' -delete",
        "find ~ -name '*.pyc' -delete",
        "find /tmp -name x -fprint /tmp/list",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// `rsync --delete` into a place of the guard removes what it holds.
#[test]
fn rsync_delete_into_the_guards_places_is_their_removal() {
    for line in [
        "rsync -a --delete empty/ ~/.config/innerwarden/",
        "rsync -a --delete-after /tmp/e/ ~/.config/innerwarden/",
        "rsync -a --delete /tmp/e/ /etc/innerwarden/",
        "rsync -a --delete /tmp/e/ ~/.claude/",
        "rsync -a --remove-source-files ~/.claude/settings.json /tmp/",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        "rsync -a --delete src/ /srv/app/",
        "rsync -a --delete src/ ./build/",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// A search from ABOVE a place of the guard that removes what it matches, and
/// whose filter may match the place, a folder on the way to it or a file the
/// guard keeps there, removes it. Measured on main on 2026-11-19: every line
/// here was allowed. The lines whose verdict hangs on what the guard's
/// folders hold on this host are in `find_reads_the_guards_folders.rs`.
#[test]
fn find_from_above_the_guards_places_is_their_removal_when_its_filter_may_match() {
    for line in [
        "find ~ -path '*innerwarden*' -delete",
        "find $HOME -iname '*INNERWARDEN*' -delete",
        "find /etc -name agent.toml -delete",
        "find / -name '*.toml' -delete",
        "find ~/.config -name '*.json' -exec rm {} \\;",
        "find /var -name '*.db' -delete",
        "find ~ -name .config -exec rm -rf {} +",
        "find ~ -regex '.*inner.*' -delete",
        "find ~ ! -name '*.rs' -delete",
        "find ~ -name 'settings*.json' -delete",
        "cd ~ && find . -path '*innerwarden*' -delete",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    // A filter that cannot match any of them, a root that holds none of
    // them, or a search that only reads, is what it was.
    // What a root above the guard's folders may match depends on what those
    // folders hold on this host: the cases from `~` are in
    // `find_reads_the_guards_folders.rs`, with a home of their own.
    for line in [
        "find ~/proj -name '*.json' -delete",
        "find . -name '*.json' -delete",
        "find /tmp -name '*.toml' -delete",
        "find ~ -name '*.toml' -exec cat {} \\;",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
