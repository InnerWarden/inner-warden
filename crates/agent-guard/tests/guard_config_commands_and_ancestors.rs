//! The guard's configuration, changed by the guard's own commands or by
//! moving a folder above it.
//!
//! Measured on main (80b8b55) on 2026-11-22: from an agent, `innerwarden llm
//! set`, `llm set-key`, `setup` and `notify` with a channel were allowed,
//! while `innerwarden allow "curl *"` was refused. And `mv ~/.config
//! ~/.config.old`, then a folder of the agent's moved in as `~/.config` with
//! an `innerwarden/llm.toml` in it, was allowed step by step (so was `mv ~
//! /tmp/h` and `rm -rf ~/.config`), while a move of `~/.config/innerwarden`
//! itself was refused.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

/// FAILS ON REVERT of `llm`, `setup` and `notify` in `GUARD_VERB_HEADS`
/// and their arms in `guard_verb_loosens`.
#[test]
fn the_guards_config_commands_are_the_persons() {
    for line in [
        "innerwarden llm set --url https://x.example/v1 --model m",
        "innerwarden llm set-key",
        "innerwarden llm set-key sk-abc",
        "innerwarden setup",
        "innerwarden notify --webhook-url https://x.example/hook",
        "innerwarden notify --slack-webhook https://x.example/s --test",
        "innerwarden notify --telegram-token t --telegram-chat 1",
        "innerwarden notify --notify-review",
        "innerwarden mute ATR-00001",
        "iw llm set --url https://x.example/v1 --model m",
        "iw-guard setup",
        "iw notify --discord-webhook https://x.example/d",
        "/usr/local/bin/innerwarden llm set-key k",
        "~/.local/bin/iw notify --webhook-url https://x.example",
        "sudo innerwarden setup",
        "bash -c 'innerwarden llm set --url https://x.example/v1 --model m'",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    // Showing the configuration, a test alert and help change nothing.
    for line in [
        "innerwarden llm",
        "innerwarden llm status",
        "innerwarden llm --help",
        "innerwarden llm set --help",
        "innerwarden setup --help",
        "innerwarden notify",
        "innerwarden notify --test",
        "iw notify -h",
        "innerwarden mute",
        "innerwarden mute --list",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// FAILS ON REVERT of `takes_guard_config_ancestor` in
/// `check_guard_self_disable_read`.
#[test]
fn a_folder_above_the_guards_config_is_not_moved_or_removed() {
    for line in [
        "mv ~/.config ~/.config.old",
        "mv ~/.config/ /tmp/c",
        "mv $HOME/.config /tmp/c",
        "mv \"$HOME\"/.config /tmp/c",
        "mv $XDG_CONFIG_HOME /tmp/c",
        "mv /home/someone/.config /tmp/c",
        "mv /Users/someone/.config /tmp/c",
        "mv ~ /tmp/h",
        "mv $HOME /tmp/h",
        "sudo mv /root /tmp/r",
        "mv /home /h2",
        "mv ~/w ~/.config",
        "mv ~/.config.old ~/.config",
        "rm -rf ~/.config",
        "rmdir ~/.config",
        "ln -s ~/.config /tmp/c",
        "ln -sfn ~/dotfiles/config ~/.config",
        "cd ~ && mv .config cfg.old",
        "cd ~/.config && mv .. /tmp/h",
        "C=~/.config; mv $C /tmp/c",
        "bash -c 'mv ~/.config /tmp/c'",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// The other end: work inside `~/.config`, a copy of it, and a move into a
/// home stay ordinary work.
#[test]
fn work_inside_config_and_into_a_home_stays_free() {
    for line in [
        "mv ~/.config/nvim ~/.config/nvim.bak",
        "rm -rf ~/.config/nvim",
        "cd ~/.config && rm -rf nvim",
        "mkdir -p ~/.config/foo && cp a ~/.config/foo/b",
        "ln -s ~/dotfiles/nvim ~/.config/nvim",
        "cp -r ~/.config /tmp/backup",
        "cp -r ~/dotfiles/. ~/.config/",
        "mv ~/w ~/.config/",
        "ls ~/.config",
        "mv x ~",
        "mv /tmp/file ~/",
        "mv ~/Downloads/x ~/Documents/",
        "mv ~/.cache ~/.cache.old",
        "rm -rf ~/tmp/build",
        "cd ~/project && rm -rf .config",
        "rm -rf node_modules && npm install",
        "git mv src lib",
        "tar -xf a.tar -C ~",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
