//! The guard's name is the guard only where a program runs: the command
//! word, the word a launcher runs, the command `find -exec` runs, the
//! package `cargo run` builds and runs, the command `ssh` hands the far
//! shell. Anywhere else it is a mention: a folder of one's own, a test
//! filter, an option's value, a build of the guard copied or listed. A
//! mention is refused only with what lowers the guard written after it
//! (`agent kernel` and a word that is not a read, `allow`, `mute`,
//! `monitor`, `dry-run`, `uninstall`, `disarm`, `--self-approve`), and held
//! for review where a program the line does not know is handed it with a
//! word the text does not show after it: that program may run it.
//!
//! Measured 2026-11-27 with `analyze_command` on main (b23c6176): every
//! line of the first list was refused, as were 385 lines of a week of the
//! people building the guard that pass once the name is taken out of such
//! places. The lines here are those, with neutral names. The refusals and
//! the lines held for review are in the corpus
//! `guard-name-places-2026-11` and `guard-lowering-evasions`.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

fn check(lines: &[&str], expected: &str) {
    let wrong: Vec<(&str, String)> = lines
        .iter()
        .map(|line| (*line, verdict(line)))
        .filter(|(_, got)| got != expected)
        .collect();
    assert!(wrong.is_empty(), "expected {expected}: {wrong:#?}");
}

/// A mention where no program runs passes: an option's value, a test
/// filter, a folder, a build of the guard copied, listed or run through a
/// variable the line gives its path, a guard folder of one's own on
/// another host.
///
/// FAILS ON REVERT: read every word as a program could be there
/// (`program_places::places` answering `WordPlace::Any` for each) and the
/// first four lines are refused again; leave the variable's value out where
/// the command stands (`Judge::resolved` answering `None`) and the fifth
/// and sixth are.
#[test]
fn the_guard_named_where_no_program_runs_is_a_mention() {
    check(
        &[
            "cargo test -p innerwarden --bin innerwarden $f",
            "ssh h1 'git -C ~/innerwarden/proj worktree remove --force ~/innerwarden/wt-1'",
            "cargo build --release -p innerwarden --bin innerwarden && ls -la target/release/innerwarden",
            "cp /home/u/tgt/main/release/innerwarden /home/u/bin/iw-main && ls -la /home/u/bin",
            "B=/home/u/tgt/main/release/innerwarden; $B --version; $B check \"ls\"",
            "ssh h1 'B=~/tgt/x/release/innerwarden; $B --version; cd ~/src/proj && git status --short'",
            "git -C /home/u/work/innerwarden log --oneline -3",
            "ssh h1 'ls -la /usr/local/bin/innerwarden; sha256sum /usr/local/bin/innerwarden'",
            "ssh h1 \"sudo -u innerwarden python3 -c 'print(1)'\"",
            "S=/home/u/scratch-innerwarden-sales/x; cp $S/a $S/b; cat $S/b",
        ],
        "allow",
    );
}

/// What a value spells into an argument of a program whose arguments are
/// data changes nothing of which program runs: it is not read, and a long
/// value used forty times no longer leaves the line unread. Spelled into
/// the command word it still is.
///
/// FAILS ON REVERT: spell every word that holds an expansion again
/// (`command_lines_spelled` reading `WordPlace::Data` words) and the first
/// line is refused as one the guard did not read to its end.
#[test]
fn only_a_word_where_a_program_runs_is_spelled_from_the_lines_values() {
    let long = "x".repeat(4000);
    let arguments = format!(
        "v='{long}'; {}X=q; X=\"a b\"; echo $X",
        "cp $v /tmp/b; ".repeat(40)
    );
    assert_eq!(verdict(&arguments), "allow", "{} bytes", arguments.len());
    let programs = format!("v='{long}'; {}X=q; X=\"a b\"; $X", "$v; ".repeat(40));
    assert_eq!(verdict(&programs), "deny", "{} bytes", programs.len());
}

/// A loosening verb written after the name is refused wherever the name
/// stands, behind the launchers the reading follows and those it does not.
///
/// FAILS ON REVERT: answer `WordsAfter::found_written` `false` and the
/// lines whose name is an option's value or an argument (`cargo run -p`,
/// `./run`) are let through.
#[test]
fn a_loosening_verb_written_after_the_name_is_refused_wherever_it_stands() {
    check(
        &[
            "taskset 1 innerwarden $V",
            "flock /tmp/l innerwarden agent kernel off",
            "setsid innerwarden $(printf mon)itor",
            "stdbuf -o0 innerwarden allow foo",
            "systemd-run --user innerwarden uninstall",
            "cargo run -p innerwarden -- monitor",
            "cargo run --bin innerwarden -- agent kernel claude-code off",
            "./run innerwarden allow x",
            "./run innerwarden agent kernel claude-code off",
            "find /usr/local/bin -name innerwarden -exec {} monitor \\;",
            "find /opt/innerwarden -type f -exec {} dry-run \\;",
            "watch -n1 innerwarden \"$X\"",
            "set -- innerwarden \"$X\"; \"$@\"",
            "X=innerwarden; set -- allow x; ${X%Z} \"$@\"",
            "which innerwarden | xargs -I@ @ \"$X\"",
            "ssh h1 innerwarden \"$X\"",
        ],
        "deny",
    );
}

/// The guard handed to a program the line does not know, with a word the
/// text does not show after it, is held for review, not let through: a
/// wrapper of one's own may run it with that word. The guard's own reading
/// holds it, and says why.
///
/// FAILS ON REVERT: drop both notes that hold such a line, `Looks::HELD`
/// in `guard_words_refusal` and `Doubt::Held` in `check_guard_self_disable`,
/// and no finding of the guard is left on these lines (another reading,
/// of the parts of a line not read, still holds them for review).
#[test]
fn the_guard_handed_to_a_program_the_line_does_not_know_is_held() {
    for line in [
        "./run innerwarden \"$X\"",
        "$TOOL innerwarden \"$X\"",
        "faketime 0 innerwarden $V",
        "./probe.sh /home/u/tgt/main/release/innerwarden $t /home/u/wt/forms.txt",
    ] {
        let analysis = analyze_command(line, None);
        assert_eq!(analysis.recommendation, "review", "{line}");
        assert!(
            analysis
                .signals
                .iter()
                .any(|signal| signal.signal == "guard_self_disable"
                    && signal.score == 25
                    && signal
                        .detail
                        .starts_with("hands the guard's program to another program")),
            "{line}: {:?}",
            analysis.signals
        );
    }
}

/// A removal or a move matches as the program a command runs, never as
/// letters inside another word: a host whose name holds `rm ` reads the
/// guard's store and removes nothing. Reading the guard's store (its
/// decisions, its database) is held for review; removing, moving or
/// stopping it stays refused.
///
/// FAILS ON REVERT: match `rm ` as letters again (`runs_a_removal`
/// answering `seg.contains("rm ")`) and the host lines are refused; leave
/// `GUARD_STORES` out of `check_security_tamper` and the reads pass.
#[test]
fn the_guards_store_read_is_held_and_its_removal_refused() {
    check(
        &[
            "ssh h-crm \"cat /var/lib/innerwarden/decisions-2026-11-27.jsonl\"",
            "cat /var/lib/innerwarden/decisions-2026-11-27.jsonl",
            "ssh h1 'cd /var/lib/innerwarden; sudo grep x decisions-2026-11-23.jsonl'",
        ],
        "review",
    );
    // A look at the names, sizes and modes of its files reads none of them.
    check(
        &[
            "ssh h-crm \"ls /var/lib/innerwarden\"",
            "ssh h1 'sudo -n stat -c \"%A %U:%G %n\" /var/lib/innerwarden/x.db'",
        ],
        "allow",
    );
    check(
        &[
            "ssh h1 \"sudo rm -rf /var/lib/innerwarden/x\"",
            "find /var/lib/innerwarden -name '*.db' -exec rm {} +",
            "ssh h1 'sudo mv /etc/innerwarden/agent.toml /tmp/'",
            "ssh h1 'sudo systemctl stop innerwarden-agent'",
            "export H\"O\"ME=/etc && git worktree remove --force $HOME/innerwarden/x",
            "printf -v HO\"\"ME /etc && git worktree remove --force $HOME/innerwarden/x",
        ],
        "deny",
    );
}

/// The guard's own verb and an agent's settings stay refused in any
/// spelling.
#[test]
fn the_kernel_protection_and_an_agents_settings_stay_refused() {
    check(
        &[
            "innerwarden agent kernel off",
            "inner\"warden\" agent kernel off",
            "i\\nnerwarden agent kernel off",
            "$(echo innerwarden) agent kernel off",
            "X=innerwarden; $X agent kernel off",
            "jq '.hooks = {}' ~/.claude/settings.json > /tmp/s && mv /tmp/s ~/.claude/settings.json",
        ],
        "deny",
    );
}

/// The ssh client behind `rtk` (a proxy that condenses a command's output)
/// is read as the client run alone, its key its use; a key read behind it
/// is still a read. An ssh whose output a test only compares is read as one
/// whose output a variable holds; one whose output a command may open by
/// its name is read as written.
///
/// FAILS ON REVERT: drop `rtk` from `launcher_command_start` and the
/// first line is a key read; drop `compared_or_printed` and the third is.
#[test]
fn the_ssh_client_behind_rtk_or_in_a_compared_value_is_read_as_its_use() {
    check(
        &[
            "rtk bypass ssh -i ~/.ssh/id_k -o BatchMode=yes h1 'tail -2 ~/x/log'",
            "rtk bypass scp -i ~/.ssh/id_k h1:/tmp/x /tmp/y",
            "[ \"$(ssh -i ~/.ssh/id_k u@h1 'cat /etc/hostname')\" = h1 ] && echo same",
            "echo \"x: $(ssh -i ~/.ssh/id_k u@h1 'cat ~/.ssh/known_hosts')\"",
        ],
        "allow",
    );
    check(
        &[
            "rtk bypass cat ~/.ssh/id_rsa",
            "cat \"$(ssh h1 'echo /home/u/.ssh/id_rsa')\"",
            "rtk bypass innerwarden agent kernel off",
            "rtk -v proxy innerwarden allow x",
        ],
        "deny",
    );
}

/// What `rtk` runs is judged as the command run alone: a removal of the
/// home or a whole tree opened to everyone behind it is refused, as it is
/// without it (main let the first two through).
///
/// FAILS ON REVERT: drop `rtk` from `launcher_command_start` and the
/// removals behind it are let through.
#[test]
fn a_command_behind_rtk_is_judged_as_run_alone() {
    check(
        &[
            "rtk bypass rm -rf ~",
            "rtk bypass bash -c 'rm -rf ~'",
            "rtk bypass chmod -R 777 /",
        ],
        "deny",
    );
}

/// The package `cargo run` builds and runs, glued to its option
/// (`--bin=NAME`, `--package=NAME`, `-pNAME`), is that package as the two
/// words are, and the guard's verb written anywhere after the guard's name
/// is refused, not only right after it.
///
/// FAILS ON REVERT: read a glued value as no name (`program_places::fill`
/// without `cargo_run_program_glued`, `guard_program_or_glued` answering
/// `guard_program`, `guard_cli_named_by` without
/// `attached_option_values_of`) and the first four lines and the three
/// glued `allow` and `uninstall` lines are let through; ask `found_written`
/// for `agent kernel` right after the name only
/// (`guard_verbs_after_any_program`) and `ls innerwarden x agent kernel off`
/// is; read the loosening verbs right after a name only
/// (`loosening_verb_written_from` answering `false`) and `./run innerwarden
/// x allow foo` is.
#[test]
fn the_guards_package_glued_to_cargos_option_is_the_guard() {
    check(
        &[
            "cargo run --bin=innerwarden -- agent kernel off",
            "cargo run --package=innerwarden -- agent kernel off",
            "cargo run -pinnerwarden -- agent kernel off",
            "cargo run -q --bin=innerwarden -- agent kernel off",
            "./run innerwarden x agent kernel off",
            "ls innerwarden x agent kernel off",
            "cargo run --bin=innerwarden -- allow foo",
            "cargo run --bin=innerwarden --release -- allow foo",
            "cargo run -pinnerwarden -- uninstall",
            "./run innerwarden x allow foo",
        ],
        "deny",
    );
    check(
        &[
            "cargo run --bin=mytool -- status",
            "cargo test --package=innerwarden x",
            "cargo -q run --bin=innerwarden -- status",
        ],
        "allow",
    );
}

/// cargo's own options before its subcommand, with their values, are not
/// the subcommand: `cargo --color always run -p NAME` builds and runs NAME.
///
/// FAILS ON REVERT: take the first word after `cargo` that is not an option
/// for the subcommand (`cargo_subcommand` without `CARGO_GLOBAL_VALUED`) and
/// these lines are held for review only.
#[test]
fn cargos_own_options_before_run_do_not_hide_the_package_it_runs() {
    check(
        &[
            "cargo --color always run -p innerwarden -- $V",
            "cargo -C /src/proj run -p innerwarden -- $V",
            "cargo --config x=1 run -p innerwarden -- $V",
            "cargo --manifest-path /src/x/Cargo.toml run -p innerwarden -- $V",
            "cargo -Z unstable-options run -p innerwarden -- $V",
            "cargo -j 4 run -p innerwarden -- $V",
            "cargo --jobs 4 run -p innerwarden -- $V",
            "cargo --target-dir /tmp/t run -p innerwarden -- $V",
            "cargo +stable --color always run -p innerwarden -- $V",
        ],
        "deny",
    );
    check(&["cargo -C /src/proj build -p innerwarden"], "allow");
}

/// What an ssh client runs on this host from its own options (`ProxyCommand`,
/// `LocalCommand`, `KnownHostsCommand`, `Match exec`) is a command line where
/// a program runs, for `ssh`, `scp` and `sftp` and the `ssh` that `rsync -e`
/// runs, with `-o` glued or apart and `=` or a space.
///
/// FAILS ON REVERT: read no option of the ssh client as a command
/// (`ssh_local_commands` answering nothing) and the `scp`, `sftp -o` glued
/// and `rsync` lines with `$V` are held for review only, and `scp -o
/// ProxyCommand="innerwarden allow x"` is let through.
#[test]
fn a_command_an_ssh_client_runs_from_its_options_is_where_a_program_runs() {
    check(
        &[
            "scp -o ProxyCommand=\"innerwarden $V\" x h1:y",
            "scp -O -o ProxyCommand=\"innerwarden $V\" x h1:y",
            "scp -J h2 -o ProxyCommand=\"$HOME/.local/bin/innerwarden $V\" x h1:y",
            "scp -o KnownHostsCommand=\"innerwarden $V\" x h1:y",
            "scp -o PermitLocalCommand=yes -o LocalCommand=\"innerwarden $V\" x h1:y",
            "scp -oProxyCommand=\"innerwarden $V\" x h1:y",
            "scp -o \"ProxyCommand innerwarden $V\" x h1:y",
            "sftp -oProxyCommand=\"innerwarden $V\" h1",
            "rsync -e \"ssh -o ProxyCommand='innerwarden $V'\" x h1:y",
            "scp -o ProxyCommand=\"innerwarden allow x\" x h1:y",
            "rsync -e \"ssh -o ProxyCommand='innerwarden monitor'\" x h1:y",
            "sftp -o \"LocalCommand innerwarden mute x\" -o PermitLocalCommand=yes h1",
        ],
        "deny",
    );
    check(
        &[
            "scp -o ProxyCommand=\"ssh -W %h:%p jump\" x h1:y",
            "scp -o ConnectTimeout=5 x h1:y",
            "rsync -e \"ssh -o ProxyCommand='ssh -W %h:%p jump'\" x h1:y",
        ],
        "allow",
    );
}

/// The guard's program named in an operand the line does not show whole
/// (what a substitution, an expansion or a pattern puts there names it, or
/// the path ends in its name), then moved, removed, overwritten, linked over
/// or changed, is refused as the path written out is, whatever program
/// found it. A copy from it, a listing or a hash of it reads it, and a name
/// of the guard in the middle of a path through a value is a folder.
///
/// FAILS ON REVERT: leave `found_guard_program_changed` out of
/// `check_guard_takedown` and these lines are held for review only, or let
/// through (`npm prefix -g`, `brew --prefix`); read a list of the programs
/// that print a path instead of the operand (`operand_names_guard_program`
/// answering only for `which`, `command -v`, `type -P`, `readlink -f`,
/// `realpath`) and the lines from `npm prefix -g` on are.
#[test]
fn the_guards_program_found_by_a_substitution_and_moved_is_refused() {
    check(
        &[
            "mv \"$(which innerwarden)\" /tmp/x",
            "mv \"$(command -v innerwarden)\" /tmp/x",
            "mv \"`which innerwarden`\" /tmp/x",
            "mv \"$(type -P innerwarden)\" /tmp/x",
            "mv \"$(readlink -f \"$(which innerwarden)\")\" /tmp/x",
            "mv \"$(which innerwarden)\"{,.off}",
            "mv \"$(command -v innerwarden)\" \"$(command -v innerwarden).bak\"",
            "mv /tmp/x \"$(which innerwarden)\"",
            "rm -f \"$(which innerwarden)\"",
            "cp /bin/true \"$(which innerwarden)\"",
            "ln -sf /bin/true \"$(which innerwarden)\"",
            "chmod 000 \"$(which innerwarden)\"",
            "truncate -s0 \"$(which innerwarden)\"",
            ": > \"$(which innerwarden)\"",
            "echo x | tee \"$(command -v innerwarden)\"",
            "mv \"$(npm prefix -g)/bin/innerwarden\" /tmp/x",
            "mv \"$(brew --prefix)/bin/innerwarden\" /tmp/x",
            "mv \"$(npm root -g)/innerwarden/bin/innerwarden\" /tmp/x",
            "mv \"$(hash -t innerwarden)\" /tmp/x",
            "mv $(find / -name innerwarden -type f 2>/dev/null) /tmp/x",
            "mv \"$(whereis -b innerwarden | cut -d' ' -f2)\" /tmp/x",
            "mv \"${commands[innerwarden]}\" /tmp/x",
            "mv \"$commands[innerwarden]\" /tmp/x",
            "mv ${commands[innerwarden]} /tmp/x",
            "mv \"$(readlink /proc/$(pgrep -n innerwarden)/exe)\" /tmp/x",
            "mv \"$(dirname \"$(which innerwarden)\")/innerwarden\" /tmp/x",
            "mv \"$(PATH=/usr/local/bin command -v innerwarden)\" /tmp/x",
            "mv \"$(builtin command -v innerwarden)\" /tmp/x",
            "mv \"$(ps -o comm= -C innerwarden)\" /tmp/x",
            "ln -sf /bin/true \"${commands[innerwarden]}\"",
            "chmod 000 \"${commands[innerwarden]}\"",
            "rm -f $(echo /usr/local/bin/innerwarden)",
            "echo x > \"$(npm prefix -g)/bin/innerwarden\"",
        ],
        "deny",
    );
    for line in [
        "mv \"$(npm prefix -g)/bin/other\" /tmp/x",
        "mv \"$W/innerwarden/wt-1\" /tmp/old",
        "ls -la \"$(npm prefix -g)/bin/innerwarden\"",
    ] {
        let analysis = analyze_command(line, None);
        assert_ne!(
            analysis.recommendation, "deny",
            "{line}: {:?}",
            analysis.signals
        );
    }
    check(
        &[
            "ls -la \"$(which innerwarden)\"",
            "sha256sum \"$(command -v innerwarden)\"",
        ],
        "allow",
    );
    let copy = analyze_command("cp \"$(which innerwarden)\" /tmp/iw-copy", None);
    assert_ne!(copy.recommendation, "deny", "{:?}", copy.signals);
}

/// A read of the guard's store is charged once, with its own reason: on
/// this host, and on another host where the line `ssh` runs holds it.
///
/// FAILS ON REVERT: take every finding seen on the remote line for one
/// charged already (`indicator == GUARD_STORE_READ || ...` in
/// `analyze_command_as_read`) and the `pkill` on another host is charged
/// once; take any tamper finding seen for the same read (`... || ...`
/// inside it) and the store read beside a remote `pkill` is not charged.
#[test]
fn a_read_of_the_guards_store_is_charged_once_with_its_reason() {
    for line in [
        "cat /var/lib/innerwarden/decisions-2026-11-27.jsonl",
        "ssh h1 'cat /var/lib/innerwarden/decisions-2026-11-27.jsonl'",
    ] {
        let analysis = analyze_command(line, None);
        let charged: Vec<_> = analysis
            .signals
            .iter()
            .filter(|signal| {
                signal.signal == "security_tooling_tamper"
                    && signal.detail.contains("reads the guard's own store")
            })
            .collect();
        assert_eq!(charged.len(), 1, "{line}: {:?}", analysis.signals);
    } // Any other tamper finding of the remote line stands there, read as
      // the line it is, and is charged once: the line around it does not
      // read the remote words again as text.
    let line = "ssh h1 'pkill -f innerwarden'";
    let analysis = analyze_command(line, None);
    let tampers: Vec<_> = analysis
        .signals
        .iter()
        .filter(|signal| signal.signal == "security_tooling_tamper")
        .collect();
    assert_eq!(tampers.len(), 1, "{line}: {:?}", analysis.signals);
    assert!(
        tampers[0]
            .detail
            .starts_with("in the line ssh runs on another host"),
        "{line}: {:?}",
        analysis.signals
    );
    assert_eq!(analysis.recommendation, "deny", "{line}");
    // A store read on this host is charged even where the remote line was
    // charged for another finding: only the same read is charged once.
    let line = "ssh h1 'pkill -f proxy'; cat /var/lib/innerwarden/d.jsonl";
    let analysis = analyze_command(line, None);
    let store_reads = analysis
        .signals
        .iter()
        .filter(|signal| {
            signal.signal == "security_tooling_tamper"
                && signal.detail.contains("reads the guard's own store")
        })
        .count();
    assert_eq!(store_reads, 1, "{line}: {:?}", analysis.signals);
}
