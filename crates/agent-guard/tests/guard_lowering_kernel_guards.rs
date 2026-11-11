//! The kernel guards an agent may be held by, lowered through the guard's
//! own programs.
//!
//! The guard refused `exec-gate` with `allow`, `approve` or `disarm`, and no
//! other verb. Measured on 2026-11-10, every line of the first three groups
//! below was allowed: a program authorised on the gate by another verb, the
//! verb left for a variable or a feeding program to supply, the gate's
//! signing tool named by a pattern. The set-up lines the documentation gives
//! an agent, and the reads, are asserted not `deny` beside them.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

fn assert_denied(cases: &[&str]) {
    for command in cases {
        assert_eq!(
            verdict(command),
            "deny",
            "this lowers a kernel guard: {command:?}"
        );
    }
}

fn assert_not_denied(cases: &[&str]) {
    for command in cases {
        assert_ne!(
            verdict(command),
            "deny",
            "nothing here lowers a kernel guard: {command:?}"
        );
    }
}

/// The verbs that authorise a program on the exec gate, take a path out of
/// the secret guard's care, clear the scope a guard is held to, or set the
/// kernel mode back.
#[test]
fn a_verb_that_lowers_a_kernel_guard_is_refused() {
    assert_denied(&[
        "sudo innerwarden-ctl exec-gate arm --pid 1234 --observe --path /tmp/tool",
        "innerwarden-ctl exec-gate arm --pid 1234 --observe --path /tmp/tool",
        "sudo innerwarden-ctl exec-gate arm --observe --path /tmp/tool --pid 1234",
        "sudo innerwarden-ctl exec-gate arm --observe --path=/tmp/tool",
        "sudo innerwarden host exec-gate arm --pid 1234 --observe --path /tmp/tool",
        "sudo innerwarden-ctl exec-gate disarm",
        "sudo innerwarden-config-sign exec-gate trust-path /tmp/tool",
        "sudo innerwarden-config-sign exec-gate scan",
        "sudo innerwarden-config-sign exec-gate approve 0123abcd",
        "sudo innerwarden-config-sign exec-gate seed-essentials",
        "sudo innerwarden-config-sign exec-gate import-rules",
        "sudo -u root /usr/local/bin/innerwarden-config-sign exec-gate import-rules --file /tmp/r.toml",
        "sudo innerwarden-config-sign exec-gate disarm",
        "sudo innerwarden-config-sign exec-gate scope-agent --clear",
        "sudo innerwarden-config-sign secret-guard scope-agent --clear",
        "sudo innerwarden-config-sign dns-guard scope-agent --pid 1234 --clear",
        "sudo innerwarden-config-sign secret-guard unprotect /home/dev/.ssh",
        "sudo innerwarden-config-sign secret-guard disarm",
        "sudo innerwarden-config-sign dns-guard disarm",
        "sudo innerwarden-config-sign userns-guard disarm",
        "sudo innerwarden-config-sign lsm --apply",
        "sudo innerwarden-config-sign lsm --mode disabled --apply",
        "sudo innerwarden-config-sign lsm --mode enforce --exec --apply",
        "sudo env innerwarden-config-sign exec-gate scan",
    ]);
}

/// The verb, the guard or the path option the text does not show whole: a
/// variable set by an earlier command, quotes inside the word, a brace
/// list. What the program gets is not what the line shows, so it is refused.
#[test]
fn a_verb_the_text_does_not_show_is_refused() {
    assert_denied(&[
        "sudo innerwarden-ctl exec-gate $V",
        "sudo innerwarden-config-sign exec-gate $V",
        "sudo innerwarden-config-sign exec-gate \"$V\"",
        "sudo innerwarden-config-sign secret-guard $V /home/dev/.ssh",
        "sudo innerwarden-config-sign userns-guard $V",
        "sudo innerwarden-ctl exec-gate --dry-run $V",
        "sudo innerwarden-ctl exec-gate --data-dir /srv/data $V",
        "sudo innerwarden-config-sign $S disarm",
        "sudo innerwarden-config-sign $S trust-path /tmp/tool",
        "sudo innerwarden-ctl $S arm --observe --path /tmp/tool",
        "sudo innerwarden-ctl exec-gate arm --observe $OPTS",
        "sudo innerwarden-ctl exec-gate arm --observe --path=$T",
        "T=/tmp/tool; sudo innerwarden-ctl exec-gate arm --observe --path $T",
        "sudo innerwarden-ctl exec-gate arm --observe --pa''th /tmp/tool",
        "sudo innerwarden-ctl exec-gate arm --observe \"--path\" /tmp/tool",
        "sudo innerwarden-ctl exec-gate a''rm --observe --path /tmp/tool",
        "sudo innerwarden-ctl exec-gate arm --observe --path{,} /tmp/tool",
        "sudo innerwarden-config-sign lsm --mode $M",
    ]);
}

/// The signing tool spelled so the text does not show its name whole.
#[test]
fn the_signing_tool_is_a_guard_program_however_it_is_spelled() {
    assert_denied(&[
        "sudo inner''warden-config-sign exec-gate disarm",
        "sudo inner\\warden-config-sign secret-guard disarm",
        "S=innerwarden-config-sign; sudo $S exec-gate disarm",
        "sudo inner*-config-sign exec-gate disarm",
        "sudo inner*-config-sign exec-gate trust-path /tmp/tool",
        "sudo inner*-config-sign lsm --apply",
        "sudo $TOOL lsm --mode disabled --apply",
        "sudo /usr/local/bin/inner''warden-config-sign exec-gate approve 0123abcd",
        "sudo inner''warden-config-sign userns-guard disarm",
        "sudo inner''warden-ctl exec-gate disarm",
    ]);
}

/// A program that adds words of its own supplies the verb, or the path
/// option; and a line handed to another shell is read as that shell reads
/// it.
#[test]
fn a_verb_fed_or_handed_to_another_shell_is_refused() {
    assert_denied(&[
        "echo disarm | xargs sudo innerwarden-ctl exec-gate",
        "echo --path /tmp/tool | xargs sudo innerwarden-ctl exec-gate arm --observe",
        "printf '%s\\n' trust-path /tmp/tool | xargs sudo innerwarden-config-sign exec-gate",
        "echo --apply | xargs sudo innerwarden-config-sign lsm",
        "echo --clear | xargs sudo innerwarden-config-sign exec-gate scope-agent",
        "sh -c 'innerwarden-config-sign exec-gate trust-path /tmp/tool'",
        "ssh host 'sudo innerwarden-config-sign exec-gate scan'",
    ]);
}

/// The set-up lines the documentation gives an agent, the verbs that
/// tighten a guard, and the reads.
#[test]
fn setting_a_kernel_guard_up_and_reading_it_are_not_refused() {
    assert_not_denied(&[
        "sudo innerwarden-ctl exec-gate arm --pid 1234 --observe",
        "sudo innerwarden-ctl exec-gate arm --pid \"$PID\" --observe",
        "sudo innerwarden-ctl exec-gate arm --observe --pid \"$PID\"",
        "sudo innerwarden-ctl exec-gate arm --observe --pid $(pgrep -o node)",
        "sudo innerwarden-ctl exec-gate arm --observe --pid=$PID",
        "sudo innerwarden-ctl exec-gate enforce --pid 1234",
        "sudo innerwarden-ctl exec-gate rehearse --pid 1234",
        "sudo innerwarden-ctl exec-gate status",
        "sudo innerwarden-ctl exec-gate status --json",
        "sudo innerwarden-ctl get incidents --days $N",
        "sudo innerwarden-config-sign exec-gate status",
        "sudo innerwarden-config-sign exec-gate list",
        "sudo innerwarden-config-sign exec-gate rehearse",
        "sudo innerwarden-config-sign exec-gate revoke /usr/bin/python3",
        "sudo innerwarden-config-sign exec-gate forget /usr/bin/python3",
        "sudo inner''warden-config-sign exec-gate status",
        "sudo innerwarden-config-sign secret-guard status",
        "sudo innerwarden-config-sign secret-guard scope-agent --pid 1234 --apply",
        "sudo innerwarden-config-sign secret-guard protect --path /etc/app/prod.key",
        "sudo innerwarden-config-sign secret-guard arm --observe --apply",
        "sudo innerwarden-config-sign secret-guard arm --apply",
        "sudo innerwarden-config-sign dns-guard status",
        "sudo innerwarden-config-sign dns-guard scope-agent --pid \"$PID\" --apply",
        "sudo innerwarden-config-sign userns-guard arm",
        "sudo innerwarden-config-sign lsm --mode log",
        "sudo innerwarden-config-sign license status",
        "sudo innerwarden-config-sign verify /etc/innerwarden/agent.toml",
    ]);
}

/// Set-up lines that lower nothing and are refused: the price of refusing
/// what the text does not show. A process number fed by another program
/// arrives where a path option could; an option's value from a variable
/// stands where the verb could.
#[test]
fn set_up_lines_that_lower_nothing_and_are_refused_at_a_price() {
    assert_denied(&[
        "pgrep -o node | xargs sudo innerwarden-ctl exec-gate arm --observe --pid",
        "sudo innerwarden-ctl exec-gate --data-dir \"$DIR\" status",
        "sudo innerwarden-ctl exec-gate arm --observe --pid 1234 $EXTRA",
    ]);
}

/// The value of `--pid` is not read. A value the line does not show, split
/// by the shell into words, can carry a path option past the guard: the
/// limit of reading one command line, written down here so a change of it
/// is a decision.
#[test]
fn a_process_number_the_line_does_not_show_is_not_read() {
    assert_not_denied(&["sudo innerwarden-ctl exec-gate arm --observe --pid $X"]);
}
