//! Guard lowerings where the guard's program or the verb reaches the command
//! through a variable whose value is built from another variable.
//!
//! Measured 2026-11-10 under bash and dash, with a program that logs its
//! argv in place of the guard's CLI and nothing else on `PATH`: the lines of
//! the first three groups ran that program with a verb that lowers the
//! guard, and the guard allowed them. Two readings were at fault. The line's
//! assignments were read into it with each value cut at its first `$`, so
//! `B=${A}warden` gave `B` no value; and the reader of the line's words knew
//! only the values that hold no expansion at all, the first one of each
//! name.
//!
//! The controls are the same shapes naming nothing of the guard, or naming
//! it with a verb that lowers nothing: asserted not `deny`.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

fn assert_denied(cases: &[&str]) {
    let allowed: Vec<_> = cases.iter().filter(|c| verdict(c) != "deny").collect();
    assert!(
        allowed.is_empty(),
        "a shell runs these lowerings: {allowed:#?}"
    );
}

fn assert_not_denied(cases: &[&str]) {
    let denied: Vec<_> = cases.iter().filter(|c| verdict(c) == "deny").collect();
    assert!(
        denied.is_empty(),
        "nothing here lowers the guard: {denied:#?}"
    );
}

/// The program in two steps and the verb in pieces, so that neither is a
/// word of the line as written.
#[test]
fn a_program_and_a_verb_built_from_other_values_are_read() {
    assert_denied(&[
        "A=inner; B=${A}warden; C=dry; D=$C-run; $B $D",
        "A=inner; B=${A}warden; C=run; $B dry-$C",
        "A=inner; B=${A}warden; C=dry; $B $C-run",
        "A=inner; B=${A}warden; V=allow; $B $V x",
        "A=inner; B=${A}warden; V=all; W=${V}ow; $B $W x",
        "A=inner; B=${A}warden; V=unin; W=${V}stall; $B $W",
        "a=inner; b=dry; x=${a}warden; $x ${b}-run",
        "A=inner B=warden; C=$A$B; D=dry; $C ${D}-run",
        "A=inner; B=$A; C=$B; D=$C; E=$D; F=$E; G=dry; H=$G; ${F}warden ${H}-run",
        // the value is two words to the shell: the program and the verb
        "A=inner; B=dry; C=${A}warden; D=\"$C ${B}-run\"; $D",
    ]);
}

/// A name appended to, or built on itself, in the order written or in the
/// order a loop runs it.
#[test]
fn a_name_appended_to_or_built_on_itself_is_read() {
    assert_denied(&[
        "A=in; A+=ner; B=dry; ${A}warden ${B}-run",
        "A=inner; A=${A}warden; B=dry; $A ${B}-run",
        "A=in; A=${A}ner; A=${A}warden; B=dry; $A ${B}-run",
        "A=in; A+=ner; A+=warden; B=dr; B+=y-run; $A $B",
        "A=in; for i in 1 2; do case $i in 2) A+=warden;; 1) A+=ner;; esac; done; B=dry; $A ${B}-run",
    ]);
}

/// The value that counts is not the first one the line gives the name, nor
/// the last: an assignment the shell drops (one command's environment, a
/// subshell), one a loop runs later, one a function reads ahead of it, a
/// name given more values than are kept.
#[test]
fn every_value_a_line_gives_a_name_is_read() {
    let many = format!(
        "{}A=inner; B=dry; ${{A}}warden ${{B}}-run",
        (1..18).map(|i| format!("A={i} true; ")).collect::<String>()
    );
    // Text that takes the line's own assignments past the limit they are
    // read into it within: the words of the line are still read.
    let long = format!(
        "v='{}'; echo{}; A=inner; B=${{A}}warden; C=dry; $B ${{C}}-run",
        "x".repeat(4000),
        " $v".repeat(40)
    );
    assert_denied(&[
        "A=x; A=inner; B=${A}warden; C=dry; $B ${C}-run",
        "A=inner; B=${A}warden; B=x true; C=dry; D=${C}-run; D=y true; $B $D",
        "A=inner; B=${A}warden; (B=x); C=dry; $B ${C}-run",
        "G=dry; for i in 1 2 3 4; do D=$C; C=$B; B=$A; A=inner; done; ${D}warden ${G}-run",
        "f() { $B $D; }; A=inner; B=${A}warden; C=dry; D=$C-run; f",
        &many,
        &long,
    ]);
}

/// The verb shows only once a value is read into the line, beside a program
/// no reading follows: a name set by `read`, a loop, `printf -v` or
/// `${NAME:=value}`, a name of the environment, an alias.
#[test]
fn a_verb_that_shows_once_a_value_is_read_beside_an_unread_program_is_refused() {
    assert_denied(&[
        ": ${A:=inner}; B=dry; ${A}warden ${B}-run",
        "read A <<< inner; B=dry; ${A}warden ${B}-run",
        "printf -v A inner; B=dry; ${A}warden ${B}-run",
        "B=dry; $GUARDBIN ${B}-run",
        "a=inner; b=dry; alias e=${a}warden; e ${b}-run",
    ]);
}

/// The program and the verb in ONE built value, run by its name alone: no
/// word of the line as written shows either. The value's piece has another
/// value ahead of it, so the reading of the line's assignments into it,
/// which knows the first value of a name, shows neither.
#[test]
fn a_built_value_that_holds_the_program_and_the_verb_is_read_where_it_runs() {
    let ahead =
        |count: usize| -> String { (1..=count).map(|i| format!("C=tool{i} true; ")).collect() };
    let behind_sixteen = format!(
        "A=x; A=inner; B=dry; {}C=\"${{A}}warden ${{B}}-run\"; $C",
        ahead(16)
    );
    let behind_seventeen = format!(
        "A=x; A=inner; B=dry; {}C=\"${{A}}warden ${{B}}-run\"; $C",
        ahead(17)
    );
    let with_a_word_after = format!(
        "A=x; A=inner; B=dry; {}C=\"${{A}}warden ${{B}}-run\"; $C now",
        ahead(16)
    );
    let past_the_limit = format!(
        "v='{}'; echo{}; {behind_sixteen}",
        "x".repeat(4000),
        " $v".repeat(40)
    );
    let more_ways = format!(
        "{}A=inner; {}B=dry; C=\"${{A}}warden ${{B}}-run\"; $C",
        (1..5).map(|i| format!("A={i} true; ")).collect::<String>(),
        (1..4).map(|i| format!("B={i} true; ")).collect::<String>()
    );
    assert_denied(&[
        "A=x; A=inner; B=dry; C=\"${A}warden ${B}-run\"; $C",
        &behind_sixteen,
        &behind_seventeen,
        &with_a_word_after,
        &past_the_limit,
        &more_ways,
        // handed to a shell, to `eval`, on a line in quotes
        "A=x; A=inner; B=dry; bash -c \"${A}warden ${B}-run\"",
        "A=x; A=inner; B=dry; C=\"${A}warden ${B}-run\"; sh -c \"$C\"",
        "A=x; A=inner; B=dry; C=\"${A}warden ${B}-run\"; eval $C",
        "bash -c 'A=x; A=inner; B=dry; C=\"${A}warden ${B}-run\"; $C'",
        // the program spelled from values, the verb's words as written
        "A=x; A=inner; B=${A}warden; $B agent install-hook --remove",
        "A=x; A=inner; B=${A}warden; $B uninstall",
        "A=x; A=inner; B=${A}warden; V=q; V=install-hook; $B agent $V --remove",
    ]);
}

/// The blank between the program and the verb is itself a value, or stands
/// inside one: the word that runs is one word as written, and names no
/// program until the value is read into it.
#[test]
fn a_blank_inside_a_value_parts_the_program_from_the_verb() {
    assert_denied(&[
        "A=x; A=inner; B=dry; S=\" \"; C=\"${A}warden${S}${B}-run\"; $C",
        "X=q; X=\"warden dry\"; C=\"inner${X}-run\"; $C",
        "X=q; X=\"warden dry\"; C=\"inner${X}-run\"; sh -c \"$C\"",
        "X=q; X=\"warden agent\"; C=\"inner${X}\"; $C install-hook --remove",
        "X=q; X=\"warden agent\"; C=\"inner${X} install-hook\"; $C --remove",
        // as the same text written out is: refused where a command takes it
        "X=q; X=\"warden uninstall is broken\"; MSG=\"inner$X\"; git commit -m \"$MSG\"",
    ]);
}

/// Values that hold a blank and lower nothing: flags, a command appended
/// to, a message with a word of the guard's verbs in it, the guard's name
/// with a verb that reads.
#[test]
fn values_that_hold_a_blank_and_lower_nothing_are_not_refused() {
    assert_not_denied(&[
        "CMD=make; CMD+=\" -j4\"; CMD+=\" all\"; $CMD",
        "CMD=make; CMD+=\" -j4\"; $CMD",
        "A=x; A=make; B=te; C=\"${A} ${B}st\"; $C",
        "S=\" \"; C=\"make${S}test\"; $C",
        "bash -c 'A=x; A=make; B=te; C=\"${A} ${B}st\"; $C'",
        "A=x; A=make; B=te; bash -c \"${A} ${B}st\"",
        "X=q; X=\"ke te\"; C=\"ma${X}st\"; $C",
        "A=x; A=inner; B=${A}warden; $B status",
        "X=q; X=\"-O2 -Wall\"; F=\"$X -g\"; gcc $F -o x x.c",
        "X=q; X=\"contain the overflow\"; MSG=\"fix: $X\"; git commit -m \"$MSG\"",
        "X=q; X=\"profile data\"; M=\"perf $X\"; echo \"$M\"",
        "X=q; X=\"warden status\"; C=\"inner${X} --json\"; $C",
        "X=q; X=\"warden to 1.6.6\"; MSG=\"bump inner$X\"; git commit -m \"$MSG\"",
    ]);
}

/// Text that costs more to read than its line is given: a long value read
/// by forty commands, one word each. No value of it holds a blank.
fn costly() -> String {
    format!("v='{}'; {}", "x".repeat(4000), "true $v; ".repeat(40))
}

/// The lowering stands behind text that costs more to read than the line is
/// given. The word that holds the program and the verb was then not spelled
/// from its values, and nothing else on the line shows either: the line was
/// allowed (found 2026-11-10).
#[test]
fn a_lowering_behind_text_that_costs_more_than_is_read_is_refused() {
    let costly = costly();
    let in_one_command = format!("v='{}'; true{}; ", "x".repeat(4000), " $v".repeat(40));
    let cases = [
        format!("{costly}X=q; X=\"warden dry\"; C=\"inner${{X}}-run\"; $C"),
        format!("{costly}X=q; X=\"warden dry\"; C=\"inner${{X}}-run\"; sh -c \"$C\""),
        format!("{costly}X=q; X=\"warden agent\"; C=\"inner${{X}}\"; $C install-hook --remove"),
        format!("{costly}A=x; A=inner; B=dry; C=\"${{A}}warden ${{B}}-run\"; $C"),
        format!("{in_one_command}X=q; X=\"warden dry\"; C=\"inner${{X}}-run\"; $C"),
    ];
    assert_denied(&cases.iter().map(String::as_str).collect::<Vec<_>>());
}

/// The same costly text with no value that holds a blank after it: no word
/// of the line is two words to a shell.
#[test]
fn text_that_costs_more_than_is_read_and_lowers_nothing_is_not_refused() {
    let costly = costly();
    let with_a_path = format!("{costly}T=src; wc -l $T/main.rs");
    assert_not_denied(&[costly.trim_end_matches("; "), &with_a_path]);
}

/// A value longer than 4096 bytes was not read into the word that ran it:
/// the blank between the program and the verb, padded to 5000 of them, hid
/// both (found 2026-11-10). The controls are long values that lower nothing:
/// a list of files, a request body, a script handed to a shell.
#[test]
fn a_long_value_is_read_into_the_word_that_runs_it() {
    let blanks = " ".repeat(5000);
    let cases = [
        format!("X=q; X=\"warden{blanks}dry\"; C=\"inner${{X}}-run\"; $C"),
        format!("X=q; X=\"warden{blanks}dry\"; C=\"inner${{X}}-run\"; sh -c \"$C\""),
    ];
    assert_denied(&cases.iter().map(String::as_str).collect::<Vec<_>>());

    let files: Vec<String> = (0..400).map(|i| format!("src/file{i}.c")).collect();
    let items: Vec<String> = (0..120)
        .map(|i| format!("{{\"id\": {i}, \"name\": \"item number {i}\"}}"))
        .collect();
    let steps: Vec<String> = (0..160)
        .map(|i| format!("echo step {i}; make -C pkg{i} test"))
        .collect();
    let controls = [
        format!("F=\"{}\"; git add $F", files.join(" ")),
        format!(
            "BODY='[{}]'; curl -s -X POST -d \"$BODY\" https://api.example.test/v1/a",
            items.join(", ")
        ),
        format!("SCRIPT='{}'; bash -c \"$SCRIPT\"", steps.join("; ")),
    ];
    assert_not_denied(&controls.iter().map(String::as_str).collect::<Vec<_>>());
}

/// The same shapes with nothing of the guard in them, or with a verb that
/// lowers nothing.
#[test]
fn values_built_from_other_values_that_lower_nothing_are_not_refused() {
    assert_not_denied(&[
        "A=make; B=$A; C=test; $B $C",
        "CMD=make; CMD=\"$CMD -j4\"; T=all; $CMD $T",
        "export PATH=$PATH:$HOME/.cargo/bin; D=crates; cargo build -p $D",
        "PATH=$PATH:/x/bin; innerwarden status",
        "B=$HOME/.local/bin/tool; F=x.txt; $B --flag $F",
        "A=src; B=$A/main.rs; C=$B; wc -l $C",
        "A=src; B=$A/main.rs; wc -l $B",
        "A=build; B=$A/out; ls $B",
        "T=te; T+=st; C=$T; $C $ARGS",
    ]);
}
