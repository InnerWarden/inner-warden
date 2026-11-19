//! The reader of inline code must not panic or stall on any line, however
//! it is spelled: accents, a no-break space, an emoji, a Perl or PHP
//! special variable followed by a multibyte character, a string folded
//! through twelve levels of %, 64 KiB of code. A panic in the guard is a
//! refusal of an ordinary line; a stall is a hook timeout.
//!
//! Measured 2026-11-19 before the fix: 1392 of the 2184 generated lines
//! panicked (a byte step that cut a character in two). The reader's own
//! cost on its largest input is held to a second by a unit test in
//! `shell/inline_calls.rs`; here a line of 64 KiB is only held to not
//! panicking, as the rest of the screening already takes seconds on it in
//! a debug build, the same on main.

use innerwarden_agent_guard::mcp::analyze_command;
use std::time::{Duration, Instant};

const RUNNERS: &[&str] = &[
    "python3 -c",
    "node -e",
    "ruby -e",
    "perl -e",
    "php -r",
    "deno eval",
];

const PIECES: &[&str] = &[
    "é=1",
    "\u{a0}",
    "x\u{a0}=\u{a0}1",
    "🦀",
    "s = \"🦀é\"",
    "$^é",
    "@^é",
    "$^W",
    "'éx=>1'",
    "f = éx=>éx",
    "const é = (a) => a",
    "ação = 'ç'",
    "import os",
    "os.system(\"echo é\")",
    "subprocess.run([\"ls\", \"-la\"])",
    "require('child_process').execSync(\"echo ü\")",
    "system(\"echo ñ\")",
    "`echo é`",
    "%x(echo é)",
    "\"%s\" % \"é\"",
    "\"{}\".format(\"é\")",
    "a += [\"é\"]",
    "b = \"é\" + \"ü\"",
    "def sh(c): os.system(c)",
    "sh(\"echo é\")",
    "# comentário é",
    "// comentário ü",
    "/* é */",
    "$x = \"é\" . \"ü\"",
    "print(\"日本語\")",
    "\u{200b}",
    "\u{feff}",
    "é",
    ";",
    "\n",
    "(",
    ")",
    "\"",
];

/// A small fixed generator, so a failure names the same line every run.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as usize
    }
}

fn line_for(runner: &str, body: &str) -> String {
    format!("{runner} '{}'", body.replace('\'', "\""))
}

/// Judges every line, each on its own, and names those that panic or take
/// longer than a second.
fn judge_all(lines: &[String], timed: bool) {
    let mut panicked = Vec::new();
    let mut slow = Vec::new();
    static WHERE: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|info| {
        if let Some(at) = info.location() {
            if let Ok(mut places) = WHERE.lock() {
                places.push(format!("{}:{}", at.file(), at.line()));
            }
        }
    }));
    for line in lines {
        let started = Instant::now();
        let outcome = std::panic::catch_unwind(|| analyze_command(line, None));
        let took = started.elapsed();
        if outcome.is_err() {
            panicked.push(line.chars().take(160).collect::<String>());
        } else if timed && took > Duration::from_secs(1) {
            slow.push((line.chars().take(160).collect::<String>(), took));
        }
    }
    std::panic::set_hook(hook);
    let mut places = WHERE
        .lock()
        .map(|places| places.clone())
        .unwrap_or_default();
    places.sort();
    places.dedup();
    assert!(
        panicked.is_empty(),
        "panicked on {} lines, at {places:?}: {panicked:#?}",
        panicked.len()
    );
    assert!(slow.is_empty(), "slower than 1 s: {slow:#?}");
}

#[test]
fn multibyte_text_anywhere_in_inline_code_does_not_panic() {
    let mut lines = Vec::new();
    for runner in RUNNERS {
        for piece in PIECES {
            lines.push(line_for(runner, piece));
            lines.push(line_for(runner, &format!("x{piece}y")));
            lines.push(line_for(runner, &format!("{piece} {piece}")));
        }
    }
    let mut random = Lcg(0x1119);
    for _ in 0..1500 {
        let runner = RUNNERS[random.next() % RUNNERS.len()];
        let count = 1 + random.next() % 8;
        let body: String = (0..count)
            .map(|_| PIECES[random.next() % PIECES.len()])
            .collect::<Vec<_>>()
            .join(if random.next().is_multiple_of(2) {
                "; "
            } else {
                ""
            });
        lines.push(line_for(runner, &body));
    }
    judge_all(&lines, true);
}

#[test]
fn deep_and_long_inline_code_does_not_panic_or_stall() {
    let mut lines = Vec::new();
    for runner in RUNNERS {
        // Twelve levels of %, nested on the left and on the right.
        let mut left = "\"%s é\"".to_string();
        let mut right = "\"é\"".to_string();
        for _ in 0..12 {
            left = format!("({left}) % (\"x\")");
            right = format!("(\"%s\") % ({right})");
        }
        lines.push(line_for(runner, &format!("import os; os.system({left})")));
        lines.push(line_for(runner, &format!("import os; os.system({right})")));
        lines.push(line_for(
            runner,
            &format!("v = {left}; w = {right}; system(v + w)"),
        ));
    }
    judge_all(&lines, true);

    // Two runners are enough for the size: each line of 64 KiB takes
    // seconds in a debug build, in the screening around the reader.
    let mut lines = Vec::new();
    for runner in ["python3 -c", "perl -e"] {
        // 64 KiB: many statements, many calls of a helper, a list grown
        // one item at a time.
        let mut many = String::from("import os\ndef sh(c): os.system(c)\n");
        let mut helper = 0;
        while many.len() < 64 * 1024 {
            many.push_str(&format!(
                "a += [\"é{helper}\"]\nsh(\"echo {helper} é\")\nb{helper} = \"x\" + \"ü\"\n"
            ));
            helper += 1;
        }
        lines.push(line_for(runner, &many));

        let mut flat = String::new();
        while flat.len() < 64 * 1024 {
            flat.push_str("é\u{a0}🦀$^é ");
        }
        lines.push(line_for(runner, &flat));
    }
    judge_all(&lines, false);
}
