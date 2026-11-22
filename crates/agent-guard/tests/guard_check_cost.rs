//! What the guard-lowering check costs on a long line.
//!
//! The hook that asks the check has a time limit, and an agent reads a hook
//! that ran out of time as an allow. So a line built to be slow to read is a
//! way past the guard, and the check's cost has to grow with the line's
//! length and no faster.
//!
//! Each shape here is one the reviews of 2026-11-09 and 2026-11-10 found
//! slow: a part of the reading that read the rest of the line again at each
//! word, name, redirection or level. Each is read at two lengths, the second
//! four times the first. A reading that costs the line's length takes four
//! times as long; one that reads the rest again at each step takes sixteen
//! times. The bound between them is eight.
//!
//! Only that ratio is asserted, both lengths read in the same run, one after
//! the other, and timed by the CPU time of the thread that reads where the
//! system keeps one (Linux, macOS). A ceiling in seconds failed on a slower
//! runner (macOS, 2026-11-21) with no change to the reading, and the wall
//! clock counts whatever else the runner was doing. That the ratio tells a
//! reading that grows with the square of the length from one that grows with
//! it is itself tested: `the_measure_tells_a_square_from_a_line`.

use std::hint::black_box;
use std::time::Duration;

use innerwarden_agent_guard::threats::check_guard_self_disable;

/// The shorter length, in bytes.
const SHORT: usize = 16 * 1024;

/// The longer length: four times the shorter.
const LONG: usize = 4 * SHORT;

/// How many times longer the long line may take than the short one.
const TIMES: u32 = 8;

/// A short line read faster than this is counted as taking this long: under
/// it the clock, not the reading, decides the ratio.
const SHORT_FLOOR: Duration = Duration::from_millis(2);

/// The two lines of a shape are read in turn, short then long, up to this
/// many times while the long one looks too slow; the fastest reading of each
/// is kept. A reading the runner held up is slower, never faster, so the
/// fastest is the one the check's own work decides.
const ROUNDS: usize = 5;

/// Set by a mutation sweep, which runs the suite once per mutant on a shared
/// runner: half a minute of measuring for each mutant is hours, and a bound
/// that fails there on a busy runner hides a mutant no test checks. Nothing
/// is measured there. Outside a sweep the bound holds, which is where a slow
/// change is caught.
const NO_CEILINGS_ENV: &str = "IW_NO_WALL_CLOCK_CEILINGS";

fn ceilings_are_asserted() -> bool {
    std::env::var_os(NO_CEILINGS_ENV).is_none()
}

/// `head`, then `unit` as often as fits in `bytes`, then `tail`.
fn repeated(head: &str, unit: &str, tail: &str, bytes: usize) -> String {
    let mut line = String::with_capacity(bytes + head.len() + tail.len());
    line.push_str(head);
    while line.len() < bytes {
        line.push_str(unit);
    }
    line.push_str(tail);
    line
}

/// As [`repeated`], with the `#` in `unit` counted up, so no two are alike.
fn numbered(head: &str, unit: &str, tail: &str, bytes: usize) -> String {
    let mut line = String::with_capacity(bytes + head.len() + tail.len());
    line.push_str(head);
    let mut count = 0usize;
    while line.len() < bytes {
        line.push_str(&unit.replace('#', &count.to_string()));
        count += 1;
    }
    line.push_str(tail);
    line
}

/// `open` and `close` as often as fit in `bytes`, one inside the other.
fn nested(open: &str, close: &str, tail: &str, bytes: usize) -> String {
    let depth = bytes / (open.len() + close.len()).max(1);
    let mut line = open.repeat(depth);
    line.push_str(&close.repeat(depth));
    line.push_str(tail);
    line
}

/// The shapes, each built to `bytes`. Six are slow to read byte for byte and
/// are built shorter, the two lengths of each still four times apart.
///
/// Five of them have no command boundary for the normaliser to cut at. Such
/// a line, once longer than one of its pieces (8 KB), is read in its
/// normalised spelling as well, which doubles the cost once and is not
/// growth (measured 2026-11-10: a step of two between 8 000 and 10 000
/// bytes, four times the cost at four times the length above it). They are
/// built to five eighths, over one piece at both lengths. Nested
/// substitutions show no such step and are built to a quarter.
///
/// Two, both of assignments, are built twice as long. Reading an assignment costs so much by itself
/// that a second reading of every assignment at each one shows only from
/// some 3 500 of them: at 3 277 the long line took 7.8 times the short one
/// (measured 2026-11-10), under the bound.
fn shapes(bytes: usize) -> Vec<(&'static str, String)> {
    let less = bytes / 4;
    let over = bytes / 8 * 5;
    let twice = bytes * 2;
    let every_character = "IFS='!\"#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                           [\\]^_`abcdefghijklmnopqrstuvwxyz'; a=\"";
    vec![
        // The guard named many times in one command.
        (
            "a redirection after each name",
            repeated("foo ", "iw 2>x ", "", bytes),
        ),
        ("a name, a redirection", repeated("", "iw >x ", "", bytes)),
        ("a name, both outputs", repeated("", "iw &>x ", "", bytes)),
        (
            "a list read after each name",
            repeated("foo ", "iw allow --list ", "", bytes),
        ),
        (
            "a name in each option",
            repeated("foo ", "--a=/iw ", "", bytes),
        ),
        (
            "a name with a value option",
            repeated("x ", "iw --data-dir ", "", bytes),
        ),
        (
            "a status in each command",
            repeated("", "iw 2>&1 status; ", "", bytes),
        ),
        // Redirections and substitutions.
        (
            "redirections before the verb",
            repeated("innerwarden ", "2>/dev/null ", "status", bytes),
        ),
        (
            "an output after each word",
            repeated("innerwarden status ", "> x ", "", bytes),
        ),
        (
            "a process substitution each",
            repeated("", "cat <(iw status) ", "", bytes),
        ),
        (
            "process substitutions four deep",
            repeated("", "cat <(cat <(cat <(cat <(iw status)))) ", "", bytes),
        ),
        (
            "a split string each",
            repeated("", "env -S 'iw status' ", "", bytes),
        ),
        (
            "a pipe into a shell each",
            repeated("", "echo x | sh; ", "innerwarden status", bytes),
        ),
        // Lines the grammar reads ahead on.
        (
            "an array and a word",
            repeated("", "x=(1)y ", "innerwarden status", over),
        ),
        (
            "an array and an escape",
            repeated("", "x=(1)\\# ", "innerwarden status", over),
        ),
        (
            "an array and a comment",
            repeated("", "x=(1)# ", "\ninnerwarden status", over),
        ),
        (
            "a case in a substitution",
            repeated(
                "",
                "a=$(case x in (x) esac)# ",
                "; innerwarden status",
                over,
            ),
        ),
        (
            "an open case each",
            repeated("", "case x in ", "innerwarden status", bytes),
        ),
        // One thing inside the other.
        (
            "substitutions nested",
            nested("a=$(", ")", "#;innerwarden status", less),
        ),
        ("groups nested", nested("(", ")", "", bytes)),
        (
            "arithmetic nested",
            nested("$((", "))", "; innerwarden status", over),
        ),
        (
            "process substitutions nested",
            nested("<(", "", "iw status", bytes),
        ),
        // Text a shell is handed.
        (
            "a here-document of defaults",
            numbered("bash <<'EOF'\n", "${x#-a} b\n", "EOF", bytes),
        ),
        (
            "a command string of names",
            numbered("sh -c '", "$v# ", "'; ", bytes),
        ),
        (
            "a here-string of one name",
            repeated("bash <<< '", "$x ", "'; ", bytes),
        ),
        (
            "every character a separator",
            repeated(every_character, "a,b;c:d ", "\"; $a x", bytes),
        ),
        // Arguments set and shifted.
        (
            "arguments set after a shift",
            repeated("shift $n; set -- ", "a ", "; $1 x", bytes),
        ),
        (
            "arguments set before a shift",
            repeated("set -- ", "a ", "; shift $n; echo ok", bytes),
        ),
        (
            "a function that shifts",
            repeated("f() { shift; }; f ", "a ", "", bytes),
        ),
        // A read of the guard's lists, many times.
        ("the mute list", repeated("", "iw mute --list ", "", bytes)),
        (
            "the allow list",
            repeated("", "innerwarden allow --list ", "", bytes),
        ),
        (
            "the mute list shown",
            repeated("", "echo iw mute --list ", "", bytes),
        ),
        (
            "the mute list piped",
            repeated("", "echo iw mute --list | ", "cat", bytes),
        ),
        (
            "the ctl's scan",
            repeated("", "innerwarden-ctl agent scan ", "", bytes),
        ),
        ("the gate's verb", repeated("", "iw exec-gate ", "", bytes)),
        // Brace expansions: too large to make, many small ones, and groups
        // the shell leaves as written.
        (
            "one word of groups of two",
            repeated("", "{a,b}", " x", bytes),
        ),
        (
            "words of fourteen groups",
            repeated("echo ", &format!("{} ", "{a,b}".repeat(14)), "", bytes),
        ),
        (
            "a sequence in each word",
            repeated("echo ", "{0..63} ", "", bytes),
        ),
        (
            "groups of one in one word",
            repeated("k", "{e..e}", "rnel", bytes),
        ),
        ("groups the shell leaves", repeated("", "{a}", "", bytes)),
        ("braces nested", nested("{", "}", "", bytes)),
        ("lists nested", nested("{a,", "}", "", bytes)),
        // Names: one assigned over and over and read back each time, and many
        // given the guard with a value read after each.
        (
            "a name assigned its own value",
            repeated("", "a=$a;", "", twice),
        ),
        (
            "the guard given, a value read",
            numbered("", "a#=iw $b ", "", bytes),
        ),
        (
            "a value read after each assignment",
            numbered("", "a#=x; $a# ;", "", twice),
        ),
    ]
}

/// What the thread that asks has spent so far: its CPU time where the
/// system keeps one, so a runner busy with other work does not count; the
/// wall clock elsewhere (Windows).
#[cfg(unix)]
fn spent() -> Duration {
    // SAFETY: clock_gettime only writes the timespec it is given.
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    let read = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut now) };
    assert_eq!(read, 0, "the thread's CPU clock could not be read");
    Duration::new(now.tv_sec as u64, now.tv_nsec as u32)
}

#[cfg(not(unix))]
fn spent() -> Duration {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed()
}

/// What one reading of `line` by `read` took.
fn reading(read: &dyn Fn(&str), line: &str) -> Duration {
    let start = spent();
    read(black_box(line));
    spent().saturating_sub(start)
}

/// Whether the long line took more than the short one's time allows it.
fn too_slow(short: Duration, long: Duration) -> bool {
    long > TIMES * short.max(SHORT_FLOOR)
}

/// The fastest readings of the short and the long line, read in turn until
/// the long one is within the bound or [`ROUNDS`] have been read.
fn measured(read: &dyn Fn(&str), short_line: &str, long_line: &str) -> (Duration, Duration) {
    let (mut short, mut long) = (Duration::MAX, Duration::MAX);
    for _ in 0..ROUNDS {
        short = short.min(reading(read, short_line));
        long = long.min(reading(read, long_line));
        if !too_slow(short, long) {
            break;
        }
    }
    (short, long)
}

fn check(line: &str) {
    black_box(check_guard_self_disable(line));
}

/// FAILS ON REVERT: take the payment for the words after each name out of
/// `guard_cli_named_later_loosens` and "a list read after each name" and "a
/// name in each option" take sixteen times as long at four times the
/// length. Hand the parser the whole text whatever it has read
/// (`shell::parse_bash`) and "an array and a word" and "an array and an
/// escape" do. The brace shapes that double with each group
/// ("one word of groups of two") do not end at all without the sum a
/// command's expansions are held to; the test that fails on that revert
/// in good time is `the_rewrite_leaves_a_word_too_large_as_written_and_says_so`.
/// Look a name's values up by reading every name the line assigned
/// (`ValuesAssigned::values`, asked by `with_values_assigned`) instead of
/// the one asked for, and "a value read after each assignment" takes 10.3
/// times as long at four times the length (2.7 on main), "the guard given,
/// a value read" 11.5 (4.2 on main), measured in a debug build on the lab
/// box, 2026-11-21. "a name assigned its own value" does not tell that
/// revert apart (2.6 both ways): its values all hold a name, and a name
/// with more values than are read is never looked up again. Ask every name the line gave the guard at each word
/// (`guard_program`) and "the guard given, a value read" takes twelve times
/// as long (19 s in a debug build on the lab box, 2026-11-10).
#[test]
#[cfg_attr(
    tarpaulin,
    ignore = "a cost measured under instrumentation measures the instrumentation"
)]
fn the_check_costs_what_the_lines_length_costs() {
    if !ceilings_are_asserted() {
        return;
    }
    // The first reading builds what the check keeps for every later one
    // (its patterns); it is not part of any line's cost.
    check("innerwarden status");
    let mut report = Vec::new();
    let mut slow = Vec::new();
    for ((name, short_line), (_, long_line)) in shapes(SHORT).into_iter().zip(shapes(LONG)) {
        let (short, long) = measured(&check, &short_line, &long_line);
        report.push(format!(
            "  {:>8.1} ms  {:>8.1} ms  {:>5.1}x  {name}",
            short.as_secs_f64() * 1e3,
            long.as_secs_f64() * 1e3,
            long.as_secs_f64() / short.max(SHORT_FLOOR).as_secs_f64(),
        ));
        if too_slow(short, long) {
            slow.push(name);
        }
    }
    assert!(
        slow.is_empty(),
        "the check took more than {TIMES} times as long at four times the length on: {slow:?}\n\
         short, long, ratio, shape:\n{}",
        report.join("\n")
    );
    if std::env::var_os("IW_PRINT_GUARD_CHECK_COST").is_some() {
        println!("{}", report.join("\n"));
    }
}

/// One pass over `bytes`, counting the spaces.
fn scan(bytes: &[u8]) -> usize {
    let mut spaces = 0;
    for byte in bytes {
        spaces += usize::from(*byte == b' ');
    }
    spaces
}

/// `read`, done as many times (a power of two) as the short line needs to
/// take four times [`SHORT_FLOOR`].
fn repeated_until_measurable(short_line: &str, read: impl Fn(&str)) -> impl Fn(&str) {
    let mut times = 1usize;
    loop {
        let start = spent();
        for _ in 0..times {
            read(black_box(short_line));
        }
        if spent().saturating_sub(start) >= 4 * SHORT_FLOOR {
            break;
        }
        times *= 2;
    }
    move |text: &str| {
        for _ in 0..times {
            read(text);
        }
    }
}

/// The measure, given a reading that grows with the line's length and one
/// that reads the rest of the line again at each word (as the slow readings
/// the shapes stand for did), passes the first and fails the second. Without
/// it, a measure that could not tell them apart (a clock too coarse, a floor
/// too high, a bound too loose) would pass every shape and prove nothing.
#[test]
#[cfg_attr(
    tarpaulin,
    ignore = "a cost measured under instrumentation measures the instrumentation"
)]
fn the_measure_tells_a_square_from_a_line() {
    if !ceilings_are_asserted() {
        return;
    }
    let words = |bytes| repeated("", &format!("{} ", "x".repeat(63)), "", bytes);
    let (short_line, long_line) = (words(SHORT), words(LONG));
    // Each reading is repeated until the short line costs well over the
    // floor, so the floor does not decide the ratio in a build where one
    // pass is fast (an optimised one).
    let line = repeated_until_measurable(&short_line, |text: &str| {
        black_box(scan(black_box(text.as_bytes())));
    });
    let square = repeated_until_measurable(&short_line, |text: &str| {
        for (at, _) in text.match_indices(' ') {
            black_box(scan(black_box(&text.as_bytes()[at..])));
        }
    });
    let (short, long) = measured(&line, &short_line, &long_line);
    assert!(
        short > SHORT_FLOOR && !too_slow(short, long),
        "a reading that grows with the length: {short:?} then {long:?}"
    );
    let (short, long) = measured(&square, &short_line, &long_line);
    assert!(
        short > SHORT_FLOOR && too_slow(short, long),
        "a reading that grows with the square of the length: {short:?} then {long:?}"
    );
}
