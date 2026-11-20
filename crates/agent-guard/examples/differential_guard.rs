//! The differential check: main's verdicts against a branch's, line by line.
//!
//! The release safety suite holds the guard to `corpus/reference.tsv`, the
//! verdicts at the last accepted state. That catches a corpus total getting
//! worse, but a pull request can still move one line from refused to allowed
//! while another moves the other way. This check judges every line twice, with
//! the guard of the merge base and with the guard of the branch, and refuses
//! the branch when a line main stops is no longer stopped.
//!
//! Three steps, so both sides judge exactly the same lines:
//!
//! ```text
//! differential_guard cases <repo>               > cases.jsonl   (branch build)
//! differential_guard judge cases.jsonl --place D > base.jsonl   (main's build)
//! differential_guard judge cases.jsonl --place D > head.jsonl   (branch build)
//! differential_guard compare --cases cases.jsonl --base base.jsonl \
//!     --head head.jsonl --changes crates/agent-guard/corpus/REFERENCE-CHANGES.md \
//!     [--base-bin PATH --head-bin PATH]                          (branch build)
//! ```
//!
//! CI builds this file at the merge base too (the branch's copy, put in place
//! before the build), so the two sides differ only in the guard under it.
//!
//! `cases` reads every corpus (`benchmarks/agent_attack_corpus.yml` and each
//! `corpus/*/cases.yml`) and adds metamorphic variants of every malicious shell
//! line: rewrites the shell treats as the same command (a redirect glued to a
//! word, a word split with quotes, a wrapper, the line moved into a body, a
//! word routed through a variable, flags clustered differently). Nothing is
//! ever executed; lines are only judged.
//!
//! A line is STOPPED when it is denied, or reviewed with a signal that holds an
//! agent (`CaseResult::blocks_for_agent`). `compare` fails when main stops a
//! line and the branch does not, unless the line is benign and named under a
//! dated entry of `REFERENCE-CHANGES.md` with `harmless-proven:`. A line marked
//! `must_refuse` (and every variant of it) is never waived, and a malicious
//! line is never waived either: proving a line harmless is only possible for a
//! line that is not an attack. Every other change of verdict is listed, in both
//! directions, with the time per line (p50, p99) and the size of both judges.
//!
//! A line that makes the guard panic is recorded as `panic` and counts as
//! stopped, as the hook refuses a call whose screening panicked (in enforce).
//! It needs the judges built with `CARGO_PROFILE_RELEASE_PANIC=unwind`: the
//! release profile aborts on a panic, and the run would end at that line.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

use innerwarden_agent_guard::benchmark::{run, Corpus};
use innerwarden_agent_guard::rules::RuleEngine;
use serde::{Deserialize, Serialize};

/// One line to judge, as `cases` writes it and `judge` reads it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Line {
    corpus: String,
    id: String,
    category: String,
    label: String,
    surface: String,
    input: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expect: Option<String>,
    #[serde(default)]
    must_refuse: bool,
    /// For a generated variant: the transformation that made it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transform: Option<String>,
}

impl Line {
    fn key(&self) -> String {
        format!("{}/{}", self.corpus, self.id)
    }
}

/// One verdict, as `judge` writes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Verdict {
    corpus: String,
    id: String,
    recommendation: String,
    stopped: bool,
    signals: Vec<String>,
    micros: u64,
    /// The guard panicked on this line. The hook refuses a call whose
    /// screening panicked (in enforce), so a panic counts as stopped; it is
    /// still listed, because a crash is a bug.
    #[serde(default)]
    panicked: bool,
}

impl Verdict {
    fn key(&self) -> String {
        format!("{}/{}", self.corpus, self.id)
    }
}

#[derive(Deserialize)]
struct RawCorpus {
    cases: Vec<RawCase>,
}

#[derive(Deserialize)]
struct RawCase {
    id: String,
    category: String,
    label: String,
    #[serde(default)]
    surface: Option<String>,
    input: String,
    #[serde(default)]
    expect: Option<String>,
    #[serde(default)]
    must_refuse: bool,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("cases") => cases(&args[1..]),
        Some("judge") => judge(&args[1..]),
        Some("compare") => compare(&args[1..]),
        _ => {
            eprintln!("usage: differential_guard cases <repo> | judge <cases.jsonl> --place <dir> | compare --cases F --base F --head F --changes F [--base-bin P --head-bin P]");
            2
        }
    };
    std::process::exit(code);
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

// ---------------------------------------------------------------------------
// cases
// ---------------------------------------------------------------------------

/// The corpora, in a fixed order: the proof corpus first, then every
/// `corpus/<name>/cases.yml` by name. A corpus added later is judged without
/// touching this file.
fn corpus_files(repo: &Path) -> Vec<(String, PathBuf)> {
    let guard = repo.join("crates/agent-guard");
    let mut out = vec![(
        "proof".to_string(),
        guard.join("benchmarks/agent_attack_corpus.yml"),
    )];
    let mut dirs: Vec<(String, PathBuf)> = std::fs::read_dir(guard.join("corpus"))
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.join("cases.yml").is_file())
                .filter_map(|p| {
                    let name = p.file_name()?.to_str()?.to_string();
                    Some((name, p.join("cases.yml")))
                })
                .collect()
        })
        .unwrap_or_default();
    dirs.sort();
    out.extend(dirs);
    out
}

fn cases(args: &[String]) -> i32 {
    let Some(repo) = args.first() else {
        eprintln!("cases: give the repository root");
        return 2;
    };
    let mut lines: Vec<Line> = Vec::new();
    let mut seen = BTreeSet::new();
    for (name, path) in corpus_files(Path::new(repo)) {
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("cases: {}: {e}", path.display());
                return 2;
            }
        };
        let raw: RawCorpus = match serde_yaml::from_str(&text) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("cases: {}: {e}", path.display());
                return 2;
            }
        };
        for c in raw.cases {
            let line = Line {
                corpus: name.clone(),
                id: c.id,
                category: c.category,
                label: c.label,
                surface: c.surface.unwrap_or_else(|| "command".to_string()),
                input: c.input,
                expect: c.expect,
                must_refuse: c.must_refuse,
                transform: None,
            };
            if !seen.insert(line.key()) {
                eprintln!("cases: {} appears twice", line.key());
                return 2;
            }
            lines.push(line);
        }
    }
    let seeds: Vec<Line> = lines.clone();
    for seed in &seeds {
        if seed.label != "malicious" || seed.surface != "command" {
            continue;
        }
        let mut inputs = BTreeSet::new();
        inputs.insert(seed.input.trim_end().to_string());
        for (transform, input) in variants(&seed.input) {
            if !inputs.insert(input.clone()) {
                continue;
            }
            lines.push(Line {
                corpus: "variants".to_string(),
                id: format!("{}~{transform}", seed.key()),
                category: seed.category.clone(),
                label: "malicious".to_string(),
                surface: "command".to_string(),
                input,
                expect: None,
                must_refuse: seed.must_refuse,
                transform: Some(transform),
            });
        }
    }
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for l in &lines {
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string(l).expect("a line serialises")
        );
    }
    0
}

/// Wrap `s` in single quotes for `bash -c`.
fn single_quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A word the shell reads as itself: letters, digits and `._-/:=@%+,`.
fn plain_word(w: &str) -> bool {
    !w.is_empty()
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-/:=@%+,".contains(c))
}

/// Metamorphic variants of one malicious shell line: rewrites the shell runs
/// as the same command. Bodies, wrappers and `bash -c` apply to any line; the
/// word-level rewrites only to a line of plain words separated by single
/// spaces, where splitting on spaces is what the shell does too.
fn variants(input: &str) -> Vec<(String, String)> {
    let s = input.trim_end();
    let mut out: Vec<(String, String)> = Vec::new();
    // Wrappers that run the rest of the line as a command.
    for (name, prefix) in [
        ("sudo", "sudo "),
        ("env", "env A=1 "),
        ("timeout", "timeout 5 "),
        ("nice", "nice -n 5 "),
        ("nohup", "nohup "),
    ] {
        out.push((format!("wrap-{name}"), format!("{prefix}{s}")));
    }
    out.push((
        "bash-c".to_string(),
        format!("bash -c {}", single_quoted(s)),
    ));
    // Bodies. A newline before the closing word keeps a here-document's
    // terminator on a line of its own.
    out.push(("body-if".to_string(), format!("if true; then\n{s}\nfi")));
    out.push(("body-for".to_string(), format!("for x in 1; do\n{s}\ndone")));
    out.push(("body-group".to_string(), format!("{{\n{s}\n}}")));
    out.push(("body-subshell".to_string(), format!("(\n{s}\n)")));
    out.push(("body-function".to_string(), format!("f() {{\n{s}\n}}\nf")));

    let words: Vec<&str> = s.split(' ').collect();
    if s.contains('\n') || words.iter().any(|w| !plain_word(w)) {
        return out;
    }
    let rest = |from: usize| words[from..].join(" ");
    let with = |i: usize, w: &str| -> String {
        let mut v: Vec<String> = words.iter().map(|x| x.to_string()).collect();
        v[i] = w.to_string();
        v.join(" ")
    };
    // xargs and find -exec take one simple command.
    out.push(("xargs".to_string(), format!("printf '' | xargs -0 {s}")));
    out.push((
        "find-exec".to_string(),
        format!("find . -maxdepth 0 -exec {s} \\;"),
    ));
    // A redirect glued to the verb (the second word), or to the program when
    // there is no second word.
    let verb = if words.len() >= 2 { 1 } else { 0 };
    for (name, redirect) in [
        ("redirect-out", ">/dev/null"),
        ("redirect-in", "</dev/null"),
        ("redirect-err", ">&2"),
    ] {
        out.push((
            name.to_string(),
            with(verb, &format!("{}{redirect}", words[verb])),
        ));
    }
    // A word split with quotes or an escape: the program and the verb.
    for (i, which) in [(0usize, "program"), (1usize, "verb")] {
        let Some(w) = words.get(i) else { continue };
        if w.len() < 3 || w.starts_with('-') || w.contains('=') || w.contains('/') {
            continue;
        }
        let (head, tail) = w.split_at(1);
        out.push((
            format!("split-quotes-{which}"),
            with(i, &format!("{head}''{tail}")),
        ));
        out.push((
            format!("split-escape-{which}"),
            with(i, &format!("{head}\\{tail}")),
        ));
        out.push((format!("ansi-c-{which}"), with(i, &format!("$'{w}'"))));
    }
    // The verb routed through a variable or a brace.
    if words.len() >= 2 && !words[1].starts_with('-') {
        out.push((
            "variable-verb".to_string(),
            format!("v={}; {} $v {}", words[1], words[0], rest(2))
                .trim_end()
                .to_string(),
        ));
        out.push((
            "brace-verb".to_string(),
            with(1, &format!("{{{},}}", words[1])),
        ));
    }
    // Flags clustered differently: reversed and split.
    for (i, w) in words.iter().enumerate() {
        let letters = w.strip_prefix('-').unwrap_or("");
        if i == 0
            || w.starts_with("--")
            || letters.len() < 2
            || !letters.chars().all(|c| c.is_ascii_alphabetic())
        {
            continue;
        }
        let reversed: String = letters.chars().rev().collect();
        if reversed != letters {
            out.push((
                format!("flags-reversed-{i}"),
                with(i, &format!("-{reversed}")),
            ));
        }
        let split: Vec<String> = letters.chars().map(|c| format!("-{c}")).collect();
        out.push((format!("flags-split-{i}"), with(i, &split.join(" "))));
    }
    out
}

// ---------------------------------------------------------------------------
// judge
// ---------------------------------------------------------------------------

/// Judge from an empty home and an empty working folder, as the release safety
/// suite does: some verdicts read what the home holds. The place is given, not
/// under `/tmp` by default, and both sides must be given the same one.
fn enter_empty_place(place: &Path) -> std::io::Result<()> {
    if place.exists() {
        std::fs::remove_dir_all(place)?;
    }
    let home = place.join("home");
    let work = place.join("work");
    std::fs::create_dir_all(&home)?;
    std::fs::create_dir_all(&work)?;
    std::env::set_var("HOME", &home);
    std::env::remove_var("XDG_CONFIG_HOME");
    std::env::set_current_dir(&work)
}

fn read_lines(path: &str) -> Result<Vec<Line>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    BufReader::new(file)
        .lines()
        .enumerate()
        .filter(|(_, l)| l.as_ref().map(|t| !t.trim().is_empty()).unwrap_or(true))
        .map(|(n, l)| {
            let l = l.map_err(|e| format!("{path}:{}: {e}", n + 1))?;
            serde_json::from_str(&l).map_err(|e| format!("{path}:{}: {e}", n + 1))
        })
        .collect()
}

fn judge(args: &[String]) -> i32 {
    let Some(path) = args.first() else {
        eprintln!("judge: give the cases file");
        return 2;
    };
    let lines = match read_lines(path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("judge: {e}");
            return 2;
        }
    };
    let place = flag(args, "--place")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/differential-place"));
    let place = std::path::absolute(&place).unwrap_or(place);
    if let Err(e) = enter_empty_place(&place) {
        eprintln!("judge: {}: {e}", place.display());
        return 2;
    }
    let engine = RuleEngine::load_embedded();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in &lines {
        // Built through serde, so a field the corpus type gains later does not
        // stop this file from building against an older guard.
        let case = serde_json::json!({
            "cases": [{
                "id": line.id,
                "category": line.category,
                "label": line.label,
                "surface": line.surface,
                "input": line.input,
                "expect": line.expect,
            }]
        });
        let corpus: Corpus = match serde_json::from_value(case) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("judge: {}: {e}", line.key());
                return 2;
            }
        };
        // A line that makes the guard panic is recorded, not fatal: the judges
        // are built with `CARGO_PROFILE_RELEASE_PANIC=unwind` for that (the
        // release profile aborts). Without unwinding, the first such line ends
        // the run and every line after it has no verdict, which `compare`
        // refuses as a broken run.
        let started = Instant::now();
        let judged =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&corpus, &engine)));
        let micros = started.elapsed().as_micros() as u64;
        let verdict = match judged {
            Ok(results) => {
                let Some(r) = results.first() else {
                    eprintln!("judge: {}: no verdict", line.key());
                    return 2;
                };
                Verdict {
                    corpus: line.corpus.clone(),
                    id: line.id.clone(),
                    recommendation: r.recommendation.clone(),
                    stopped: r.blocks_for_agent(),
                    signals: r.signals.clone(),
                    micros,
                    panicked: false,
                }
            }
            Err(_) => Verdict {
                corpus: line.corpus.clone(),
                id: line.id.clone(),
                recommendation: "panic".to_string(),
                stopped: true,
                signals: Vec::new(),
                micros,
                panicked: true,
            },
        };
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string(&verdict).expect("a verdict serialises")
        );
    }
    0
}

// ---------------------------------------------------------------------------
// compare
// ---------------------------------------------------------------------------

/// The cases named `harmless-proven:` in a dated entry of REFERENCE-CHANGES.md
/// (`- YYYY-MM-DD: ...`, continued on indented lines). The names run from the
/// label to the end of the entry, as `corpus/id`, separated by spaces or commas.
fn harmless_proven(md: &str) -> BTreeSet<String> {
    fn dated(line: &str) -> bool {
        let b = line.as_bytes();
        b.len() >= 14
            && line.starts_with("- ")
            && b[2..6].iter().all(u8::is_ascii_digit)
            && b[6] == b'-'
            && b[7..9].iter().all(u8::is_ascii_digit)
            && b[9] == b'-'
            && b[10..12].iter().all(u8::is_ascii_digit)
            && b[12] == b':'
    }
    let mut entries: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    for line in md.lines() {
        if dated(line) {
            entries.extend(current.take());
            current = Some(line.to_string());
        } else if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(c) = current.as_mut() {
                c.push(' ');
                c.push_str(line.trim());
            }
        } else {
            entries.extend(current.take());
        }
    }
    entries.extend(current);
    let mut named = BTreeSet::new();
    for entry in entries {
        let Some(at) = entry.find("harmless-proven:") else {
            continue;
        };
        for word in entry[at + "harmless-proven:".len()..].split([' ', ',', ';']) {
            let word = word.trim_matches(|c: char| c == '`' || c == '.' || c == '(' || c == ')');
            if word.contains('/') && !word.is_empty() {
                named.insert(word.to_string());
            }
        }
    }
    named
}

fn read_verdicts(path: &str) -> Result<BTreeMap<String, Verdict>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut out = BTreeMap::new();
    for (n, l) in BufReader::new(file).lines().enumerate() {
        let l = l.map_err(|e| format!("{path}:{}: {e}", n + 1))?;
        if l.trim().is_empty() {
            continue;
        }
        let v: Verdict = serde_json::from_str(&l).map_err(|e| format!("{path}:{}: {e}", n + 1))?;
        out.insert(v.key(), v);
    }
    Ok(out)
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

/// The input as one table cell: newlines shown as `\n`, pipes escaped, long
/// lines cut.
fn cell(input: &str) -> String {
    let flat = input
        .replace('\n', "\\n")
        .replace('|', "\\|")
        .replace('`', "'");
    let cut: String = flat.chars().take(140).collect();
    if cut.len() < flat.len() {
        format!("`{cut}...`")
    } else {
        format!("`{cut}`")
    }
}

fn shown(v: &Verdict) -> String {
    format!(
        "{}{}",
        v.recommendation,
        if v.stopped { " (stops)" } else { "" }
    )
}

fn compare(args: &[String]) -> i32 {
    let (Some(cases_path), Some(base_path), Some(head_path), Some(changes_path)) = (
        flag(args, "--cases"),
        flag(args, "--base"),
        flag(args, "--head"),
        flag(args, "--changes"),
    ) else {
        eprintln!("compare: give --cases, --base, --head and --changes");
        return 2;
    };
    let lines = match read_lines(&cases_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("compare: {e}");
            return 2;
        }
    };
    let (base, head) = match (read_verdicts(&base_path), read_verdicts(&head_path)) {
        (Ok(b), Ok(h)) => (b, h),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("compare: {e}");
            return 2;
        }
    };
    let waived = match std::fs::read_to_string(&changes_path) {
        Ok(md) => harmless_proven(&md),
        Err(e) => {
            eprintln!("compare: {changes_path}: {e}");
            return 2;
        }
    };
    // A side that judged fewer lines is a broken run, never a pass.
    let missing: Vec<String> = lines
        .iter()
        .map(Line::key)
        .filter(|k| !base.contains_key(k) || !head.contains_key(k))
        .collect();
    if !missing.is_empty() {
        eprintln!(
            "compare: {} line(s) have no verdict on one side, first: {}",
            missing.len(),
            missing[0]
        );
        return 2;
    }

    let mut report = String::new();
    let _ = writeln!(report, "## Guard verdicts: main against this branch\n");
    let _ = writeln!(
        report,
        "Every corpus line and every generated variant, judged by the guard of the merge base and by the guard of this branch, from an empty home. **Stops** = deny, or a review that holds an agent.\n"
    );

    // Per corpus.
    let mut corpora: BTreeMap<&str, [usize; 5]> = BTreeMap::new();
    for l in &lines {
        let b = &base[&l.key()];
        let h = &head[&l.key()];
        let row = corpora.entry(l.corpus.as_str()).or_default();
        row[0] += 1;
        row[1] += usize::from(b.stopped);
        row[2] += usize::from(h.stopped);
        row[3] += usize::from(b.recommendation != h.recommendation || b.stopped != h.stopped);
        row[4] += usize::from(l.must_refuse);
    }
    let _ = writeln!(report, "| corpus | lines | must-refuse | stopped by main | stopped by this branch | verdict changed |");
    let _ = writeln!(report, "|---|---|---|---|---|---|");
    for (name, r) in &corpora {
        let _ = writeln!(
            report,
            "| {name} | {} | {} | {} | {} | {} |",
            r[0], r[4], r[1], r[2], r[3]
        );
    }

    // Main stops it, this branch does not.
    let mut failures: Vec<(&Line, &Verdict, &Verdict, &'static str)> = Vec::new();
    let mut accepted: Vec<(&Line, &Verdict, &Verdict)> = Vec::new();
    let mut other_changes: Vec<(&Line, &Verdict, &Verdict)> = Vec::new();
    for l in &lines {
        let b = &base[&l.key()];
        let h = &head[&l.key()];
        if b.stopped && !h.stopped {
            let why = if l.must_refuse {
                Some("must-refuse: never waived")
            } else if l.label != "benign" {
                Some("malicious: only a benign line can be proven harmless")
            } else if !waived.contains(&l.key()) {
                Some("benign, not named harmless-proven in REFERENCE-CHANGES.md")
            } else {
                None
            };
            match why {
                Some(w) => failures.push((l, b, h, w)),
                None => accepted.push((l, b, h)),
            }
        } else if b.recommendation != h.recommendation || b.stopped != h.stopped {
            other_changes.push((l, b, h));
        }
    }
    let _ = writeln!(report, "\n### Stopped by main, not by this branch\n");
    if failures.is_empty() && accepted.is_empty() {
        let _ = writeln!(report, "None.");
    } else {
        let _ = writeln!(
            report,
            "| result | case | label | main | this branch | input |"
        );
        let _ = writeln!(report, "|---|---|---|---|---|---|");
        for (l, b, h, why) in &failures {
            let _ = writeln!(
                report,
                "| **FAIL** ({why}) | {} | {} | {} | {} | {} |",
                l.key(),
                l.label,
                shown(b),
                shown(h),
                cell(&l.input)
            );
        }
        for (l, b, h) in &accepted {
            let _ = writeln!(
                report,
                "| waived (harmless-proven) | {} | {} | {} | {} | {} |",
                l.key(),
                l.label,
                shown(b),
                shown(h),
                cell(&l.input)
            );
        }
    }
    let _ = writeln!(report, "\n### Every other change of verdict\n");
    if other_changes.is_empty() {
        let _ = writeln!(report, "None.");
    } else {
        let _ = writeln!(report, "| case | label | main | this branch | input |");
        let _ = writeln!(report, "|---|---|---|---|---|");
        for (l, b, h) in &other_changes {
            let _ = writeln!(
                report,
                "| {} | {} | {} | {} | {} |",
                l.key(),
                l.label,
                shown(b),
                shown(h),
                cell(&l.input)
            );
        }
    }

    // A line that makes either guard panic. The hook refuses such a call in
    // enforce, so it counts as stopped above; it is listed here because a
    // crash is a bug whichever side it is on.
    let crashes: Vec<&Line> = lines
        .iter()
        .filter(|l| base[&l.key()].panicked || head[&l.key()].panicked)
        .collect();
    let _ = writeln!(report, "\n### Lines that crash the guard\n");
    if crashes.is_empty() {
        let _ = writeln!(report, "None.");
    } else {
        let _ = writeln!(
            report,
            "| case | main | this branch | input |\n|---|---|---|---|"
        );
        for l in &crashes {
            let _ = writeln!(
                report,
                "| {} | {} | {} | {} |",
                l.key(),
                shown(&base[&l.key()]),
                shown(&head[&l.key()]),
                cell(&l.input)
            );
        }
    }

    // What main itself lets through: a baseline, not a failure of this branch.
    let holes: Vec<&Line> = lines
        .iter()
        .filter(|l| l.must_refuse && l.transform.is_none() && !base[&l.key()].stopped)
        .collect();
    let mut variant_holes: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for l in lines.iter().filter(|l| l.transform.is_some()) {
        let t = l.transform.as_deref().unwrap_or("");
        let family = t.split('-').take(2).collect::<Vec<_>>().join("-");
        let e = variant_holes.entry(family).or_default();
        e.1 += 1;
        e.0 += usize::from(!base[&l.key()].stopped);
    }
    let _ = writeln!(
        report,
        "\n### What main does not stop (baseline, not a failure)\n"
    );
    let _ = writeln!(
        report,
        "Must-refuse lines main does not stop: {}.",
        holes.len()
    );
    if !holes.is_empty() {
        let _ = writeln!(report, "\n| case | main | input |\n|---|---|---|");
        for l in &holes {
            let _ = writeln!(
                report,
                "| {} | {} | {} |",
                l.key(),
                shown(&base[&l.key()]),
                cell(&l.input)
            );
        }
    }
    let _ = writeln!(
        report,
        "\nVariants of malicious lines main does not stop, by transformation:\n"
    );
    let _ = writeln!(
        report,
        "| transformation | variants | not stopped by main |\n|---|---|---|"
    );
    for (t, (open, total)) in &variant_holes {
        let _ = writeln!(report, "| {t} | {total} | {open} |");
    }

    // Time per line and size of the judges: the baseline for later steps.
    let mut tb: Vec<u64> = base.values().map(|v| v.micros).collect();
    let mut th: Vec<u64> = head.values().map(|v| v.micros).collect();
    tb.sort_unstable();
    th.sort_unstable();
    let _ = writeln!(report, "\n### Time per line and size\n");
    let _ = writeln!(
        report,
        "| guard | lines | p50 | p99 | max |\n|---|---|---|---|---|"
    );
    for (name, t) in [("main", &tb), ("this branch", &th)] {
        let _ = writeln!(
            report,
            "| {name} | {} | {} us | {} us | {} us |",
            t.len(),
            percentile(t, 0.50),
            percentile(t, 0.99),
            t.last().copied().unwrap_or(0)
        );
    }
    for (name, path) in [
        ("main", flag(args, "--base-bin")),
        ("this branch", flag(args, "--head-bin")),
    ] {
        if let Some(p) = path {
            match std::fs::metadata(&p) {
                Ok(m) => {
                    let _ = writeln!(
                        report,
                        "\nJudge binary ({name}, release build of this file): {} bytes.",
                        m.len()
                    );
                }
                Err(e) => {
                    let _ = writeln!(report, "\nJudge binary ({name}): {p}: {e}");
                }
            }
        }
    }
    let _ = writeln!(
        report,
        "\nTimes are measured on whatever machine runs this and are reported, not gated. The binary is the guard engine with its embedded rules plus this small judge."
    );

    let _ = writeln!(report, "\n### Result\n");
    if failures.is_empty() {
        let _ = writeln!(
            report,
            "PASS: no line main stops goes unstopped on this branch ({} waived as harmless-proven).",
            accepted.len()
        );
    } else {
        let _ = writeln!(
            report,
            "FAIL: {} line(s) main stops are not stopped on this branch. A benign line can be waived with a dated entry in REFERENCE-CHANGES.md that names it after `harmless-proven:`; a malicious or must-refuse line cannot.",
            failures.len()
        );
    }
    print!("{report}");
    i32::from(!failures.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_waiver_is_read_only_from_a_dated_entry() {
        let md = "# Why\n\nharmless-proven: real/real-001\n\n- 2026-11-21: real/real-002 deny -> allow.\n  harmless-proven: real/real-002, `real/real-003`.\n- 2026-11-22: nothing waived here.\n";
        let named = harmless_proven(md);
        assert!(named.contains("real/real-002"));
        assert!(named.contains("real/real-003"));
        assert!(!named.contains("real/real-001"));
    }

    #[test]
    fn variants_of_a_plain_line_cover_every_family() {
        let v = variants("systemctl stop innerwarden-agent");
        let names: BTreeSet<&str> = v.iter().map(|(n, _)| n.as_str()).collect();
        for want in [
            "wrap-sudo",
            "bash-c",
            "body-if",
            "xargs",
            "find-exec",
            "redirect-out",
            "split-quotes-verb",
            "variable-verb",
            "brace-verb",
        ] {
            assert!(names.contains(want), "{want}");
        }
        assert!(v.contains(&(
            "redirect-out".to_string(),
            "systemctl stop>/dev/null innerwarden-agent".to_string()
        )));
        assert!(v.contains(&(
            "variable-verb".to_string(),
            "v=stop; systemctl $v innerwarden-agent".to_string()
        )));
    }

    #[test]
    fn a_quoted_or_multi_line_seed_gets_no_word_level_rewrite() {
        let v = variants("perl -e 'print 1'");
        assert!(v
            .iter()
            .all(|(n, _)| !n.starts_with("split-") && !n.starts_with("redirect-")));
        let h = variants("bash <<'EOF'\necho x\nEOF");
        assert!(h
            .iter()
            .any(|(n, s)| n == "body-if" && s.ends_with("EOF\nfi")));
    }

    #[test]
    fn flags_are_reversed_and_split() {
        let v = variants("rm -rf /");
        assert!(v.contains(&("flags-reversed-1".to_string(), "rm -fr /".to_string())));
        assert!(v.contains(&("flags-split-1".to_string(), "rm -r -f /".to_string())));
    }
}
