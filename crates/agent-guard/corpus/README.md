# Release safety suite

One measure of the guard per release, instead of chasing variants one by one.

```
cargo test -p innerwarden-agent-guard --test release_eval -- --nocapture
```

It runs every case below through the same inspectors as the proof benchmark
(`src/benchmark.rs`, embedded rules) and prints, per corpus: attacks caught /
total, attacks stopped for an agent, false positives / benign total, and every
case whose verdict differs from `reference.tsv`. It fails when any corpus
catches fewer attacks, stops fewer or raises more false positives than the
reference, when one case goes from caught to missed or from passing to a false
positive, or when the corpora and the reference no longer hold the same cases.

Every run judges from an empty home and an empty working folder, because some
verdicts read what is there (the guard's own files under the home, the SSH keys
present). The numbers are the same on any machine.

## Corpora

| Corpus | File | What it holds |
|---|---|---|
| proof | `../benchmarks/agent_attack_corpus.yml` | the curated agent-attack corpus and benign controls |
| attack-2026-11 | `attack-2026-11/cases.yml` | the lines the guard's tests fixed on 2026-11-18 and 19 (removals, persistence files, SSH keys and their use, the guard's own files, secret reads, shell runner forms), with the verdict each test asserts |
| real | `real/cases.yml` | lines agents really ran while building the guard, refused or held, then labelled by a person |

In `real`, `right_block` means the refusal was right (`expect: deny`: only a
deny counts); `legit_work` and `guard_bug` mean the line should pass, at most
for review (`expect: review`: a deny is the false positive). Most of them are
still denied today: that is the backlog the suite measures, not a pass. real-017
held a token, redacted before it came here; without it the line is reviewed, not
denied, and is counted as a miss.

Hosts, users, addresses and task numbers are replaced in `real`; a line seen
twice is kept once; Write and Edit tool calls are not shell lines and are left
out. Nothing in the corpora is executed.

## Changing the reference

`reference.tsv` changes only in a pull request that says why: add a dated line
to `REFERENCE-CHANGES.md` naming the cases that moved. CI refuses a reference
change without one (`scripts/release-eval-reference-check.sh`). After a
deliberate change:

```
IW_RELEASE_EVAL_WRITE=1 cargo test -p innerwarden-agent-guard --test release_eval
```

A new case enters the same way: add it to a corpus, rewrite the reference, and
say so in `REFERENCE-CHANGES.md`.
