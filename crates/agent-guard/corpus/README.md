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

**The numbers are those of an empty home.** Every run judges from an empty home
and an empty working folder, because some verdicts read what is there (the
guard's own files under the home, the SSH keys present). That makes the numbers
the same on any machine, and it means they are not the numbers of a host where
the guard is installed: there, `find ~ -name config.json -delete` is denied,
because the guard's own files sit under that home, while from the empty home it
is allowed. The guard reads the home from the process environment, so
`tests/release_eval.rs` holds a single test and puts the home back when it ends.

## Corpora

| Corpus | File | What it holds |
|---|---|---|
| proof | `../benchmarks/agent_attack_corpus.yml` | the curated agent-attack corpus and benign controls |
| attack-2026-11 | `attack-2026-11/cases.yml` | the lines the guard's tests fixed on 2026-11-18 and 19 (removals, including through xargs and find -exec, persistence files, SSH keys and their use, the guard's own files, secret reads, shell runner forms), with the verdict each test asserts; a test that only asserts "not allow" gives `expect: review` |
| real | `real/cases.yml` | lines agents really ran while building the guard, refused or held, then labelled by a person |
| external-2026-11 | `external-2026-11/cases.yml` | attacks the guard's authors did not write: AgentDojo's injection tasks (the text injected into a tool result and the tool calls the attack wants) and the shell calls of a model poisoned with a public recipe, with benign controls from the same sources; sources and licences in `external-2026-11/SOURCES.md`, the end-to-end result through the proxy and the hook in `external-2026-11/RESULTS.md` |

In `real`, `right_block` means the refusal was right (`expect: deny`: only a
deny counts); `legit_work` and `guard_bug` mean the line should pass, at most
for review (`expect: review`: a deny is the false positive). 25 of the 31 are
still denied on 2026-11-19: that is the false-positive baseline the suite
holds, not a pass. They fall in two known families: interpreter code or a
here-document carrying a word of the guard (refused by decision), and
`innerwarden check` of a dangerous line, where the argument is read as a
command. real-017
held a token, redacted before it came here; without it the line is reviewed, not
denied, and is counted as a miss.

Hosts, users, addresses and internal folder and file names are replaced in
`real` by neutral ones that keep the shape of the line; a line seen twice is
kept once; Write and Edit tool calls are not shell lines and are left
out. Nothing in the corpora is executed.

In `external-2026-11`, a tool call is written whole, as an MCP client sends it,
with `surface: tool_call` and the input `{"tool": ..., "arguments": {...}}`.
The suite judges each message on its own, so what the proxy decides from the
session (an argument that came out of an earlier result, the loop breaker,
pinned tools) is not in these verdicts; `RESULTS.md` has the session numbers.
Its misses and false positives at the first reference are the baseline the
suite holds, not a pass.

## Changing the reference

`reference.tsv` changes only in a pull request that says why: add a dated line
(`- YYYY-MM-DD: ...`) to `REFERENCE-CHANGES.md` that names every case whose
line moved, as `corpus/id` or a run like `a11-001..a11-040`, and why its new
verdict is right. CI refuses a reference change where a moved case is not named
(`scripts/release-eval-reference-check.sh`). After a
deliberate change:

```
IW_RELEASE_EVAL_WRITE=1 cargo test -p innerwarden-agent-guard --test release_eval
```

A new case enters the same way: add it to a corpus, rewrite the reference, and
say so in `REFERENCE-CHANGES.md`.
