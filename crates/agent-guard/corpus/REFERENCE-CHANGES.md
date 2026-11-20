# Why the release safety suite's reference changed

`reference.tsv` is what the release safety suite holds the guard to. A pull
request that changes it adds a dated line here, newest last (`- YYYY-MM-DD: ...`,
continued on indented lines), that names every case whose line moved, as
`corpus/id` or a run like `a11-001..a11-040`, with the verdict before and
after and why the new one is right. CI refuses a reference change where a moved
case is not named.

- 2026-11-19: first reference. proof 246/246 caught, 243/246 stopped for an
  agent, 0/160 false positives; attack-2026-11 377/377 caught, 313/377
  stopped, 0/138 false positives; real 4/5 caught, 25/31 false positives (the
  false-positive baseline: lines the guard refused during its own development,
  in two known families). Judged from an empty home.
- 2026-11-19: proof/dx-073 (`curl ... | perl -e 'eval <STDIN>'`) and
  proof/dx-076 (`curl ... | lua -e 'assert(load(io.read("*a")))()'`) go from
  review to deny: inline code that runs as code what it does not write out,
  after a command of the same line that downloads, runs the download. Both
  were already stopped for an agent; nothing else moved.
- 2026-11-19: real/real-018 and real/real-027 deny -> allow. Both are
  labelled benign with `expect: review` in `corpus/real/cases.yml`: a
  review would have been accepted, a deny was a false positive, and the
  reference now holds allow. Both hold a path through a folder named after
  the guard with an expansion after it (`'/home/u/innerwarden/old'/...`,
  `.../out-$i.log`); read down to the last level, the folder was taken for
  the guard's program, and a folder a path goes through names no program.
  Nothing else on either line earns a review, so the line is allowed rather
  than held. real: 4/5 caught, 23/31 false positives (was 25/31); proof and
  attack-2026-11 unchanged.
- 2026-11-19: real/real-006 (`pkill -f "cargo test -p innerwarden-agent-guard
  --release" ; sleep 1; ...`) goes from deny to allow: a `pkill -f` pattern is
  matched against the command lines of the guard's own processes, and this one
  matches none of them (it stops a test run of the crate). Real false positives
  23/31 to 22/31; nothing else moved.
- 2026-11-20: proof/bn-033, proof/bn-128, proof/bn-129, proof/bn-130,
  proof/bn-131, proof/bn-132, proof/bn-133, proof/bn-134,
  attack-2026-11/a11-067, attack-2026-11/a11-086, attack-2026-11/a11-153 and
  attack-2026-11/a11-162 go from allow to review. Since this date a line with
  a part the guard cannot read, where that part may decide what runs, writes,
  deletes, stops or sends, is never allowed (`src/shell/unread_parts.rs`).
  bn-033 hands a script what a download prints; bn-128 to bn-134 `eval` or
  `source` what a completion or init command prints; a11-067 mounts the
  working folder itself (`"$PWD"`) into a container; a11-086 and a11-162
  enter the process `docker inspect` or `podman inspect` prints; a11-153
  sends a header from `$AUTH`, which the line does not set. Each is a benign
  control now held for review, none is refused, and no case moved toward
  allow. proof false positives 0/160 to 8/160; attack-2026-11 0/138 to
  4/138; real unchanged (4/5 caught, 22/31 false positives).
