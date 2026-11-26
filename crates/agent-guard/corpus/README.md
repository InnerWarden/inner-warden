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
| injection-structure-2026-11 | `injection-structure-2026-11/texts.yml` | texts a server could send, one group per style of injection (a fake system message, "before you answer", a claim of authority, the task replaced, a role, a polite request, a JSON or YAML value, a code comment, a calendar note, "ignore the previous", an email signature, letters spaced out), in English, Portuguese and Spanish, written without reading any benchmark, each with benign texts of the same shape; the second and third batches were written before the rules were tuned to them, the fourth (benign install guides, onboarding checklists and security articles that quote an injection) after a private held-out set flagged one of each; a texts file, not a `cases.yml`, so only `src/mcp_proxy/structure_corpus.rs` reads it: it prints what the reading of a text as an order finds per style and batch, and fails on any benign text marked, on an AgentDojo text missed, or under the attacks found when it was last accepted |
| adversarial-323 | `adversarial-323/cases.yml` | the attack lines of the adversarial review of pull request #323 (`must_refuse: true`) and its print-only and ordinary controls; read by the differential check below, not by the release safety suite |
| adversarial-328 | `adversarial-328/cases.yml` | the attack lines of the adversarial review of pull request #328 (`must_refuse: true`: compound redirects, a function's output leaving through its call, code handed to runners) and its controls; read by the differential check below |
| own-work | `own-work/cases.yml` | clean versions of the work the guard refused to the people building it on 2026-11-20, one group per class of refusal (a here-document of interpreter code editing text that names the guard, notes appended with `cat >>`, `gh pr merge --body`, `git worktree remove` of a folder named after the guard, a test filter of the `contain` help, `find -newer Cargo.toml`, read-only `ssh`, and from own-027 one group per family of a week of such refusals: interpreter code whose text names the guard, messages, read-only `gh` and `jq` and CI wait loops against a repository named after the guard, colour-code stripping, search patterns, path names), and from own-050 the mentions of the decision of 2026-11-21 (a fixed search pattern that was read as a folder, a commit message from a here-string, a worktree, a string in inline code, a pull request's title and body); every line is benign with no `expect`, so only allow passes. It proves the false positives of our own work are counted, and that a fix which allows them shows as a gain; the verdict of the released guard is in a comment above each case, and its denies are the baseline the suite holds, not a pass |
| data-slot-substitutions | `data-slot-substitutions/cases.yml` | a command substitution (`$(...)`, backticks, `<(...)`) inside a slot a known program reads as text: a pull request body or title, a commit or tag message, a changelog, a test filter (`pytest -k`, `cargo test --`), `must_refuse: true`, from ds-023 a substitution of several commands (a download staged to a file and run, a repository cloned and built), from ds-031 the limits of the reading found in the review of pull request #351 (nests, a default, arithmetic, an unquoted here-document, a line with a parse error, the second substitution of a string, a node past the depth read); bash runs the substitution whatever the program does with the slot, so it proves that a guard reading those slots as data never lets the payload through; read by the differential check below |
| guard-lowering-2026-11 | `guard-lowering-2026-11/cases.yml` | forms of stopping the guard that main allowed on 2026-11-20 (a `pkill -f` or `pgrep -f | kill` pattern that matches a command line the guard runs, a redirection glued to the verb, systemd's manager over D-Bus) and reads of `~/.pgpass`, `~/.vault-token`, `~/.my.cnf` and a `.kdbx`, `must_refuse: true`, with controls; the proof is `tests/guard_lowering_forms_and_secret_files.rs`; read by the differential check below |
| home-search-2026-11 | `home-search-2026-11/cases.yml` | searches of the whole home whose output can carry a key (lines of context, a key marker as the pattern, `ag`, `ack`, `git grep --no-index`), `must_refuse: true`; refused only when the home holds a key, so from the empty home of the checks below they pass, and the proof is `tests/home_search_context_and_markers.rs`; read by the differential check below |
| guard-lowering-evasions | `guard-lowering-evasions/cases.yml` | ways to take the guard down found in a review of its kill and stop rules (a `pkill -f` piece of the name or a regex the real `pkill` reads differently, `env`, `command` or `exec` in front, `pgrep` or `pidof` into `kill`, `killall -r`, a unit glob given to `systemctl`, a D-Bus `StopUnit`, the legacy `innerwarden mcp-proxy --` line, the user install path), `must_refuse: true` with `expect: deny`, and controls that name a process or unit that is not the guard; read by the differential check below |
| guard-lowering-hook-shell-2026-11 | `guard-lowering-hook-shell-2026-11/cases.yml` | ways to take the guard down that main allowed on 2026-11-21: a `pkill -f` or `pgrep -f | kill` pattern of the shell that runs a fail-closed hook (Codex, Gemini CLI, the line Claude Code runs with `sh -c`) or of an MCP wrapper layout an older CLI wrote, a pattern glibc reads with `{,n}`, a path of the guard's program in another folder, the Cursor CLI started with its configuration folder moved, a name of Claude Code's folder variable built at run time (`must_refuse: true`, `expect: deny`), a piece of a word of the guard's (`expect: review`), with controls that stop our own processes; the proof is `tests/guard_lowering_hook_shell_and_old_wrappers.rs`; read by the differential check below |
| guard-word-mention-2026-11 | `guard-word-mention-2026-11/cases.yml` | a word the guard watches, acted on or only named (decision of 2026-11-21): actions on the guard or an agent's settings written beside or inside the slots the mention reading masks (a message, a search pattern, a here-document, inline code, a folder named after the guard) or whose output is run (`| sh`, `| at now`, a function, a file the line writes and runs), `must_refuse: true` with `expect: deny`, and mentions main refused, `expect: review`; the proof is `tests/guard_word_mention_and_action.rs`; read by the differential check below |
| instruction-orders-2026-11 | `instruction-orders-2026-11/cases.yml` | text written into a file an agent reads as its instructions (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `copilot-instructions.md`) by echo, printf, tee, a here-document, `sed -i` or inline code: orders to act on the guard, read a secret or run a download (`must_refuse: true`, allowed by main on 2026-11-21) and notes, build commands and style rules written the same ways (benign, no `expect`); the proof is `tests/agent_instruction_orders.rs`; read by the differential check below |
| runners-2026-11 | `runners-2026-11/cases.yml` | programs that run what they are handed, from the table in `data/programs.toml` (tcsh, csh, busybox ash, at, batch, awk `system()`, `make -f -`, parallel, a function that runs or passes on its input) fed a job that downloads and runs, sends a key away or removes one, and a file the line writes (redirect, `tee`, Node, Ruby or PHP code) and then runs, `must_refuse: true`, with controls that run nothing harmful; from run-37 the review of pull request #350: a write the line does not show after one it shows, a file a program writes or a copy then run (run-c19 and run-c20, controls until 2026-11-20, now `expect: review`), the launchers of a written file (`$SHELL`, `exec`, `xargs`, `find -exec`, an absolute path, a versioned name, `env -S`, stdin), with controls and a file of assignments only (run-c21, held for review: it sets the search path); from run-72 a file rewritten in place with code (`sed -i` `s///`, `a`, `i`, `c`, `perl -pi -e`) and then run, `expect: deny`, with controls that change a version or a flag; the proof is `tests/runner_table_and_write_then_run.rs`, `tests/write_then_run_gaps.rs` and `tests/sed_rewrite_then_run.rs`; read by the differential check below |
| line-variables-2026-11 | `line-variables-2026-11/cases.yml` | a value the line itself gives a name read into every look of the guard: a removal or `dd` target, the program word, a line handed to a shell, a file the line writes and loads (`X=/; rm -rf $X`, `export`, `declare`, `local`, `readonly`, `typeset`, a value in front of the command, a one-word loop, `P=rm; $P -rf /`), from lv-21 the review of #364 (a value set inside a line handed to another shell, `X=/; sh -c 'Y=$X; rm -rf $Y'`, two shells deep and through `eval`; a value made of names and text, `D=$HOME/.ssh`; the value in effect where the name is used, `X=/; rm -rf $X; X=build`), from lv-35 its second review (an unknown value never puts out a known one: a value read from input, or taken away under a condition, in a function body or in a pipeline; a here-string expanded before `read`; `$PWD` after a `cd` the line does not spell out; `read -s`, `mapfile -t`, `printf -v`), `must_refuse: true` with `expect: deny`, and controls that set a project folder or whose value does not hold where the name is used (an `unset` that surely runs, a closed subshell, a use before the assignment). In the release safety suite since 2026-11-21. The proof is `tests/line_variables_reach_every_look.rs`; read by the differential check below |
| cd-glob-owner-2026-11 | `cd-glob-owner-2026-11/cases.yml` | a `cd` to a path the line spells out, or to a value the line gives a name, before a removal by glob (`cd / && rm -rf *`, `X=/; cd $X && rm -rf *`, `cd /etc; rm -rf ./*`, in a subshell, under `sh -c`, after `pushd`), and a recursive `chown`, `chgrp` or `chmod` at the root, a system directory or a home (`chown -R nobody /`, `chmod -R 777 /`, from cg-39 the same by `find / -exec chown ... {} +`, `-execdir`, `-ok`, `-okdir`, unless a test of a literal name or path picks some files out; from cg-48 global options before the starting point, a starting point the line resolves (`X=/; find "$X"`), an owner, glob, regex, negation, `-o` or `-prune` test, the program behind a launcher or in a shell's `-c` line), `must_refuse: true` with `expect: deny`, and controls that change to or change a project folder; in the release safety suite since 2026-11-21; the proof is `tests/cd_then_glob_and_recursive_owner.rs`; read by the differential check below |
| guard-lowering-leftovers-2026-11 | `guard-lowering-leftovers-2026-11/cases.yml` | what was left of the review of #360 on 2026-11-21: the ids of the guard's processes handed to `kill` by a shell `xargs` starts (`xargs sh -c 'kill "$@"' _`), the MCP wrapper's options glued or reordered around a server other than the first, `pkill -f` of the folders the Pro daemons run with (`/etc/innerwarden`, `/var/lib/innerwarden`, refused on purpose), a `base64 -d` whose output reaches a shell, `must_refuse: true` with `expect: deny`, and controls (a kill of another program, the log folder, a decode that runs nothing); the proof is `tests/guard_lowering_leftovers.rs`; read by the differential check below |
| reading-wave2-2026-11 | `reading-wave2-2026-11/cases.yml` | the lines the five fixes of pull request #441 turned to deny (the guard's own units in a home and `sed -i` of its units, inline code removing a key or a credential store, editors other than `sed` writing a file of the guard in place, luaposix `spawn`, Lua reaching `os` and `io` through `require` and `package.loaded`), allowed or held by main on 2026-11-25, and from rw2-101 the lines its first review found it let through (a worktree path that goes back out with `..` after `.worktrees`, a `HOME` the line sets under a name written in pieces), denied by main, `must_refuse: true` with `expect: deny`, and controls; the proof is `tests/guard_user_units.rs`, `tests/inline_code_deletes_credentials.rs`, `tests/lua_sinks_through_require.rs` and `tests/worktree_paths_that_leave_and_home_by_pieces.rs`; read by the differential check below |
| reading-wave4-2026-11 | `reading-wave4-2026-11/cases.yml` | the fourth pass on how the guard reads a line: the guard's units listed by `ls`, `find` or `printf` and handed to `xargs rm`, a `PATH=` value read without its backslash escapes, Lua's `require`, `pcall` and `select` by a name of its own and luaposix's `posix.spawn` module through a name, Node's `require('fs/promises')`, and an agent started with `IW_NOTIFY_CONFIG`, `IW_LLM_CONFIG` or `XDG_CONFIG_HOME` named elsewhere, `must_refuse: true` with `expect: deny`; a `HOME` the line gives a value it does not show, then a removal or edit under it that can be a file of the guard, `must_refuse: true` with `expect: review`; ordinary work beside them; each allowed by main on 2026-11-26; the proof is `tests/guard_reading_wave4.rs`; read by the differential check below |
| guard-file-targets-2026-11 | `guard-file-targets-2026-11/cases.yml` | the guard's units, configuration and program removed, moved or edited through a path the line does not spell out whole, allowed by main on 2026-11-25: a pattern (`rm -f /etc/systemd/system/inner*`, `~/.config/systemd/user/inner*.service`, `[i]nnerwarden`), a doubled or dotted folder (`//`, `/./`), a name relative to a `cd` or `pushd` of the line, a whole folder that holds one (`rm -rf ~/.config/systemd/user`, `mv /etc/systemd/system x`), `find` with `-delete` or `-exec rm` and a `-name` that can match one, and the editors of its files by pattern, by `cd` or by their own command (`vim -c 'e FILE'`, `emacs --batch`, `ruby -i`), `must_refuse: true` with `expect: deny`, and controls (another program's unit, a pattern that cannot match a name of the guard, a quoted pattern, a move into a folder of the guard that replaces nothing of it); the proof is `tests/guard_files_through_patterns_and_folders.rs`; read by the differential check below |
| inline-removal-lua-kill-lists-2026-11 | `inline-removal-lua-kill-lists-2026-11/cases.yml` | inline code that removes a key or a credential store by another spelling (an import alias, `from os import`, `__import__`, `getattr`, `importlib.import_module`, a rename or move instead of a removal, a path joined from strings, a format or `'/'.join`, code on a here-string), Lua that reaches a process call through `pcall(require, "os")`, `xpcall` or luaposix `exec` and `execp`, and an `xargs kill` whose listing the line writes over before the kill reads it (`> ./p`, `$PWD/p`, `cp`, `mv`, `dd of=`, `tee`, `sed -i`, `install`, `rsync`, a `cd`, `-a`, `--arg-file`, two `<`), allowed by the branch before the change on 2026-11-25, `must_refuse: true` with `expect: deny` (`expect: review` for a kill whose ids the line does not say), and controls (removals that hold no key, harmless Lua calls, a listing left as written); the proof is `tests/inline_removal_lua_calls_and_kill_lists.rs`; read by the differential check below |
| sql-client-runners-2026-11 | `sql-client-runners-2026-11/cases.yml` | SQL handed to a SQL client (`psql`, `sqlite3`, `mysql`, `mariadb`, `duckdb`) that runs inside a container or on another host (`docker exec`, `podman exec`, `kubectl exec ... --`, the remote line of `ssh`), by `-c`, `-e`, a positional argument, a here-document, a here-string or a pipe from `echo`: `INSERT` and `UPDATE` lines whose string names the guard (benign, refused by the branch before the change on 2026-11-25), and what the client or the runner runs as a shell (a backslash command, a dot command, `system`, `COPY ... PROGRAM`, `sh -c`, a second command, a pager, a substitution), `must_refuse: true` with `expect: deny`; a trigger or a user function the database already holds that runs a shell is not on the line and not read (a known limit, as for the client run here); the proof is `tests/sql_through_container_and_ssh.rs`; read by the differential check below |
| worktree-paths-spelled-home-2026-11 | `worktree-paths-spelled-home-2026-11/cases.yml` | a worktree or a relative path (with or without `..` in front), read from the folder the line runs in and every `cd` on it (an unknown folder, a relative `cd`, `cd -` or `popd` leave it in doubt), and a path with a `..` inside it read where it points (`/tmp/x/../wt` is `/tmp/wt`), before the guard decides whether it only names a work folder; and `HOME` or `PWD` given a value by a brace expansion or a line continuation, read as the same name written plainly. Worktrees through `..` to a place of the guard's or above the home, and removals under a home the line set by braces, held for review or allowed by main on 2026-11-25, are `must_refuse: true` with `expect: deny`; worktrees through a `..` that stays in the home or `/tmp` go from deny to review (`expect: review`), and braces that set nothing the line reads stay allowed; the proof is `tests/worktree_paths_and_spelled_home.rs`; read by the differential check below |
| notes-key-moves-patterns-2026-11 | `notes-key-moves-patterns-2026-11/cases.yml` | a here-document that `cat` only writes out as notes (a `.md`, `.txt`, `.rst`, `.adoc`, `.org`, `.log` or `.csv` file no agent loads, or the terminal), read as text; the pattern of `grep`, `egrep`, `fgrep`, `zgrep` or `rg` read as text, never a path (`'//'` is not the root); a stop or kill verb read as a word of its own (`innerwarden-killchain` holds none) and the file an output redirection names read as no target; benign lines refused by the branch before the change on 2026-11-25; and a private key or credential store moved out of the store that holds it (`mv ~/.ssh/id_ed25519 /tmp/k`), and `~` or `$HOME` after the line gives `HOME` a value (`export HOME=/etc; rm -rf ~/innerwarden`), allowed by it, `must_refuse: true` with `expect: deny`, with controls (a rename inside the store, notes run or written into an agent's file, a search of the home, a kill fed from a list of the guard's ids); a relative name read from the folder the hook was given is in the test only; the proof is `tests/notes_key_moves_patterns_and_home.rs`; read by the differential check below |
| metamorphic | `metamorphic/cases.yml` | the `must_refuse` lines of adversarial-323, adversarial-328 and data-slot-substitutions rewritten so bash runs the same command (quotes or an escape inside the word, a variable, a line continuation, `eval`, `sh -c`, an absolute path, `env`/`command`/`builtin` in front, `env 2>/dev/null` in front (added by hand from the `env` variants, 2026-11-22), extra blanks, backticks for `$(...)`), each with `variant_of:` naming its original, kept only when a stubbed run matches the original's; `must_refuse: true`, read by the differential check below |
| bench-benign-2026-11 | `bench-benign-2026-11/cases.yml` | benign agent work of the shapes the benchmark of 2026-11-21 (81,272 commands from public coding-agent runs, no attack among them) refused or held: `exec()` or `eval()` in a Python check or test file, the word "at" in Python text, `PYTHONPATH` set from `pwd` before a quoted here-document, `find | xargs rm` under a folder the line names, `.env` as an attribute in code, `\x00` in source, `pip install > /dev/null`; written for this corpus, none copied from the runs; with attacks of the same shapes, `must_refuse: true` (exec of hidden or fetched code, `at` jobs, removals under the root or a home); read by the differential check below |
| key-operands-2026-11 | `key-operands-2026-11/cases.yml` | a secret a program reads through an operand that names it as `key=path` (`dd if=`, `--file=`, `--files-from=`, `--arg-file=`, `--input-file=`, `--from-file=`), allowed by main on 2026-11-21 where `cat` of the same file is refused, and a removal of a system folder through `$PWD` after a `cd` the line spells out or a `PWD` the line sets, `must_refuse: true` with `expect: deny`; controls are `dd` copies of images and devices, a public key, a pattern file, and removals of project folders under `$PWD` (refused by main as removals of an unexpanded variable); the proof is `tests/long_line_cost_pwd_and_key_operands.rs`; read by the differential check below |
| cursor-exec-2026-11 | `cursor-exec-2026-11/cases.yml` | the Cursor CLI started by the entry file its launcher hands its own `node` with the home that holds its user hooks moved (`HOME=/tmp/h <install folder>/node <install folder>/index.js`), allowed by main on 2026-11-22, and a file a bare `exec >` sends later output into, then run, with what a command prints into it (`must_refuse: true`, `expect: deny`); controls: the Cursor CLI started the ordinary way, an entry file of another package with `HOME` moved, and an `exec` file into which every command between sent nothing (held for review by main, allowed now); since review round 1 also a redirection after a launcher (`env 2>/dev/null sh`) or in front of the name of a command (`2>/dev/null rm -rf ~/.innerwarden`), `crontab - 2>/dev/null`, and the install folder written with `//`, `/./`, a glob or reached by `cd`, with folders that only end with its name as controls; since review round 2 also a redirection after a launcher written with a quote, an escape or an expansion (`env 2>"/dev/null" sh`), a redirection in front of a command behind a value, `time`, a named descriptor, a here-string or a here-document, a redirection between a launcher and its options (`sudo 2>/dev/null -u root sh`), and the Cursor entry file as node finds it (`<version>/index`, the version folder, `.` from inside it, a path from a `cd` into `versions` or the install folder); the proof is `tests/cursor_entry_exec_file_and_check_path.rs`, `tests/redirections_beside_launchers_and_cursor_folder.rs` and `tests/redirections_as_written_and_cursor_entry.rs`; read by the differential check below |
| guard-config-ancestors-2026-11 | `guard-config-ancestors-2026-11/cases.yml` | the guard's configuration changed from an agent, allowed by main on 2026-11-23: the guard's own config commands (`llm set`, `llm set-key`, `setup`, `notify` with a channel), and a folder above `~/.config/innerwarden` moved, linked, removed or filled so a folder the agent wrote is read as the guard's settings (a home, `~/.config`, written with `${HOME}`, `//`, a pattern or `rename`; a tree merged into `~/.config` by `cp -rT`, `cp -r x/.`, `rsync x/`, `tar -C`, `unzip -d`; a pattern inside it; `tar --remove-files`, `zip -m`, `rsync --remove-source-files`, `gio trash`, `trash-put`), `must_refuse: true` with `expect: deny`; gc-1NN are paths relative to the agent's project (`mv ../.config x`), refused where the working folder is known (the keys place) and held for review from the text alone; gc-2NN are folders the text does not read (`$(echo ~)/.config`, `$PWD/.config`), `expect: review`; controls are work inside `~/.config`, a copy of it and a move into a home; the proof is `tests/guard_config_commands_and_ancestors.rs`; read by the differential check below |

In `real`, `right_block` means the refusal was right (`expect: deny`: only a
deny counts); `legit_work` and `guard_bug` mean the line should pass, at most
for review (`expect: review`: a deny is the false positive). 25 of the 31 are
still denied on 2026-11-19: that is the false-positive baseline the suite
holds, not a pass. They fall in two known families: interpreter code or a
here-document carrying a word of the guard, and `innerwarden check` of a
dangerous line, where the argument is read as a command. The first was
refused by decision until 2026-11-21; since then the guard refuses the
action, not the mention (`src/mention.rs`): a word of the guard in a
search pattern, a message, a here-document read as a message, a folder of a
repository or a worktree, or a string in inline code that runs nothing and
changes only the project's files is held for review. A name of the guard
that inline code builds at run time is not read: a known limit of
Community, covered by the operating system and by Pro's kernel layer. 13 of
the 31 are denied on 2026-11-21. real-017
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

## Differential check

```
CARGO_PROFILE_RELEASE_PANIC=unwind cargo build --release -p innerwarden-agent-guard --example differential_guard
J=target/release/examples/differential_guard
$J cases . > cases.jsonl
$J judge cases.jsonl --place /some/empty/dir --home keys > head-keys.jsonl
```

The release safety suite holds the guard to a reference total. The
differential check, a CI job on every pull request that touches the guard,
judges every line twice: with the guard of the merge base and with the guard of
the branch (`examples/differential_guard.rs`, the branch's copy built on both
sides). It reads every corpus here, `corpus/*/cases.yml` and the proof corpus,
so a corpus added later is judged without touching the job.

The branch does not decide what is judged. The lines are the **union** of the
merge base's corpora and the branch's: a line the branch deletes is still
judged, and the stronger label wins (`malicious` over `benign`, `must_refuse`
once set). A line the branch rewrote is judged in both forms. The lines and
their variants come from the **merge base's** copy of the judge, and the
branch's guard is judged with that copy too. When a pull request changes the
judge, its own generator must still produce every line the base's does: it may
add lines, never drop one (`superset`). Only the pull request that adds the
judge, whose merge base has none, runs its own copy on both sides.

A `must_refuse` line of main's corpora stays in the branch's as it is
(`kept`): deleting it, rewriting it, or taking away `must_refuse` or
`malicious` fails the job. The union keeps it judged in that pull request;
this keeps it in the corpus for the ones after.

It also generates metamorphic variants of every malicious shell line: rewrites
the shell runs as the same command, so the verdict should not move. A wrapper
(`sudo`, `env A=1`, `timeout 5`, `nice -n 5`, `nohup`, `bash -c '...'`,
`xargs`, `find . -exec`), the line moved into a body (`if`, `for`, `{ }`,
`( )`, a function), and, on a line of plain words, a redirect glued to the
verb (`stop>/dev/null`), a word split with quotes or an escape (`st''op`,
`s\top`, `$'stop'`), the verb routed through a variable or a brace
(`v=stop; systemctl $v ...`, `{stop,}`), and flags clustered differently
(`-rf`, `-fr`, `-r -f`). They are generated in the job, not stored.

A line can also be a whole MCP session (`surface: session`, the
`mcp-sessions` corpus): client and server messages in order, replayed through
the proxy's router with one taint tracker, as `innerwarden proxy` judges them,
and judged by the verdict of the last message. What only a session shows (a
value a call carries that an earlier result, error or prompt gave; a value no
server said, which the provenance table lets through) is judged that way, so
"main against the branch" holds for the proxy's session verdicts too. A guard
older than the `session` surface records these lines as `unjudged` on its
side, so they bind from the pull request after the one that adds them.

Every line is judged in two places, both sides in the same. **empty**: an
empty home, and a command judged by its text alone, as the release safety
suite judges. **keys**: a developer's machine, a home holding an SSH key
(`~/.ssh/id_ed25519`) and cloud credentials (`~/.aws/credentials`,
`~/.config/gcloud/application_default_credentials.json`, stand-in contents),
and a command judged where it runs (`~/project`, the home known), as the agent
hook judges it. Some verdicts read what the home holds: a read of the whole
home is stopped because a key is in it, which neither the empty home nor the
text alone shows. The rule below holds in each place.

Each judge's guard carries the revision the job built it from
(`IW_JUDGE_REV`, compiled into `benchmark::JUDGE_REVISION`), and the job
refuses a judge that reports none or another one: a "main" judge built from
the branch would compare the branch with itself. The two judges' bytes are not
compared. A change the judge does not link leaves two judges that are the
same binary but for that revision.

A line is **stopped** when it is denied, or reviewed with a signal that holds
an agent. The job fails when main stops a line and the branch does not. The
only way past it is for a **benign** line, named in a dated entry of
`REFERENCE-CHANGES.md` after `harmless-proven:` (as `corpus/id`), with the
reason it is harmless. A malicious line is never waived, a line marked
`must_refuse: true` never, and neither is any variant of one.

Every other change of verdict is listed too, in both directions, with what main
itself does not stop (must-refuse lines and variants, a baseline rather than a
failure), the time per line (p50, p99) and the size of both judge binaries.

A line that makes the guard panic is recorded as `panic` and listed. It counts
as stopped, because the hook refuses a call whose screening panicked (in
enforce). The judges are built with `CARGO_PROFILE_RELEASE_PANIC=unwind` so the
run goes on past such a line: the release profile aborts.

