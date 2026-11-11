#!/usr/bin/env bash
# Cargo's target runner for the mutation sweeps: run a test binary with its
# address space capped, so a mutant that allocates without end fails its own
# test run instead of taking the machine down.
#
# usage: set CARGO_TARGET_<HOST TRIPLE>_RUNNER to this script (the workflow
#        does it); cargo then calls `mutants-test-runner.sh <binary> <args>...`.
#
# Why: on 2026-11-09 (run 42585938875) thirteen of the forty shards of the
# weekly sweep died with "The runner has received a shutdown signal" and left
# no report, a third of the sweep. Measured on a 4-core box the same day: the
# mutant `index += 1` to `index -= 1` in output_redirect_targets (threats.rs)
# steps the loop back onto the word it has just pushed, forever, and the test
# process grew until the kernel killed it at the 6 GiB a probe allowed it. On a
# runner with no cap that growth takes the whole machine, long before the
# per-mutant timeout fires.
#
# With the cap, the allocation that crosses it fails, the Rust runtime aborts
# the test binary, `cargo test` fails, and cargo-mutants counts the mutant as
# caught, which it is: no run of the tests passes with it. Measured: that
# mutant aborts in 16 seconds ("memory allocation of 9 bytes failed") and is
# reported caught, and the unmutated suite passes under the cap.
#
# Why not a cgroup (`systemd-run --scope -p MemoryMax=...`): when the kernel
# kills a process for memory inside a scope, systemd stops the whole scope by
# default, cargo-mutants with it, and the shard still ends with no report. That
# is what the probe above did. Only test binaries run through a target runner,
# so rustc, cargo and cargo-mutants are not capped, and an address-space cap
# does not count the page cache the builds fill.
#
# MUTANTS_TEST_MEMORY_KIB  the cap in KiB. Default 4 GiB.
# MUTANTS_TEST_RUNNER_LOG  when set, one line is appended per run, so the
#                          workflow can prove the cap was applied at all.
set -euo pipefail

cap=${MUTANTS_TEST_MEMORY_KIB:-4194304}
ulimit -v "$cap"
if [ -n "${MUTANTS_TEST_RUNNER_LOG:-}" ]; then
  echo "$(ulimit -v) KiB ${1##*/}" >> "$MUTANTS_TEST_RUNNER_LOG"
fi
exec "$@"
