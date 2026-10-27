# Phase 1 - Status

**Docker daemon:** READY
**Effect:** Baseline scans cannot run until Docker daemon is up and target container is available.

## Ready

- Scanner: `janissary 7.5.0` (editable install; `src/` identical between 7.5.0 tag and HEAD - no reinstall required).
- Harness: `benchmark/track_a/runner.py` invocable; `--help` exits 0.
- Scorer: `score_dast_aware.py` reproduces P=1.000 / R=0.854 / F1=0.921 on `r1+rec`.
- Invocation configs: `tools_default.env`, `tools_tuned.env` under `artifacts/7.5.0-baseline/invocations/`.
- Run script: `run-baseline.ps1`.

## Critical finding (logged in Amendment 23)

Every existing run on disk carries `tool_version: 7.3.0`, not 7.5.0:

- `20261024T130735Z-janissary-r1` - tool=7.3.0 harness=1b4cf6cd exit=1
- `20261024T130735Z-janissary-r1+rec` - tool=7.3.0 harness=1b4cf6cd exit=1
- `20261025T013503Z-janissary-r2+rec` - tool=7.3.0 harness=1b4cf6cd exit=1
- `20261025T020331Z-janissary-r2` - tool=7.3.0 harness=e4658115 exit=1
- `20261025T062837Z-janissary-r3` - tool=7.3.0 harness=e4658115 exit=1

The README's Precision 1.000 for 7.5.0 is inherited from 7.3.0 via the non-scoring-path claim for 7.4/7.5. It is not empirically measured on 7.5.0. Amendment 23 exists to close that gap.

## Preconditions to unblock

1. Docker Desktop starts (currently stopped, daemon will not respond).
2. Benchmark source cloned at `C:\Users\M5 E60\janissary-project\owasp-benchmark` at SHA `20cbf3d11123347e47ed89541e6942836def53f7` (currently missing).
3. Image `janissary/owasp-benchmark:20cbf3d` built locally.
4. Container up on port 8080; `curl http://127.0.0.1:8080/benchmark/` returns 200.

## When unblocked

Window 1 (target):

    cd benchmark\track_a
    .\build_and_run.ps1

Window 2 (scanner):

    .\artifacts\7.5.0-baseline\invocations\run-baseline.ps1 -RunNumber 1 -Arm default
    .\artifacts\7.5.0-baseline\invocations\run-baseline.ps1 -RunNumber 2 -Arm default
    .\artifacts\7.5.0-baseline\invocations\run-baseline.ps1 -RunNumber 3 -Arm default

## Out of scope

- Benchmark source modifications.
- Harness modifications.
- `benchmark/track_c/` (untracked, user's parallel Item 1 work).
- `README.new.md` (untracked, unrelated draft).
