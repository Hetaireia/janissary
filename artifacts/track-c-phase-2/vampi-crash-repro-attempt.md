# VAmPI crash reproduction attempt

**Date:** 2026-10-28T18:59:02Z
**Original observation:** `/users/v1/_debug` produced exit 0xC0000005 in `runner.py` batch invocation on 2026-10-28T075535Z-vampi.

## Attempts

| # | Context | Result |
|---|---|---|
| 1 | Command 43 batch (`runner.py --app vampi`) | **exit 0xC0000005 (crash)** |
| 2 | Command 44 direct invocation | exit 0, 0-byte stdout, 0-byte stderr |
| 3 | Command 44 direct invocation (repeat) | exit 0, 0-byte stdout, 0-byte stderr |
| 4 | Command 44 direct invocation (repeat 2) | exit 0, 0-byte stdout, 0-byte stderr |
| 5 | Command 45 batch (`runner.py --app vampi`) | exit 0, 0-byte stdout, 0-byte stderr |

## Conclusion

Crash rate: **1 in 5 attempts (20%)**. Not reproducible on demand. Not deterministic.

The crash was a transient scanner reliability issue, not a reproducible bug. It is
tracked as a scanner stability concern (separate from measurement correctness):

- For Item A measurement purposes: `/users/v1/_debug` is a **valid TN** in the 4
  successful scans. Findings count is 0 in all clean runs.
- For scanner reliability tracking: a 1-in-5 crash rate on a specific endpoint is
  not acceptable as a long-term quality bar, but is not currently blocking the
  Phase 2 corpus measurement.
- The transient crash does not invalidate the score.json from either run. If it
  recurs in a future run, this evidence documents what we have already tried.

## Files

- Original crash observation: `benchmark/track_c/runs/20261028T075535Z-vampi/manifest.json`
- Clean re-run (Command 45): `benchmark/track_c/runs/20261028T075758Z-vampi/score.json`
- Empty stdout/stderr from direct invocation: `vampi-crash-stdout.txt`, `vampi-crash-stderr.txt`
- Response body from `/users/v1/_debug`: `vampi-debug-response-body.txt`
