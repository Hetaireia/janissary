# ADR-026 -- crAPI tri-session validation (M43.5)

**Status:** Accepted (2026-11-05). Phase 2 close-out.
**Supersedes:** None.
**Completes:** FUTURE-STATE-PLAN.md L157 (deferred by ADR-025 D2).
**Extends:** ADR-023 (tri-session rotation), ADR-025 (crAPI validation), SCHEMA.md v2.1.

## Context

Plan L157 says `[ ] Tri-session auth works against crAPI end-to-end`.
ADR-025 D2 deferred this to M43.5 because M43 was scoped to crAPI
single-session validation. M43 shipped (F1=1.0, both runs preserved as
`20261030T110245Z-crapi` and `20261105T055315Z-crapi`). M43.5 is the
remaining piece: prove M41's rotation works against a real target.

Probe 2026-11-05 (post-M43) found:

1. **`runner.py` (268 lines) runs one subprocess per trial** via
   `subprocess.run(["janissary", "scan", ...])`. Identity is threaded via
   `--bearer <jwt>` derived from `session._jns_bearer` (a custom attribute
   set by `login()`, not a header).

2. **`login(cfg)` returns one `requests.Session`.** Reads `cfg["login"]`.
   JWT captured from a JSON field (`capture_jwt_from_json`). Single
   identity by construction — one login, one session, one JWT.

3. **The scanner already accepts `--sessions PATH`** (M41, ADR-023 D4).
   When the subprocess is invoked with `--sessions <file>`, the scanner
   internally rotates on 401. The runner does not need rotation logic.

4. **`scan_case(cfg, session, case, out_dir, idx)` builds a subprocess
   command** from cfg + session. Adding `--sessions <path>` to that
   command is a 3-line change.

5. **`score.py` treats `aborts: 0` as success.** The current per-trial
   record already has `aborted: bool`. A trial with `aborted: true`
   counted as a failure. Scanner's 401-abort (ADR-010) sets exit code 2
   and marks `aborted: true`. `aborts: 0` in `score.json` therefore
   proves: no trial hit an unrecoverable 401 abort.

6. **`login_alt` does not exist** anywhere in `apps.json`, `cases.csv`,
   `runner.py`, or `score.py`. No prior multi-identity pattern.

The original ADR-025 D2 estimate ("~2-day milestone") assumed runner
would need multi-identity loop logic. The probe shows this is unnecessary
— the scanner already handles rotation; the runner just needs to pass
through one flag.

## Decisions

### D1. Runner gains `--sessions-file PATH` flag

```python
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True)
    ap.add_argument("--sessions-file", default=None,
                    help="Path to sessions JSON for scanner tri-session rotation")
    args = ap.parse_args()
    ...
```

When non-None, `scan_case` appends `["--sessions", args.sessions_file]`
to the subprocess command. When None (default), current behavior is
byte-for-byte preserved.

### D2. Runner propagates sessions_file through scan_case

```python
def scan_case(cfg, session, case, out_dir, idx, sessions_file=None):
    ...
    if sessions_file:
        cmd += ["--sessions", sessions_file]
    ...
```

Default `None` preserves the single-identity path used by M43 and all
prior runs. No behavioral change to existing invocations.

### D3. `apps.json["crapi"].login_alt` documents the second identity

Mirror of `login` with different email/name/phone. Not consumed by
`runner.py` (which receives `--sessions-file` as an external path).
Documented so operators know what second identity to create when
producing the sessions file:

```json
"login_alt": {
  "url": "/identity/api/auth/login",
  "capture_jwt_from_json": "token",
  "pre_register": {
    "url": "/identity/api/auth/signup",
    "json": {
      "name": "JNS TrackC Alt",
      "email": "jns-trackc-alt@example.com",
      "number": "+15550003333",
      "password": "JnsTrackcAlt!456"
    }
  },
  "data": {
    "email": "jns-trackc-alt@example.com",
    "password": "JnsTrackcAlt!456"
  }
}
```

Not added to `apps/crapi/README.md` in M43.5-1 — added in M43.5-2 as
part of the validation setup documentation.

### D4. Sessions file format = SCHEMA.md v2.1 / M41 format

```json
[
  {"cookie": null, "bearer": "<jwt_primary>"},
  {"cookie": null, "bearer": "<jwt_alt>"}
]
```

Matches `SessionSpec` shape consumed by `auth.load_sessions_file()`
(M41). No new format.

### D5. Validation is a manual sessions file, not auto-generation

Alternative considered and rejected: runner auto-builds sessions file
from `login` + `login_alt` at scan time. Rejected because:

- Session file lifecycle (create, use, cleanup) is a test-harness
  concern, not a runner concern
- The two validation runs need *different* sessions files (both-valid,
  invalid-then-valid), so auto-generation can only satisfy one
- Manual file makes the "what is being tested" explicit — the sessions
  file *is* the test configuration

Validation workflow (documented in apps/crapi/README):

1. Start crAPI (10 containers)
2. Login as `login.data.email` → capture `jwt_a`
3. Login as `login_alt.data.email` → capture `jwt_b`
4. Write `sessions-both-valid.json` = `[{bearer: jwt_a}, {bearer: jwt_b}]`
5. Write `sessions-rotation.json` = `[{bearer: "<invalid>"}, {bearer: jwt_b}]`
6. Run `runner --app crapi --sessions-file sessions-both-valid.json`
7. Run `runner --app crapi --sessions-file sessions-rotation.json`
8. Both must produce `aborts: 0` and F1=1.0

### D6. Two validation runs required

**Run 1 — both valid**: sessions file has `[valid_A, valid_B]`. Scanner
uses A for all trials (rotation never fires because no 401s). Proves:
scanner accepts multi-session config without breaking the scan. Baseline
score must match single-identity run (TP=2/FP=0/FN=0/TN=3).

**Run 2 — invalid primary, valid secondary**: sessions file has
`[<invalid_jwt>, valid_B]`. Scanner tries A, gets 401, rotates to B,
succeeds. Proves: rotation fires on 401 and recovers. `aborts: 0` in
`exit_codes.json` is the proof — if rotation failed, the trial would
abort (per ADR-010). Score must also match baseline (B has same access
as A for all 5 trials).

### D7. `exit_codes.json` gains `sessions_used` field

When `sessions_file` is set, each trial record gains
`sessions_used: N` (N = count of sessions in the file). Single-identity
runs leave the field absent (backward compat).

Not strictly required — `aborts: 0` is the actual proof. But it makes
the evidence trail visible in the run directory: a reviewer reading
`exit_codes.json` sees "this trial used N sessions" and knows rotation
was configured.

### D8. `score.py` unchanged

No new outcome types. No new metrics. `aborts: 0` + matching F1 is the
complete validation. `per_case` shape unchanged.

### D9. `apps/crapi/README.md` gains "Tri-session validation" section

Documents the workflow (D5) + shows example sessions files + names the
two validation runs (both-valid + rotation) and their expected score.

### D10. Plan L157 flips to `[x]` after both validation runs pass

Change `[ ] Tri-session auth works against crAPI end-to-end (deferred
to M43.5...)` to `[x] ... (validated 2026-11-05: 2 runs, aborts=0,
F1=1.0; see ADR-026)`. The M43.5 row in the plan table also flips from
`| — |` pending to delivered.

### D11. `apps.json["crapi"]` minimal change

Add `login_alt` block only. No change to `login`, `verify_url`,
`image_digests`, `safe_endpoints`, `known_vulnerable`, `trial_class`.
Existing M43 config preserved byte-for-byte.

### D12. ~5 new tests, all in `tests/integration/test_track_c_runner.py`

- `test_runner_no_sessions_file_preserves_single_identity` — regression
- `test_runner_sessions_file_forwarded_to_subprocess` — checks argv
- `test_runner_sessions_file_adds_sessions_used_to_exit_record`
- `test_scanner_accepts_sessions_file_from_runner` — end-to-end stub
- `test_runner_sessions_file_missing_errors_cleanly`

No new unit tests for `score.py` (unchanged). No new tests for
`login_alt` (JSON-only addition).

## Consequences

**Positive:**
- M43.5 lands as ~40 lines of code (vs ADR-025 D2's ~2-day estimate)
- M43 evidence trail preserved (single-identity baseline still valid)
- Runner gains a clean flag that generalizes to any app with a sessions
  file (dvwa, juice-shop, vampi all benefit from the same mechanism)
- Two-run validation (both-valid + invalid-primary) proves both "config
  accepted" and "rotation fires"

**Negative:**
- Sessions file lifecycle is manual (create, run, cleanup). Documented
  in apps/crapi/README; not automated. Reasonable for a benchmark
  harness that explicitly values reproducibility over convenience.
- Two validation runs per M43.5 delivery. Doubles the "minutes of
  crAPI running" but each run is ~30s (5 trials × ~3s each + stack wait).

**Neutral:**
- `login_alt` is documented but not code-consumed; future features
  (auto-session-building, multi-identity reporting) can use it.
- `sessions_used` is diagnostic only; scoring ignores it.
- M43.5 delivery = one code commit + one docs commit + two run dirs.

## Alternatives rejected

**A: Auto-generate sessions file inside runner.** Rejected (D5).
Lifecycle is harness concern; different validation runs need different
files.

**B: Add `--dual-identity` flag that loops trials twice.** Rejected.
The scanner already handles rotation internally with `--sessions`.
Runner-side looping would double the request count without proving
anything the scanner test doesn't prove.

**C: Force rotation via `--force-rotation` flag.** Rejected (D6).
The invalid-primary sessions file is a cleaner primitive: user controls
exactly what "invalid" means, and the test reads naturally from the
sessions file.

**D: Extend `score.py` with per-identity outcomes.** Rejected (D8).
If both identities can access the same trials, score is identical.
If they can't, that's an app-level finding, not a scanner scoring
concern. Keep score.py focused on TP/FP/FN/TN.

**E: Skip the both-valid run.** Rejected. Proves the multi-session
config is accepted without errors even when rotation never fires.
Without this, a rotation-only test could pass while the non-rotation
path silently broke.

## References

- `docs/FUTURE-STATE-PLAN.md` L157 (target of this ADR)
- `docs/decisions/ADR-023-tri-session-auth.md` (M41, mechanism)
- `docs/decisions/ADR-025-crapi-end-to-end-validation.md` (M43, deferral)
- `docs/decisions/ADR-010-mid-scan-auth-expiry.md` (abort-on-401 contract)
- `benchmark/track_c/SCHEMA.md` v2.1 (trial model, session semantics)
- `benchmark/track_c/runner.py` — `login()` (L61), `scan_case()` (L168),
  `main()` (L232)
- `benchmark/track_c/apps.json` — crAPI block (add `login_alt`)
- `src/janissary/auth.py` — `load_sessions_file()` (M41)
- `src/janissary/cli.py` — `--sessions` flag (M41)
- `tests/integration/test_scanner_tri_session.py` (M41 unit proof)
- Prior crAPI runs: `20261030T110245Z-crapi`, `20261105T055315Z-crapi`
