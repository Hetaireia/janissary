# ADR-010 — Mid-scan auth expiry detection

**Status:** Accepted (2026-10-27). Session 0.3.9.
**Supersedes:** None.
**Blocks:** Nothing. Unblocks enterprise parity on authenticated scans.

## Context

`src/janissary/auth.py` (static-v1, shipped 0.3.x) supports `--cookie` and
`--bearer`. Its docstring names the limitation:

    "No refresh hooks; a token that expires mid-scan will produce a run of
    401s and that's a documented limitation."

That "documented limitation" is a **silent false-negative class**. If the
token expires after preflight succeeds, the payload loop continues to issue
requests, receives 401 responses, evaluates login-page or error-JSON bodies
against injection signatures, and correctly concludes "not vulnerable" —
because there is nothing to match. The scan continues to completion and
reports a clean result. The user is told the target is clean when the
scanner was locked out.

Recon for session 0.3.9 established:

1. **Session propagation works.** `Scanner.__init__` line 240:
   `self.session = session or requests.Session()`. Every `_request` branch
   routes through `self.session.get/post(...)` (lines 288, 296, 314, 315,
   326, 327, 338, 346). `cmd_scan` (cli.py:224-240) builds the auth session
   with `apply_to_session(auth_session, auth_cfg)` and passes it as
   `session=auth_session`. Auth headers reach every payload request.

2. **Zero 401 handling exists in `src/janissary/engine/`.** A `git grep`
   for `401|403|status_code` in `engine/**/*.py` returns nothing. The
   payload loop (scanner.py:513-518) catches `RequestException` and checks
   `r is None`, then proceeds to `ResponseSnapshot.from_response(r)` with
   no status inspection. A 401 is consumed identically to a 200 with an
   empty body.

3. **The abort infrastructure already exists.** Preflight failure
   (scanner.py:454-457) sets `summary.aborted = True`,
   `summary.abort_reason = reason`, returns the summary. `cmd_scan`
   (cli.py:253-254) emits the reason; (cli.py:281-282) returns exit code 2.
   The 401 detector reuses this exact contract.

Enterprise DAST tools (Acunetix, Burp Enterprise, Invicti) all detect
session loss and either abort or re-authenticate. JANISSARY shipping without
it is the same enterprise-parity class that ADR-009 closed for SARIF.

The label "401 abort — Phase 1.1 -> 1.2, open" carried in known-issues for
several sessions is stale: no abort exists, no code aborts, no `Phase 1.1`
or `Phase 1.2` references exist in the tree. The real concern is the silent
false-negative class this ADR addresses.

## Decisions

### D1. Session propagation is correct; documented, not changed

Recon (Context §1) confirms the auth session reaches every payload request.
No code change. This decision exists so future readers do not re-investigate.

### D2. New `Scanner.__init__` kwarg `auth_configured: bool = False`

Explicit opt-in, not header inspection. Rationale:

- **Header inspection is fragile.** A session may carry `Cookie` for reasons
  unrelated to scan auth (site cookies harvested during fingerprinting). A
  `Cookie` header does not imply "the user authenticated."
- **`session is not None` is misleading.** `__init__` line 240 always creates
  a `requests.Session()` when `session` is None. Every scan has a session.
- **Explicit parameter is testable and unambiguous.**

`cmd_scan` (cli.py:230-242) passes `auth_configured=not auth_cfg.is_empty`.
Every existing test that constructs `Scanner(...)` without the kwarg gets
`auth_configured=False` — current behaviour preserved byte-for-byte.

### D3. Consecutive-401 counter, threshold = 2

`self._consecutive_401s: int = 0` initialized in `__init__`. In the payload
loop after `if r is None: continue`:

    if r.status_code == 401:
        self._consecutive_401s += 1
    else:
        self._consecutive_401s = 0

Fire when `self._consecutive_401s >= 2` AND `self.auth_configured`.

**Threshold rationale:**

- **1 is too aggressive.** CDN rate limiting, session rotation races between
  concurrent requests, and target-side flakiness can produce isolated 401s
  on a healthy authenticated scan. Aborting on a single transient 401
  produces false abort reports.
- **2 is the signal.** Two consecutive 401s after the last non-401 response
  mean the auth state is definitively gone. Reset-on-success makes the
  counter fire only on a run.
- **3 wastes a request.** After the second 401, we know auth is gone.
  Additional requests only evaluate login-page bodies against injection
  signatures and produce no findings.

### D4. Abort, do not annotate

On fire: `summary.aborted = True`,
`summary.abort_reason = f"auth expired: {n} consecutive HTTP 401 responses (param={param}, last payload={name})"`,
break the payload loop, break the param loop, fall through to the existing
post-loop code (grouping at scanner.py:930-934, WAF attach at 937-938, pacer
stats at 939-940).

**Partial findings are preserved.** A scan that found 3 SQLi and then lost
auth should report those 3 SQLi with `aborted=True` and exit code 2, not
throw away the evidence. The existing `cmd_scan` path already handles this:
`_emit_abort_reason(summary.abort_reason)` prints a clear warning,
`return 2` signals the user that coverage was incomplete.

Annotation (attaching a warning to each finding) was considered and rejected:
it produces findings that look complete and hides the incomplete-coverage
signal inside each row. The exit code is the right surface for "this scan
did not complete."

### D5. Payload loop only; baseline 401s tolerated

`collect_baseline` makes `baseline_count` requests (default 10) before the
payload loop begins. If auth expires during baseline collection, those
requests 401 and the counter would not fire until the payload loop. Worst
case: 10 baseline 401s + 2 payload 401s = 12 requests before abort.

Acceptable because:

- The 12-request cost is bounded and small relative to a full scan.
- Fixing it requires either a `Baseline.auth_expired` field (broader change)
  or a restructure of `collect_baseline` to return a summary — both outside
  this ADR's scope.
- A future amendment can extend the counter to baseline collection; the
  threshold and behaviour contract this ADR establishes are unchanged.

Documented limitation.

### D6. Agent path deferred

`git grep Scanner(` shows exactly one construction site: `cli.py:230`.
`cmd_agent` uses `janissary.agent.Agent`, which has its own request loop.
Applying the same detector there is a separate ADR. This ADR is scoped to
the direct-scan path.

### D7. Benchmark neutrality by construction

The benchmark harness (`benchmark/track_a/`) passes no `--cookie` or
`--bearer`. `auth_cfg.is_empty` is True, `auth_configured=False`, the
threshold never fires. F1=0.921 unchanged. No scoring-path file is touched.

### D8. Exit code: unchanged

`cmd_scan` (cli.py:281-282) already returns 2 when `summary.aborted` is True.
The 401 abort path reuses this. No CLI surface change. The `_emit_abort_reason`
helper prints the `abort_reason` string.

### D9. Two commits

- Commit 1: this ADR (design lock).
- Commit 2: implementation (scanner.py + cli.py) + 6 tests.

Same rhythm as ADR-009's design-then-impl split, scaled down to one impl
commit. The ADR is a design lock that precedes code consuming it — landing
the ADR alone gives visibility before implementation commitment.

### D10. Test strategy: 6 tests in `tests/integration/test_scanner.py`

`test_scanner.py` already ships `FakeSession` (line 36) and the
handler-pattern (`clean_handler`, `sql_error_handler`). New tests follow
that shape — no new fixtures, no new file. Gotcha P: reuse `FakeResponse` /
`FakeSession` as they exist.

Tests:

1. `test_scanner_aborts_on_consecutive_401s_when_auth_configured`
2. `test_scanner_does_not_abort_on_401s_when_auth_not_configured`
3. `test_scanner_does_not_abort_on_single_401_then_200`
4. `test_scanner_aborts_on_second_consecutive_401_not_first`
5. `test_scanner_preserves_findings_before_401_abort`
6. `test_scanner_401_counter_resets_on_success`

## Consequences

- **Positive.** Auth expiry produces a clear abort + exit code 2 instead of
  silent false negatives. Enterprise parity on authenticated scans. Partial
  findings preserved and reported.
- **Negative.** Scans that encounter two consecutive 401s for reasons other
  than auth expiry (aggressive CDN rate limiting configured to 401 rather
  than 429, for example) will abort. Mitigation: reset-on-success means
  alternating 401/200 traffic never triggers; and if this class of false
  abort is observed in the field, threshold can be raised to 3 in a follow-up
  amendment without changing the contract.
- **Neutral.** Benchmark unchanged. All 597 existing tests unchanged (new
  kwarg defaults False). No new CLI flag.

## Alternatives considered and rejected

**Annotate findings instead of aborting.** Rejected. Enterprise dashboards
aggregate finding counts; annotating each finding with "auth may have
expired" produces dashboards that look complete but are unreliable. Exit
code 2 is unambiguous and already the established signal.

**Re-authenticate on 401 via `--refresh-cmd` or session hook.** Deferred.
Requires session state management, credential store, and a refresh contract
that does not exist yet. This ADR establishes the detection primitive;
re-authentication is a separate feature.

**Threshold=1.** Rejected. False aborts on transient 401s are worse than the
delayed abort from threshold=2.

**Threshold=3.** Rejected. Wastes one request per scan for no diagnostic
benefit over threshold=2.

**Detect 401 in the baseline loop.** Deferred. Documented as D5. The
12-request bound is acceptable; extending the counter is a future amendment.

**Inspect `self.session.headers` for `Authorization` or `Cookie` instead of
adding `auth_configured` kwarg.** Rejected. Fragile (see D2).

## References

- `src/janissary/auth.py` — static-v1 auth; docstring names the limitation
  this ADR addresses.
- `src/janissary/engine/scanner.py` — `Scanner.__init__` (line 217),
  `_request` (line 281), `_paced_request` (line 354), `preflight`
  (line 373), `collect_baseline` (line 418), `scan` (line 445),
  preflight-abort contract (lines 452-457).
- `src/janissary/cli.py` — `cmd_scan` auth wiring (lines 224-228),
  `Scanner` construction (line 230), abort handling (lines 253-254,
  281-282).
- `tests/integration/test_scanner.py` — `FakeSession` (line 36),
  handler-pattern tests (lines 86, 108, 124, 140, 154).
- Session 0.3.8 handover — `session-0.3.8.txt` — the 401-label rectification
  and the 0.3.9 scope decision.
- ADR-007 (finding identity), ADR-009 (SARIF enterprise parity) — the
  enterprise-first framing this ADR extends.
