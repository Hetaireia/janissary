# ADR-011 — Agent-path auth threading + 401 detection

**Status:** Accepted (2026-10-27). Session 0.3.11. Design lock only;
implementation deferred to 0.3.12.
**Supersedes:** None.
**Related:** ADR-010 (scanner-path auth expiry detection). ADR-011
does not extend ADR-010; the two paths have different request shapes
and the scanner payload-loop pattern does not transfer.

## Context

ADR-010 shipped mid-scan auth expiry detection for the direct-scan
path (`Scanner.scan`). Its next-scope item 1 was "agent-path 401
detection (ADR-010 D6)." Session 0.3.11 recon established that the
item's framing was inaccurate: the actual concern is not a missing
detector, it is a global mutable-state auth injection mechanism that
a detector would have nowhere clean to hook into.

### Recon findings

1. **Adapters do not thread session.** `src/janissary/agent/adapters.py`
   defines four adapters — `admin_adapter`, `xmlrpc_adapter`,
   `graphql_adapter`, `fingerprint_adapter` — each with signature
   `(target: str, context: dict) -> list[Finding]`. `context` carries
   `timeout` and `proxies`; it does not carry a session or auth config.

2. **Auth injection happens via process-global monkey-patch.**
   `src/janissary/cli.py` L877-890:

       auth_cfg = auth_from_args(args)
       _orig_session_init = requests.Session.__init__
       if not auth_cfg.is_empty:
           def _auth_init(self, *a, **kw):
               _orig_session_init(self, *a, **kw)
               apply_to_session(self, auth_cfg)
           requests.Session.__init__ = _auth_init
       try:
           result = agent.run(args.url, extra_platforms=extra_platforms)
       finally:
           if not auth_cfg.is_empty:
               requests.Session.__init__ = _orig_session_init

   Every `requests.Session()` created anywhere in the process during
   `agent.run()` — including inside each recon module invoked by an
   adapter — inherits the auth headers. This is why `agent/` has zero
   session references: it does not need to thread, it inherits.

3. **The monkey-patch is fragile on four axes.**
   - Process-global: any concurrent thread or callback inherits it.
   - Untestable: no way to mock without either patching
     `requests.Session` in tests or exercising the full subprocess.
   - Exception-unsafe: if `_orig_session_init` raises, or if
     `agent.run()` catches and swallows an exception, the `finally`
     block's restore may race with in-flight sessions.
   - Silent: if `apply_to_session` fails (e.g. bad header value),
     the exception surfaces in whichever recon module is created
     first, misattributing the failure.

4. **The scanner-path 401 pattern does not transfer.** ADR-010 D3
   counts consecutive 401s in `Scanner.scan`'s payload loop. The
   agent has no payload loop — `Agent.run()` (agent.py L137) loops
   over `self.plan` and calls `self.adapters[module](target,
   context)` once per module. Each adapter internally issues N
   requests (N depends on the recon module: admin probe is ~30
   paths, fingerprint is ~10, graphql is ~5, xmlrpc is ~2). A 401
   counter for the agent must either wrap each adapter call (module-
   granular) or install a response hook on the session (request-
   granular).

5. **`AgentRun` already has the abort contract.** agent.py L43-44:

       aborted: bool = False
       abort_reason: str = ""

   L157-158 already sets both for the "no fingerprinter, no adapters"
   case. The plumbing a 401 detector needs to write into exists.
   `cmd_agent` L901-902 prints `[!] ABORTED: {reason}` when
   `result.aborted`. L942 returns exit code 2. All the downstream
   handling already works.

6. **Recon modules accept `session=`.** From prior sessions'
   `tests/unit/test_admin.py` and `tests/unit/test_fingerprint.py`
   recon, `probe_admin(..., session=session)` and
   `fingerprint(..., session=session)` both accept the kwarg. Threading
   the session through adapter context reaches underlying modules
   with zero signature changes to the modules themselves.

## Decisions

### D1. Session threading replaces the monkey-patch

`Agent.__init__` gains a new kwarg `session: requests.Session | None = None`.
`Agent.run` passes `context["session"] = self.session` to each adapter.
Each adapter in `default_adapters()` calls `context.get("session")` and
passes it to the underlying recon module's `session=` kwarg.

`cmd_agent` (cli.py) constructs the session once, passes it via
`Agent(store, adapters=..., fingerprinter=..., session=auth_session)`.
The `requests.Session.__init__` monkey-patch (L877-890) is deleted
entirely.

**No behavior change when session is None.** Every existing test
constructs `Agent(store, adapters=...)` without a session and gets
`session=None`. Each adapter passes `session=None` to the recon
module, which the recon module handles as "create a fresh session."
Current behavior preserved.

### D2. Response-hook 401 detection

When `session` is not None and `auth_configured` is True, install a
`session.hooks["response"]` hook:

    def _response_hook(response, *args, **kwargs):
        if response.status_code == 401:
            self._consecutive_401s += 1
        else:
            self._consecutive_401s = 0
        if self._consecutive_401s >= THRESHOLD and not self._aborted:
            self._aborted = True
            self._abort_reason = (
                f"auth expired: {self._consecutive_401s} consecutive "
                f"HTTP 401 responses (last url={response.url})"
            )
        return response

Hook installed in `Agent.__init__` when session is provided and
`auth_configured` is True. Removed in `run`'s finally (defensive).

### D3. Threshold=2, matching ADR-010 D3

Same rationale as ADR-010: 1 rejects transient 401s (CDN rate limits,
session-rotation races); 2 is the signal; 3 wastes a request. Reset-on-
success means alternating 401/200 traffic never triggers.

The threshold is a shared contract with ADR-010. If ADR-010's
threshold is ever raised by a field report, ADR-011's threshold
raises with it.

### D4. Fire condition: auth_configured AND threshold reached

Both must hold. If `auth_configured=False`, 401s do not abort (baseline
behavior: unauthenticated scan of a protected resource correctly
yields no findings). If `auth_configured=True` and threshold fires:
`AgentRun.aborted = True`, `abort_reason` populated, module dispatch
loop breaks, findings collected so far preserved.

### D5. Abort mid-run, do not annotate

Same argument as ADR-010 D4. Aborting with exit code 2 and a named
reason is the correct enterprise signal. Partial findings are
preserved. Annotating individual findings with "auth may have expired"
hides the incomplete-coverage signal inside each finding row.

### D6. Scope: agent path only

`cmd_agent` (cli.py L804-944). The scanner path (`Scanner.scan`) is
already covered by ADR-010 and is not touched. Other CLI commands
(`cmd_fingerprint`, `cmd_admin`, etc.) are invoked directly, not
through the agent, and are out of scope. If a future session adds
auth expiry detection to a direct recon command, that is a separate
ADR.

### D7. Session hooks are additive; existing behavior is preserved

`session.hooks["response"]` is a list of callables. Adding one does
not remove any that already exist. If the user's session already has
response hooks (e.g. from their own tooling), those continue to fire.
The 401 counter is an additional listener, not a replacement.

### D8. Benchmark neutrality by construction

The benchmark harness invokes the CLI without `--cookie` or `--bearer`.
`auth_cfg.is_empty` is True. `cmd_agent` passes `session=None` to
`Agent`. The response hook is not installed. F1=0.921 unchanged. No
scoring-path file is touched.

### D9. Three commits

- **Commit 1 (this session, 0.3.11):** ADR-011 (this document). Design
  lock for review before code.
- **Commit 2 (session 0.3.12):** session threading — remove monkey-
  patch, thread session through `context`, update adapters. No new
  behavior; 603 existing tests should still pass. This refactor is
  the load-bearing change. If it lands green, detection in commit 3
  has a clean foundation.
- **Commit 3 (session 0.3.12):** response-hook 401 counter, abort
  semantics, tests. New behavior on top of the refactor.

Splitting threading from detection keeps each commit reviewable. The
refactor commit is the larger diff (~40-60 lines across `cli.py`,
`agent/agent.py`, `agent/adapters.py`) but has zero new behavior; the
detection commit is ~20-30 lines plus 6 tests, entirely additive.

### D10. Test strategy

`tests/unit/test_agent.py` gains a new `FakeSession` class. Existing
tests use `_adapter_returning(findings)` which ignores session — those
tests remain unchanged (the new session kwarg defaults None).

New tests (in `test_agent.py` under a new "ADR-011: auth threading and
401 detection" section):

- `test_agent_accepts_session_kwarg` — construct with session; assert
  `agent.session is session`.
- `test_agent_passes_session_via_adapter_context` — adapter captures
  `context["session"]`; assert identity.
- `test_agent_does_not_install_hook_when_no_session` — construct
  without session; assert `session is None` and no hook installed on
  anything.
- `test_agent_response_hook_counts_401s` — verify counter increments,
  resets, and fires at threshold=2 (unit-test the hook in isolation).
- `test_agent_aborts_on_consecutive_401s_when_auth_configured` — run
  with a FakeSession whose FakeResponse returns 401 for all but the
  first few; assert `run.aborted is True`, `run.abort_reason` mentions
  the count and url.
- `test_agent_does_not_abort_on_401s_when_auth_not_configured` —
  same session, `auth_configured=False`; assert `run.aborted is False`.
- `test_agent_preserves_findings_before_401_abort` — FakeSession
  returns one finding-producing response then 401s; assert findings
  in `run` before abort survive.
- `test_cmd_agent_uses_threaded_session_not_monkey_patch` — CLI
  test (subprocess or direct cmd_agent invocation with monkey-patched
  FakeSession); capture `requests.Session.__init__` identity before
  and after; assert unchanged. This is the specific test that proves
  D1 landed.

Total: 8 new tests. 603 → 611.

## Consequences

- **Positive.** Monkey-patch removed. Session threading is explicit
  and testable. 401 detection on the agent path closes the last
  silent-false-negative class in the current tree. Agent-path auth
  becomes mockable in unit tests without touching `requests.Session`.
- **Negative.** The refactor commit is large — `cli.py` monkey-patch
  removal (L877-890), `agent/agent.py` constructor + context threading,
  four adapters each gaining a `session=context.get("session")` line,
  and `tests/unit/test_agent.py` gains a `FakeSession`. Risk of
  breaking existing tests is real but bounded — existing tests use
  `_adapter_returning` which ignores session, and recon modules
  already accept `session=None`.
- **Neutral.** No CLI surface change. No new flags. Exit code 2
  already handled by `cmd_agent` L942. Benchmark unchanged.

## Alternatives considered and rejected

**Keep the monkey-patch, add a response hook to whatever session the
monkey-patch creates.** Rejected. The hook would need to install
itself inside the patched `_auth_init`, which is already thread-
unsafe. Also fails the testability criterion — still no way to
exercise the 401 path in isolation.

**Extend ADR-010's counter to work "generically" across both paths.**
Rejected. The scanner path counts in a payload loop with a known
`self._consecutive_401s` on the scanner instance. The agent path has
no analogous loop. A shared counter would need a shared session object
with a hook, which is what D2 does — but sharing the counter class
across paths would couple unrelated code. Keep the two detectors
independent; the threshold contract is shared, the implementation is
not.

**Threshold=1 for the agent path** (fewer requests, faster abort).
Rejected. Same rationale as ADR-010 D3: transient 401s are common
enough that threshold=1 produces false aborts. The session-hook
approach makes threshold=2 cheap because the hook fires per request,
not per module.

**Skip the refactor, do only detection on top of the monkey-patch.**
Rejected. Detection without threading has nowhere clean to hook. The
monkey-patch is the technical debt; ADR-011 pays it down as a
prerequisite to the feature, not as an unrelated cleanup.

**Defer the entire arc to 8.x.** Rejected. The monkey-patch fragility
is a live risk (thread-safety, exception safety, testability), not a
cosmetic concern. If any of those axes fails in the field — a
concurrent test running in the same process, a swallowed exception —
it produces confusing failures unrelated to the operator's intent.
Fixing it now, in a controlled refactor session, is cheaper than
debugging it later when it matters.

## References

- `src/janissary/agent/agent.py` — `AgentRun` (L34-59), `Agent.run`
  (L137-188), abort contract (L43-44, L157-158).
- `src/janissary/agent/adapters.py` — four adapters (L20, L57, L99,
  L140), `default_adapters` (L170).
- `src/janissary/agent/__init__.py` — public surface, exports
  `Agent`, `AgentRun`, `Finding`, `FindingStore`.
- `src/janissary/cli.py` — `cmd_agent` L804-944; monkey-patch
  L877-890; abort handling L901-902, L942.
- `src/janissary/auth.py` — `AuthConfig`, `apply_to_session`.
- `tests/unit/test_agent.py` — existing tests (19 defs), `FakeFP`,
  `FakeWAF`, `_adapter_returning`.
- `tests/unit/test_admin.py`, `tests/unit/test_fingerprint.py` —
  recon modules accept `session=` kwarg.
- ADR-010 — scanner-path auth expiry detection. Threshold contract
  shared with D3 above.
- Session 0.3.10 handover — `session-0.3.10.txt` — the sweep that
  promoted "agent-path 401 detection" as next-scope item 1.
- Session 0.3.11 recon — the agent-module structure and monkey-patch
  discovery that re-characterized the item.
