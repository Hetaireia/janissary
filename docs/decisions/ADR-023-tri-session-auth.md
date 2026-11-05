# ADR-023 -- Tri-session auth rotation (extends ADR-010)

**Status:** Accepted (2026-11-05). Phase 2 implementation.
**Supersedes:** None.
**Amends:** ADR-010 (adds tri-session rotation mode; single-session abort behavior unchanged).
**Extends:** ADR-016 (vocabulary), ADR-022 (design-lock-first pattern).

## Context

ADR-010 (2026-10-27) established auth-expiry detection for single-session
scans: two consecutive 401s while `auth_configured=True` aborts with a
clear `abort_reason`, preserving partial findings. That solution is
correct for the single-session case: if the user provides one cookie and
the target stops accepting it, the scanner aborts with an accurate
diagnostic instead of silently evaluating login-page bodies as "not
vulnerable."

But single-session has a limitation the milestone list names explicitly:
**tri-session auth (A/B/C)**. Three use cases:

1. **Load-balanced targets** rotate auth cookies across requests. A scan
   holding one cookie sees intermittent 401s as the LB cycles between
   backends, then aborts -- even though all provided sessions are valid.

2. **Short-TTL sessions** (common on internal tools: 15-minute TTL). Two
   or three cookies with staggered issuance extend coverage without
   re-authentication.

3. **Multi-identity testing.** Pentesters verifying "does endpoint X leak
   data between A and B" need both sessions simultaneously. Today this
   requires two scans; tri-session lets one scan use A, B, C
   interchangeably.

ADR-010 explicitly deferred this: "Re-authenticate on 401 via
`--refresh-cmd` or session hook. Deferred. Requires session state
management, credential store, and a refresh contract that does not exist
yet." M41 is that state management, scoped to **rotation** (we do not
mint new sessions, we rotate among the provided ones).

## Current state (evidence)

Probe 2026-11-05:

1. **`AuthConfig` (src/janissary/auth.py:28-46) is stateless config.**
   Fields: `cookie: str | None`, `bearer: str | None`. No session state.
   Extending with `sessions: list[SessionSpec] | None = None` is
   additive; nothing else constructs `AuthConfig` directly (only
   `auth_from_args` in the same file).

2. **`_consecutive_401s` lives on `Scanner` (scanner.py:427).** Not on
   the session, not a module global. Rotation must hook the payload
   loop where the counter is managed.

3. **ADR-010 abort threshold (scanner.py:1122) is `>= 2`** when
   `auth_configured=True`. Correct fallback for tri-session when
   rotation exhausts (see D7).

4. **`apply_to_session` does not clear managed headers before setting**
   (auth.py:57: `session.headers[k] = v`). If rotation swaps from
   `Cookie: A` to `bearer: B` (no cookie), the old `Cookie: A` persists.
   D3 fixes this.

5. **Zero session-rotation code exists.** Probe searched for
   `SessionTriplet|session_triplet|tri_session|rotate_session|session_rotation`
   across `src/` and `tests/` -- nothing.

6. **ADR-010 factual claims match shipped code.** Unlike ADR-017
   (which ADR-022 corrected), ADR-010 is accurate -- threshold, counter
   location, abort message shape all confirmed. M41 extends ADR-010
   without correcting it.

## Decisions

### D1. New `SessionSpec` type; `AuthConfig.sessions: list[SessionSpec] | None = None`

```python
@dataclass(frozen=True)
class SessionSpec:
    cookie: str | None = None
    bearer: str | None = None

    def headers(self) -> dict: ...


@dataclass
class AuthConfig:
    cookie: str | None = None
    bearer: str | None = None
    sessions: list[SessionSpec] | None = None
```

`sessions=None` means single-session (current behavior).
`sessions=[...]` means rotation mode.

`AuthConfig.headers()` and `apply_to_session` operate on `sessions[0]`
when `sessions` is non-None; otherwise on `cookie`/`bearer`. This
preserves every existing test byte-for-byte.

### D2. New `_SessionRotator` class

State machine in `src/janissary/engine/session_rotator.py`:

```python
class _SessionRotator:
    def __init__(self, sessions: list[SessionSpec]):
        self._sessions = sessions
        self._current = 0
        self._exhausted = False

    def current(self) -> SessionSpec:
        return self._sessions[self._current]

    def can_rotate(self) -> bool:
        return not self._exhausted

    def rotate(self) -> SessionSpec | None:
        if self._exhausted:
            return None
        self._current += 1
        if self._current >= len(self._sessions):
            self._exhausted = True
            return None
        return self._sessions[self._current]
```

Never revisits a failed session (once exhausted, stays exhausted).
Prevents ping-ponging between A and B.

### D3. `apply_to_session` clears managed headers before applying

```python
def apply_to_session(session, config):
    if config is None or config.is_empty:
        return
    for h in ("Cookie", "Authorization"):
        session.headers.pop(h, None)
    for k, v in config.headers().items():
        session.headers[k] = v
```

Required for correct rotation between sessions with different header
profiles. Affects single-session case: calling apply twice is still
idempotent, and no existing test asserts stale headers persist.

### D4. New CLI flag `--sessions PATH`

Reads a JSON file containing an array of `{cookie: str|null,
bearer: str|null}` objects. Requires >= 2 entries (else use
`--cookie`/`--bearer`). Mutual exclusion with `--cookie`/`--bearer`:
exit 64 if both provided.

Alternative CLI forms rejected:

- **`--cookie-1 X --cookie-2 Y --cookie-3 Z`**: 6 flags to cover the
  cookie+bearer matrix, clutters `--help`.
- **`--sessions "a;b;c"`**: cannot express bearer-only sessions.
  Ambiguous delimiter if cookie value contains `;` (which it typically
  does -- cookies are `name=val; name2=val2`).
- **Environment variable**: does not fit `--cookie`/`--bearer` pattern.

JSON file matches ADR-008 (SARIF), ADR-009 (agent findings), and
ADR-022 structured-config precedent.

### D5. Rotation triggers on 401 in the payload loop only

Baseline 401s (in `collect_baseline`) do not rotate. Matches ADR-010 D5
(payload loop only; baseline 401s tolerated). If baseline goes 401
(session bad from the start), rotation at the first payload request
still catches it within one extra request.

### D6. Rotation retries once per 401, never mid-payload

On a 401 in the payload loop:

1. If `can_rotate()`: call `apply_to_session(self.session, rotator.rotate())`,
   then retry the same request ONCE via `_paced_request`.
2. If retry succeeds (non-401): reset `_consecutive_401s` to 0, continue
   scan with the new session.
3. If retry also 401: increment `_consecutive_401s`, do NOT rotate again
   within the same payload attempt. Next payload attempt will start from
   the new (rotated) session.

This bounds each 401 payload attempt to 2 requests. Prevents
multi-rotation thrash.

### D7. `_consecutive_401s` counts post-rotation 401s, resets on success

Counter increments only when a 401 survives rotation (retry still 401)
or no rotation available. Successful rotation resets to 0. This is the
natural extension of ADR-010 D3 semantics.

Trace with 3 sessions [A, B, C], all bad:

    Payload 1: A -> 401 -> rotate to B, retry -> 401. Counter=1. Session=B.
    Payload 2: B -> 401 -> rotate to C, retry -> 401. Counter=2. ABORT.

Trace with 3 sessions, A and B bad, C good:

    Payload 1: A -> 401 -> rotate to B, retry -> 401. Counter=1. Session=B.
    Payload 2: B -> 401 -> rotate to C, retry -> 200. Counter=0. Session=C.

Both traces preserve ADR-010 threshold-2 semantics.

### D8. Sessions exhausted -> fallback to ADR-010 abort

Once `can_rotate()` is False (all sessions tried), 401 handling falls
back to pure ADR-010: counter increments, aborts at threshold=2.

### D9. Scanner gains `auth_sessions: list[SessionSpec] | None = None`

Added to `Scanner.__init__`. When non-None, `self._session_rotator`
is constructed from it. When None (default), no rotator exists and
401 handling runs pure ADR-010 logic.

`cmd_scan` wires this from `auth_cfg.sessions`:

```python
sessions = getattr(auth_cfg, "sessions", None)
scanner = Scanner(
    ...,
    auth_configured=not auth_cfg.is_empty or bool(sessions),
    auth_sessions=sessions,
)
```

### D10. Abort message extended when tri-session active

Single-session (unchanged from ADR-010):
    "auth expired: 2 consecutive HTTP 401 responses (param=..., last payload=...)"

Tri-session (extended):
    "auth expired: 2 consecutive HTTP 401 responses after rotation; N/M sessions attempted (param=..., last payload=...)"

Where N = rotator.current_idx + 1, M = len(sessions). Exit code still 2.

### D11. Existing ADR-010 behavior byte-for-byte preserved

When `--sessions` not used, no `_SessionRotator` constructed, 401
handling runs pure ADR-010 logic, all existing tests pass without
modification. Verification: 919 unit + 38 SARIF integration green.

### D12. Tests in three files, ~22 new

- `tests/unit/test_auth.py`: ~8 tests added (SessionSpec,
  apply_to_session clearing, sessions-file loading)
- `tests/unit/test_session_rotator.py`: ~8 tests (new file, rotator
  state machine)
- `tests/integration/test_scanner_tri_session.py`: ~6 tests (end-to-end
  401 rotation, matches ADR-010 D10 handler pattern)

## Consequences

**Positive:**
- Load-balanced / short-TTL / multi-identity scans work without
  re-authentication
- Single-session behavior unchanged (ADR-010 fully preserved)
- ADR-010 abort semantics still apply when rotation exhausts
- CLI surface is one new flag (`--sessions PATH`)

**Negative:**
- `apply_to_session` now clears managed headers (D3). Any external
  caller relying on "additive header-set" semantics changes behavior.
  Mitigation: no such caller in this repo; if an external integrator
  exists, semver-major release note.
- JSON file format is a new schema users must learn. Mitigation:
  sample file in docs/ or examples/ (implementation choice).

**Neutral:**
- M41 scope ~300 lines code + ~250 lines tests.
- M42 (IDOR candidate probe) unaffected; no shared code.
- M43 (crAPI validation) can use tri-session for authenticated scans.

## Alternatives rejected

**Option A: `SessionTriplet` class distinct from `AuthConfig`.**
Rejected -- same rationale as ADR-022 D5 rejection of a new
`CandidateFinding` class. Adding a field to `AuthConfig` is smaller,
preserves every existing call site, and no external code distinguishes.

**Option B: `--cookie-1/2/3` flags.**
Rejected -- 6 flags to cover cookie+bearer matrix, clutters help, no
support for bearer-only sessions.

**Option C: Round-robin every request.**
Rejected -- works for load-balanced targets but breaks for short-TTL
(rotating before 401 wastes a good session) and multi-identity
(findings mix identities randomly). Rotation on 401 is the right
trigger.

**Option D: Auto-refresh via re-authentication.**
Deferred -- same as ADR-010 D-alt. Requires credential store, auth
flow contract, backend cooperation. Out of scope.

**Option E: Proactive preflight checks on all sessions.**
Rejected -- adds N extra requests per scan for a diagnostic that
rotation-on-401 provides lazily.

## References

- ADR-010 -- mid-scan auth expiry detection (behavior M41 extends)
- ADR-016 -- Verified vs Discovery vocabulary
- ADR-022 -- Track B emission reconciliation (design-lock-first pattern)
- src/janissary/auth.py -- AuthConfig, apply_to_session, add_auth_flags,
  auth_from_args
- src/janissary/engine/scanner.py -- _consecutive_401s (line 427),
  401 handling (lines 1115-1127)
- tests/unit/test_auth.py -- existing AuthConfig tests
- tests/integration/test_scanner.py -- existing scanner 401 tests
  (per ADR-010 D10)
