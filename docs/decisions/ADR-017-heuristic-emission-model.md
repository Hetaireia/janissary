# ADR-017 -- Heuristic emission model (Track B returns candidates, not findings)

**Status:** Accepted (2026-11-04). Phase 0 Foundation.
**Supersedes:** None.
**Amends:** ADR-016 D3 (parenthetical reference to `CandidateFinding (new)` -- see D5 below).
**Extends:** ADR-001 (sole-emitter invariant), ADR-016 (vocabulary).
**Blocks:** M36a completion (ADR series 016-021); M38 (Track B engine implementation).

## Context

ADR-016 locked the vocabulary: Track A (Verified Engine) emits findings,
Track B (Discovery Engine) produces triage candidates. But ADR-016 was
deliberately silent on the *mechanism*. It said "Track B does not emit
`ScanFinding`" in one line and moved on. The critical question --
how does Track B avoid emitting, given that the sole-emitter rule
(ADR-001) has to hold across both engines -- was not specified.

Phase 1 (M37-M38) will build the `heuristic/` package. Without an
explicit emission contract, the first Track B PR will drift into
emitting findings directly. That drift is the "dual detection" failure
mode the strategy document rejects (FUTURE-STATE-PLAN.md Executive
Summary). This ADR closes that gap.

## Current state (evidence)

Three facts from the existing codebase, verified 2026-11-04:

1. `tests/unit/test_cli_unproven_display.py` constructs `ScanFinding`
   objects with `verification_status="unproven"` and asserts the
   human CLI displays them with an `[unproven]` marker. This is the
   M16 pattern. It is tested and shipping.

2. `src/janissary/engine/scanner.py` sets `f._engine_emitted = True`
   on every finding routed through `_ENGINE.verify()`. The append
   path asserts this flag before allowing the finding into the
   summary list. That is the structural enforcement of ADR-001.

3. The existing Track A payload loop (line ~1042 onward) sets
   `verification_status` and `verification_reason` explicitly per
   finding, based on what the oracle returned. No module outside
   the engine sets these fields.

Together these mean: the emission contract already exists in practice,
just not in writing. ADR-017 writes it down.

## Decisions

### D1. Track B modules return `ScanFinding` with `verification_status` unset

A Track B module (e.g., `heuristic/engine.py`) constructs `ScanFinding`
objects with all fields it knows about -- `param`, `payload_name`,
`payload_value`, `category`, `severity`, `finding_type`, `detail`,
`response_status`, `url`, `method`, `raw_request`, `raw_response` --
but does not touch `verification_status` or `verification_reason`.
Those fields default to their dataclass defaults (`None`).

Rationale: Track B knows the *observation* (the response looked like a
local file inclusion), but it does not know the *verdict* (is this
provable by differential?). Only the engine knows that.

### D2. The `_engine_emitted` flag is the enforcement mechanism

Every `ScanFinding` that reaches `summary.findings` must have
`_engine_emitted = True`. That flag is set by `_ENGINE.verify()` and
by nothing else. When Track B returns candidates, it must submit them
to `_ENGINE.verify()` -- exactly the same path Track A uses -- so they
carry the flag.

The existing `assert` in the append path (scanner.py, before each
`summary.findings.append(f)` call) is the runtime guarantee. A Track B
module that tries to bypass `_ENGINE.verify()` will fail the assert
at runtime, not at code review. This is ADR-001's enforcement, made
load-bearing.

### D3. `_ENGINE.verify()` is the sole source of `verification_status`

For a Track B candidate, `_ENGINE.verify()` sets:

- `verification_status = "unproven"` (default for Track B)
- `verification_reason = "heuristic:<signature_id>"` (e.g.,
  `heuristic:HEUR-001`)

For a Track B candidate that happens to pass an independent
differential check that the engine runs (e.g., the candidate fires a
DB-error signature AND a fresh baseline confirms the same signature
is absent), `_ENGINE.verify()` may promote:

- `verification_status = "verified"`
- `verification_reason = "engine:promoted_from_heuristic"`

The engine decides. The heuristic module never gets a vote. This is
exactly the Track A behavior -- the oracle decides, the caller reports
-- applied to Track B.

### D4. Routing is by `verification_status`, not by source

Downstream consumers route on `verification_status`, not on which
module produced the finding:

- `verification_status == "verified"` -> main SARIF run (blocks CI)
- `verification_status == "unproven"` -> discovery SARIF run (triage)

A Track A finding that somehow ends up `unproven` (e.g., an oracle
that returned "candidate" and needs engine re-check) routes to the
discovery stream. A Track B candidate that got promoted routes to the
main stream. **The stream is a property of the verdict, not of the
origin.** This survives any future re-balancing of Track A vs Track B
responsibilities.

### D5. Do not introduce a `CandidateFinding` class

FUTURE-STATE-PLAN.md Part 3 proposed `HeuristicEngine returns
CandidateFinding, not ScanFinding`. ADR-017 overrides that proposal
on engineering grounds:

- A new `CandidateFinding` class would require changing
  `_ENGINE.verify()`'s signature (currently `verify(candidate: ScanFinding)`)
- It would require rewriting `test_cli_unproven_display.py` and every
  other test that constructs `ScanFinding` for unproven scenarios
- It would require a conversion layer at the boundary (ScanFinding ->
  CandidateFinding -> ScanFinding)
- It would provide zero user-facing gain -- the user sees `unproven`
  labels either way
- It would violate Failure Pattern 3 of FUTURE-STATE-PLAN.md
  ("rewriting working code")

The existing `ScanFinding + verification_status="unproven"` pattern
already does the job, is tested, and can be extended additively. ADR-017
adopts it as the canonical mechanism. ADR-016 D3's parenthetical
mention of `CandidateFinding (new)` was aspirational; this decision
supersedes it.

**What Track B does get that Track A does not have**:

- `signals: list[str]` -- the list of heuristic signature IDs that
  matched (e.g., `["HEUR-001"]`, `["HEUR-002", "HEUR-014"]`). This is
  set by the Track B module before calling `_ENGINE.verify()`. It
  flows into `verification_reason` as `heuristic:HEUR-001+HEUR-002`
  and into SARIF's `properties.signals`.

This field already exists on `ScanFinding` (it is currently empty for
Track A findings). Track B is the first user.

## Consequences

**Positive:**
- 1.000 precision is enforced structurally (via `_engine_emitted`
  assert) not just by convention
- Track B modules follow exactly the same protocol as Track A modules:
  construct `ScanFinding`, submit to `_ENGINE.verify()`, report what
  came back
- Zero code changes required to existing code to enable this contract
  (Track A already does the right thing; the assert is already there)
- SARIF routing in M40 is a simple switch on `verification_status`,
  not a per-module config
- The `CandidateFinding` class is not introduced, keeping imports
  simple and test fixtures unchanged

**Negative:**
- The contract is convention + runtime assert, not type-level. A
  determined author can bypass it by setting `_engine_emitted = True`
  manually. Mitigation: code review catches this -- it is one grep
  away (`grep -r '_engine_emitted' src/` should only match scanner.py
  and this ADR).
- Track B modules must remember not to set `verification_status`.
  Mitigation: the field defaults to `None`, and the engine treats
  `None` as "unproven, needs check" -- so forgetting is safe by
  construction. Setting it is the anti-pattern, not forgetting.

**Neutral:**
- This is a documentation ADR. No code changes ship with it. M38 will
  implement the pattern when the `heuristic/` package lands.
- The `signals` field being first populated by Track B is a
  forward-compatible addition; Track A can adopt it later if useful.

## Alternatives rejected

**Option A: New `CandidateFinding` class distinct from `ScanFinding`.**
Rejected per D5. Adds a conversion layer, breaks 856 tests, no
user-visible gain. Would need to ship in the same release as the
Track B engine (breaking change risk) rather than additively.

**Option B: Track B returns `ScanFinding` with `verification_status=
"unproven"` set directly by the module.**
Rejected because it violates D2. If Track B sets the status, then
Track B is the verdict-maker, and the sole-emitter rule erodes. The
correct boundary is: Track B sets `signals` (observations), the
engine sets `verification_status` (verdict).

**Option C: Track B writes candidates to a separate file, no in-memory
structure.**
Rejected because the existing test pattern (`test_cli_unproven_display.py`)
exercises display for unproven `ScanFinding` objects. A file-based
path would need a parallel display path, doubling the test surface.
The in-memory pattern is already tested and works.

**Option D: Track B can promote directly to `verified` if it is
confident enough.**
Rejected. This is exactly the "dual detection" failure mode. There is
no path where a heuristic module promotes its own candidate to a
finding. Promotion goes through `_ENGINE.verify()`, which runs an
independent check (ADR-001).

## References

- `docs/FUTURE-STATE-PLAN.md` Part 3 Phase 1 (M37-M38)
- `docs/FUTURE-STATE-PLAN.md` Part 4 Failure Pattern 3 (rewriting
  working code -- D5 applies this to the plan's own proposal)
- ADR-001 -- verification engine sole-emitter invariant
- ADR-016 -- Verified vs Discovery vocabulary (this ADR amends D3)
- `src/janissary/engine/scanner.py` -- `_engine_emitted` enforcement,
  Track A reference implementation
- `tests/unit/test_cli_unproven_display.py` -- M16 unproven marker
  (proof the existing pattern works)
- `src/janissary/verification/engine.py` -- `_ENGINE.verify()`, sole
  setter of `verification_status`