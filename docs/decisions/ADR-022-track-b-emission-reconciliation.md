# ADR-022 -- Track B emission contract (reconciled with shipped code)

**Status:** Accepted (2026-11-05). Phase 1 implementation fixup.
**Supersedes:** None.
**Amends:** ADR-017 D1, D2, D5 (shipped code diverged from ADR-017's stated evidence).
**Extends:** ADR-016 (vocabulary), ADR-017 (emission model), ADR-020 (dataclasses).

## Context

ADR-017 was written 2026-11-04, immediately before M37 was implemented.
It stated three facts "verified 2026-11-04":

1. `ScanFinding.verification_status` defaults to `None`
2. `_engine_emitted = True` is set by `_ENGINE.verify()` and nothing else
3. `signals: list[str]` "already exists on ScanFinding"

Code probe on 2026-11-05 (pre-M38) found all three false:

1. `ScanFinding.verification_status: str = "verified"` (scanner.py:236). The
   dataclass field defaults to `"verified"`, matching pre-Phase-0.1 behavior.
   Any ScanFinding constructed without an explicit status is `verified`, not `None`.
2. `_engine_emitted = True` is set in **two** places: scanner.py:280 (inside
   `_to_scan_finding()`, the intended path) AND scanner.py:892 (inside
   `_candidate_to_scan_finding()`, the legacy path that does NOT call `_ENGINE.verify()`).
3. `ScanFinding` has no `signals` field. `CandidateFinding` has
   `discovery_reason: str | None`, which is the semantic equivalent -- but on a
   different class.

These discrepancies matter because ADR-017 D1 says "Track B constructs ScanFinding
with verification_status unset -- defaults to None." Following that literally today
would produce `"verified"` findings -- the exact failure mode ADR-017 was written
to prevent.

Additionally: `_ENGINE.verify()` takes `CandidateFinding` (not `ScanFinding`),
returns `VerifiedFinding` (not `ScanFinding`), and `_to_scan_finding()` converts.
ADR-017 D2 wrote "Track B constructs ScanFinding... submit to _ENGINE.verify()" --
a type mismatch that would fail at runtime.

Root cause unclear: either (a) ADR-017 was drafted against a hypothetical codebase
rather than verified against reality; or (b) Phase 0.1 rewiring changed
`_engine_emitted` semantics after ADR-017 was written. Either way, this ADR
reconciles the contract with reality.

## Decisions

### D1. Track B constructs `CandidateFinding`, not `ScanFinding`

Track B (heuristic/engine.py) produces `CandidateFinding` objects.
`CandidateFinding` exists for exactly this purpose: pre-verification type with
evidence fields and `discovery_reason`, without `verification_status`.

This supersedes ADR-017 D1. `ScanFinding` remains the post-verification type,
constructed only by `_to_scan_finding()`.

### D2. Track B routes through `_ENGINE.verify()` and `_to_scan_finding()`

Track B flow:

1. `HeuristicEngine.match(observations)` -> `list[HeuristicMatch]` (pure)
2. `HeuristicEngine.to_candidates(matches)` -> `list[CandidateFinding]` with
   `discovery_reason="heuristic:<sig_id>"`
3. Per candidate: `_ENGINE.verify(candidate)` -> `VerifiedFinding`
4. Per `VerifiedFinding`: `_to_scan_finding(verified)` -> `ScanFinding`
   (with `_engine_emitted=True`)
5. Append to `summary.findings`

This is the same path Track A uses (SSRF at scanner.py:745, GraphQL at
scanner.py:930+). It uses `_to_scan_finding()` -- the "correct" setter of
`_engine_emitted` per ADR-017 D2.

The legacy path via `_candidate_to_scan_finding()` (scanner.py:872) remains for
existing integration modules. Track B does not use it. A future ADR may unify
the two; out of M38's scope.

### D3. `HeuristicConfirmer` returns `unproven` with `candidate.discovery_reason`

New confirmer added to `_ENGINE`'s list: `HeuristicConfirmer`. Logic:

```python
def confirm(self, candidate):
    reason = candidate.discovery_reason or ""
    if reason.startswith("heuristic:"):
        return ConfirmerResult(unproven=True, reason=reason)
    return None
```

Placed **last** in the confirmer list, so:

- If `CorroboratorConfirmer` can promote (differential proves it), Track B's
  candidate gets `verified` -- per ADR-017 D3's "engine decides" contract.
- If no other confirmer fires, `HeuristicConfirmer` returns `unproven` with reason
  `"heuristic:HEUR-001"` -- matching ADR-017 D3's intent.
- If `discovery_reason` is None (Track A candidates), `HeuristicConfirmer`
  returns None -> existing `no_confirmer_matched` fallback fires -> zero
  behavior change for Track A.

### D4. `signals` field deferred to M40

ADR-017 D5 claimed `signals: list[str]` "already exists on ScanFinding" -- it
doesn't. ADR-019 D3 requires `result.properties.signals` in SARIF for M40. But
M38 doesn't need `signals` functionally: Track B findings render as `[unproven]`
via existing display code (test_cli_unproven_display.py), and `verification_reason`
already carries `heuristic:HEUR-001` for debugging.

M40 will add `signals` and wire `verification_reason="heuristic:X+Y"` ->
`signals=["X", "Y"]` parsing. Deferring keeps M38 small.

### D5. `--heuristic` CLI flag uses scanner-collected observations

Scanner gains `_collect_observations: bool` (default False). When True, `scan()`
appends `(url, body, headers)` per payload-loop response to `self._observations`.
After scan completes, `cmd_scan` (cli.py) runs the heuristic engine against those
observations.

Rationale: Track B does not need fresh network traffic -- the payload loop
already fetched every response we want to match. Re-fetching would double
request count and complicate pacer/waf interaction.

If a scan has no observations (target unreachable), `--heuristic` produces zero
candidates. Valid outcome; summary's negative-results reporting handles it.

## Consequences

**Positive:**
- ADR-017's semantic contract (Track B -> unproven, no direct promotion) preserved
- Track B uses same emission path as Track A -- no new anti-patterns
- `_engine_emitted` remains the sole-append-guard invariant (existing tests verify)
- M38 scope stays at ~250 lines code + ~200 lines tests
- `HeuristicConfirmer` addition extends existing confirmer pattern (no new machinery)

**Negative:**
- ADR-017's "already exists" claims are wrong; readers of ADR-017 without this
  ADR will be confused. Mitigation: cross-reference is explicit.
- `_candidate_to_scan_finding()` remains a parallel setter for `_engine_emitted`.
  Mitigation: this ADR records that the "sole setter" claim in ADR-017 D2 is
  aspirational, not enforced. Future cleanup deferred.
- `--heuristic` requires scanner to expose `_observations`. Mitigation:
  underscore-prefixed field, empty unless flag enables collection.

**Neutral:**
- M40 will add `signals` per ADR-019 D3. ADR-022 explicitly defers, does not block.
- `HeuristicConfirmer` registered in `_ENGINE` (scanner.py:305) is a one-line
  change. Track A behavior unchanged because confirmer only fires on
  `discovery_reason.startswith("heuristic:")`.

## References

- ADR-016 -- Verified vs Discovery vocabulary
- ADR-017 -- Heuristic emission model (amended by D1/D2/D5 here)
- ADR-019 -- Triage output format (signals deferred to M40 per D4)
- ADR-020 -- Frozen dataclasses
- src/janissary/verification/types.py -- CandidateFinding, VerifiedFinding
- src/janissary/verification/engine.py -- verify(), _promote()
- src/janissary/engine/scanner.py -- _to_scan_finding() (line 280),
  _candidate_to_scan_finding() (line 892)
- tests/unit/test_cli_unproven_display.py -- unproven marker tests
