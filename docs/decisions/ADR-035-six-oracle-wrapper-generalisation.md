# ADR-035 — Generalise the six oracle wrappers in engine/scanner.py (tiered migration)

**Status:** Proposed
**Date:** 2026-11-23 (amended 2026-11-24)
**Defects:** D-23 (GH#4 — six-oracle duplication is how findings get attributed to the wrong family)
**Related:** ADR-033 (evidence grading), ADR-034 (OOB DNS-vs-HTTP discrimination), D-7, M83, M89

## Context

`src/janissary/engine/scanner.py` contains 13 `CandidateFinding(` construction sites. D-23 asserts that "six oracles each restate the baseline-and-confirm shape." The original draft of this ADR treated all six as a single-shape class; the classification pass of 2026-11-23 resolved them into three tiers.

### Site classification (all 13 sites inspected 2026-11-23)

| Site | Description | Classification |
|---|---|---|
| L1170 | SSRF OOB collaborator phase | Out of scope (ADR-034) |
| L1970 | Traversal collapse oracle | Out of scope |
| L2019 | LFI content oracle | Out of scope |
| L2061 | SSRF response-body oracle | Out of scope |
| L2105 | Blind SQLi paired true/false oracle | Out of scope |
| L2140 | trustbound — `check_trustbound_oracle` | **Tier A** |
| L2177 | securecookie — `check_securecookie_oracle` | **Tier A** |
| L2214 | weakrand — `check_weakrand_oracle` | **Tier A** |
| L2347 | Analyzer primary-detector emitter | Out of scope |
| L2399 | sqli — `check_sqli_quote_oracle` | **Tier B** |
| L2455 | xpathi — `check_xpath_error_oracle` | **Tier B** |
| L2499 | ldapi — `check_ldap_injection_oracle` | **Tier C** |
| L2576 | pathtraver existence (r2/noexist probe) | Out of scope |

### Tier definitions

**Tier A (L2140, L2177, L2214)** — single-response in-loop oracles. The oracle function receives the baseline and the current observation and returns hits in one call. This is the shape D-23 describes.

The three do not share a detect signature, and the earlier draft's claim that they do is why this ADR needed a second pass:

| Site | Oracle | Signature |
|---|---|---|
| L2140 | `check_trustbound_oracle` | `(baseline, snapshot, marker)` |
| L2177 | `check_securecookie_oracle` | `(baseline, response, marker)` |
| L2214 | `check_weakrand_oracle` | `(baseline, snapshot)` |

Two take a third marker argument and one does not, and the two that do disagree on whether the second argument is a `ResponseSnapshot` or an http response. The driver therefore carries the shape explicitly — `snapshot+marker`, `response+marker`, `snapshot` — instead of assuming one.

**Tier B (L2399, L2455)** — paired multi-snapshot oracles. The oracle requires two observations (quote plus OR-bypass for SQLi; error plus reflection for XPath) before emitting. Not single-response in the tier-A sense.

**Tier C (L2499)** — deferred snapshot oracle. The wildcard snapshot is cleared after hit. Additionally, L2499 carries a duplicate `_say` emit block at 2532–2538 which is noted but not fixed by this ADR.

### Corrections to the original ADR-035 draft

Ten corrections apply against the previous version:

1. **Path** — `scanner.py` → `src/janissary/engine/scanner.py`
2. **Tier split** — the original treated all six as one shape. Tier A/B/C split reflects the observed structure.
3. **Field count** — `CandidateFinding` takes ~15 kwargs, not "fourteen." No `evidence_grade` or `reflection_context` at these sites.
4. **Routing** — none of the six sites routes `UnprovenVerification → candidates`. The original draft implied this; it is false.
5. **L2499 double-`_say`** — noted, out of scope for this ADR.
6. **L2347** — classified as analyzer primary-detector emitter, out of scope.
7. **Driver signature** — the draft's `(detect, param, payload_value, response, snapshot, context, quiet, seen_guard=None)` does not hold. There is no `context` object: `baseline` is a separate argument because two of the three oracles read it, `shape` carries the arity difference, and `target`, `method` and `summary` are passed rather than reached for so the driver stays a module-level function. The real signature is in Decision 2.
8. **Signature parity** — the draft claimed all three tier A oracles share a detect signature. They do not; see the tier table.

## Decision

1. **First implementation scope: Tier A only** (L2140, L2177, L2214).
2. Introduce one driver in `engine/scanner.py`: `_emit_oracle_findings(detect, *, param, payload_value, response, snapshot, baseline, shape, payload_name, category, finding_type, severity, target, method, summary, quiet, seen_guard=None)`. The driver owns the construction-and-routing steps for tier A sites. Everything after `detect` is keyword-only: at this width a positional call is unreadable and one transposed pair would pass silently.
3. Each tier A site becomes a single driver call, passing the `check_*_oracle` function, its `shape`, and the four literals (`payload_name`, `category`, `finding_type`, `severity` default).
4. `seen_guard` is an `_OracleSeenGuard` instance owned by `scan()`, not a bool: the driver would only rebind a bool, so the latch could never travel back out. The guard trips when the oracle returns hits, not when a hit verifies — which is what the `weakrand_seen` flag meant before migration.
5. Migration is per-site, tier A only. Reference migration: **securecookie at L2177**.
6. **Tier B and Tier C are deferred** to a follow-up ADR or an explicit Accept of amended scope. This ADR does not commit to their migration.
7. The L2499 double-`_say` bug at 2532–2538 is noted. Fixing it is out of scope. Recommend a new defect entry (D-31).
8. `CandidateFinding`, `_ENGINE`, `summary.record()`, `summary.candidates`, `_say()`, `_to_scan_finding()`, and both stream guards remain unchanged.

## Gate

- Tier A sites (L2140, L2177, L2214) inspected in full and documented in the reference migration PR.
- `tests/unit/test_oracle_driver.py`: driver routes verified findings to `record()`, emits the quiet line only when not quiet, suppresses every hit after the first when a `seen_guard` is supplied, trips the guard even when nothing verifies, and feeds each shape the arguments its oracle declares.
- Driver neutrality is proved before any migration: `test_driver_matches_legacy_securecookie_field_for_field` compares the driver against a frozen copy of the pre-migration site body and requires an equal `ScanFinding`, equal `_say` arguments and an equal serialiser call order.
- Per-site parity test for each tier A migration: byte-identical `ScanFinding` for same fixture — same `finding_type`, `severity`, `detail`, `payload_name`, `raw_request`, `raw_response`.
- M89 delta 0 after each tier A migration commit.
- Per-class recall on M89 unchanged or better, measured per class.
- Zero new false positives on M89.
- Full suite green, ruff clean, both stream guards enforced.
- Reference migration (securecookie) M89-verified before the second tier A site is touched.
- **Tier B and Tier C migrations require a separate ADR or an explicit Accept of an expanded scope. They are not gated by this ADR.**

## Consequences

- D-23's misattribution class is closed for tier A. Tier B and tier C remain as noted.
- The M83 Gate E fix (`f9fbc1d`) becomes a single change at the driver for tier A oracles.
- Cost: one driver function, three migration commits, one inspection pass. Tier B/C deferred.
- Risk: the driver accumulates per-oracle branches as future sites need quirks. Mitigation: the three tier-A shapes are enumerated in the driver and in the tier table above, so a fourth shape is a visible change to both; a site needing anything beyond an argument shape belongs in tier B/C scope, not as a new tier A argument.
- Risk: the parity fixture is incomplete and drift escapes it. Mitigation: M89 delta-0 after each migration commit.

## Alternatives considered

- **Generalise all six in one ADR** (original draft's scope). Rejected: tier B and tier C have different detect signatures. Forcing them into a shared driver now would either lose their multi-snapshot behaviour or bloat the driver with per-tier branches.
- **Defer tier A until tier B/C scope is clarified.** Rejected: tier A is clean and low-risk; deferring it delays D-23 closure for no gain.
- **Leave the six in place.** Rejected: D-23 and the M83 Gate E fix both name the defect.
- **Extract a base class.** Rejected: subclass overrides reintroduce drift. One driver with one construction site closes the class.
- **Extract routing only, leaving construction per-site.** Noted as fallback under Consequences.

## Refs

- `engine/scanner.py` L2140, L2177, L2214 (tier A)
- `engine/scanner.py` L2399, L2455 (tier B — deferred)
- `engine/scanner.py` L2499 (tier C — deferred; double-`_say` at 2532–2538)
- `engine/scanner.py` L2576, L1170, L2347, L1970, L2019, L2061, L2105 (out of scope)
- `engine/scanner.py` L453–L456, L536–L545 (stream guards)
- `verification/confirmers.py` (`OracleConfirmer` from `f9fbc1d`)
- `detection/analyzer.py` L1002 (`check_trustbound_oracle`), L1068 (`check_securecookie_oracle`), L947 (`check_weakrand_oracle`) — tier A
- `engine/scanner.py` L382–L479 (the driver and `_OracleSeenGuard`)
- `tests/unit/test_oracle_driver.py` (five tests, including the neutrality parity test)
- `detection/analyzer.py` L854 (`check_sqli_quote_oracle`), L891 (`check_xpath_error_oracle`) — tier B
- `detection/analyzer.py` L1112 (`check_ldap_injection_oracle`) — tier C
- ADR-033 (evidence grading), ADR-034 (SSRF phase shape)
- D-23 register entry (`docs/MILESTONE-REGISTER-COLLATED.md`)
- M89 corpus and M89 delta gate
