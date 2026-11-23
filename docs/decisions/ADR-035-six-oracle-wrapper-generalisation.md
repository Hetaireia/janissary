# ADR-035 — Generalise the six oracle wrappers in engine/scanner.py (tiered migration)

**Status:** Proposed
**Date:** 2026-11-23 (amended 2026-11-23)
**Defects:** D-23 (GH#4 — six-oracle duplication is how findings get attributed to the wrong family)
**Related:** ADR-033 (evidence grading), ADR-034 (OOB DNS-vs-HTTP discrimination), D-7, M83, M89

## Context

`src/janissary/engine/scanner.py` contains 13 `CandidateFinding(` construction sites. D-23 asserts that "six oracles each restate the baseline-and-confirm shape." The original draft of this ADR treated all six as a single-shape class; the classification pass of 2026-11-23 resolved them into three tiers.

### Site classification (all 13 sites inspected 2026-11-23)

| Site | Description | Classification |
|---|---|---|
| L1118 | SSRF OOB collaborator phase | Out of scope (ADR-034) |
| L1902 | Traversal collapse oracle | Out of scope |
| L1951 | LFI content oracle | Out of scope |
| L1993 | SSRF response-body oracle | Out of scope |
| L2037 | Blind SQLi paired true/false oracle | Out of scope |
| L2072 | trustbound — `check_trustbound_oracle` | **Tier A** |
| L2109 | securecookie — `check_securecookie_oracle` | **Tier A** |
| L2146 | weakrand — `check_weakrand_oracle` | **Tier A** |
| L2279 | Analyzer primary-detector emitter | Out of scope |
| L2331 | sqli — `check_sqli_quote_oracle` | **Tier B** |
| L2387 | xpathi — `check_xpath_error_oracle` | **Tier B** |
| L2431 | ldapi — `check_ldap_injection_oracle` | **Tier C** |
| L2507 | pathtraver existence (r2/noexist probe) | Out of scope |

### Tier definitions

**Tier A (L2072, L2109, L2146)** — single-response in-loop oracles. The oracle function receives the baseline and the current response, and returns hits in one call. Same detect signature across all three. This is the shape D-23 describes.

**Tier B (L2331, L2387)** — paired multi-snapshot oracles. The oracle requires two observations (quote plus OR-bypass for SQLi; error plus reflection for XPath) before emitting. Not single-response in the tier-A sense.

**Tier C (L2431)** — deferred snapshot oracle. The wildcard snapshot is cleared after hit. Additionally, L2431 carries a duplicate `_say` emit block at 2453–2469 which is noted but not fixed by this ADR.

### Corrections to the original ADR-035 draft

Six corrections apply against the previous version:

1. **Path** — `src/janissary/scanner.py` → `src/janissary/engine/scanner.py`
2. **Tier split** — the original treated all six as one shape. Tier A/B/C split reflects the observed structure.
3. **Field count** — `CandidateFinding` takes ~15 kwargs, not "fourteen." No `evidence_grade` or `reflection_context` at these sites.
4. **Routing** — none of the six sites routes `UnprovenVerification → candidates`. The original draft implied this; it is false.
5. **L2431 double-`_say`** — noted, out of scope for this ADR.
6. **L2279** — classified as analyzer primary-detector emitter, out of scope.

## Decision

1. **First implementation scope: Tier A only** (L2072, L2109, L2146).
2. Introduce one driver in `engine/scanner.py`: `_emit_oracle_findings(detect, param, payload_value, response, snapshot, context, quiet, seen_guard=None)`. The driver owns the construction-and-routing steps for tier A sites.
3. Each tier A site becomes a single driver call, passing the `check_*_oracle` function and the four literals (`payload_name`, `category`, `finding_type`, `severity` default).
4. Migration is per-site, tier A only. Reference migration: **securecookie at L2109**.
5. **Tier B and Tier C are deferred** to a follow-up ADR or an explicit Accept of amended scope. This ADR does not commit to their migration.
6. The L2431 double-`_say` bug at 2453–2469 is noted. Fixing it is out of scope. Recommend a new defect entry (D-31).
7. `CandidateFinding`, `_ENGINE`, `summary.record()`, `summary.candidates`, `_say()`, `_to_scan_finding()`, and both stream guards remain unchanged.

## Gate

- Tier A sites (L2072, L2109, L2146) inspected in full and documented in the reference migration PR.
- `tests/unit/test_oracle_driver.py`: driver routes verified to `record()`, emits the quiet line only when not quiet, suppresses second hits when `seen_guard` is supplied.
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
- Risk: the driver accumulates per-oracle branches as future sites need quirks. Mitigation: tier A sites share signature by definition; a site needing new behaviour belongs in tier B/C scope, not as a new tier A argument.
- Risk: the parity fixture is incomplete and drift escapes it. Mitigation: M89 delta-0 after each migration commit.

## Alternatives considered

- **Generalise all six in one ADR** (original draft's scope). Rejected: tier B and tier C have different detect signatures. Forcing them into a shared driver now would either lose their multi-snapshot behaviour or bloat the driver with per-tier branches.
- **Defer tier A until tier B/C scope is clarified.** Rejected: tier A is clean and low-risk; deferring it delays D-23 closure for no gain.
- **Leave the six in place.** Rejected: D-23 and the M83 Gate E fix both name the defect.
- **Extract a base class.** Rejected: subclass overrides reintroduce drift. One driver with one construction site closes the class.
- **Extract routing only, leaving construction per-site.** Noted as fallback under Consequences.

## Refs

- `engine/scanner.py` L2072, L2109, L2146 (tier A)
- `engine/scanner.py` L2331, L2387 (tier B — deferred)
- `engine/scanner.py` L2431 (tier C — deferred; double-`_say` at 2453–2469)
- `engine/scanner.py` L2507, L1118, L2279, L1902, L1951, L1993, L2037 (out of scope)
- `engine/scanner.py` L409–L447, L516–L542 (stream guards)
- `verification/confirmers.py` (`OracleConfirmer` from `f9fbc1d`)
- `detection/analyzer.py` L1002 (`check_trustbound_oracle`), L1068 (`check_securecookie_oracle`), L947 (`check_weakrand_oracle`) — tier A
- `detection/analyzer.py` L854 (`check_sqli_quote_oracle`), L891 (`check_xpath_error_oracle`) — tier B
- `detection/analyzer.py` L1112 (`check_ldap_injection_oracle`) — tier C
- ADR-033 (evidence grading), ADR-034 (SSRF phase shape)
- D-23 register entry (`docs/MILESTONE-REGISTER-COLLATED.md`)
- M89 corpus and M89 delta gate