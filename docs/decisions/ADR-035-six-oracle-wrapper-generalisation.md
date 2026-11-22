# ADR-035 — Generalise the six single-response oracle wrappers in scanner.py

**Status:** Proposed
**Date:** 2026-11-23
**Defects:** D-23 (GH#4 — six-oracle duplication is how findings get attributed to the wrong family)
**Related:** ADR-033 (evidence grading), ADR-034 (OOB DNS-vs-HTTP discrimination), D-7 (request-accounting contract), M83, M89

## Context

`scanner.py` contains 13 `CandidateFinding(` construction sites. D-23 asserts that "six oracles each restate the baseline-and-confirm shape, and the duplication is how findings get attributed to the wrong family." The classification pass resolves D-23's "six" against the tree.

### Sites in scope

Six sites wrap a call to a `check_*_oracle` detection function from `detection/analyzer.py`, each emitting at most one class per parameter:

| Site | Category | `payload_name` | `finding_type` | Detection function |
|---|---|---|---|---|
| L2072 | trustbound | `trustbound_marker` | `trustbound_session_oracle` | `check_trustbound_oracle` |
| L2109 | securecookie | `securecookie_flag_oracle` | `securecookie_flag_oracle` | `check_securecookie_oracle` |
| L2146 | weakrand | `weakrand_rng_oracle` | `weakrand_rng_oracle` | `check_weakrand_oracle` |
| L2331 | sqli | `sql_quote_oracle` | `sqli_quote_oracle` | `check_sqli_quote_oracle` |
| L2387 | xpathi | `xpath_error_oracle` | `xpathi_error_oracle` | `check_xpath_error_oracle` |
| L2431 | ldapi | `ldap_wildcard` | `ldap_injection` | `check_ldap_injection_oracle` |

Two of the six (L2109, L2146) have been inspected in full. Both have identical structure: the same fourteen `CandidateFinding` fields in the same order, the same `_ENGINE.verify()` call, the same `summary.record()` call, the same `_say()` block. They differ only in the detection function called and in the `payload_name` / `category` / `finding_type` / `severity` literals. The four uninspected sites resolve to the same literals through the classification pass. Per decision 6 below, all six must be inspected in full before any migration commit.

### Sites explicitly out of scope

| Site | Role | Why out of scope |
|---|---|---|
| L2507 | Paired-probe existence oracle (traversal) | Fires a payload, observes, then fires a second probe to confirm. Not single-response; the wrapper owns two requests, not one. |
| L1118 | SSRF phase | Builds candidates from OOB collaborator hits. Shape governed by ADR-034, not by the single-response pattern. |
| L2279 | Primary analyzer emission site | Sits inside the main scan loop after the `CORROBORATOR_ONLY_TYPES` and `payload_reflected` suppression gates. Carries `reflection_context` (a field the six do not). All literals are runtime-derived from the analyzer's per-finding output (`payload_name=name`, `category=category`, `finding_type=f.get("type", ...)`), not per-site literals. Default severity is `"low"`, not `"medium"` / `"high"`. Shares the routing layer with the six but not the construction layer. |
| L1902, L1951, L1993, L2037 | Four sites in the main scan loop's primary detectors | Clustered per-detector wrappers (SQLi, XSS, cmdi, etc.) that emit on the analyzer's own output rather than on a single-response baseline-versus-payload comparison. Structurally distinct from the six. Their relationship to D-23 is not established in this session and they are not in scope. |

The M83 Gate E fix of 2026-11-21 (commit `f9fbc1d`) is the class of bug D-23 names. Two of these six oracles (securecookie, weakrand) were falling through to `AnalyzerImplicitConfirmer`, and because each wrapper duplicated construction-and-verify, the fix required two changes — a new `OracleConfirmer` class and an insertion into the engine list — instead of one.

## Decision

1. Introduce one driver in `scanner.py`: `_emit_oracle_findings(detect, param, payload_value, response, snapshot, context, quiet, seen_guard=None)`. The driver owns the steps currently duplicated in each of the six wrappers:
   - Call `detect(baseline, response, ...)` to obtain hits.
   - For each hit, construct a `CandidateFinding` with the standard fourteen fields.
   - Call `_ENGINE.verify(candidate)`.
   - Route to `summary.record()` on `VerifiedFinding`, to `summary.candidates` on unproven, skip on failed (matching current behaviour at each site).
   - Convert to `ScanFinding` via `_to_scan_finding()`.
   - Emit the `_say()` line when not quiet.
   - Update the `seen_guard` set if a per-param-once guard is supplied.

2. Each of the six sites is reduced to a single driver call. The literals (`payload_name`, `category`, `finding_type`, `severity` default) become arguments.

3. The `seen_guard` argument preserves existing per-param-once behaviour (securecookie and weakrand fire once per parameter; the other four do not currently guard, and pass `None`).

4. Migration is per-site. The driver ships with a reference migration — **securecookie at L2109** — as the first site. The other five follow individually, one per commit.

5. No other `CandidateFinding(` site is touched. L2507, L1118, L2279, and L1902–L2037 stay as they are.

6. **Before the first migration commit**, all six sites (L2072, L2109, L2146, L2331, L2387, L2431) are read in full and documented in the migration PR. If any site does not match the shape seen at L2109 and L2146, it is removed from the migration scope and D-23 is re-examined for the correct count. This precondition exists because four of the six shapes are currently inferred from the classification pass, not confirmed by reading the wrapper bodies.

7. `CandidateFinding`, `_ENGINE`'s confirmer list, `summary.record()`, `summary.candidates`, `_say()`, `_to_scan_finding()`, and the `_VerifiedFindingsList` / `_UnprovenFindingsList` guards remain unchanged.

## Gate

- All six sites (L2072, L2109, L2146, L2331, L2387, L2431) inspected in full and documented in the reference migration PR. Migration does not proceed if any site does not match the pattern.
- `tests/unit/test_oracle_driver.py`: driver routes verified to `record()`, unproven to `candidates`, emits the quiet line only when `--quiet` is not set, and suppresses second hits when `seen_guard` is supplied.
- Per-site parity test: for each migrated site, the driver produces a `ScanFinding` byte-identical to the pre-migration path for the same fixture — same `finding_type`, `severity`, `evidence_grade`, `detail`, `payload_name`, `raw_request`, `raw_response`.
- M89 delta 0 after each migration commit, not only at the end.
- Per-class recall on M89 unchanged or better, measured per class.
- Zero new false positives on M89.
- Full unit suite green, ruff clean, both stream guards (`_VerifiedFindingsList`, `_UnprovenFindingsList`) still enforced.
- The reference migration (securecookie) is M89-verified before the second site is touched.

## Consequences

- The misattribution class D-23 names is closed by construction for the six single-response oracles: one code path builds `CandidateFinding` for any of the six. A future single-response oracle is a `check_*_oracle` function plus a driver call, not a 40-line wrapper.
- The M83 Gate E fix (`f9fbc1d`) becomes a single change at the driver rather than a two-place change.
- Cost: one driver function (~40 lines), six migration commits, one parity test per site, one inspection commit.
- Risk: the driver accumulates per-oracle branches as future sites need quirks. Mitigation: any per-oracle behaviour enters the driver through arguments, not through `if finding_type == ...` branches. Review checklist item enforced on every migration PR.
- Risk: the parity fixture is incomplete and drift escapes it. Mitigation: the M89 delta-0 gate after every migration commit is the backstop. A drift that escapes both the parity fixture and M89 would be a new class of defect and warrants its own register entry.
- The routing layer that L2279 shares with the six is not extracted by this ADR. If a future defect traces to that duplication, extracting the routing layer alone — leaving construction separate at L2279 — is a smaller refactor available then.

## Alternatives considered

- **Leave the six in place.** Rejected: D-23 and the M83 Gate E fix both name the same defect. Two-place changes per oracle-level fix accumulate.
- **Extract a shared base class instead of a driver.** Rejected: a base class allows each subclass to override construction, which is where drift lives. One driver with one construction site closes the class.
- **Generalise all 13 `CandidateFinding(` sites.** Rejected: the other seven are not single-response oracles. L2507 is a paired probe. L1118 is the SSRF phase. L2279 carries `reflection_context` and runtime-derived literals. L1902–L2037 are per-detector wrappers. Forcing them through one driver would fit a shape they do not have.
- **Extract only the routing layer (verify → record → say), leaving construction per-site.** Rejected as the primary approach: construction is where the literals and the field order live, and the duplication D-23 names is construction-and-routing together, not routing alone. Noted as a fallback under Consequences.
- **Single-commit rewrite of all six.** Rejected: an M89 regression would be unattributable to a single oracle.

## Refs

- `scanner.py` L2072, L2109, L2146, L2331, L2387, L2431 (the six sites in scope)
- `scanner.py` L2507 (paired-probe traversal — out of scope)
- `scanner.py` L1118 (SSRF phase — out of scope, ADR-034)
- `scanner.py` L2279 (primary analyzer emission site — out of scope, identified by full inspection)
- `scanner.py` L1902, L1951, L1993, L2037 (primary detector wrappers — out of scope)
- `scanner.py` L409–L447, L516–L542 (stream guards, unchanged)
- `confirmers.py` (`OracleConfirmer` inserted in `f9fbc1d`)
- `detection/analyzer.py` L854 (`check_sqli_quote_oracle`), L891 (`check_xpath_error_oracle`), L947 (`check_weakrand_oracle`), L1002 (`check_trustbound_oracle`), L1068 (`check_securecookie_oracle`), L1112 (`check_ldap_injection_oracle`)
- ADR-033 (evidence grading vocabulary used by the parity test)
- ADR-034 (SSRF phase and specialised confirmer shape)
- D-23 register entry (`docs/MILESTONE-REGISTER-COLLATED.md` line 70)
- M89 corpus and M89 delta gate