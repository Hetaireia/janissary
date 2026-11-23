# ADR-036 — Split request counts into measured and estimated, with deprecated aliases

**Status:** Proposed
**Date:** 2026-11-23
**Defects:** D-7 (C-1 — summary.total_requests mixes measured and estimated counts)
**Related:** D-25 (SARIF approximateRequests precedent), ADR-001 (benchmark methodology), ADR-008 (SARIF enterprise parity), ADR-019 (triage output), D-5, D-6, D-26..D-30 (all gated on D-7)

## Context

Measured from the tree, not assumed:

- ScanSummary declares total_requests: int = 0 (scanner.py:557) and approximate_requests: int = 0 (scanner.py:562). The comment at 559-561 states that total_requests is "measured per-call" and approximate_requests is "formula-based estimate for modules without HTTP instrumentation (host-bypass, WebSocket protocol probes, GraphQL detect/probes)."
- Fifteen write sites target one of the two fields:
  - Eight into total_requests with += 1 (1026, 1050, 1187, 1335, 1405, 1712, 1786, 2483) — structurally measured
  - Two into total_requests with computed counts (1723: += len(self.waf_profile.probes), 1751: += self.baseline_count) — structurally estimated, but written to the measured field
  - Four into approximate_requests with computed counts (1202, 1231, 1352, 1369)
  - One overwrite, not increment: 1297 approximate_requests = 3
- Merge sites at cli.py:259-260, 298-299, 323-324 propagate both fields from sub-scans (GraphQL, WebSocket, host-bypass) into the primary summary.
- Consumers reading total_requests without knowing the mix: CLI prints at cli.py:125, 144, 1346. The JSON envelope (83-84) and SARIF (1724-1725) carry both fields, but downstream code is free to read total_requests alone and receive a number that includes configuration-derived counts.

Consequence: a scan that ran 100 measured requests plus a WAF phase with 20 configured probes and 3 baseline samples reports total_requests = 123. No consumer can tell that 23 of those were never individually observed.

Register S8 states: "absorbing Tier A before this fix permanently corrupts the denominator." Register S9 ranks D-7 as item 0. D-26..D-30 (minted 2026-11-23) each carry a "M89 delta 0" gate and cannot be measured cleanly until the denominator is honest.

## Decision

1. **Two-phase data model change.** ScanSummary gains three new fields and loses two writable fields across two releases.

Phase 1 (v7.11.3):
- Add requests_measured: int = 0 — count of observed HTTP responses, incremented once per emission
- Add requests_estimated: int = 0 — count derived from formula or configuration, for phases lacking per-response instrumentation
- Add requests_estimated_breakdown: dict[str, int] = field(default_factory=dict) — per-source sub-counts for debugging
- Convert total_requests and approximate_requests to read-only computed properties:

    @property
    def total_requests(self) -> int:
        # Deprecated: use requests_measured + requests_estimated. Removed in 7.12.0.
        return self.requests_measured + self.requests_estimated

    @property
    def approximate_requests(self) -> int:
        # Deprecated: use requests_estimated. Removed in 7.12.0.
        return self.requests_estimated

Phase 2 (v7.12.0):
- Remove total_requests and approximate_requests from ScanSummary, JSON envelope, and SARIF invocation.properties. Gate for Phase 2 defined in its own ADR.

2. **Every write site is rewritten in Phase 1.** No site continues to write total_requests or approximate_requests. Each of the 15 sites is rewritten to target requests_measured or requests_estimated explicitly. The pre-classification below is derived from the grep of total_requests|approximate_requests in scanner.py (2026-11-23). "Audit" columns are confirmed by reading the enclosing function in Phase 1; "Pre-classified" columns are definitive from the write expression alone.

| Line | Current write | Pre-classified | Audit required |
|---|---|---|---|
| 1026 | total_requests += 1 | MEASURED | Yes — confirm enclosing call corresponds to observed response |
| 1050 | total_requests += 1 | MEASURED | Yes — same |
| 1187 | total_requests += 1 | MEASURED | Yes — same |
| 1202 | approximate_requests += len(payloads) + 2 | ESTIMATED | No — formula-derived |
| 1231 | approximate_requests += max(len(candidates) * 2, 10) | ESTIMATED | No — formula-derived |
| 1297 | approximate_requests = 3 (overwrite) | ESTIMATED | No — preserved as-is (Decision 4) |
| 1335 | total_requests += 1 | MEASURED | Yes — same |
| 1352 | approximate_requests += (...) | ESTIMATED | No — formula-derived |
| 1369 | approximate_requests += 6 | ESTIMATED | No — formula-derived |
| 1405 | total_requests += 1 | MEASURED | Yes — same |
| 1712 | total_requests += 1 | MEASURED | Yes — same |
| 1723 | total_requests += len(self.waf_profile.probes) | ESTIMATED (currently mis-filed) | No — this is the bug |
| 1751 | total_requests += self.baseline_count | ESTIMATED (currently mis-filed) | No — this is the bug |
| 1786 | total_requests += 1 | MEASURED | Yes — same |
| 2483 | total_requests += 1 | MEASURED | Yes — same |

After Phase 1: 8 MEASURED sites write requests_measured += 1. 7 ESTIMATED sites write requests_estimated += <value> and record requests_estimated_breakdown[<key>] += <value>. The two mis-filed sites (1723, 1751) migrate from total_requests to requests_estimated — that migration is the bug fix.

3. **Audit requirement.** Before any Phase 1 write-site change, each of the 15 sites is read in full — enclosing function, loop structure, whether the code path is instrumented elsewhere. Two classifications are possible:

- MEASURED — the increment corresponds one-to-one with an HTTP response the scanner observes and records evidence for
- ESTIMATED — the increment is computed from configuration, a payload-list length, or a formula

Sites that are individually ambiguous (a += 1 inside a loop over configured items rather than over received responses) are reclassified as ESTIMATED unless the loop body is confirmed to correspond to observed responses.

If a phase has BOTH an instrumented per-response += 1 and a formula-based +=, the formula-based site is removed (double-count fix) and the phase's count is measured only.

4. **The overwrite at 1297 is preserved as an overwrite.** approximate_requests = 3 becomes requests_estimated = 3. Its overwrite semantics (reset, not increment) are preserved exactly; if this site's overwrite is a bug, it is a separate defect and out of this ADR's scope.

5. **requests_estimated_breakdown key convention.** Keys are stable identifiers declared in a single frozenset in the module:

    _ESTIMATE_SOURCES = frozenset({
        "waf_probe", "baseline", "graphql_detect", "graphql_probe",
        "websocket_protocol_probe", "host_bypass_probe",
    })

Writes not in the frozenset raise ValueError at write time to prevent drift.

6. **Consumer changes (Phase 1).**

Internal:
- CLI prints at cli.py:125, 144, 1346 updated to show both counts explicitly.

  Before (cli.py:125): Total requests:  123
  After (cli.py:125): Total requests:  123  (measured: 100, estimated: 23)

  Before (cli.py:144): 123 request(s); target responded normally.
  After (cli.py:144): 100 measured request(s) (23 estimated); target responded normally.

  Before (cli.py:1346): [*] Total requests:    123
  After (cli.py:1346): [*] Total requests:    123  (measured: 100, estimated: 23)

- Merge sites at cli.py:259-260, 298-299, 323-324 rewritten to add requests_measured and requests_estimated, and to merge requests_estimated_breakdown by key.
- JSON envelope at cli.py:83-84 extended to carry requests_measured, requests_estimated, requests_estimated_breakdown alongside the existing total_requests and approximate_requests.
- SARIF at cli.py:1724-1725 extended to carry requestsMeasured and requestsEstimated alongside the existing totalRequests and approximateRequests.

External:
- total_requests and approximate_requests continue to appear at every consumer, sourced from the read-only properties. Downstream tooling is unaffected in Phase 1.

7. **Test changes (Phase 1).** Every test file reading or writing these fields:

| File | Tests to inspect | Likely change |
|---|---|---|
| test_sarif_output.py | ~6 (lines 19, 182, 185, 186, 190, 191) | One already updated in D-25; add assertions for requestsMeasured and requestsEstimated in SARIF invocation.properties |
| test_summary_merge.py | 5 (lines 36, 41, 46, 47, 49, 115, 118) | Assert merge sums all three new fields; add a case where breakdown keys collide and must sum |
| test_ws_cli.py | 3 (lines 43, 96-105) | Verify WebSocket sub-summary's estimates flow through merge |
| test_graphql_cli.py | 3 (lines 61, 83-87) | Verify GraphQL sub-summary's estimates flow through merge |
| test_host_bypass.py | 1 (line 332-333) | Verify host-bypass sub-summary's estimates flow through merge |
| test_scanner.py | 1 (line 280) | Rewrite s.total_requests = N to target the measured or estimated field based on the test's intent |
| test_ssrf.py | 2 (lines 290, 292) | Same |
| test_negative_results.py | 1 (line 16) | Same |
| test_negative_result_with_candidates.py | 1 (lines 46-48) | Same |
| test_m75_routing.py | 1 (line 59) | JSON envelope assertions; extend to new fields |
| test_scanner_probe_evidence.py | 1 (line 171) | Same |
| test_sqli_union.py | 1 (line 261) | Same |
| test_scanner_recon.py | 1 (line 93) | Same |
| test_scanner_tri_session.py | 1 (lines 28, 63) | Same |

New file tests/unit/test_request_count_provenance.py with five invariants:

1. s.total_requests == s.requests_measured + s.requests_estimated
2. s.approximate_requests == s.requests_estimated
3. s.total_requests = 5 raises AttributeError (property is read-only)
4. s.requests_estimated_breakdown["invalid_key"] = 1 raises ValueError at write time
5. merge(a, b).requests_estimated_breakdown[k] == a.breakdown[k] + b.breakdown[k] for every key in _ESTIMATE_SOURCES

8. **Phase 2 gating.** Removal of total_requests and approximate_requests is gated on a separate ADR (proposed 7.12.0). This ADR does not authorise Phase 2.

## Gate

Phase 1 (this ADR's scope):

- Audit complete: all 15 write sites classified as MEASURED or ESTIMATED, with the classification recorded in code comments
- No site writes total_requests or approximate_requests (both are read-only properties)
- CLI prints show both counts explicitly on all three lines (cli.py:125, 144, 1346)
- JSON envelope carries total_requests, approximate_requests, requests_measured, requests_estimated, requests_estimated_breakdown
- SARIF invocation.properties carries totalRequests, approximateRequests, requestsMeasured, requestsEstimated
- Merge sites propagate all three new fields; a merge test verifies (10 measured, 5 estimated) + (3 measured, 2 estimated) = (13 measured, 7 estimated)
- Full unit suite green
- M89 delta 0 (the measured denominator is unchanged; estimated counts do not enter M89 scoring)
- Ruff clean
- For every phase that was previously estimated AND is now instrumented elsewhere, the formula-based site is removed and that phase's contribution to requests_estimated is zero

Phase 2 (separate ADR, target 7.12.0):
- To be specified in its own ADR

## Consequences

- The mixed denominator that register S8 names as a blocker for M89 rescoring is closed. D-26..D-30 can be measured.
- Downstream tooling that reads total_requests from JSON continues to work in 7.11.3 via the computed property. Migration to explicit measured/estimated reads is optional in 7.11.3 and required by 7.12.0.
- Cost: one dataclass rewrite (fields to properties), 15 write-site rewrites with per-site audit, ~15 test rewrites, 2 consumer extensions (CLI print + envelope), one new test file.
- Risk: an estimated site that is actually measured (or vice versa) is misclassified in the audit. Mitigation: the audit is a formal review step with per-site justification in the PR; M89 delta 0 catches gross errors.
- Risk: requests_estimated_breakdown drift. Mitigation: frozenset rejection raises at write time.
- Risk: external consumers depend on approximate_requests being an actual field. Mitigation: computed property preserves read access; the field was never writable via a public API; the only writers are internal call sites that are rewritten in Phase 1.
- Risk: requests_estimated includes estimates that are exact counts (e.g. baseline_count matches actual requests). Mitigation: the audit's MEASURED classification is available for sites confirmed to correspond one-to-one with observed responses; exact but config-derived counts remain ESTIMATED unless the audit reclassifies them.

## Alternatives considered

- Option A — provenance tag only (total_requests_provenance: str). Rejected: labels the bug rather than fixing it. CLI prints still show the mixed number; consumers still cannot separate the components.
- Option D — RequestCount dataclass with measured, estimated, sources on every increment. Rejected: over-engineered for two integers. The three-field approach is equivalent information at lower complexity.
- Keep total_requests writable in Phase 1. Rejected: allows new code to reintroduce the mix. Read-only property is the invariant.
- Single-phase change (add fields and remove aliases at once). Rejected: breaks downstream consumers without a deprecation window. The two-phase approach lets external tooling migrate.

## Refs

- scanner.py:550-580 (ScanSummary dataclass)
- scanner.py write sites: 1026, 1050, 1187, 1202, 1231, 1297, 1335, 1352, 1369, 1405, 1712, 1723, 1751, 1786, 2483
- cli.py:83-84 (JSON envelope), 125, 144, 1346 (CLI prints), 259-260, 298-299, 323-324 (merge sites), 1724-1725 (SARIF)
- ADR-001 (benchmark methodology), ADR-008 (SARIF enterprise parity), ADR-019 (triage output)
- D-7 register entry (docs/MILESTONE-REGISTER-COLLATED.md line 54)
- D-25 (SARIF approximateRequests precedent, commit 3350aa5)
- M89 corpus and delta gate
- D-26..D-30 (minted 2026-11-23, all gated on D-7)
