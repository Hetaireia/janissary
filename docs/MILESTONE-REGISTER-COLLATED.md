import os

docs = "## JANISSARY — Consolidated Milestone & Evidence Register
**Revision:** 2026-11-18 (Revision 4)
**Authority:** This document is the authoritative collation of registered, proposed, and unreconciled milestones as of this date.

## 1. The Three-Tier Milestone Reality
The dashboard visually combines 108 milestones. For governance purposes, they must be treated as three distinct tiers:

| Tier | Range | Status | Count |
|---|---|---|---|
| 1 | M1-M90 | Registered Baseline (Approved) | 90 |
| 2 | M91-M99 | Proposed-Unapproved | 9 |
| 3 | M100-M108 | Unreconciled (Dashboard Only) | 9 |

## 2. Verified Status - M1-M90
The following is the extracted status of each approved milestone as per the dashboard and register.

### Verified-Delivered
M82a, M82b

### Verified-Policy
M12

### Verified-Partial
M37, M76, M83, M84

### Claimed-Delivered (Dashboard)
M1–M15, M17, M19, M20, M21, M22, M23, M25, M26, M27, M28, M29, M30, M31, M32, M35, M36, M38, M61, M62, M63, M64, M65, M66, M67, M68, M69, M70, M71, M73, M74, M75, M77, M78, M79, M80, M81, M82

### Claimed-Pending (Dashboard)
M16, M24, M33, M34, M39, M40, M41, M42, M43, M44, M45, M46, M47, M48, M49, M50, M51, M52, M53, M54, M55, M56, M57, M58, M59, M60, M72, M85, M86, M87, M88, M89, M90

### No-Implementation-Identified
M39, M85, M86, M87, M88, M89, M90

## 3. Proposed-Unapproved (M91-M99)
M91, M92, M93, M94, M95, M96, M97, M98, M99

## 4. Unreconciled (M100-M108)
M100, M101, M102, M103, M104, M105, M106, M107, M108

## 5. Discrepancies (D-Items)
This section records all known anomalies and defects requiring resolution.

| ID | Description | Status |
|---|---|---|
| D-1 | Milestone ID collision (M37, M89, M82a) | Open |
| D-2 | ADR-018 references non-existent ADR-025 | Open |
| D-3 | Duplicate ascension documents | Open |
| D-4 | Malformed nested directory | Open |
| --= | --- | --- |
| D-13 | VerificationEngine docstring stale | Open |
| D-14 | Case count 2,258 vs 2,740 | Open |
| D-15 | F1 0.922 is a rescore, not clean-exit run | Open |
| D-16 | README bom and protected lines | Open |
| D-17 | ADR-027 candidate-only ambiguity | Open |
| D-18 | FN-12 milestone attribution | Open |
| D-19 | .gitignore drops __init__.py | Open |
| D-20 | Pre-commit hooks not installed | Resolved (Hooks fire, confirmed) |

## 6. Path Traversal Disclosure
Path traversal detection is implemented, including a paired-probe existence oracle and verification through the normal finding boundary. However, measured recall on the current OWASP Benchmark path-traversal corpus is low (0.075). Path traversal remains included in the DAST-applicable headline score and is excluded from the supplemental supported-classes score, as defined by ADR-027. These scopes are reported separately to avoid obscuring the limitation.

Per-category F1: pathtraver-01 (0.049), pathtraver-02 (0.154), pathtraver-00 (0.160), pathtraver-03 (0.308).

## 7. Known Limitations
*Honesty over assumptions. These are actively tracked, known issues.*

1. **Path traversal**: weak measured recall (0.075). Detection is implemented, but measured recall on the current corpus is low. Included in DAST-applicable and excluded from supported-classes.
2. **SPA catch-all behaviour**: possible false positives. The probe runs a structural DOM differential against the root page before emission. Residual FP surface: SPA routes whose DOM matches the root page closely enough to pass the structural gate.
3. **Authentication expiry**: two consecutive 401 responses (when auth is configured) abort the scan. No automatic token refresh or OAuth2 recovery exists yet.
4. **Framework-specific SQL injection**: recognises database error patterns, but framework-specific profiles and delivery-path analysis remain future work.
5. **SSRF**: current OOB and metadata-marker coverage. The file:// payload remains deferred; confidence-aware OOB attribution is not implemented.
6. **IDOR**: candidate-only discovery, two-identity requirement and manual assessment. No automatic suppression heuristic is applied (ADR-031).
7. **Completeness semantics**: `scan_complete=true` means no tracked incomplete condition was observed; it does not mean every possible attack vector was tested.

## 8. External Research Assessment
The following is an assessment of the research handover (lostsec, WAFF-LED, Ghost Bits, etc.) and its impact on JANISSARY.

**The Trap (Request Multiplication)**: Absorbing Tier A items (1,207 WAFFL-LED bypasses, 90 SSRF parameters) before fixing `total_requests` will permanently corrupt the denominator. Priority C-1 (Request-Accounting Contract) must be resolved before any Tier A corpus work begins.

**DNS vs HTTP False Positives)**: Priority B-10 (DNS-vs-HTTP discrimination) is the likely mechanism for the 727 SSRF false positives. IF JANISSARY counts a DNS callback as a verified SSRF, we are emitting Informative-grade evidence as a verified finding.

**Parse-Proven Bypass (C-5)**: A WAF bypass only counts if the backend framework parses the payload. This is non-negotiable for preserving precision.

**SSLF Attribution (B-9/10)**: The lostsec article provides a P4 to P1 severity matrix. We must adopt this evidence-grading schema. A DNS-only callback is P4, not P1.

**Tier A Corpus Deduplication**: You WeH0ill And Lostsec have ~50% overlap. Merging them verbatim will inflate the corpus without adding coverage.

## 9. Sequencing Recommendation
The order is forced by dependency, not preference.

0. Request-accounting contract (C-1)
1. Confirm in-band echo + 307 redirector exist (B-13)
2. Stack fingerprinting (B-8)
3. Evidence grading schema P4->P1 (B-9)
4. DNS-vs-HTTP discrimination (B-10)
5. Tier A corpus, traversal side (A-1, A-7, A-8)
6. Tier A corpus, SSRF side (A-3, A-4, A-11)
7. Parse-proven-bypass requirement (C-5)

## 10. Explicit Non-Claims
*- No repository file was read, modified, or executed in producing this summary.
* No test was run. No benchmark was run.
* F1 0.922 is a rescore of committed artefacts, not a clean-exit run.
* The 727 SSRF false positives and 0.049–0.308 traversal recall are handover/register figures, not measurements.
