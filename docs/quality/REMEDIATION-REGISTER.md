# Janissary Remediation Register

**Source of truth for the Quality & Reliability Programme (JAN-L01 to JAN-L12).**
Statuses are evidence-derived from code, tests, benchmark artefacts, and commit history. They are not inferred from roadmap labels.

## Precision Assurance Gates (Current Status)

| Gate | Status | Reason |
|---|---|---|
| 1 — Precision | **FAIL** | L09 resolved, but no FP regression corpus exists yet. |
| 2 — Detection | **PARTIAL** | Per-class recall published; no 3-run CI requirement enforced. |
| 3 — Reliability | **PARTIAL** | Auth state now reported (bd7f1c3); reauth workflow and abort-path tests outstanding. |
| 4 — Evidence | **PARTIAL** | `verification_status` in all formats; category contract not enforced. |
| 5 — Release | **PARTIAL** | v7.11.0 clean, but L01/L02 remain open. |

---

## Work Packages

### JAN-L01 — SPA Catch-All False Positives
- **Status:** Mitigated
- **Priority:** P0
- **Evidence:** Issue #1 open. README documents structural DOM gate (`root@U@signature@U@match`) discarding candidates.
- **Remaining Gap:** Residual: SPA routes with near-identical DOM to root still pass. No regression corpus.
- **Next Action:** Build multi-stage route pipeline (root + nonexistent negative control). Add React/Angular/Vue regression fixtures.
- **Closure Criterion:** Regression corpus passes with zero verified admin-panel FPs.

### JAN-L02 — Mid-Scan Authentication Expiry
- **Status:** Partial
- **Priority:** P0
- **Evidence:** `bd7f1c3` — `ScanSummary.auth_state` with values `unknown` (default), `authenticated`, `unauthenticated`, `expired`, `recovery_failed`. Set at `scan()` start from `auth_configured`; set on two-consecutive-401 abort. `_summary_to_dict` emits the key; `_print_summary` renders it on abort. 4 tests in `tests/unit/test_auth_state.py`. ADR-010 safety unchanged.
- **Remaining Gap:** No `AuthStateManager` (health checks, reauth workflow, OAuth2 refresh). `expired` vs `recovery_failed` distinguishes rotation-inactive from rotation-exhausted, but there is no path back to `authenticated` after a `recovery_failed` abort. Reauth itself is not tested — the abort path in `scanner.py` is not covered by unit tests (would need `_paced_request`, `collect_baseline` and `_detect_waf` mocked).
- **Next Action:** (1) Add an abort-path test that mocks `_paced_request` to return two 401s and asserts `auth_state == "expired"`. (2) Extend with an `AuthStateManager` when reauth is specified. Reconcile with tri-session (M41) rather than a parallel subsystem.
- **Closure Criterion:** Structured auth state in all output formats (JSON, JSONL, SARIF — not just text). Reauth tested against a mock IdP.

### JAN-L03 — Framework-Specific SQL Injection
- **Status:** Not Started
- **Priority:** P0
- **Evidence:** No DBMS-fingerprint or dialect-profile module exists. LIMITATIONS documents FN-12 exception only.
- **Remaining Gap:** No ORM profiles, no dialect selection, no delivery-path analysis.
- **Next Action:** Build FN-classification table (delivered/neutralised/indistinguishable) before touching payloads.
- **Closure Criterion:** DBMS/framework corpus passes; no precision regression.

### JAN-L04 — Path Traversal Recall
- **Status:** Accepted Limitation (Partial)
- **Priority:** P0
- **Evidence:** Recall 0.075; per-subcategory F1 0.049–0.308. Amendment 5: structural ceiling ~4/72. `docs/pathtraver.md` documents it.
- **Remaining Gap:** 65 FN remain, ~68/72 structurally unobservable by this oracle on this corpus.
- **Next Action:** Split register entry into *observable-but-missed* (fixable) vs *structurally unobservable* (document, do not chase). Build dedicated traversal corpus.
- **Closure Criterion:** Observable subset recall ≥0.30 without FP regression.

### JAN-L05 — SSRF / OOB Coverage
- **Status:** Mitigated
- **Priority:** P1
- **Evidence:** BL-1 redirect-chain shipped 2026-11-10. Interactsh (M14) shipped. AWS/GCP/Azure metadata shipped.
- **Remaining Gap:** `file://` deferred by design. No confidence-aware OOB attribution.
- **Next Action:** Add interaction-to-payload attribution tests. Verify negative controls produce zero verified SSRF.
- **Closure Criterion:** Negative-control suite produces zero verified SSRF.

### JAN-L06 — IDOR and Authorisation Detection
- **Status:** In Progress
- **Priority:** P1
- **Evidence:** M42 shipped, candidate-only (`--idor`), requires two identities. `run_idor` routes through `_ENGINE.verify()`.
- **Remaining Gap:** No semantic verification (200-vs-200 still triggers). No role/tenant matrix.
- **Next Action:** Add positive/negative authorisation fixtures (public-resource access must not verify).
- **Closure Criterion:** Positive/negative authorisation fixtures pass.

### JAN-L07 — Discovery / Modern SPA Coverage
- **Status:** Accepted Limitation (Deliberate)
- **Priority:** P1
- **Evidence:** ADR-021 defers crawler with explicit triggers. OpenAPI import (ADR-030) is compensating control.
- **Remaining Gap:** No JS endpoint extraction, no sitemap/robots/HTML form parsing.
- **Next Action:** First-stage only: sitemap + robots + HTML form + JS-string extraction feeding existing scanner.
- **Closure Criterion:** Deferred until named enterprise demand (ADR-021 triggers).

### JAN-L08 — JWT and Prototype Pollution
- **Status:** Accepted Gap
- **Priority:** P1/P2
- **Evidence:** README line 174: not implemented, no committed delivery date.
- **Remaining Gap:** Neither implemented, not even as Discovery signatures.
- **Next Action:** Implement as Discovery candidates first; graduate only after verification contracts exist.
- **Closure Criterion:** Discovery signatures exist; verified contracts defined.

### JAN-L09 — Finding Classification Integrity
- **Status:** Resolved
- **Priority:** P0
- **Evidence:** `039291c` — `ScanSummary.candidates` + `_CandidatesList`. `scan_host_bypass` routes there. `finding_count = len(findings)` strictly.
- **Remaining Gap:** Category/evidence contract at the emission boundary still open (Issue #4, deferred).
- **Next Action:** Close Issue #4 — enforce per-category evidence contracts in `_VerifiedFindingsList.append`.
- **Closure Criterion:** Rule 1 / Rule 3 violation closed. (Category contract remains tracked under L11).

### JAN-L10 — Scan Completeness and Negative Results
- **Status:** Partial
- **Priority:** P0
- **Evidence:** `scan_incomplete` exists and is emitted in JSON (`cli.py:54`). LIMITATIONS has "What 'no finding' means" section.
- **Remaining Gap:** No structured completeness accounting (endpoints/skipped/WAF-blocked). No consistency guarantee across formats.
- **Next Action:** Add completeness block to `_summary_to_dict` and render it in all formats from one source.
- **Closure Criterion:** Completeness block in all output formats from one source.

### JAN-L11 — Benchmark Harness Coverage
- **Status:** Partial
- **Priority:** P0
- **Evidence:** 2,740 cases. Scorer misattribution fixed 2026-11-10 (`FAMILY_OF` lacked `sqli_blind`).
- **Remaining Gap:** No explicit skipped/unsupported denominator. README line 158 states `20 of 33` DAST-applicable.
- **Next Action:** Publish denominator: total/applicable/executed/skipped/unsupported.
- **Closure Criterion:** Denominator published in `BENCHMARK.md`.

### JAN-L12 — Resumable / Fault-Tolerant Scanning
- **Status:** Not Started
- **Priority:** P1
- **Evidence:** No checkpointing, no resumable state.
- **Remaining Gap:** Scan restart loses in-flight findings.
- **Next Action:** Defer behind L09/L10. Persist findings-per-endpoint so interruption resumes without duplicates.
- **Closure Criterion:** Deferred.

---

*Last updated: 2026-11-11 (L09 resolved in 039291c; L02 partial in bd7f1c3). Next review scheduled.*
