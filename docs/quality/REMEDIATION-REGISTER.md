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
- **Evidence:** `bd7f1c3` — `ScanSummary.auth_state` with values `unknown` (default), `authenticated`, `unauthenticated`, `expired`, `recovery_failed`. Set at `scan()` start from `auth_configured`; set on two-consecutive-401 abort. `_summary_to_dict` emits the key; `_print_summary` renders it on abort. `e96f31c` adds abort-path coverage: 3 tests against real ResponseSnapshot/compute_arming_state with 3 mocks, plus the auth_configured gate test. 7 tests total in `tests/unit/test_auth_state.py`. ADR-010 safety unchanged.
- **Remaining Gap:** No `AuthStateManager` (health checks, reauth workflow, OAuth2 refresh). `expired` vs `recovery_failed` distinguishes rotation-inactive from rotation-exhausted, but there is no path back to `authenticated` after a `recovery_failed` abort. Abort-path unit tests now exist (`e96f31c`).
- **Next Action:** Extend with an `AuthStateManager` when reauth is specified. Reconcile with tri-session (M41) rather than a parallel subsystem.
- **Closure Criterion:** Structured auth state in all output formats (JSON, JSONL, SARIF — not just text). Reauth tested against a mock IdP.

### JAN-L03 — Framework-Specific SQL Injection
- **Status:** Not Started
- **Priority:** P0
- **Evidence:** No DBMS-fingerprint or dialect-profile module exists. LIMITATIONS documents FN-12 exception only.
- **Remaining Gap:** No ORM profiles, no dialect selection, no delivery-path analysis.
- **Next Action:** Build FN-classification table (delivered/neutralised/indistinguishable) before touching payloads.
- **Closure Criterion:** DBMS/framework corpus passes; no precision regression.

### JAN-L04a — Path Traversal Recall (observable cases)
- **Status:** In Progress
- **Priority:** P0
- **Evidence:** Full corpus 133 vulnerable cases, TP=10, FN=123, recall 0.075 (`docs/pathtraver.md:57`, artefact `run-1-recovery-score.txt`). A 72-case hand sample split 4 existence-divergence / 22 fixed-string scaffold / 46 write-sink scaffold; selection not preserved in the repo. The 4/22/46 split is representative, not a census.
- **Remaining Gap:** The observable-subset denominator is not established. The 72-sample implies ~4/72 (5.6%) have a divergence the current oracle can act on, but the full corpus yields 10 TP, which exceeds 4 — so either the sample under-represents observable cases or some TPs come from a different mechanism. No dedicated traversal harness exists to measure either way.
- **Next Action:** (1) Instrument the traversal path to report delivery vs neutralisation vs no-divergence per case (mandate L04 "establish the real cause"). (2) Build a dedicated traversal harness with a documented denominator. (3) Only then set a recall target against a verified figure.
- **Closure Criterion:** Observable-subset recall measured against a documented denominator, no FP regression against the existing baseline.

### JAN-L04b — Path Traversal (structurally unobservable)
- **Status:** Accepted Limitation
- **Priority:** Documentation
- **Evidence:** 123 of 123 non-firing pathtraver cases fall into the "no divergence" bucket by construction of the paired-differential oracle (`docs/pathtraver.md:57`). Two scaffolds account for the sample majority: fixed-string `already exists` on both payloads (22/72), and write-sink echo with no other outcome (46/72).
- **Remaining Gap:** None fixable by signature expansion. This is the oracle's information-theoretic ceiling on that corpus. Additional payloads cannot create a differential where the target produces none.
- **Next Action:** Record the exclusion in `BENCHMARK.md` with corpus-level evidence, so the 0.075 aggregate carries its denominator inline rather than in a separate document.
- **Closure Criterion:** Exclusion documented in BENCHMARK.md with corpus-level evidence; aggregate recall reported with the caveat inline.

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

### JAN-L11 — Benchmark Coverage Documentation
- **Status:** Resolved
- **Priority:** P1
- **Evidence:** `BENCHMARK.md:975` states the denominator explicitly: FULL CORPUS (2740 cases) and DAST-APPLICABLE (2258 cases, 482 excluded via `dast_excluded.txt`). Line 735 breaks out 93 structurally skipped cases (89 header_any, 3 out_of_scope_stream, 1 out_of_scope_uri). Amendment 27 defines two labelled scopes — DAST-applicable 0.921 (TP 987, FP 0, FN 169) and supported-classes 0.977 (TP 977, FP 0, FN 46) — with guardrails at lines 1919-1922 preventing the supplemental from superseding the headline. Scorer misattribution fixed 2026-11-10 (`FAMILY_OF` lacked `sqli_blind`). The navigational index landed in `ad8cb13`, adding headline, supplemental, denominator, gate and pathtraver ceiling to the top of `BENCHMARK.md` as a labelled non-pre-registration block.
- **Remaining Gap:** None for closure. The amendment log remains long by design — it is a frozen pre-registration and the amendments are the historical record. The index mitigates the length for a reader; it does not shorten it.
- **Next Action:** Maintenance, not remediation. Update the navigational index whenever a new headline amendment supersedes 0.921. Nothing enforces this — it is a manual obligation recorded here so a future session knows the index can go stale.
- **Closure Criterion:** Met by `ad8cb13`. The headline and its supplemental are reachable from the top of `BENCHMARK.md` without reading the amendment chain.

### JAN-L12 — Resumable / Fault-Tolerant Scanning
- **Status:** Not Started
- **Priority:** P1
- **Evidence:** No checkpointing, no resumable state.
- **Remaining Gap:** Scan restart loses in-flight findings.
- **Next Action:** Defer behind L09/L10. Persist findings-per-endpoint so interruption resumes without duplicates.
- **Closure Criterion:** Deferred.

---

*Last updated: 2026-11-11 (L09 resolved in 039291c; L02 partial in bd7f1c3 with abort-path tests in e96f31c; L04 split into L04a/L04b with corrected denominators from docs/pathtraver.md; L11 resolved — denominator at BENCHMARK.md:975, stale figures fixed in bc7e335, navigational index in ad8cb13). Next review scheduled.*
