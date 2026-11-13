# Janissary Remediation Register

**Source of truth for the Quality & Reliability Programme (JAN-L01 to JAN-L12).**
Statuses are evidence-derived from code, tests, benchmark artefacts, and commit history. They are not inferred from roadmap labels.

**Citation convention:** every package's Evidence line must cite at least one `src/` `file:line` and, for any claimed mitigation, the introducing SHA. A citation that does not survive `grep` is not evidence. Packages without a code citation are `Not Started` regardless of narrative.

## Precision Assurance Gates (Current Status)

| Gate | Status | Reason |
|---|---|---|
| 1 — Precision | **FAIL** | L09 resolved, but no FP regression corpus exists yet. |
| 2 — Detection | **PARTIAL** | Per-class recall published; no 3-run CI requirement enforced. |
| 3 — Reliability | **PARTIAL** | Auth state now reported (dc09b70); SARIF coverage in `1c8aaa8`; reauth workflow outstanding. |
| 4 — Evidence | **PARTIAL** | `verification_status` in all formats; category contract not enforced. |
| 5 — Release | **PARTIAL** | v7.11.0 clean, but L01/L02 remain open. |

---

## Work Packages

### JAN-L01 — SPA Catch-All False Positives
- **Status:** Mitigated
- **Priority:** P0
- **Evidence:** Structural DOM gate implemented as `fingerprint`->`root_signature`->`hamming` distance in `src/janissary/engine/baseline_struct.py:95` (`_root_signature_from`), `baseline_struct.py:27-28` (`dom_fingerprint`, `hamming`), consumed by `src/janissary/detection/collapse_oracle.py:18`. README notation `root@U@signature@U@match` describes this pipeline; it is not a code literal. Issue #1 open.
- **Remaining Gap:** Residual: SPA routes with near-identical DOM to root still pass. No regression corpus.
- **Next Action:** Build multi-stage route pipeline (root + nonexistent negative control). Add React/Angular/Vue regression fixtures.
- **Closure Criterion:** Regression corpus passes with zero verified admin-panel FPs.

### JAN-L02 — Mid-Scan Authentication Expiry
- **Status:** Partial
- **Priority:** P0
- **Evidence:** `dc09b70` — `ScanSummary.auth_state` with values `unknown` (default), `authenticated`, `unauthenticated`, `expired`, `recovery_failed`. Set at `scan()` start from `auth_configured`; set on two-consecutive-401 abort. `_summary_to_dict` emits the key; `_print_summary` renders it on abort. `e96f31c` adds abort-path coverage: 3 tests against real ResponseSnapshot/compute_arming_state with 3 mocks, plus the auth_configured gate test. 7 tests total in `tests/unit/test_auth_state.py`. ADR-010 safety unchanged. `1c8aaa8` — SARIF now carries `auth_state` at `properties.auth_state` (sibling of `completeness`, not nested inside it); two tests in `tests/unit/test_scan_completeness.py`. JSON carries it at `_summary_to_dict` top level. **JSONL carries no scan-level record** — `emitter.py` JSONL branch writes findings and candidates only; `scan_meta` is a parameter but consumed only by `_build_document` (JSON branch). Excluded by design per L10: JSONL is the finding stream; `--json` is the complete-document format.
- **Remaining Gap:** No `AuthStateManager` (health checks, reauth workflow, OAuth2 refresh). `expired` vs `recovery_failed` distinguishes rotation-inactive from rotation-exhausted, but there is no path back to `authenticated` after a `recovery_failed` abort. Abort-path unit tests now exist (`e96f31c`). SARIF and JSON carry structured `auth_state`; JSONL does not carry scan-level metadata at all — excluded by design per L10, not an `auth_state` bug.
- **Next Action:** Extend with an `AuthStateManager` when reauth is specified. Reconcile with tri-session (M41) rather than a parallel subsystem.
- **Closure Criterion:** Structured auth state in all output formats (JSON, JSONL, SARIF — not just text). Reauth tested against a mock IdP.

### JAN-L03 — Framework-Specific SQL Injection
- **Status:** Not Started
- **Priority:** P0
- **Evidence:** No ORM-profile module, no dialect-keyed payload selection, no delivery-path analysis. Detection-side DBMS classification does exist: `detection/analyzer.py:126-175` carries `DB_ERROR_PATTERNS` keyed by six dialects (mysql, postgresql, hsqldb, mssql, oracle, sqlite), and `test_db_error_forces_sqli_category` pins that path. `scanner.py:1918` consumes `db_error` as a finding type only — no dialect-keyed payload selection. Two payloads are dialect-targeted by name (`sql_sleep_mysql`, `sql_sleep_pg`, `scanner.py:73`), but the scanner sends the full set rather than selecting between them. Classification frame and open items in `docs/l03_sqli_classification.md`. FN-12 (`LIMITATIONS.md:35`) is FIXED (2026-11-01) and concerns non-2xx baselines, not framework SQLi; it is not L03 evidence.
- **Remaining Gap:** No ORM profiles, no dialect selection, no delivery-path analysis.
- **Next Action:** Classification frame written; all open items 9.1-9.6 resolved 2026-11-14 (`docs/l03_sqli_classification.md`). Next in M83 order: per-case record schema, then measurement protocol, then implementation. No payload or scanner change is justified by classification alone.
- **Closure Criterion:** DBMS/framework corpus passes; no precision regression.

### JAN-L04a — Path Traversal Recall (observable cases)
- **Status:** In Progress
- **Priority:** P0
- **Evidence:** Full corpus 133 vulnerable cases, TP=10, FN=123, recall 0.075 (`docs/pathtraver.md:57`, artefact `run-1-recovery-score.txt`). A 72-case hand sample split 4 existence-divergence / 22 fixed-string scaffold / 46 write-sink scaffold; selection not preserved in the repo. The 4/22/46 split is representative, not a census.
- **Remaining Gap:** The observable-subset denominator is not established. The 72-sample implies ~4/72 (5.6%) have a divergence the current oracle can act on, but the full corpus yields 10 TP, which exceeds 4 — so either the sample under-represents observable cases or some TPs come from a different mechanism. No dedicated traversal harness exists to measure either way. **Census arithmetic closed 2026-11-13:** the 133 vulnerable cases decompose as 10 findings + 60 SSRF-only + 49 executed-silent + 14 payload-neutralised (`docs/pathtraver_audit_amendment.md` §3). The 60 SSRF-only cases explain why the corpus yields 10 TP against the 72-sample's ~4 estimate — the sample did not include SSRF-only findings on pathtraver URLs. The 49 executed-silent cases are the target of the L04a instrumented harness (M83 Phase 2).
- **Next Action:** (1) Instrument the traversal path to report delivery vs neutralisation vs no-divergence per case (mandate L04 "establish the real cause"). (2) Build a dedicated traversal harness with a documented denominator. (3) Only then set a recall target against a verified figure.
- **Closure Criterion:** Observable-subset recall measured against a documented denominator, no FP regression against the existing baseline.

### JAN-L04b — Path Traversal (structurally unobservable)
- **Status:** Superseded — merged into L04a
- **Priority:** Documentation
- **Evidence:** The 72-case hand sample recorded 46/72 write-sink scaffold and 22/72 fixed-string scaffold (`analyzer.py:776-783`, `docs/pathtraver.md:55`), which are plausible unobservable classes. However, the sample is not a census, and the "123 of 123 by construction" claim was withdrawn from `docs/pathtraver.md` (corrected 2026-11-13, commit `5fae530`). The 133-case census decomposes as 10 findings + 60 SSRF-only + 49 executed-silent + 14 payload-neutralised (`docs/pathtraver_audit_amendment.md` §3); only the 49 executed-silent could be "no observable divergence", and they have not been individually classified.
- **Remaining Gap:** Cannot be accepted as a limitation until classified. Merged into L04a's instrumented harness, which will record per-case classification and produce a defensible denominator.
- **Next Action:** None independently — tracked under L04a. When M83 Phase 2's harness produces `case_records.jsonl`, the classification counts will either confirm the sample's ~64% write-sink estimate or show it was over-represented.
- **Closure Criterion:** Retired. L04a's closure criterion subsumes it.

### JAN-L05 — SSRF / OOB Coverage
- **Status:** Mitigated
- **Priority:** P1
- **Evidence:** Metadata payloads at `src/janissary/engine/scanner.py:124` (AWS IMDSv1), `:136` (GCP), `:142` (Azure). Redirect-chain metadata path `466cb1f` (ADR-029 BL-1, 7 tests); OOB-via-redirect `212b5d1` (ADR-029 BL-1b, 4 tests). Interactsh CI enablement `4a68c7a`; workflow-scope caveat recorded `49f2c78`.
- **Remaining Gap:** `file://` deferred by design. No confidence-aware OOB attribution.
- **Next Action:** Add interaction-to-payload attribution tests. Verify negative controls produce zero verified SSRF.
- **Closure Criterion:** Negative-control suite produces zero verified SSRF.

### JAN-L06 — IDOR and Authorisation Detection
- **Status:** Partial
- **Priority:** P1
- **Evidence:** M42 shipped, candidate-only (`--idor`), requires two identities. `run_idor` routes through `_ENGINE.verify()` (`scanner.py:1339`). L06a `91e9281` adds five authorisation-boundary integration tests to `tests/integration/test_scanner_idor.py`: 200/200 public-resource shape asserts `unproven` and not `verified`; length within 5pct asserts candidate; length beyond 5pct asserts no candidate; A-observation-non-2xx asserts no candidate; B-5xx asserts no candidate. Committed with 1088 unit / 1183 unit+integration passing and both ruff gates green.
- **Remaining Gap:** Semantic verification beyond the status+body predicate is L06b. No role/tenant matrix.
- **Next Action:** None for L06a -- the boundary is covered. L06b carries the remaining design work.
- **Closure Criterion:** L06a met by `91e9281`. L06b resolved by ADR-031. Remaining: role/tenant matrix for semantic verification.

### JAN-L06b — IDOR Public-Resource Suppression
- **Status:** Resolved
- **Priority:** P2
- **Evidence:** `is_idor_candidate` (`detection/idor.py:79`) compares A-status, B-status, and body equality-or-5pct-length only. It carries no public/private resource signal, so a 200/200 matching-body response emits an `unproven` candidate whether the resource is legitimately public or an IDOR. `test_run_idor_public_resource_shape_emits_unproven_not_verified` (`91e9281`) pins the current behaviour: the detector reports and defers to analyst triage. **ADR-031** records this as the intended control.
- **Remaining Gap:** None. Public-resource suppression is a deliberate non-goal: the detector emits `unproven` candidates and analyst triage is the control (ADR-031). Options (i) and (ii) were rejected; neither is foreclosed if triage volume becomes a measured problem.
- **Next Action:** None. Decision recorded in ADR-031 (option iii: triage as the control). No detector change.
- **Closure Criterion:** A recorded design decision (ADR) plus fixtures that assert whichever behaviour is chosen. If (iii) is chosen, closure is the ADR alone.

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
- **Evidence:** `README.md:72`: not implemented, no committed delivery date.
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
- **Status:** Resolved
- **Priority:** P0
- **Evidence:** `a795234` — `_scan_completeness()` derives `scan_complete` from four tracked conditions (aborted, scan_incomplete, auth lost, params unbaselined) and returns `params_identified`, `params_baselined` and a `reasons` list. `_summary_to_dict` emits the block; `_print_summary` renders the reasons only when incomplete. `4a8f63f` wires it into SARIF via `properties.completeness` on every run, from the same `_scan_completeness` source. HTML and PDF receive the `payload` dict and already carried it. JSON and the human summary carry it. 10 tests in `tests/unit/test_scan_completeness.py`; full suite 1088 passed. `scan_incomplete` was already emitted in JSON (`cli.py:54`). LIMITATIONS has a "What 'no finding' means" section.
- **Remaining Gap:** Recorded as accepted limitation, not a gap. (1) JSONL does not carry the block, by design: `OutputEmitter.emit` writes one line per finding, and a scan-level header record would break every line-by-line consumer. JSON is the complete-document format; JSONL is the finding stream. A consumer that needs completeness requests `--json`. (2) Four mandate fields are untracked anywhere in the scanner — WAF-blocked counts, timeout counts, skipped-check counts, endpoint-discovery counts — and are deliberately absent rather than emitted as zero, because a zero that means unknown reads like a measurement. Instrumenting them is a scanner change, not a reporting one.
- **Next Action:** None for this entry. If the four untracked fields are later judged worth instrumenting, that work belongs in a new item with its own criterion; it is not a completeness-reporting task.
- **Closure Criterion:** Met by `a795234` and `4a8f63f`. The completeness block reaches every output format that carries a scan-level record, from a single derivation function. JSONL is documented as an intentional absence because its line-per-finding structure has no scan-level record to carry it.

### JAN-L11 — Benchmark Coverage Documentation
- **Status:** Resolved
- **Priority:** P1
- **Evidence:** `BENCHMARK.md:975` states the denominator explicitly: FULL CORPUS (2740 cases) and DAST-APPLICABLE (2258 cases, 482 excluded via `dast_excluded.txt`). Line 735 breaks out 93 structurally skipped cases (89 header_any, 3 out_of_scope_stream, 1 out_of_scope_uri). Amendment 27 defines two labelled scopes — DAST-applicable 0.921 (TP 987, FP 0, FN 169) and supported-classes 0.977 (TP 977, FP 0, FN 46) — with guardrails at lines 1919-1922 preventing the supplemental from superseding the headline. Scorer misattribution fixed 2026-11-10 (`FAMILY_OF` lacked `sqli_blind`). The navigational index landed in `ad8cb13`, adding headline, supplemental, denominator, gate and pathtraver ceiling to the top of `BENCHMARK.md` as a labelled non-pre-registration block. **Amendment 29 (2026-11-13, commit `1a1f7f6`)** supersedes the 0.921 headline with a complete v7.11.1 measurement: DAST-applicable 0.922 (TP 988, FP 0, FN 168); the supported-classes supplemental is retained at 0.977 and marked pending re-check against the committed run (`docs/pathtraver.md:143`). The navigational index reflects the 0.922 headline as of `5fae530`.
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

*Last updated: 2026-11-14 (L09 resolved in 039291c; L02 partial in dc09b70 with abort-path tests in e96f31c and SARIF auth_state in 1c8aaa8; L04 split into L04a/L04b with corrected denominators from docs/pathtraver.md; L11 resolved — denominator at BENCHMARK.md:975, stale figures fixed in bc7e335, navigational index in ad8cb13; L10 resolved — block in a795234, SARIF wiring in 4a8f63f, JSONL accepted-absent; L06 split into L06a (five authorisation-boundary fixtures in `91e9281`) and L06b (public-resource suppression, design-only); L06 status In Progress -> Partial; L06b Resolved via ADR-031; bd7f1c3 -> dc09b70 throughout). Next review scheduled.*
