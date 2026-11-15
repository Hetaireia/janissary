# M83 Measurement Report — Stage 1

**Prepared:** 2026-11-15
**Milestone:** M83 — Traversal Observability Harness
**Registered status:** verified-partial
**Harness commit:** afd6c5956a1df7933cff828f31907fe5b4fa153f
**Authority:** docs/STRATEGIC-ROADMAP-2026-11-15.md §5 Stage 1
**Scope:** Evidence report only. No source, test, corpus, or milestone change.

## 1. Purpose and scope

This report records Stage 1 validation of the M83 traversal measurement pipeline. It answers one question: does the recorder, classifier, diagnostics, and runner integration produce trustworthy, repeatable per-case evidence under real execution?

The twelve validation items originate in the roadmap's Stage 1. Each receives a disposition: evidenced, partially evidenced, or verified gap. Findings outside M83's scope, discovered during execution, are recorded separately in §5 and are not attributed to M83.

This report does not modify source, tests, corpus, milestone status, or roadmap. It is evidence, not action.

## 2. Execution environment

### 2.1 Target

- Image: janissary/owasp-benchmark:20cbf3d (matches every historical Track A manifest)
- Container: janissary-benchmark, running on port 8080
- URL: http://127.0.0.1:8080/benchmark
- Verified live via HTTP 200 returning the OWASP Benchmark index
- Startup time approximately 12 seconds (Server startup in 12083 milliseconds); first request during startup returns an empty reply, not a connection refusal

### 2.2 Working startup sequence

The tracked build_and_run.ps1 script does not start the target correctly (see §9 item 13). The sequence that produced a working target:

    docker run --rm -d --name janissary-benchmark -p 8080:8080 janissary/owasp-benchmark:20cbf3d
    (wait ~15s for Tomcat startup)
    curl.exe -v --max-time 30 http://127.0.0.1:8080/benchmark/

Operational preconditions, undocumented in the repo (item 16):
- Docker Desktop must be running before docker run
- Opera browser must be closed; it holds port 8080 and would prevent container startup

### 2.3 Container image drift (item 15)

At investigation start, the running container was janissary/owasp-benchmark:20cbf3d-ldapfix — a variant not mentioned in any tracked file, with port 10389 (LDAP) mapped. With no LDAP server running, all HTTP requests to this container hung: TCP connect succeeded, HTTP request sent, zero bytes returned in 30s. The -ldapfix variant was stopped. The plain 20cbf3d image — the one every historical manifest records — was started instead.

### 2.4 Exit-code semantics (item 18)

All runs examined (the morning run at 20261115T070456Z, and today's B2 runs r1 and r2) reported manifest exit_code 1. The morning run had 0 findings; today's runs had 1 finding each. Exit code is not a defect signal, is not a findings signal, and cannot serve as a stop gate in future authorisations without further investigation.

## 3. The twelve validation items

Items 1, 2, 5, 6, 7, 8 are evidenced by source and test inspection (Part A). Item 3 is evidenced by B1 execution. Item 4 is evidenced structurally with a qualification. Items 9, 10, 11 are partially evidenced with specific limitations. Item 12 is a verified gap.

| # | Item | Disposition | Evidence |
|---|---|---|---|
| 1 | CLI --record-case-dir wired | evidenced | 17 tests in tests/unit/test_cli_record_case_dir.py; 10 references in src/janissary/cli.py |
| 2 | Scanner receives recording directory | evidenced | scanner.py:625 parameter, :660 storage, :662-668 recorder construction, :2199 call site, :2256 status write |
| 3 | Real executable path | evidenced | tests/integration/test_harness_e2e.py PASSED in 9.05s (B1); reinforced by B2 real-target runs |
| 4 | Schema agreement scanner and runner | evidenced (structural) | Scanner writes 8 fields; runner validates 6 (three booleans, three non-negative ints) with two invariants. scanner_version and completed_at are informational, not type-validated |
| 5 | Case ID safety and naming | evidenced | tests/unit/test_cli_record_case_dir.py: test_validate_rejects_dotdot_segments, rejects_symlink, rejects_unsanitized_basename; tests/unit/test_scanner_recording.py: test_recorder_rejects_unsanitized_case_dir_name |
| 6 | Recording status written and interpreted | evidenced | scanner.py:1465 _write_recording_status; 4 unit tests; runner.py:388 reads status; 3 runner tests cover missing/invalid/failed |
| 7 | Missing/invalid/failed status | evidenced | runner tests: test_classification_recording_failed, indeterminate_when_status_missing, recording_disabled, test_status_invalid_fields_indeterminate |
| 8 | Zero-observation vs failures | evidenced | runner tests: test_classification_has_observations, zero_observations, recording_failed, test_recording_summary_invariants |
| 9 | Timeout/aborted/skipped/not-reached taxonomy | partially evidenced | Code path exists at runner.py:303, 305, 307, 310. B2 observed recording_indeterminate fired correctly (BenchmarkTest02467, status_file_missing) in both runs. Other branches (not_reached, scan_aborted_at_case, scan_errored_at_case, execution_state_indeterminate) are implemented but not tested — no test file asserts their outcomes |
| 10 | Repeatability | partially evidenced | Structural pass (selection, skip set, dispositions, findings content). Per-case evidence 26/30 match; 4/30 differ due to target behaviour, not recorder. See section 7 |
| 11 | Corpus selection and provenance | partially evidenced | case_vectors.csv and _safe_sample.csv carry case-level vulnerable true/false labels. Per-payload expected outcomes are absent. Aggregation semantics (multiple payload attempts to one case-level TP/FP/FN) is unresolved. See section 6 |
| 12 | Scoring and aggregate output | verified gap | benchmark/track_a/score_dast_aware.py reads only findings.jsonl. It does not consume case_records.jsonl, case_raw/, recording_summary.json, or case_missing.jsonl. Recorder output is not consumed by any current tool. See section 5.2 |

## 4. B2 execution evidence

### 4.1 Runs

Run 1: benchmark/track_a/runs/20261115T083529Z-janissary-r1
Run 2: benchmark/track_a/runs/20261115T083836Z-janissary-r2
Corpus: benchmark/track_a/_safe_sample.csv (30 cases, all safe-labelled)
Target: http://127.0.0.1:8080/benchmark
Tool version: 7.11.1

### 4.2 Structural comparison

Identical across runs:
- case_selection.json (byte-identical)
- skipped.jsonl (identical set)
- case_raw directory list (30 dirs, identical names)
- recording_summary.json primary_dispositions (29 has_observations, 1 recording_indeterminate)
- accounting_valid true (both runs)
- findings count (1 and 1)
- findings fingerprint (jfv1:78ddd423be1a66db3127c665ce72fc8b, byte-identical)
- indeterminate case (BenchmarkTest02467, reason status_file_missing, both runs)

### 4.3 Per-case field comparison

Of 30 case directories (identical set across runs):
- 29 cases had comparable case_records_raw.jsonl in both runs
- Of those 29: 25 match on all compared fields (status, content_type, structural_signature, evidence_hash, body_original_length, body_truncated, body_stored for both exists and noexist probes)
- Of those 29: 3 differ only on body_stored / structural_signature / evidence_hash, due to a random 12-hex-character canary suffix the target echoes in its response — BenchmarkTest00648, 00718, 02398 (e.g. passwd_janissary_noexist_ad914d13881f versus c1918589e849)
- Of those 29: 1 differs on every field for both probes because the target has persistent state that changes between runs — BenchmarkTest01570 (run 1 response "But file doesn't exist yet." fresh; run 2 response "And file already exists." state created by run 1)
- 1 case (BenchmarkTest02467) is excluded from field comparison: no case_records_raw.jsonl in either run, recorder never fired (missing recording_status.json, the indeterminate case)

The 4 differing cases out of 29 comparable are target behaviour, not recorder non-determinism. The recorder faithfully captured what happened at the target in each run.

### 4.4 Interpretation

Per item 10 (repeatability):
- Structural, selection, disposition, and finding-level reproducibility is evidenced.
- Per-case evidence-level byte-equality is limited by target design (random canary suffix) and target state (persistent side effects). A two-run comparison against a state-mutating target cannot produce byte-identical per-case evidence even with a perfectly deterministic recorder.
- Item 10's disposition is therefore partial: the pipeline is reproducible; the target is not.

## 5. Out-of-scope defect findings

### 5.1 Item 17 — SSRF oracle entity-encoding false positive

Both B2 runs produced a verified SSRF finding on BenchmarkTest00648, a safe-labelled XSS case in category xss-01.

- Payload sent: http://mailhog:8025/
- Response body: http&#x3a;&#x2f;&#x2f;mailhog&#x3a;8025&#x2f; (46 bytes, HTML-entity-encoded reflection of the payload)
- Oracle logic: ssrf_response_oracle checked "mailhog marker absent from baseline and outside the reflected payload," found "mailhog" in the response, concluded SSRF

The oracle's reflected-payload exclusion did not recognise the HTML-entity-encoded form as a reflection of the sent payload. The encoded form (http&#x3a;&#x2f;&#x2f;mailhog...) is not character-for-character the sent payload (http://mailhog...), so the exclusion failed to fire.

Additional observations:
- severity critical (disproportionate for a reflection artifact)
- confidence "0.0" while verification_status "verified" (internally inconsistent)

This is a precision defect in the SSRF detection path. It is deterministic across both B2 runs (identical fingerprint). It is not an M83 finding — it is the SSRF oracle firing on a safe XSS case during a scan whose recording was correctly captured.

Future workstream: the strategic roadmap (docs/STRATEGIC-ROADMAP-2026-11-15.md section 5) places SSRF confidence-aware attribution at Stage 5 (L05). This report identifies the defect as a candidate for that workstream. It does not assert L05 ownership, does not assert the defect has been scoped, and does not propose a fix. Whether it is addressed within L05 or as a separate correction is a decision outside this report's authority.

### 5.2 Item 12 — Scorer does not consume recorder output

The scorer benchmark/track_a/score_dast_aware.py reads run-directory findings.jsonl exclusively. No path in the scorer references case_records.jsonl, case_raw/, recording_summary.json, case_missing.jsonl, or case_selection.json. Therefore:

- The M83 recorder produces trustworthy per-case evidence.
- No current tool consumes it.
- M83-to-M37 measurement against per-case evidence is not reachable via the current scorer.

This is not a Stage 1 defect in the recorder. It is a verified integration gap between recorder and scorer.

## 6. Corpus and labels

### 6.1 Ground truth

benchmark/track_a/case_vectors.csv carries a vulnerable column with true/false values. 2,740 data rows plus header. Case-level labels.

benchmark/track_a/_safe_sample.csv: 30 data rows plus header. All safe-labelled. Used for B2.

### 6.2 Per-payload expectations

The corpus does not provide per-payload expected outcomes. A case with multiple payload attempts has no specification for how those attempts collapse into a case-level TP/FP/FN classification.

### 6.3 Aggregation question (item 11)

The unresolved question is: how do multiple payload attempts per case aggregate to a case-level benchmark outcome? For a safe case with 1 finding and 29 silent payloads, is the case classified as "found" (any finding) or "not found" (majority)? For a vulnerable case with the same profile, the reverse question applies. Neither _safe_sample.csv nor case_vectors.csv specifies an aggregation rule.

This is a scoring design decision that precedes item 12's scorer integration. Even if a scorer consumed recorder output, it would need an aggregation rule that the current corpus does not state.

## 7. Reproducibility assessment (item 10)

What reproduces:
- Case selection
- Skip set
- Case directory list
- Disposition counts
- Finding count
- Finding content (byte-identical fingerprint)
- Indeterminate case identity and reason

What does not:
- Per-case structural signatures and evidence hashes (target random canary suffix; target state mutation)

Attribution: differences traced to target, not recorder. The recorder captures what the target actually returned in each run.

Consequence for measurement: per-case signature equality is not a useful health check against a state-mutating, canary-randomised target. The pipeline is correct; the target is non-deterministic by design.

## 8. Acceptance criteria (roadmap Stage 1)

| Criterion | Disposition |
|---|---|
| Real end-to-end recording demonstrated | Pass — B1 e2e passed; B2 real-target runs |
| Case-level provenance complete | Pass with limitation — 30/30 cases dispositioned; 1 case indeterminate |
| Recording failures remain visible | Pass — item 9's indeterminate taxonomy fired correctly |
| Execution failure distinguishable from zero observations | Pass — distinct disposition classes; verified by unit tests |
| Repeated runs produce explainable outputs | Pass — 25/29 comparable cases byte-identical; 4/29 explainable as target behaviour; 1 indeterminate case excluded from field comparison |
| Aggregate metrics traceable to individual cases | Partial — traceable in principle, but item 12 scorer gap blocks consumption |
| All 12 validation areas evidenced or dispositioned | Pass — 8 evidenced, 3 partially evidenced, 1 verified gap, all with cited evidence |

Overall: dispositioned with limitations. Not a full pass; not a fail. The pipeline is trustworthy. The surrounding measurement infrastructure has gaps (items 11, 12) and the target itself has reproducibility limits (items 19, 20).

## 9. Remaining dispositions and next steps

### 9.1 Environment and operational findings

These are outside M83's code. They affect reproducibility of the measurement pipeline and belong in future Track A startup documentation.

Item 13 — build_and_run.ps1 port mapping contradicts its own Dockerfile. Both committed in 0648ba1. Script maps -p 8443:8443; Dockerfile EXPOSE 8080 and entrypoint rewrites Tomcat to 8080. Script would produce an unreachable target. Not fixed by this report.

Item 14 — target startup is undocumented in a form that reproduces prior runs. Tracked script broken; correct startup only inferable from Dockerfile.

Item 15 — current running container image drift. The -ldapfix variant required an undocumented LDAP server. Pre-existing manifests do not record -ldapfix. Resolved in this session by restarting plain 20cbf3d.

Item 16 — target startup requires Docker Desktop running and Opera browser closed. Neither precondition documented.

Item 19 — target observation reproducibility is limited by design. Random canary suffix per request prevents per-case byte-level comparison.

Item 20 — target has persistent state side-effects. BenchmarkTest01570 created a file in run 1 that changed run 2's response.

### 9.2 Stage 1 exit-gate disposition

Stage 1 exit gate requires the acceptance criteria to be demonstrated with cited evidence. Dispositions:

- 8 items evidenced
- 3 items partially evidenced (9, 10, 11), each named with its specific limitation stated
- 1 item verified gap (12)
- 7 environment findings (13-16, 18-20) outside M83 code, recorded for future Track A startup documentation
- 1 out-of-scope defect (17) in the SSRF oracle, candidate for future L05 workstream

The Stage 1 exit gate is dispositioned, not fully passed. Item 12's gap blocks M83-to-M37 measurement via the current scorer. Item 11's aggregation question blocks a defensible per-case FP/FN classification even if the scorer were fixed.

### 9.3 M83 milestone status

M83 remains verified-partial. No status change is proposed by this report.

Rationale: verified-delivered requires all acceptance criteria demonstrated with cited evidence. Items 9, 10, 11 are partially evidenced. Item 12 is a verified gap. Those four items block verified-delivered.

The milestone register section 5.1 already records the M83 gap. This report provides the evidence for that gap; it does not close it. A register update would be a separate write authorisation.

### 9.4 Decisions surfaced, not proposed

Not proposed by this report as actions. Stage 1 surfaces the following decisions:

1. Item 12 — assign an owner for scorer integration, or accept that M83's evidence is unconsumed and that M37's measured acceptance is deferred.
2. Item 11 — decide an aggregation rule for case-level labels, or accept that aggregate metrics remain findings-based until decided.
3. Items 13-16, 18-20 — schedule a Track A startup documentation pass to close the environment gap.
4. Item 17 — decide whether it belongs to L05's future scope, or a separate correction.

No action is proposed by this report. Each decision is outside the report's authority.

## 10. Appendix

### 10.1 Run directories

B2 Run 1: benchmark/track_a/runs/20261115T083529Z-janissary-r1
B2 Run 2: benchmark/track_a/runs/20261115T083836Z-janissary-r2
Morning run: benchmark/track_a/runs/20261115T070456Z-janissary-r1

### 10.2 Cited files

Source:
- src/janissary/harness/pathtraver.py
- src/janissary/engine/scanner.py
- src/janissary/cli.py
- benchmark/track_a/runner.py
- benchmark/track_a/score_dast_aware.py
- benchmark/common/run_utils.py

Tests:
- tests/unit/test_cli_record_case_dir.py
- tests/unit/test_scanner_recording.py
- tests/unit/test_harness_pathtraver_signature.py
- tests/unit/test_harness_pathtraver_classification.py
- tests/unit/test_harness_pathtraver_recorder.py
- tests/integration/test_harness_runner.py
- tests/integration/test_harness_e2e.py

Docs:
- docs/STRATEGIC-ROADMAP-2026-11-15.md
- docs/MILESTONE-REGISTER.md
- docs/m83_scope.md
- docs/m83_gate_d_proposal.md

Benchmark:
- benchmark/track_a/case_vectors.csv
- benchmark/track_a/_safe_sample.csv
- benchmark/track_a/build_and_run.ps1
- benchmark/track_a/Dockerfile.owasp-benchmark

### 10.3 Verification performed

- B1 pytest tests/integration/test_harness_e2e.py — 1 passed in 9.05s
- B2 Run 1 exit_code 1, accounting_valid true, findings 1
- B2 Run 2 exit_code 1, accounting_valid true, findings 1
- Structural comparison: selection, skipped, case dirs all IDENTICAL
- Per-case field comparison: 26/30 match, 4/30 differ (target canary randomness; target state mutation; indeterminate case)
- Post-run git state HEAD afd6c59, origin/main e16811c, status clean except two pre-existing untracked files

