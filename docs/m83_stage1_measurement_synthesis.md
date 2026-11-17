# M83 Stage 1 — Consolidated Measurement Evidence Synthesis

Consolidated Stage 1 measurement evidence synthesis.

Prepared: 2026-11-16
Evidence source: two 2026-11-15 full-corpus runs (`benchmark/track_a/runs/20261115T115138Z-janissary-r1` and `benchmark/track_a/runs/20261115T201527Z-janissary-r2`) and the read-only investigations conducted against them. No new evidence introduced; no repository file written by this synthesis.
Status: provisional baseline. Repeatability established under the two tested controlled conditions (section 8); universal repeatability under materially different conditions remains unresolved.

## 1. Tier convention

Three tiers, used throughout, not to be collapsed:

- **Established** — demonstrated from artefacts. Would require new evidence to overturn.
- **Strongly supported** — consistent with all evidence; no artefact contradicts; the specific trigger or causal chain is unproven.
- **Unresolved** — insufficient evidence; not resolvable from existing artefacts.


## 2. Execution summary

Two full-corpus runs under identical conditions at `benchmark/track_a/runs/20261115T115138Z-janissary-r1` and `benchmark/track_a/runs/20261115T201527Z-janissary-r2`.

| Attribute | Value |
|---|---|
| Corpus | `benchmark/track_a/case_vectors.csv`, 2,740 cases |
| Target | `http://127.0.0.1:8080/benchmark`, image `janissary/owasp-benchmark:20cbf3d` (sha256 `57693fcd...`) |
| Harness commit | `8a9acc55f11c1f79c8accff4ad92891d4a190f39` — sourced from Run 1 `manifest.json` |
| Tool version | 7.11.1 |
| Window | started `11:51:38Z`, finished `13:01:23Z` — 70 minutes |
| Manifest exit code | 1 (findings present; not a defect signal) |
| Container | `f25cc0ef...`, started fresh before the run |

**Tier:** *Established* as executed with those attributes. *Strongly supported* as a fresh-container run — freshness inferred from Docker's `--rm` plus container replacement, not from a direct filesystem check. *Unresolved* as repeatable: two controlled full-corpus runs establish repeatability and failure-set determinism (section 8); universal repeatability under materially different conditions remains unresolved.

## 3. Corpus accounting

| Disposition | Count |
|---|---:|
| has_observations | 2,560 |
| not_reached | 93 |
| recording_indeterminate | 87 |
| zero_observations | 0 |
| recording_failed | 0 |
| recording_disabled | 0 |
| **Total** | **2,740** |

`accounting_valid: true`; `primary_dispositions_sum = missing_breakdown_sum = 2,740`. **Tier: Established.**

Decomposition from read-only cross-tab:

| Category | not_reached | recording_indeterminate |
|---|---:|---:|
| All `header_any` (89 corpus total) | 89 | — |
| `out_of_scope_stream` (3 corpus total) | 3 | — |
| `out_of_scope_uri` (1 corpus total) | 1 | — |
| `ldapi-00` | — | 59 (all of the category) |
| Other categories (sqli-00 to sqli-05, pathtraver-00) | — | 28 |

The 93 `not_reached` are deliberate dispatch exclusions (`runner.py:98-99`); the 87 `recording_indeterminate` are scanner subprocess failures (section 6). These are distinct measurement limitations and must not be merged.

Vulnerable-case composition:
- 93 `not_reached`: 42 vulnerable, 51 safe. 14 vulnerable are pathtraver (pathtraver-00 x5, pathtraver-01 x4, pathtraver-02 x5).
- 87 `recording_indeterminate`: 27 vulnerable (all `ldapi-00`), 60 safe. 2 safe are pathtraver-00.

## 4. Benchmark result

| Block | TP | FP | FN | TN | P | R | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Full corpus | 961 | 0 | 454 | 1,325 | 1.000 | 0.679 | 0.809 |
| DAST-applicable | 961 | 0 | 195 | 1,102 | 1.000 | 0.831 | 0.908 |
| Supported-classes | 951 | 0 | 72 | 967 | 1.000 | 0.930 | 0.964 |

`findings=2039`, `wrong_family=0`, `orphan=0`, `out_of_scope=727` (SSRF; item 17 at corpus scale).

**Tier:** Precision 1.000 and FP 0 are *established* across every observed execution. Recall 0.831 and F1 0.908 are *established for this run*; not claimed as repeatable.

## 5. Pathtraver primary and secondary measurements

| Subcategory | TP | FN | Recall (of all vulnerable) |
|---|---:|---:|---:|
| pathtraver-00 | 4 | 42 | 0.087 |
| pathtraver-01 | 1 | 39 | 0.025 |
| pathtraver-02 | 3 | 33 | 0.083 |
| pathtraver-03 | 2 | 9 | 0.182 |
| **Total** | **10** | **123** | **0.075** |

**Primary — historical-comparable:** 10 / 133 = 0.075. Denominator includes 14 vulnerable pathtraver cases deliberately excluded from dispatch (all `header_any`). End-to-end pipeline coverage, not detector-only.

**Secondary — reachable population:** 10 / 119 = 0.084. Denominator excludes the 14 `header_any` exclusions. Isolates measured detection performance among cases that ran.

**+7 acceptance floor on primary:** 17 / 133 = 0.128.

The 2 safe pathtraver cases among the 87 indeterminate (`BenchmarkTest00134`, `BenchmarkTest00135`) do not change vulnerable recall; they are unobserved-not-positive (see section 12).

## 6. Item 23 — 87 subprocess failures

**Exit mechanism — Established.** Every one of the 87 cases has rc=2, a pre-created `case_raw/<tn>/` directory, and empty contents. `_emit_scan_result()` returns 2 when `summary.aborted` is true (`cli.py:597-598`). The other ten `return 2` sites in `cli.py` are on non-`scan` subcommands.

**Strongly supported.** The 87 rc=2 outcomes represent scanner aborts, most plausibly preflight failures at `scanner.py:1505-1507`. The four preflight sub-conditions (`scanner.py:899-906`) are observationally identical at the filesystem layer: request exception, no response, HTTP 5xx, empty body.

**Not fully excluded.**

- Argument-parsing exit-2 path: `parse_args()` can terminate internally with code 2 without any explicit `parser.error()` call. The custom `_ArgumentParser` subclass at `cli.py:1939` was not inspected. Uniform arguments across 2,653 successful cases make a general parsing failure implausible; a value-dependent parse failure for the specific testname-bearing parameter values of the 87 cases is implausible but not strictly excluded.
- 401-abort followed by silent status-write failure at `scanner.py:1586-1601`. `_write_recording_status()` catches all `Exception` silently (`scanner.py:1486-1489`); the 401-abort path does not `return` before reaching line 2256. This path is a qualified alternative, not eliminated by the filesystem evidence alone.

**Loss mechanism — Established.** Three independent design points each guarantee the abort reason is not preserved by the runner:

1. `--jsonl` is the runner's format (`runner.py:642`). JSONL mode of `OutputEmitter` (`emitter.py:344-365`) writes only findings and candidates, never scan metadata.
2. `_emit_scan_result()` emits at `cli.py:592-595` before the abort check at line 597. The abort reason never reaches the emitter.
3. The runner captures stdout only (`runner.py:666`; `_err_s` bound but unused). Stderr — where `_emit_abort_reason` writes at `cli.py:103` and `:916` — is discarded.

**Cross-confirmation.** None of the 87 testnames appears in `findings.jsonl`. All 2,039 records use the 19-field finding schema; no abort record, no zero-finding stub, no error record exists.

**The `OutputEmitter` lead is closed — established negatively.** The pipeline was designed to lose the abort reason. No artefact from this run or any prior run contains the abort reason for any of the 87. Resolving the trigger requires new runtime evidence (a single scanner invocation with `--json` or `--export`, or stderr capture) or an authorised instrumentation change. Neither is in scope.

**The 27 vulnerable `ldapi-00` cases are unobserved, not demonstrated detector misses — Established.** Their absence from `findings.jsonl` reflects a subprocess abort before the detector ran, not a detection failure. This distinction constrains what M37 can claim to improve.

## 7. Historical comparison and the 27-TP reconciliation

| Baseline | DAST TP | Findings total |
|---|---:|---:|
| 2026-11-12 (`20261112T180530Z`) | 988 | 2,077 |
| 2026-11-15 (`20261115T115138Z`) | 961 | 2,039 |
| Delta | -27 | -38 |

**Reconciliation — Established.** All 27 vulnerable `ldapi-00` cases were TPs in the 2026-11-12 baseline; the same 27 cases are indeterminate in the 2026-11-15 run; the sets are exactly equal (27/27 overlap, zero asymmetric exclusions on either side). `988 - 27 = 961` is proven from per-case artefacts, not inferred from totals.

## 8. `BenchmarkTest02467` anomaly and failure-set determinism

`BenchmarkTest02467` (pathtraver-03, param, safe) is indeterminate in both 30-case B2 executions (`20261115T083529Z`, `20261115T083836Z` and again in the `20261115T095411Z` / `20261115T095541Z` pair) and successful in the 2,740-case run.

**Observed difference — Established.** The outcome differs between the two execution conditions.

**Cause — Unresolved.** Candidate confounding variables, listed without ranking and without assigning evidential weight:

- execution scale
- run duration
- target warm-up state
- state-mutation timing
- filesystem cache state
- per-case ordering

None is isolated by the available evidence.

**Consequence — Established.** The 87-case failure set was deterministic across two full-corpus runs under identical conditions (20261115T115138Z and 20261115T201527Z): identical indeterminate testnames (87/87), identical not_reached testnames (93/93), identical 2,039 finding fingerprints, and identical scoring at every level (DAST-applicable TP 961 / FP 0 / FN 195, P 1.000 / R 0.831 / F1 0.908). Two observations do not establish universal determinism; the result establishes determinism under these specific controlled conditions.

## 9. Item-by-item disposition

All 23 items are recorded. The four classification groups preserve the distinct natures of the findings; no item is implied to be an M83 defect unless its class says so.

Class key: ME = M83 measurement evidence; EE = Environment and execution finding; OS = Out-of-scope finding; DR = Dispatch and recording limitation.

| # | Class | Item | Disposition | Tier |
|---|---|---|---|---|
| 1 | ME | CLI `--record-case-dir` wired | Evidenced | Established |
| 2 | ME | Scanner receives recording directory | Evidenced | Established |
| 3 | ME | Real executable path | Evidenced (B1 e2e + B2 + full corpus) | Established |
| 4 | ME | Schema agreement scanner to runner | Structural agreement; `scanner_version` and `completed_at` informational, not type-validated | Established (structural) |
| 5 | ME | Case ID safety and naming | Evidenced | Established |
| 6 | ME | Recording status written and interpreted | Evidenced | Established |
| 7 | ME | Missing / invalid / failed status | Evidenced | Established |
| 8 | ME | Zero-observation vs failures | Evidenced | Established |
| 9 | ME | Failure-state taxonomy | `not_reached` and `recording_indeterminate` exercised at scale; `scan_aborted_at_case`, `scan_errored_at_case`, `execution_state_indeterminate` untested | Partially evidenced |
| 10 | ME | Repeatability | Two full-corpus runs under identical conditions; identical disposition sets, indeterminate set, skipped set, finding count, and fingerprint set (section 8) | Established under tested conditions |
| 11 | ME | Case provenance and aggregation | Case-level labels present; aggregation rule documented; alternative rules not adopted | Partially evidenced |
| 12 | ME | Scorer integration | `score_dast_aware.py` reads findings only; recorder output unconsumed | Verified gap |
| 13 | EE | `build_and_run.ps1` port mapping | Script maps 8443:8443 vs Dockerfile `EXPOSE 8080`; both committed in `0648ba1` | Environment finding |
| 14 | EE | Startup undocumented for prior-run reproduction | No tracked file names the correct startup command | Environment finding |
| 15 | EE | Container image drift | `-ldapfix` variant previously running, required undocumented LDAP server | Environment finding |
| 16 | EE | Target startup preconditions | Docker Desktop running; Opera closed | Environment finding |
| 17 | OS | SSRF entity-encoding FP | Deterministic; 727 occurrences at full-corpus scale; Stage 5 candidate | Out-of-scope defect |
| 18 | EE | Exit-code semantics | exit 1 on runs with findings; cannot serve as defect gate | Environment finding |
| 19 | EE | Target canary randomisation | Per-request random suffix defeats per-case byte-equality | Environment finding |
| 20 | EE | Target state mutation | `BenchmarkTest01570` creates a file that changes subsequent responses | Environment finding |
| 21 | DR | `header_any` exclusions | Deliberate; `runner.py:98-99`; 93 cases (89 header_any + 4 out_of_scope) | Resolved |
| 22 | DR | `ldapi-00` indeterminate cases | 59/59 `ldapi-00` indeterminate; all rc=2, empty dir; mechanism shared with 28 other cases | Resolved to evidence limits |
| 23 | DR | 87 subprocess failures | Exit mechanism and loss mechanism established; specific trigger unresolved | Mechanism established, trigger unresolved |

## 10. What is not established

Carried forward explicitly, not as gaps to be smoothed:

- Item 10 repeatability: two full-corpus measurements exist (20261115T115138Z and 20261115T201527Z), and repeatability was demonstrated across those two controlled observations — identical indeterminate and not_reached sets, identical 2,039 finding fingerprints, identical scoring at every level. Universal repeatability under materially different conditions is not established.
- Universal failure-set determinism: two full-corpus runs under identical conditions produced identical failure sets; determinism under materially different conditions (different image, host, load, or timing) remains untested.
- Which preflight condition fires for the 87 cases: four candidate sub-conditions indistinguishable from current artefacts; 401-then-silent-write not excluded.
- Whether `ldapi-00` and `02467` share a root cause: plausible; unestablished.
- Whether M37's +7 floor exceeds measurement noise: the 87 indeterminate cases are 3.2% of the 2,740-case corpus; the +7 floor is 5.3% of the 133-vulnerable historical denominator. Because the denominators differ, these figures cannot be directly compared as a margin. Failure-set stability under identical conditions is now established (section 8); the contribution of environmental variation between the M37 comparison window and the baseline window remains untested.

## 11. M37 acceptance implications

An M37 acceptance claim must be supported by two comparable full-corpus measurements under the same execution conditions. Two such measurements now exist (20261115T115138Z and 20261115T201527Z), and they are identical in finding fingerprints, indeterminate and not_reached sets, and scoring at every level. Repeatability under the tested conditions is therefore established; whether the same result would hold under materially different conditions is not.

Primary denominator: 133 (all vulnerable pathtraver). Secondary: 119 (reachable; excludes 14 `header_any`). The +7 acceptance floor on the primary denominator is 17/133 = 0.128.

Two further implications follow:

- Two-run confirmation of any acceptance delta remains a requirement. It is not required because the failure set is unstable under controlled conditions; two full-corpus runs demonstrate that it is stable. It is required because repeatability across two controlled observations does not eliminate environmental variation between execution windows, and does not by itself distinguish detector improvement from measurement variation.
- Any M37 comparison must be against a same-conditions baseline. Two same-conditions runs now exist for this purpose.

## 12. Scorer treatment of unobserved cases

The scorer (`benchmark/track_a/score_dast_aware.py`) treats any case with no matching finding on its URL path as TN (safe) or FN (vulnerable). For the 87 indeterminate cases this is not positive observation of clean behaviour; it is absence-of-finding.

| Case group | Scorer outcome | What was observed |
|---|---|---|
| 60 safe indeterminate | TN | Nothing — subprocess aborted before detector ran |
| 27 vulnerable `ldapi-00` | FN | Nothing — subprocess aborted before detector ran |
| 2 safe pathtraver indeterminate | TN | Nothing |

**Disclosure requirement — Established.** Any downstream use of the TN and FN counts, or of the 0.075 primary and 0.084 reachable pathtraver figures, inherits this limitation. Any M37 change to safe-case detection could re-classify the 2 safe pathtraver indeterminates and must be evaluated against this disclosure, not against a bare TN count.

## 13. Boundaries

This document is an evidence synthesis. It does not authorise:

- any register or roadmap change;
- any source, test, corpus, or runner change;
- any benchmark execution or container operation;
- any second full-corpus baseline run;
- any M37 implementation;
- any staging, commit, or push.

M83 remains verified-partial. The decisions this document surfaces are for separate assessment.

