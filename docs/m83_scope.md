# M83 — Path Traversal Classification Scope

**Status:** scope document, awaiting decision on three open rules
**Depends on:** `docs/pathtraver_audit_amendment.md`, audit §5.2
**Prerequisite for:** any future achievable-recall statement for traversal

---

## 1. The problem this scope addresses

The current documentation in `docs/pathtraver.md` presents 123 non-firing pathtraver cases as "structurally unobservable", and asserts they fall into a "no divergence" bucket "by construction of the oracle". Audit §5.2 rejects this claim on two grounds:

1. The 72-case sample from which the shape counts derive was never preserved, so the sample is not a census.
2. The classification "no divergence" requires the paired existence oracle to have evaluated each case — which requires preconditions (in-arm payload delivery, paired probe responses, baseline availability) that have not been verified for the 49 executed-silent cases.

M83 exists to answer that gap, by classifying each pathtraver case against the five §5.2 classes, using a forward measurement that preserves evidence.

## 2. The five §5.2 classes

| Class | Definition (from audit §5.2) | Grounding |
|---|---|---|
| `existence_divergence` | Existing and nonexistent paths produce distinguishable results | `analyzer.py:784` `check_pathtraver_oracle`; ADR-003 §Context; ADR-027 D7 |
| `no_observable_divergence` | Vulnerability sink produces indistinguishable responses | Oracle non-firing branch; ADR-003 |
| `distinctive_content` | File contents or file-specific evidence appears | ADR-006 collapse oracle concept; LFI content oracle |
| `payload_neutralised` | Application never receives effective traversal input | Audit §5.2; supported by `skipped.jsonl` mode data |
| `inconclusive` | Insufficient evidence | Boundary class; ADR-006 WAF-block discussion |

**Alias:** the roadmap uses `no divergence` for `no_observable_divergence`. This document uses the §5.2 full name. Any roadmap reference should be read as the same class.

## 3. Per-case record schema

Each pathtraver case in a classified run must produce one record with these fields. The record extends the existing run-directory convention (`findings.jsonl`, `skipped.jsonl`, `timeouts.jsonl`, `manifest.json`) rather than inventing a parallel subsystem.

```json
{
  "testname": "BenchmarkTest00028",
  "category": "pathtraver-00",
  "mode": "param",
  "delivery": {
    "delivered": true,
    "request_method": "GET",
    "request_path": "/benchmark/pathtraver-00/BenchmarkTest00028?BenchmarkTest00028=...",
    "payload_verbatim": "../../../../etc/passwd",
    "payload_observed": "…",
    "delivery_status": "unchanged"
  },
  "probes": {
    "baseline":      { "status": 200, "headers_sha256": "...", "body_sha256": "..." },
    "exists_path":   { "status": 200, "headers_sha256": "...", "body_sha256": "..." },
    "nonexist_path": { "status": 200, "headers_sha256": "...", "body_sha256": "..." }
  },
  "comparison": {
    "status_diff": false,
    "headers_diff": false,
    "body_diff": false,
    "structural_diff": false,
    "leak_signal": false
  },
  "classification": "no_observable_divergence",
  "classification_reason": "…",
  "evidence_hash": "sha256(...)"
}

**Attachment point.** `check_pathtraver_oracle` (`analyzer.py:784`) already receives both probe responses as inputs (`snapshot_exists`, `snapshot_noexist`, `payload_exists`, `payload_noexist`). The recorder attaches at the call site: capture those five arguments plus the classification returned, write one record. No change inside the oracle itself.

**Delivery classification vocabulary.** Borrowed from audit §5.1 Stage 2 (SQLi delivery-path classification) for consistency: `unchanged | normalised | encoded | truncated | rejected | ambiguous`.

**`structural_diff` definition.** Whether the normalised structural signature differs between the two probe responses. The signature is implementation-defined; a reasonable default is the SHA-256 of the response body after whitespace normalisation, dynamic-token masking, and HTML-tag-stripping. The harness design must fix this definition before classification begins, because the definition drives the `no_observable_divergence` boundary.


## 4. Delivery mode → classification mapping

The baseline run's `skipped.jsonl` shows three modes. Each maps to a different disposition under this scope:

| Mode | Cases | Initial disposition | Rationale |
|---|---|---|---|
| `header_any` | 98 | `payload_neutralised` | Payload never delivered via header channel |
| `out_of_scope_stream` | 3 | Out of traversal scope | Different vulnerability class |
| `out_of_scope_uri` | 1 | Out of traversal scope | Different vulnerability class |

The 49 executed-silent cases are not in `skipped.jsonl` and are not in `timeouts.jsonl`. They are the actual target of the forward measurement: they were delivered, but produced no finding, and their disposition is currently **unknown** — not "no divergence by construction".

## 5. Three open rules — decide before running the harness

### Rule 1 — denominator definition

Which classes count toward the "classified denominator" for achievable recall?

| Option | Denominator | Resulting achievable recall (assuming 10 TP, 49 inconclusive, 98 neutralised) |
|---|---|---|
| **R1a** All 133 vulnerable cases count | 10 + 49 + 14 + 60 = 133 | **10 / 133 = 0.075** (matches shipped figure) |
| **R1b** Only executed cases count | 10 + 49 = 59 | 10 / 59 = 0.169 |
| **R1c** `payload_neutralised` excluded, inconclusive counted | 10 + 49 = 59 | same as R1b unless inconclusive resolved |
| **R1d** Only `existence_divergence` + `no_observable_divergence` | 10 + N classified | depends on harness result |

**Note on the numerator.** The recall numerator is 10 in the current run because no non-firing case has been classified as `existence_divergence` in retrospect. Under R1b or R1c, the denominator is 59 regardless of how the 49 executed-silent cases are eventually classified — the recall does not improve merely by moving non-findings between `inconclusive` and `no_observable_divergence`. That distinction matters only for a supplementary statement of how much of the executed set was structurally unobservable.

**Census caveat.** Before Rule 1 can be applied, the 133 census must be re-derived (see `pathtraver_audit_amendment.md` §3). The 10 + 49 + 98 = 157 arithmetic does not currently reconcile with 133.

### Rule 2 — inconclusive adjudication

| Option | Rule | Effect |
|---|---|---|
| **R2a** Strict — inconclusive unless a positive signal | Only classify as a non-inconclusive class if the signal is unambiguous | Higher precision, more inconclusive |
| **R2b** Lenient — classify by best-fit | Assign to the closest class with a documented rationale | Lower precision, fewer inconclusive |
| **R2c** Two-tier — primary + confidence | Emit primary class and confidence band | More information, more complex reporting |

**Recommendation:** R2a. It matches the §5.2 principle that "the paired existence oracle is logically sound … report only when the distinction is supported", and it avoids the failure mode the audit warns against — broadening the gate to increase score.


### Rule 3 — leakage branch disposition

The oracle's docstring names three silent branches:

> "Silent when both agree, when either is ambiguous, or when the signals leak from the payload or the baseline."

The five §5.2 classes do not name the third. A silent result caused by leakage is a **fourth** case that must be dispositioned explicitly.

| Option | Disposition | Rationale |
|---|---|---|
| **R3a** Fold into `inconclusive` | Leakage is insufficient evidence of divergence | Simple; consistent with R2a |
| **R3b** New class `signal_leak` | Preserves diagnostic information | Broader taxonomy, requires doc update |
| **R3c** Suppress silently | Not recorded | Rejected — violates evidence preservation |

**Recommendation:** R3a. It keeps the taxonomy at five classes as §5.2 specifies, and the leakage diagnostic can still be recorded in `classification_reason` without needing a top-level class.

## 6. The 60 SSRF-only cases

`findings.jsonl` contains 60 entries with `class=ssrf` on pathtraver URLs. The scorer treats them as out-of-scope and they do not count as TP/FP. Under §5.3, these cases fall under the SSRF capability model:

> "Where the application cannot control the necessary metadata headers or perform the required multi-step interaction, the result should be reported as unsupported or untested rather than implying cloud metadata coverage."

**Disposition:** the 60 SSRF-only cases are **inside** the 133 census — they
are vulnerable pathtraver testcases on which the SSRF oracle fired rather than
the traversal oracle. For M83's denominator they count. Their classification
is deferred to §5.3's capability profiles (URL fetch / DNS resolution / HTTP
callback / redirect following / cloud metadata / file protocol) as a separate
work item, because the traversal oracle cannot classify them. The scorer's
current treatment as out-of-scope is a scoring convention, not a classification
statement.

## 7. The constraint

Carried verbatim from audit §5.2:

> "A critical principle: never loosen the traversal oracle simply to improve its benchmark score. A scanner that reports 100 additional false positives is not an improvement."

M83's success metric is **classification completeness**, not recall. If the harness shows that most of the 49 executed-silent cases are `no_observable_divergence`, achievable recall may be much higher than current documentation suggests. If it shows most are `inconclusive` due to delivery problems, achievable recall may remain low — but the number will be honest.

## 8. Phase 2 measurement protocol (summary)

1. **Dedicated harness** for pathtraver, separate from the general scanner.
2. **Preserve case selection** — write the exact list of cases in the run directory as `case_selection.json`.
3. **Record delivered request** — full wire-level request as issued.
4. **Record both probe responses** — existing-path and nonexistent-path.
5. **Record comparison features** — status, headers, body, structural signature, leak-detection.
6. **Classify per case** — assign one of the five classes with reason.
7. **Write per-case record** — one JSON line per case, in `case_records.jsonl` in the run directory.

Total cases: all 133 (or the re-derived census), not the 72-case sample. The 72-case sample's outcome counts, as recorded in `analyzer.py:776-783`, provide a prior for the harness result, not a substitute for it.

## 9. What this scope does not do

- It does not change the oracle.
- It does not change the scanner's detection behaviour.
- It does not commit to any recall number.
- It does not classify the 60 SSRF-only cases (they belong under §5.3).
- It does not retroactively classify the baseline run — that run lacked the evidence, which is why the forward harness is needed.

## 10. Entry points

- `docs/pathtraver.md` — corrected on 2026-11-13 (5 edits applied; see `pathtraver_audit_amendment.md` for the source). The circular "by construction" claim is removed; the provenance note remains, pending the harness's classification.
- `docs/pathtraver_audit_amendment.md` — retroactive count corrections.
- `analyzer.py:784` — `check_pathtraver_oracle`, the attachment point for the per-case recorder.
- `benchmark/track_a/runner.py` — run-directory contract to be extended with `case_records.jsonl` and `case_selection.json`.

---

*Decisions recorded: R1b (denominator = executed cases only), R2a (strict inconclusive), R3a (leakage folded into inconclusive). The §5 options tables are retained for provenance; the recorded choices are authoritative.*