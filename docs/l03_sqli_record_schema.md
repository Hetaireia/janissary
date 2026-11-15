# L03 — SQLi Per-Case Record Schema

**Status:** Schema specification (no implementation)
**Parent:** JAN-L03, `docs/l03_sqli_classification.md`
**Scope:** Specification only. No payload, scanner, oracle, or threshold changes.

## 1. Purpose

`docs/l03_sqli_classification.md` §5 establishes what evidence classifies an observation as `delivered` / `neutralised` / `indistinguishable`. This document specifies how that evidence is recorded per case, so classification is measurable rather than argued.

One record per (param, payload-pair) observation. Both firing and non-firing observations are recorded — the classification question is about the non-firing cases, and a schema that only records findings cannot answer it.

## 2. Scope

Records are produced for:

- `payload_name` beginning `sql_` (from `DEFAULT_PAYLOADS`, `scanner.py:73`)
- `payload_name` beginning `sqli_blind_` (from blind-pair probes)

Both firing and non-firing observations are recorded.

Out of scope:

- Cross-class `db_error` findings produced by non-SQLi payloads
- Cross-class `timing_anomaly` findings produced by non-SQLi payloads
- Union extraction from `attack sqli` (not on scan path — see §3 of the classification doc)
- Traversal, XSS, SSRF, and other-class observations

## 3. Oracle attachment points

Two standalone SQLi oracles run on the scan path:

| Oracle | Definition | Call site | Input shape |
|---|---|---|---|
| `check_sqli_quote_oracle` | `analyzer.py:838` | `scanner.py:1994` | 3-snapshot triple (baseline, quote, or) |
| `check_blind_sqli_oracle` | `blind_sqli_oracle.py:54` | `scanner.py:1700` | 2-snapshot pair (true, false), keyword-only |

The recorder wraps the oracle call and captures inputs plus the returned finding list. No change inside either oracle.

No other scan-path site produces SQLi oracle evidence. Error-pattern (`db_error`) and timing (`timing_anomaly`) observations are produced by the differential analyzer, not by dedicated SQLi oracles, and are not recorded here (§2).

## 4. Record schema

One JSONL record per (param, payload-pair, attempt) observation, written to `case_records.jsonl` in the run directory alongside `findings.jsonl` / `skipped.jsonl` / `timeouts.jsonl` / `manifest.json`. Baselines and cross-attempt reproducibility are managed in auxiliary files described in §4.4.

```json
{
  "observation_id": "sha256(param|payload_pair|run_id|attempt)[0:16]",
  "run_id": "20261114T033012Z-target-r1",
  "attempt": 1,
  "testname": "BenchmarkTest00028",
  "category": "sqli-00",
  "param": "id",
  "oracle": "quote | blind",
  "payload_name": "sql_quote",
  "dialect": "postgresql",
  "baseline_id": "sha256(target|param|baseline_run_id)[0:16]",
  "delivery": {
    "delivered": true,
    "request_method": "GET",
    "request_path": "/rest/products/search?q=...",
    "payload_verbatim": "'",
    "payload_observed": "...",
    "delivery_status": "unchanged"
  },
  "observations": [
    {
      "role": "quote",
      "status": 500,
      "headers_sha256": "...",
      "body_sha256": "...",
      "body_length": 234,
      "elapsed": 0.052,
      "payload": "'"
    },
    {
      "role": "or",
      "status": 200,
      "headers_sha256": "...",
      "body_sha256": "...",
      "body_length": 12345,
      "elapsed": 0.048,
      "payload": "' OR '1'='1"
    }
  ],
  "comparison": {
    "error_signature_hit": true,
    "boolean_divergence": false,
    "timing_anomaly": false,
    "status_divergence": true,
    "length_divergence": true
  },
  "classification": "delivered | neutralised | indistinguishable",
  "classification_reason": "...",
  "uncertainty": "...",
  "evidence_hash": "sha256(...)"
}

### 4.1 observations[] and role

An array, not fixed keys, because the two oracles produce different role-sets:

| Oracle | Roles | Rationale |
|---|---|---|
| quote | `quote`, `or` | `check_sqli_quote_oracle(baseline, quote_snapshot, or_snapshot)`; baseline referenced by `baseline_id` |
| blind | `true`, `false` | `check_blind_sqli_oracle` takes paired true/false responses |

The `baseline` snapshot the quote oracle receives is not carried in `observations[]`; it is referenced via the top-level `baseline_id` and resolved against `baselines.jsonl` (§4.4). For blind, there is no baseline — the oracle's comparison is true-vs-false.

Blind SQLi records both `true` and `false` observations linked by role tag to the same classification record. For the blind oracle, `payload_name` names the base payload pair; the per-observation `role` disambiguates which half of the pair produced that response.

### 4.2 comparison block

Five booleans, each derived from channel-specific evidence:

| Field | Meaning | Evidence |
|---|---|---|
| `error_signature_hit` | Dialect error string present in any observation body | `DB_ERROR_PATTERNS` match against `body` |
| `boolean_divergence` | True and false responses differ reproducibly | Blind oracle's `_coherent` / `_coherent_for_length` |
| `timing_anomaly` | Any observation elapsed beyond `MIN_TIMING_DELTA` and `z >= MIN_TIMING_Z` vs baseline | `analyzer.py:~675` gate, restricted to SQLi observations per §2 |
| `status_divergence` | Any observation status differs from baseline | Direct comparison |
| `length_divergence` | Any observation normalised length differs from baseline beyond `BAND_SLACK` | `analyzer.py` length check |

For quote oracle, `boolean_divergence` is always `false` (no paired flip). For blind oracle, `error_signature_hit`, `status_divergence`, `length_divergence` still apply — the true/false pair can produce status or length differences.

`dialect` is populated when `error_signature_hit` is true, using the canonical identifier from `docs/l03_sqli_classification.md` §9.6 (`postgresql`, not `postgres`). It is `null` otherwise. For records written from the blind oracle, `dialect` is populated only if a dialect error string appears in either half of the pair.

`boolean_divergence` and `timing_anomaly` record what that attempt observed; they are not gated on cross-attempt reproducibility. Reproduction across `runs_required` attempts is adjudicated in the summary record (§4.4), which is the authority for confirmed divergence.

### 4.3 classification and uncertainty

Values and rationale per `docs/l03_sqli_classification.md` §2 and §6 (M83 R2a strict-inconclusive).

`uncertainty` is required. A record with no `uncertainty` field is rejected — it claims more certainty than any single observation supports (§7 of the classification doc).

### 4.4 baselines.jsonl and the reproducibility summary

Two auxiliary files accompany `case_records.jsonl`.

**`baselines.jsonl`** — one record per (target, param), keyed by `baseline_id`. Each record carries the complete baseline evidence: `status`, `headers_sha256`, `body_sha256`, `body_length`, `elapsed`, plus the identity fields `baseline_id`, `target`, `param`. Records in `case_records.jsonl` reference this by `baseline_id`; the hash is for integrity checking and does not substitute for the referenced evidence. `baseline_id` is `sha256(target|param|baseline_run_id)[0:16]`. The blind oracle has no baseline and its records carry `baseline_id: null`.

**`reproducibility_summary.jsonl`** — one record per composite identity `(target, category, dialect, oracle, param, payload_pair)`. Each record carries:

```json
{
  "summary_id": "sha256(target|category|dialect|oracle|param|payload_pair)[0:16]",
  "target": "http://127.0.0.1:8080/benchmark",
  "category": "sqli-00",
  "dialect": "postgresql",
  "oracle": "quote",
  "param": "id",
  "payload_pair": "sql_quote",
  "runs_observed": 3,
  "runs_required": 3,
  "confirmed": true,
  "confirmed_booleans": {
    "boolean_divergence": true,
    "timing_anomaly": false
  }
}
```

`confirmed` is true when `runs_observed >= runs_required` and every observed run agreed on the boolean values relevant to classification. `confirmed_booleans` is the set of booleans the summary adjudicates as reproduced.

**Authority for confirmed divergence.** Per-attempt records carry the raw booleans the attempt observed. Only the summary asserts `confirmed`. The record answers what was observed; the summary answers what is confirmed. Absence of a matching summary record means the observation has not been adjudicated as reproducible and may not be claimed as such.

## 5. Firing and non-firing both recorded

The oracle returns zero or more finding dicts. Both outcomes produce a record:

- **Firing:** classification is still recorded, because the evidence path matters for future recall work even when the oracle succeeded
- **Non-firing:** this is the FNs-under-classification case — the record captures what the response showed, and §5 of the classification doc judges it

A schema that records only firing cases cannot distinguish `delivered` from `neutralised` from `indistinguishable` on non-firing observations. Non-firing is the point.

## 6. No code changes

This document specifies the schema. Implementing the recorder is a separate change with its own tests. No payload, scanner, oracle, or threshold edits are approved by this document.

## 7. Open items

**7.1 — Record ordering and interleaving. DECIDED 2026-11-15.** One JSONL record per attempt, with a 1-indexed `attempt` field; retries are retained, not collapsed. Reproducibility aggregation moves to a separate summary file (§4.4). Per-attempt records carry raw observed booleans; only the summary asserts confirmed divergence.

**7.2 — Baseline deduplication. DECIDED 2026-11-15.** Shared `baselines.jsonl`; records carry a top-level `baseline_id` that resolves unambiguously to the complete baseline evidence. The baseline hash is for integrity checking and does not replace the referenced evidence (§4.4).

**7.3 — Comparison booleans are derived from responses, not from oracle output. DECIDED 2026-11-15.** Share derivation via an extracted helper; oracle and recorder call the same function. The implementation ticket includes the oracle refactor to call it.

**7.4 — Category value convention. DECIDED 2026-11-15.** Record carries the full benchmark sub-category (`sqli-00`, `sqli-01`, …), matching M83's `pathtraver-00` convention.

## 8. Acceptance criteria

1. Scope is SQLi payload names only — §2
2. Both firing and non-firing observations recorded — §5
3. Blind SQLi records both true and false via role tags — §4.1
4. Cross-class `db_error` and `timing_anomaly` excluded — §2
5. `observations[]` array accommodates both oracle shapes — §4.1
6. `uncertainty` field mandatory — §4.3
7. No code changes — §6
8. Open items named before implementation — §7
9. `payload_name` recorded per record — §4, §4.1
10. Per-attempt booleans recorded as observed; not gated on reproducibility — §4.2, §4.4
11. Canonical `dialect` recorded — §4, §4.2
12. One record per (param, payload-pair, attempt); `attempt` field present — §4, §4.4
13. Baselines shared in `baselines.jsonl`; `baseline_id` resolves unambiguously — §4, §4.4
14. Reproducibility summary in a separate file; authority for confirmed divergence — §4.4