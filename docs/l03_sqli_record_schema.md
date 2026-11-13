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

One JSONL record per (param, payload-pair) observation, written to `case_records.jsonl` in the run directory alongside `findings.jsonl` / `skipped.jsonl` / `timeouts.jsonl` / `manifest.json`.

```json
{
  "observation_id": "sha256(param|payload_pair|run_id)[0:16]",
  "run_id": "20261114T033012Z-target-r1",
  "testname": "BenchmarkTest00028",
  "category": "sqli",
  "param": "id",
  "oracle": "quote | blind",
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
      "role": "baseline",
      "status": 200,
      "headers_sha256": "...",
      "body_sha256": "...",
      "body_length": 12345,
      "elapsed": 0.045,
      "payload": null
    },
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
| quote | `baseline`, `quote`, `or` | `check_sqli_quote_oracle(baseline, quote_snapshot, or_snapshot)` |
| blind | `true`, `false` | `check_blind_sqli_oracle` takes paired true/false responses |

No `baseline` role for blind: the blind oracle does not take one. Its comparison is true-vs-false, not injection-vs-baseline.

Blind SQLi records both `true` and `false` observations linked by role tag to the same classification record.

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

### 4.3 classification and uncertainty

Values and rationale per `docs/l03_sqli_classification.md` §2 and §6 (M83 R2a strict-inconclusive).

`uncertainty` is required. A record with no `uncertainty` field is rejected — it claims more certainty than any single observation supports (§7 of the classification doc).

## 5. Firing and non-firing both recorded

The oracle returns zero or more finding dicts. Both outcomes produce a record:

- **Firing:** classification is still recorded, because the evidence path matters for future recall work even when the oracle succeeded
- **Non-firing:** this is the FNs-under-classification case — the record captures what the response showed, and §5 of the classification doc judges it

A schema that records only firing cases cannot distinguish `no_observable_divergence` from `payload_neutralised` from `inconclusive` on the silent 49. Non-firing is the point.

## 6. No code changes

This document specifies the schema. Implementing the recorder is a separate change with its own tests. No payload, scanner, oracle, or threshold edits are approved by this document.

## 7. Open items

**7.1 — Record ordering and interleaving.** If the same (param, payload) is observed more than once in a run (e.g., retries), either all records are kept or the last is retained. Decision required before implementation.

**7.2 — Baseline deduplication.** Every SQLi payload for a given param shares the same baseline. A separate baseline record per observation duplicates storage; a shared reference reduces it but complicates readers. Decision required before implementation.

**7.3 — Comparison booleans are derived from responses, not from oracle output.** The oracle returns a finding or not; the booleans describe the inputs. A separate derivation function per channel must exist for the recorder, distinct from the oracle's internal logic, or the two must share. Risk of drift. Decision required before implementation.

## 8. Acceptance criteria

1. Scope is SQLi payload names only — §2
2. Both firing and non-firing observations recorded — §5
3. Blind SQLi records both true and false via role tags — §4.1
4. Cross-class `db_error` and `timing_anomaly` excluded — §2
5. `observations[]` array accommodates both oracle shapes — §4.1
6. `uncertainty` field mandatory — §4.3
7. No code changes — §6
8. Open items named before implementation — §7