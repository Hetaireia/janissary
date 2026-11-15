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

One JSONL record per (param, payload-pair, attempt) observation, written to `case_records.jsonl` in the run directory alongside `findings.jsonl` / `skipped.jsonl` / `timeouts.jsonl` / `manifest.json`. Baselines and cross-run reproducibility are managed in auxiliary files described in §4.4.

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

**Reserved fields (OP.9).** The `delivery` block is specified shape, not populated behaviour. No SQLi producer exists for `delivery.delivered`, `delivery.request_method`, `delivery.request_path`, `delivery.payload_observed`, or `delivery.delivery_status`. These fields are reserved design intent, marked NOT CURRENTLY POPULATED BY THE SQLi IMPLEMENTATION. They must not participate in classification or reproducibility until a producer is implemented and verified. `delivery.payload_verbatim` has a producer only in the pathtraver harness (`harness/pathtraver.py:239`), not on the SQLi path.

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

`boolean_divergence` and `timing_anomaly` record what that attempt observed; they are not gated on cross-run reproducibility. Reproduction across `runs_required` runs is adjudicated in the summary record (§4.4), which is the authority for confirmed divergence. Attempts are reconciled within a run before runs are compared (§4.4); "attempt" and "run" are not interchangeable counting units.

### 4.3 classification and uncertainty

Values and rationale per `docs/l03_sqli_classification.md` §2 and §6 (M83 R2a strict-inconclusive).

`uncertainty` is required. A record with no `uncertainty` field is rejected — it claims more certainty than any single observation supports (§7 of the classification doc).

### 4.4 baselines.jsonl, run identity, and the reproducibility summary

Two auxiliary files accompany `case_records.jsonl`.

**`baselines.jsonl`** — one record per (run_id, target, param), keyed by `baseline_id`. Each record carries the complete baseline evidence: `status`, `headers_sha256`, `body_sha256`, `body_length`, `elapsed`, plus identity fields `baseline_id`, `run_id`, `target`, `param`. Records in `case_records.jsonl` reference this by `baseline_id`. `baseline_id` is `sha256(run_id|target|param)[0:16]` — the run and parameter are part of the identity, so a baseline from one run is never silently reused for another. The blind oracle has no baseline and its records carry `baseline_id: null`.

**Run identity and independence.** A run is one independent scan invocation against one target with its own baseline collection. `run_id` is generated at invocation and carried on every per-attempt record. A run qualifies for reproducibility aggregation only when all of:

- it has a distinct `run_id`, and is not a replay of an existing qualifying run;
- its `target` and `config_hash` match the summary's composite identity;
- where baseline collection applies to the oracle (the quote oracle), the run has its own baseline for the relevant `target` and `param`; the blind oracle produces no baseline and its records carry `baseline_id: null`, which does not violate this condition;
- the run completed (manifest exists, exit status recorded).

A qualifying run counts regardless of whether every evidence boolean was collected. An uncollected boolean makes that run's value `unobserved`; it does not disqualify the run. `qualifying_runs` is the source of truth: `runs_observed` is `len(qualifying_runs)`, never derived from whichever evidence fields happened to be populated.

**Replay detection.** A replay is re-execution of the same scan invocation. Replaying under a retained `run_id` produces no new qualifying run: the existing summary's `runs_observed` does not increment, and the replay's attempts are recorded but treated as additional attempts within the existing run (subject to the partial-observation rule).

**What the contract cannot detect.** A copied run directory assigned a fresh `run_id` is indistinguishable from a genuinely new run by the mechanisms in this schema. The protocol does not claim independence for such cases. Consumers needing a stronger guarantee must verify provenance externally — CI logs, signed run artifacts, or a run-ledger maintained outside this schema. The `qualifying_runs` list is an assertion of the schema's rules, not a cryptographic proof of execution history.

**`config_hash`.** `manifest.json` carries `config_hash`, the SHA-256 over a canonicalised serialisation of the configuration dimensions that affect detection outcomes: payload set, threshold values (`MIN_TIMING_DELTA`, `MIN_TIMING_Z`, `MIN_SLEEP_FLOOR`, `BAND_SLACK`), oracle enablement flags, and authentication configuration. The manifest also carries `config_hash_algorithm` and `config_hash_inputs` (the enumerated dimensions covered). A dimension absent from `config_hash_inputs` is not covered by the independence guarantee; equal `config_hash` values assert equality only over the listed inputs.

**`reproducibility_summary.jsonl`** — one record per composite identity `(target, category, dialect, oracle, param, payload_pair)`, scoped to exactly one `config_hash`. `run_id` is not part of the key; the summary groups evidence *across* runs. Runs from different configurations are never aggregated under one summary. `config_hash` is part of the summary identity, not a partition applied after the fact — two summaries with different `config_hash` values never share a `summary_id`:

```
summary_id = sha256(target|category|dialect|oracle|param|payload_pair|config_hash)[0:16]
```

The summary record carries `config_hash` as an explicit field so the identity is auditable without recomputation. Each record carries:

```json
{
  "summary_id": "sha256(target|category|dialect|oracle|param|payload_pair|config_hash)[0:16]",
  "target": "http://127.0.0.1:8080/benchmark",
  "config_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
  "category": "sqli-00",
  "dialect": "postgresql",
  "oracle": "quote",
  "param": "id",
  "payload_pair": "sql_quote",
  "runs_required": 3,
  "runs_observed": 2,
  "qualifying_runs": ["20261115T033012Z-target-r1", "20261115T041045Z-target-r1"],
  "evidence": {
    "error_signature_hit": {
      "state": "confirmed-true",
      "conditions": [],
      "partial": false,
      "run_values": {
        "20261115T033012Z-target-r1": "true",
        "20261115T041045Z-target-r1": "true"
      },
      "disagreement_runs": [],
      "unobserved_runs": [],
      "attempts_total": 3,
      "attempts_observed": 3,
      "attempts_true": 3,
      "attempts_false": 0,
      "attempts_unobserved": 0
    },
    "boolean_divergence": {
      "state": "confirmed-false",
      "conditions": ["partial-observation"],
      "partial": true,
      "run_values": {
        "20261115T033012Z-target-r1": "false",
        "20261115T041045Z-target-r1": "unobserved"
      },
      "disagreement_runs": [],
      "unobserved_runs": ["20261115T041045Z-target-r1"],
      "attempts_total": 3,
      "attempts_observed": 2,
      "attempts_true": 0,
      "attempts_false": 2,
      "attempts_unobserved": 1
    },
    "timing_anomaly": {
      "state": "unobserved",
      "conditions": ["not-probed"],
      "partial": true,
      "run_values": {
        "20261115T033012Z-target-r1": "unobserved",
        "20261115T041045Z-target-r1": "unobserved"
      },
      "disagreement_runs": [],
      "unobserved_runs": ["20261115T033012Z-target-r1", "20261115T041045Z-target-r1"],
      "attempts_total": 0,
      "attempts_observed": 0,
      "attempts_true": 0,
      "attempts_false": 0,
      "attempts_unobserved": 0
    }
  },
  "summary_conditions": ["insufficient-runs", "partial-observation", "not-probed"]
}
```

**Run-level value.** For one evidence boolean, from the attempts in one run:

| Attempts in the run | Run value |
|---|---|
| none collected the boolean | `"unobserved"` |
| collected attempts all agree on true | `"true"` |
| collected attempts all agree on false | `"false"` |
| collected attempts disagree | `"disagreed"` |
| some collected, all collected agree, some did not collect | the agreed value; run `partial` is set (OP.10 Option B) |

A run with no collected observations is `"unobserved"`, never `"false"`. Missing attempts are never treated as agreement.

**Two kinds of unobserved.** A run is `"unobserved"` for a boolean in two distinct situations:

- **Not probed:** no attempt in the run attempted this boolean. `attempts_total: 0`, `attempts_unobserved: 0`.
- **Probed, not collected:** at least one attempt attempted the boolean but collected no value (timeout, error, no response). `attempts_total: N > 0`, `attempts_unobserved: N`.

Both produce run value `"unobserved"`. They are distinguishable in the underlying per-attempt records, and the counters preserve the distinction at summary level. A summary showing `attempts_total: 0` for timing means timing was not exercised, not that timing evidence was collected and was negative.

**Attempt counters.** For each evidence field:

- `attempts_total` — all attempts in qualifying runs for this evidence field's classification unit
- `attempts_observed` — attempts that collected a value; equals `attempts_true + attempts_false`
- `attempts_unobserved` — attempts that were made but did not collect a value for this field

Required identities:

```
attempts_total    = attempts_observed + attempts_unobserved
attempts_observed = attempts_true + attempts_false
```

`attempts_total` must reconcile with the sum of per-attempt records carrying this `summary_id`.

**Field `state`.** From the run values across qualifying runs, in precedence order:

1. any run value `"disagreed"` -> `"disagreed-within-run"`
2. all run values `"unobserved"` -> `"unobserved"`
3. observed run values disagree with each other -> `"disagreed"`
4. observed runs all agree, at least one run `"unobserved"` -> the agreed `"confirmed-true"` / `"confirmed-false"` (with `partial: true`)
5. all runs collected and agree -> `"confirmed-true"` / `"confirmed-false"`

**Field `conditions`** is an array of independently applicable, possibly coexisting conditions:

- `"not-probed"` — at least one qualifying run has `attempts_total: 0` for this boolean (the boolean was not exercised in that run)
- `"partial-observation"` — at least one attempt in at least one run exercised the boolean but collected no value, or a run's collection was incomplete
- `"within-run-disagreement"` — at least one run value is `"disagreed"`
- `"cross-run-disagreement"` — observed run values include both `"true"` and `"false"`

`not-probed` and `partial-observation` are distinct: the first is "the measurement was not attempted," the second is "the measurement was attempted and failed to produce a value." Both may apply simultaneously.

`run_values` uses the four string values above — never booleans — because a run can itself be `disagreed` or `unobserved`.

**`partial` flag.** `partial: true` whenever evidence coverage across qualifying runs is incomplete — that is, whenever `"not-probed"` or `"partial-observation"` is present in `conditions`. `partial: false` requires every qualifying run to have collected the boolean.

**`summary_conditions`** is a reporting-level array, not an enum, so conditions can coexist:

- `"insufficient-runs"` — `runs_observed < runs_required`
- `"not-probed"` — at least one field's conditions include `"not-probed"`
- `"partial-observation"` — at least one field's conditions include `"partial-observation"`
- `"within-run-disagreement"` — at least one field's conditions include `"within-run-disagreement"`
- `"cross-run-disagreement"` — at least one field's conditions include `"cross-run-disagreement"`

An empty array means none of these were detected; it does not independently prove every channel is positive.

**Authority and reading.** Per-attempt records carry the raw booleans each attempt observed. The summary adjudicates reproduction. There is no top-level `confirmed` field: each evidence field's `state` is authoritative for that boolean, `conditions` records overlapping defects, and `summary_conditions` qualifies whether the run set is sufficient. A consumer must read `state`, `conditions`, and `summary_conditions` together — `"confirmed-false"` with `summary_conditions: ["insufficient-runs"]` is a negative observation from too few runs, not a settled result.

## 5. Firing and non-firing both recorded

The oracle returns zero or more finding dicts. Both outcomes produce a record:

- **Firing:** classification is still recorded, because the evidence path matters for future recall work even when the oracle succeeded
- **Non-firing:** this is the FNs-under-classification case — the record captures what the response showed, and §5 of the classification doc judges it

A schema that records only firing cases cannot distinguish `delivered` from `neutralised` from `indistinguishable` on non-firing observations. Non-firing is the point.

## 6. No code changes

This document specifies the schema. Implementing the recorder is a separate change with its own tests. No payload, scanner, oracle, or threshold edits are approved by this document.

## 7. Decisions and open items

**7.1 — Record ordering and interleaving. DECIDED 2026-11-15.** One JSONL record per attempt, with a 1-indexed `attempt` field; retries are retained, not collapsed. Reproducibility aggregation moves to a separate summary file (§4.4). Per-attempt records carry raw observed booleans; only the summary asserts confirmed divergence.

**7.2 — Baseline deduplication. DECIDED 2026-11-15.** Shared `baselines.jsonl`; records carry a top-level `baseline_id` that resolves unambiguously to the complete baseline evidence. The baseline hash is for integrity checking and does not replace the referenced evidence (§4.4).

**7.3 — Comparison booleans are derived from responses, not from oracle output. DECIDED 2026-11-15.** Share derivation via an extracted helper; oracle and recorder call the same function. The implementation ticket includes the oracle refactor to call it.

**7.4 — Category value convention. DECIDED 2026-11-15.** Record carries the full benchmark sub-category (`sqli-00`, `sqli-01`, …), matching M83's `pathtraver-00` convention.

**7.5 — `case_selection.json` placement. OPEN.** The measurement protocol requires a per-run enumerated case list (`case_selection.json`, mirroring `docs/m83_scope.md` §8 step 2). Whether this is a protocol-level run artifact or a schema-level artifact is undecided. Recorded here as an open question; do not treat the artifact as either decided or excluded.

**7.6 — Channel-combination scope. OPEN.** The scope over which evidence from different channels may be combined into one classification verdict — which attempts/observations share a classification unit, and whether one channel's `disagreed` blocks another channel's `confirmed-true` — is undecided. Protocol-level (Phase D); recorded here so the schema does not imply a resolution.

**7.7 — `classification` field meaning in per-attempt records. OPEN.** Whether a per-attempt record's `classification` field is an attempt-local observation or a resolved classification, and whether the authoritative adjudication is written to a separate Phase D artifact, is undecided. Until resolved, the field is attempt-local only and must not be read as final.

## 8. Acceptance criteria

1. Scope is SQLi payload names only — §2
2. Both firing and non-firing observations recorded — §5
3. Blind SQLi records both true and false via role tags — §4.1
4. Cross-class `db_error` and `timing_anomaly` excluded — §2
5. `observations[]` array accommodates both oracle shapes — §4.1
6. `uncertainty` field mandatory — §4.3
7. No code changes — §6
8. Decisions and open items recorded — §7
9. `payload_name` recorded per record — §4, §4.1
10. Per-attempt booleans recorded as observed; not gated on reproducibility — §4.2, §4.4
11. Canonical `dialect` recorded — §4, §4.2
12. One record per (param, payload-pair, attempt); `attempt` field present — §4, §4.4
13. Baselines shared in `baselines.jsonl`; `baseline_id` resolves unambiguously — §4, §4.4
14. Reproducibility summary in a separate file; authority for confirmed divergence — §4.4
15. `run_id` present on per-attempt records; not part of the summary composite key — §4.4
16. Independence contract stated; `qualifying_runs` is the source of truth for `runs_observed` — §4.4
17. Per-field `evidence` carries five-state `state`, `conditions` array, `partial` flag, four-valued `run_values`, `disagreement_runs`, `unobserved_runs`, and attempt counters — §4.4
18. No aggregate `confirmed`; `summary_conditions` array permits coexisting conditions — §4.4
19. `config_hash` on manifest with `config_hash_algorithm` and `config_hash_inputs` — §4.4
20. `delivery.*` marked reserved / not populated — §4