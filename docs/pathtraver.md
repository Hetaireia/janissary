# Pathtraver Retrospective Audit Amendment

**Status:** amendment to the November retrospective audit (§4 "M83 audit" of the
session handover dated 2026-11-13)
**Supersedes:** the outcome table in §4 of that handover
**Applies to:** tool v7.11.1, harness commit `ea7b3e5`, baseline run
`benchmark/track_a/runs/20261112T180530Z-janissary-r1`

---

## 1. Corrected outcome counts

The handover recorded "14 skipped (header_any mode)". That figure is wrong by a
factor of seven. `skipped.jsonl` for the baseline run contains **101** lines,
with three distinct modes:

| Outcome | Cases | Evidence state | Disposition |
|---|---|---|---|
| Traversal findings | 10 | In `findings.jsonl`, existence oracle | `existence_divergence` |
| SSRF-only findings | 60 | `class=ssrf` on pathtraver URLs; scorer treats as out-of-scope | Out of traversal scope; §5.3 capability model |
| Executed, no finding | 49 | Absent from `findings.jsonl`, `skipped.jsonl`, `timeouts.jsonl` | `inconclusive` |
| Skipped — `header_any` | 98 | In `skipped.jsonl`; payload never delivered | `payload_neutralised` |
| Skipped — `out_of_scope_stream` | 3 | In `skipped.jsonl`; scoping decision | Out of traversal scope |
| Skipped — `out_of_scope_uri` | 1 | In `skipped.jsonl`; scoping decision | Out of traversal scope |

`timeouts.jsonl` is empty for this run. No vulnerable case is attributable to
timeout.

## 2. What the handover got wrong

1. **Skipped count.** Recorded 14; actual 101. Mode attribution was also
   imprecise: the handover attributed all skips to `header_any`, but 4 of the
   101 are `out_of_scope_stream` / `out_of_scope_uri`, which are scoping
   decisions, not delivery failures.
2. **Consequence for `payload_neutralised`.** The class applies to the **98**
   `header_any` cases. It does **not** apply to the whole skipped set — the 4
   out-of-scope cases are in a different category and belong under the SSRF /
   scoping discussion, not under traversal delivery.

## 3. Arithmetic gap requiring re-derivation

The handover states 133 vulnerable cases. The corrected breakdown by
disposition gives:

    10 (findings) + 49 (executed silent) + 98 (header_any skipped) = 157

157 ≠ 133. The difference is 24. This means either the 133 census is wrong, or
the outcomes above count cases that are not in the 133.

**M83 must re-derive the 133 figure** from `benchmark/track_a/case_vectors.csv`
∩ `benchmark/track_a/_pathtraver_only.csv` before any achievable-recall
denominator is stated. The 133 figure appears in:

- `docs/pathtraver.md:57` (provenance note)
- The handover's §4 table
- The Amendment 29 commentary

If the re-derivation shows a number other than 133, all three must be corrected.

## 4. Exit-code semantics recorded

`benchmark/track_a/runner.py:18-20` states:

> "Per-case stdout appended to findings.jsonl. Per-case exit … error other
> than exit code 1 (findings) is a hard fail."

Therefore:

- `manifest.json` `"exit_code": 1` on the baseline run means **findings are
  present**, not that the scan failed.
- Exit codes other than 0 and 1 indicate genuine failures.

The handover's §4 table did not record this. Any future reference to the
baseline run should note that `exit_code: 1` is the expected signal for
"findings present", not a reproducibility defect.

## 5. §4.1 of the retrospective audit — non-reproduction

The November audit's §4.1 reported a bug in `heuristic/engine.py`
`_select_target()`:

> "The header aggregation uses a literal backslash-n sequence rather than an
> actual newline separator."

Verification against HEAD `0ca5bfe`:

- `heuristic/engine.py:380` — `headers = "\n".join(f"{k}: {v}" for k, v in
  obs.headers.items())` — `"\n"` is a genuine newline character.
- `heuristic/engine.py:384` — `return (obs.body or "") + chr(10) + headers` —
  `chr(10)` is byte-identical to `"\n"`.

Both use genuine newlines. The audit's claim **does not reproduce**. Either
the bug was fixed between 11 November and HEAD, or the audit misread `chr(10)`
as a literal backslash sequence. No fix is required at HEAD.

## 6. Items retired from the handover's outstanding list

The following were listed as pending in §4/§5 of the handover but are already
addressed at HEAD or by this session's verification:

| Item | Disposition |
|---|---|
| `_select_target()` backslash-n bug | Does not reproduce; no fix needed |
| Exit-code-1 semantics unrecorded | Recorded in §4 above |
| 14 skipped figure | Corrected to 101 in §1 above |

## 7. Items deferred to M83

| Item | Reason |
|---|---|
| Re-derivation of 133 census | §3 above; requires census query |
| Denominator rule decision | M83 scope; three options with arithmetic |
| Inconclusive adjudication rule | M83 scope; three options |
| Disposition of 60 SSRF-only cases | M83 scope; §5.3 capability model |
| `docs/pathtraver.md:57` provenance note | Already corrected in commit applying 5 edits; §5.2 harness still needed to close the claim |

---

*This amendment is authoritative for the retrospective counts. Future documents
referring to the M83 audit must cite this amendment, not the handover §4 table.*