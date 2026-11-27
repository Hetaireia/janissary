# Pathtraver Retrospective Audit Amendment

**Status:** amendment to the November retrospective audit (§4 "M83 audit" of the session handover dated 2026-11-13)

**Supersedes:** the outcome table in §4 of that handover

**Applies to:** tool v7.11.1, harness state at commit `ea7b3e5` (general benchmark runner; no dedicated pathtraver harness exists yet — that is what M83 builds), baseline run `benchmark/track_a/runs/20261112T180530Z-janissary-r1`

---

> **Document pairing.** This amendment corrects `docs/pathtraver.md`, the user-facing
explanation of the pathtraver ceiling. Commit `5fae530` (2026-11-13) replaced that
file's text with a copy of this amendment instead of applying the corrections in place;
the essay was restored on 2026-11-28. Every `docs/pathtraver.md:NN` reference below is to
the restored essay.

## 1. Corrected outcome counts

The handover recorded "14 skipped (header_any mode)". That figure is wrong by a factor of seven. `skipped.jsonl` for the baseline run contains **101** lines, with three distinct modes:

| Outcome | Cases | Evidence state | Disposition |
|---|---|---|---|
| Traversal findings | 10 | In `findings.jsonl`, existence oracle | `existence_divergence` |
| SSRF-only findings | 60 | `class=ssrf` on pathtraver URLs; scorer treats as out-of-scope | Out of traversal scope; §5.3 capability model |
| Executed, no finding | 49 | Absent from `findings.jsonl`, `skipped.jsonl`, `timeouts.jsonl` | `inconclusive` |
| Skipped — `header_any`, vulnerable | 14 | In `skipped.jsonl`; payload never delivered | `payload_neutralised` |
| Skipped — `header_any`, not vulnerable | 84 | In `skipped.jsonl`; payload never delivered | Outside the 133 |
| Skipped — `out_of_scope_stream` | 3 | In `skipped.jsonl`; scoping decision | Out of traversal scope |
| Skipped — `out_of_scope_uri` | 1 | In `skipped.jsonl`; scoping decision | Out of traversal scope |

The 133 census is confirmed by `_pathtraver_only.csv` (133 `,true$` rows) and by intersection with `case_vectors.csv` (133 vulnerable cases, no orphans either direction). The corrected breakdown by disposition closes exactly:

    10 (findings)
  + 60 (SSRF-only findings, inside the 133)
  + 49 (executed, no finding)
  + 14 (skipped header_any, vulnerable)
  = 133

The 98 figure in `skipped.jsonl` counts all `header_any` skips, of which 14 are vulnerable and 84 are not. The 4 `out_of_scope_*` skips are not vulnerable, do not enter the 133, and are not part of M83.

**Recall consequence.** 10 / 133 = 0.075, which is exactly the figure already recorded in `docs/pathtraver.md:57`. The documentation recall number was always correct; what was wrong was its justification — "123 non-firing cases fall into a no-divergence bucket by construction" is now replaced by the three-way decomposition above. None of the 123 has been classified as `no_observable_divergence`; that is what the §5.2 harness exists to determine.

`timeouts.jsonl` is empty for this run. No vulnerable case is attributable to timeout.

## 2. What the handover got wrong

1. **Skipped count.** Recorded 14; actual 101. Mode attribution was also imprecise: the handover attributed all skips to `header_any`, but 4 of the 101 are `out_of_scope_stream` / `out_of_scope_uri`, which are scoping decisions, not delivery failures.

2. **Consequence for `payload_neutralised`.** The class applies to the **98** `header_any` cases. It does **not** apply to the whole skipped set — the 4 out-of-scope cases belong under the SSRF / scoping discussion, not under traversal delivery.

## 3. Arithmetic gap requiring re-derivation

The handover states 133 vulnerable cases. Its own disposition breakdown, taken at face value, does not close:

    10 (findings) + 49 (executed silent) + 98 (header_any skipped) = 157

157 is not 133. The difference is 24, and the reason is that 98 counted every `header_any` skip rather than only the 14 vulnerable ones inside the 133.

**Resolved in §1.** The 133 census re-derives exactly from `benchmark/track_a/case_vectors.csv` intersect `benchmark/track_a/_pathtraver_only.csv` (133 on both sides, no orphans either direction), and the breakdown closes at 133 once the 84 non-vulnerable `header_any` skips and the 4 `out_of_scope_*` skips are separated out. The 133 figure stands in all three places that carry it:

- `docs/pathtraver.md:57` (provenance note)
- The handover §4 table
- The Amendment 29 commentary

**M83 still owes** the denominator rule and the adjudication rule for the 49 `inconclusive` cases. What it no longer owes is the census itself.

## 4. Exit-code semantics recorded

`benchmark/track_a/runner.py:18-20` states:

> "Per-case stdout appended to findings.jsonl. Per-case exit … error other than exit code 1 (findings) is a hard fail."

Therefore:

- `manifest.json` `"exit_code": 1` on the baseline run means **findings are present**, not that the scan failed.
- Exit codes other than 0 and 1 indicate genuine failures.

Any future reference to the baseline run should note that `exit_code: 1` is the expected signal for "findings present", not a reproducibility defect.

## 5. §4.1 of the retrospective audit — non-reproduction

The November audit's §4.1 reported a bug in `heuristic/engine.py` `_select_target()`:

> "The header aggregation uses a literal backslash-n sequence rather than an actual newline separator."

Verification against HEAD `0ca5bfe`:

- `heuristic/engine.py:380` — `headers = "\n".join(f"{k}: {v}" for k, v in obs.headers.items())` — `"\n"` is a genuine newline character.
- `heuristic/engine.py:384` — `return (obs.body or "") + chr(10) + headers` — `chr(10)` is byte-identical to `"\n"`.

Both use genuine newlines. The audit's claim **does not reproduce**. No fix is required at HEAD.

## 6. Items retired from the handover's outstanding list

| Item | Disposition |
|---|---|
| `_select_target()` backslash-n bug | Does not reproduce; no fix needed |
| Exit-code-1 semantics unrecorded | Recorded in §4 above |
| 14 skipped figure | Corrected to 101 in §1 above |

## 7. Items deferred to M83

| Item | Reason |
|---|---|
| Re-derivation of 133 census | §1 and §3 above; resolved — census re-derived at 133 both sides |
| Denominator rule decision | M83 scope; three options with arithmetic |
| Inconclusive adjudication rule | M83 scope; three options |
| Disposition of 60 SSRF-only cases | M83 scope; §5.3 capability model |
| `docs/pathtraver.md:57` provenance note | Already corrected; §5.2 harness still needed to close the claim |

---

*This amendment is authoritative for the retrospective counts. Future documents referring to the M83 audit must cite this amendment, not the handover §4 table.*
