# README Claims Inventory

**Generated:** 2026-10-27T21:46:12Z  
**Repo:** `C:\Users\M5 E60\janissary-project\janissary\janissary`  
**Audit target:** `7.5.0` -> `e5b484078223f626e32b7ab8552ee947ff71253d`

## Files scanned

- `README.md` - 418 lines, tracked
- `README.new.md` - 34 lines, untracked

## Matches by category

- **benchmark**: 15 lines
- **false-positive**: 8 lines
- **percentage**: 15 lines
- **precision**: 14 lines

## Detailed matches

### README.md

| Line | Categories | Rules fired | Text |
|---:|---|---|---|
| 17 | percentage | percent-any | `[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)` |
| 25 | benchmark | benchmark | `\| At a glance \| Key facts, benchmark headline, install \|` |
| 29 | benchmark | benchmark, owasp | `\| Benchmark \| OWASP Benchmark results \|` |
| 40 | false-positive | false-positive | `- **Bug bounty hunters** who need high-signal findings with Burp-ready evidence, not a wall of false positives to triage by hand.` |
| 52 | benchmark, false-positive, percentage, precision | benchmark, decimal-3dp, exact-1.000, f1, FP-token, owasp, precision, recall | `\| **Benchmark (OWASP)** \| **F1 0.921** - Precision 1.000 - Recall 0.854 - 0 FP \|` |
| 64 | false-positive | false-positive | `> **What makes JANISSARY different:** JANISSARY is an open-source DAST tool that offers proven WAF resilience, zero-false-positive differential detection, an...` |
| 68 | benchmark, false-positive, percentage, precision | benchmark, decimal-3dp, exact-1.000, f1, FP-token, owasp, precision, recall | `Every finding is gated by a baseline comparison — nothing emits from a single response. Reproduced on v7.3.0 (F1 unchanged through 7.4.0 and 7.5.0) against t...` |
| 170 | benchmark | benchmark | `## Benchmark` |
| 172 | benchmark | benchmark, owasp | `JANISSARY is scored against the OWASP Benchmark DAST-applicable corpus. Full results, methodology, and the class-aware definition are in `BENCHMARK.md`. Run ...` |
| 176 | percentage, precision | decimal-3dp, exact-1.000, precision | `\| Precision \| 1.000 \|` |
| 177 | percentage, precision | decimal-3dp, recall | `\| Recall \| 0.854 \|` |
| 178 | percentage, precision | decimal-3dp, f1 | `\| F1 \| 0.921 \|` |
| 179 | false-positive | FP-token | `\| TP / FP / FN \| 987 / 0 / 169 \|` |
| 180 | percentage, precision | decimal-3dp, exact-1.000, f1 | `\| Categories at F1 1.000 \| 20 \|` |
| 181 | percentage, precision | decimal-3dp, f1 | `\| 3-run unassisted baseline F1 \| 0.903 ± 0.009 (n=3) \|` |
| 183 | benchmark | benchmark | `Reproduce: `python benchmark/track_a/score_dast_aware.py benchmark/track_a/runs/20261024T130735Z-janissary-r1+rec`` |
| 185 | benchmark, percentage, precision | benchmark, decimal-3dp, f1 | `The F1 0.921 figure applies the FN-recovery protocol to the first two baseline runs; the third baseline run (`20261025T062837Z-janissary-r3`, F1 0.895) has n...` |
| 187 | benchmark, percentage, precision | benchmark, decimal-3dp, f1 | `The weakest category is path traversal (F1 0.049–0.308), documented in `docs/pathtraver.md` as a property of the benchmark target, not a scanner gap.` |
| 358 | precision | precision | `Being explicit about scope is part of being honest about precision:` |
| 362 | benchmark | owasp | `- **Not a full OWASP Top 10 scanner yet.** It ships SQLi, XSS, SSRF, and partial traversal. IDOR is 7.6.0. JWT and prototype pollution are 7.7.0.` |
| 369 | false-positive | false-positive | `- **SPA Catch-All False Positives (Issue #1):** Applications that return HTTP 200 for arbitrary routes (like SPAs) can cause the admin-panel check to report ...` |
| 372 | benchmark, percentage, precision | benchmark, decimal-3dp, recall | `- **Path traversal recall 0.049-0.308.** Not a supported detection class in 7.x. Documented in ``docs/pathtraver.md`` as a property of the benchmark target, ...` |
| 375 | benchmark, percentage, precision | benchmark, decimal-3dp, recall | `- **Path traversal recall 0.049-0.308.** Not a supported detection class in 7.x. Documented in ``docs/pathtraver.md`` as a property of the benchmark target, ...` |
| 378 | benchmark, percentage, precision | benchmark, decimal-3dp, recall | `- **Path traversal recall 0.049-0.308.** Not a supported detection class in 7.x. Documented in ``docs/pathtraver.md`` as a property of the benchmark target, ...` |
| 390 | benchmark | owasp | `JANISSARY was run against OWASP Juice Shop behind ModSecurity + OWASP CRS. The scanner detected the WAF, received block signals, and paced requests without a...` |

### README.new.md

| Line | Categories | Rules fired | Text |
|---:|---|---|---|
| 17 | percentage | percent-any | `[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)` |
| 25 | false-positive | false-positive | `> **The Strategic Wedge:** JANISSARY is an open-source DAST tool that offers proven WAF resilience, zero-false-positive differential detection, and Burp-read...` |
| 28 | benchmark, false-positive, percentage, precision | benchmark, decimal-3dp, exact-1.000, f1, FP-token, owasp, precision, recall | `**Differential detection, measured.** Every finding is gated by a baseline comparison — nothing emits from a single response. Reproduced on v7.3.0 against th...` |

