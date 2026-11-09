# ZAP vs JANISSARY -- single-case and 20-case demonstration

**Status:** Reproducible on this hardware. Full-corpus comparison hardware-blocked.
**Date:** 2026-11-09
**Parent:** BENCHMARK.md Track A, hypotheses H-A1..H-A4

## The result

Against OWASP Benchmark test cases, both tools given the same URLs, the same parameter, and the same target:

| Scope | JANISSARY | ZAP (default invocation) |
|---|---|---|
| BenchmarkTest00008 (sqli-00, known vulnerable) | TP | FAIL-NEW: 0 |
| 20 sqli-00 cases | 20/20 TP | 0/20 TP |

JANISSARY figures from `runs/20261108T000131Z-janissary-r1` (F1 0.921, sqli-00 F1 1.000). ZAP figures from `runs/20261109T123834Z-zap-r3` (automation framework) and `runs/zap-manual` (single-URL `zap-full-scan.py`).

## Why ZAP fails

OWASP Benchmark's servlets are designed to defeat error-based and reflection-based detection:

1. Even when SQL is injected, the servlet returns HTTP 200 with no error message.
2. The response body does not reflect the payload.
3. There is no timing-based observable for the time-based rules to fire.

ZAP's SQL Injection rule [40018] and its five time-based variants all executed (`PASS:` in the scan output) and found nothing. This is not a ZAP bug — it is the ZAP detection model applied to a corpus that is explicitly designed to test that model.

JANISSARY's differential oracle fires because it compares response *shape* between the payload probe and the baseline, not content or error messages. The differential signal is present; the error/reflection signal is not.

## What this does NOT claim

- Not "ZAP is worse than JANISSARY in general." ZAP is a mature tool that does many things well.
- Not "the full corpus has been compared." 20 of 2740 cases have been tested.
- Not "H-A1 is confirmed." One case and one 20-case subset cannot carry a p-value claim.

## What would change this

If ZAP's scan policy were tuned per-case (custom scripting, custom payloads), the result could shift. That is out of scope per ADR-028 — the comparison is "stock ZAP as the ZAP project recommends it," which is what a user gets when they download ZAP and run it.

## Full comparison -- hardware blocker

Full 2740-case, 3-run-per-tool comparison requires ~70 hours of scan time and 16 GB+ RAM. This machine has 7.7 GB total, 4 GB in WSL. Cannot complete. Tracked in WORKFLOW.md NEXT item 2.
