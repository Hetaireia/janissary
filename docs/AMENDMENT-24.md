# Amendment 24 — Item 2 real-world negatives (pre-registration)

**Status:** Active (design phase)
**Parent:** `docs/AMENDMENT-23.md` Item A (real-world FP rate)
**Baseline:** 7.5.0 (`e5b484078223f626e32b7ab8552ee947ff71253d`)
**Related:** `benchmark/track_c/`, `artifacts/7.5.0-baseline/`

## Purpose

Pre-register the campaign that will produce the real-world false-positive rate claimed under Amendment 23 Item A. This amendment governs the *design* — the corpus, unit of trial, and interval method. The measurement itself runs in future sessions against a locked corpus.

The rule from Amendment 23 carries forward unchanged: **pre-register the protocol, run it once, publish the result regardless of shape.** No tuning against the measurement corpus after the first run.

## Starting position — Track C today

Track C exists as a prototype, not a completed harness. What works after commit `e7b4170` (2026-10-28):

- Runner (`benchmark/track_c/runner.py`) logs in to DVWA, sets security level to low, invokes `janissary scan --jsonl --quiet --no-waf`, writes one JSONL per vuln class.
- Scorer (`benchmark/track_c/score.py`) maps findings to cases via `CLASS_MAP`, produces TP/FP/FN and P/R/F1 in `score.json`.
- Corpus (`apps.json`): DVWA and Juice Shop, 6 cases total.

What the pilot measured on DVWA (local, security=low, 4 cases):

| Metric | Pilot result |
|---|---|
| TP | 2 (xss, sqli) |
| FP | 8 |
| FN | 2 (sqli_blind, traversal) |
| Precision | 0.200 |
| Recall | 0.500 |
| F1 | 0.286 |

These numbers are a **development diagnostic**, not a measurement. They are committed to `benchmark/track_c/runs/20261028T073716Z-dvwa/` as the audit trail of the pilot state. **They are not a published claim.**

Two concrete interpretations to resolve before scaling:

1. **The 8 FPs are scanner over-detection.** Janissary fires findings whose `class` does not match the DVWA endpoint's expected vulnerability type. These are real FPs if the finding is wrong, but "the same endpoint reflects unencoded input" may be a legitimate observation the scanner labels as `xss` while the case expects `sqli`. The distinction matters: over-labels vs over-fires.
2. **The 8 FPs are scorer artefacts.** The scoring logic marks any finding from `sqli.jsonl` whose class ≠ sqli as FP. If janissary legitimately emits multiple finding classes per URL (e.g. `sqli:sql_injection` plus `xss:reflection` on the same URL), the FPs are correct-by-rules but misleading as a precision statement.

Diagnostic to run before scaling to 60 apps: dump the class distribution for every `.jsonl` and decide whether "mixed-class findings on one URL" should count toward the FP rate. That is an **adjudication rubric** decision, not a scanner change. Amendment 23's FP rubric (confirmed FP / confirmed real bug / unverifiable) already covers it, but the Track C scorer collapses the rubric to a boolean.

## Corpus (locked before the first measurement run)

### Hard requirements
- Self-hosted only. No external scans.
- Image pinned by SHA-256 digest, not tag.
- `docker compose up -d` produces a running instance with a healthcheck that passes within 120s.
- Every app has at least one known-vulnerable endpoint and at least one known-safe endpoint at the security level used for the trial.

### Target composition (60+ apps, 1,500+ trials)

| Category | Minimum apps | Notes |
|---|---:|---|
| CMS (WordPress, Drupal, Joomla, Ghost) | 4 | Known plugins only, pinned versions |
| Code hosting (Gitea, Gogs) | 2 | |
| Forums / community (Discourse, Flarum) | 2 | |
| File sync (Nextcloud, Seafile) | 2 | |
| Dashboards (Grafana, Metabase) | 2 | |
| SPAs with catch-all routing | 10 | Static-only, no backend |
| REST / GraphQL APIs | 10 | Pinned OpenAPI spec |
| ModSecurity-fronted apps | 10 | ModSecurity + OWASP CRS in front |
| CDN-fronted apps | 5 | Proxied domain owned by maintainer |
| E-commerce (WooCommerce, Magento Luma) | 3 | |
| Static microservices | 10 | Small pinned apps with healthchecks |

**Total target:** 60 apps, ≥1,500 trials. A "trial" is `(target, endpoint, parameter)`.

### What goes into `apps.json` (schema change)

The current schema (`base_url`, `healthcheck`, `login`) is pilot-grade. Amendment 24 pins the following additional fields, required for a locked run:

- `image_digest`: SHA-256 of the pinned image.
- `security_level`: exact level if the app has a security dial (DVWA).
- `login.cookies`: list of cookie names to preserve; runner sends them via `--cookie`.
- `login.setup`: extra endpoints to hit after login.
- `safe_endpoints`: at least one per app, used as negatives for FP measurement.
- `known_vulnerable`: at least one per app, with expected `class`.
- `trial_class`: one of the nine Track C classes (sqli, sqli_blind, xss, cmdi, traversal, ssrf, ldapi, xpathi, weakrand).
- `excluded`: boolean. `true` = the app is documented but not scored (e.g. WAF training).

### What goes into `cases.csv` (schema change)

Current columns: `app,path,method,param,vuln_class,notes`.

Amendment 24 adds:
- `expected_finding_class`: the class string that a finding must carry to count as TP.
- `safe`: `true`/`false`. Safe cases are the FP-measurement trials; a finding on a safe case is FP.

A locked run scores the union of `safe=true` cases (for FP rate) and `safe=false` cases (for recall). **The FP rate claimed under Item A is computed only over the `safe=true` cases.**

## Unit of trial

`(app, endpoint, parameter)` — a single HTTP request parameter. Findings on other URLs are not counted toward this trial.

## Interval method

Clopper-Pearson on the FP rate, **cluster-aware by app**. Parameters within one app are not treated as independent. This matches Amendment 23's pre-registered method exactly.

## Adjudication

Before the locked run:
- Two adjudicators (the maintainer plus one external reviewer) independently classify a random 10% sample of FPs using Amendment 23's three-way rubric (confirmed FP / confirmed real bug / unverifiable).
- Inter-rater agreement is reported alongside the FP rate. If agreement is below 0.80 (Cohen's kappa), the rubric is tightened and the run is invalidated.
- Sample evidence bundles (raw request, raw response, finding record) are published with the run.

## Locked set (hold-out)

Once the 60-app corpus is built:
- The corpus is split 70/30: dev apps (42) and locked apps (18).
- Dev apps are used for Track C harness stabilization. Locked apps are touched exactly once.
- If the harness must be changed after seeing locked results, the locked set is retired in favour of a fresh one (Amendment 23 burned-data rule).

## Claim ladder contribution

- **Item A (real-world FP rate ≤ X%)** — this amendment produces the numerator and denominator.
- **Item C (competitor comparison)** — the same corpus is scanned with ZAP, Nuclei, sqlmap, dalfox for the same categories. Same per-trial scoring.
- **Item B (held-out precision)** — out of scope here. Item B is Track A held-out positives, not Track C.

## What this amendment does NOT do

- It does not measure anything on its own. It defines the campaign.
- It does not pre-register the number. The number is whatever the locked run produces.
- It does not commit to hitting 60 apps on a specific date. The corpus is built incrementally, and app-by-app entries are recorded in `apps.json` as they are added, before any scan of that app.

## Realistic sequencing

| Phase | Work | Sessions |
|---|---|---|
| 1 | Fix harness schema: `apps.json` and `cases.csv` extensions above. No scans. | 1 |
| 2 | Add first 5 apps (DVWA + Juice Shop + 3 more). Scan each on dev mode. Stabilize runner. | 1-2 |
| 3 | Add 20 apps total. Each app one scan on dev split, log results to `track_c/runs/`. | 3-4 |
| 4 | Add 42 apps total (dev split). Verify harness stability across all. | 3-5 |
| 5 | Lock 18 apps (locked split). Single scan each. Compute cluster-aware Clopper-Pearson interval. | 1 |
| 6 | Adjudication: two reviewers, random 10% sample, kappa. | 1 |
| 7 | Publish: Amendment 23 gets the measured `X`. README gets the honest FP rate. | 1 |

**Total: 10-15 sessions of focused work**, spread across weeks of calendar time. This is Option D. It is not a session of typing — it is infrastructure built incrementally.

## This session's deliverable

Commit of this amendment plus the working pilot harness (Commit `e7b4170` + metadata commit). No apps have been added beyond DVWA and Juice Shop. No locked apps exist. No FP rate is claimed.

The next session starts with Phase 1 above: schema change, no scans.
## Pilot FP analysis (2026-10-28)

The "interpretations to resolve" section above is now resolved by the pilot data. Recording what we found.

### What the 8 FPs are

Dump of `sqli.jsonl` (16 findings, all on `/vulnerabilities/sqli/`):

| class | count |
|---|---:|
| `sqli` | 8 |
| `traversal` | 8 |

Dump of `xss.jsonl` (2 findings, all on `/vulnerabilities/xss_r/`):

| class | count |
|---|---:|
| `xss` | 2 |

Every URL is correct. Every payload is correct. The XSS endpoint produces only XSS findings. **The SQLi endpoint produces both SQLi findings (correct) and traversal findings on the same requests (incorrect).**

### Interpretation 2 is ruled out

This is not a scorer artefact. The scorer's `category_of` fix (commit `e7b4170`) now correctly reads the `class` field from janissary's JSONL. The 8 FPs are what janissary actually emitted: `{"class": "traversal", ...}` on URLs where the only vulnerability is SQL injection.

### Interpretation 1 is confirmed, with specificity

Janissary over-fires traversal on SQL injection payloads. The likely mechanism (unverified): DVWA's SQL error responses contain file-path fragments (e.g. `/var/www/html/...`) in their stack traces, and janissary's differential detector sees "path-like string appeared in response body" and classifies it as traversal.

This is a **real precision bug in the scanner on a real application**, exactly the class of problem Amendment 23 Item A is designed to measure. It is not a scoring quirk, not a rubric question, not a Track C harness issue.

### What this means for the campaign

The pilot demonstrates the campaign works: it surfaced a real scanner precision problem on the first target. Scaling to 60+ apps will produce either:

- **The same pattern at scale:** janissary systematically emits traversal findings alongside SQLi on many apps. That becomes the Item A number, published honestly.
- **A different pattern at scale:** the DVWA case is idiosyncratic; other apps don't produce this. Either way, we now know the harness measures real precision, not just scorer agreement.

This finding does not change the pre-registration. It is a measurement result that will be part of the campaign's output.

### Not fixed in this session

The traversal mis-classification is **not** being patched here. Per Amendment 23's burned-data rule and the general principle of pre-registration: fixing detectors against dev-split findings is fine (dev data is for hardening), but the fix must be logged as a change against the baseline so that later measurements on the fixed scanner are attributed to the fix, not silently inherited.

This becomes the first task of a future session that addresses scanner precision: identify why the differential detector labels SQL error pages as traversal, and add a class-specific gate. That is a **scanner change**, not a benchmark change, and belongs in a new version (7.5.1 or 7.6.0) with its own Amendment or changelog entry.

### Logged for the next session

- Investigate why `class: "traversal"` fires on SQL error responses. Raw evidence: `benchmark/track_c/runs/20261028T073716Z-dvwa/sqli.jsonl`.
- If fixable: patch, re-measure DVWA, log delta explicitly.
- If not fixable soon: leave as-is, note in the campaign docs, proceed to 60-app scaling with the known classifier behaviour.
### 2026-10-28 - Traversal collapse oracle fix (7.5.1)

The 8 false traversal findings on DVWA sqli (`sqli.jsonl`, 16 findings, 8 sqli + 8 traversal on the same payload) have been diagnosed and fixed.

Root cause:

- `engine/scanner.py` invoked `check_traversal_collapse_oracle` for **every payload**, per ADR-006 D1 sub-note ("fire on any payload when armed").
- `detection/collapse_oracle.py` line 59 (`_aux_tiny_body`): `return ":" in body or "/" in body`. Any HTML error page has `</pre>` and any error message has `:`. The SQL syntax error body (<162 bytes vs 4538-byte baseline) passes this check.
- `check_traversal_collapse_oracle` line 133-134 hardcodes `"category": "traversal"`, so a collapse on an SQL injection payload was labeled traversal.

Fix:

- `engine/scanner.py`: gate the call to `check_traversal_collapse_oracle` on `payload_category == "traversal"`. Traversal payloads still reach the oracle. Non-traversal payloads do not — their own class-specific oracle covers them.

Version bump: 7.5.0 → 7.5.1.

Verification: re-ran DVWA pilot with the patched scanner. `sqli.jsonl` now shows sqli findings only. `xss.jsonl` unchanged. Scoring delta from the failed run (20261028T073716Z-dvwa) to the fixed run: see `benchmark/track_c/runs/<test-run>/score.json`.

This fix changes scanner behaviour against non-traversal payloads. Per Amendment 23 protocol, this must be logged against the baseline so the before/after delta is attributable. Future measurements on 7.5.1 will not reproduce the false traversal findings on 7.5.0.

### 2026-10-28 - score.json correction

Commit `e1565a0` (the traversal collapse fix) referenced `benchmark/track_c/runs/20261028T074432Z-dvwa/score.json` in its message and in the log entry above, but that file did not exist. The re-score command inside that commit's verification block failed silently — a PowerShell `try`/`finally` interacted with a `Pop-Location` and the pipe output was lost. The scanner fix itself is correct (traversal count 0, sqli and xss preserved); the missing piece was the formal score artifact.

This is a commit-message / amendment-log error, not a code error. Per Amendment 23's discipline, the correction is recorded here rather than silent. The previous commit is not amended — rewriting history is worse than appending a correction.

Both `score.json` files have now been written cleanly with a proper call. Measured before/after delta:

| Metric | Before (`20261028T073716Z-dvwa`) | After (`20261028T074432Z-dvwa`) | Delta |
|---|---:|---:|---:|
| TP | 2 | 2 | 0 |
| FP | 8 | 0 | -8 |
| FN | 2 | 2 | 0 |
| Precision | 0.200 | 1.000 | +0.800 |
| Recall | 0.500 | 0.500 | 0.000 |
| F1 | 0.286 | 0.667 | +0.381 |

The fix removed 8 false positives and preserved all 2 true positives. Precision on this pilot went from 0.200 to 1.000.

Both score files are now committed, so the before/after claim is fully reproducible from the repo.

### 2026-10-28 - Phase 1 complete (schema v2)

Schema v2 implemented. `benchmark/track_c/SCHEMA.md` documents the contract. `apps.json` and `cases.csv` extended; scorer rewritten to per-case TP/FP/FN/TN with proper TN handling for safe trials.

Changes:

- `SCHEMA.md` (new): field-by-field contract for apps.json and cases.csv, scoring model, locked-run requirements.
- `apps.json`: added `image_digest` (null), `security_level`, `excluded`, `trial_class`, `safe_endpoints`, `known_vulnerable`, `login.cookies`, `login.setup`. Backfilled for DVWA and Juice Shop.
- `cases.csv`: added `safe` and `expected_finding_class` columns. Backfilled 4 existing vulnerable rows. Added 4 safe trials (2 per app).
- `score.py`: rewritten. Per-case accounting. `safe=true` trials produce TN (no findings) or FP (any finding). `safe=false` trials produce TP (matching class), FP (wrong class), or FN (no findings). Adds `fp_rate_safe` field to score.json — the raw fraction, not the cluster-aware interval (which is computed at campaign level per Amendment 24).
- `runner.py`: unchanged. Reads `path`, `method`, `param`, all preserved.

Verified on DVWA: 6 cases (4 vuln + 2 safe), TP=2 (sqli+xss), FN=2 (sqli_blind+traversal), TN=2 (/index.php, /instructions.php). See `benchmark/track_c/runs/<this-commit>/score.json`.

This does NOT produce a real-world FP rate. It produces the apparatus that measures one. The 60-app corpus does not exist yet; Phase 2 adds the first 3 apps beyond DVWA and Juice Shop.

### 2026-10-28 - Phase 1 complete (schema v2)

Schema v2 implemented. `benchmark/track_c/SCHEMA.md` documents the contract. `apps.json` and `cases.csv` extended; scorer rewritten to per-case TP/FP/FN/TN with proper TN handling for safe trials.

Changes:

- `SCHEMA.md` (new): field-by-field contract for apps.json and cases.csv, scoring model, locked-run requirements.
- `apps.json`: added `image_digest` (null), `security_level`, `excluded`, `trial_class`, `safe_endpoints`, `known_vulnerable`, `login.cookies`, `login.setup`. Backfilled for DVWA and Juice Shop.
- `cases.csv`: added `safe` and `expected_finding_class` columns. Backfilled 4 existing vulnerable rows. Added 4 safe trials (2 per app).
- `score.py`: rewritten. Per-case accounting. `safe=true` trials produce TN (no findings) or FP (any finding). `safe=false` trials produce TP (matching class), FP (wrong class), or FN (no findings). Adds `fp_rate_safe` field to score.json — the raw fraction, not the cluster-aware interval (which is computed at campaign level per Amendment 24).
- `runner.py`: unchanged. Reads `path`, `method`, `param`, all preserved.

Verified on DVWA: 6 cases (4 vuln + 2 safe), TP=2 (sqli+xss), FN=2 (sqli_blind+traversal), TN=2 (/index.php, /instructions.php). See `benchmark/track_c/runs/<this-commit>/score.json`.

This does NOT produce a real-world FP rate. It produces the apparatus that measures one. The 60-app corpus does not exist yet; Phase 2 adds the first 3 apps beyond DVWA and Juice Shop.
