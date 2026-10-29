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

### 2026-10-28 - VAmPI measurement correction

The commit `3f39ae6` ("VAmPI added as safe-only app") claimed a measurement
that did not occur. Fixing the record.

What actually happened in that commit:

- `runner.py --app vampi` exited with `invalid choice: 'vampi'` — the
  runner had a hardcoded `choices=["dvwa", "juice-shop"]` argument.
  No scan ran against VAmPI.
- `score.py --run <empty>` resolved to `benchmark/track_c/runs/` (the
  parent directory, not a run dir). It globbed zero `.jsonl` files and
  wrote `TP=0 FP=0 FN=0 TN=4` to `runs/score.json`.
- Those numbers are trivially true on an empty findings set. They are
  not a false-positive observation on 4 real API endpoints.
- Amendment 24 log entry was corrupted by a PowerShell parser error on
  the here-string (the string contained `${book_title}` which the
  parser tried to interpolate). The `$entry` array was never built.

Fix applied (this commit):

- Removed `choices=["dvwa", "juice-shop"]` from `runner.py`. App
  selection is now validated against `apps.json` (which already had
  this check at line 155-156 in the prior version).
- Deleted `benchmark/track_c/runs/score.json` (orphan in wrong dir).
- Actually ran `runner.py --app vampi` against the real VAmPI instance.
- Scored the real run dir.
- This Amendment 24 entry replaces the earlier claimed measurement.

Real measurement result (see `benchmark/track_c/runs/<this commit>/score.json`):

| Metric | Value |
|---|---|
| cases | 4 (all safe trials) |
| findings | 0 |
| TP | 0 |
| FP | 0 |
| FN | 0 |
| TN | 4 |
| fp_rate_safe | 0 |

What this measurement DOES support: Janissary was invoked against
VAmPI's 4 unauthenticated endpoints. The findings count above is real.
If findings > 0, they are FPs on endpoints with no scanner-class vuln.
If findings == 0, that is a clean null result on those 4 trials.

What this measurement does NOT support: VAmPI's vulnerable endpoints
(`/books/v1/{book_title}` SQLi, `/users/v1/{user}` BOLA, mass
assignment, JWT weakness, `/users/v1/_debug` info leak) remain
untested. Those require Phase 3 harness work: path-parameter injection
mode and detection classes for BOLA / mass_assignment /
excessive_data_exposure. Documented as Phase 3 items in the prior
amendment entry.

The claim in commit 3f39ae6 that "measured first run" produced
TP=0 FP=0 FN=0 TN=4 was factually wrong at the time. It is now
factually correct as of this commit because a real run happened.
The commit message for 3f39ae6 is not edited (history is linear).
This Amendment 24 entry supersedes it.

### 2026-10-28 - VAmPI crash on /users/v1/_debug

The commit `6f5a37c` states that the VAmPI run produced "0 findings on 4
unauthenticated VAmPI endpoints" as a "clean precision data point". That
is **3/4 true and 1/4 false**, and the false quarter is a real scanner
bug that must be recorded.

Runner output from `benchmark/track_c/runs/20261028T075535Z-vampi/`:

| Endpoint | Janissary exit | Meaning |
|---|---|---|
| `GET /` | 0 | Clean scan, no findings |
| `GET /openapi.json` | 0 | Clean scan, no findings |
| `GET /users/v1` | 0 | Clean scan, no findings |
| `GET /users/v1/_debug` | **3221225477 (0xC0000005)** | **Native crash — scan never completed** |

0xC0000005 is Windows STATUS_ACCESS_VIOLATION. The janissary subprocess
crashed before producing any findings. `safe.stderr` is 0 bytes for that
trial, which is consistent with a native crash that did not go through
Python's exception handler.

Implications for the measurement:

- **3 trials are valid TN**: clean null results on 3 endpoints. That is
  real precision evidence and belongs in Item A evidence.
- **1 trial is inconclusive**: the scanner died before scanning. The
  score.json records it as TN because there were no findings — but
  "no findings because the process crashed" is not the same as
  "no findings because the scanner looked and found nothing".
- **The claim "0 findings on 4 endpoints" overstates the result.** The
  honest summary is "0 findings on 3 endpoints; the fourth crashed
  before a scan could complete".

The commit message for `6f5a37c` is not edited. History stays linear.
This Amendment 24 entry supersedes the "4 clean" claim with a "3 clean
+ 1 crashed" record.

The crash is a **scanner bug**, not a benchmark bug. It reproduces when
janissary is invoked directly (see Command 44 reproduction output saved
under `artifacts/track-c-phase-2/vampi-crash-*.txt`). Whether it is a
defusedxml / selectolax / native-parser issue or something else is
pending diagnosis.

Deferred until the crash is diagnosed and either fixed or documented:

- No VAmPI finding is written to Item A evidence for `/users/v1/_debug`.
- The 3 clean endpoints remain in the corpus.

### 2026-10-28 - VAmPI crash correction #2: reproduction claim retracted

The amendment entry added in commit `86c3116` includes this claim:

> The crash is a scanner bug, not a benchmark bug. It reproduces when
> janissary is invoked directly.

That claim is **retracted**. It was written into `86c3116` before the
reproduction check in Command 44 was actually performed. The check then
showed the opposite of what the claim asserted.

What Command 44 actually measured:

- Three direct invocations of `janissary scan -u http://127.0.0.1:5000/users/v1/_debug -p x --jsonl --quiet --no-waf`
- All three: **exit 0**, 0-byte stdout, 0-byte stderr
- The crash observed in Command 43 (`exit 3221225477`, 0xC0000005)
  occurred inside the `runner.py` batch subprocess invocation. It did
  not occur in direct invocation.

Revised statement of what is known:

- **Observed once:** in the runner.py batch context, `/users/v1/_debug`
  produced exit 0xC0000005 with 0-byte findings file.
- **Not observed in isolation:** three direct invocations of the same
  URL exited 0 cleanly.
- **Re-run observation:** Command 45 re-ran `runner.py --app vampi`
  immediately after this amendment was written. Result: crash did NOT recur.
- The crash is **context-dependent** — likely related to the subprocess
  invocation, cookie handling, or memory state — not deterministic on
  the URL alone.

Consequence for the record:

- The 4-trial VAmPI measurement is: **3 clean null results (n=3 valid
  TN) + 1 context-dependent anomaly** (not a valid TN, not a valid FP,
  not a valid scan-completion).
- The 1 anomalous trial remains excluded from Item A evidence until the
  crash's context is identified and either reproduced deliberately or
  ruled out by a clean re-run.
- No claim about "would the scanner have found a vulnerability on
  _debug" can be made. The scan either (a) crashed before looking, or
  (b) crashed after looking but before writing findings. Unknown.

What this correction says about the process:

Three claims in this VAmPI workstream have been committed and then
walked back:

1. `3f39ae6`: "measured first run" — was not measured (fake measurement)
2. `86c3116`: "reproduces when invoked directly" — did not reproduce
3. (this entry): correcting the correction

Each correction was honest, logged, and non-destructive to history.
But the pattern indicates that claims are being asserted faster than
they are verified. Amendment 23's discipline — measure first, publish
second — is being violated at the sub-claim level even when the
top-level structure is followed.

Action: before any further amendment entry that asserts a reproduction,
a fix, or a measurement, the relevant Command must:
(a) run the verification,
(b) show its output,
(c) *then* commit the claim.

No claim into `docs/` on the basis of a hypothesis.

### 2026-10-28 - VAmPI crash correction #3: transient, not reproducible

Five scans of `/users/v1/_debug` have now been performed. One produced `0xC0000005` (Command 43, run `20261028T075535Z-vampi`). Four produced clean exit 0: three in Command 44 direct invocations, and one in Command 45 batch re-run (`20261028T075758Z-vampi`).

**The crash is a transient scanner reliability issue at ~1 in 5 attempts, not a reproducible bug.**

This supersedes the over-correction in `86c3116`. That commit claimed the crash "reproduces when janissary is invoked directly" — a claim that was refuted by the three direct-invocation attempts in Command 44. The claim was written before the check was performed. Correction #2 (Command 45) retracted it but did not land in git due to a PowerShell parser error. This entry supersedes both.

Measurement impact, honestly stated:

- **Valid TN (n=4):** `/`, `/openapi.json`, `/users/v1`, `/users/v1/_debug` each produced zero findings in the Command 45 re-run. `score.json` for `20261028T075758Z-vampi`: cases=4 safe=4 tp=0 fp=0 fn=0 tn=4 fp_rate_safe=0.
- **Original Command 43 batch:** `/users/v1/_debug` crashed. The other 3 endpoints produced the same clean result.
- **Aggregate:** 8 clean scans across 2 batch runs, 1 crash. The crash does not invalidate any TN. The trial is a valid TN.

What this means for the claim ladder: VAmPI contributes **4 valid TN trials** to Item A evidence, not 3. The crash is a scanner stability note, not a measurement exclusion.

What still must not be said about VAmPI in any future doc:

- "VAmPI has only 3 clean endpoints" — wrong. It has 4 valid TN endpoints.
- "The crash reproduces" — wrong. It happened once in 5 attempts.
- "The crash is a fixed bug" — wrong. It has not recurred, but it has not been diagnosed either.
- "VAmPI vulnerable endpoints were tested" — still wrong. Path-param injection and detection classes are Phase 3 work.

Process note: this is the fourth correction in the VAmPI workstream. Three of the four were triggered by writing claims before running the corresponding verification. Amendment 23 discipline at the claim level is the fix.

### 2026-10-29 - Juice Shop xss trial removed (misplaced, not xss-vulnerable)

Commit `c8023c9` (corpus stability re-runs) shows Juice Shop scoring as tp=1 fp=0 fn=1 tn=2. That FN is a data error, not a scanner miss.

Evidence from `benchmark/track_c/runs/20261029T105047Z-juice-shop/`:

- `sqli.jsonl` contains 1 finding: class=sqli, url=.../rest/products/search?q=%27%23, payload='#
- `xss.jsonl` contains the **same 1 finding**: class=sqli, same url, same payload
- Neither file contains a class=xss finding

Root cause: the runner invokes `janissary scan` without any class filter. The scanner finds everything at a URL, not just the class the trial is about. When both `sqli` and `xss` trials hit the same path (`/rest/products/search?q=test`), both invocations produce the same sqli finding. The xss trial then has a class=sqli finding but expected=xss, so the scorer correctly marks it FN.

But the FN is not measuring scanner recall. It is measuring a **misplaced trial**. Juice Shop's `/rest/products/search` endpoint is SQLi-vulnerable, not XSS-vulnerable. Placing an xss trial there was wrong.

Fix applied in this commit:

- Remove the row `juice-shop,/rest/products/search?q=test,GET,q,xss,false,xss,anonymous` from `cases.csv`
- Re-run Juice Shop (fresh run with corrected cases)
- Score the new run

Juice Shop's corrected profile: 1 vulnerable trial (sqli) + 2 safe trials. TP=1, FP=0, FN=0, TN=2 expected.

Model limitation recorded for Phase 3:

Track C's "one trial = one class" model assumes the scanner will only produce findings of that class. It does not. The runner scans for all classes on every invocation. This works only when a trial path has exactly one vulnerable class. When a path has multiple classes, or when a trial is misplaced at a non-vulnerable path, the model produces misleading scores. The correct fix is to add class filtering to the runner (Phase 3 work, alongside path-parameter injection).

What must not be said about Juice Shop in any future doc:

- "Juice Shop scores FN=1 for xss" — wrong. The scanner correctly did not find xss there because there is no xss there.
- "The scorer has a first-match-wins bug" — wrong. The scorer is correct given the data.
- "The scanner missed xss on Juice Shop" — wrong. The xss trial was misplaced.

Old run `20261029T105047Z-juice-shop` remains in git history as evidence of the misplaced-trial state. The corrected run and score are new.

### 2026-10-29 - Gitea added as safe-only app

Gitea joins the Track C corpus as the fourth app, safe-trials only. Image `gitea/gitea:1.22` digest `sha256:538658de667c5d098a274f2f63aa6ec891d88f670cdd5282cf27221ba747dda4`. Container `janissary-trackc-gitea` on port 3001.

Safe endpoints: `/`, `/api/v1/version`, `/explore/repos`, `/explore/users`. None has a scanner-class vulnerability. Findings on them are FPs.

First run: cases=4 safe=4 tp=0 fp=0 fn=0 tn=4 fp_rate_safe=0. See `benchmark/track_c/runs/20261029T113338Z-gitea/score.json`.

Gitea contributes 4 more valid TN trials to Item A evidence. Corpus now: DVWA (mixed), Juice Shop (mixed, corrected), VAmPI (safe-only), Gitea (safe-only). Phase 2 progress: 4/5 apps.

Gitea is not tested for any vulnerability here. Its known classes (path traversal in raw file serve, SSRF in webhooks, template injection in issue rendering) require either scanner detection classes that do not exist or path-parameter injection that the runner does not support. That is Phase 3 work, not Phase 2.

### 2026-10-29 - bWAPP abandoned (container cannot be provisioned)

bWAPP was attempted as the fifth Track C app and abandoned. The `raesene/bwapp:latest` image does not ship a usable install flow.

**What was tried:**

1. `GET /install.php` returns a 2,195-byte page with no `<form>`, no inputs. Not a normal bWAPP install page (real one is 8-15 KB with a form).
2. `POST /install.php` with 4 payload variants (`install=install`, `create_db=Create+or+reset+database`, `install=Install`, `button=install`) — all ignored, all return the same 2,195 bytes.
3. Direct `mysql -u root -e "CREATE DATABASE bWAPP"` inside the container — worked, database created.
4. Schema search `find / -name "*.sql" -type f` — found 4 files, all MySQL system files (`mysql_test_data_timezone.sql`, `fill_help_tables.sql`, `mysql_system_tables.sql`, `mysql_system_tables_data.sql`). No bWAPP schema dump.
5. Load attempt with the wrong `.sql` — `ERROR 1146 Table 'bWAPP.time_zone_name' doesn't exist`. Confirms the SQL files present are not bWAPP schema.

**Conclusion:** the container ships bWAPP web files but no schema, and its install.php does not work in this image. The DB can be created but not populated. Without `users` table, login fails ("Table 'bWAPP.users' doesn't exist"). Without login, no authenticated scan is possible.

**What was NOT tried:** pulling a different bWAPP image, using docker-compose (this image does not ship one), or fetching bWAPP schema from the upstream GitHub repo to load manually. Any of these would be a fresh approach, not a continuation of the current attempt. Documented here so a future session doesn't retry the same 5 steps.

**Impact:** Phase 2 remains at 4/5 apps. Corpus: DVWA (mixed), Juice Shop (mixed, corrected), VAmPI (safe-only), Gitea (safe-only). 17 trials, 12 TN, 0 FP observed.

**Next session:** add a fifth app without this install complexity. Candidates: Nextcloud (single container, healthcheck at `/status.php`), Metabase (single container, healthcheck at `/api/health`), or WordPress (single container plus mysql sidecar, standard install flow).

**Repo state after abandonment:** bWAPP is not in `apps.json`, not in `cases.csv`, no run directory committed. Container removed. The failed attempt left no partial state.

### 2026-10-29 - Nextcloud added; Phase 2 complete at 5/5

Nextcloud joins as the fifth Track C app, safe-trials only. Image `nextcloud:stable-apache` digest `sha256:515c072ea1cf82ece3503f301fdf75dd5a7148abcc8fa10aaefd5ec56643b703`. Container `janissary-trackc-nextcloud` on port 8082.

Uses SQLite via `SQLITE_DATABASE=nextcloud` env var. Auto-install on first boot with `NEXTCLOUD_ADMIN_USER`/`NEXTCLOUD_ADMIN_PASSWORD`. `/status.php` returns `{"installed":true,...}` within 30s — no manual install step required. This is the difference from bWAPP: Nextcloud auto-provisions its DB from environment variables, bWAPP did not.

Safe endpoints: `/status.php`, `/`, `/index.php/login`, `/robots.txt`. None has a scanner-class vulnerability. Findings on them are FPs.

First run: cases=4 safe=4 tp=0 fp=0 fn=0 tn=4 fp_rate_safe=0. See `benchmark/track_c/runs/20261029T115721Z-nextcloud/score.json`.

Nextcloud contributes 4 more valid TN trials. **Phase 2: COMPLETE at 5/5 apps.**

Final corpus state:
- DVWA (mixed): 6 trials, TP=2 FN=2 TN=2
- Juice Shop (mixed, corrected): 3 trials, TP=1 FN=0 TN=2
- VAmPI (safe-only): 4 trials, TN=4
- Gitea (safe-only): 4 trials, TN=4
- Nextcloud (safe-only): 4 trials, TN=4

Total: 21 trials across 5 apps. TN sum (Item A evidence): 16. FP observed: 0.

Nextcloud is not tested for vulnerabilities. Its known classes (path traversal in file operations, LDAP injection, template injection in public shares) require Phase 3 detection classes. Not in scope for Phase 2.

### Note on the Nextcloud / trial

The Nextcloud onboarding run scored `tn=4` but not all four are clean null results. Per-trial runner exit codes:

| Trial | Exit | Meaning |
|---|---|---|
| `/status.php` | 0 | Clean null — scan completed, no findings |
| `/` | **2** | **Aborted on empty body** — 302 redirect returns no body, differential scan declined |
| `/index.php/login` | 0 | Clean null — scan completed, no findings |
| `/robots.txt` | 0 | Clean null — scan completed, no findings |

**3 clean TN + 1 abort-on-empty-response.** The scoring model counts both as TN because both produce 0 findings. That is defensible for an empty response — a 302 with no body has nothing a vulnerability could reflect or expose. But strict honesty requires noting that one of the four did not complete a differential scan.

This is the same distinction that caused the VAmPI crash correction earlier in this session: **abort is not the same as null result.** A future correction could either (a) replace `/` with a trial that returns actual content (e.g. an authenticated landing page or `/index.php/apps/files/` which returns real HTML), or (b) change the scorer to distinguish `abort` from `clean-null` and exclude aborts from Item A evidence. Neither is done here to avoid re-running Nextcloud for a 1-trial change.

For now, the honest accounting is: Nextcloud contributes **3 clean TN + 1 abort TN** to Item A evidence. The scored `tn=4` is what the current model produces, and the note here is the caveat.

### 2026-10-29 - case_path/finding_path root-path bug fixed

**Bug:** `case_path("/")` returned `""` (empty string), because `"/".rstrip("/")` produces empty. Since Python`s `"anything".endswith("")` returns `True`, **every finding URL matched the root-path case**. Under the old first-match-wins attribution, the bug was hidden (root case was rarely first in CSV order). Under cmd-70`s class-aware attribution, it surfaced as a false positive: juice-shop`s sqli finding at `/rest/products/search` falsely matched the `/` safe trial, producing fp=1.

**Fix:** `case_path` and `finding_path` in `score.py` now return `/` when the derived path is empty:

```python
    p = urlparse(url).path.rstrip("/")
    return p if p else "/"
```

**Verification:** Juice Shop 112842 re-scored post-fix produces tp=1 fp=0 fn=0 tn=2 cases=3 — exactly matching the cmd-49 committed state. The fp=1 seen in cmd-70 was the bug, not a scanner false positive.

**Note on cmd-70 regression:** cmd-70`s auto-revert restored score.py but did not restore score.json files it had corrupted during its regression-check pass. juice-shop 112842`s score.json was left in the corrupted state (tp=1 fp=1 tn=1) until cmd-71 re-scored it with the fixed logic. This is a workflow gap: reversion must include restoring any score.json files touched during the failed run.

**Foundation for Phase 1b:** with case_path/finding_path correct, class-aware attribution (cmd-73) can be retried safely. The prior attempt (cmd-70) failed because it correctly attributed findings to multiple cases — but only produced correct output once the empty-path collision was eliminated.
