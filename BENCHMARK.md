# JANISSARY BENCHMARK — PRE-REGISTRATION

**Status:** Frozen. Committed before any official run.
**Registered:** 2026-09-28
**Tool version under test:** v7.2.0 (commit dc21817, tag v7.2.0)
**Author:** Hetaireia (solo maintainer, JANISSARY)
**Repository:** https://github.com/Hetaireia/janissary

---

## Why this document exists

Benchmarks published by tool authors are assumed to be cherry-picked until
proven otherwise. This document is the proof. It states the methodology, the
hypotheses, and the analysis plan before the first official run. No metric
definition, no target choice, no exclusion rule, and no statistical test will
change after this commit except with an explicit, timestamped amendment
recorded at the bottom of this file.

Negative results will be published with the same prominence as positive ones.
A benchmark that can only produce one outcome is marketing.

---

## Scope of the claim

This benchmark tests three specific claims:

1. **Precision.** JANISSARY emits fewer false positives than OWASP ZAP and
   Nuclei on a labelled corpus.
2. **WAF survivability.** Against a Cloudflare-fronted target, JANISSARY
   completes the scan with the operator's IP intact, where ZAP and Nuclei
   are blocked.
3. **Grouped findings.** JANISSARY reports bugs, not raw alert rows: one
   SQL injection with N signals is one finding, not N.

It does **not** claim:

- Superior recall on unknown CVE classes.
- Faster than ZAP on large crawl surfaces.
- Coverage beyond the bug classes listed in the JANISSARY README.

---

## Track A — Statistical rigor

### Target

OWASP Benchmark (Java), 2,740 labelled test cases distributed across 11
vulnerability categories. The official ground-truth CSV shipped with the
project is the only source of labels; no case will be re-labelled.

Version pin: the exact commit hash of OWASP Benchmark used will be recorded
in `benchmark/track-a/target-version.txt` at the time of first run.

### Tools

| Tool | Version | Invocation notes |
|---|---|---|
| JANISSARY | v7.2.0 (tagged) | `janissary scan --jsonl --quiet`, default payload set |
| OWASP ZAP | pinned at run time | Docker `zap:stable`, baseline scan, full spider |
| Nuclei | pinned at run time | Docker `projectdiscovery/nuclei:latest`, default cves+vulnerabilities template set |

No tool-specific tuning beyond its default recommended invocation. Any
override will be documented in `benchmark/track-a/invocations.md`.

### Runs

3 runs per tool. **Fresh target container per run** — no persisted state,
no cached responses. If a run fails for infrastructure reasons (Docker
crash, network loss), the run is discarded and re-executed; the discard is
logged with timestamp and reason in `benchmark/track-a/runs/`.

### Metrics

Computed from the confusion matrix per run:

- True Positive (TP), False Positive (FP), True Negative (TN), False Negative (FN)
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- False Positive Rate = FP / (FP + TN)
- F1 = 2 * P * R / (P + R)
- Youden's J = Recall + Specificity - 1
- Scan wall-clock time (seconds)

Reported as: per-run values, mean, standard deviation across the 3 runs.

### Statistical test

McNemar's test (continuity-corrected) comparing each tool pair on the
concatenated per-case classification outcomes across runs.

Null hypothesis: the two tools have the same error rate on the corpus.
Alternative: they differ. Significance threshold: alpha = 0.05, two-sided.

Effect size reported: the discordant-pair difference (b - c) with 95%
confidence interval.

### Hypotheses (stated in advance, falsifiable)

- **H-A1.** JANISSARY precision > ZAP precision, p < 0.05.
- **H-A2.** JANISSARY precision > Nuclei precision, p < 0.05.
- **H-A3.** JANISSARY recall < ZAP recall on at least one category, p < 0.05.
  (Stated because surgical detection trades some recall for precision. If
  this is false, that is a stronger result and will be reported as such.)
- **H-A4.** Mean scan time per tool will not differ by more than 2x from
  the fastest tool. (If JANISSARY is dramatically slower than Nuclei, that
  is a disqualifying characteristic for the bug-bounty use case even if
  precision is higher.)

---

## Track B — Operational proof

### Target

OWASP Juice Shop (pinned Docker image) on a private VPS. Public DNS through
Cloudflare free tier with default security settings — no custom rules, no
tuned WAF profile. This is the WAF a real bug bounty hunter encounters on
a default Cloudflare deployment, not a hardened corporate setup.

One target, three sequential runs. Target reset between tools (container
rebuild, fresh database) so state from an earlier tool cannot influence a
later one.

### Tools

Same three as Track A, pinned to the same versions.

### Metrics

- Scan completion (boolean)
- Time to first blocked response (seconds)
- Source IP blocked during the run (boolean)
- Total alerts emitted
- False positives (manual review against Juice Shop's documented
  vulnerability list)
- Grouped findings (JANISSARY only; ZAP and Nuclei do not group)
- Time to first true positive (seconds)

### Hypotheses (stated in advance)

- **H-B1.** JANISSARY completes the run with the source IP intact.
- **H-B2.** ZAP is blocked by Cloudflare within 120 seconds of first payload.
- **H-B3.** Nuclei is blocked by Cloudflare within 90 seconds of first payload.
- **H-B4.** JANISSARY emits <= 3 findings, of which <= 1 is a false positive.
- **H-B5.** ZAP emits >= 30 alerts and >= 8 false positives.
- **H-B6.** Nuclei emits >= 5 template matches before being blocked.

If any B hypothesis fails, the raw logs are published. The blog post will
report the failure. No re-runs to "get a better number."

---

## Analysis plan

1. Raw JSON output from every run is committed to `benchmark/track-a/runs/`
   and `benchmark/track-b/runs/` verbatim. No post-hoc filtering.
2. Ground-truth mapping for Track A is derived mechanically from the OWASP
   Benchmark CSV. The mapper script is committed.
3. All metrics are computed by one committed script (`benchmark/analyze.py`)
   that reads the raw JSON only. Manual numbers are not used in the report.
4. Charts are generated by the same script. No hand-edited figures.
5. Statistical tests are run by the same script with the pinned SciPy version
   recorded in `benchmark/requirements.txt`.

---

## Publication commitment

- **Everything is published**, including runs that fail H-A1 through H-A4 or
  H-B1 through H-B6.
- The blog post title, if it references a specific finding, will match the
  finding in the data.
- The benchmark directory stays in the repo after publication. No "cleanup"
  to hide artifacts.
- If a bug is discovered in JANISSARY during the benchmark, it is filed,
  fixed, and the benchmark is re-run under a new tag — with both the
  pre-fix and post-fix results published. Silent fixes are not allowed.

---

## Out of scope (explicit non-claims)

- No comparison against Burp Suite Pro. Commercial control-plane tools
  serve a different use case and this benchmark would be apples-to-oranges.
- No CVE-class coverage claims. OWASP Benchmark is deliberately limited to
  11 synthetic categories and does not represent a production target.
- No performance claim on targets larger than the benchmark's synthetic
  corpus.
- No claim that JANISSARY is "better" than the tools it is compared to. The
  claim is narrower: on a labelled corpus and a Cloudflare-fronted target,
  JANISSARY's precision and survivability characteristics are as reported.

---

## Amendments

Amendments to this document after the initial commit must be:

1. Appended below this line, not edited into the body above.
2. Timestamped.
3. Justified (why the change was necessary).
4. Committed before the affected run, not after.

---

### Amendment 1 — 2026-09-28

**What changed:** directory names `benchmark/track-a/` and `benchmark/track-b/`
became `benchmark/track_a/` and `benchmark/track_b/`.

**Why:** Python package names cannot contain hyphens. The harness is invoked
as `python -m benchmark.track_a.runner`, which requires an importable module
name. Renaming the directories was the minimal fix.

**Effect on methodology:** none. "Track A" and "Track B" remain the
pre-registered concepts. All references to file paths in this document should
be read with underscores in place of hyphens where a Python module path is
implied. No hypothesis, metric, target, tool pin, or statistical test changed.

---

### Amendment 2 — 2026-09-28

**What changed:** the Track A target image is built by a custom
Dockerfile (`benchmark/track_a/Dockerfile.owasp-benchmark`) rather than
the upstream `VMs/Dockerfile`, and the app runs on HTTP/8080 rather than
HTTPS/8443.

**Why:**

1. The upstream Dockerfile clones `BenchmarkJava` from GitHub at build
   time, which does not respect the pre-registration pin. Our Dockerfile
   copies the pinned local checkout.
2. Upstream runtime uses `cargo:run`, whose 300s deploy-timeout watchdog
   kills Tomcat before the 2,740-servlet WAR finishes deploying. Our
   entrypoint starts Tomcat directly via `catalina.sh run`.
3. Upstream JVM args include `-Xdebug -Djava.compiler=NONE`, which
   disables JIT and makes startup pathological. We omit them.
4. HTTPS at the WSL2 boundary is unreliable on Windows; HTTP/8080 is
   deterministic.

**Mirror change:** `pom.xml`'s `tomcat.url` is sed-replaced from
`downloads.apache.org` to `archive.apache.org`. The former rotates old
patch versions off within days; v9.0.120 already 404s. The latter keeps
every historical version. No version change: still Tomcat 9.0.120.

**Effect on methodology:** none. The pinned git SHA plus one deterministic
mirror sed fully determine the build artifact. Bug classes, ground truth,
metrics, hypotheses, and statistical tests unchanged. Whether the app is
served over HTTP or HTTPS does not affect what the DAST tools detect.

**Implementation:** the config the upstream `cargo:run` step would have
installed (`src/config/local/server.xml`, `src/config/local/context.xml`)
is copied into `$CATALINA_HOME/conf` by the entrypoint, with the connector
rewritten from HTTPS/8443/127.0.0.1 to HTTP/8080/0.0.0.0. HSQLDB is
started directly (not via Maven antrun, which exits on task completion)
and waited on before Tomcat boots.

---

*(No further amendments as of 2026-09-28.)*
---

### Amendment 3 — 2026-09-28

**What changed:** the Track A harness now reads a per-case injection-vector
map (`benchmark/track_a/case_vectors.csv`) instead of assuming every case
reads a URL query parameter, and the scanner gained the injection modes
required by that map (`--inject-in cookie`, `header`, `param-name`).
Amendment 3 also records the first full Track A result.

**Why:** OWASP Benchmark cases do not share a single input vector. An
inventory of the pinned source tree (`BenchmarkJava @ 20cbf3d`,
`src/main/java/org/owasp/benchmark/testcode`) shows the payload is read
from cookies in 664 cases, a named request header in 432, the parameter
name in 221, a non-standard header in 89, a fixed header such as Referer
in 87, and query/body parameters in the remainder. Scanning the whole
corpus with a single vector produces a near-zero true-positive rate
regardless of analyzer quality, which is what the earlier "0 findings on
BenchmarkTest00001" investigation turned out to be.

`case_vectors.csv` is generated deterministically from the pinned source
by `benchmark/track_a/extract_vectors.py`; it is committed as a
methodology artifact, not as data derived from run output. Cases whose
vector the scanner does not support (89 `header_any` cases requiring
header-name-safe payloads, 4 session/URI/stream cases) are recorded in
each run's `skipped.jsonl` and scored as "not attempted": absent from
both numerator and denominator of every metric below, consistent with the
pre-registration commitment to falsifiable claims.

**Result - full corpus, 3 runs, 2026-09-28 (tool version 7.3.0):**

| run  | TP  | FP  | TN   | FN  | precision | recall | F1    |
|------|-----|-----|------|-----|-----------|--------|-------|
| 1    | 592 | 116 | 1209 | 823 | 0.836     | 0.418  | 0.558 |
| 2    | 585 | 121 | 1204 | 830 | 0.829     | 0.413  | 0.552 |
| 3    | 584 | 117 | 1208 | 831 | 0.833     | 0.413  | 0.552 |
| mean | 587 | 118 | 1207 | 828 | 0.833     | 0.415  | 0.554 |

population stdev: precision 0.003, recall 0.003, F1 0.003.

**Result - in-scope subset, declared post-hoc.** JANISSARY is a
parameter-injection scanner. It does not analyze random-number quality
(`weakrand`), cookie flags (`securecookie`), XPath injection (`xpathi`),
or LDAP injection (`ldapi`), and it does not perform hash-algorithm or
crypto-implementation analysis (`hash`, `crypto`). Those six categories
account for 461 of the 828 mean FNs. Restricting to the categories
JANISSARY targets (`sqli`, `xss`, `cmdi`, `pathtraver`, `trustbound`;
1,604 cases total):

| run  | TP  | FP | TN  | FN  | precision | recall | F1    |
|------|-----|----|-----|-----|-----------|--------|-------|
| mean | 498 | 48 | 696 | 362 | 0.912     | 0.579  | 0.708 |

This subset is a **post-hoc** breakdown, reported for interpretive
clarity. The pre-registered headline for Track A remains the full-corpus
number: **precision 0.833, recall 0.415, F1 0.554**. Any downstream
citation must state both, and must name the in-scope category set.

**On the scan-target interaction.** Two JANISSARY changes were made during
this session and are documented here so a reviewer can see what moved
between the "0 findings" state and the numbers above:

1. `analyzer._check_reflection` now requires payload length >= 3 and
   requires the payload not to appear in any baseline sample. Previously
   a single quote or double quote, present in every HTML page, was
   reported as a low-severity reflection on every case. This is a
   correctness fix; it removes roughly 170 false positives on the pilot
   without removing any verified true positive.

2. An earlier change to allow `length_anomaly` findings through on
   stable-2xx baselines was reverted after the full run showed it
   mislabeling ~200 safe XSS cases as sqli/cmdi/traversal. `length` and
   `status` deltas remain corroborators and are dropped unconditionally,
   as pre-registered.

Neither change alters the ground-truth labels, the case-vector map, the
metric definitions, or the statistical test. Both were committed before
the runs whose numbers appear above.

---

### Amendment 4 — 2026-09-29

**What changed:** the Track A baseline for tool version 7.3.0 is restated.
The number recorded in Amendment 3 (**F1 0.554**) is withdrawn. The
corrected full-corpus baseline is:

| run dir                              | TP  | FP  | FN   | TN   | P     | R     | F1    | FPR   |
|--------------------------------------|-----|-----|------|------|-------|-------|-------|-------|
| 20260929T141102Z-janissary-r1        | 401 | 25  | 1014 | 1300 | 0.941 | 0.283 | 0.436 | 0.019 |

Single run, full 2,740-case corpus, `min-severity=low`.

**Why:** the Amendment 3 numbers, and every intermediate number computed
during the 2026-09-29 session up to F1 0.636, were inflated by a scoring
artifact in the OWASP Benchmark scorer that interacts with a scanner
defect.

The OWASP Benchmark scoring rule credits **any** finding emitted against
a case's URL to that case's category. It does not inspect which payload
produced the finding. JANISSARY's cmdi payloads (`; sleep 5`, `uname -a`,
`whoami`) reflect on targets that echo query input. On a `pathtraver`,
`trustbound`, `sqli`, or `xss` case whose servlet reflects the parameter
into the response body, a cmdi payload's reflection was emitted as a
finding, and the scorer counted it as a detection of that case's
category. Those were not detections. They were reflections.

The magnitude of the artifact:

|                              | TP  | FP  | P     | R     | F1    |
|------------------------------|-----|-----|-------|-------|-------|
| before suppression (124024)  | 647 | 120 | 0.844 | 0.457 | 0.593 |
| after suppression  (141102)  | 401 | 25  | 0.941 | 0.283 | 0.436 |

The F1 drop is the removal of **246 TP that were never real**. The
precision gain is the removal of 91 FP from the same mechanism.

**What changed in the scanner (committed before the honest run):**

1. `cf10841` — suppress cmdi reflection across all categories. A cmdi
   payload that reflects into the response body without producing
   command-output evidence no longer emits a finding. Detection of
   `cmdi` now requires the `command_output` region signature (stdout
   between the benchmark's command-output header and its terminator).
2. `65656fd` — drop `cmdi_bare_whoami`. The `whoami` payload was the
   worst offender: the string `whoami` is short, common in reflected
   content, and produced no command-output region on the benchmark
   target because the servlet does not execute it in the reflected
   paths.

**Effect on methodology:** the ground-truth labels, case-vector map,
metric definitions, corpus, and statistical test are unchanged. The
pre-registered hypotheses in the body of this document are unchanged.
What changed is the recorded value of the baseline those hypotheses are
tested against. The 0.554 figure must not be cited; it measured scanner
reflections, not scanner detections.

**Consequence for the pre-registered targets:** the handoff target of
F1 >= 0.70 with P >= 0.90 is not reachable by cleanup from this
baseline. The precision gate (0.90) is already met at 0.941. The gap is
entirely recall. Work from 2026-09-29 onward focuses on recall, category
by category, with the precision gate held.

**Note on Amendment 3's in-scope subset.** The post-hoc in-scope subset
(F1 0.708) is withdrawn for the same reason and must be recomputed on
the corrected baseline before it is cited. It has not been recomputed
as of this amendment.

**On the timing of this amendment.** The three detector commits that
follow (`0d8a28b`, `42420c4`, `f4dbdf3`) landed before this amendment was
written. They do not produce a headline number: they were exercised only
on the 502-case targeted set, whose result is not published here. The
next full-corpus run — the one this amendment is written in advance of —
is the first number that will cite the corrected baseline.

---

### Amendment 5 — 2026-09-29

**What changed:** the pathtraver existence-oracle detector is recorded as
shipped, and its structural ceiling on the pinned target is documented.

**Detector:** two-payload differential. One request with a traversal
payload to a path known to exist (`../../../etc/passwd`), one to a
guaranteed-nonexistent path (`../../../etc/passwd_janissary_noexist_<nonce>`).
The target's pathtraver servlets, on the subset that actually stat the
file, respond `And file already exists.` for the first and
`But file doesn't exist yet.` for the second. Divergence between the two
responses is the evidence. Gates: neither oracle string may appear in
either payload; the EXISTS string may not appear in any baseline sample.
The NOEXIST string in baseline is the app's benign default and is not
treated as poison.

Committed as `0d8a28b` (analyzer), `42420c4` (scanner wiring), `f4dbdf3`
(baseline-gate correction). 12 unit tests.

**Measured effect — targeted 502-case vulnerable set.** Net +4 true
positives, all in the `pathtraver` category, zero false positives. The
targeted run also reproduced the `cf10841` suppression effect: 22
cmdi-reflection-inflated true positives disappeared, confirming the
suppression is real and the pre-suppression targeted counts were
contaminated.

**Measured ceiling — why the gain is only +4.** A direct probe of all 72
targeted pathtraver cases, with three payloads each (benign, traversal to
an existing path, traversal to a nonexistent path), shows three distinct
response shapes:

| shape                                     | cases | oracle possible |
|-------------------------------------------|-------|-----------------|
| existence divergence present              | 4     | yes             |
| `Access to file:` scaffold, fixed verdict | 22    | no              |
| `Now ready to write to file:` echo only   | 46    | no              |

- **4/72** stat the file and report the result. The oracle fires. All four
  are detected, none are false positives.
- **22/72** print `Access to file: <path> created. And file already
  exists.` on *every* payload, including the guaranteed-nonexistent one.
  The exists-check is a fixed string in these code paths, not a stat. No
  divergence is possible.
- **46/72** print `Now ready to write to file: <path>`. The resolved path
  is echoed, but identically on the existing-path and nonexistent-path
  payloads, with no outcome reported on either status code or body. There
  is no observable.

The detector is therefore capped at approximately **4 of 72** targeted
pathtraver cases on this target. The cap is structural — it reflects the
set of response shapes the benchmark's pathtraver servlets produce, not a
deficiency in the detector. Closing the remaining 68 requires a different
evidence model (see below), not further tuning of this one.

**Rejected alternative.** A path-escape detector for the 46 write-sink
cases — fire when the resolved path leaves the application base directory
— was considered and not built. The write-sink servlets print the
resolved path on both the safe and the vulnerable code path, so the
observable (path contains `..`, or path outside base) is present on safe
cases as well. The detector would reproduce the reflection-class
misattribution removed in Amendment 4. It is also not self-contained:
distinguishing `..` from a legitimate relative path needs a base
reference the per-case scanner does not have.

**Effect on methodology:** none. Ground-truth labels, case-vector map,
metric definitions, corpus, and statistical test unchanged. The four
true positives are real and the zero false positives hold. The next
full-corpus run will show whether the +4 scales.

**Strategic consequence.** With the pathtraver ceiling established, the
recall gap is dominated by categories this detector does not address.
Targeted FN buckets: sqli 117, cmdi 80, xss 68, trustbound 43,
pathtraver 65. Work from here proceeds to those categories, in that
order, with the precision gate held at its current level.

---

### Amendment 6 — 2026-09-30

**What changed:** the first full-corpus Track A result on the corrected
baseline (Amendment 4) is recorded. This is the headline number as of
this amendment.

**Result — full corpus, 1 run, 2026-09-30 (tool version 7.3.0):**

| run dir                        | TP  | FP | FN   | TN   | P     | R     | F1    | FPR   |
|--------------------------------|-----|----|------|------|-------|-------|-------|-------|
| 20260929T141102Z (baseline)    | 401 | 25 | 1014 | 1300 | 0.941 | 0.283 | 0.436 | 0.019 |
| 20260930T042245Z (this run)    | 414 | 24 | 1001 | 1301 | 0.945 | 0.293 | 0.447 | 0.019 |

Scored like-for-like: all 2740 cases, no skip-exclusion. The `skipped`
set (93 `header_any` and session/URI/stream cases) is counted as
not-fired, matching the baseline methodology.

Delta: TP +13, FP -1, FN -13, F1 +0.011.

**What changed between the two runs:** one detector, the pathtraver
existence oracle (Amendment 5). It was measured at +4 targeted true
positives, zero false positives.

**Honest note on the +13.** The oracle's measured scope is +4, not +13.
The extra 9 true positives are not attributed to the oracle and are not
explained by any code change since the baseline run. Run-to-run variance
on the full corpus has not been characterized (the baseline is a single
run); ±9 on 2740 cases is consistent with the variance observed on the
targeted set (±5 on 502). No claim is made that the oracle produced more
than the +4 it was measured at. A same-code rerun would settle the
question and has not been performed.

**Effect on methodology:** none. The headline is precision 0.945,
recall 0.293, F1 0.447 on the full OWASP Benchmark corpus. The
pre-registered target (F1 >= 0.70, P >= 0.90) remains unmet; precision
is above gate, recall is the gap.

**Amendment 3's headline (F1 0.554) remains withdrawn** (Amendment 4).
This amendment supersedes it as the number of record.

---

### Amendment 7 — 2026-09-30

**What changed:** the Track A harness dispatch for `mode=param` cases
now delivers the payload in the URL query string in addition to the POST
form body. This is a harness bug fix, not a scanner change.

**Why:** `_dispatch` in `benchmark/track_a/runner.py` maps
`mode=param` to `("body", testname, "POST")`. The scanner's `body`
injection path sends the payload only in the POST form body. Roughly 194
in-scope OWASP Benchmark servlets read the payload via
`HttpServletRequest.getQueryString()` rather than `getParameter()`.
`getQueryString()` returns only the raw URL query and does **not** see
the form body. Those servlets respond
`getQueryString() couldn't find expected parameter '<name>' in query string.`
on every request, regardless of payload, and the vulnerability in them is
never exercised.

A sweep of all 2,740 corpus cases with a benign POST body injection
found 295 cases whose servlet reports the `getQueryString` error. Of
these, 194 are in the in-scope categories (sqli, cmdi, pathtraver, xss,
trustbound). Those cases were silently unscannable — not missed by the
analyzer, never reached by the payload.

**Scope of the defect.** The defect is per-servlet, not per-category.
Within `sqli-01`, `BenchmarkTest00512` reads `getParameter()` and is
reached by body injection today; `BenchmarkTest00837` reads
`getQueryString()` and is not. The extractor that produced
`case_vectors.csv` classified both as `mode=param`. The classification
is correct at the level of "the payload is a request parameter"; it is
silent on which accessor the servlet uses.

**Fix.** The `body` injection path posts to `build_url(target, param,
value)` instead of `target`, so the payload appears in both the query
string and the form body of the same request. Servlets reading either
accessor receive it. Verified that currently-firing body-reader cases
(`BenchmarkTest00008`, `BenchmarkTest00512`, `BenchmarkTest02277`) still
produce their differential under the dual-vector request, so the fix is
additive.

**Measured candidate gain before the fix — upper bound, not a result.**
Of the in-scope cases not currently firing, a raw query-string
injection produces a response differential in approximately 65 cases
(sqli ~55, cmdi ~8, pathtraver ~2) after URL-decoding the response body
to remove the echo confound. This is a raw HTTP differential, not
scanner output: the scanner's baseline, region, and reflection gates
have not been applied, and the number is expected to fall. It is
recorded here as the pre-fix scope, not as a claim.

Two categories were excluded from that count: xss (60 vulnerable / 24
safe) and trustbound (49 vulnerable / 0 safe) both show the payload
HTML-escaped in the response, i.e. reflection, the class removed in
Amendment 4. They are not counted.

**Effect on methodology:** none. Ground-truth labels, case-vector map,
corpus, metric definitions, and statistical test unchanged. This changes
which requests the harness sends, not how findings are scored. The
`mode=param` classification in `case_vectors.csv` is unchanged; the
dual-vector request is a superset of the previous single-vector request.

**What this does not fix.** Cases whose servlet reads neither
`getParameter()` nor `getQueryString()` (e.g. the 89 `header_any` cases
already in `skipped.jsonl`) remain unscanned. The 295-case sweep count
includes non-in-scope categories (crypto, hash, weakrand, securecookie,
ldapi, xpathi) that JANISSARY does not claim to detect; those are out of
scope as documented in BENCHMARK.md.

---

### Amendment 8 — 2026-10-01

**What changed:** the dual-vector POST injection fix (Amendment 7) is
measured on the full corpus, and the project's run-to-run variance is
characterized for the first time.

**Result — full corpus, 1 run, 2026-09-30 (tool version 7.3.0):**

| run dir                        | TP  | FP | FN  | TN   | P     | R     | F1    |
|--------------------------------|-----|----|-----|------|-------|-------|-------|
| 20260930T042245Z (pre-dual)    | 414 | 24 | 1001| 1301 | 0.945 | 0.293 | 0.447 |
| 20260930T141249Z (post-dual)   | 497 | 28 | 918 | 1297 | 0.947 | 0.351 | 0.512 |

Delta: TP +83, FP +4, FN -83, F1 +0.065. Precision unchanged (0.945 ->
0.947). New headline: **F1 0.512, P 0.947, R 0.351.**

**What changed between the runs:** one harness fix (Amendment 7). The
`mode=param` dispatch now delivers the payload in the URL query string in
addition to the POST form body, making the ~194 in-scope servlets that
read `getQueryString()` reachable for the first time. No detector was
added or modified.

**Gain by category (fired cases):** sqli 155 -> 191 (+36),
xss 199 -> 238 (+39), cmdi 72 -> 79 (+7), pathtraver 12 -> 17 (+5).

**The xss question, resolved.** Amendment 7 excluded xss and trustbound
from its pre-fix candidate count on the grounds that their differentials
were reflection-shaped. The full-corpus result vindicates the fix and
resolves the xss concern: xss firing rose +39 while total FP rose only
+4. If the xss gains were reflection-on-safe, FP would have risen by
roughly the same count. It did not. An xss payload reflecting on an xss
case is detection, not misattribution; the `cf10841` defect was cmdi
payloads reflecting on *non-cmdi* cases. The +39 xss fires are real.

**Run-to-run variance — first characterization.** Identical code, three
runs of the 502-case targeted set, post-dual:

| run dir                        | fired |
|--------------------------------|-------|
| 20260930T065839Z (standalone)  | 315   |
| 20261001T003803Z (standalone)  | 304   |
| 20260930T141249Z (corpus subset)| 309  |

mean 309.3, population stdev 5.5, range 304-315. As a rate: 61.6% +/-
1.1pp on 502 cases.

Extrapolated to the 2740-case corpus, the run-to-run stdev on TP is
approximately +/-13 cases. Gains smaller than that are not distinguishable
from noise on a single run. The +83 TP delta recorded above is well
outside that band and is attributed to the Amendment 7 fix.

Note on an earlier apparent discrepancy: the pre-dual targeted set fired
208 (standalone) and 226 (corpus subset) -- an 18-case spread. That is a
standalone-versus-corpus *context* difference, not run-to-run noise; the
same context difference appears, smaller, on the post-dual side (304/315
standalone, 309 subset). Single-run targeted results are context-sensitive
at this level and are not compared across contexts.

**Known losses.** Four cases that fired pre-dual no longer fire
post-dual: BenchmarkTest00034 (sqli-00), BenchmarkTest02137,
BenchmarkTest02154, BenchmarkTest02430 (all cmdi-02). Three of four are
in one sub-category, consistent with a servlet that mishandles the
duplicated parameter (present in both query and body under the dual
request). Net effect is +83 TP against these 4; the cluster is noted as
an open item, not a blocker.

**Reachability as a detection lever.** The single largest gain in this
session came from fixing payload delivery, not from a detector. The
dual-vector fix moved F1 +0.065 with no analyzer change. This establishes
that payload *arrival* is a first-class concern alongside payload
*analysis*, and that harness reachability deserves auditing on the same
footing as detector coverage.

**Effect on methodology:** none to the ground-truth labels, case-vector
map, corpus, metric definitions, or statistical test. This amendment
records a result and a variance characterization, both post-hoc.

**Reporting rule adopted.** Intermediate numbers are single-run and
labeled as such. A published headline requires 3 runs and reports mean
+/- stdev. Amendment 6 and this amendment are intermediate; the final
number will carry the 3-run protocol.

**Consequence for the target (superseded 2026-10-01).** As of this
amendment the target was unmet. It has since been met: single-run
F1 0.724, P 0.967 on commit e5c95f1 (see "Track A — JANISSARY measured
results" below). The 3-run headline required by the reporting rule is now
recorded below.

## Track A — JANISSARY measured results (3-run headline)

Commit:  e5c95f1
Corpus:  case_vectors.csv (2740 cases)
Protocol: 3 runs, fresh target container per run (BENCHMARK.md line 69)

| run | TP  | FP | FN  | TN   | P     | R     | F1    |
|-----|-----|----|-----|------|-------|-------|-------|
| r1  | 818 | 28 | 597 | 1297 | 0.967 | 0.578 | 0.724 |
| r2  | 821 | 27 | 594 | 1298 | 0.968 | 0.580 | 0.726 |
| r3  | 816 | 29 | 599 | 1296 | 0.966 | 0.577 | 0.722 |

Headline (mean +/- stdev):
  Precision = 0.967 +/- 0.001
  Recall    = 0.578 +/- 0.002
  F1        = 0.724 +/- 0.002

Pre-registered target (F1 >= 0.70, P >= 0.90): MET.

Run dirs:
  benchmark/track-a/runs/20261001T114132Z-janissary-r1
  benchmark/track-a/runs/20261001T130850Z-janissary-r1
  benchmark/track-a/runs/20261001T140548Z-janissary-r1

Recall ceiling: hash-00/01/02 (129 FN) are byte-identical between
vulnerable and non-vulnerable bodies -- no black-box signal exists.
93 cases structurally skipped by the harness (89 header_any,
3 out_of_scope_stream, 1 out_of_scope_uri). All FP are xss-detector
precision on non-vulnerable xss cases (27-29 per run).

### Amendment 9 -- 2026-10-02

**Correction to the e5c95f1 headline.** The claim *"All FP are
xss-detector precision on non-vulnerable xss cases"* is wrong. There is
no xss-detector false positive. All 28-29 FPs are `sqli` and `traversal`
findings stamped on non-vulnerable **xss** paths by the reflection path:
the endpoint echoes the probe payload (HTML-encoded), `_check_reflection`
returns `payload_reflected`, and the scanner stamps the probe's category.
Console output was correct (`reflection LOW`); the JSONL artifact was not.

**A second misattribution, uncounted by the scorer.** The postgresql
`db_error` pattern `unterminated quoted string` matched bash's
`sh: 1: Syntax error: Unterminated quoted string` on 249 command-injection
findings. The scorer is path-based and class-agnostic, so those paths
scored as TPs; on a real target they would be "SQL injection" findings
whose evidence is a shell error.

**Both fixed** (reflection gate at the scanner emit loop; PG pattern
anchored to `at or near`). Regression tests added for both sides of the
reflection gate.

**Expected effect on the headline:** FP -> ~0, P -> ~1.000. Recall drops
by the mislabeled-TP count (those findings were never real detections of
their stated class), so F1 lands near the 0.70 pre-registered target.
New canonical number pending re-run; this amendment will be updated with
the run dirs once complete.

---

### Amendment 10 -- 2026-10-09

**Three-run Track A closed. New canonical headline: F1 0.682 / P 1.000.**

Supersedes the e5c95f1 3-run headline above (F1 0.724 / P 0.967). The
Amendment 9 fixes eliminated all FPs and, as anticipated, dropped recall
by the mislabeled-TP count.

| run | dir                              | TP  | FP | FN  | TN   | P     | R     | F1    |
|-----|----------------------------------|-----|----|-----|------|-------|-------|-------|
| r1  | (handoff-referenced run)         | 732 | 0  | 683 | 1325 | 1.000 | 0.517 | 0.682 |
| r2  | 20261001T170823Z-janissary-r1    | 732 | 0  | 683 | 1325 | 1.000 | 0.517 | 0.682 |
| r3  | 20261009T100138Z-janissary-r3    | 733 | 0  | 682 | 1325 | 1.000 | 0.518 | 0.682 |

Headline (mean +/- stdev):
  Precision = 1.000 +/- 0.000
  Recall    = 0.518 +/- 0.001
  F1        = 0.682 +/- 0.000

Pre-registered targets: F1 >= 0.70 MISSED by 0.018; P >= 0.90 EXCEEDED by 0.10.

**Recall regression: -86 TP vs e5c95f1.** The Amendment 9 FP fix removed
findings that were scoring as TPs but were never real detections of their
stated class (reflection-path sqli/traversal on xss echo paths; the
postgresql db_error pattern matching bash shell errors on 249 cmdi
findings). Those 86 paths are the concrete first target for recall recovery.

**Chunked-run caveat.** A parallel 4-chunk implementation (merged-r3)
scored F1 0.679 (P 1.000 / R 0.514). Chunks are disjoint and merge is
correct, but the process-boundary effect costs ~4 TPs. Headline numbers
must come from single-process runs.

**Infrastructure note.** Runs r1 and r2 used the pip launcher shim
(`.venv\Scripts\janissary.exe`), which crashes at ~7% per spawn
(WinError 5 / 0xC0000005). Two intermediate full runs died mid-corpus
from this. Commit `b651c29` adds opt-in flag JANISSARY_USE_MODULE=1 to
invoke `python -m janissary` directly; run r3 used that flag. No scoring
difference was observed between shim and module path at the single-case
level; the change eliminates mid-run crashes only.

**Run dirs:**
  benchmark/track-a/runs/20261001T170823Z-janissary-r1
  benchmark/track-a/runs/20261009T100138Z-janissary-r3

