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