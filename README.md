# JANISSARY

**Differential DAST for teams who need results they can trust.**

`v7.3.0` — Apache 2.0

> ### Authorised use only
>
> JANISSARY is a dual-use security testing tool. Use it **only**
> against systems you own, or systems you have prior written
> permission to test.
>
> By running any network command you accept the
> [Terms of Use](LEGAL.md). Review with `janissary terms show`.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)

---

## Why JANISSARY

Most DAST tools are either expensive enterprise platforms or raw scripts that produce unusable noise. JANISSARY is different in three specific ways:

**Differential detection, measured.** Every finding is gated by a baseline comparison — nothing emits from a single response. On the OWASP Benchmark DAST-applicable corpus: precision 1.000 (0 FP), recall 0.851, F1 0.920 across 2,258 cases (1,156 vulnerable). Reproducible in one command.

**WAF-aware pacing.** Detects Cloudflare, Akamai, Sucuri, Imperva, AWS WAF, F5, Barracuda, ModSecurity, Wordfence, and Fastly, then adapts request pacing on block signals and recovers on clean streaks. If you're scanning an authorised target, getting blocked mid-scan wastes the scan.

**Multi-protocol coverage.** HTTP, XML-RPC, GraphQL, and WebSocket, combined into a single agent run.

---

## See it work

![JANISSARY demo](docs/demo.gif)

One real SQL injection, scanned with `janissary scan`:

```text
$ janissary scan -u "http://localhost:5001/sqli?q=test" -p q

[*] Scanning http://localhost:5001/sqli?q=test
[*] Parameters: q
[*] Baseline samples: 10

[*] Probing for WAF...
    No WAF signatures observed
  [q] baseline is static - timing gates disabled
  [q] sql_single_quote -> CRITICAL: db_error | SQLITE error signature matched
  [q] sql_union_null  -> HIGH: status_change | Baseline 200 -> Payload 500
  ...

============================================================
SCAN SUMMARY
============================================================
  Target:          http://localhost:5001/sqli?q=test
  Parameters:      q
  Method:          GET
  Total requests:  29
  Findings:        11 in 2 groups

  Baselines:
    q: samples=10 mean=2.0484s std=0.0098s stable_body=True

  Findings:
    F-001  CRITICAL sqli:sql_injection  (param=q)
           - [sql_single_quote] db_error: SQLITE error signature matched
           - [sql_single_quote] status_change: Baseline 200 -> Payload 500
           - [sql_single_quote] length_anomaly: Response 3.6x baseline
           - [sql_or_1eq1]      length_anomaly: Response 3.8x baseline
           - [sql_union_null]   status_change: Baseline 200 -> Payload 500
           - [sql_union_null]   length_anomaly: Response 10.1x baseline
           - [sql_sleep_mysql]  status_change: Baseline 200 -> Payload 500
           - [sql_sleep_mysql]  length_anomaly: Response 3.3x baseline
           - [sql_sleep_pg]     status_change: Baseline 200 -> Payload 500
           - [sql_sleep_pg]     length_anomaly: Response 5.8x baseline

    F-002  LOW      sqli:reflection  (param=q)
           - [sql_single_quote] payload_reflected: Payload reflected (raw)

  Findings by severity:
    CRITICAL   1
    HIGH       4
    MEDIUM     5
    LOW        1
```

Eleven signals, **one bug**. Every piece of evidence for `F-001` points
at the same SQL injection, so JANISSARY groups them. `F-002` is a
different root cause (reflection) and stays separate. One finding to
triage, with the receipts attached.
---

## Benchmark

JANISSARY is scored against the OWASP Benchmark DAST-applicable corpus. Full results, methodology, and the class-aware definition are in `BENCHMARK.md`. The current run is `benchmark/track-a/runs/merged-am19-recovered`.

| Metric | Value |
|---|---|
| Precision | 1.000 |
| Recall | 0.851 |
| F1 | 0.920 |
| TP / FP / FN | 984 / 0 / 172 |
| Categories at F1 1.000 | 18 |

Reproduce: `python benchmark/track_a/score_dast_aware.py benchmark/track-a/runs/merged-am19-recovered`

The weakest category is path traversal (F1 0.049–0.308), documented in `docs/pathtraver.md` as a property of the benchmark target, not a scanner gap.

## Install


```bash
pip install janissary

# From source (development)
git clone https://github.com/Hetaireia/janissary.git
cd janissary
pip install -e .
```

---

## Quickstart

Accept the Terms of Use (required once before any network command):

```bash
janissary terms accept
```

Scan a single endpoint:

```bash
janissary scan -u "https://target.example/sqli?q=test" -p q
```

Scan a Git repository for leaked credentials:

```bash
janissary creds ./my-repo --scan-git
```

Fingerprint a target:

```bash
janissary fingerprint https://target.example
```

Probe for admin panels:

```bash
janissary admin https://target.example
```

---

## Commands

| Command | What it does |
|---|---|
| `scan` | HTTP scanning: SQLi, XSS, SSRF, traversal, cmdi |
| `creds` | Credential discovery in tree or Git history |
| `fingerprint` | CMS and technology identification |
| `graphql` | GraphQL detection and field enumeration |
| `ws` | WebSocket recon |
| `admin` | Admin panel discovery, 18 platforms |
| `agent` | Orchestrates recon, persists findings |
| `terms` | Show, check, or accept Terms of Use |
| `attack sqli-union` | UNION extractor (gated) |
| `attack nuclei` | Nuclei runner (gated) |

Run `janissary --help` for full flags.

---

## Attack modules

The `attack` subcommands are opt-in. They require `--attack-confirm` in addition to the Terms-of-Use gate. Neither alone is enough.

- **`attack sqli-union`** - extracts DBMS version, current database, database list, and table list from a vulnerable parameter. Hard limits: 32 columns, 100 rows, 64KB. Aborts on instability.
- **`attack nuclei`** - shells out to the Nuclei binary, streams JSONL, parses findings. Requires an explicit template list; refuses to run Nuclei's default set.

---

## Agent

The `agent` command ties the recon modules together: fingerprint, detect WAF, consult the platform knowledge base, run applicable modules, persist findings.

```bash
janissary agent https://target.example --attack-confirm
```

---


## Scope, authentication, and machine-readable output

### Scope enforcement

Hunters run against bug-bounty programs whose scope is contractual.
`--scope-include` and `--scope-exclude` refuse to touch anything outside
the declared boundary - before any network I/O, with exit code 64 and an
empty stdout.

```bash
# Only scan example.com and its subdomains, never admin.example.com
janissary scan -u "https://api.example.com/v1/items?id=1" -p id \
  --scope-include "*.example.com" \
  --scope-exclude "admin.example.com"

# Internal network, CIDR-based
janissary scan -u "http://10.1.2.3/" -p q --scope-include "10.0.0.0/8"
```

Deny always beats allow. Pattern syntax: `example.com`, `*.example.com`,
`10.0.0.0/8`, `10.0.0.5`, `/api/`, `https://api.example.com/v1/`, or `*`
for any. If no `--scope-include` is given, everything passes the include
check; excludes still apply.

### Authentication

Static cookie and bearer-token headers apply to every request in the scan:
WAF probes, preflight, baselines, and payloads.

```bash
janissary scan -u "https://app.example.com/profile?id=1" -p id \
  --cookie "session=abc123; csrf=xyz"

janissary agent https://app.example.com --attack-confirm \
  --bearer "eyJhbGciOi..."
```

`--redact-auth` swaps `Authorization` and `Cookie` header values with
`[REDACTED]` in JSON/JSONL output only. Body content is untouched - a
leaked secret inside a response body is often the actual bug. Use this
before pasting scan output into a bug report.

### Machine-readable output

`--json` emits one envelope document to stdout. `--jsonl` emits one
finding per line. Both reserve stdout for the machine payload; every
human status line (progress, WAF feedback, backoff) goes to stderr.
`--quiet` silences stderr only - it never affects stdout.

```bash
# One document, all findings
janissary scan -u "https://target.example/?q=1" -p q --json > scan.json

# Streaming, filter with jq
janissary scan -u "https://target.example/?q=1" -p q --jsonl | jq -c .
```

Every finding carries `raw_request` and `raw_response` as HTTP/1.1 text
with CRLF line endings, ready to paste into Burp Repeater.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## Known Limitations
*Honesty over assumptions. These are actively tracked, known issues.*

- **SPA Catch-All False Positives (Issue #1):** Applications that return HTTP 200 for arbitrary routes (like SPAs) can cause the admin-panel check to report false positives (e.g., `/wp-admin/`). Future work requires moving beyond status codes to content-length and body-signature differentials.
- **HTTP 401 Abort Behavior (Issue #2):** A 401 response currently aborts the scan instead of reporting an `auth_required` state. Future work will capture 401/403, continue safe checks, and report the auth state cleanly.
- **Framework-Specific SQLi:** Payloads are now expanded to handle parenthesized SQL queries (Juice Shop), but ORM-specific edge cases remain a constant target for improvement.

## License

Apache 2.0 for the source code. See [LICENSE](LICENSE).

Use is additionally governed by the [Terms of Use](LEGAL.md), which supplement and do not replace the Apache 2.0 licence.

## Live WAF Evidence

JANISSARY was run against OWASP Juice Shop behind ModSecurity + OWASP CRS. The scanner detected the WAF, received block signals, and paced requests without aborting the scan.

```text
[*] Probing for WAF...
    WAF detected: unknown (confidence 0.90)
[*] Initial inter-request delay: 2.80s
...

  WAF:
    detected=True vendor=None confidence=0.9

  Pacer:
    final_delay=30.0s events=38

  Findings:
    F-001  CRITICAL sqli:sql_injection  (param=q)
           - [sql_hash_comment] db_error: SQLITE error signature matched
```

Configuration: `docker-compose.waf.yml` (ModSecurity CRS reverse proxy in front of Juice Shop). This closes the gap between "architecturally paces" and "provably paces."


## Docker

```bash
docker run --rm oraclemode337/janissary scan -u "https://target.example" -p q
```

The image exposes the same entrypoint as the PyPI package. Use host.docker.internal to reach services on the host from inside the container.

