# JANISSARY

**Differential DAST for teams who need results they can trust.**

`v7.5.0` — Apache 2.0

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

![JANISSARY demo](docs/demo.gif)

---

## Why JANISSARY

Most DAST tools are either expensive enterprise platforms or raw scripts that produce unusable noise. JANISSARY is different in three specific ways:

> **What makes JANISSARY different:** JANISSARY is an open-source DAST tool that offers proven WAF resilience, zero-false-positive differential detection, and Burp-native output at a free price point.


**Differential detection, measured.** Every finding is gated by a baseline comparison — nothing emits from a single response. Reproduced on v7.3.0 (F1 unchanged through 7.4.0 and 7.5.0) against the OWASP Benchmark DAST-applicable corpus under the pre-registered methodology in [`BENCHMARK.md`](BENCHMARK.md): precision 1.000 (0 FP), recall 0.854, F1 0.921 across 2,258 cases (1,156 vulnerable). Three baseline runs give a mean unassisted F1 of 0.903 ± 0.009; the FN-recovery pass at `JANISSARY_TIMEOUT=180` (Amendment 20 protocol; applied to runs 1 and 2) closes to 0.921. Run artifacts committed under [`benchmark/track_a/runs/`](benchmark/track_a/runs/).

**WAF-aware pacing.** Detects Cloudflare, Akamai, Sucuri, Imperva, AWS WAF, F5, Barracuda, ModSecurity, Wordfence, and Fastly, then adapts request pacing on block signals and recovers on clean streaks. If you're scanning an authorised target, getting blocked mid-scan wastes the scan.

**Multi-protocol coverage.** HTTP, XML-RPC, GraphQL, and WebSocket, combined into a single agent run.

---

## SSRF via collaborator - new in 7.5.0

`janissary scan --collaborator <URL>` adds out-of-band Server-Side Request Forgery detection to the standard scan loop. Five OOB-detectable payloads - `http`, `https`, `gopher`, `dict`, `dns_only` - are sent per parameter after the differential payload loop. Collaborator hits become findings.

| Finding category | Severity | Meaning |
|---|---|---|
| `ssrf:collaborator_hit` | CRITICAL | Target made an HTTP/HTTPS fetch to your collaborator. Real SSRF. |
| `ssrf:dns_only_resolution` | INFO | Target resolved an arbitrary hostname but did not establish TCP. Useful signal, not full SSRF. |

Compatible with **Burp Pro**, **interactsh**, and **ProjectDiscovery interact.sh** through the standard poll protocol. Each payload gets a unique subdomain (`jns-<16hex>`) so hits are attributed deterministically.

Two flags on `scan`:

- `--collaborator URL` - your collaborator endpoint.
- `--ssrf-timeout N` - outer wait for collaborator hits (default 10s).

Example:

```bash
janissary scan -u "https://target.example/api/fetch?url=https://example.com" -p url --collaborator "https://your-collaborator-endpoint" --ssrf-timeout 15
```

SSRF is opt-in: with no `--collaborator`, the SSRF phase is a no-op and adds zero requests. Three additional payloads that cannot be observed via OOB - `metadata_http`, `metadata_v6`, `file` - require response-body inspection and are deferred to a future response-body detection path.

---

## See it work

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

JANISSARY is scored against the OWASP Benchmark DAST-applicable corpus. Full results, methodology, and the class-aware definition are in `BENCHMARK.md`. Run artifacts are committed under `benchmark/track_a/runs/`; the recovered run is `20261024T130735Z-janissary-r1+rec`.

| Metric | Value |
|---|---|
| Precision | 1.000 |
| Recall | 0.854 |
| F1 | 0.921 |
| TP / FP / FN | 987 / 0 / 169 |
| Categories at F1 1.000 | 20 |
| 3-run unassisted baseline F1 | 0.903 ± 0.009 (n=3) |

Reproduce: `python benchmark/track_a/score_dast_aware.py benchmark/track_a/runs/20261024T130735Z-janissary-r1+rec`

The F1 0.921 figure applies the FN-recovery protocol to the first two baseline runs; the third baseline run (`20261025T062837Z-janissary-r3`, F1 0.895) has not been recovery-scored. Full detail in `BENCHMARK.md` Amendment 22.

The weakest category is path traversal (F1 0.049–0.308), documented in `docs/pathtraver.md` as a property of the benchmark target, not a scanner gap.

## Install


```bash
pip install janissary==7.5.0

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

Scans with ``--cookie`` or ``--bearer`` abort with exit code 2 when two consecutive HTTP 401 responses arrive mid-scan. Findings collected before the abort are preserved, and ``abort_reason`` names the threshold, param, and last payload attempted, so an expired session is reported cleanly rather than producing false negatives.

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

SARIF 2.1.0 export is available via ``--export *.sarif`` on ``scan`` and ``agent``. Output is catalog-driven with CWE taxonomy and cross-run partialFingerprints, suitable for CI/CD and GitHub code scanning.

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
- **Path traversal recall 0.049-0.308.** Not a supported detection class in 7.x. Documented in ``docs/pathtraver.md`` as a property of the benchmark target, not a scanner gap.
- **SSRF payload scope (7.5.0):** Five OOB-detectable payloads ship today. Three additional payloads that require response-body inspection - ``metadata_http``, ``metadata_v6``, ``file`` - are deferred to a future response-body detection path.
- **No IDOR detection yet.** Insecure Direct Object Reference is not in 7.5.0. It is planned for 7.6.0.

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
docker run --rm oraclemode337/janissary:7.5.0 scan -u "https://target.example" -p q
```

The image exposes the same entrypoint as the PyPI package. Use host.docker.internal to reach services on the host from inside the container.

