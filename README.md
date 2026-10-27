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

---

## Why JANISSARY

Most DAST tools are either expensive enterprise platforms or raw scripts that produce unusable noise. JANISSARY is different in three specific ways:

> **The Strategic Wedge:** JANISSARY is an open-source DAST tool that offers proven WAF resilience, zero-false-positive differential detection, and Burp-ready output at a free price point.


**Differential detection, measured.** Every finding is gated by a baseline comparison — nothing emits from a single response. Reproduced on v7.3.0 against the OWASP Benchmark DAST-applicable corpus under the pre-registered methodology in [`BENCHMARK.md`](BENCHMARK.md): precision 1.000 (0 FP), recall 0.854, F1 0.921 across 2,258 cases (1,156 vulnerable). F1 held unchanged through 7.4.0 and 7.5.0 — both arcs are non-scoring-path by construction, verified by `test_scanner_ssrf_no_collaborator_no_ssrf_findings`. Three baseline runs give a mean unassisted F1 of 0.903 ± 0.009; the FN-recovery pass at `JANISSARY_TIMEOUT=180` (Amendment 20 protocol; applied to runs 1 and 2) closes to 0.921. Run artifacts committed under [`benchmark/track_a/runs/`](benchmark/track_a/runs/).

**WAF-aware pacing.** Detects Cloudflare, Akamai, Sucuri, Imperva, AWS WAF, F5, Barracuda, ModSecurity, Wordfence, and Fastly, then adapts request pacing on block signals and recovers on clean streaks. If you're scanning an authorised target, getting blocked mid-scan wastes the scan.

**Multi-protocol coverage.** HTTP, XML-RPC, GraphQL, and WebSocket, combined into a single agent run. Every finding carries `raw_request` and `raw_response` as CRLF HTTP/1.1 text, ready to paste into Burp Repeater.

---

## SSRF via collaborator — new in 7.5.0

`janissary scan --collaborator <URL>` adds out-of-band Server-Side Request Forgery detection to the standard scan loop. Five OOB-detectable payloads — `http`, `https`, `gopher`, `dict`, `dns_only` — are sent per parameter after the differential payload loop. Collaborator hits become findings.

| Finding category | Severity | Meaning |
|---|---|---|
| `ssrf:collaborator_hit` | CRITICAL | Target made an HTTP/HTTPS fetch to your collaborator. Real SSRF. |
| `ssrf:dns_only_resolution` | INFO | Target resolved an arbitrary hostname but did not establish TCP. Useful signal, not full SSRF. |

Compatible with **Burp Pro**, **interactsh**, and **ProjectDiscovery interact.sh** through the standard poll protocol. Each payload gets a unique subdomain (`jns-<16hex>`) so hits are attributed deterministically.

Two flags on `scan`:

- `--collaborator URL` — your collaborator endpoint (Burp Collaborator, interactsh server, or ProjectDiscovery interact.sh).
- `--ssrf-timeout N` — outer wait for collaborator hits (default 10s).

Example: SSRF on a URL-fetching parameter.

```bash
janissary scan \
  -u "https://target.example/api/fetch?url=https://example.com" \
  -p url \
  --collaborator "https://your-collaborator-endpoint" \
  --ssrf-timeout 15
