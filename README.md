<p align="center"><img src="docs/branding/banners/Janissary%20Signal%20Over%20Noise%20Banner.png" alt="JANISSARY — SIGNAL OVER NOISE." width="100%"></p>

<p align="center"><b>Differential DAST for teams who need results they can trust.</b></p>

<p align="center"><sub>Precision-gated scanning. Every finding proves itself before it is reported.</sub></p>

<p align="center">
<img alt="OWASP F1 0.938" src="https://img.shields.io/badge/OWASP_F1-0.938-D4AF37?style=flat-square&labelColor=0B0B0F">
<img alt="Precision 1.000" src="https://img.shields.io/badge/precision-1.000-12141A?style=flat-square&labelColor=0B0B0F">
<img alt="Licence Apache-2.0 core" src="https://img.shields.io/badge/licence-Apache--2.0_core-12141A?style=flat-square&labelColor=0B0B0F">
<img alt="Version 7.11.1" src="https://img.shields.io/badge/version-7.11.1-4B5057?style=flat-square&labelColor=0B0B0F">
</p>

<p align="center"><a href="#architecture">Architecture</a> · <a href="#benchmark">Benchmark</a> · <a href="#install">Install</a> · <a href="#licence">Licence</a> · <a href="#limitations">Limitations</a></p>

---

> [!CAUTION]
> **Authorised use only.** JANISSARY is a dual-use security testing tool. Use it **only** against systems you own, or systems you have prior written permission to test. By using this tool, you accept the Terms of Use in LEGAL.md.

<a id="architecture"></a>

## Architecture

Two engines, one contract. A discovery engine fires payloads; a confirmer engine re-tests every candidate against a baseline response and only the confirmer may emit a verified finding. Anything it cannot prove is reported separately as a candidate and never laundered into the findings stream.

<p align="center"><img src="docs/branding/janissary-architecture-diagram.png" alt="Architecture diagram: discovery engine, candidate queue, confirmer chain, dual-stream output" width="100%"></p>

The split is load-bearing. A finding that survives the confirmer has a reproduction, not an opinion, and the two-stream output keeps unproven leads visible without inflating what the tool claims.

<a id="benchmark"></a>

## Benchmark

OWASP Benchmark, DAST-applicable subset, 2,258 cases. Clean-exit run at harness commit 8ecb302, 67 minutes, WSL Ubuntu under Python 3.14.4, 2,740 spawns, zero native crashes.

<table align="center" width="100%">
<tr>
<td align="center" width="25%"><h2><b>0.938</b></h2><sub>F1 · DAST-APPLICABLE</sub></td>
<td align="center" width="25%"><h2><b>1.000</b></h2><sub>PRECISION</sub></td>
<td align="center" width="25%"><h2><b>0.884</b></h2><sub>RECALL</sub></td>
<td align="center" width="25%"><h2><b>1,022 / 0</b></h2><sub>TP / FP</sub></td>
</tr>
</table>

<p align="center"><sub><b>0.922</b> BASELINE · P 1.000 · R 0.855 · TP 988 · <code>ea7b3e5</code></sub></p>

> **Attribution.** The +34 TPs over that baseline are entirely path traversal, all from commit `f964339`; every other category is unchanged. This is not a generalised capability jump.

> **Single run.** These figures are one execution at 8ecb302, not a mean of repeats.

> [!NOTE]
> Precision 1.000 is scoped to this corpus and does not establish a real-world false-positive rate. The M89 negative corpus targets that.

The +34 true positives over that baseline are entirely path traversal and all trace to one commit, f964339. Every other category is unchanged, and precision stays at 1.000 in both runs. Path traversal recall moves from 0.075 BASELINE to 0.323.

Full corpus: TP 1,022, FP 0, FN 393, TN 1,325, P 1.000, R 0.722, F1 0.839. Supported-classes subset, which excludes path traversal: TP 978, FP 0, FN 45, TN 967, F1 0.978. Method, dispositions and provenance are in BENCHMARK.md, Amendment 30.

<a id="why"></a>

## Why JANISSARY

### Differential detection, measured

Every finding is gated by a baseline comparison. Nothing emits from a single response. The 0.938 figure is one change in one class, clean-exit, with the non-claims stated rather than buried.

### WAF-aware pacing

Detects Cloudflare, Akamai, Sucuri, Imperva, AWS WAF, F5, Barracuda, ModSecurity, Wordfence and Fastly, then adapts request pacing on block signals and recovers on clean streaks. Getting blocked mid-scan wastes the scan.

### Multi-protocol coverage

HTTP, XML-RPC, GraphQL and WebSocket combined into a single agent run.

<a id="capabilities"></a>

## Capabilities

| Area | Detail | Status |
|---|---|---|
| SQL injection | Error, union, blind | shipped |
| Reflected XSS | Context-aware payloads | shipped |
| Command injection | Shell and argument forms | shipped |
| SSRF | Out-of-band via collaborator, cloud metadata markers | shipped |
| Path traversal | Content-signature differential | partial, 0.323 recall |
| Recon | CMS and technology fingerprint, 18-platform admin probe | shipped |
| Protocols | HTTP, XML-RPC, GraphQL, WebSocket | shipped |
| Orchestration | Agent: fingerprint, WAF, KB, modules, findings | shipped |
| Output | text, JSON, JSONL, SARIF 2.1.0 | shipped |

<a id="install"></a>

## Install

PyPI, git main, and the Docker image are at **7.11.1** (2026-11-21; includes ADR-032 SPA false-positive floor, ADR-033 evidence grading P1-P4, ADR-034 DNS-vs-HTTP OOB discrimination).

<details>
<summary>pip install</summary>

```bash
pip install janissary

# 7.11.x line
git clone https://github.com/Hetaireia/janissary.git
cd janissary
pip install -e .
```

</details>

<details>
<summary>Docker</summary>

```bash
docker run --rm oraclemode337/janissary:7.11.1 scan -u https://target.example/sqli?q=test -p q
```

</details>

<details>
<summary>source</summary>

```bash
git clone https://github.com/Hetaireia/janissary.git
cd janissary
pip install -e '.[dev]'
pytest -q
```

</details>

<a id="quickstart"></a>

## Quickstart

Authorised use is covered by a non-blocking safe-harbour notice in LEGAL.md.

<details>
<summary>Scan a single endpoint</summary>

```bash
janissary scan -u "https://target.example/sqli?q=test" -p q
```

</details>

<details>
<summary>Scan a Git repository for leaked credentials</summary>

```bash
janissary creds ./my-repo --scan-git
```

</details>

<details>
<summary>Fingerprint a target</summary>

```bash
janissary fingerprint https://target.example
```

</details>

<details>
<summary>Probe for admin panels</summary>

```bash
janissary admin https://target.example
```

</details>

<a id="commands"></a>

## Commands

| Command | Purpose |
|---|---|
| scan | HTTP scanning: SQLi, XSS, SSRF, traversal, cmdi |
| creds | Credential discovery in a tree or Git history |
| fingerprint | CMS and technology identification |
| graphql | GraphQL detection and field enumeration |
| ws | WebSocket recon |
| admin | Admin panel probe |
| agent | Orchestrates recon, persists findings |
| attack sqli-union | UNION extractor, gated |

<a id="scope"></a>

## Scope, auth and output

Scope enforcement, auth headers and the JSON, JSONL and SARIF 2.1.0 writers are documented in docs/. Scope is enforced at the requester, so an out-of-scope redirect fails closed rather than following.

<a id="licence"></a>

## Licence

JANISSARY is open-core. The core is Apache-2.0 because a scanner you cannot read is a scanner you cannot trust, and the free core is the front door rather than a demo.

| Licence | Class | Contents |
|---|---|---|
| **Apache-2.0** | Apache License 2.0 | Detection engine, confirmer chain, differential workflow, IDOR |
| **Commercial** | Proprietary | Control plane: SSO and RBAC, fleet scheduling, ticketing, SLAs |

The M89 negative corpus is not published. WAF backoff curves and pacing logic are available in the open-source repository.

Governing law is Victoria, Australia. IDOR stays in the Apache-2.0 core, not behind a paid tier. Contribution terms and the outbound licence grant are in CONTRIBUTING.md.

<a id="limitations"></a>

## Known limitations

Path traversal recall is 0.323, up from 0.075 BASELINE. The remaining false negatives are target-capped on this corpus: the response layout does not leak the file-existence oracle for most cases, so they are structurally undetectable rather than unimplemented.

Precision 1.000 is scoped to this corpus. It does not establish a real-world false-positive rate, which is the target of the M89 negative regression corpus.

The 0.938 headline is one run, not a three-run mean. Attribution is a single commit in a single class.

---

<p align="center"><sub><a href="BENCHMARK.md">method, amendments, provenance</a> · <a href="docs/">documentation</a> · <a href="SECURITY.md">disclosure</a> · <a href="CONTRIBUTING.md">contribution terms</a> · <a href="https://dev.to/janissary">writing</a></sub></p>

<p align="center"><sub><b>SIGNAL OVER NOISE.</b> · Hetaireia · Victoria, Australia · Apache-2.0 core</sub></p>
