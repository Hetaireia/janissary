# SSRF via collaborator

Out-of-band Server-Side Request Forgery detection, added to the standard
scan loop behind the `--collaborator` flag. SSRF is one of the finding
categories documented in the [README feature table](../README.md#what-it-does).

This document is the deep dive; the README carries a one-line summary and a
cross-link. Moved from the README during the branding restructure pass on
2026-11-10 to keep the README focused on first contact. Content
preserved verbatim apart from the header line, which dropped the stale
"new in 7.5.0" framing.


`janissary scan --collaborator <URL>` adds out-of-band Server-Side Request Forgery detection to the standard scan loop. Five OOB-detectable payloads - `http`, `https`, `gopher`, `dict`, `dns_only` - are sent per parameter after the differential payload loop. Collaborator hits become findings.

| Finding category | Severity | Meaning |
|---|---|---|
| `ssrf:collaborator_hit` | CRITICAL | Target made an HTTP/HTTPS fetch to your collaborator. Real SSRF. |
| `ssrf:dns_only_resolution` | INFO | Target resolved an arbitrary hostname but did not establish TCP. Useful signal, not full SSRF. |

### Compatibility

Compatible with **Burp Pro**, **interactsh**, and **ProjectDiscovery interact.sh** through the standard poll protocol. Each payload gets a unique subdomain (`jns-<16hex>`) so hits are attributed deterministically.

Two flags on `scan`:

- `--collaborator URL` - your collaborator endpoint.
- `--ssrf-timeout N` - outer wait for collaborator hits (default 10s).

### Example
```bash
janissary scan -u "https://target.example/api/fetch?url=https://example.com" -p url --collaborator "https://your-collaborator-endpoint" --ssrf-timeout 15
```

### Opt-in, zero cost when off

SSRF is opt-in: with no `--collaborator`, the SSRF phase is a no-op and adds zero requests. Three additional payloads that cannot be observed via OOB - `metadata_http`, `metadata_v6`, `file` - require response-body inspection and are deferred to a future response-body detection path.

---
