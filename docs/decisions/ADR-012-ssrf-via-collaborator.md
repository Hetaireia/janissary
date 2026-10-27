# ADR-012 — SSRF detection via Burp-compatible collaborator

**Status:** Accepted (2026-10-27). Session 0.3.14 design lock.
**Supersedes:** None. **Blocks:** Nothing. Unblocks SSRF as a first-class scanner feature.

## Context

JANISSARY detects SQLi, XSS, LDAP, XPath, traversal, command injection. It does
not detect SSRF as a general scanner feature — despite SSRF being the
second-highest-value finding class in modern bug bounty after IDOR. Two partial
implementations exist (`graphql.py:112` ssrf_url payload, `xmlrpc.py:562`
pingback probe); neither generalizes to "any parameter may be SSRF-vulnerable."

### Recon findings (session 0.3.14)

1. OWASP Benchmark has zero SSRF cases. `BENCHMARK.md` and `ADR-001` contain no
   SSRF references. F1 is unaffected by SSRF additions.
2. `DifferentialAnalyzer` cannot be reused — snapshot-based, SSRF evidence is
   out-of-band, asynchronous.
3. `_paced_request` (scanner.py:357) is the right chokepoint but the wrong
   timing — 30+ calls per parameter, per-call polling is ~15s/param.
4. `ScanFinding` (scanner.py:160) already has every field SSRF needs.
5. `sarif_rules._RULES` (line 169) and `grouping._ROOT_CAUSE_MAP` (line 20) are
   extensible dicts — SSRF entries plug in without structural change.
6. `scope.py:29` already names "DNS-rebinding SSRF" as a scope scenario.
7. No collaborator client exists. New module
   `src/janissary/integrations/collaborator.py`, patterned on `xmlrpc.detect()`.

## Decisions

### D1. Burp-compatible protocol, user-supplied endpoint

User supplies `--collaborator <url>`. JANISSARY speaks the Burp poll protocol:
`GET <url>/poll?id=<unique>` returning
`{"responses": [{"protocol": "dns"|"http", "data": {...}}]}`. Compatible with
Burp Pro, interactsh, ProjectDiscovery interact.sh. Zero new infrastructure to
host. No SLA. No lifecycle management.

### D2. Unique subdomain per payload

Each payload embeds `<uniq>.<collab-id>.<domain>`. Hit on
`ssrf_payload_3.<collab-id>.<domain>` maps deterministically to payload 3. No
timestamp inference when 10 payloads fire in 2s.

Eight v1 payloads: `ssrf_http`, `ssrf_https`, `ssrf_gopher`
(`gopher://<uniq>.<collab>:6379/_INFO` for Redis), `ssrf_dict`
(`dict://<uniq>.<collab>:6379/`), `ssrf_metadata_http` (169.254.169.254 with
Host rewrite), `ssrf_metadata_v6` (`[fd00:ec2::254]`), `ssrf_file`
(`file:///etc/passwd`), `ssrf_dns_only` (`http://<uniq>.<collab>:9/` — DNS
fires, TCP refused, exercises the D5 negative-case gate).

### D3. SSRF runs as a post-payload phase

After the per-parameter payload loop, if `--collaborator` supplied:

    for param in self.params:
        <baseline + differential payload loop>  # existing
        if self.collaborator is not None:
            self._ssrf_phase(param, quiet=quiet)

`_ssrf_phase` sends 8 payloads via `_paced_request`, records send-time per
payload, polls at t+2s, t+5s, t+10s. First hit terminates polling. Cost: ~15s
per parameter worst case, ~2s common case (skip polls 2-3 if poll 1 empty).

### D4. Timeout semantics

Poll at 2s, 5s, 10s after last SSRF payload send. `--ssrf-timeout` overrides the
10s outer wait. Fast path (2s) catches typical Burp Collaborator <100ms.
5s/10s handle proxied or sluggish egress. Responses arriving after 10s are
unmatched by timestamp, ignored.

### D5. False-positive gates

A collaborator response is an SSRF finding only when ALL hold:
- Protocol is `http` or `https` (not `dns`)
- Response timestamp > payload send timestamp
- Response address matches one of the sent payload subdomains
- The scanned target is in scope (existing scope gate)

DNS-only responses emit a separate `info`-severity finding
(`finding_type="dns_only_resolution"`), visible with `--verbose`. A target that
resolves our hostname but refuses TCP is usually `getaddrinfo()` in a redirect
handler, not a vulnerable sink. Emitting as high would erode trust.

HTTP/HTTPS responses emit `severity="critical"`,
`finding_type="collaborator_hit"`. Source IP of the hit (Burp and interactsh
both include it) is recorded in `ScanFinding.extra` as evidence, not a gate
(target may be behind CDN, VPC, or proxy).

### D6. Scope contract

Scope gates the target. SSRF payload delivery does not violate scope: the
payload is sent to the target; the target's outbound fetch is the target's
behavior, not JANISSARY's. The collaborator URL is never in scope — it is
evidence collection. `scope.py:29` already names DNS-rebinding SSRF.

### D7. Benchmark neutrality confirmed by construction

OWASP Benchmark has no SSRF cases (recon 1). The 8 SSRF payloads run only when
`--collaborator` is supplied; the benchmark harness passes no such flag.
`_ssrf_phase` is guarded by `if self.collaborator is not None` (False for all
benchmark runs). F1=0.921 unchanged.

### D8. Three commits across two sessions

- **0.3.14 (this session):** ADR-012 design lock. One commit. No code.
- **0.3.15 commit 1:** implementation — `collaborator.py`, `_ssrf_phase`,
  `--collaborator` and `--ssrf-timeout` CLI flags, SARIF/grouping entries,
  8 tests.
- **0.3.15 commit 2:** version bump 7.4.0 → 7.5.0 + CHANGELOG.

Cut 7.5.0 after 0.3.15. Same operator runbook as 7.4.0.

### D9. Test matrix (8 tests, tests/unit/test_ssrf.py)

1. `test_ssrf_hit_http_emits_finding`
2. `test_ssrf_hit_https_emits_finding`
3. `test_ssrf_dns_only_emits_info_finding`
4. `test_ssrf_no_hit_emits_nothing`
5. `test_ssrf_collaborator_unreachable_skips_phase`
6. `test_ssrf_collaborator_auth_failure_skips_phase`
7. `test_ssrf_unique_subdomains_attributed_correctly`
8. `test_ssrf_benchmark_neutral`

Test count: 611 → 619 (+8).

### D10. Scope boundaries

In v1: blind SSRF via Burp-compatible collaborator (majority of modern SSRF
bounty findings). Deferred to future ADRs: semi-blind SSRF via timing
differential (ADR-013 candidate), stored SSRF via marker polling (ADR-014
candidate), project-hosted collaborator (7.6.x option, evidence-driven).

## Consequences

Positive: SSRF first-class; interoperates with existing nuclei/ffuf/Burp Pro
ecosystem rather than reinventing OOB; zero infrastructure; DNS-only info
finding gives triage signal. Negative: requires external collaborator; users
without one get a clean error and zero behavior change. Neutral: no new
dependencies, zero runtime cost when `--collaborator` absent, no interaction
with ADR-010/011 (auth expiry and SSRF detection orthogonal).

## Alternatives rejected

Reuse `DifferentialAnalyzer` with OOB evidence type (snapshot-based abstraction
is wrong). Per-payload synchronous polling (15s/param). HTTP/HTTPS-only payloads
(skips gopher/dict, the classic SSRF→RCE bridge). Project-hosted collaborator as
v1 (violates zero-hosting directive). DNS-only hits at `high` severity (usually
not a vulnerable sink; produces FPs that erode trust). Scope-include collaborator
URL (evidence endpoint, not scan target).

## References

- src/janissary/integrations/graphql.py:112 — partial SSRF payload
- src/janissary/integrations/xmlrpc.py:562 — pingback SSRF probe
- src/janissary/engine/scanner.py:515 — payload loop (`_ssrf_phase` runs after)
- src/janissary/engine/scanner.py:160 — `ScanFinding` (all fields exist)
- src/janissary/sarif_rules.py:169 — `_RULES` dict
- src/janissary/engine/grouping.py:20 — `_ROOT_CAUSE_MAP`
- src/janissary/scope.py:29 — DNS-rebinding SSRF already named
- src/janissary/integrations/xmlrpc.py:344 — `detect()` pattern
- ADR-010, ADR-011 — auth detection (orthogonal)
- Session 0.3.14 recon — scanner surface analysis
