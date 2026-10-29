# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [7.6.0] - 2026-10-30

Phase 4 completion. Closes all three FNs from the track C baseline (dvwa, bwapp).

### Added
- **LFI content oracle** (`src/janissary/detection/lfi_oracle.py`) - detects in-page
  file-content injection via passwd/shadow/hosts/win.ini/group signature matching.
  Fires when a payload response contains a known-file signature absent from every
  baseline snapshot. Closes FN-3 (bwapp `/directory_traversal_1.php`).
- **Blind SQLi paired oracle** (`src/janissary/detection/blind_sqli_oracle.py`) -
  paired TRUE/FALSE payload detection (`1' OR '1'='1` vs `1' AND '1'='2`). Status
  code delta is authoritative; length delta is gated on no-reflection. Closes FN-1
  (dvwa `/vulnerabilities/sqli_blind/`).
- **Deep + absolute traversal payloads** - `traversal_passwd_deep`
  (`../../../../../etc/passwd`) and `traversal_passwd_abs` (`/etc/passwd`) added to
  `DEFAULT_PAYLOADS`. The original 3-deep payloads work on bWAPP (2 segments) but
  cannot reach `/etc/passwd` from DVWA (5 segments). Closes FN-2
  (dvwa `/vulnerabilities/fi/`).
- 14 new unit tests (5 LFI oracle, 9 blind SQLi oracle). Total unit suite: 550.

### Measurement
Track C corpus: **tp=8 fp=0 fn=0 tn=21 recall=1.0 precision=1.0 f1=1.0** across
6 apps. Previously tp=5 fn=3 recall=0.625 f1=0.7692. Precision maintained at 1.0;
zero false positives across all 21 safe trials.

### Notes
- `PHASE-4-PLAN.md` corrected: FN-1 was misdiagnosed as "temporal oracle needed"
  (actually status-code delta); FN-2 as "oracle too narrow" (actually payload-depth
  gap). FN-3 classification was correct.
- SSRF detection (7.5.0) unchanged.


## [7.5.0] - 2026-10-28

### Added

- **SSRF detection via Burp-compatible collaborator** (ADR-012). `janissary scan --collaborator <URL>` enables out-of-band Server-Side Request Forgery detection: five OOB-detectable payloads (http, https, gopher, dict, dns_only) are sent per parameter after the differential payload loop, and hits from the collaborator are reported as findings. Compatible with Burp Pro, interactsh, and ProjectDiscovery interact.sh through the standard poll protocol. Unique subdomain per payload (`jns-<16hex>`) gives deterministic attribution.
- **New finding categories**: `ssrf:collaborator_hit` (CWE-918, critical) for HTTP/HTTPS fetches by the target, and `ssrf:dns_only_resolution` (CWE-918, info) for DNS-only resolutions that did not establish TCP. The DNS-only class is visible with `--verbose`; it indicates a target that resolves arbitrary hostnames but does not fully SSRF.
- **New CLI flags on `scan`**: `--collaborator URL` (Burp-compatible poll endpoint) and `--ssrf-timeout N` (outer wait, default 10s).
- **New module** `src/janissary/integrations/collaborator.py` exposes `CollaboratorClient`, `CollaboratorError`, `SsrfHit`, `SsrfPayload`, and `SSRF_PAYLOADS`.

### Changed

- `Scanner.__init__` accepts `collaborator` and `ssrf_timeout` kwargs. Both default to no-collaborator / 10.0, so existing callers see no behavior change.
- `Scanner.scan` runs `_ssrf_phase` at the end of each parameter's payload loop only when a collaborator is configured. Zero additional requests when the flag is absent.

### Notes

- Test count: 611 → 619 (+8, four client primitives in `tests/unit/test_ssrf.py` and four scanner-integration tests).
- Benchmark neutral by construction: OWASP Benchmark has zero SSRF cases and the benchmark harness passes no `--collaborator`, so `_ssrf_phase` is a no-op on the scoring path. F1=0.921, FP=0 unchanged from 7.4.0. Verified by `test_scanner_ssrf_no_collaborator_no_ssrf_findings`.
- Scope delta from ADR-012 D2: the design listed 8 payloads; three (`metadata_http`, `metadata_v6`, `file`) cannot be detected via collaborator OOB and require response-body inspection. They are deferred to a follow-up response-body detection path. The five shipped (http, https, gopher, dict, dns_only) cover the standard blind-SSRF case that is the majority of modern bug-bounty findings.
- No breaking changes. All new behavior is opt-in via `--collaborator`.

## [7.4.0] - 2026-10-27

### Added

- **SARIF 2.1.0 export for agent findings** (ADR-009). `janissary agent --export *.sarif` now emits SARIF with catalog-driven rules, CWE taxonomy, cross-run partialFingerprints, and invocation metadata that distinguishes single-target from multi-target runs.
- **Mid-scan auth expiry detection, direct-scan path** (ADR-010). Scans with `--cookie` or `--bearer` now abort with exit code 2 when two consecutive HTTP 401 responses arrive during the payload loop. Findings collected before the abort are preserved. `abort_reason` names the threshold, param, and last payload attempted.
- **Mid-scan auth expiry detection, agent path** (ADR-011). `cmd_agent` no longer monkey-patches `requests.Session.__init__`; session is threaded explicitly through `Agent.__init__`, adapter context, and all four recon targets (`probe_admin`, `xmlrpc.detect`, `graphql.detect`, `fingerprint`). Response-hook 401 counter with threshold=2, matching the scanner path.

### Changed

- Ruff version pinned to `==0.16.9` in `pyproject.toml` dev extras; `[tool.ruff]` `required-version = "==0.16.9"` enforces it at runtime. Version drift between local and CI is now impossible.
- Pre-commit stage names migrated to current identifiers (`pre-commit`, `pre-push`). The six deprecation warnings per gate run are gone.
- ADR-007 D5 legacy-store silent-dedupe behavior now has explicit test coverage (4 tests in `test_finding_store.py`).

### Fixed

- L4 comment in `.pre-commit-config.yaml` referenced a `--hook-stage push` value that pre-commit 4.7.0 does not accept. Corrected to `pre-push`.

### Notes

- Test count: 586 → 611 (+25 new tests across the arc).
- Benchmark: F1=0.921, FP=0 on the OWASP Benchmark r1+rec artifact, unchanged from 7.3.0. All arc changes are non-scoring-path by construction (SARIF serialization, CLI wiring, dependency pin, config, tests, agent auth threading).
- No breaking changes. All new behavior is opt-in (`auth_configured=False` default on both `Scanner` and `Agent`; SARIF export triggered by file extension; other extensions keep the JSON exporter).

## [7.3.0] - 2026-10-22

### Changed

- Code freeze. Functionally complete; frozen at 7.3.0 to prevent regressions.

### Added

- `release/` templates and stepwise GitHub Release automation.

### Notes

- No scored benchmark claim in this release. Methodology is in `BENCHMARK.md`;
  scored results and run artifacts will be published separately once committed
  to `benchmark/track_a/runs/`.

## [7.2.0] - 2026-09-28

### Added

- `--json` and `--jsonl` flags on `scan` and `agent`: machine-readable
  output on stdout, human status on stderr. Findings include
  `raw_request` and `raw_response` as raw HTTP/1.1 for Burp Repeater.
- `--scope-include` and `--scope-exclude` on `scan`, `agent`, and both
  `attack` subcommands: contractual scope enforcement with hard refusal
  (exit 64) before any network I/O. Supports exact hostnames, wildcards,
  CIDR (v4 and v6), path prefixes, and full URL prefixes.
- `--cookie`, `--bearer`, and `--redact-auth` on `scan` and `agent`:
  static auth applied to every request in the scan. `--redact-auth`
  masks Authorization/Cookie header values in JSON/JSONL output for
  safe sharing, while leaving bodies untouched.
- `src/janissary/output/` package: schema v1.0, emitter, and raw HTTP
  serialization helpers.
- `src/janissary/scope.py`: scope policy engine.
- `src/janissary/auth.py`: static auth helpers.
- 38 new unit tests across scope, auth, and output modules.

### Fixed

- Aborted scans under `--quiet` previously returned exit code 2 with an
  empty stderr. Abort reasons now always reach stderr, regardless of
  `--quiet`, so scripted pipelines can see why a scan died.

## [7.1.0] - 2026-09-25

### Added
- Differential detection engine (replaces keyword matching)
- Baseline normalization for CSRF tokens, timestamps, UUIDs, session IDs
- DB-specific error patterns for MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- 28 unit tests covering all false-positive gates
- 91% test coverage on the detection analyzer
- Apache 2.0 license
- Editable install via pyproject.toml with console entry point

### Changed
- DB error detection now requires database-specific patterns, not generic keywords
- Timing detection requires a variable baseline with std >= 0.05s
- Reflection detection requires executable context for XSS severity
- Status detection requires baseline to be 2xx and payload to be 5xx

### Removed
- Generic ERROR_KEYWORDS list (source of 80% of false positives)

## [7.0.0] - 2026-09-24

### Added
- Initial prototype release
