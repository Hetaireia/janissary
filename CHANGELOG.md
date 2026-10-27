# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
