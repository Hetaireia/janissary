# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
