# ADR-008 — SARIF enterprise parity (Phase 0.3c)

**Status:** Accepted (2026-10-26)
**Depends on:** ADR-007 (finding identity, `partialFingerprints`)
**Blocks:** 0.3c-a (this ADR + module), 0.3c-b (wiring)

## Context

Phase 0.3b shipped `partialFingerprints.finding/v1` on every SARIF
result. That gives cross-run identity. The remaining SARIF output is
minimal:

- `ruleId` is a raw string like `sqli:db_error`. No `rules[]` array,
  so no `shortDescription`, no `helpUri`, no taxonomy tags.
- `level` collapses five severities into two SARIF levels
  (`error` / `warning`). SARIF 2.1.0 defines four.
- `properties.security-severity` is absent. GitHub Code Scanning
  reads this field -- not `level` -- to compute the Critical / High /
  Medium / Low badge it displays to reviewers.
- `taxonomies[]` is absent. No CWE classification anywhere in the
  output, despite every finding type being classifiable.
- `runs[].invocations[]` is absent. Orchestrators cannot detect scan
  health from the output alone.
- Every result uses `summary.target` for `artifactLocation.uri`. The
  per-finding `f.url` (which includes the payload) is more precise.

Concrete impact: uploading the current SARIF to GitHub Code Scanning
produces results that display with no severity badge, no CWE link,
no rule name. The fingerprint is correct but the surrounding shell
is not enterprise-grade.

## Decisions

### D1. Rule ID stability

Rule IDs stay `{category}:{finding_type}`. No churn to existing
consumers. Rule IDs already appear in emitted JSON (`ruleId`) and are
not being altered by this ADR.

### D2. Rule catalog module

New module `src/janissary/sarif_rules.py`. Pure: dataclass, helpers,
catalog dictionary, no I/O, no `cli.py` import. Directly testable
without running a scan.

Rationale: the wiring in `_write_sarif` becomes a mechanical
substitution once the catalog exists. Splitting the PR mirrors the
0.3a/0.3b split pattern that worked.

### D3. Catalog scope — scanner findings only

The catalog enumerates every `finding_type` the scanner emits as a
final finding after the `CORROBORATOR_ONLY_TYPES` filter. It does
not include agent-only categories (`admin`, `xmlrpc`, `graphql`,
`fingerprint`) because `agent.Finding` objects do not reach
`_write_sarif` today — `_write_sarif` takes a `ScanSummary`, which
carries only `ScanFinding` instances. If agent findings ever reach
SARIF, the fallback descriptor (D5) handles them until catalog
entries are added.

Corroborator types (`status_change`, `length_anomaly`,
`length_shrink`) are also not cataloged: `scanner.py` drops them
unconditionally before `ScanFinding` construction, so they never
appear in `summary.findings`.

### D4. CWE mapping

Standard OWASP/CWE classification, no project-specific judgment:

| Category | CWE | Justification |
|---|---|---|
| sqli | CWE-89 | SQL Injection |
| traversal | CWE-22 | Path Traversal |
| cmdi | CWE-78 | OS Command Injection |
| ldapi | CWE-90 | LDAP Injection |
| xpathi | CWE-643 | XPath Injection |
| xss | CWE-79 | Cross-site Scripting |
| trustbound | CWE-501 | Trust Boundary Violation |
| securecookie | CWE-614 | Cookie Missing Secure Attribute |
| weakrand | CWE-338 | Use of Cryptographically Weak PRNG |

No category is unmapped. Future categories will need entries added
here; the fallback path (D5) covers them until then.

### D5. Fallback for uncataloged pairs

`rule_for(category, finding_type)` returns a generic `RuleMeta` when
the pair is not in the catalog:

- `short_description` = humanized `finding_type`
  (`some_new_type` -> `Some New Type`)
- `cwes` = `()` (no tags)
- `default_severity` = `"medium"`

This keeps SARIF valid for any finding_type produced in future
phases without requiring a same-day catalog update. The result
renders with generic metadata, not with broken metadata.

### D6. Severity level mapping

SARIF 2.1.0 defines four levels: `error`, `warning`, `note`, `none`.

| Severity | SARIF level |
|---|---|
| critical | error |
| high | error |
| medium | warning |
| low | note |
| info | note |
| unknown | note |

We never emit `none` — that would suppress the finding from a
dashboard's default view, which is wrong for anything the scanner
actually produced.

Prior `_write_sarif` collapsed `low` and `info` into `warning`. This
ADR honors all four levels; `low` and `info` demote from `warning`
(which GitHub treats as a defect) to `note` (informational).

### D7. security-severity scores

CVSS-style 0.0–10.0 floats, chosen to align with GitHub Code
Scanning's tier boundaries:

| Severity | Score |
|---|---|
| critical | 9.5 |
| high | 7.5 |
| medium | 5.5 |
| low | 3.5 |
| info | 0.1 |
| unknown | 0.1 |

Emitted as a string with one decimal (`"9.5"`). The value lands in
both `rules[].properties.security-severity` (default per rule) and
`results[].properties.security-severity` (dynamic per result). When
a rule's results span multiple severities, the result-level value
overrides the rule-level default and GitHub honors the per-result
value.

### D8. Taxonomy

Emit one `taxonomies[]` entry for CWE, listing every CWE referenced
by the catalog. Component IDs are `cwe-NNN`. Over-listing CWEs not
referenced by any result in a given scan is harmless and keeps the
taxonomy stable across scans.

### D9. Invocations

Emit one `invocations[]` entry per run with `executionSuccessful`
(derived from `not summary.aborted`) and `properties` carrying
target, params, method, total requests, and finding count. On
aborted scans, include `toolExecutionNotifications[]` with the
abort reason so orchestrators can surface it.

### D10. Benchmark neutrality

`_write_sarif` is not on the benchmark scoring path.
`benchmark-gate.yml` scores the committed `findings.jsonl`
artifact against ground-truth vuln IDs — it never invokes SARIF
serialization. F1=0.921, FP=0 unchanged by construction.

### D11. 0.3c-a / 0.3c-b boundary

**0.3c-a (this ADR + module):**

- `src/janissary/sarif_rules.py` — catalog + helpers
- `tests/unit/test_sarif_rules.py` — unit tests
- No changes to `cli.py`, `scanner.py`, `finding_store.py`, or any
  existing file

**0.3c-b (wiring):**

- `cli._write_sarif` rewrite using the module
- `tests/integration/test_sarif_output.py` — full document shape,
  invocation metadata, rule dedup, fingerprint preservation

## Verification plan

0.3c-a:

- `sarif_level` returns correct level for all six severities
  (including unknown)
- `security_severity` returns correct float for all six severities
- `cwe_tag` format: `external/cwe/cwe-89` for CWE 89
- `rule_for` returns catalog entry for all 16 catalog pairs
- `rule_for` returns fallback for unknown pair, with humanized name
- `RuleMeta.to_sarif` shape: `id`, `shortDescription.text`,
  `helpUri`, `properties["security-severity"]` string with one
  decimal
- `RuleMeta.to_sarif` includes `properties["tags"]` when CWEs
  present, omits it when empty
- `rule_id` format: `{category}:{finding_type}`
- `all_rule_ids` returns unique, sorted IDs
- `cwe_taxonomy` includes expected CWEs (89, 22, 78, 79 among
  others) with correct `taxa` entries

0.3c-b (next):

- Full SARIF doc validates against 2.1.0 structural expectations
  (schema URI, version, runs array, tool driver with rules, results
  reference rules by index)
- Rule dedup: two findings with same `(category, finding_type)`
  share one rule entry, distinct `ruleIndex`
- `partialFingerprints` preserved on every result
- `artifactLocation.uri` = `f.url or summary.target`
- Invocations reflect `summary.aborted`, `total_requests`,
  `finding_count`

## Consequences

**Positive.**

- GitHub Code Scanning, Azure DevOps Code Analysis, and any
  SARIF-aware dashboard can display JANISSARY findings with
  severity badges, CWE links, and human-readable rule names.
- CWE classification makes findings legible to compliance
  workflows (SOC2 evidence, ISO 27001 mapping) without manual
  lookup.
- Per-result `security-severity` lets severity escalation in a
  finding (e.g. medium -> critical as more evidence accumulates)
  reflect correctly in dashboards, keyed by the stable
  fingerprint.
- Aborted scans communicate their state through SARIF metadata,
  not just exit codes — orchestrators can triage without parsing
  stderr.

**Neutral.**

- 0.3c-a is purely additive: new files only. No existing module,
  no existing test touched.
- Benchmark gate unaffected.

**Negative, minor.**

- `sarif_rules.py` becomes a maintenance surface: new finding
  types need catalog entries added. Mitigated by the fallback
  path — uncataloged types still emit valid SARIF, just with
  generic metadata.
- CWE mapping is opinionated on categories that could plausibly
  fit multiple CWEs (e.g. `trustbound` could be CWE-501 or
  CWE-384). The catalog picks one; if a future need demands
  multiple CWEs per rule, `cwes` is a tuple and supports it
  without schema change.

**Deferred.**

- Agent findings in SARIF (requires `_write_sarif` signature
  change from `ScanSummary` to accept either).
- Rule-level `help.markdown` for richer display (SARIF allows;
  no consumer demands it yet).
- Per-result `codeFlows[]` for exploit chains (out of scope for
  0.3c).

## Alternatives considered and rejected

- **Hard-code rule metadata inline in `_write_sarif`.** Rejected —
  untestable without running a scan; catalog drift invisible until
  upload.
- **Populate `rules[]` from distinct rule IDs observed in a scan.**
  Rejected as the sole source — results in `rules[]` that vary per
  scan, breaking dashboards that cache rule metadata across scans.
  The catalog is the fixed source of truth; the wiring emits the
  catalog entries for rules actually observed, keeping `rules[]`
  stable per unique rule while remaining scan-adaptive in
  membership.
- **Single `security-severity` per rule based on finding type.**
  Rejected — the same rule can produce findings at different
  severities across targets. Result-level override is correct.
- **Include agent categories (`admin`, `graphql`, etc.) in the
  catalog now.** Rejected — dead code until 0.3c-b or later wires
  agent findings to SARIF. Fallback path covers them if that
  happens.
- **Wait until wiring is done to write the ADR.** Rejected — ADRs
  that trail the code become descriptions, not decisions. The
  catalog is a decision surface (CWE choices, severity tiers,
  fallback semantics); lock it before the wiring consumes it.

## References

- ADR-007 — finding identity scheme (`partialFingerprints`).
- SARIF 2.1.0 spec — §3.19.2 (tool), §3.19.23 (rules),
  §3.20 (invocations), §3.27.10 (result.level),
  §3.27.17 (partialFingerprints), §3.19.3 (taxonomies).
- GitHub Code Scanning documentation — `security-severity`
  property, severity badge derivation.
- `engine/scanner.py:ScanFinding` — the finding shape whose fields
  the catalog and wiring consume.
- `cli.py:_write_sarif` — the wiring target (0.3c-b).
