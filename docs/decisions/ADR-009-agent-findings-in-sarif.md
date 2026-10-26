# ADR-009 — Agent findings in SARIF (Phase 0.3.6)

**Status:** Proposed (2026-10-27)
**Depends on:** ADR-007 (finding identity, `partialFingerprints`),
ADR-008 (SARIF enterprise parity, catalog and rendering)
**Supersedes:** ADR-008 D3 only (catalog scope: "scanner findings
only")
**Blocks:** 0.3.6 (this ADR + implementation)

## Context

ADR-008 shipped SARIF output for scanner findings. `_write_sarif`
takes a `ScanSummary` and renders an enterprise-grade SARIF document:
catalog-driven `rules[]`, per-result `security-severity`, CWE
taxonomy, invocations, `partialFingerprints`.

Agent-driven scans produce `list[agent.Finding]` objects. These are
orchestrator-facing artefacts — the scenario where an enterprise
wraps JANISSARY into a pipeline and consumes findings from an
agent run rather than a direct scan. Today, those findings can only
be exported as JSON. They cannot be uploaded to GitHub Code
Scanning, Azure DevOps Code Analysis, or any SARIF-aware dashboard.

ADR-008 D3 explicitly scoped the catalog to scanner findings:

> It does not include agent-only categories (`admin`, `xmlrpc`,
> `graphql`, `fingerprint`) because `agent.Finding` objects do not
> reach `_write_sarif` today … If agent findings ever reach SARIF,
> the fallback descriptor (D5) handles them until catalog entries
> are added.

That "if" is now "when". This ADR extends the SARIF surface to
accept `list[agent.Finding]` without disturbing the scan path.

## Decisions

### D1. Single `_write_sarif` with union type

`_write_sarif(source: ScanSummary | list[agent.Finding], path: str)`
— one entry point, runtime dispatch. Rationale: the handover's
Option 3 specifies this shape. Sibling functions
(`_write_sarif_summary` / `_write_sarif_findings`) would push
bookkeeping onto callers who already know which form they hold.

Dispatch is a `isinstance(source, ScanSummary)` check. `ScanSummary`
is a dataclass; a `list` of `Finding` is unambiguously not a
`ScanSummary`. No ambiguity, no duck-typing risk. An empty list is
dispatched to the agent path (valid SARIF, empty results) — which
is the correct reading, since a scan that produced no findings still
has a `ScanSummary` with `.findings == []`.

### D2. Internal normalization

Refactor the existing `_write_sarif` body into two pieces:

- `_from_scan_summary(summary: ScanSummary) -> _SarifRunInput`
- `_from_agent_findings(findings: list[Finding]) -> _SarifRunInput`
- `_render_sarif(input: _SarifRunInput, path: str) -> None`

`_SarifRunInput` is a small dataclass holding the pre-rendered
pieces: results (list of dicts), rules (deduped), invocations (one
entry), taxonomies (one entry), run_properties.

Rationale: the SARIF document structure is identical regardless of
input source. Extract that shape once, then render. Without
normalization, the agent path would duplicate rules-dedup, taxonomy
emission, and file-write logic — three places to drift instead of
one.

### D3. Agent target semantics

For `_from_agent_findings`, invocation `properties` carries:

- All findings share one `target` → `properties.target = <that>`,
  `properties.targets` absent.
- Findings span multiple targets → `properties.target = null`,
  `properties.targets = <sorted unique list>`.
- No findings → neither `target` nor `targets` emitted.

Per-result `artifactLocation.uri = f.target` for every finding.
Rationale: agent findings never carry an injected payload — `target`
is the base URL. No `f.url or summary.target` fallback is needed;
each finding owns its location.

`method` and `params` are omitted from invocation properties on the
agent path. They are scan-only concepts; emitting empty strings or
empty lists would be misleading.

### D4. Field mapping (Finding -> SARIF result)

- `category` + `finding_type` -> `ruleId = "{category}:{finding_type}"`
- `severity` -> `level` (via `sarif_level`) and
  `properties["security-severity"]` (via `security_severity`)
- `detail` (or rule short description if empty) -> `message.text`
- `target` -> `locations[0].physicalLocation.artifactLocation.uri`
- `fingerprint` -> `partialFingerprints["finding/v1"]`
- `response_status` -> `properties["response-status"]` (when non-null)
- `payload` -> `properties["attack-payload"]` (when non-empty)
- `discriminator` -> `properties["discriminator"]` (when non-empty)
- `recorded_at` -> `properties["recorded-at"]`
- `extra` (dict) -> merged into `properties`, reserved keys win (D6)

Rule metadata (shortDescription, helpUri, CWE tags, default
security-severity) comes from `rule_for(category, finding_type)`,
identical to the scan path. No new catalog entries required — the
fallback descriptor handles agent-only categories until entries are
added, per ADR-008 D5.

### D5. Rules set derivation

Rules emitted = union of `(category, finding_type)` across all
findings, deduped by `ruleId`, ordered deterministically (sort by
`ruleId`). Each `RuleMeta.to_sarif()` produces the rule descriptor.
Same dedup contract as the scan path (ADR-008 verification plan).

### D6. Property precedence — reserved keys win

`Finding.extra` may contain arbitrary user metadata. When `extra`
contains a key that overlaps a SARIF-reserved computed property
(`security-severity`, `ruleId`, `level`, `partialFingerprints`,
`tags`), the computed value wins. No override.

Rationale: `security-severity` is derived from `severity`. If
`extra` could override it, an unscrupulous or malformed finding
could falsify its dashboard severity. The reserved set is computed,
not user-supplied.

### D7. Fingerprint preservation

`Finding.fingerprint` is computed in `__post_init__` via
`finding_identity.compute_fingerprint` and already carries the
`jfv1:` prefix (ADR-007 D3). Emit unchanged as
`partialFingerprints["finding/v1"]`. No re-computation. This
preserves ADR-007 D7 stability across agent findings.

### D8. Empty findings

`_from_agent_findings([])` returns a `_SarifRunInput` with
`results=[]`, `rules=[]`, one invocation with
`executionSuccessful=True` and `properties.findingCount=0`.
Schema-valid. Same shape contract as the empty-`ScanSummary` case
already tested in `test_sarif_empty_findings_still_schema_valid`.

### D9. Test strategy — extend, don't duplicate

Extend `tests/integration/test_sarif_schema.py` with agent-path
cases. No new fixtures — reuse the vendored OASIS schema and the
existing `_assert_schema_valid` helper.

New test cases:

- `test_write_sarif_agent_findings_validates_against_schema`
- `test_write_sarif_agent_empty_findings_validates`
- `test_write_sarif_agent_single_target_invocation_metadata`
- `test_write_sarif_agent_multi_target_invocation_metadata`
- `test_write_sarif_agent_fingerprint_preserved`
- `test_write_sarif_agent_extra_property_collision_reserved_wins`
- `test_write_sarif_scan_summary_backwards_compatible`

No unit tests for `_from_agent_findings` in isolation. The function
is pure and its entire behaviour is observed through the SARIF
document; testing it indirectly through the schema-validated
integration test is cleaner than two test files.

### D10. CLI wiring

Agent command, when `--export <path>` is set and the export format
resolves to SARIF (via extension `.sarif` / `.sarif.json`, matching
existing scan-path convention), calls
`_write_sarif(list_of_findings, path)` instead of the JSON exporter.
Exact call site identified during implementation by reading the
existing agent command body. No new CLI flags, no new subcommands.

### D11. Benchmark neutrality

The agent SARIF path is not on the benchmark scoring path.
`benchmark-gate.yml` scores the committed `findings.jsonl` artefact
against ground-truth vuln IDs — it never invokes `_write_sarif`.
F1=0.921, FP=0 unchanged by construction. Same acceptance gate as
ADR-008 D10.

### D12. One PR, not split

ADR-007 and ADR-008 used two-PR splits (0.3a/0.3b, 0.3c-a/0.3c-b)
because each introduced a substantial standalone module before
wiring. ADR-009's surface is one function refactor, one new helper,
one call site, and test extensions. No standalone module to land
independently. Split would be artificial.

## Consequences

**Positive.**

- Agent-orchestrated scans reach SARIF parity with direct scans.
- Single source of truth for SARIF rendering across both paths.
- `Finding.fingerprint` preserved verbatim — no identity drift.

**Neutral.**

- `ScanSummary` path unchanged. Refactor is internal to `cli.py`.
- No new fixtures, no new dependencies.

**Negative, minor.**

- `_write_sarif` gains a runtime `isinstance` dispatch; failures
  for unsupported types are `TypeError` at call time, not import
  time. Mitigated by union type annotation.
- Agent findings for categories not in the catalog render with
  fallback descriptor (generic description, no CWE tags). Documented
  in ADR-008 D5.

**Deferred.**

- Catalog entries for agent-only categories.
- Rule-level `help.markdown`.
- Per-result `codeFlows[]`.

## Alternatives considered and rejected

- **Sibling `_write_sarif_summary` / `_write_sarif_findings`** —
  rejected: the handover names the union signature as the
  requirement. Pushes dispatch to callers who already know.
- **Separate `src/janissary/sarif_agent.py` module** — rejected:
  shared rendering logic (taxonomies, invocation emission, file
  write, rules dedup) would be duplicated.
- **Duck typing instead of `isinstance`** — rejected:
  unambiguous; no probing of `.findings` attribute.
- **Synthesise fake `ScanSummary` from findings** — rejected:
  `ScanSummary` carries fields agent findings do not have (`params`,
  `method`, `baselines`, `waf`, `pacer`). Faking them corrupts
  invocation metadata.
- **Deduplicate inside `_from_agent_findings`** — rejected:
  `FindingStore.add()` already deduplicates by fingerprint. Shadowing
  that policy would make SARIF diverge from store contents.
- **Merge into ADR-008** — rejected: ADR-008 scoped itself
  explicitly to scanner findings. ADR-009 supersedes D3 only, not
  the whole ADR.

## References

- ADR-007 — finding identity (`partialFingerprints.finding/v1`).
- ADR-008 — SARIF enterprise parity. Superseded on D3 only.
- SARIF 2.1.0 spec §3.27.10, §3.27.17, §3.20, §3.19.23.
- `src/janissary/cli.py:_write_sarif` — refactor target.
- `src/janissary/sarif_rules.py` — unchanged. `rule_for` reused.
- `src/janissary/agent/finding_store.py:Finding` — input shape.
- `src/janissary/engine/scanner.py:ScanSummary` — existing shape.
- `tests/integration/test_sarif_schema.py` — extended.
- handover session-0.3.5 NEXT-SCOPE MENU item 2 — Option 3 scope.