# ADR-019 -- Triage output format (SARIF secondary run)

**Status:** Accepted (2026-11-04). Phase 0 Foundation.
**Supersedes:** None.
**Extends:** ADR-009 (agent findings in SARIF), ADR-016 (vocabulary), ADR-017 (emission model).
**Blocks:** M36a completion (ADR series 016-021); M40 (SARIF triage stream implementation).

## Context

ADR-017 established that Track B candidates carry
`verification_status="unproven"` and are distinguished from Track A
`"verified"` findings by that field alone. ADR-016 D3 committed to
SARIF routing by `verification_status`. Neither ADR specified the
concrete output shape.

Phase 1 deliverable M40 is "SARIF discovery triage stream." Without
a format decision, M40's implementation will be ad-hoc and possibly
incompatible with the GitHub code scanning upload that M20 built. CI
consumers need a stable shape. Enterprise integrators need to know
what to filter on. This ADR locks the shape.

## Decisions

### D1. Single SARIF 2.1.0 file per scan, two runs

One scan produces one SARIF file. That file contains two entries in
the `runs[]` array:

- `runs[0]` -- verified findings. `properties.track = "verified"`.
  Consumers who only want CI-blocking results read this run.
- `runs[1]` -- discovery candidates. `properties.track = "discovery"`.
  Consumers who want the triage queue read this run.

If a scan has zero findings in one track, the corresponding run is
still emitted with an empty `results: []` array. Presence of the run
is a stable contract; only its `results` array varies.

Rationale: SARIF 2.1.0's `runs[]` array is exactly designed for this.
The alternative (two separate files) breaks the "one artifact per
scan" convention that M19 and M20 established, doubles the upload
surface for GitHub code scanning, and complicates the Ascension
dashboard's run directory structure.

### D2. Every result carries `partialFingerprints` for stable dedup

Each finding's `results[i].partialFingerprints` contains:

- `finding/v1` -- the stable identity (from ADR-007)
- `verification_status/v1` -- `"verified"` or `"unproven"`

The second fingerprint allows cross-run tracking of a finding that
started as a candidate (unproven) and later became verified (via
rescan or engine promotion). Without it, a triage reviewer who sees
"candidate #42" in run N cannot correlate to "verified #7" in run N+1.

Rationale: ADR-007 already established stable identity per finding.
The verification_status field is stable per finding *version* -- if
the finding is reclassified from unproven to verified, that is a
state transition that partial fingerprints should track. GitHub code
scanning uses partialFingerprints for exactly this ("same finding,
new state").

### D3. `properties.signals` carries the heuristic signature IDs

For `runs[1]` (discovery) results, each `result.properties.signals`
lists the heuristic signature IDs that matched:

    "properties": {
        "signals": ["HEUR-001", "HEUR-014"],
        "track": "discovery"
    }

For `runs[0]` (verified) results, `properties.signals` is present but
may be empty `[]`. Track A does not currently use signature IDs; the
field is present for schema consistency and future use.

Rationale: ADR-017 D5 established `signals: list[str]` on
`ScanFinding` for Track B. The SARIF schema already permits arbitrary
`properties` objects. This maps cleanly.

### D4. CI consumers filter by `properties.track`, not by filename

Any CI job that wants "block the build on verified findings only"
reads `janissary.sarif`, filters to `runs[i].properties.track ==
"verified"`, and processes results from that run. A job that wants
"show the triage queue in a comment" filters to `properties.track ==
"discovery"`.

This is documented in a new `docs/CI-INTEGRATION.md` (deferred to
M40 implementation, not part of this ADR). The ADR only commits to
the SARIF shape. Documentation follows when M40 ships.

### D5. Backwards compatibility with M19/M20 (v7.10.x)

Today, `janissary scan --export results.sarif` produces a single-run
SARIF file: `runs: [run_0]` with no `properties.track`. That is the
pre-ADR-019 shape.

When M40 ships, the shape changes to two runs with `properties.track`
on each. This is a schema-additive change -- SARIF validators that
accept single-run files also accept multi-run files. But existing
consumers (the M20 self-scan workflow) treat `runs[0]` as "all
findings." After M40, `runs[0]` is "verified only."

**Migration path:** for one release cycle (M40's version), we emit:

- If `verification_status` is used anywhere in the run: emit
  two-run shape (`verified`, `discovery`)
- If all findings are `verified` (current state, before Track B
  ships): emit single-run shape (`verified`) to preserve M20's
  behavior

After M38 ships (Track B exists), all scans emit two-run shape,
because Track B is always available (even if empty). This is the
"honest migration" pattern from ADR-009 D10 (SARIF export for agent
findings).

## Consequences

**Positive:**
- M40's implementation is unblocked: the shape is specified
- GitHub code scanning compatibility preserved (single file, runs array)
- Cross-run state transitions are trackable (partialFingerprints)
- Future Track C (if ever) adds `runs[2]` without breaking A or B
- Consumers do not need per-scanner configuration: filter on
  `properties.track` and you are done

**Negative:**
- The two-run shape is more complex than one-run for simple
  consumers. Mitigation: `docs/CI-INTEGRATION.md` (M40) shows
  copy-paste examples for both "block on verified" and "show triage
  queue" workflows.
- Migration from M20's single-run shape to M40's two-run shape is a
  behavior change for the self-scan workflow. Mitigation: D5's
  conditional emission defers the change until Track B exists.

**Neutral:**
- No code changes ship with this ADR. M40 implements the pattern.
- The SARIF `category` field (used by github/codeql-action/upload-sarif)
  is not affected: same upload, same category, richer content.

## Alternatives rejected

**Option A: Two separate files (`verified.sarif`, `discovery.sarif`).**
Rejected because it breaks the one-artifact-per-scan convention that
M19 and M20 established, doubles upload volume for code scanning,
and complicates the Ascension dashboard run directory structure
(which expects one SARIF per run).

**Option B: Single SARIF run with mixed `verification_status` values
and `properties.track` per result (not per run).**
Rejected because SARIF `properties` on individual results does not
support the level of filtering that CI consumers need. The
`runs[i].properties.track` shape allows consumers to ignore an entire
run (cheap), vs per-result filtering (requires processing the full
results array).

**Option C: Non-SARIF format for the discovery stream (e.g., JSONL
triage queue).**
Rejected because it breaks the "one export format per scan" pattern
that --export has established. If a user wants JSONL, they can use
--jsonl (per ADR-008). If they want SARIF, they get SARIF. Mixed
formats in one scan is a config explosion.

**Option D: Repurpose the existing `unproven` label as a non-`kind`
SARIF property.**
Rejected because `properties.track` is more specific than
`properties.kind`. GitHub code scanning uses `kind` for
`pass`/`fail`/`review`/`open`/`informational`; overloading it for
`verified`/`discovery` would confuse the CI filters that already use
`kind` for their semantics.

## References

- `docs/FUTURE-STATE-PLAN.md` Part 3 Phase 1 (M37-M40)
- ADR-007 -- finding identity scheme (partialFingerprints base)
- ADR-008 -- SARIF schema (JSONL alternative)
- ADR-009 -- SARIF export for agent findings (D10 migration pattern)
- ADR-016 -- Verified vs Discovery vocabulary (D3 mapping table)
- ADR-017 -- Heuristic emission model (D5: signals field)
- `src/janissary/cli.py` -- `_write_sarif()`, `_render_sarif()`
- `.github/workflows/janissary-selfscan.yml` -- M20 consumer (needs
  update when M40 ships, per D5)