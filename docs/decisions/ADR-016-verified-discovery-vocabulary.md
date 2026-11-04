# ADR-016 -- Verified vs Discovery engine vocabulary

**Status:** Accepted (2026-11-04). Phase 0 Foundation.
**Supersedes:** None. **Blocks:** M36a completion (ADR series 016-021).
**Extends:** ADR-001 (sole-emitter invariant), ADR-009 (SARIF output).

## Context

The FUTURE-STATE-PLAN.md (Part 2, Decision 4) formalizes a dual-path
acquisition model: a deterministic Verified path for every finding the
tool can prove by baseline differential, and a heuristic Discovery path
for candidates that warrant triage but lack verification. The uploaded
roadmap referred to these as "Track A" and "Track B."

That terminology is correct internally (it maps to the phase structure,
ADRs, and file names) but is user-hostile. A security engineer running
JANISSARY for the first time sees neither "Track A" nor "Track B" in
the human output -- they see findings and (optionally) triage candidates.

Two vocabularies must coexist:

1. **Internal** (ADRs, code, commit messages, sprint notes): Track A / Track B
2. **External** (README, --help, human output, SARIF output, UI, docs): Verified / Discovery

The naming mismatch is not merely cosmetic. Every subsequent ADR in the
Phase 0 series (017-021) will reference the two paths. Locking
vocabulary now prevents drift. If we say "Track A" in the README next
month and "Verified Engine" in an ADR, users and maintainers lose the
thread.

## Decisions

### D1. Internal vocabulary: Track A / Track B

Wherever code, ADRs, or engineering notes reference the acquisition
paths, use:

- **Track A** -- deterministic acquisition + verification, gated by
  `_ENGINE.verify()` (ADR-001). Emits `ScanFinding` with
  `verification_status="verified"`.
- **Track B** -- heuristic acquisition, does not emit `ScanFinding`.
  Returns `CandidateFinding` that either routes to the triage stream
  or is promoted by `_ENGINE.verify()` if it happens to pass a
  differential gate.

Rationale: "A" and "B" are neutral, ordering-agnostic, and survive
future renames. They appear in the upstream roadmap, so they are the
continuity term.

### D2. External vocabulary: Verified Engine / Discovery Engine

Wherever user-facing surfaces reference the paths, use:

- **Verified Engine** -- what produces the findings you can trust.
  Precision claim 1.000 applies here only.
- **Discovery Engine** -- what produces triage candidates. Precision
  claim does not apply; candidates are labeled and tracked separately.

Rationale: "Verified" and "Discovery" describe what the user sees,
what the SARIF output routes to, and what the CLI flags toggle. They
map to the plan's "verified findings vs discovery candidates" language
in Decision 4 and to the M16 `unproven` marker.

### D3. Mapping table (canonical)

| Surface | Internal name | External name | Code module |
|---|---|---|---|
| Engine | Track A | Verified Engine | `engine/scanner.py::Scanner`, `verification/` |
| Engine | Track B | Discovery Engine | `heuristic/` (to be created in M37) |
| Output | Track A findings | Verified findings | `ScanFinding` with `verification_status="verified"` |
| Output | Track B candidates | Discovery candidates | `CandidateFinding` (new), marked `unproven` |
| CLI | (internal only) | `--discovery` (flag, off by default) | `cli.py` |
| SARIF run 1 | Track A | Verified (default run) | `_write_sarif()` existing behavior |
| SARIF run 2 | Track B | Discovery (secondary run) | `properties.track: "discovery"` |

### D4. ADR series contract

ADRs 017-024 use this vocabulary. Specifically:

- ADR-017 (heuristic emission model) uses "Track B returns
  `CandidateFinding`, never `ScanFinding`"
- ADR-019 (triage queue output) uses "SARIF secondary run tagged
  `properties.track: discovery`"
- ADR-022 (tri-session auth) uses "Track A verification extended to
  three sessions"

Any future ADR that introduces a third acquisition path (crawler,
fuzzer, plugin) must return `CandidateFinding` and enter through the
same `_ENGINE.verify()` boundary. There is no "Track C" that emits
directly.

## Consequences

**Positive:**
- Single vocabulary per audience -- engineering sees A/B, users see
  Verified/Discovery
- Every future ADR has a canonical mapping table to cite (D3)
- The "1.000 precision" claim survives because Track B cannot emit
  `ScanFinding` by contract; D2 makes this explicit in the vocabulary
- SARIF routing (M19 already emits `unproven`) extends naturally to
  a second run tagged `discovery`

**Negative:**
- Two vocabularies require maintainer discipline to keep in sync
- New contributors will need a one-paragraph orientation (this ADR)
- "Track A" is meaningless to users; a first-time reader of an ADR
  who has not read the plan will wonder why not just "Verified"

**Neutral:**
- No code changes required by this ADR alone
- M39 (SSRF metadata payloads) just shipped: those are Track A
  (deterministic, emit `ScanFinding`) even though they are "metadata"
  payloads. They are not discovery candidates. The distinction is
  about verification, not about payload novelty.

## Alternatives rejected

**Option A: One vocabulary throughout (Verified/Discovery everywhere).**
Rejected because ADRs and code comments would need a search-replace
that breaks history and grep-ability. "Track A" is the term the
upstream roadmap uses, so it survives; better to accept the split.

**Option B: "Track A"/"Track B" everywhere including user output.**
Rejected because security engineers will ask "where is Track C?" --
the letters imply there should be more, which invites scope creep.

**Option C: Named engines like "Precision" and "Recal".** Rejected
because "Recal" reads as a typo, "Precision" collides with the metric
name, and neither survives the "what does this tool do?" one-liner test.

## References

- `docs/FUTURE-STATE-PLAN.md` Part 2 Decision 4
- `docs/FUTURE-STATE-PLAN.md` Part 3 Phase 0 (ADR series 016-021)
- ADR-001 -- verification engine sole-emitter invariant
- ADR-009 -- agent findings in SARIF
- ADR-012 -- SSRF (M39 payloads live under Track A verification)
- `src/janissary/engine/scanner.py` -- Track A reference implementation
- `tests/unit/test_cli_unproven_display.py` -- M16 unproven marker