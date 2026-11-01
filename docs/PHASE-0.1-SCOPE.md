# Phase 0.1 Scope — the emission boundary

Recorded 2026-11-01 (session 12). Companion to `docs/ROADMAP.md` Phase 0.1.

## The invariant

**Every finding emitted into `ScanSummary.findings` is produced by
`VerificationEngine.verify()`.** The engine is the sole emitter of
verified scan findings.

## What this covers

All 13 emission sites in `src/janissary/engine/scanner.py` route through
`_ENGINE.verify(candidate)` → `_to_scan_finding(result)` → append. Each
finding carries `verification_status` and `verification_reason` set by
the engine, not by the emission site.

Rewired across commits `cd6ef31`..`f3dff72` (Phase 0.1 parts 4-12).

## What this does NOT cover (explicitly out of scope)

### Nuclei (`src/janissary/attack/nuclei.py`)

`NucleiRun.findings` is a separate container. Nuclei templates carry
their own verification semantics (matchers, extractors) that are not
Janissary's. No module in `src/` instantiates `NucleiRunner` — the
module is a library adapter, not part of the scan pipeline.

If nuclei is ever wired into `Scanner.scan()`, its findings must either
route through `VerificationEngine` as `CandidateFinding` (with
`verification_reason` like `nuclei:<template-id>`) or be reported under
a distinct output category that does not claim Janissary verification.

### WebSocket (`src/janissary/integrations/websocket.py`)

`WebSocketFinding` is a distinct type with distinct semantics. Per
`docs/ROADMAP.md` Phase 2.2, WebSocket verification is a protocol-specific
oracle that does not exist yet. `WebSocketProfile.findings` does not
flow into `ScanSummary.findings`.

### GraphQL (`src/janissary/integrations/graphql.py`)

GraphQL findings are emitted directly from the standalone
`janissary graphql` subcommand (`cli.py:cmd_graphql`), not routed
through `ScanSummary.findings`. The `integrations/graphql.py` module
implements introspection, depth probes, alias probes, argument
fuzzing, and batch detection — feature coverage is present. The
missing piece is integration: findings surface as raw recon output
rather than as `VerifiedFinding` objects subject to Phase 0.1's
boundary invariant and Phase 0.3's normalizer.

When GraphQL is wired into `Scanner.scan()` (Phase 2.1 proper), its
findings must:
1. Produce `CandidateFinding` objects with the schema path attached.
2. Route through `VerificationEngine.verify()` before entering
   `ScanSummary.findings`.
3. Use a `GraphQLNormalizer` (Phase 0.3 interface) to strip
   field-order variance and resolver-timing noise before delta
   comparison.

Tracked as FN-15 in `docs/PHASE-6-PLAN.md`.

### Store merge (`src/janissary/agent/agent.py`)

`store.extend(findings)` merges already-emitted findings into the
persistent store. It is not an emission site — it consumes findings
that were already routed through the engine.

## Consequence for the runtime invariant

The Phase 0.1 runtime assertion checks `ScanSummary.findings` only.
Nuclei, WebSocket, and store findings are not in that container and are
not asserted on. When Phase 2.2 adds WebSocket support, this document
must be updated and the assertion extended.