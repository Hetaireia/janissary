# ADR-014 — gRPC/Protobuf dependency selection (FN-17)

**Status:** Accepted (2026-11-03) - Option 1 (grpcio + google.protobuf).
Accepted as policy for FN-17 when implemented; `pyproject.toml` is
unchanged. A future reversal requires ADR-015 superseding this one.
**Depends on:** nothing — this decision is a precondition for FN-17, not a consequence of any prior ADR
**Blocks:** FN-17 (Phase 2.3) implementation. Named as a precondition at
`PHASE-6-PLAN.md:882-883`: *"The infrastructure decision (Protobuf
dependency) should be made explicitly before code work begins."*
**Does not commit to:** implementing FN-17. Acceptance means "when FN-17
implementation begins, use this dependency set." `pyproject.toml` is
unchanged by acceptance. If FN-17 is never scheduled, this ADR is a
documented answer to a question no one yet asked — harmless.

## Context

`PHASE-6-PLAN.md:803-920` files FN-17 as a greenfield build gap:

- `src/janissary/integrations/grpc.py` does not exist
- `tests/unit/test_grpc.py` does not exist
- Zero code-level references to `grpc`, `protobuf`, or `proto3` in
  `src/` (AST-verified 2026-11-03; the one textual hit at
  `protocols/base.py:16` is a docstring describing the
  protocol-agnostic `NormalizedResponse.body` field)
- `pyproject.toml` carries five runtime dependencies
  (`requests`, `websockets`, `defusedxml`, `selectolax`, `mmh3`) —
  none touch Protobuf

The roadmap (`docs/ROADMAP.md:75-77`) says Phase 2.3 is:

> **2.3** gRPC: reflection-based discovery; Protobuf-level oracle. If
> reflection unavailable, report `grpc_reflection_unavailable` and
> emit zero — never fall back to HTTP-level guessing.

The plan expands this into a four-piece scope (gRPCDiscoveryModule,
baseline_message(), fuzz_field(), verification oracle) at
`PHASE-6-PLAN.md:823-838`; that expansion is the project's operational
reading of the roadmap bullet, not the roadmap's text. The plan's
heading at line 823 calls the expansion "unmodified" — it is a more
detailed reading, not an unmodified quote.

The plan (`PHASE-6-PLAN.md:862-872`) names two structural concerns:

1. **Binary protocol infrastructure.** Protobuf requires encode/decode
   tooling. This ADR answers which tooling, if any.
2. **Reflection gating.** Non-reflecting servers are unserviceable by
   design — the roadmap forbids HTTP-level fallback because guessing
   at binary framing produces decode errors or false positives.

The dependency question — which library provides the Protobuf
encode/decode layer and the gRPC transport — is what this ADR decides.
It is a *decision*, not an implementation; FN-17 remains unscheduled.

## Options

### Option 1: `grpcio` + `google.protobuf`

Official gRPC implementation for Python. `grpcio` provides the HTTP/2
transport and gRPC protocol layer; `google.protobuf` provides the wire
runtime; `grpcio-tools` compiles `.proto` files to Python at build
time.

**Pros:** the boring correct choice; extensively documented; handles
real-world servers, streaming, and edge cases; maintained by Google;
most likely to "just work" on arbitrary deployments. When gRPC support
fires at all, the project's precision positioning depends on it firing
*correctly* — the failure mode here is silent false negatives on real
servers.

**Cons:** native-compiled wheel per platform (~20 MB compressed,
larger uncompressed); install-time `protoc` toolchain if using
`grpcio-tools`; a substantial footprint added to a project whose
current five runtime deps are all small. Native wheels are the kind of
thing that fails on unusual CI runners, Alpine containers, or
cross-platform builds.

### Option 2: `betterproto` + `grpclib`

Pure-Python alternative. `betterproto` generates dataclass-based
Protobuf encoders/decoders; `grpclib` provides the HTTP/2 transport
layer.

**Pros:** pure Python — no native compilation; smaller install;
dataclass-native output is more idiomatic to this codebase's style
(`@dataclass(frozen=True)` used throughout `protocols/`).

**Cons:** less mature than `grpcio` (in beta at time of writing);
smaller community; some edge cases — bidirectional streaming, unusual
field types, map fields, oneof — less exercised than in `grpcio`;
still requires a `.proto` code-generation step. For a scanner whose
job is to work on arbitrary real servers, "less exercised edge cases"
is a precision risk.

### Option 3: Hand-rolled minimal Protobuf

Implement the subset of Protobuf framing needed for a scanner
(varint wire types 0 and 2, length-delimited messages) plus HTTP/2
framing (settings, flow control, stream multiplexing) manually. Zero
external dependency.

**Pros:** no new dependency; complete control over framing; no
native-compilation or install-size cost.

**Cons:** HTTP/2 framing is genuinely non-trivial — settings
negotiation, flow control windows, per-stream multiplexing, header
compression (HPACK). Protobuf decoder must handle all wire types that
appear in real-world descriptors (2 through 5, plus groups in older
schemas). Estimate: 800-1200 lines of new code before any scanner
logic. This is exactly the class of code where a subtle bug silently
produces wrong answers — the failure mode the project exists to
prevent. ADR-005 (gated corroborator) and ADR-006 (traversal collapse
oracle) exist precisely because "subtly wrong differential oracle" is
the bug class this project has invested most in avoiding.

### Option 4: Defer

Do not decide now. Revisit when FN-17 is scheduled.

**Pros:** no premature commitment; deferring costs nothing today.

**Cons:** the plan explicitly names this as a precondition
(`PHASE-6-PLAN.md:882-883`) precisely so that whoever picks up FN-17
does not spend a session re-litigating it. Deferring leaves FN-17
blocked with no documented path forward. That is the state the plan
was trying to avoid.

## Recommendation

**Option 1 — `grpcio` + `google.protobuf`**, accepted as a policy for
when FN-17 is implemented, not as an immediate dependency addition.

Reasoning:

1. **Precision over install size.** The project's positioning —
   "Differential DAST for teams who need results they can trust" — is
   incompatible with "promising but not-yet-battle-tested" transport
   code. The cost of a gRPC false negative caused by `betterproto`'s
   handling of an edge case would be much larger than the cost of a
   20 MB wheel. Users installing a DAST scanner for teams already
   expect non-trivial dependencies; a DAST scanner that gets gRPC
   wrong is worse than one that installs in 30 seconds.

2. **Hand-rolled is precision-risky by construction.** This is the
   same class of decision ADR-005 and ADR-006 resolved in favor of
   *not* inventing the differential oracle. HTTP/2 plus Protobuf
   framing is a well-defined problem with well-maintained reference
   implementations; reimplementing it introduces an entire category of
   potential silent-wrong-answer bugs that no benchmark in this repo
   is currently set up to catch (Phase 2.3 verification criterion 6
   acknowledges this: "Benchmark target added to `benchmark/track_c/`
   — currently none exists").

3. **The choice is reversible.** Unlike a data-format decision, the
   library is swappable if install size becomes a real operational
   problem. Both Option 1 and Option 2 use `.proto` files as the source
   of truth; switching is a `pyproject.toml` change plus re-generating
   stubs. If a future session finds grpcio's weight is a blocker, that
   session opens a superseding ADR. Nothing about this ADR is
   load-bearing beyond the current absence of FN-17.

4. **"Accepted" does not mean "added."** `pyproject.toml` is unchanged
   by acceptance. The dependency addition happens *with FN-17
   implementation*, not with ADR acceptance. If FN-17 is never
   scheduled, the ADR sits as documentation of a decision that only
   activates under a specific trigger. This mirrors ADR-013's pattern:
   accepted as policy, no code change at acceptance time.

If Option 1 is later reversed in favor of Option 2, the reversal is a
new ADR, and the switch is straightforward because both use `.proto`
files. If reversed in favor of Option 3, the reversal is much larger
in scope and should carry its own ADR with a detailed framing-layer
plan.

## Consequences

- **Option 1 accepted:** `pyproject.toml` gains `grpcio`,
  `google.protobuf`, and (for development) `grpcio-tools` *when FN-17
  implementation begins*, not now. CI matrix expands to cover native
  wheel installs on Linux/macOS/Windows when FN-17 first hits CI. No
  code change at ADR-acceptance time.
- **Option 2 accepted:** `pyproject.toml` gains `betterproto` and
  `grpclib`. Smaller install, no native compilation. FN-17's
  verification criterion 4 (`GRPCNormalizer` in `protocols/grpc.py`)
  still stands; only the transport layer changes.
- **Option 3 accepted:** `integrations/grpc.py` grows by ~800-1200
  lines of framing + codec before any scanner logic. FN-17's estimate
  (12-20 hours, `PHASE-6-PLAN.md:860`) grows substantially. Verification
  criterion 4 becomes the primary risk.
- **Option 4 accepted:** FN-17 remains blocked with no documented
  default. Any session picking it up re-litigates this ADR from
  scratch. This is the state the plan explicitly tries to avoid.

## References

- `docs/PHASE-6-PLAN.md:803-920` — FN-17 filed; the plan's own framing
  of the dependency decision, the four-piece scope expansion, and the
  verification criterion
- `docs/ROADMAP.md:66-77` — Phase 2 / 2.3 gRPC scope (bullet form, not
  a heading; the plan's "unmodified" citation is a more detailed
  reading, not the roadmap's text)
- `docs/decisions/ADR-013-ws-echo-reflection-policy.md` — the
  "accepted as policy, no code change" pattern this ADR mirrors
- `pyproject.toml` — current five-dependency runtime footprint
- `b7a83d2` — FN-17 filing commit
- `f28b10e` — ROADMAP Phase 2 adoption
