# Janissary Roadmap

> Adopted 2026-11-01 (session 4, commit A of roadmap adoption).
>
> This is a **plan**, not a contract. Version references in the original
> working document reflect the state at time of writing (7.3.0); see
> `CHANGELOG` for current state. Detailed per-milestone instructions
> live in `Session-Handover-2026-11-01-session3.md` and follow-up
> session handovers. This file captures the strategic core.

## Non-negotiable architectural decision

**The verification engine is the sole emitter of findings.** Everything
else — protocol expansion, heuristic discovery, monetization — depends
on this boundary holding.

## Strategic positioning

Do not compete with Invicti, Bright, or Checkmarx on breadth. Compete on
one claim they cannot easily make: every finding is proven by a
reproducible differential, and the tool tells you honestly when it
cannot prove one.

Monetization is **open-core with a paid exploration/triage surface**, not
a paid precision tier. The free CLI stays whole and trustworthy; paid
tiers sell workflow, volume, and enterprise isolation.

## Phase 0 — Architecture hardening (months 0-3)

Objective: make the verification engine the structural chokepoint before
adding any new protocol or discovery capability.

Milestones:
- **0.1** Formalise the discovery → verification boundary.
  `VerificationEngine` is the only emitter; attack modules return
  `CandidateFinding`; only the engine produces `VerifiedFinding`.
- **0.2** Regression-test known failure modes. Juice Shop: `wordpress_admin`
  produces zero emissions on SPA; missed SQLi reported as
  "candidate generated, verification failed" (not silently dropped);
  401 during scan produces `scan_incomplete` flag.
- **0.3** Protocol-aware `BaselineNormalizer` interface. HTTP first;
  strips CSRF tokens, nonces, timestamps, session IDs before comparison.

**Precision gate:** P=1.000 on the existing benchmark with zero bypasses.
A module that cannot pass without losing recall is deferred to Phase 2,
not given a bypass.

## Phase 1 — Credibility and benchmark expansion (months 3-6)

Objective: publish externally reproducible precision claims on the
hardened architecture.

Milestones:
- **1.1** Expand benchmark beyond OWASP Benchmark. Add crAPI and Juice
  Shop with per-class P/R/F1. Report known weaknesses (pathtraver recall
  0.049-0.308 remains visible).
- **1.2** External reproduction partnership. `BENCHMARK.md` with exact
  digest, commit, command, expected output, and "what would falsify
  this claim".
- **1.3** `LIMITATIONS.md` linked from README, updated every release.
  Per-class recall, candidate-only classes, unsupported protocols.

**Precision gate:** P=1.000 on expanded corpus for all verified findings.
Candidate-only findings reported separately.

## Phase 2 — Protocol expansion in precision-safe order (months 6-12)

Order matters: **GraphQL → WebSocket → gRPC**. Each protocol solves its
baseline problem before the next begins.

- **2.1** GraphQL depth: introspection-driven; oracle compares `data`
  object structurally, not HTTP status.
- **2.2** WebSocket: three-phase learn/probe/verify; oracle compares
  message sequences, not frames.
- **2.3** gRPC: reflection-based discovery; Protobuf-level oracle.
  If reflection unavailable, report `grpc_reflection_unavailable` and
  emit zero — never fall back to HTTP-level guessing.

**Precision gate:** each protocol reaches P=1.000 on its target before
the next begins. A protocol that cannot is marked "candidate-only".

## Phase 3 — Heuristic discovery engine (months 12-18)

Objective: increase recall without touching precision.

- **3.1** Bounded `CandidateQueue` with backpressure. Heuristic engine
  blocks or drops when full; verification engine never rushes.
- **3.2** Three heuristic families (parameter anomaly, state transition,
  framework surface), each with kill criterion: <5 new verified findings
  per 500 candidates → disabled by default, experimental flag.
- **3.3** Verify-first, merge-second. Every candidate verified
  independently before grouping.

**Precision gate:** P=1.000 holds with heuristic engine enabled.
Heuristic engine increases candidate volume; it does not increase
false-positive emissions.

## Phase 4 — Monetization surface (months 18-24)

- **4.1** Team SaaS: triage surface, suppression management, scheduled
  scans, Slack/Jira. $49-99/user/month. Free CLI remains the precision
  engine.
- **4.2** Enterprise: custom discovery plugins (verification engine
  gates them), clean-snapshot isolation, distributed verification,
  compliance reporting. $25K-75K annual contract value. On-premises;
  no phone-home.

**Precision gate:** precision claim stays in the free tier.

## What not to do (precision-destroying shortcuts)

- **Do not let the heuristic engine emit.** It proposes; the
  verification engine disposes.
- **Do not add a protocol before its normalizer is stable.** WebSocket
  frame-level oracles fire on interleaved traffic; gRPC status-code
  oracles fire on decode errors.
- **Do not publish a benchmark number you cannot reproduce in one
  command.** "Project-reported" is not "reproducible".
- **Do not move precision behind a paywall.** Paid tiers sell triage,
  retention, isolation, compliance — not deliberate degradation.
- **Do not compete on protocol count.** Out-honesty the enterprise
  vendors: publish what you support, publish what you miss, make the
  verification engine's refusal to engage a feature.