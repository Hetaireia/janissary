# ADR-013 — WebSocket echo-reflection candidate policy (FN-16)

**Status:** Accepted (2026-11-02) — Option 1 (status quo). The
recommendation below was accepted as-is; no code change. A future
reversal requires ADR-014 superseding this one.
**Depends on:** ADR-007 (finding identity), FN-16 parts 6a/6b
(`8f821ad`, `186c7a8`, `02c6a05`, `c9f2035`)
**Blocks:** none — no downstream work waits on this decision

## Context

`WebSocketDiscoveryModule.discover()` emits one `CandidateFinding` per
(field, payload) pair whenever the probe's normalized response differs
from the learned baseline. A local echo server produces 11 findings
from 3 payloads. All 11 are accurately `verification_status=unproven`
— no false verification, no false severity. But the *volume* is
indistinguishable in the human-facing count from a scan that actually
found something.

Evidence:

- Smoke 2026-11-02, echo server `ws://127.0.0.1:8765`, payload file
  `hello\n{"op":"ping"}`, `scan --ws --ws-payloads`: **11 findings,
  all `severity=medium`, all `category=websocket`, all `*_probe`
  finding types, all `unproven`.** Detail strings carry the delta
  classification: `echoed_payload` 10, `length_delta` 1 (outlier:
  `generic_null_byte`, null byte not preserved in normalized echo).
- Verification is not in question: `WebSocketReconConfirmer` marks
  every `websocket_*` candidate `unproven`. There is no false positive.
- UX has been improved twice: the summary now shows `(unproven: N)`
  (`186c7a8`), and detail strings carry the delta kind (`c9f2035`).

The remaining question is not "is this a bug" — it is not — but
"should `discover()` suppress candidates whose only delta is verbatim
echo?"

## Options

### Option 1: Status quo

Keep `discover()` as-is. All deltas produce candidates. UX fixes
(`186c7a8`, `c9f2035`) are the mitigation.

**Pros:** maximum recall; on real reflective targets, a verbatim-echo
candidate is often the first signal of a reflected-XSS-class finding.
Zero code change.

**Cons:** echo-heavy endpoints produce predictable noise; users learn
to ignore `--ws` findings.

### Option 2: Suppress `echoed_payload`

If `_classify_delta` returns `echoed_payload`, skip emission.

**Pros:** clean output on echo servers.

**Cons:** asymmetric cost. `echoed_payload` is the exact signature of a
reflected-XSS candidate; suppression loses those on live targets.
Breaks `test_discovery_end_to_end_echo_produces_candidates` (asserts
`len == 2`).

### Option 3: Require corroboration

Emit `echoed_payload` candidates only if the same field produces a
non-echo delta (frame_count / length / content) under a second payload.

**Pros:** keeps reflected-XSS detections where corroborated.

**Cons:** doubles probe count on echoing fields; requires cross-probe
grouping that `verify()` doesn't do today; reduces recall when only one
payload is available or reflection is the sole signal. Scope: 2-3
sessions, larger than `02c6a05` or `c9f2035`.

### Option 4: User-controlled flag

Add `--ws-suppress-echo` or a severity tier (drop `echoed_payload` to
`info` by default).

**Pros:** user choice; no behavior change unless requested.

**Cons:** adds surface; "noisy but complete" is the current state — a
flag doesn't fix it, it documents it.

## Recommendation

**Option 1 — status quo.** Reasoning:

1. The verification engine is honest; no bug to fix.
2. `echoed_payload` is the signature of reflected-XSS candidates.
   Suppression has an asymmetric cost against real targets that a
   noisy echo-server smoke does not justify.
3. The UX problem is real but fixable — two fixes already shipped.
4. A future refinement that does not commit to suppression: extend
   `_classify_delta` to distinguish "pure reflection" (payload value is
   the *only* delta after stripping payload from probe_norm vs baseline)
   from "reflection amid other changes." That is `02c6a05`-shaped and
   lets a later session make a finer-grained call.

If Option 1 is later reversed in favor of Option 4, prefer the flag
`--ws-include-echo` (default off) — the *inverse* of `--ws-suppress-echo`,
because a user running `--ws` on a real target wants suppression more
often than a user running on a smoke endpoint wants the raw list.

## Consequences

- **Option 1 accepted:** no code change. `LIMITATIONS.md` stays accurate.
  This ADR stays as the record; a future reversal requires ADR-014.
- **Option 2 or 3 accepted:** new ADR supersedes this one before code
  changes. Break `test_discovery_end_to_end_echo_produces_candidates`.
  Scope: 2-3 sessions.
- **Option 4 accepted:** separate ADR scoping the flag surface.
  Estimated one session.

## References

- `docs/PHASE-6-PLAN.md` FN-16 follow-up, "Not bugs" section
- `LIMITATIONS.md` "WebSocket recon findings"
- `c9f2035` four-way delta taxonomy
- `02c6a05` binary delta taxonomy
- `8f821ad` http→ws URL derivation
- `186c7a8` unproven count in severity summary
