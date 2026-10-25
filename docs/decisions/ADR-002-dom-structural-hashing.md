# ADR-002: DOM structural hashing design

**Status:** Accepted
**Date:** 2026-10-25
**Blocks:** Phase 1.3a (implementation), and by extension 1.3b-1.3e and 2.2
**Prereqs:** ADR-001 (benchmark methodology)

## Context

JANISSARY's differential detection compares a baseline response to a payload response on status, length, and body. This works on classic server-rendered applications, where a fake path returns 404 and a real injection changes the response.

Single Page Applications break this. When a request hits a route the server does not know, a catch-all configuration returns `HTTP 200 OK` with the root `index.html`; client-side JavaScript then renders a "Page Not Found" view in the browser. The HTTP layer sees: status 200, length matching a baseline variant, body non-empty. The differential engine observes a valid response and emits a finding.

This is documented as **Issue #1** in the README: 39 SPA catch-all false positives on a Node SPA test target.

A second problem is the inverse. For path traversal, the interesting signal is not always a status or a length change — it is that the response *structure* collapsed. `../../../../etc/passwd` returns a flat text body with no HTML skeleton at all, often at the same status as the baseline, sometimes with a shorter length than the baseline (making it invisible to a "response got larger" heuristic). Current traversal recall is F1 0.049-0.308 (see ADR-003).

Both problems share a shape: **HTTP-layer features are insufficient to distinguish "the application responded" from "the application responded with the application's structure."** A structural fingerprint of the response body, gated on the baseline phase, fixes both.

## Decision

### Parser: selectolax

`selectolax` (Modest/HTML5 under the hood) is selected over `html.parser`, `lxml.html`, and BeautifulSoup.

- **Version:** 1.0.2
- **Wheels verified:** cp314 win_amd64 (2 wheels, standard + free-threaded), cp314 manylinux x86_64 (2 wheels)
- **Fallback:** `html.parser` with explicit void-element handling if a future CPython version lacks wheels. Void elements (`area`, `base`, `br`, `col`, `embed`, `hr`, `img`, `input`, `link`, `meta`, `param`, `source`, `track`, `wbr`) must be listed explicitly and never pushed onto the nesting stack. The fallback path is not implemented now; it is documented for portability.

Rationale: `html.parser` mis-tokenizes malformed HTML silently. Adversarial fuzzing frequently produces malformed HTML (an unbalanced quote swallowing the rest of a page, an unclosed tag, a broken attribute). `lxml.html` and BeautifulSoup are too slow and heavy for per-response use. `selectolax` is fast enough to run on every baseline-phase response and robust to the malformed cases that fuzzing produces.

### Hash: mmh3

`mmh3` (MurmurHash3) is selected for the SimHash inner hash.

- **Version:** 5.3.1
- **Wheels verified:** cp314 win_amd64 (2 wheels)
- **Fallback:** `hashlib.blake2b(digest_size=8)` (stdlib, deterministic, ~1 microsecond per shingle) if wheels are unavailable. Both are documented as viable; mmh3 is preferred for speed.

**`hash()` is forbidden.** Python's built-in `hash()` is randomized per process by `PYTHONHASHSEED` (or by default randomness) for security reasons. A baseline fingerprint computed in one process and a payload fingerprint computed in another would produce different bit values, and Hamming distance between them would be meaningless. Any SimHash implementation on this project that calls built-in `hash()` must be rejected in review.

### Skeleton extraction

The skeleton is the ordered sequence of tag names in the response, with text content and attributes removed.

- **Ignored tags:** `script`, `style`, `noscript`, `svg`, `path` — these carry content that changes without structural meaning
- **Stripped:** all text nodes, all attribute values (including IDs, classes, nonces, and CSRF tokens), all comments
- **Kept:** tag names, order, and nesting
- **Output:** a flat list of tag tokens (e.g. `['<div>', '<h1>', '</h1>', '<p>', '</p>', '</div>']`)

The skeleton is not a tree; it is an ordered sequence. Nesting balance is preserved by emitting both opening and closing tokens, but the fingerprint does not distinguish `<div><p></p></div>` from `<div></div><p></p>` — the sequence is what matters for distance comparison.

### Shingle size: 3

Shingles are 3-token sliding windows over the skeleton, concatenated into strings and hashed. `n=3` is the standard choice for SimHash over structural tokens: it preserves enough local ordering to distinguish "adjacent elements" from "distant elements" without making the shingle set so large that Hamming distance becomes dominated by boilerplate. `n=1` loses ordering entirely; `n>=5` produces too many unique shingles for small pages and produces noisier fingerprints.

### Hamming thresholds

Three bands, each used for a different decision:

| Distance | Interpretation | Action |
|---|---|---|
| **0-3** | Structurally identical to baseline | Discard (SPA catch-all, or genuinely unchanged page) — **combined with root signature check, see below** |
| **4-15** | Partial structural change | Flag as "potential structural change" — do not emit; feed to corroboration |
| **>20** | Structural collapse | High-confidence structural divergence — confirm traversal or similar |

The gaps (16-20) are deliberate. A response 16-20 bits from baseline is genuinely ambiguous — neither "same structure" nor "collapsed" — and should be treated as noise. This is a conservative gate.

### Integration point: baseline phase

The structural fingerprint is computed during the **baseline phase**, not per payload request.

- The baseline phase sends N baseline requests (currently 5, `--baseline-count 5`). Every baseline response of content type `text/html` has its fingerprint computed.
- If all baseline fingerprints are within Hamming distance 3 of each other, the baseline is "structurally stable" and the gate is armed. If they spread more widely, the target's structural variance is high (a dynamic home page, a rotating ad banner — but note that text changes do not move the fingerprint, only tag structure does) and the gate is disabled for this target. **A disabled gate defaults to today's behavior; it does not block the scan.**
- When a payload response returns `200 OK` and content type `text/html`, the fingerprint is computed and compared to the armed baseline. No fingerprints are computed for non-HTML responses, and no fingerprint is computed for responses that already fail the status/length differential (that path is cheaper and comes first).

Rationale: computing SimHash per payload is wasted work when the baseline is unstable. Arming the gate once at baseline time is both cheaper and more honest about what the gate can decide.

### Combined signal requirement

**SimHash alone is never sufficient to discard a finding or to emit one.** Both directions require additional evidence:

- **Discard:** `distance <= 3` **AND** the response matches the stored root signature **AND** status 200. A legitimate page that happens to have the same skeleton as the root still fails the root-signature check if the body differs in a way that matters (e.g. contains the injected parameter value reflected in text). The root signature is the SHA-256 of the first 4 KB of the canonicalized root page body, computed during the baseline phase.
- **Emit:** `distance > 20` **AND** one of: response body length < 10% of baseline average, response contains no `<` character at all (flat text), or response matches a known-file signature (e.g. `/etc/passwd` line format). Distance alone never fires a finding.

### Success criteria for 1.3c

Phase 1.3c ships when:

1. The 39 SPA catch-all FPs from Issue #1 are reduced to **0**
2. No true positives are lost on the DAST-applicable benchmark (`--min-f1 0.92 --max-fp 0` still passes on the r1+rec artifact)
3. A synthetic SPA test fixture produces zero findings on fake routes and correct findings on real vulnerabilities

If criteria 1 and 2 cannot both be met, the gate is disabled by default and Issue #1 remains open. Precision wins ties.

## Rejected alternatives

- **MD5 or SHA-256 of the DOM tree:** non-locality-preserving. A one-character change produces a completely different hash, so Hamming distance is meaningless. This was explicitly rejected in the project's design notes.
- **Python `hash()`:** non-deterministic across processes. See above.
- **`lxml.html` or BeautifulSoup:** too slow, too heavy for per-response use. selectolax is the speed-appropriate choice.
- **`html.parser` alone:** mis-tokenizes malformed HTML silently. Acceptable as a fallback only with explicit void-element handling and a try/except.
- **SimHash as a replacement for differential detection:** it is a **corroborator**, not a detector. A design that drops differential detection and relies on structural hashing is wrong and will be rejected in review. SimHash decides *whether* a differential signal is meaningful; it does not create one.
- **Levenshtein tag-tree distance** (the approach in the original 1.3 one-liner): O(n*m) time per comparison, unsuitable for per-response use at scale. Shingled SimHash is O(n).

## Consequences

- **Phase 1.3a** implements skeleton extraction + SimHash + Hamming distance per this ADR.
- **Phase 1.3b** implements the baseline structural variance index and the arming logic.
- **Phase 1.3c** implements the gated corroborator and targets Issue #1.
- **Phase 1.3d** implements the `>20` structural-collapse path and targets traversal and WAF-block detection.
- **Phase 1.3e** writes the regression suite (void tags, swallowed attributes, catch-all, raw `/etc/passwd`) and re-runs the benchmark.
- **Phase 2.2** (traversal dictionary/encoding) is re-scoped: 1.3d supplies confirmation, 2.2 supplies payload coverage. Neither is sufficient alone.
- New dependencies: `selectolax>=1.0.2`, `mmh3>=5.3.1`. Both go into `[project.dependencies]`, not `[dev]`. Both add native extensions; the CI matrix must keep building.
- The 39 SPA FPs in Issue #1 remain visible in the repo until 1.3c ships. That is not a regression from this ADR; it is the baseline the ADR is written against.

## Verification plan (before 1.3a merges)

1. `pip download selectolax==1.0.2 mmh3==5.3.1 --only-binary=:all: --no-deps` succeeds on cp314 win_amd64 and cp314 manylinux x86_64 (this is the pre-flight already run; re-run in CI on dependency upgrade)
2. A unit test constructs two DOMs that differ only in text (e.g. `User: Alice` vs `User: Bob`) and asserts Hamming distance `<= 3`
3. A unit test constructs two DOMs that differ structurally (an extra nested `<div>`) and asserts Hamming distance `> 20`
4. A unit test asserts `hash()` is never called (a static grep is sufficient; alternatively, a deprecation shim in the module asserts on import)
5. A synthetic fixture exercises a malformed HTML page (unbalanced quotes, unclosed tags) and asserts the parser does not raise and produces a deterministic fingerprint

If items 2 or 3 fail — i.e. the thresholds do not separate the cases — the ADR is amended with revised thresholds **before** 1.3a is implemented. Thresholds are not tuned after 1.3a merges.

## References

- `docs/decisions/ADR-001-benchmark-methodology.md` — the benchmark context this ADR operates within
- `docs/decisions/ADR-003-pathtraver-ceiling.md` — the ceiling 1.3d is expected to improve
- README §Known Issues — Issue #1 (SPA catch-all FPs)
- Original design notes (DOM hashing blueprint) — referenced as historical context, not normative