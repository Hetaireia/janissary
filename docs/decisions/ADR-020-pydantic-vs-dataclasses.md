# ADR-020 -- Schema validation: dataclasses + __post_init__, not pydantic

**Status:** Accepted (2026-11-04). Phase 0 Foundation.
**Supersedes:** None.
**Extends:** ADR-016 (vocabulary), ADR-017 (emission model).
**Blocks:** M36a completion (ADR series 016-021); M37 (heuristic signatures module).

## Context

The uploaded roadmap proposed a heuristic signature registry using
pydantic:

    class HeuristicSignature(BaseModel):
        id: str = Field(..., description="Unique structural check identifier")
        category: str = Field(..., description="Vulnerability type")
        target_layer: str = Field(..., description="'body', 'headers', or 'both'")
        patterns: List[str] = Field(..., description="Regex patterns")
        base_confidence: float = Field(default=0.450, ...)

That is idiomatic pydantic. It is not idiomatic for JANISSARY. The
entire codebase uses dataclasses throughout -- ScanFinding,
ScanSummary, SsrfPayload, SsrfHit, AuthConfig, WAFProfile, PacerConfig,
FindingGroup, and dozens of others.

M37 will land `src/janissary/heuristic/signatures.py` as the signature
registry. Before any code lands, this ADR locks the schema layer.
The decision was made after explicit comparison of pydantic's
capabilities against what dataclasses + the existing tooling can do,
not by dismissing pydantic's value (see D3 and D4).

## Current state (evidence)

Verified 2026-11-04:

- `pydantic` is not in `pyproject.toml` dependencies
- `pydantic` is not imported anywhere in `src/` (0 imports)
- `@dataclass` decorators appear throughout `src/` (46 occurrences)
- `__post_init__` is already used in the codebase (4 occurrences,
  confirming the pattern is idiomatic for this project)
- `mypy` is configured in `pyproject.toml` with `python_version = "3.10"`
  and runs in CI (see `.github/workflows/ci.yml`)
- The heuristic signature list will be *static configuration*, read at
  scan start, not runtime user input requiring schema validation


## Decisions

### D1. Heuristic signatures are frozen dataclasses with __post_init__ validation

`HeuristicSignature` is a `@dataclass(frozen=True)`. Fields:

- `id: str` -- e.g., `"HEUR-001"`
- `category: str` -- e.g., `"sqli:error_leak"`
- `target_layer: str` -- `"body"`, `"headers"`, or `"both"`
- `patterns: tuple[str, ...]` -- tuple, not list, for immutability
- `base_confidence: float = 0.450`

```python
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class HeuristicSignature:
    id: str
    category: str
    target_layer: str
    patterns: tuple[str, ...]
    base_confidence: float = 0.450

    def __post_init__(self) -> None:
        # Eager regex compilation -- raises SyntaxError on malformed
        # pattern at construction time, matching pydantic behavior.
        for p in self.patterns:
            re.compile(p)

        # Range gate -- pydantic would enforce this via
        # Field(ge=0.0, lt=1.0). Two lines close the same gap.
        if not (0.0 <= self.base_confidence < 1.0):
            raise ValueError(
                f"HeuristicSignature({self.id!r}): "
                f"base_confidence must be in [0.0, 1.0); "
                f"got {self.base_confidence}"
            )
```

Defaults set at definition. Validation runs at construction.
Frozen gives immutability for free (attempting to assign a field
raises `FrozenInstanceError`, matching pydantic behavior).

### D2. The registry is a module-level constant, not a JSON/YAML file

`HEURISTIC_SIGNATURES: tuple[HeuristicSignature, ...]` is defined in
`heuristic/signatures.py` as a literal constant. It ships with the
package. Users who want custom signatures construct their own tuple
of `HeuristicSignature` instances and pass it to the engine.

Rationale: signatures change with detection capability, not with
customer configuration. They belong in version control, tested at
build time, not at scan time. Bundling them as data would require a
loader and schema validator (where pydantic earns its keep -- but
only if we are loading untrusted data, which we are not).

### D3. The three layers that close pydantic validation surface

Pydantic validates in five domains. Each is covered without the
dependency:

| Domain | Pydantic mechanism | Dataclass equivalent | Coverage |
|---|---|---|---|
| **Type checking** | `Field(...)` | `@dataclass` + `mypy` in CI | **Equivalent** |
| **Malformed regex** | `Field(..., regex=...)` | `re.compile()` in `__post_init__` (D1) | **Equivalent** |
| **Value range** | `Field(ge=..., le=...)` | `if not (lo <= x <= hi): raise` in `__post_init__` (D1) | **Equivalent** |
| **Required vs default** | `Field(...)` vs `Field(default=...)` | dataclass with/without default | **Equivalent** |
| **Immutability** | `ConfigDict(frozen=True)` | `@dataclass(frozen=True)` | **Equivalent** |

No pydantic capability relevant to a static signature registry
remains unimplemented after D1. The gap is zero for this use case.
The trade-off becomes "10-15 MB dependency for zero incremental
validation."

### D4. Pydantic is the right tool at a different boundary

The correct use of pydantic is:

- Enterprise API ingress (future Phase 5): validate JSON payloads
  from an HTTP API where the caller is untrusted. `BaseModel` with
  `Field(..., description=...)` generates both schema and OpenAPI
  docs. Dataclasses + manual `if` checks would work but reinvent a
  wheel that FastAPI already expects.
- Multi-tenant SaaS config (future Phase 5): validate per-tenant
  signature overrides against a schema before persisting. The schema
  would live in a JSON file (untrusted boundary), not in code.

If those features ever ship, pydantic is the right tool **at that
boundary**. This ADR commits to the current context (static in-code
registry, trusted at import) and makes the boundary explicit. A future
ADR can introduce pydantic for the API layer without conflicting with
this one -- different trust boundaries, different tools.

### D5. Enforce via existing CI, not a new pipeline

The three validation layers (mypy, eager regex, `__post_init__`) run:

- **At import**: `__post_init__` fires on every `HEURISTIC_SIGNATURES`
  entry. A malformed regex or out-of-range confidence aborts import
  of `heuristic.signatures` -- the package will not load.
- **At CI**: `mypy` runs in `.github/workflows/ci.yml`. Type errors
  block PRs.
- **At test time**: `tests/unit/test_heuristic_signatures.py` (M37
  deliverable) exercises the validation paths.

No new CI infrastructure is required. The existing pipeline carries
the same validation weight pydantic would, via a different mechanism.

## Consequences

**Positive:**
- Zero new runtime dependencies for Phase 1 (M37, M38)
- Consistency: `heuristic/signatures.py` looks like every other module
  in the package
- Frozen dataclasses give immutability for free
- Tests use direct construction (`HeuristicSignature(id="HEUR-001",
  ...)`) like every other existing test
- `dataclasses.asdict()` gives JSON-serializable output when needed --
  no adapter layer
- The `__post_init__` pattern is already used elsewhere in the
  codebase (4 existing occurrences, confirmed 2026-11-04)

**Negative:**
- No automatic JSON schema generation for the signature registry.
  Mitigation: schema generation is only needed if we ever serve the
  registry over an API (D4). At that boundary, pydantic enters.
- No automatic type coercion from string inputs (e.g., `"0.45"` to
  `0.45`). Mitigation: CLI and code paths never accept signatures from
  strings. If that changes, an adapter is 5 lines.
- `__post_init__` is conventional, not declarative. A reader comparing
  to pydantic's `Field(ge=0.0, lt=1.0)` sees the same intent, but must
  read two lines instead of one. Acceptable for the number of fields
  involved (one today; likely 2-3 forever).

**Neutral:**
- No code changes ship with this ADR. M37 implements the pattern.
- The uploaded roadmap's pydantic field structure is preserved.
  `HeuristicSignature` fields map 1:1; only the container type changes
  (BaseModel -> frozen dataclass).
## Alternatives rejected

**Option A: Adopt pydantic exactly as the uploaded roadmap proposed.**

Rejected after explicit capability comparison (D3). Pydantic's entire
relevant validation surface is closed by mypy + eager `re.compile()` +
two-line `__post_init__` range check. Cost is real (10-15 MB runtime
dependency, either two patterns or one refactor against 867 tests,
pydantic version churn). Benefit for this use case is zero.

**Option B: Use pydantic only for heuristic schemas, keep dataclasses
for everything else.**

Rejected because two patterns in one codebase is worse than either
pattern alone. Contributors would need to know which files use which.
Every new module would be a coin flip on which to use. Consistency
principle argues against this.

**Option C: Migrate everything to pydantic.**

Rejected outright. Would require rewriting every dataclass in `src/`,
breaking 867 tests, and touching code that has been stable for months.
Massive scope creep against Failure Pattern 3 (don't rewrite working
code).

**Option D: Use attrs or msgspec instead of both.**

Rejected because they have the same problem pydantic has (new
dependency) without the marginal benefit of a schema validator, or
without the declarative range-check syntax the codebase already
eschews.

**Option E: Dataclasses without __post_init__ validation.**

Rejected. This was the draft position before explicit comparison. It
dismissed pydantic's range-check capability without closing the gap.
The `__post_init__` in D1 closes it. Without D1, Option E would be
dishonest -- accepting a weakness while claiming equivalence.

## References

- `docs/FUTURE-STATE-PLAN.md` Part 3 Phase 1 (M37, M38)
- `docs/FUTURE-STATE-PLAN.md` Part 4 Failure Pattern 3 (rewriting
  working code -- D1 applies this to the plan's own proposal)
- ADR-016 -- Verified vs Discovery vocabulary (schema-agnostic)
- ADR-017 -- Heuristic emission model (D5: signals field is
  `list[str]`, which dataclasses support directly)
- `pyproject.toml` -- current dependency list (no pydantic), mypy config
- `.github/workflows/ci.yml` -- mypy runs per-PR
- `src/janissary/engine/scanner.py` -- `@dataclass ScanFinding`,
  `@dataclass ScanSummary` (canonical pattern)