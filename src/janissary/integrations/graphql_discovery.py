"""GraphQL discovery module (Phase 2.1 + FN-15 part 2).

Wraps existing GraphQL recon functions (``detect()``, ``depth_probe()``,
``alias_probe()``, ``fuzz_arguments()``) to produce ``CandidateFinding``
objects. Produces candidates only -- does not route through the
VerificationEngine. That wiring is part 3.

Design conventions:

- Every ``finding_type`` is prefixed with ``"graphql_"``. Part 3 will
  add a ``GraphQLReconConfirmer`` that emits ``unproven=True`` for any
  finding whose type has this prefix. Without that confirmer, the
  engine would fall through to ``AnalyzerImplicitConfirmer`` and mark
  these observations as verified, which would overclaim: introspection
  being enabled is not a vulnerability, it is a configuration
  observation pending context.
- Candidates are emitted liberally; the engine filters ruthlessly.
  A "clean" depth probe produces zero candidates; an excessive one
  produces one. A "clean" argument fuzz result produces zero candidates;
  one with errors produces one. Emitting every response would flood the
  engine; emitting only confirmed findings would make this module the
  oracle, which it is not.

Contract:
    GraphQLDiscoveryModule(client, profile).discover(...) -> list[CandidateFinding]
"""
from __future__ import annotations

from typing import Any

from janissary.verification.types import CandidateFinding

from .graphql import (
    FuzzResult,
    GraphQLClient,
    GraphQLProfile,
    alias_probe,
    depth_probe,
    fuzz_arguments,
)


_DEPTH_THRESHOLD = 10
_ALIAS_THRESHOLD = 100


class GraphQLDiscoveryModule:
    """Produce GraphQL ``CandidateFinding`` objects from a recon profile.

    Cheap by default: profile observations are already gathered by
    ``detect()`` and cost nothing to convert into candidates. Probes
    and fuzzing require additional HTTP round-trips and are opt-in.
    """

    def __init__(self, client: GraphQLClient, profile: GraphQLProfile) -> None:
        self.client = client
        self.profile = profile

    def discover(
        self,
        include_probes: bool = True,
        include_fuzz: bool = False,
        max_fuzz_targets: int | None = 20,
    ) -> list[CandidateFinding]:
        """Return all candidates the module can extract from this profile.

        Profile observations (introspection, batching, suggestions) are
        always included — they are free.

        Probes (``depth_probe``, ``alias_probe``) are each 2–4 HTTP
        requests and are included when ``include_probes=True`` (default).

        Argument fuzzing is opt-in via ``include_fuzz=True``. It fires
        one HTTP request per payload per target. ``max_fuzz_targets``
        caps how many (field, arg) pairs are fuzzed. ``None`` = no cap
        (dangerous; caller beware).
        """
        candidates: list[CandidateFinding] = []
        candidates.extend(self._profile_observations())
        if include_probes:
            candidates.extend(self._probe_candidates())
        if include_fuzz:
            candidates.extend(self._fuzz_candidates(max_fuzz_targets))
        return candidates

    # ------------------------------------------------------------------
    # Profile observations (free)
    # ------------------------------------------------------------------

    def _profile_observations(self) -> list[CandidateFinding]:
        out: list[CandidateFinding] = []

        if self.profile.introspection_enabled:
            type_count = self.profile.type_count
            out.append(self._candidate(
                finding_type="introspection_enabled",
                severity="info",
                detail=(
                    f"Schema introspection enabled "
                    f"({type_count} types exposed); schema oracle in production"
                ),
                payload_name="introspection_query",
                payload_value="__schema introspection",
            ))

        if self.profile.batched_queries:
            out.append(self._candidate(
                finding_type="batching_accepted",
                severity="info",
                detail="Server accepts batched queries (DoS amplification vector)",
                payload_name="batch_probe",
                payload_value="2x __typename in array",
            ))

        if self.profile.suggestions_supported:
            out.append(self._candidate(
                finding_type="suggestions_enabled",
                severity="info",
                detail=(
                    "Field-name suggestions enabled "
                    "(schema oracle via 'Did you mean' error messages)"
                ),
                payload_name="field_suggestion_probe",
                payload_value="__definitelyNotARealField",
            ))

        return out

    # ------------------------------------------------------------------
    # Probes (2-4 requests each)
    # ------------------------------------------------------------------

    def _probe_candidates(self) -> list[CandidateFinding]:
        out: list[CandidateFinding] = []

        depth, refusal = depth_probe(self.client)
        if depth is not None and depth >= _DEPTH_THRESHOLD:
            out.append(self._candidate(
                finding_type="depth_abuse",
                severity="medium",
                detail=(
                    f"Query depth {depth} accepted without refusal "
                    f"(threshold {_DEPTH_THRESHOLD}); DoS amplification risk"
                ),
                payload_name="depth_probe",
                payload_value=f"nested __typename x{depth}",
            ))

        aliases, alias_refusal = alias_probe(self.client)
        if aliases is not None and aliases >= _ALIAS_THRESHOLD:
            out.append(self._candidate(
                finding_type="alias_abuse",
                severity="medium",
                detail=(
                    f"Alias count {aliases} accepted without refusal "
                    f"(threshold {_ALIAS_THRESHOLD}); resource amplification risk"
                ),
                payload_name="alias_probe",
                payload_value=f"aliased __typename x{aliases}",
            ))

        return out

    # ------------------------------------------------------------------
    # Argument fuzzing (opt-in)
    # ------------------------------------------------------------------

    def _fuzz_candidates(
        self, max_targets: int | None
    ) -> list[CandidateFinding]:
        targets = self._enumerate_fuzz_targets(max_targets)
        out: list[CandidateFinding] = []
        for field, arg in targets:
            try:
                results = fuzz_arguments(self.client, field, arg)
            except Exception:
                # A fuzz target that errors outright is not a finding;
                # continue to the next target.
                continue
            for result in results:
                if result.errors:
                    out.append(self._fuzz_candidate(field, arg, result))
        return out

    def _fuzz_candidate(
        self, field: str, arg: str, result: FuzzResult
    ) -> CandidateFinding:
        first_error = result.errors[0] if result.errors else ""
        detail = (
            f"Fuzzing {field}({arg}: {result.payload_name}) produced "
            f"{len(result.errors)} error(s): {first_error[:120]}"
        )
        return self._candidate(
            finding_type="argument_fuzz_error",
            severity="medium",
            detail=detail,
            payload_name=f"fuzz:{field}.{arg}",
            payload_value=str(result.payload_value)[:200],
        )

    def _enumerate_fuzz_targets(
        self, max_targets: int | None
    ) -> list[tuple[str, str]]:
        """Extract (field, arg) pairs from the introspected schema.

        Walks the Query root type, enumerates its fields and their
        arguments. Skips __typename-style introspection fields.
        """
        schema = self.profile.schema or {}
        query_type_name = self.profile.query_type or "Query"

        targets: list[tuple[str, str]] = []
        for t in schema.get("types") or []:
            if not isinstance(t, dict):
                continue
            if t.get("name") != query_type_name:
                continue
            for field in t.get("fields") or []:
                if not isinstance(field, dict):
                    continue
                fname = field.get("name")
                if not fname or fname.startswith("__"):
                    continue
                for arg in field.get("args") or []:
                    if not isinstance(arg, dict):
                        continue
                    aname = arg.get("name")
                    if not aname:
                        continue
                    targets.append((fname, aname))
                    if max_targets is not None and len(targets) >= max_targets:
                        return targets
            return targets  # only the root Query type matters
        return targets

    # ------------------------------------------------------------------
    # Builder
    # ------------------------------------------------------------------

    def _candidate(
        self,
        finding_type: str,
        severity: str,
        detail: str,
        payload_name: str,
        payload_value: str,
    ) -> CandidateFinding:
        return CandidateFinding(
            param=payload_name,
            payload_name=payload_name,
            payload_value=payload_value,
            category="graphql",
            severity=severity,
            finding_type=f"graphql_{finding_type}",
            detail=detail,
            url=self.profile.endpoint,
            method="POST",
        )
