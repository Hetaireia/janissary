"""Heuristic signature engine (M38, Track B / Discovery Engine).

Per ADR-017 (emission model) and ADR-022 (reconciliation), this module:
- Matches HTTP response observations against HEURISTIC_SIGNATURES
- Produces CandidateFinding with discovery_reason='heuristic:<sig_id>'
- Never constructs ScanFinding, never sets verification_status
- Caller (scanner.scan()) routes through _ENGINE.verify() -> _to_scan_finding()

The heuristic engine is pure: it takes observations (already fetched by
the payload loop) and returns candidates. No network traffic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from janissary.heuristic.signatures import (
    HEURISTIC_SIGNATURES,
    HeuristicSignature,
)
from janissary.heuristic.types import Observation
from janissary.verification.types import CandidateFinding


@dataclass(frozen=True)
class HeuristicMatch:
    """A single signature-match: which signature, which pattern, evidence."""

    signature_id: str
    category: str
    target_layer: str
    matched_pattern: str
    evidence_excerpt: str
    confidence: float
    observation_index: int
    suppressed: bool = False
    suppression_reason: str = ""
    suppressed_by_observation_index: int | None = None


@dataclass(frozen=True)
class MatchGroup:
    """Aggregation of heuristic matches sharing (url, method, param).

    M82a: multi-signal aggregation model. Groups matches produced by
    ``HeuristicEngine.match()`` by their endpoint and parameter so that
    downstream (M82b) can emit one candidate per parameter with
    observation counts, distinct payload families, and evidence
    attribution.

    Suppressed matches aggregate alongside unsuppressed ones — the
    caller (M82b) decides the filtering policy. M82a is model-only:
    no CandidateFinding fields are populated here.

    R3 (M82a scope): ``categories`` and ``confidences`` are retained as
    frozensets. No reduction policy is baked in — M82b decides how to
    collapse a multi-signature group into one candidate.

    R1 (M82a scope): ``first_observation_id`` and ``last_observation_id``
    are the observation IDs at ``first_observation_index`` and
    ``last_observation_index`` respectively. They are NOT the
    lexicographically smallest/largest IDs.
    """

    url: str
    method: str
    param: str
    matches: tuple[HeuristicMatch, ...]
    signature_ids: frozenset[str]
    categories: frozenset[str]
    confidences: frozenset[float]
    payload_families: frozenset[str]
    contributing_observation_ids: tuple[str, ...]
    first_observation_index: int
    last_observation_index: int
    first_observation_id: str
    last_observation_id: str


class HeuristicEngine:
    """Match observations against heuristic signatures.

    Per ADR-022 D1/D2: produces CandidateFinding (not ScanFinding).
    The caller routes through _ENGINE.verify() -> _to_scan_finding().
    """

    def __init__(
        self, signatures: tuple[HeuristicSignature, ...] = HEURISTIC_SIGNATURES
    ) -> None:
        self._signatures = signatures
        self._suppressed_count: int = 0

    @property
    def suppressed_count(self) -> int:
        """Payload matches suppressed in the most recent match() call."""
        return self._suppressed_count

    def match(self, observations: list[Observation]) -> list[HeuristicMatch]:
        """Return payload matches; baseline matches populate suppression.

        Baseline observations (``is_baseline=True``) are matched first to
        build a suppression set keyed by the strict triple
        (signature_id, matched_pattern, target_layer). A payload match is
        marked suppressed when its triple appears in that set. Baseline
        matches are never returned as findings.

        ``suppressed_by_observation_index`` on a suppressed match points
        to the first baseline observation (in the original input sequence)
        that produced the matching triple.
        """
        baseline_first_match: dict[tuple[str, str, str], int] = {}
        for idx, obs in enumerate(observations):
            if not obs.is_baseline:
                continue
            for sig in self._signatures:
                target = self._select_target(sig.target_layer, obs)
                if target is None:
                    continue
                for pattern in sig.patterns:
                    m = re.search(pattern, target)
                    if m:
                        key = (sig.id, pattern, sig.target_layer)
                        if key not in baseline_first_match:
                            baseline_first_match[key] = idx
                        break

        self._suppressed_count = 0
        matches: list[HeuristicMatch] = []
        for idx, obs in enumerate(observations):
            if obs.is_baseline:
                continue
            for sig in self._signatures:
                target = self._select_target(sig.target_layer, obs)
                if target is None:
                    continue
                for pattern in sig.patterns:
                    m = re.search(pattern, target)
                    if m:
                        key = (sig.id, pattern, sig.target_layer)
                        suppressed = key in baseline_first_match
                        if suppressed:
                            self._suppressed_count += 1
                        matches.append(
                            HeuristicMatch(
                                signature_id=sig.id,
                                category=sig.category,
                                target_layer=sig.target_layer,
                                matched_pattern=pattern,
                                evidence_excerpt=m.group(0)[:200],
                                confidence=sig.base_confidence,
                                observation_index=idx,
                                suppressed=suppressed,
                                suppression_reason=(
                                    "baseline_match" if suppressed else ""
                                ),
                                suppressed_by_observation_index=(
                                    baseline_first_match[key] if suppressed else None
                                ),
                            )
                        )
                        break  # one pattern per signature per observation
        return matches

    def to_candidates(
        self,
        matches: list[HeuristicMatch],
        observations: list[Observation],
        *,
        include_suppressed: bool = False,
    ) -> list[CandidateFinding]:
        """Convert matches to CandidateFinding.

        discovery_reason='heuristic:<sig_id>' triggers HeuristicConfirmer.
        verification_status is deliberately NOT set (CandidateFinding has
        no such field; ADR-022 D1).
        """
        candidates: list[CandidateFinding] = []
        for m in matches:
            if m.suppressed and not include_suppressed:
                continue
            obs = observations[m.observation_index]
            detail = (
                f"Heuristic {m.signature_id} matched "
                f"{m.target_layer} pattern {m.matched_pattern!r}; "
                f"evidence: {m.evidence_excerpt!r}"
            )
            if m.suppressed:
                detail = f"[suppressed: {m.suppression_reason}] " + detail
            candidates.append(
                CandidateFinding(
                    param=obs.param,
                    payload_name=obs.payload_name or "heuristic",
                    payload_value=obs.payload_value or m.matched_pattern,
                    category=m.category,
                    severity="low",
                    finding_type=f"heuristic_{m.category.replace(':', '_')}",
                    detail=detail,
                    response_status=obs.response_status,
                    response_length=len(obs.body or ""),
                    url=obs.url,
                    method=obs.method,
                    discovery_reason=f"heuristic:{m.signature_id}",
                    confidence=m.confidence,
                    evidence_excerpt=m.evidence_excerpt,
                )
            )
        return candidates

    def aggregate(
        self,
        matches: list[HeuristicMatch],
        observations: list[Observation],
    ) -> list[MatchGroup]:
        """Aggregate matches into per-parameter groups (M82a).

        Groups matches by ``(url, method, param)``. Within each group,
        retains distinct signatures, categories, confidences and
        payload families; deduplicates contributing observation IDs;
        and records first/last original observation indices plus the
        observation IDs at those indices (not lexicographic extrema).

        Suppressed matches aggregate alongside unsuppressed ones.
        M82a does not filter — M82b decides candidate integration
        (confidence/category reduction, suppression handling).

        Returns groups sorted by ``first_observation_index`` ascending.
        """
        buckets: dict[tuple[str, str, str], list[HeuristicMatch]] = {}
        for m in matches:
            obs = observations[m.observation_index]
            key = (obs.url, obs.method, obs.param)
            buckets.setdefault(key, []).append(m)

        groups: list[MatchGroup] = []
        for (url, method, param), group_matches in buckets.items():
            signature_ids = frozenset(m.signature_id for m in group_matches)
            categories = frozenset(m.category for m in group_matches)
            confidences = frozenset(m.confidence for m in group_matches)

            contributing_ids: set[str] = set()
            payload_families: set[str] = set()
            for m in group_matches:
                obs = observations[m.observation_index]
                if obs.observation_id:
                    contributing_ids.add(obs.observation_id)
                if obs.payload_name:
                    payload_families.add(obs.payload_name)

            first_idx = min(m.observation_index for m in group_matches)
            last_idx = max(m.observation_index for m in group_matches)

            groups.append(
                MatchGroup(
                    url=url,
                    method=method,
                    param=param,
                    matches=tuple(group_matches),
                    signature_ids=signature_ids,
                    categories=categories,
                    confidences=confidences,
                    payload_families=frozenset(payload_families),
                    contributing_observation_ids=tuple(sorted(contributing_ids)),
                    first_observation_index=first_idx,
                    last_observation_index=last_idx,
                    first_observation_id=observations[first_idx].observation_id,
                    last_observation_id=observations[last_idx].observation_id,
                )
            )

        groups.sort(key=lambda g: g.first_observation_index)
        return groups

    @staticmethod
    def _select_target(layer: str, obs: Observation) -> str | None:
        if layer == "body":
            return obs.body or ""
        headers = "\n".join(f"{k}: {v}" for k, v in obs.headers.items())
        if layer == "headers":
            return headers
        if layer == "both":
            return (obs.body or "") + chr(10) + headers
        return None
