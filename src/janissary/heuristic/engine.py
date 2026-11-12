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


class HeuristicEngine:
    """Match observations against heuristic signatures.

    Per ADR-022 D1/D2: produces CandidateFinding (not ScanFinding).
    The caller routes through _ENGINE.verify() -> _to_scan_finding().
    """

    def __init__(
        self, signatures: tuple[HeuristicSignature, ...] = HEURISTIC_SIGNATURES
    ) -> None:
        self._signatures = signatures

    def match(self, observations: list[Observation]) -> list[HeuristicMatch]:
        """Return all matches across observations, in observation order."""
        matches: list[HeuristicMatch] = []
        for idx, obs in enumerate(observations):
            for sig in self._signatures:
                target = self._select_target(sig.target_layer, obs)
                if target is None:
                    continue
                for pattern in sig.patterns:
                    m = re.search(pattern, target)
                    if m:
                        matches.append(
                            HeuristicMatch(
                                signature_id=sig.id,
                                category=sig.category,
                                target_layer=sig.target_layer,
                                matched_pattern=pattern,
                                evidence_excerpt=m.group(0)[:200],
                                confidence=sig.base_confidence,
                                observation_index=idx,
                            )
                        )
                        break  # one pattern per signature per observation
        return matches

    def to_candidates(
        self,
        matches: list[HeuristicMatch],
        observations: list[Observation],
    ) -> list[CandidateFinding]:
        """Convert matches to CandidateFinding.

        discovery_reason='heuristic:<sig_id>' triggers HeuristicConfirmer.
        verification_status is deliberately NOT set (CandidateFinding has
        no such field; ADR-022 D1).
        """
        candidates: list[CandidateFinding] = []
        for m in matches:
            obs = observations[m.observation_index]
            candidates.append(
                CandidateFinding(
                    param=obs.param,
                    payload_name=obs.payload_name or "heuristic",
                    payload_value=obs.payload_value or m.matched_pattern,
                    category=m.category,
                    severity="low",
                    finding_type=f"heuristic_{m.category.replace(':', '_')}",
                    detail=(
                        f"Heuristic {m.signature_id} matched "
                        f"{m.target_layer} pattern {m.matched_pattern!r}; "
                        f"evidence: {m.evidence_excerpt!r}"
                    ),
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
