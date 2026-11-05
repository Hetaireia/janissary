"""Heuristic signatures + engine (Track B / Discovery Engine).

Per ADR-017 and ADR-022: this package never constructs ScanFinding,
never sets verification_status. Candidates route through
_ENGINE.verify() in the caller (scanner.scan()).
"""

from janissary.heuristic.types import Observation
from janissary.heuristic.signatures import (
    HEURISTIC_SIGNATURES,
    VALID_TARGET_LAYERS,
    HeuristicSignature,
)
from janissary.heuristic.engine import (
    HeuristicEngine,
    HeuristicMatch,
)

__all__ = [
    "Observation",
    "HEURISTIC_SIGNATURES",
    "VALID_TARGET_LAYERS",
    "HeuristicSignature",
    "HeuristicEngine",
    "HeuristicMatch",
]
