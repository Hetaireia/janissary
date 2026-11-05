"""Heuristic signature registry for the Discovery Engine (M37).

Per ADR-017 (heuristic emission model), Track B / the Discovery Engine emits
*candidates*, never findings. Per ADR-020 (schema validation), signatures are
frozen dataclasses validated eagerly in ``__post_init__``, with no pydantic
dependency.

This module is a self-contained leaf. It is intentionally *not* imported by
the scan pipeline until M38 (heuristic/engine.py + --heuristic CLI flag).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Valid values for :attr:`HeuristicSignature.target_layer`.
VALID_TARGET_LAYERS: frozenset[str] = frozenset({"body", "headers", "both"})


@dataclass(frozen=True)
class HeuristicSignature:
    """A single heuristic pattern group.

    Frozen so registry entries cannot be mutated at runtime (ADR-020).
    Validation happens eagerly in :meth:`__post_init__` so that malformed
    patterns fail at import time rather than at scan time.
    """

    id: str
    category: str
    target_layer: str
    patterns: tuple[str, ...]
    base_confidence: float = 0.450

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise ValueError(f"id must be a non-empty string, got {self.id!r}")
        if not isinstance(self.category, str) or not self.category:
            raise ValueError(
                f"category must be a non-empty string, got {self.category!r}"
            )
        if self.target_layer not in VALID_TARGET_LAYERS:
            raise ValueError(
                f"target_layer must be one of {sorted(VALID_TARGET_LAYERS)}, "
                f"got {self.target_layer!r}"
            )
        if not isinstance(self.patterns, tuple) or not self.patterns:
            raise ValueError(
                f"patterns must be a non-empty tuple, got {self.patterns!r}"
            )
        for pattern in self.patterns:
            if not isinstance(pattern, str):
                raise ValueError(
                    f"pattern must be a string, got {type(pattern).__name__}: "
                    f"{pattern!r}"
                )
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(
                    f"invalid regex in signature {self.id!r}: {pattern!r}: {exc}"
                ) from exc
        if not isinstance(self.base_confidence, float):
            raise ValueError(
                f"base_confidence must be a float, got "
                f"{type(self.base_confidence).__name__}"
            )
        if not (0.0 <= self.base_confidence < 1.0):
            raise ValueError(
                f"base_confidence must be in [0.0, 1.0), got {self.base_confidence!r}"
            )


#: Initial signature seeds. HEUR-001 through HEUR-003 per M37 spec.
HEURISTIC_SIGNATURES: tuple[HeuristicSignature, ...] = (
    HeuristicSignature(
        id="HEUR-001",
        category="sqli:error_leak",
        target_layer="body",
        patterns=(
            r"SQL syntax.*?MySQL",
            r"Warning.*?\Wmysql_",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"ORA-\d{4,5}",
            r"PostgreSQL.*?ERROR",
            r"SQLite/JDBCDriver",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark after the character string",
        ),
    ),
    HeuristicSignature(
        id="HEUR-002",
        category="traversal:leak",
        target_layer="body",
        patterns=(
            r"root:x?:0:0:",
            r"\[boot loader\]",
            r"daemon:.*?:/usr/sbin",
        ),
    ),
    HeuristicSignature(
        id="HEUR-003",
        category="debug:disclosure",
        target_layer="both",
        patterns=(
            r"Traceback \(most recent call last\)",
            r"at [\w.$]+\([^)]*\.java:\d+\)",
            r"<b>Warning</b>:",
            r"Notice: .*? in /[^:]+\.php on line \d+",
        ),
    ),
)
