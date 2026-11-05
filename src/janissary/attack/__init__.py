"""Active exploitation primitives.

This package is architecturally separate from `detection` on purpose.
Detection identifies; attack extracts. Keeping them in separate
packages makes the distinction explicit in the code layout, which
supports the good-faith-research framing in LEGAL.md.

Every module in this package is destructive-adjacent. Every CLI
entry point into it must require an explicit --attack-confirm flag
in addition to the Terms-of-Use gate.
"""

from .nuclei import (
    NucleiError,
    NucleiFinding,
    NucleiNotFound,
    NucleiRun,
    NucleiRunner,
    parse_nuclei_line,
)
from .sqli_union import (
    AttackConfirmationRequired,
    ExtractionResult,
    ExtractionStep,
    UnionExtractor,
    UnstableTargetError,
    build_union_payload,
    detect_dbms,
    split_concat,
)

__all__ = [
    "AttackConfirmationRequired",
    "ExtractionResult",
    "ExtractionStep",
    "NucleiError",
    "NucleiFinding",
    "NucleiNotFound",
    "NucleiRun",
    "NucleiRunner",
    "UnionExtractor",
    "UnstableTargetError",
    "build_union_payload",
    "detect_dbms",
    "parse_nuclei_line",
    "split_concat",
]
