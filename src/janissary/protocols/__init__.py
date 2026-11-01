"""Protocol adapters - baseline normalizers (Phase 0.3).

See docs/ROADMAP.md Phase 0.3.
"""
from .base import BaselineNormalizer, NormalizedResponse
from .http import HTTPNormalizer

__all__ = [
    "BaselineNormalizer",
    "HTTPNormalizer",
    "NormalizedResponse",
]