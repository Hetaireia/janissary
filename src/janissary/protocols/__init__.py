"""Protocol adapters - baseline normalizers (Phase 0.3).

See docs/ROADMAP.md Phase 0.3.
"""
from .base import BaselineNormalizer, NormalizedResponse
from .graphql import GraphQLNormalizer
from .http import HTTPNormalizer

__all__ = [
    "BaselineNormalizer",
    "GraphQLNormalizer",
    "HTTPNormalizer",
    "NormalizedResponse",
]