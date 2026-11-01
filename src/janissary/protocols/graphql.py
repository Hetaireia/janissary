"""GraphQL BaselineNormalizer (Phase 0.3 + FN-15).

Sits alongside HTTPNormalizer as the second BaselineNormalizer
implementation. GraphQL responses are JSON, but the JSON has
structure-specific volatile fields (extensions, resolver timings)
that generic body normalization cannot see. This module parses
the JSON, strips known-volatile structure, and re-serializes with
sorted keys.

Design source: docs/ROADMAP.md Phase 2.1 and docs/PHASE-6-PLAN.md FN-15.

Contract:
    GraphQLNormalizer().normalize(response) -> NormalizedResponse

Where `response` is duck-typed: any object with `.text` or `.body`
attribute, `.status_code` or `.status`, and `.headers` dict. The
same shapes HTTPNormalizer accepts.
"""
from __future__ import annotations

import json
from typing import Any

from .base import NormalizedResponse
from .http import HTTPNormalizer, _get_headers, _get_status, _get_text


_TIMING_KEYS = frozenset({
    "time",
    "duration",
    "elapsed",
    "elapsed_ms",
    "duration_ms",
    "timing",
    "startTime",
    "endTime",
})


def _sort_keys(obj: Any) -> Any:
    """Recursively sort dict keys. Lists preserve order (GraphQL data
    arrays are ordered; sorting them would lose meaning)."""
    if isinstance(obj, dict):
        return {k: _sort_keys(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_sort_keys(item) for item in obj]
    return obj


def _strip_extensions(obj: Any, stripped: list[str]) -> Any:
    """Remove `extensions` dicts at any level. Apollo Tracing and custom
    instrumentation attach timing/cost data here; it varies per response
    and is never the finding signal."""
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if k == "extensions" and isinstance(v, dict):
                if "body:extensions_stripped" not in stripped:
                    stripped.append("body:extensions_stripped")
                continue
            result[k] = _strip_extensions(v, stripped)
        return result
    if isinstance(obj, list):
        return [_strip_extensions(item, stripped) for item in obj]
    return obj


def _strip_timings(obj: Any, stripped: list[str]) -> Any:
    """Remove timing keys from any dict. GraphQL resolvers sometimes
    expose per-field timing outside the extensions convention."""
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if k in _TIMING_KEYS:
                if "body:timing_keys_stripped" not in stripped:
                    stripped.append("body:timing_keys_stripped")
                continue
            result[k] = _strip_timings(v, stripped)
        return result
    if isinstance(obj, list):
        return [_strip_timings(item, stripped) for item in obj]
    return obj


class GraphQLNormalizer:
    """BaselineNormalizer for GraphQL JSON responses.

    Parses the response as JSON, strips extensions and timing keys
    recursively, sorts keys recursively, re-serializes canonical form.
    Falls back to HTTPNormalizer for non-JSON bodies (HTML error pages,
    reverse-proxy errors) so CSRF stripping and whitespace collapse
    still apply.

    Note on `stripped`: it records only content that was *removed*
    (extensions, timing keys). Key sorting is a reordering, not a
    removal, so it is always applied silently. If a caller needs to
    know whether the body was reordered, they should compare the
    original response body to NormalizedResponse.body directly.
    """

    protocol_name = "graphql"

    def __init__(self) -> None:
        self._fallback = HTTPNormalizer()

    def normalize(self, response: Any) -> NormalizedResponse:
        text = _get_text(response)
        status = _get_status(response)
        headers = _get_headers(response)

        stripped: list[str] = []
        parsed: Any = None
        try:
            parsed = json.loads(text) if text.strip() else None
        except (ValueError, TypeError):
            parsed = None

        if parsed is None:
            # Non-JSON response. Delegate to HTTP normalizer; its stripped
            # list may include header/body CSRF redactions, which we merge.
            base = self._fallback.normalize(response)
            return NormalizedResponse(
                body=base.body,
                length=base.length,
                status=status,
                headers=base.headers,
                stripped=("body:non_json_fallback",) + base.stripped,
            )

        # JSON path: strip extensions, strip timings, sort keys.
        # Key sorting is a reordering, not a removal, so it is NOT
        # recorded in `stripped` (which is reserved for content that
        # was removed). The canonical body is always key-sorted.
        parsed = _strip_extensions(parsed, stripped)
        parsed = _strip_timings(parsed, stripped)
        sorted_parsed = _sort_keys(parsed)
        body = _canonical(sorted_parsed)

        return NormalizedResponse(
            body=body,
            length=len(body),
            status=status,
            headers=headers,
            stripped=tuple(stripped),
        )


def _canonical(obj: Any) -> str:
    """Deterministic JSON serialization for comparison and output."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
