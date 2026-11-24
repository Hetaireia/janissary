"""Self-Referential Normalization Probe for path-traversal (ADR-036 Phase 3)."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from janissary.detection.pathtraver_reflection_guard import is_payload_reflected

_DYNAMIC_TOKEN_RE = re.compile(
    r"(?:nonce|csrf[_-]?token|request[_-]?id|trace[_-]?id|timestamp)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9._-]{8,}"
    r"|(?<=['\"=])(?:[0-9a-f]{32,64}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=['\"=])",
    re.IGNORECASE,
)


def _normalize_body_for_comparison(body: str) -> str:
    """Strip dynamic tokens and normalize whitespace for hash comparison."""
    if not body:
        return ""
    normalized = _DYNAMIC_TOKEN_RE.sub("<DYNAMIC_TOKEN>", body)
    return re.sub(r"\s+", " ", normalized).strip()


def _compute_normalized_hash(body: str) -> str:
    """Compute SHA-256 hash of normalized body."""
    normalized = _normalize_body_for_comparison(body)
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()


def check_normalization_probe(
    *,
    probe_payload: str,
    existing_asset_response: dict[str, Any],
    self_referential_response: dict[str, Any],
    nonexistent_canary_response: dict[str, Any],
    baseline_response: dict[str, Any],
) -> bool:
    """Return True iff self-referential probe satisfies the ADR-036 M89 contract."""
    if not all(
        [
            probe_payload,
            existing_asset_response,
            self_referential_response,
            nonexistent_canary_response,
            baseline_response,
        ]
    ):
        return False

    if existing_asset_response.get("status_code") != 200:
        return False
    if self_referential_response.get("status_code") != 200:
        return False

    self_ref_body = self_referential_response.get("body", "")
    if not self_ref_body or is_payload_reflected(probe_payload, self_ref_body):
        return False

    asset_hash = _compute_normalized_hash(existing_asset_response.get("body", ""))
    self_ref_hash = _compute_normalized_hash(self_ref_body)
    canary_hash = _compute_normalized_hash(nonexistent_canary_response.get("body", ""))
    baseline_hash = _compute_normalized_hash(baseline_response.get("body", ""))

    # Self-referential probe must reproduce the known asset while canary stays distinct
    return (
        self_ref_hash == asset_hash
        and (
            nonexistent_canary_response.get("status_code") != 200
            or canary_hash != asset_hash
        )
        and (
            self_ref_hash != baseline_hash
            or baseline_response.get("status_code") != 200
        )
    )


def build_self_referential_probe(payload: str) -> str | None:
    """Return a probe naming the payload last segment twice, or None.

    The probe is ``<payload><sep>..<sep><last>``, which resolves back to
    the same asset on a server that normalizes the path textually and
    fails on one that does not. None when there is no separator to
    build the double reference on.
    """
    if not payload:
        return None
    cut = max(payload.rfind("/"), payload.rfind("\\"))
    if cut <= 0 or cut == len(payload) - 1:
        return None
    sep = payload[cut]
    last = payload[cut + 1 :]
    return payload + sep + ".." + sep + last
