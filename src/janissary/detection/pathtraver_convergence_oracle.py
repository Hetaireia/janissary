"""Depth-Invariant Convergence Oracle for path-traversal (ADR-036 Phase 4)."""

from __future__ import annotations

from typing import Any

from janissary.detection.pathtraver_normalization_probe import _compute_normalized_hash
from janissary.detection.pathtraver_reflection_guard import is_payload_reflected


def check_convergence_oracle(
    *,
    payload_n: str,
    payload_n_plus_1: str,
    depth_n_minus_1_response: dict[str, Any],
    depth_n_response: dict[str, Any],
    depth_n_plus_1_response: dict[str, Any],
    nonexistent_canary_response: dict[str, Any],
) -> bool:
    """Return True iff root-clamping convergence satisfies the ADR-036 M89 contract."""
    if not all(
        [
            payload_n,
            payload_n_plus_1,
            depth_n_minus_1_response,
            depth_n_response,
            depth_n_plus_1_response,
            nonexistent_canary_response,
        ]
    ):
        return False

    status_n = depth_n_response.get("status_code")
    status_next = depth_n_plus_1_response.get("status_code")
    if not isinstance(status_n, int) or status_n >= 500 or status_n != status_next:
        return False

    body_n = depth_n_response.get("body", "")
    body_next = depth_n_plus_1_response.get("body", "")
    if (
        not body_n
        or is_payload_reflected(payload_n, body_n)
        or is_payload_reflected(payload_n_plus_1, body_next)
    ):
        return False

    hash_prev = _compute_normalized_hash(depth_n_minus_1_response.get("body", ""))
    hash_n = _compute_normalized_hash(body_n)
    hash_next = _compute_normalized_hash(body_next)
    hash_canary = _compute_normalized_hash(nonexistent_canary_response.get("body", ""))

    return (
        hash_n == hash_next
        and hash_n != hash_prev
        and (
            hash_n != hash_canary
            or status_n != nonexistent_canary_response.get("status_code")
        )
    )
