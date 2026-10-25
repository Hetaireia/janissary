"""Structural gating helpers for admin probe (ADR-005, Phase 1.3c).

Pure helpers: no requests, no side effects.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from janissary.detection import normalize_body
from janissary.engine.dom_hash import StructuralFingerprint, fingerprint, hamming

if TYPE_CHECKING:
    import requests

SPA_CATCHALL_REASON = "spa_catchall_admin"
MAX_HAMMING = 3
SIGNATURE_BYTES = 4096


@dataclass(frozen=True)
class DiscardVerdict:
    discard: bool
    reason: str | None
    hamming: int | None
    root_signature_match: bool | None


def compute_root_state(
    home: requests.Response | None,
) -> tuple[StructuralFingerprint | None, str | None, str]:
    if home is None or home.status_code != 200:
        return None, None, "disabled_no_root"
    ct = (home.headers.get("content-type") or "").lower()
    if "text/html" not in ct:
        return None, None, "disabled_no_html_root"
    body = home.text or ""
    if not body.strip():
        return None, None, "disabled_no_html_root"
    fp = fingerprint(body)
    if fp.shingle_count == 0:
        return None, None, "disabled_no_html_root"
    sig = hashlib.sha256(
        normalize_body(body).encode("utf-8", errors="ignore")[:SIGNATURE_BYTES]
    ).hexdigest()
    return fp, sig, "enabled"


def should_discard_admin_hit(
    *,
    response_text: str,
    response_content_type: str,
    root_fingerprint: StructuralFingerprint,
    root_signature_hex: str,
) -> DiscardVerdict:
    ct = (response_content_type or "").lower()
    if "text/html" not in ct:
        return DiscardVerdict(False, None, None, None)
    body = response_text or ""
    body_fp = fingerprint(body)
    if body_fp.shingle_count == 0:
        return DiscardVerdict(False, None, None, None)
    dist = hamming(body_fp.value, root_fingerprint.value)
    if dist > MAX_HAMMING:
        return DiscardVerdict(False, None, dist, None)
    sig = hashlib.sha256(
        normalize_body(body).encode("utf-8", errors="ignore")[:SIGNATURE_BYTES]
    ).hexdigest()
    sig_match = sig == root_signature_hex
    if not sig_match:
        return DiscardVerdict(False, None, dist, False)
    return DiscardVerdict(True, SPA_CATCHALL_REASON, dist, True)
