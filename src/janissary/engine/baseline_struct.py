"""Structural arming logic for the DOM-hash corroborator (Phase 1.3b).

Pure functions; no I/O; no Scanner dependency. See ADR-004.

Public API:
    compute_arming_state(baseline: Baseline) -> BaselineArmingState

The state is computed from ``Baseline.snapshots`` — the same list
``Scanner.collect_baseline`` already populates — and adds zero requests.

Exceptions from ``dom_hash.fingerprint`` (malformed HTML that Lexbor
refuses to parse) are not caught here. If a body reaches this module with
content type ``text/html``, the corresponding request already succeeded;
a parse failure should surface as a bug, not be silently absorbed. 1.3c
decides whether to add per-sample resilience at the call site.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from enum import Enum

from janissary.detection import Baseline, ResponseSnapshot
from janissary.detection.analyzer import normalize_body
from janissary.engine.dom_hash import fingerprint as dom_fingerprint
from janissary.engine.dom_hash import hamming

MIN_ARMING_SAMPLES: int = 3
MAX_ARMING_HAMMING: int = 3
ROOT_SIGNATURE_BYTES: int = 4096


class ArmingReason(str, Enum):
    """Why a baseline is or is not structurally armed."""

    ARMED = "armed"
    UNARMED_NO_HTML_SAMPLES = "unarmed_no_html_samples"
    UNARMED_INSUFFICIENT_SAMPLES = "unarmed_insufficient_samples"
    UNARMED_EMPTY_SKELETON = "unarmed_empty_skeleton"
    UNARMED_DISPERSION = "unarmed_dispersion"


@dataclass(frozen=True)
class BaselineArmingState:
    """Immutable per-(param, scan) arming decision.

    ``armed`` is the gate toggle consumed by 1.3c.
    ``reason`` is a machine-readable enum, stable across releases.
    ``fingerprints`` is one 64-bit SimHash value per HTML sample, in input
    order. ``root_signature`` is the SHA-256 hex of the canonicalized root
    body truncated to ``ROOT_SIGNATURE_BYTES``, or ``None`` when no unique
    mode exists. ``sample_count`` is ``len(fingerprints)``. ``hamming_max``
    is the maximum pairwise Hamming distance between fingerprints; 0 for
    fewer than two samples.
    """

    armed: bool
    reason: ArmingReason
    fingerprints: tuple[int, ...]
    root_signature: str | None
    sample_count: int
    hamming_max: int


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _is_html(content_type: str | None) -> bool:
    if not content_type:
        return False
    media = content_type.split(";", 1)[0].strip().lower()
    return media == "text/html"


def _html_snapshots(baseline: Baseline) -> list[ResponseSnapshot]:
    return [s for s in baseline.snapshots if _is_html(s.content_type)]


def _max_pairwise_hamming(fingerprints: list[int]) -> int:
    if len(fingerprints) < 2:
        return 0
    m = 0
    for i in range(len(fingerprints)):
        for j in range(i + 1, len(fingerprints)):
            d = hamming(fingerprints[i], fingerprints[j])
            if d > m:
                m = d
    return m


def _root_signature_from(snapshots: list[ResponseSnapshot]) -> str | None:
    if not snapshots:
        return None
    counts = Counter(s.fingerprint for s in snapshots)
    top = counts.most_common()
    if not top:
        return None
    if len(top) >= 2 and top[0][1] == top[1][1]:
        # Ambiguous mode (top-two tie): no canonical root.
        return None
    mode_fp, mode_count = top[0]
    if mode_count < 2:
        return None
    for s in snapshots:
        if s.fingerprint == mode_fp:
            normalized = normalize_body(s.body)
            payload = normalized.encode("utf-8", errors="ignore")[:ROOT_SIGNATURE_BYTES]
            return hashlib.sha256(payload).hexdigest()
    return None  # unreachable: mode_fp came from a snapshot


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def compute_arming_state(baseline: Baseline) -> BaselineArmingState:
    """Decide whether the structural gate is armed for this baseline.

    Pure. Does not mutate ``baseline``. Makes no network calls.

    See ADR-004 §D6 for the precedence of ``reason`` codes.
    """
    html = _html_snapshots(baseline)
    sample_count = len(html)

    if sample_count == 0:
        return BaselineArmingState(
            armed=False,
            reason=ArmingReason.UNARMED_NO_HTML_SAMPLES,
            fingerprints=(),
            root_signature=None,
            sample_count=0,
            hamming_max=0,
        )

    fingerprints: list[int] = []
    shingle_counts: list[int] = []
    for s in html:
        fp = dom_fingerprint(s.body)
        fingerprints.append(fp.value)
        shingle_counts.append(fp.shingle_count)

    if sample_count < MIN_ARMING_SAMPLES:
        return BaselineArmingState(
            armed=False,
            reason=ArmingReason.UNARMED_INSUFFICIENT_SAMPLES,
            fingerprints=tuple(fingerprints),
            root_signature=None,
            sample_count=sample_count,
            hamming_max=_max_pairwise_hamming(fingerprints),
        )

    if any(c == 0 for c in shingle_counts):
        return BaselineArmingState(
            armed=False,
            reason=ArmingReason.UNARMED_EMPTY_SKELETON,
            fingerprints=tuple(fingerprints),
            root_signature=None,
            sample_count=sample_count,
            hamming_max=_max_pairwise_hamming(fingerprints),
        )

    hmax = _max_pairwise_hamming(fingerprints)
    if hmax > MAX_ARMING_HAMMING:
        return BaselineArmingState(
            armed=False,
            reason=ArmingReason.UNARMED_DISPERSION,
            fingerprints=tuple(fingerprints),
            root_signature=None,
            sample_count=sample_count,
            hamming_max=hmax,
        )

    return BaselineArmingState(
        armed=True,
        reason=ArmingReason.ARMED,
        fingerprints=tuple(fingerprints),
        root_signature=_root_signature_from(html),
        sample_count=sample_count,
        hamming_max=hmax,
    )
