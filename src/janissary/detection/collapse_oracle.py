"""Traversal collapse oracle (ADR-006, Phase 1.3d).

Pure. No I/O. Consumes the arming state from baseline_struct (ADR-004)
and the payload response. Emits a traversal_collapse finding only when
min_dist > 20 AND at least one auxiliary signal fires.

Signal definitions per ADR-006 D1 (with the D1 sub-tightening added
2026-10-26: tiny_body requires body to contain ":" or "/").
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from janissary.detection.analyzer import Baseline, ResponseSnapshot
from janissary.engine.baseline_struct import BaselineArmingState
from janissary.engine.dom_hash import fingerprint, hamming

MAX_COLLAPSE_DIST: int = 20
TINY_BODY_FRACTION: float = 0.10
MARKERS: tuple[str, ...] = (
    "root:",
    "daemon:",
    "/bin/",
    "/etc/",
    "/usr/",
    "127.0.0.1",
)
PASSWD_RE = re.compile(r"^root:[^:]*:\d+:\d+:", re.MULTILINE)
SHADOW_RE = re.compile(r"^root:[^:]*:\d+:", re.MULTILINE)
HOSTS_RE = re.compile(r"^127\.0\.0\.1\s+localhost", re.MULTILINE)


@dataclass(frozen=True)
class CollapseVerdict:
    """Result of the collapse classifier. Reason is the priority winner."""

    emit: bool
    reason: str | None
    min_distance: int | None
    aux_signals: tuple[str, ...]


def _baseline_mean_length(baseline: Baseline) -> float:
    bodies = [s.body for s in baseline.snapshots if s.body]
    if not bodies:
        return 0.0
    return sum(len(b) for b in bodies) / len(bodies)


def _aux_tiny_body(body: str, baseline_mean: float, status: int) -> bool:
    if not (200 <= status < 500):
        return False
    if baseline_mean <= 0:
        return False
    if len(body) >= TINY_BODY_FRACTION * baseline_mean:
        return False
    return ":" in body or "/" in body


def _aux_no_markup(body: str) -> bool:
    if "<" in body:
        return False
    lower = body.lower()
    return any(m in lower for m in MARKERS)


def _aux_known_file_sig(body: str) -> bool:
    return bool(
        PASSWD_RE.search(body) or SHADOW_RE.search(body) or HOSTS_RE.search(body)
    )


def _classify_collapse(
    *,
    baseline: Baseline,
    arming: BaselineArmingState,
    snapshot: ResponseSnapshot,
    response_status: int,
) -> CollapseVerdict:
    if not arming.armed or not arming.fingerprints:
        return CollapseVerdict(False, None, None, ())

    body = snapshot.body or ""
    payload_fp = fingerprint(body)
    if payload_fp.shingle_count == 0:
        return CollapseVerdict(False, None, None, ())

    min_dist = min(hamming(fp, payload_fp.value) for fp in arming.fingerprints)
    if min_dist <= MAX_COLLAPSE_DIST:
        return CollapseVerdict(False, None, min_dist, ())

    mean_len = _baseline_mean_length(baseline)
    signals: list[str] = []
    if _aux_no_markup(body):
        signals.append("collapse_no_markup")
    if _aux_known_file_sig(body):
        signals.append("collapse_known_file")
    if _aux_tiny_body(body, mean_len, response_status):
        signals.append("collapse_tiny_body")

    if not signals:
        return CollapseVerdict(False, None, min_dist, ())
    return CollapseVerdict(True, signals[0], min_dist, tuple(signals))


def check_traversal_collapse_oracle(
    *,
    baseline: Baseline,
    arming: BaselineArmingState,
    snapshot: ResponseSnapshot,
    response_status: int,
    payload_value: str,
    payload_name: str,
) -> list[dict]:
    """Return zero or one finding dict. Pure. No I/O.

    ``payload_value`` and ``payload_name`` are included in the returned
    finding for traceability but do not gate the decision (ADR-006 D1
    sub-note: fire on any payload when armed).
    """
    verdict = _classify_collapse(
        baseline=baseline,
        arming=arming,
        snapshot=snapshot,
        response_status=response_status,
    )
    if not verdict.emit:
        return []
    return [
        {
            "type": "traversal_collapse",
            "category": "traversal",
            "severity": "critical",
            "reason": verdict.reason,
            "aux_signals": list(verdict.aux_signals),
            "min_distance": verdict.min_distance,
            "detail": (
                f"Structural collapse (min_dist={verdict.min_distance}): "
                f"{verdict.reason} via {payload_name}={payload_value[:40]!r}"
            ),
        }
    ]
