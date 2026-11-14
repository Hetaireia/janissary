"""M83 path traversal per-case recorder.

Implements the recording side of the M83 design: captures each
path-traversal oracle observation to a per-case JSONL file, with
structural signatures, evidence hashes, and re-derived classification.

Design: docs/m83_gate_d_proposal.md
Scope: docs/m83_scope.md
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from janissary.detection import analyzer

BODY_STORE_LIMIT = 4096

_UUID_V4_RE = re.compile(
    r"(?<![A-Za-z0-9_])[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![A-Za-z0-9_])",
    re.IGNORECASE,
)

_HEX_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])[0-9a-f]{32,64}(?![A-Za-z0-9_])",
    re.IGNORECASE,
)

_B64_MARKER_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<marker>(?:value|token|id|nonce|csrf|session)=[\"']?)"
    r"(?P<b64>[A-Za-z0-9+/]{20,}={0,2})"
    r"(?P<close>[\"']?)",
    re.IGNORECASE,
)

_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _evidence_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()


def _structural_signature(body: str, content_type: str = "") -> str:
    s = re.sub(r"\s+", " ", body).strip()
    s = _UUID_V4_RE.sub("<UUID>", s)
    s = _HEX_TOKEN_RE.sub("<HEX>", s)
    s = _B64_MARKER_RE.sub(r"\g<marker><B64>\g<close>", s)
    if "html" in content_type.lower():
        try:
            from selectolax.parser import HTMLParser

            tree = HTMLParser(s)
            s = tree.text() or ""
        except Exception:
            s = _HTML_TAG_RE.sub("", s)
        s = re.sub(r"\s+", " ", s).strip()
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()


def _sanitize_case_id(testname: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", testname)
    if not safe:
        return "_"
    if len(safe) > 64:
        digest = hashlib.sha256(testname.encode("utf-8")).hexdigest()[:8]
        safe = safe[:55] + "_" + digest
    return safe


@dataclass
class RecorderDiagnostics:
    records_attempted: int = 0
    records_written: int = 0
    failures_total: int = 0
    failure_log_written: bool = False
    failure_log_broken: bool = False


def _derive_classification(
    *,
    baseline: Any,
    snapshot_exists: Any,
    snapshot_noexist: Any,
    payload_exists: str,
    payload_noexist: str,
    oracle_result: list[dict],
) -> tuple[str, str]:
    """Reconstruct which silent branch fired, mirroring the oracle logic."""
    if len(oracle_result) > 0:
        return (
            "existence_divergence",
            oracle_result[0].get("detail", "existence divergence"),
        )

    for pv in (payload_exists, payload_noexist):
        if analyzer._PATHTRAVER_EXISTS.search(pv or ""):
            return ("inconclusive", "payload leakage: exists pattern in payload")
        if analyzer._PATHTRAVER_NOEXIST.search(pv or ""):
            return ("inconclusive", "payload leakage: noexist pattern in payload")

    for s in baseline.snapshots or []:
        if analyzer._PATHTRAVER_EXISTS.search(s.body or ""):
            return (
                "inconclusive",
                "baseline poisoned: baseline snapshot carries exists-signal",
            )

    sig_a = analyzer._pathtraver_signal(snapshot_exists.body or "")
    sig_b = analyzer._pathtraver_signal(snapshot_noexist.body or "")
    if sig_a is None:
        return ("inconclusive", "signal extraction failed: exists probe")
    if sig_b is None:
        return ("inconclusive", "signal extraction failed: noexist probe")
    if sig_a == sig_b:
        return (
            "no_observable_divergence",
            f"both probes reported '{sig_a}'",
        )
    return (
        "inconclusive",
        "recorder could not reconstruct branch: signals differ but oracle silent",
    )


class PathtraverRecorder:
    def __init__(
        self,
        case_id: str,
        raw_path: Path,
        failure_path: Path,
    ) -> None:
        if not case_id or _sanitize_case_id(case_id) != case_id:
            raise ValueError(
                f"case_id must be non-empty and pre-sanitized: "
                f"got {case_id!r}, expected {_sanitize_case_id(case_id)!r}"
            )
        self.case_id = case_id
        self._raw_path = Path(raw_path)
        self._failure_path = Path(failure_path)
        self._diagnostics = RecorderDiagnostics()
        self._observation_counter = 0

    @property
    def diagnostics(self) -> RecorderDiagnostics:
        return self._diagnostics

    def record(
        self,
        *,
        url: str,
        param: str,
        baseline: Any,
        snapshot_exists: Any,
        snapshot_noexist: Any,
        payload_exists: str,
        payload_noexist: str,
        oracle_result: list[dict],
    ) -> None:
        self._diagnostics.records_attempted += 1
        self._observation_counter += 1
        observation_id = f"{self.case_id}_obs{self._observation_counter:04d}"

        try:
            record = self._build_record(
                observation_id=observation_id,
                url=url,
                param=param,
                baseline=baseline,
                snapshot_exists=snapshot_exists,
                snapshot_noexist=snapshot_noexist,
                payload_exists=payload_exists,
                payload_noexist=payload_noexist,
                oracle_result=oracle_result,
            )
            with self._raw_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
            self._diagnostics.records_written += 1
        except Exception as exc:
            self._diagnostics.failures_total += 1
            self._record_failure_safe(url=url, param=param, exception=repr(exc))

    def _record_failure_safe(self, *, url: str, param: str, exception: str) -> None:
        try:
            with self._failure_path.open("a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(
                        {
                            "case_id": self.case_id,
                            "url": url,
                            "param": param,
                            "exception": exception,
                        }
                    )
                    + "\n"
                )
            self._diagnostics.failure_log_written = True
        except Exception:
            self._diagnostics.failure_log_broken = True

    def _build_record(
        self,
        *,
        observation_id: str,
        url: str,
        param: str,
        baseline: Any,
        snapshot_exists: Any,
        snapshot_noexist: Any,
        payload_exists: str,
        payload_noexist: str,
        oracle_result: list[dict],
    ) -> dict:
        exists_body = snapshot_exists.body or ""
        noexist_body = snapshot_noexist.body or ""
        exists_ct = getattr(snapshot_exists, "content_type", "") or ""
        noexist_ct = getattr(snapshot_noexist, "content_type", "") or ""
        sig_exists = _structural_signature(exists_body, exists_ct)
        sig_noexist = _structural_signature(noexist_body, noexist_ct)
        classification, reason = _derive_classification(
            baseline=baseline,
            snapshot_exists=snapshot_exists,
            snapshot_noexist=snapshot_noexist,
            payload_exists=payload_exists,
            payload_noexist=payload_noexist,
            oracle_result=oracle_result,
        )
        return {
            "observation_id": observation_id,
            "case_id": self.case_id,
            "url": url,
            "param": param,
            "delivery": {
                "request_path": url,
                "payload_verbatim": payload_exists,
                "payload_noexist": payload_noexist,
            },
            "baseline": {
                "snapshot_count": len(baseline.snapshots or []),
                "modal_status": getattr(baseline, "modal_status", None),
            },
            "probes": {
                "exists": {
                    "status": getattr(snapshot_exists, "status", None),
                    "content_type": exists_ct,
                    "evidence_hash": _evidence_hash(exists_body),
                    "structural_signature": sig_exists,
                    "body_truncated": len(exists_body) > BODY_STORE_LIMIT,
                    "body_original_length": len(exists_body),
                    "body_stored": exists_body[:BODY_STORE_LIMIT],
                },
                "noexist": {
                    "status": getattr(snapshot_noexist, "status", None),
                    "content_type": noexist_ct,
                    "evidence_hash": _evidence_hash(noexist_body),
                    "structural_signature": sig_noexist,
                    "body_truncated": len(noexist_body) > BODY_STORE_LIMIT,
                    "body_original_length": len(noexist_body),
                    "body_stored": noexist_body[:BODY_STORE_LIMIT],
                },
            },
            "comparison": {"structural_diff": sig_exists != sig_noexist},
            "classification": classification,
            "classification_reason": reason,
            "oracle_fired": len(oracle_result) > 0,
        }
