"""Family-neutral append-only evidence recorder for scanner probe attempts.

The recorder stores request-attempt metadata and oracle evaluations without
capturing response bodies or changing scanner/detector behaviour.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SCHEMA_VERSION = 1
_CASE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_ORACLE_RESULTS = {"finding", "no_finding", "indeterminate"}
_REQUEST_OUTCOMES = {
    "response",
    "exception",
    "none_response",
    "not_attempted",
}


@dataclass
class ProbeEvidenceDiagnostics:
    """Write diagnostics for one recorder instance."""

    records_attempted: int = 0
    records_written: int = 0
    failures_total: int = 0
    failure_log_written: bool = False
    failure_log_broken: bool = False


class ProbeEvidenceRecorder:
    """Append request-attempt and oracle-evaluation evidence as JSONL."""

    def __init__(
        self,
        *,
        case_id: str,
        raw_path: Path,
        failure_path: Path,
    ) -> None:
        if not isinstance(case_id, str) or not _CASE_ID_RE.fullmatch(case_id):
            raise ValueError(f"unsanitized case_id: {case_id!r}")

        self.case_id = case_id
        self.raw_path = Path(raw_path)
        self.failure_path = Path(failure_path)
        self.run_id = uuid.uuid4().hex
        self.diagnostics = ProbeEvidenceDiagnostics()
        self._event_counter = 0
        self._attempt_counter = 0

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _probe_id(
        self,
        *,
        param: str,
        payload_name: str,
        payload_value: str,
    ) -> str:
        identity = {
            "case_id": self.case_id,
            "param": param,
            "payload_name": payload_name,
            "payload_sha256": self._digest(payload_value),
        }
        canonical = json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return "probe_" + self._digest(canonical)[:24]

    def _next_event_id(self) -> str:
        self._event_counter += 1
        return f"evt_{self.run_id}_{self._event_counter:06d}"

    def _next_attempt_id(self) -> str:
        self._attempt_counter += 1
        return f"attempt_{self.run_id}_{self._attempt_counter:06d}"

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _append_failure(self, failure: dict[str, Any]) -> None:
        try:
            self.failure_path.parent.mkdir(parents=True, exist_ok=True)
            with self.failure_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(failure, sort_keys=True, ensure_ascii=False) + "\n"
                )
            self.diagnostics.failure_log_written = True
        except Exception:
            self.diagnostics.failure_log_broken = True

    def _append_event(self, event: dict[str, Any]) -> str | None:
        """Append an event, returning None if persistence fails."""
        event_id = str(event["event_id"])
        self.diagnostics.records_attempted += 1

        try:
            serialized = json.dumps(
                event,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            self.raw_path.parent.mkdir(parents=True, exist_ok=True)
            with self.raw_path.open("a", encoding="utf-8") as handle:
                handle.write(serialized + "\n")
            self.diagnostics.records_written += 1
        except Exception as exc:
            self.diagnostics.failures_total += 1
            self._append_failure(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "case_id": self.case_id,
                    "run_id": self.run_id,
                    "event_id": event_id,
                    "event_type": event.get("event_type"),
                    "failure_type": type(exc).__name__,
                    "failure_message": str(exc)[:500],
                    "occurred_at": self._timestamp(),
                }
            )
            return None

        return event_id

    def record_probe_attempt(
        self,
        *,
        param: str,
        payload_name: str,
        payload_value: str,
        request_outcome: str,
        request_attempted: bool = True,
        response_status: int | None = None,
        snapshot_captured: bool = False,
        failure_reason: str | None = None,
        parent_event_id: str | None = None,
        attempt_role: str = "initial",
        used_for_snapshot: bool = False,
    ) -> str | None:
        """Record one actual or explicitly unattempted HTTP request attempt.

        The payload itself is not persisted. Its SHA-256 digest contributes to
        the stable logical probe identity.
        """
        if not isinstance(request_attempted, bool):
            raise TypeError("request_attempted must be a boolean")
        if not isinstance(snapshot_captured, bool):
            raise TypeError("snapshot_captured must be a boolean")
        if not isinstance(used_for_snapshot, bool):
            raise TypeError("used_for_snapshot must be a boolean")
        if request_outcome not in _REQUEST_OUTCOMES:
            raise ValueError(f"invalid request_outcome: {request_outcome!r}")
        if not request_attempted and request_outcome != "not_attempted":
            raise ValueError(
                "request_outcome must be 'not_attempted' when no request was sent"
            )
        if request_attempted and request_outcome == "not_attempted":
            raise ValueError(
                "request_outcome cannot be 'not_attempted' when a request was sent"
            )
        if request_outcome == "response" and response_status is None:
            raise ValueError("response outcome requires a response_status")
        if request_outcome != "response" and response_status is not None:
            raise ValueError("non-response outcome cannot have a response_status")
        if snapshot_captured and request_outcome != "response":
            raise ValueError("snapshot cannot be captured without a response")
        if used_for_snapshot and not snapshot_captured:
            raise ValueError("snapshot cannot be used unless it was captured")
        if not isinstance(param, str):
            raise TypeError("param must be a string")
        if not isinstance(payload_name, str):
            raise TypeError("payload_name must be a string")
        if not isinstance(payload_value, str):
            raise TypeError("payload_value must be a string")
        if response_status is not None and (
            isinstance(response_status, bool) or not isinstance(response_status, int)
        ):
            raise TypeError("response_status must be an integer or None")
        if not isinstance(attempt_role, str) or not attempt_role:
            raise ValueError("attempt_role must be a non-empty string")

        event_id = self._next_event_id()
        attempt_id = self._next_attempt_id()
        event = {
            "schema_version": _SCHEMA_VERSION,
            "event_type": "probe_attempt",
            "event_id": event_id,
            "case_id": self.case_id,
            "run_id": self.run_id,
            "recorded_at": self._timestamp(),
            "param": param,
            "probe_id": self._probe_id(
                param=param,
                payload_name=payload_name,
                payload_value=payload_value,
            ),
            "attempt_id": attempt_id,
            "parent_event_id": parent_event_id,
            "attempt_role": attempt_role,
            "payload_name": payload_name,
            "payload_sha256": self._digest(payload_value),
            "request_attempted": request_attempted,
            "request_outcome": request_outcome,
            "response_received": request_outcome == "response",
            "response_status": response_status,
            "snapshot_captured": snapshot_captured,
            "used_for_snapshot": used_for_snapshot,
            "failure_reason": failure_reason,
        }
        return self._append_event(event)

    def record_oracle_evaluation(
        self,
        *,
        oracle_id: str,
        param: str,
        prerequisite_event_ids: dict[str, str | None],
        oracle_evaluated: bool,
        oracle_result: str,
        indeterminate_reason: str | None = None,
        finding_count: int = 0,
    ) -> str | None:
        """Record an oracle result and the exact attempt events it consumed."""
        if not isinstance(oracle_id, str) or not oracle_id:
            raise ValueError("oracle_id must be a non-empty string")
        if not isinstance(param, str):
            raise TypeError("param must be a string")
        if oracle_result not in _ORACLE_RESULTS:
            raise ValueError(f"invalid oracle_result: {oracle_result!r}")
        if not isinstance(oracle_evaluated, bool):
            raise TypeError("oracle_evaluated must be a boolean")
        if (
            isinstance(finding_count, bool)
            or not isinstance(finding_count, int)
            or finding_count < 0
        ):
            raise ValueError("finding_count must be a non-negative integer")
        if not isinstance(prerequisite_event_ids, dict):
            raise TypeError("prerequisite_event_ids must be a dictionary")
        if any(
            not isinstance(key, str)
            or (value is not None and not isinstance(value, str))
            for key, value in prerequisite_event_ids.items()
        ):
            raise TypeError("prerequisite event names and IDs must be strings or None")
        if oracle_evaluated and oracle_result == "indeterminate":
            raise ValueError("an evaluated oracle cannot have an indeterminate result")
        if not oracle_evaluated and oracle_result != "indeterminate":
            raise ValueError("an unevaluated oracle must have an indeterminate result")
        if oracle_result == "finding" and finding_count < 1:
            raise ValueError("a finding result requires finding_count >= 1")
        if oracle_result != "finding" and finding_count != 0:
            raise ValueError("finding_count must be zero when no finding was returned")
        if oracle_result == "indeterminate" and not indeterminate_reason:
            raise ValueError("an indeterminate result requires a reason")

        event = {
            "schema_version": _SCHEMA_VERSION,
            "event_type": "oracle_evaluation",
            "event_id": self._next_event_id(),
            "case_id": self.case_id,
            "run_id": self.run_id,
            "recorded_at": self._timestamp(),
            "oracle_id": oracle_id,
            "param": param,
            "prerequisite_event_ids": dict(prerequisite_event_ids),
            "oracle_evaluated": oracle_evaluated,
            "oracle_result": oracle_result,
            "indeterminate_reason": indeterminate_reason,
            "finding_count": finding_count,
        }
        return self._append_event(event)

    def diagnostics_dict(self) -> dict[str, Any]:
        """Return a detached diagnostics snapshot."""
        return asdict(self.diagnostics)
