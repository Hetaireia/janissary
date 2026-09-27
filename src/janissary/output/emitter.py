"""Machine-readable output for JANISSARY (schema v1.0).

Contract:
  * stdout carries the machine payload when --json/--jsonl is set.
  * stderr carries every human-facing status line.
  * --quiet silences stderr only; it never affects stdout.
  * --export is orthogonal: it writes a document to disk and does not
    touch stdout.

Callers route logging to stderr themselves when format != HUMAN.
"""

from __future__ import annotations

import json
import sys
import uuid
from collections.abc import Mapping
from dataclasses import asdict, is_dataclass
from datetime import date, datetime, timezone
from enum import Enum
from pathlib import Path
from typing import IO, Any

SCHEMA_VERSION = "1.0"
TOOL_NAME = "janissary"

# Always present in the serialized finding, even when the value is None, so
# consumers can rely on their presence.
_REQUIRED_FINDING_KEYS = frozenset(
    {
        "id",
        "class",
        "title",
        "severity",
        "url",
        "method",
        "raw_request",
        "raw_response",
    }
)


class OutputFormat(str, Enum):
    HUMAN = "human"
    JSON = "json"
    JSONL = "jsonl"


def add_output_flags(parser) -> None:
    """Attach --json / --jsonl to a subparser (mutually exclusive)."""
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--json",
        dest="output_format",
        action="store_const",
        const=OutputFormat.JSON,
        help=(
            "Emit one JSON document to stdout (scan envelope + findings "
            "array). Human status is redirected to stderr."
        ),
    )
    group.add_argument(
        "--jsonl",
        dest="output_format",
        action="store_const",
        const=OutputFormat.JSONL,
        help=(
            "Emit newline-delimited JSON to stdout, one finding per line. "
            "Human status is redirected to stderr."
        ),
    )
    parser.set_defaults(output_format=OutputFormat.HUMAN)


def _json_default(obj: Any) -> Any:
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj).decode("utf-8", errors="replace")
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=repr)
    return repr(obj)


def _coerce_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("utf-8", errors="replace")
    return str(value)


def _normalize_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(k): _normalize_value(v) for k, v in value.items()}
    if is_dataclass(value) and not isinstance(value, type):
        return {k: _normalize_value(v) for k, v in asdict(value).items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_normalize_value(v) for v in value]
    if hasattr(value, "__dict__"):
        return {
            k: _normalize_value(v)
            for k, v in vars(value).items()
            if not k.startswith("_")
        }
    return _coerce_str(value)


def _as_mapping(obj: Any) -> dict:
    if isinstance(obj, Mapping):
        return dict(obj)
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in vars(obj).items() if not k.startswith("_")}
    raise TypeError(f"Cannot normalize finding of type {type(obj).__name__}")


def _normalize_headers(headers: Any) -> dict:
    if not headers:
        return {}
    if isinstance(headers, Mapping):
        return {str(k): str(v) for k, v in headers.items()}
    try:
        return {str(k): str(v) for k, v in headers}
    except Exception:
        return {}


def _normalize_request(req: Any) -> dict | None:
    if req is None:
        return None
    m = _as_mapping(req)
    return {
        "method": _coerce_str(m.get("method")),
        "url": _coerce_str(m.get("url")),
        "headers": _normalize_headers(m.get("headers")),
        "body": _coerce_str(m.get("body")),
    }


def _normalize_response(resp: Any) -> dict | None:
    if resp is None:
        return None
    m = _as_mapping(resp)
    body = _coerce_str(m.get("body"))
    status = m.get("status")
    if status is None:
        status = m.get("status_code")
    return {
        "status": status,
        "headers": _normalize_headers(m.get("headers")),
        "body": body,
        "body_length": len(body) if body is not None else 0,
    }


def _normalize_finding(finding: Any) -> dict:
    m = _as_mapping(finding)
    cls = m.get("class") or m.get("bug_class") or m.get("category")
    param = m.get("parameter") or m.get("param")
    out: dict = {
        "id": _coerce_str(m.get("id")),
        "class": _coerce_str(cls),
        "title": _coerce_str(m.get("title")),
        "severity": _coerce_str(m.get("severity")),
        "confidence": _coerce_str(m.get("confidence")),
        "url": _coerce_str(m.get("url")),
        "method": _coerce_str(m.get("method")),
        "parameter": _coerce_str(param),
        "payload": _coerce_str(m.get("payload") or m.get("payload_value")),
        "evidence": _normalize_value(m.get("evidence")),
        "request": _normalize_request(m.get("request")),
        "response": _normalize_response(m.get("response")),
        "raw_request": _coerce_str(m.get("raw_request")),
        "raw_response": _coerce_str(m.get("raw_response")),
        "signals": _normalize_value(m.get("signals")) or [],
        "root_cause_group": _coerce_str(m.get("root_cause_group")),
        "timestamp": _coerce_str(m.get("timestamp")) or _iso_now(),
    }
    return {
        k: v
        for k, v in out.items()
        if v is not None or k in _REQUIRED_FINDING_KEYS
    }


def _redact_finding(finding: dict) -> dict:
    """Apply auth redaction to a normalized finding.

    Only touches headers on structured request/response and the raw
    HTTP/1.1 blobs. Body content is left alone so a leaked secret
    inside the response body still shows up - that is often the bug.
    """
    from janissary.auth import redact_headers, redact_raw_http

    if finding.get("raw_request"):
        finding["raw_request"] = redact_raw_http(finding["raw_request"])
    if finding.get("raw_response"):
        finding["raw_response"] = redact_raw_http(finding["raw_response"])
    req = finding.get("request")
    if isinstance(req, dict) and isinstance(req.get("headers"), dict):
        req["headers"] = redact_headers(req["headers"])
    resp = finding.get("response")
    if isinstance(resp, dict) and isinstance(resp.get("headers"), dict):
        resp["headers"] = redact_headers(resp["headers"])
    return finding


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tool_version() -> str:
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("janissary")
        except PackageNotFoundError:
            pass
    except Exception:
        pass
    try:
        from janissary import __version__ as v

        return str(v)
    except Exception:
        return "unknown"


class OutputEmitter:
    """Serialize findings to stdout in HUMAN / JSON / JSONL form.

    Returns the normalized finding list so callers can render human output
    from the same source of truth.
    """

    def __init__(
        self,
        fmt: OutputFormat = OutputFormat.HUMAN,
        *,
        stdout: IO[str] | None = None,
        redact: bool = False,
    ) -> None:
        self.fmt = fmt if isinstance(fmt, OutputFormat) else OutputFormat(fmt)
        self._stdout = stdout if stdout is not None else sys.stdout
        self.redact = redact

    def emit(
        self,
        findings: list,
        scan_meta: Mapping[str, Any] | None = None,
    ) -> list[dict]:
        normalized: list[dict] = []
        for i, f in enumerate(findings, start=1):
            n = _normalize_finding(f)
            if n.get("id") is None:
                n["id"] = f"F-{i:03d}"
            if self.redact:
                n = _redact_finding(n)
            normalized.append(n)

        if self.fmt is OutputFormat.JSON:
            doc = self._build_document(normalized, scan_meta)
            self._stdout.write(
                json.dumps(
                    doc,
                    indent=2,
                    ensure_ascii=False,
                    default=_json_default,
                )
                + "\n"
            )
            self._stdout.flush()

        elif self.fmt is OutputFormat.JSONL:
            for f in normalized:
                self._stdout.write(
                    json.dumps(
                        f,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        default=_json_default,
                    )
                    + "\n"
                )
            self._stdout.flush()

        return normalized

    def _build_document(
        self,
        findings: list[dict],
        scan_meta: Mapping[str, Any] | None,
    ) -> dict:
        meta = dict(scan_meta or {})
        meta.setdefault("id", str(uuid.uuid4()))
        meta.setdefault("started_at", _iso_now())
        meta.setdefault("finished_at", _iso_now())
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": TOOL_NAME,
            "tool_version": _tool_version(),
            "scan": meta,
            "finding_count": len(findings),
            "findings": findings,
        }
