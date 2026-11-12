"""Observation providers for the heuristic engine (M80).

A provider is any object implementing ``observations() -> list[Observation]``.
The provider supplies ``source_id``; the module computes ``observation_id``
deterministically from canonical content.

This module performs no verification. Observations are discovery evidence.
The verification boundary remains ``verification.engine.VerificationEngine``.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Protocol, runtime_checkable

from janissary.heuristic.types import (
    OBSERVATION_BODY_MAX_BYTES,
    OBSERVATION_FIXTURE_ALLOWED_FIELDS,
    OBSERVATION_PROVIDER_ID_PATTERN,
    Observation,
)

_PROVIDER_ID_RE = re.compile(OBSERVATION_PROVIDER_ID_PATTERN)


class ObservationLoadError(ValueError):
    """Raised when a fixture observation fails validation.

    Attributes:
        line_number: 1-based line number in the fixture, or None.
        category: one of
            'malformed_json', 'missing_required', 'unknown_field',
            'reserved_verification', 'provider_supplied',
            'non_observation_field', 'invalid_field_type',
            'oversized_evidence', 'invalid_provider_id', 'missing_file'.
    """

    def __init__(
        self,
        message: str,
        *,
        line_number: int | None = None,
        category: str = "invalid",
    ) -> None:
        prefix = f"line {line_number}: " if line_number is not None else ""
        super().__init__(f"{prefix}{message}")
        self.line_number = line_number
        self.category = category


def _canonical(s: str) -> str:
    """Escape separators so they cannot forge a field boundary."""
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n")


def _compute_observation_id(
    url: str,
    method: str,
    param: str,
    payload_name: str,
    payload_value: str,
) -> str:
    """Deterministic content-addressed probe identity.

    Canonical form: url|method|param|payload_name|payload_value,
    each field escaped (backslash, pipe, newline), joined with a single
    pipe, UTF-8 encoded, SHA-256, full 64 hex characters.

    Deliberately excluded from the hash:
      - headers: dict iteration order is not canonical across providers
      - body: evidence; identical probes to identical endpoints return
              different bodies over time and must not split identity
      - response_status: transient
      - source_id: provider identity, not probe identity
      - any timestamp or random value: unstable across replays

    Consequence: this is a PROBE identity, not a complete-observation
    identity. Two observations with the same five fields but different
    response bodies share the same observation_id.
    """
    parts = [
        _canonical(url),
        _canonical(method),
        _canonical(param),
        _canonical(payload_name),
        _canonical(payload_value),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _validate_provider_id(source_id: str) -> None:
    """Reject non-conforming source_id; never silently normalise."""
    if not isinstance(source_id, str) or not _PROVIDER_ID_RE.fullmatch(source_id):
        raise ObservationLoadError(
            f"invalid source_id {source_id!r}; must match "
            f"{OBSERVATION_PROVIDER_ID_PATTERN}",
            category="invalid_provider_id",
        )


@runtime_checkable
class ObservationProvider(Protocol):
    """Structural interface for anything that yields observations."""

    @property
    def source_id(self) -> str: ...

    def observations(self) -> list[Observation]: ...


class ScannerProvider:
    """Wraps a live Scanner's collected observations.

    The ``source_id`` embeds ``id(scanner)``, which is process-specific.
    It distinguishes scanner instances within one process; it is NOT
    stable across separate executions. Do not rely on it for cross-run
    aggregation.
    """

    def __init__(self, scanner) -> None:
        self._scanner = scanner
        self._source_id = f"scanner:{id(scanner):x}"
        _validate_provider_id(self._source_id)

    @property
    def source_id(self) -> str:
        return self._source_id

    def observations(self) -> list[Observation]:
        raw = self._scanner.get_observations()
        out: list[Observation] = []
        for o in raw:
            out.append(
                Observation(
                    url=o.url,
                    body=o.body,
                    headers=dict(o.headers),
                    method=o.method,
                    response_status=o.response_status,
                    payload_name=o.payload_name,
                    payload_value=o.payload_value,
                    param=o.param,
                    source_id=self._source_id,
                    observation_id=_compute_observation_id(
                        o.url, o.method, o.param, o.payload_name, o.payload_value
                    ),
                )
            )
        return out


class StaticFixtureProvider:
    """Loads observations from a JSONL fixture.

    Fixture records supply observation content only. ``source_id`` is
    supplied at construction time; ``observation_id`` is computed.
    A record that attempts to supply either, or any field outside
    OBSERVATION_FIXTURE_ALLOWED_FIELDS, is rejected.
    """

    def __init__(self, path: str | Path, *, source_id: str = "fixture") -> None:
        _validate_provider_id(source_id)
        self._path = Path(path)
        self._source_id = source_id

    @property
    def source_id(self) -> str:
        return self._source_id

    def observations(self) -> list[Observation]:
        if not self._path.exists():
            raise ObservationLoadError(
                f"fixture not found: {self._path}", category="missing_file"
            )
        out: list[Observation] = []
        with self._path.open(encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                out.append(self._load_one(line, lineno))
        return out

    def _load_one(self, line: str, lineno: int) -> Observation:
        try:
            record = json.loads(line)
        except json.JSONDecodeError as e:
            raise ObservationLoadError(
                f"malformed JSON: {e.msg}",
                line_number=lineno,
                category="malformed_json",
            ) from None
        if not isinstance(record, dict):
            raise ObservationLoadError(
                "fixture record must be a JSON object",
                line_number=lineno,
                category="malformed_json",
            )

        for f in (
            "verification_status",
            "verification_reason",
            "_engine_emitted",
            "fingerprint",
        ):
            if f in record:
                raise ObservationLoadError(
                    f"reserved verification field {f!r} not permitted in "
                    f"observations; observations are discovery evidence only",
                    line_number=lineno,
                    category="reserved_verification",
                )

        for f in ("source_id", "observation_id"):
            if f in record:
                raise ObservationLoadError(
                    f"field {f!r} is supplied by the provider, not the record",
                    line_number=lineno,
                    category="provider_supplied",
                )

        if "confidence" in record:
            raise ObservationLoadError(
                "field 'confidence' is not an observation field; confidence "
                "is heuristic metadata and belongs on HeuristicMatch",
                line_number=lineno,
                category="non_observation_field",
            )

        unknown = set(record) - OBSERVATION_FIXTURE_ALLOWED_FIELDS
        if unknown:
            raise ObservationLoadError(
                f"unknown field(s): {sorted(unknown)}",
                line_number=lineno,
                category="unknown_field",
            )

        for req in ("url", "body"):
            if req not in record:
                raise ObservationLoadError(
                    f"missing required field {req!r}",
                    line_number=lineno,
                    category="missing_required",
                )

        _type_checks = {
            "url": (str,),
            "body": (str,),
            "method": (str,),
            "payload_name": (str,),
            "payload_value": (str,),
            "param": (str,),
            "response_status": (int, type(None)),
        }
        for fname, allowed in _type_checks.items():
            if fname in record and not isinstance(record[fname], allowed):
                raise ObservationLoadError(
                    f"field {fname!r} has invalid type {type(record[fname]).__name__}",
                    line_number=lineno,
                    category="invalid_field_type",
                )

        if "headers" in record:
            h = record["headers"]
            if not isinstance(h, dict):
                raise ObservationLoadError(
                    f"field 'headers' must be a dict, got {type(h).__name__}",
                    line_number=lineno,
                    category="invalid_field_type",
                )
            for k, v in h.items():
                if not isinstance(v, str):
                    raise ObservationLoadError(
                        f"headers[{k!r}] must be str, got {type(v).__name__}",
                        line_number=lineno,
                        category="invalid_field_type",
                    )

        body = record.get("body") or ""
        if (
            isinstance(body, str)
            and len(body.encode("utf-8")) > OBSERVATION_BODY_MAX_BYTES
        ):
            raise ObservationLoadError(
                f"evidence body exceeds {OBSERVATION_BODY_MAX_BYTES} bytes",
                line_number=lineno,
                category="oversized_evidence",
            )

        return Observation(
            **record,
            source_id=self._source_id,
            observation_id=_compute_observation_id(
                str(record.get("url", "")),
                str(record.get("method", "GET")),
                str(record.get("param", "")),
                str(record.get("payload_name", "")),
                str(record.get("payload_value", "")),
            ),
        )
