"""OpenAPI spec import for scan target enumeration.

Reads a single file OpenAPI 3.0 JSON spec and enumerates every
operation (path by HTTP method) declared in it. This is Stage 1 of
ADR-030: no $ref resolution, no Swagger 2.0, no server templating.
Those come in later stages.

The parser returns both what it imported and what it skipped, with
reasons. len(imported) + len(skipped) must equal the total operation
count in the spec. That is the silent drop invariant from ADR-030.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

HTTP_METHODS: frozenset[str] = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)


class OpenAPIImportError(Exception):
    """Raised when a spec file is unreadable or not a valid 3.0 document."""


@dataclass
class Operation:
    path: str
    method: str
    operation_id: str = ""
    parameter_names: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "method": self.method,
            "operation_id": self.operation_id,
            "parameter_names": list(self.parameter_names),
        }


@dataclass
class SkipRecord:
    path: str
    method: str
    reason: str

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "method": self.method,
            "reason": self.reason,
        }


@dataclass
class ParseResult:
    source: str
    spec_version: str = ""
    imported: list[Operation] = field(default_factory=list)
    skipped: list[SkipRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.imported) + len(self.skipped)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "spec_version": self.spec_version,
            "imported": [o.to_dict() for o in self.imported],
            "skipped": [s.to_dict() for s in self.skipped],
            "notes": list(self.notes),
        }


class OpenAPIParser:
    def __init__(self, source: str | Path) -> None:
        self.source = Path(source)
        self.result = ParseResult(source=str(self.source))

    def parse(self) -> ParseResult:
        raw = self._load()
        spec = self._validate(raw)
        self.result.spec_version = str(spec.get("openapi", ""))
        paths = spec.get("paths") or {}
        if not isinstance(paths, dict):
            raise OpenAPIImportError(
                "spec paths is not an object: " + type(paths).__name__
            )
        for path, item in paths.items():
            self._enumerate_path(str(path), item)
        return self.result

    def _load(self) -> Any:
        if not self.source.is_file():
            raise OpenAPIImportError(
                "spec file not found: " + str(self.source)
            )
        try:
            text = self.source.read_text(encoding="utf8")
        except OSError as exc:
            raise OpenAPIImportError(
                "could not read spec file: " + str(exc)
            ) from exc
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise OpenAPIImportError(
                "spec is not valid JSON: " + str(exc)
            ) from exc

    def _validate(self, raw: Any) -> dict:
        if not isinstance(raw, dict):
            raise OpenAPIImportError(
                "spec root is not a JSON object: " + type(raw).__name__
            )
        version = raw.get("openapi")
        if not isinstance(version, str):
            raise OpenAPIImportError(
                "spec has no openapi version string"
            )
        if not version.startswith("3.0."):
            raise OpenAPIImportError(
                "unsupported spec version: " + version
                + " (Stage 1 handles 3.0.x only)"
            )
        if "paths" not in raw:
            raise OpenAPIImportError("spec has no 'paths' object")
        return raw

    def _enumerate_path(self, path: str, item: Any) -> None:
        if not isinstance(item, dict):
            self.result.skipped.append(
                SkipRecord(
                    path=path,
                    method="*",
                    reason="path item is not an object: "
                    + type(item).__name__,
                )
            )
            self.result.notes.append(
                "skipped non object path item: " + path
            )
            return
        for method_key, op in item.items():
            method = str(method_key).lower()
            if method not in HTTP_METHODS:
                continue
            if not isinstance(op, dict):
                self.result.skipped.append(
                    SkipRecord(
                        path=path,
                        method=method,
                        reason="operation is not an object: "
                        + type(op).__name__,
                    )
                )
                continue
            self.result.imported.append(
                Operation(
                    path=path,
                    method=method,
                    operation_id=str(op.get("operationId") or ""),
                    parameter_names=self._parameter_names(op),
                )
            )

    def _parameter_names(self, op: dict) -> list[str]:
        params = op.get("parameters")
        if not isinstance(params, list):
            return []
        names: list[str] = []
        for p in params:
            if isinstance(p, dict):
                name = p.get("name")
                if isinstance(name, str) and name:
                    names.append(name)
        return names


def parse_spec(source: str | Path) -> ParseResult:
    return OpenAPIParser(source).parse()
