"""OpenAPI spec import for scan target enumeration.

Reads a single file OpenAPI 3.0 JSON spec and enumerates every
operation (path by HTTP method) declared in it. Stage 2 of ADR-030
adds local and external $ref resolution for path items and parameter
entries. Still no Swagger 2.0, no server templating, no request-body
import -- those come in later stages.

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

from janissary.importers.refs import RefError, RefResolver

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
    base_url: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "method": self.method,
            "operation_id": self.operation_id,
            "parameter_names": list(self.parameter_names),
            "base_url": self.base_url,
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
        self._resolver: RefResolver | None = None
        self._base_url: str = ""

    def parse(self) -> ParseResult:
        raw = self._load()
        spec = self._validate(raw)
        openapi_v = spec.get("openapi")
        swagger_v = spec.get("swagger")
        if isinstance(swagger_v, str):
            self.result.spec_version = "swagger " + swagger_v
        elif isinstance(openapi_v, str):
            self.result.spec_version = openapi_v
        self._resolver = RefResolver(spec, self.source)
        self._base_url = self._resolve_base_url(spec)
        paths = spec.get("paths") or {}
        if not isinstance(paths, dict):
            raise OpenAPIImportError(
                "spec paths is not an object: " + type(paths).__name__
            )
        for path, item in paths.items():
            self._enumerate_path(
                str(path), item, self._resolver.root_path
            )
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
        openapi_version = raw.get("openapi")
        swagger_version = raw.get("swagger")
        is_v3 = (
            isinstance(openapi_version, str)
            and openapi_version.startswith("3.0.")
        )
        is_v2 = (
            isinstance(swagger_version, str)
            and swagger_version == "2.0"
        )
        if not is_v3 and not is_v2:
            raise OpenAPIImportError(
                "unsupported spec version: openapi="
                + str(openapi_version)
                + " swagger=" + str(swagger_version)
                + " (Stage 3 handles 3.0.x and 2.0)"
            )
        if "paths" not in raw:
            raise OpenAPIImportError("spec has no 'paths' object")
        return raw

    def _resolve_base_url(self, spec: dict) -> str:
        swagger_v = spec.get("swagger")
        if isinstance(swagger_v, str) and swagger_v == "2.0":
            return self._resolve_v2_base_url(spec)
        return self._resolve_v3_base_url(spec)

    def _resolve_v2_base_url(self, spec: dict) -> str:
        host = spec.get("host")
        if not isinstance(host, str) or not host:
            return ""
        base_path = spec.get("basePath", "")
        if not isinstance(base_path, str):
            base_path = ""
        schemes = spec.get("schemes")
        scheme = "https"
        if isinstance(schemes, list) and schemes and isinstance(schemes[0], str):
            scheme = schemes[0]
        return scheme + "://" + host + base_path

    def _resolve_v3_base_url(self, spec: dict) -> str:
        servers = spec.get("servers")
        if not isinstance(servers, list) or not servers:
            return ""
        first = servers[0]
        if not isinstance(first, dict):
            self.result.notes.append(
                "servers[0] is not an object; base_url unresolved"
            )
            return ""
        url = first.get("url")
        if not isinstance(url, str) or not url:
            self.result.notes.append(
                "servers[0].url missing or not a string; base_url unresolved"
            )
            return ""
        variables = first.get("variables")
        if not isinstance(variables, dict):
            variables = {}
        out = url
        while "{" in out:
            start = out.find("{")
            end = out.find("}", start)
            if end == -1:
                break
            name = out[start + 1:end]
            var_spec = variables.get(name)
            if not isinstance(var_spec, dict):
                self.result.notes.append(
                    "server variable " + name
                    + " has no definition; base_url unresolved"
                )
                return ""
            default = var_spec.get("default")
            if not isinstance(default, str) or not default:
                self.result.notes.append(
                    "server variable " + name
                    + " has no default; base_url unresolved"
                )
                return ""
            out = out[:start] + default + out[end + 1:]
        return out

    def _enumerate_path(
        self, path: str, item: Any, item_path: Path
    ) -> None:
        resolver = self._resolver
        if resolver is None:
            raise RuntimeError("resolver not initialized; call parse() first")
        try:
            item, item_path = resolver.resolve(item, item_path)
        except RefError as exc:
            self.result.skipped.append(
                SkipRecord(
                    path=path,
                    method="*",
                    reason="unresolvable path item: " + str(exc),
                )
            )
            return
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
                    parameter_names=self._parameter_names(op, item_path),
                    base_url=self._base_url,
                )
            )

    def _parameter_names(
        self, op: dict, current_path: Path
    ) -> list[str]:
        params = op.get("parameters")
        if not isinstance(params, list):
            return []
        resolver = self._resolver
        if resolver is None:
            raise RuntimeError("resolver not initialized; call parse() first")
        names: list[str] = []
        for p in params:
            if not isinstance(p, dict):
                continue
            try:
                p, _ = resolver.resolve(p, current_path)
            except RefError as exc:
                self.result.notes.append(
                    "unresolvable parameter ref: " + str(exc)
                )
                continue
            if not isinstance(p, dict):
                continue
            name = p.get("name")
            if isinstance(name, str) and name:
                names.append(name)
        return names


def parse_spec(source: str | Path) -> ParseResult:
    return OpenAPIParser(source).parse()
