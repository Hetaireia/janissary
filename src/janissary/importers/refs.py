"""$ref resolution for the OpenAPI parser (ADR-030 Stage 2).

Resolves $ref chains in path items and parameter entries only. The
resolution surface is deliberately narrow -- schemas, responses, and
request bodies are never traversed -- which keeps memory bounded on
large specs and avoids pulling Stage 5 concerns into Stage 2.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class RefError(Exception):
    """Raised when a $ref cannot be resolved."""


class RefResolver:
    """Resolves local and external $ref chains.

    Tracks the file each node came from so nested refs resolve
    relative to the correct document, not the root spec.
    """

    def __init__(
        self,
        root_doc: Any,
        root_path: str | Path,
        max_depth: int = 10,
    ) -> None:
        self._root_path = Path(root_path).resolve()
        self._cache: dict[Path, Any] = {self._root_path: root_doc}
        self._path_cache: dict[Path, Path] = {}
        self._max_depth = max_depth

    @property
    def root_path(self) -> Path:
        return self._root_path

    def resolve(self, node: Any, current_path: str | Path) -> tuple[Any, Path]:
        if not isinstance(node, dict) or "$ref" not in node:
            return node, Path(current_path)
        path = self._resolved_path(current_path)
        visited: set[tuple[Path, str]] = set()
        depth = 0
        while isinstance(node, dict) and "$ref" in node:
            ref = node["$ref"]
            if not isinstance(ref, str) or not ref:
                raise RefError("$ref is not a non-empty string")
            key = (path, ref)
            if key in visited:
                raise RefError("cyclic $ref: " + ref)
            if depth >= self._max_depth:
                raise RefError(
                    "$ref depth limit (" + str(self._max_depth) + ") exceeded: " + ref
                )
            visited.add(key)
            doc, path, pointer = self._split(ref, path)
            node = self._lookup(doc, pointer, ref)
            depth += 1
        return node, path

    def _resolved_path(self, current_path: str | Path) -> Path:
        p = Path(current_path)
        cached = self._path_cache.get(p)
        if cached is not None:
            return cached
        r = p.resolve()
        self._path_cache[p] = r
        return r

    def _split(self, ref: str, current_path: Path) -> tuple[Any, Path, str]:
        if ref.startswith("#"):
            return self._cache[current_path], current_path, ref[1:]
        if "#" in ref:
            file_part, pointer = ref.split("#", 1)
        else:
            file_part, pointer = ref, ""
        target = (current_path.parent / file_part).resolve()
        return self._load(target), target, pointer

    def _load(self, path: Path) -> Any:
        if path in self._cache:
            return self._cache[path]
        try:
            text = path.read_text(encoding="utf8")
            doc = json.loads(text)
        except OSError as exc:
            raise RefError(
                "external ref unreadable: " + str(path) + " (" + str(exc) + ")"
            ) from exc
        except json.JSONDecodeError as exc:
            raise RefError(
                "external ref not valid JSON: " + str(path) + " (" + str(exc) + ")"
            ) from exc
        self._cache[path] = doc
        return doc

    def _lookup(self, doc: Any, pointer: str, original: str) -> Any:
        if not pointer:
            return doc
        if not pointer.startswith("/"):
            raise RefError(
                "unsupported JSON pointer (missing leading slash): " + original
            )
        node = doc
        for raw in pointer.lstrip("/").split("/"):
            part = raw.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict):
                if part not in node:
                    raise RefError(
                        "JSON pointer not found at '" + part + "' in " + original
                    )
                node = node[part]
            elif isinstance(node, list):
                try:
                    idx = int(part)
                except ValueError as exc:
                    raise RefError(
                        "JSON pointer list index not int: " + original
                    ) from exc
                if idx < 0 or idx >= len(node):
                    raise RefError(
                        "JSON pointer list index out of range: " + original
                    )
                node = node[idx]
            else:
                raise RefError(
                    "JSON pointer traversed non-container in " + original
                )
        return node
