"""Persistent findings store.

Append-only. JSON-backed. One file per store. No server, no database,
no dependencies beyond the standard library.

A finding is a dict with a stable key set. Two findings are considered
the same (and the second is skipped) when they share a dedup key,
which is derived from target, category, finding_type, and the
discriminator (param or name) of the finding.

The store is deliberately simple:

    store = FindingStore("findings.json")
    store.add(finding)
    store.save()
    ...
    store = FindingStore("findings.json")
    for f in store.all():
        ...

Atomic writes: save() writes to a temporary file, then renames it
into place. If the process dies mid-write, the original file is
untouched.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FINDING_KEYS: tuple[str, ...] = (
    "target",
    "category",
    "severity",
    "finding_type",
    "discriminator",
    "detail",
    "payload",
    "response_status",
    "recorded_at",
)


@dataclass
class Finding:
    target: str
    category: str
    severity: str
    finding_type: str
    discriminator: str = ""
    detail: str = ""
    payload: str = ""
    response_status: int | None = None
    recorded_at: str = ""
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.recorded_at:
            self.recorded_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def dedup_key(self) -> str:
        parts = [
            self.target or "",
            self.category or "",
            self.finding_type or "",
            self.discriminator or "",
        ]
        blob = "|".join(parts).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()[:32]

    def to_dict(self) -> dict:
        d = asdict(self)
        # Merge the extra dict inline so consumers do not need to know
        # about the wrapper.
        extra = d.pop("extra", {}) or {}
        d.update(extra)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        known = {
            "target",
            "category",
            "severity",
            "finding_type",
            "discriminator",
            "detail",
            "payload",
            "response_status",
            "recorded_at",
        }
        base = {k: data.get(k) for k in known if k in data}
        extra = {k: v for k, v in data.items() if k not in known}
        # Backfill required fields that may be missing.
        base.setdefault("target", "")
        base.setdefault("category", "")
        base.setdefault("severity", "info")
        base.setdefault("finding_type", "unknown")
        base.setdefault("discriminator", "")
        base.setdefault("detail", "")
        base.setdefault("payload", "")
        return cls(**base, extra=extra)


class FindingStore:
    """Append-only, deduplicating store of findings."""

    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)
        self._findings: list[Finding] = []
        self._keys: set[str] = set()

    # ------------------------------------------------------------------

    def add(self, finding: Finding) -> bool:
        """Add a finding. Returns True if it was new, False if duplicate."""
        key = finding.dedup_key()
        if key in self._keys:
            return False
        self._keys.add(key)
        self._findings.append(finding)
        return True

    def extend(self, findings: Iterable[Finding]) -> int:
        """Add many findings. Returns the count of new ones."""
        added = 0
        for f in findings:
            if self.add(f):
                added += 1
        return added

    def all(self) -> list[Finding]:
        return list(self._findings)

    def by_target(self, target: str) -> list[Finding]:
        return [f for f in self._findings if f.target == target]

    def by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self._findings if f.severity == severity]

    def by_category(self, category: str) -> list[Finding]:
        return [f for f in self._findings if f.category == category]

    def count(self) -> int:
        return len(self._findings)

    def __len__(self) -> int:
        return len(self._findings)

    # ------------------------------------------------------------------

    def save(self) -> Path:
        """Write the store atomically. Returns the path."""
        payload = {
            "version": 1,
            "saved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "findings": [f.to_dict() for f in self._findings],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)

        fd, tmp_name = tempfile.mkstemp(
            prefix=self.path.name + ".",
            suffix=".tmp",
            dir=str(self.path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            os.replace(tmp_name, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise
        return self.path

    def load(self) -> int:
        """Load findings from the store file. Returns count loaded."""
        if not self.path.exists():
            return 0
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return 0
        items = data.get("findings") if isinstance(data, dict) else None
        if not isinstance(items, list):
            return 0

        self._findings.clear()
        self._keys.clear()
        for item in items:
            if not isinstance(item, dict):
                continue
            f = Finding.from_dict(item)
            self.add(f)
        return len(self._findings)

    def clear(self) -> None:
        self._findings.clear()
        self._keys.clear()

    # ------------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        by_sev: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        targets: set[str] = set()
        for f in self._findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
            if f.target:
                targets.add(f.target)
        return {
            "total": len(self._findings),
            "by_severity": by_sev,
            "by_category": by_cat,
            "targets": sorted(targets),
        }
