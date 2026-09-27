"""Nuclei runner.

Nuclei is an external, template-driven vulnerability scanner. This
module does not reimplement its template engine. It shells out to the
`nuclei` binary, requests JSONL output, and parses each line into a
structured result.

Guard rails, applied in this order:

    1. `attack_confirm=True` is required at construction time. This
       mirrors the UNION extractor and is separate from the
       Terms-of-Use gate that the CLI applies before dispatch.
    2. The `nuclei` binary must be resolvable on PATH. If it is not,
       construction raises `NucleiNotFound`.
    3. A non-empty `templates` list is required. The module will not
       run Nuclei's default template set against a target, because
       that set is very broad and would exceed the reasonable scope
       of an authorised engagement without explicit intent.

Only tags, severity, and template paths are passed through to the
binary. Arbitrary Nuclei flags are not exposed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field

DEFAULT_TIMEOUT = 300.0
MAX_TIMEOUT = 1800.0
DEFAULT_RATE_LIMIT = 50

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AttackConfirmationRequired(Exception):  # noqa: N818
    """Raised when the runner is constructed without confirmation."""


class NucleiNotFound(Exception):  # noqa: N818
    """Raised when the nuclei binary is not on PATH."""


class NucleiError(Exception):
    """Raised when the nuclei binary returns a non-zero exit status."""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    matched_at: str
    host: str = ""
    type: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)
    reference: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "matched_at": self.matched_at,
            "host": self.host,
            "type": self.type,
            "description": self.description,
            "tags": list(self.tags),
            "reference": list(self.reference),
        }


@dataclass
class NucleiRun:
    target: str
    templates: list[str]
    command: list[str] = field(default_factory=list)
    findings: list[NucleiFinding] = field(default_factory=list)
    exit_code: int | None = None
    elapsed: float = 0.0
    stdout_lines: int = 0
    stderr_tail: str = ""
    aborted: bool = False
    abort_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "templates": list(self.templates),
            "command": list(self.command),
            "findings": [f.to_dict() for f in self.findings],
            "exit_code": self.exit_code,
            "elapsed": round(self.elapsed, 3),
            "stdout_lines": self.stdout_lines,
            "stderr_tail": self.stderr_tail,
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
        }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_nuclei_line(line: str) -> NucleiFinding | None:
    """Parse one JSONL line from nuclei into a NucleiFinding.

    Returns None for blank lines and for lines that do not carry a
    template-id (nuclei sometimes emits progress or warning objects).
    """
    line = (line or "").strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None

    info = obj.get("info") or {}
    template_id = obj.get("template-id") or obj.get("templateID") or ""
    if not template_id:
        return None

    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    reference = info.get("reference") or []
    if isinstance(reference, str):
        reference = [reference]

    return NucleiFinding(
        template_id=str(template_id),
        name=str(info.get("name", "")),
        severity=str(info.get("severity", "info")),
        matched_at=str(obj.get("matched-at") or obj.get("matched") or ""),
        host=str(obj.get("host", "")),
        type=str(obj.get("type", "")),
        description=str(info.get("description", "")),
        tags=[str(t) for t in tags],
        reference=[str(r) for r in reference],
        raw=obj,
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class NucleiRunner:
    def __init__(
        self,
        target: str,
        templates: list[str],
        attack_confirm: bool = False,
        severity: str | None = None,
        tags: list[str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        rate_limit: int = DEFAULT_RATE_LIMIT,
        nuclei_path: str | None = None,
    ) -> None:
        if not attack_confirm:
            raise AttackConfirmationRequired(
                "The Nuclei runner requires attack_confirm=True. "
                "This is the --attack-confirm flag on the CLI. It is "
                "separate from, and in addition to, the Terms-of-Use "
                "acceptance gate. Both are required."
            )

        if not templates:
            raise ValueError(
                "templates must be a non-empty list. The runner will "
                "not use nuclei's default template set."
            )

        self.target = target
        self.templates = list(templates)
        self.severity = severity
        self.tags = list(tags or [])
        self.timeout = max(1.0, min(float(timeout), MAX_TIMEOUT))
        self.rate_limit = max(1, int(rate_limit))

        resolved = nuclei_path or shutil.which("nuclei")
        if not resolved:
            raise NucleiNotFound(
                "the 'nuclei' binary was not found on PATH. Install it "
                "from https://github.com/projectdiscovery/nuclei or "
                "pass nuclei_path explicitly."
            )
        self.nuclei_path = resolved

    # ------------------------------------------------------------------

    def build_command(self) -> list[str]:
        cmd = [
            self.nuclei_path,
            "-target",
            self.target,
            "-jsonl",
            "-silent",
            "-no-color",
            "-rate-limit",
            str(self.rate_limit),
        ]
        for t in self.templates:
            cmd += ["-t", t]
        if self.severity:
            cmd += ["-severity", self.severity]
        if self.tags:
            cmd += ["-tags", ",".join(self.tags)]
        return cmd

    def run(self) -> NucleiRun:
        cmd = self.build_command()
        result = NucleiRun(
            target=self.target,
            templates=list(self.templates),
            command=cmd,
        )

        start = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result.aborted = True
            result.abort_reason = f"nuclei timed out after {self.timeout}s"
            result.elapsed = time.perf_counter() - start
            return result
        except FileNotFoundError as exc:
            result.aborted = True
            result.abort_reason = f"nuclei binary vanished: {exc}"
            result.elapsed = time.perf_counter() - start
            return result

        result.elapsed = time.perf_counter() - start
        result.exit_code = proc.returncode

        stdout = proc.stdout or ""
        lines = stdout.splitlines()
        result.stdout_lines = len(lines)
        for line in lines:
            finding = parse_nuclei_line(line)
            if finding is not None:
                result.findings.append(finding)

        stderr = (proc.stderr or "").strip()
        if stderr:
            # Keep the last few lines; nuclei can be chatty.
            tail = stderr.splitlines()[-5:]
            result.stderr_tail = "\n".join(tail)

        if proc.returncode not in (0, 1):
            # Nuclei returns 0 on clean scan, 1 when it finds something,
            # and other codes on error.
            result.aborted = True
            result.abort_reason = f"nuclei exited with code {proc.returncode}"

        return result
