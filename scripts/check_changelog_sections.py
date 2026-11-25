"""Assert the changelog section for a version is long enough to release.

release.yml extracts the `## [<version>]` section from CHANGELOG.md and
refuses to create a Release when the section is under 200 characters.
A version that reaches a tag with a thin section therefore strands the tag:
PyPI and Docker have already accepted it. This hook applies the same floor
at commit time, so the CI gate cannot fail for length afterwards.

Usage: python scripts/check_changelog_sections.py [version]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

FLOOR = 200
ROOT = Path(__file__).resolve().parents[1]


def declared_version(pyproject: Path) -> str:
    text = pyproject.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise SystemExit(f"{pyproject}: no [project].version")
    return match.group(1)


def section(lines: list[str], version: str) -> str:
    start = f"## [{version}] "
    try:
        begin = next(i for i, line in enumerate(lines) if line.startswith(start))
    except StopIteration:
        raise SystemExit(
            f"CHANGELOG.md: no '{start.strip()}' heading for {version}; "
            "write the section before bumping the version"
        ) from None
    body: list[str] = []
    for line in lines[begin + 1 :]:
        if line.startswith("## ["):
            break
        body.append(line)
    return "\n".join(body).strip()


def main(argv: list[str]) -> int:
    version = argv[1] if len(argv) > 1 else declared_version(ROOT / "pyproject.toml")
    lines = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").splitlines()
    body = section(lines, version)
    if len(body) < FLOOR:
        print(
            f"changelog section {version} is {len(body)} chars, "
            f"floor is {FLOOR}: release.yml would refuse this version",
            file=sys.stderr,
        )
        return 1
    print(f"changelog section {version}: {len(body)} chars (floor {FLOOR})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
