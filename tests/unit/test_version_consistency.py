"""Assert runtime __version__ matches pyproject.toml declared version.

A previous release shipped with janissary.__version__ hardcoded to a stale
value (7.5.1 while pyproject declared 7.7.0). Users running
`janissary --version` got the stale string and had no way to know whether
they'd installed the new release. This test prevents recurrence.
"""

from __future__ import annotations

import re
from pathlib import Path

import janissary


def test_runtime_version_matches_pyproject():
    """janissary.__version__ must equal pyproject.toml's [project].version."""
    pyproject = Path(__file__).parents[2] / "pyproject.toml"
    content = pyproject.read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
    assert m, "Could not find version declaration in pyproject.toml"
    declared = m.group(1)
    assert janissary.__version__ == declared, (
        f"janissary.__version__={janissary.__version__!r} "
        f"but pyproject.toml declares version={declared!r}. "
        f"Users running `janissary --version` would see "
        f"{janissary.__version__!r} and have no way to know they were on "
        f"a stale build."
    )


def test_version_is_not_the_placeholder():
    """A source-uninstalled placeholder (0.0.0+...) means the fix regressed."""
    assert not janissary.__version__.startswith("0.0.0+"), (
        f"janissary.__version__={janissary.__version__!r} is the "
        f"source-uninstalled placeholder. This should only occur when "
        f"the package is not installed at all."
    )
