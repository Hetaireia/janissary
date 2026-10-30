# JANISSARY-VERSION-TAG-GUARD
# pyproject [project].version must not lag the newest git tag.
# Closes the gap that let pyproject sit at 7.7.1 while tags
# v7.8.0..v7.10.2 existed. Uses git tag --list (NOT git describe)
# so unreachable tags still count. Tags must be vX.Y.Z.
import re
import shutil
import subprocess
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parent.parent
TAG_RE = re.compile(r"^v?(\d+(?:\.\d+)*)$")


def _git(*args):
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _tags_available():
    if shutil.which("git") is None:
        return False
    try:
        _git("rev-parse", "--git-dir")
        return bool(_git("tag", "--list"))
    except (subprocess.CalledProcessError, OSError):
        return False


def _key(text):
    m = TAG_RE.match(text.strip())
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def _newest_tag():
    best = best_key = None
    for tag in _git("tag", "--list").splitlines():
        k = _key(tag)
        if k is None:
            continue
        if best_key is None or k > best_key:
            best, best_key = tag, k
    return best


def _pyproject_version():
    raw = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    return tomllib.loads(raw)["project"]["version"]


@pytest.mark.skipif(not _tags_available(), reason="needs git checkout with tags")
def test_pyproject_not_behind_newest_tag():
    newest = _newest_tag()
    assert newest is not None, "no X.Y[.Z] tags found"

    pkg = _pyproject_version()
    pkg_key = _key(pkg)
    assert pkg_key is not None, f"pyproject version {pkg!r} not X.Y[.Z]"

    assert pkg_key >= _key(newest), (
        f"pyproject version {pkg!r} is behind newest git tag {newest!r}. "
        "Bump pyproject.toml and janissary.__version__, or retag."
    )
