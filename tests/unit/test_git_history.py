"""Unit tests for the git history credential scanner.

These tests build real temporary git repositories — no mocks. Git is
required on PATH; the whole module skips if it is not found.

The deleted-secret test is the important one: a token committed in one
commit and removed in the next must still be found when scanning
history, even though the working tree is clean.

Windows git crash workaround
----------------------------
Windows git 2.55 intermittently returns STATUS_ACCESS_VIOLATION
(3221225477) when antivirus is scanning a freshly-created repository.
Every git invocation in this module goes through _git_run, which
retries once on that code. Without this, tests flake.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from janissary.credentials.git_history import (
    _validate_repo_path,
    list_commits,
    scan_commit,
    scan_git_history,
)

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None,
    reason="git not on PATH",
)

WINDOWS_RETRYABLE_CODES = {3221225477, 3221225501}


# -------------------------------------------------------------------
# FIXTURES
# -------------------------------------------------------------------

FAKE_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"


def _git_run(
    args: list[str],
    cwd: Path,
    check: bool = True,
    timeout: int = 30,
) -> subprocess.CompletedProcess:
    """subprocess.run wrapper with one retry on Windows AV crash."""
    last: subprocess.CompletedProcess | None = None
    for attempt in (1, 2, 3, 4):
        last = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
            shell=False,
            stdin=subprocess.DEVNULL,
        )
        if last.returncode == 0:
            return last
        if last.returncode not in WINDOWS_RETRYABLE_CODES:
            break
        time.sleep(0.5 * attempt)
    assert last is not None
    if check and last.returncode != 0:
        raise subprocess.CalledProcessError(
            last.returncode,
            args,
            last.stdout,
            last.stderr,
        )
    return last


def _init_repo(path: Path) -> Path:
    """Create a minimal git repo at path.

    Identity is passed per-commit via `git -c user.*=...` rather than
    written with `git config`. Windows git 2.55 crashes with
    STATUS_ACCESS_VIOLATION when `git config` writes to .git/config
    while antivirus is scanning the newly-created repository.
    """
    path.mkdir(parents=True, exist_ok=True)
    _git_run(["git", "init", "-q"], cwd=path)
    return path


def _commit(path: Path, message: str) -> None:
    _git_run(["git", "add", "-A"], cwd=path)
    _git_run(
        [
            "git",
            "-c",
            "user.email=janissary@example.test",
            "-c",
            "user.name=janissary-test",
            "commit",
            "-q",
            "-m",
            message,
            "--allow-empty",
        ],
        cwd=path,
    )


@pytest.fixture
def clean_repo(tmp_path: Path) -> Path:
    repo = _init_repo(tmp_path / "clean_repo")
    (repo / "readme.md").write_text("just a readme\n", encoding="utf-8")
    _commit(repo, "initial commit")
    return repo


@pytest.fixture
def leaky_repo(tmp_path: Path) -> Path:
    """Repo with a token introduced in one commit and removed in the next."""
    repo = _init_repo(tmp_path / "leaky_repo")

    (repo / "readme.md").write_text("readme\n", encoding="utf-8")
    _commit(repo, "initial commit")

    (repo / "config.env").write_text(
        f"GITHUB_TOKEN={FAKE_TOKEN}\n",
        encoding="utf-8",
    )
    _commit(repo, "add config with token (oops)")

    (repo / "config.env").unlink()
    _commit(repo, "remove config")

    return repo


# -------------------------------------------------------------------
# PATH VALIDATION
# -------------------------------------------------------------------


def test_validate_accepts_real_repo(clean_repo: Path):
    p = _validate_repo_path(str(clean_repo))
    assert p == clean_repo.resolve()


def test_validate_rejects_non_git_dir(tmp_path: Path):
    d = tmp_path / "not_a_repo"
    d.mkdir()
    with pytest.raises(ValueError, match="not a git repository"):
        _validate_repo_path(str(d))


def test_validate_rejects_missing_path(tmp_path: Path):
    with pytest.raises(ValueError, match="not a directory"):
        _validate_repo_path(str(tmp_path / "does_not_exist"))


def test_validate_rejects_empty_string():
    with pytest.raises(ValueError, match="empty"):
        _validate_repo_path("")


def test_validate_windows_absolute_path_is_accepted(clean_repo: Path):
    """The prototype's blacklist rejected every C:\\... path."""
    resolved = _validate_repo_path(str(clean_repo))
    assert resolved.is_dir()
    assert (resolved / ".git").is_dir()


def test_validate_allow_root_accepts_within(tmp_path: Path):
    repo = _init_repo(tmp_path / "inside" / "repo")
    (repo / "x.txt").write_text("x\n", encoding="utf-8")
    _commit(repo, "init")
    _validate_repo_path(str(repo), allow_root=str(tmp_path))


def test_validate_allow_root_rejects_outside(tmp_path: Path):
    outside = _init_repo(tmp_path / "outside" / "repo")
    (outside / "x.txt").write_text("x\n", encoding="utf-8")
    _commit(outside, "init")
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    with pytest.raises(ValueError, match="not under allowed root"):
        _validate_repo_path(str(outside), allow_root=str(allowed))


def test_shell_metacharacters_in_path_are_harmless(tmp_path: Path):
    """Semicolons and ampersands in a path must not trip validation."""
    dangerous_dir = tmp_path / "re;po&name"
    repo = _init_repo(dangerous_dir)
    (repo / "x.txt").write_text("x\n", encoding="utf-8")
    _commit(repo, "init")
    p = _validate_repo_path(str(repo))
    assert p == repo.resolve()


# -------------------------------------------------------------------
# COMMIT ENUMERATION
# -------------------------------------------------------------------


def test_list_commits_returns_them_newest_first(leaky_repo: Path):
    commits = list_commits(leaky_repo)
    assert len(commits) == 3
    assert commits[0][3] == "remove config"
    assert commits[-1][3] == "initial commit"


def test_list_commits_respects_max_commits(leaky_repo: Path):
    commits = list_commits(leaky_repo, max_commits=2)
    assert len(commits) == 2


# -------------------------------------------------------------------
# PER-COMMIT SCAN
# -------------------------------------------------------------------


def test_scan_commit_finds_token(leaky_repo: Path):
    commits = list_commits(leaky_repo)
    sha = commits[1][0]
    hits = scan_commit(leaky_repo, sha, enable_entropy=False)
    ids = [h["token_type"] for h in hits]
    assert "github-pat" in ids


def test_scan_commit_clean_is_empty(clean_repo: Path):
    commits = list_commits(clean_repo)
    hits = scan_commit(clean_repo, commits[0][0], enable_entropy=False)
    assert hits == []


# -------------------------------------------------------------------
# END-TO-END
# -------------------------------------------------------------------


def test_scan_history_finds_deleted_token(leaky_repo: Path):
    """The token is gone from the working tree but present in history."""
    assert not (leaky_repo / "config.env").exists()

    findings = scan_git_history(str(leaky_repo), enable_entropy=False, quiet=True)
    tokens = [f for f in findings if f["token_type"] == "github-pat"]
    assert len(tokens) == 1
    f = tokens[0]
    assert f["commit_author"] == "janissary-test"
    assert "commit" in f
    assert "commit_date" in f
    assert f["source"].startswith("git:")
    assert f["redacted"] != f["full_token"]


def test_scan_history_clean_repo_is_empty(clean_repo: Path):
    findings = scan_git_history(str(clean_repo), enable_entropy=False, quiet=True)
    assert findings == []


def test_scan_history_respects_max_commits(leaky_repo: Path):
    findings = scan_git_history(
        str(leaky_repo),
        max_commits=1,
        enable_entropy=False,
        quiet=True,
    )
    assert [f for f in findings if f["token_type"] == "github-pat"] == []


def test_scan_history_allow_root_guard(tmp_path: Path):
    repo = _init_repo(tmp_path / "repos" / "leaky")
    (repo / "cfg.env").write_text(
        f"GITHUB_TOKEN={FAKE_TOKEN}\n",
        encoding="utf-8",
    )
    _commit(repo, "leak")

    allowed = tmp_path / "allowed"
    allowed.mkdir()

    with pytest.raises(ValueError, match="not under allowed root"):
        scan_git_history(str(repo), allow_root=str(allowed), quiet=True)

    findings = scan_git_history(
        str(repo),
        allow_root=str(tmp_path),
        enable_entropy=False,
        quiet=True,
    )
    assert any(f["token_type"] == "github-pat" for f in findings)
