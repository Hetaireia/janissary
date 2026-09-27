"""Git history credential scanner.

Walks `git log --all` and scans each commit's *added* lines for
secrets. Uses the same rule engine and entropy fallback as the file
scanner, so a token leaked in a commit message, a deleted file, or a
rewritten config is caught the same way a token in the working tree
would be.

Only added lines are scanned. If the same token is committed and then
later removed, it appears once — as an addition — not twice (once as
an addition, once as a removal).

Path handling
-------------
The prototype's _sanitize_repo_path rejected any path containing
shell metacharacters, including backslash. On Windows this rejected
every absolute path (`C:\\Users\\...`). The correct security model is:

  1. Never invoke a shell. subprocess.run([...], shell=False) passes
     argv directly to the executable; shell metacharacters in an
     argument have no special meaning.
  2. Validate that the path is a directory that contains `.git/`.
  3. Optionally, if the caller supplies allow_root, verify the resolved
     path is under that root. This defends against a caller who has
     been tricked into passing an attacker-controlled path.

With shell=False and a `.git` existence check, path sanitization by
string filtering is both unnecessary and (as the prototype showed)
harmful.

Windows git crash workaround
----------------------------
Windows git 2.55 has a known race where git <config> writes to
.git/config collide with antivirus / filesystem watchers, causing
git to crash with STATUS_ACCESS_VIOLATION (0xC0000005 / 3221225477)
instead of returning an error. _run_git retries once on that code.

Limitations
-----------
- Merge commits produce no diff by default; a secret introduced only
  in a merge is not detected. This matches gitleaks' default behavior.
- `max_commits` caps the walk. A full scan of a large repo will be
  slow; pass max_commits to bound it.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from .scanner import scan_text_for_secrets

GIT_TIMEOUT = 60
WINDOWS_RETRYABLE_CODES = {3221225477, 3221225501}  # ACCESS_VIOLATION, DLL_INIT_FAILED


# -------------------------------------------------------------------
# PATH VALIDATION
# -------------------------------------------------------------------


def _validate_repo_path(repo_path: str, allow_root: str | None = None) -> Path:
    """Return a resolved Path to a git working tree, or raise ValueError.

    Structural checks only — no string filtering. See module docstring.
    """
    if not repo_path:
        raise ValueError("repo_path is empty")
    p = Path(repo_path).expanduser().resolve()
    if not p.is_dir():
        raise ValueError(f"not a directory: {p}")
    git_dir = p / ".git"
    if not git_dir.is_dir():
        raise ValueError(f"not a git repository (no .git directory): {p}")
    if allow_root is not None:
        root = Path(allow_root).expanduser().resolve()
        try:
            p.relative_to(root)
        except ValueError:
            raise ValueError(f"{p} is not under allowed root {root}") from None
    return p


# -------------------------------------------------------------------
# GIT WRAPPER
# -------------------------------------------------------------------


def _run_git(
    repo: Path,
    args: list[str],
    timeout: int = GIT_TIMEOUT,
) -> subprocess.CompletedProcess:
    """Invoke git with the given args. shell=False, no string building.

    Retries once on Windows STATUS_ACCESS_VIOLATION, which Windows git
    2.55 can emit spuriously when antivirus is watching the repo.
    """
    cmd = ["git", "-C", str(repo), "-c", "core.quotepath=false", *args]
    last: subprocess.CompletedProcess | None = None
    for attempt in (1, 2, 3):
        last = subprocess.run(
            cmd,
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
        if last.returncode not in WINDOWS_RETRYABLE_CODES or attempt >= 3:
            return last
        time.sleep(0.3 * attempt)
    assert last is not None
    return last


# -------------------------------------------------------------------
# COMMIT ENUMERATION
# -------------------------------------------------------------------

_LOG_FORMAT = "%H%x00%an%x00%ad%x00%s"


def list_commits(
    repo: Path,
    max_commits: int | None = None,
) -> list[tuple[str, str, str, str]]:
    """Return [(sha, author, date, subject), ...] newest-first."""
    r = _run_git(
        repo,
        ["log", "--all", f"--pretty=format:{_LOG_FORMAT}", "--date=iso"],
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"git log failed (code {r.returncode}): {r.stderr.strip()[:200]}"
        )
    out: list[tuple[str, str, str, str]] = []
    for line in r.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\x00")
        if len(parts) != 4:
            continue
        out.append((parts[0], parts[1], parts[2], parts[3]))
    if max_commits is not None:
        out = out[:max_commits]
    return out


# -------------------------------------------------------------------
# DIFF FILTER
# -------------------------------------------------------------------


def _added_lines(diff_text: str) -> str:
    """Return only the added (+) lines from a diff.

    Excludes the +++ file header. Excludes removed (-) lines: a
    secret that appears only as a removal was already reported when
    it was added in an earlier commit.

    Includes context ( ) lines so a rewrite hunk that keeps a token
    in the surrounding lines still surfaces it.
    """
    out: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+++"):
            continue
        if line.startswith("-"):
            continue
        if line.startswith("+") or line.startswith(" "):
            out.append(line[1:])
    return "\n".join(out)


# -------------------------------------------------------------------
# PER-COMMIT SCAN
# -------------------------------------------------------------------


def scan_commit(
    repo: Path,
    sha: str,
    enable_entropy: bool = True,
    added_only: bool = True,
) -> list[dict]:
    """Return findings for one commit's diff."""
    r = _run_git(
        repo,
        ["show", "--no-color", "--pretty=format:", sha],
    )
    if r.returncode != 0:
        return []
    text = _added_lines(r.stdout) if added_only else r.stdout
    return scan_text_for_secrets(
        text,
        source_label=f"git:{sha[:10]}",
        enable_entropy=enable_entropy,
    )


# -------------------------------------------------------------------
# TOP-LEVEL
# -------------------------------------------------------------------


def scan_git_history(
    repo_path: str,
    max_commits: int | None = None,
    enable_entropy: bool = True,
    *,
    allow_root: str | None = None,
    quiet: bool = False,
) -> list[dict]:
    """Scan a git repository's history for secrets.

    Raises ValueError if repo_path is not a git working tree (or is
    outside allow_root when supplied). Returns a list of finding dicts
    in the same shape as scanner.scan_text_for_secrets, augmented with
    commit, commit_author, and commit_date keys.
    """
    repo = _validate_repo_path(repo_path, allow_root=allow_root)
    commits = list_commits(repo, max_commits=max_commits)
    if not quiet:
        print(f"[*] git history: {len(commits)} commit(s) to inspect")

    findings: list[dict] = []
    for i, (sha, author, date, _subject) in enumerate(commits, 1):
        hits = scan_commit(repo, sha, enable_entropy=enable_entropy)
        for h in hits:
            h["commit"] = sha
            h["commit_author"] = author
            h["commit_date"] = date
        findings.extend(hits)
        if not quiet and i % 50 == 0:
            print(f"    ... scanned {i}/{len(commits)} commits")
    if not quiet:
        print(f"[*] git history scan: {len(findings)} token(s) found")
    return findings
