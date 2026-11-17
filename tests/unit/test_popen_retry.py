"""Unit tests for _popen_with_retry (transient PermissionError mitigation)."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from benchmark.track_a.runner import _popen_with_retry


def test_succeeds_first_attempt():
    """No PermissionError -> no retry, no sleep."""
    sentinel = MagicMock(name="proc")
    with patch("benchmark.track_a.runner.subprocess.Popen", return_value=sentinel) as mock_popen, patch("benchmark.track_a.runner.time.sleep") as mock_sleep:
        result = _popen_with_retry(["cmd"], creationflags=0)
    assert result is sentinel
    assert mock_popen.call_count == 1
    assert mock_sleep.call_count == 0


def test_retries_on_permission_error_then_succeeds():
    """PermissionError on first attempt -> retried, second attempt returns proc."""
    sentinel = MagicMock(name="proc")
    side_effects = [PermissionError(13, "Access is denied"), sentinel]
    with patch("benchmark.track_a.runner.subprocess.Popen", side_effect=side_effects) as mock_popen, patch("benchmark.track_a.runner.time.sleep") as mock_sleep:
        result = _popen_with_retry(["cmd"], creationflags=0)
    assert result is sentinel
    assert mock_popen.call_count == 2
    assert mock_sleep.call_count == 1


def test_raises_after_all_attempts_exhausted():
    """Three PermissionErrors -> raise on the third."""
    with patch("benchmark.track_a.runner.subprocess.Popen", side_effect=PermissionError(13, "Access is denied")) as mock_popen, patch("benchmark.track_a.runner.time.sleep"):
        with pytest.raises(PermissionError):
            _popen_with_retry(["cmd"], creationflags=0)
    assert mock_popen.call_count == 3


def test_does_not_retry_on_other_oserror():
    """FileNotFoundError is a real defect (missing binary) - must propagate immediately."""
    with patch("benchmark.track_a.runner.subprocess.Popen", side_effect=FileNotFoundError("no python")), patch("benchmark.track_a.runner.time.sleep") as mock_sleep:
        with pytest.raises(FileNotFoundError):
            _popen_with_retry(["cmd"], creationflags=0)
    assert mock_sleep.call_count == 0

