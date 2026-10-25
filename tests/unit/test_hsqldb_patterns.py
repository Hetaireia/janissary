from pathlib import Path

from janissary.detection.analyzer import DB_ERROR_PATTERNS


def test_hsqldb_patterns_present():
    assert "hsqldb" in DB_ERROR_PATTERNS
    samples = [
        "unexpected token: 1 in statement [ CALL  ]",
        "unexpected end of statement in statement [ CALL  ]",
        "user lacks privilege or object not found: TEST in statement [ CALL test ]",
        "java.sql.SQLSyntaxErrorException: some error",
        "org.hsqldb.HsqlException: foo",
    ]
    for s in samples:
        assert any(p.search(s) for p in DB_ERROR_PATTERNS["hsqldb"]), \
            f"HSQLDB pattern missing for: {s}"


def test_hsqldb_patterns_do_not_match_shell_errors():
    """The 8a65195 lesson: shell errors must not match DB patterns."""
    shell = "sh: 1: Syntax error: Unterminated quoted string"
    for dbms, patterns in DB_ERROR_PATTERNS.items():
        for p in patterns:
            assert not p.search(shell), \
                f"{dbms} pattern {p.pattern!r} matches shell error"


def test_db_error_forces_sqli_category(tmp_path):
    """db_error findings must carry class=sqli regardless of probe."""
    src = Path("src/janissary/engine/scanner.py").read_text(encoding="utf-8")
    # Anchor: the override must be present in the emit loop
    assert 'if f.get("type") == "db_error":' in src
    assert 'category = "sqli"' in src
