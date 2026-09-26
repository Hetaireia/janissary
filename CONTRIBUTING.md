# Contributing to JANISSARY

Thanks for your interest. This document covers the dev setup, code
style, and the PR process.

## Development Setup

```bash
git clone https://github.com/Hetaireia/janissary
cd janissary
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Run the test suite:

```bash
pytest
```

Run linting and type checks:

```bash
ruff check src tests
mypy src
```

## Code Style

- **Python 3.10+**. Use modern syntax (`X | None`, `match` statements).
- **Line length: 88** (Black default).
- **Type hints on all public functions.** `mypy --strict` must pass.
- **No `shell=True` in subprocess calls.** Ever.
- **No new dependencies without a discussion in an issue first.**

We use `ruff` for linting and formatting. Run `ruff format src tests`
before committing.

## The Detection Engine Rules

If you are contributing a new detection gate, read this first.

The engine design principle is: **it is better to miss a finding
than to emit a false positive.** Every gate must:

1. **Compare against a baseline.** No finding may be emitted from a
   single response alone.
2. **Have a named, testable condition.** "Response looks suspicious"
   is not a gate. "Response contains `ORA-` followed by 5 digits and
   the baseline does not" is a gate.
3. **Include a unit test with a negative case.** For every gate,
   there must be a test that asserts the gate does NOT fire on
   benign input.

PRs that add a detection gate without a negative test will be
rejected.

## Adding a Payload

Payloads live in `src/janissary/detection/payloads.py`. Each payload
is a tuple of `(name, value, category, severity)`.

- `name` must be unique and snake_case.
- `value` is the raw string sent to the target.
- `category` is one of: `sqli`, `nosqli`, `xss`, `ssrf`, `traversal`,
  `cmdi`, `ldap`, `ssti`, `xxe`, `auth`, `header_injection`, `gql`.
- `severity` is one of: `critical`, `high`, `medium`, `low`, `info`.

## Adding a Credential Rule

Credential rules live in `src/janissary/credentials/rules.py`. Each
rule is a dict with `id`, `description`, `regex`, `secret_group`,
`entropy`, and `allowlist`.

Include a test fixture with a **redacted** sample of the token. Never
commit a real token.

## PR Process

1. Open an issue first for non-trivial changes.
2. Fork, branch, and implement.
3. Add tests. All new code must have >80% coverage.
4. Update `CHANGELOG.md` under `## [Unreleased]`.
5. Open a PR. Fill in the template.

PRs are reviewed within 72 hours. We aim to merge within 7 days.

## Governance

JANISSARY is maintained by a small core team. Decisions about the
detection engine and the payload library are made by consensus of
the core team. Community contributions are welcomed and credited in
the release notes.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
By participating, you agree to uphold it.
