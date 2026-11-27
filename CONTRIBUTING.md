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
- **Type hints on all public functions.** `mypy (strict mode is aspirational)` must pass.
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

## Release Process

Maintainer only. A release is a bump commit, a tag on that commit, and the tag
push. The tag push is what runs the publish workflow — a bump commit on its own
publishes nothing.

1. Confirm `main` is green in CI and the working tree is clean.
2. Bump `[project].version` in `pyproject.toml`. `janissary.__version__` is read
   from installed distribution metadata, not hardcoded, so nothing in `src/`
   moves with it.
3. **Reinstall the package into the venv** with `python -m pip install -e .`
   before running the suite. The editable install records the declared version
   at install time and that metadata survives a `pyproject.toml` edit, while
   `tests/unit/test_version_consistency.py` compares the two. Skip this and the
   version-consistency test fails at pre-push on a bump that is otherwise
   correct — the failure is stale metadata, not a bad edit.
   The venv carries no `setuptools` or `wheel`, so leave build isolation on:
   `--no-build-isolation` fails on the `supports_feature` backend hook.
4. Move the `## [Unreleased]` entries into a new `## [<version>] - <date>`
   section and write a release note. The section must clear 200 characters or
   the release workflow refuses the tag.
5. Update the README version badge, the release-note list and the `docker run`
   tag.
6. Commit, tag the commit `v<version>`, and push the tag.

Retry a failed publish with `workflow_dispatch` against the existing tag. Do not
delete and re-push the tag: the version assertion and the PyPI duplicate check
both trip on a moved tag, and each retry costs a published version number.

PRs are reviewed within 72 hours. We aim to merge within 7 days.

## Governance

JANISSARY is maintained by a project maintainer. Decisions about the
detection engine and the payload library are made by consensus of
the core team. Community contributions are welcomed and credited in
the release notes.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
By participating, you agree to uphold it.


## Licensing
Contributions are accepted under the Apache License 2.0 (see LICENSE). By submitting a pull request, you agree to license your contribution under these terms. No Contributor License Agreement (CLA) or copyright assignment is required.

### Developer Certificate of Origin

Every commit needs a sign-off line certifying you wrote it, or otherwise have the right to submit it under Apache-2.0, per the [Developer Certificate of Origin 1.1](https://developercertificate.org/). Add it with `git commit -s`, which appends:

```text
Signed-off-by: Your Name <you@example.com>
```

Use a real name and a reachable address. A maintainer will ask for the sign-off if it is missing.
