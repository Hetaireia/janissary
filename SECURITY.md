# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 7.x     | Yes       |
| < 7.0   | No        |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Report vulnerabilities in JANISSARY itself to
`hetaireia.it@gmail.com`. Include:

- A description of the vulnerability
- Steps to reproduce
- The affected version
- Any suggested fix

We will acknowledge receipt within 48 hours and provide a timeline
for a fix within 5 business days.

## Scope

JANISSARY is an offensive security tool. The following are **not**
considered vulnerabilities in JANISSARY:

- The tool can be used to attack systems. This is its purpose.
- The tool triggers WAF blocks. This is expected behavior.
- The tool produces false positives in some edge cases. Report these
  as bugs, not security issues.

The following **are** in scope:

- Command injection in JANISSARY's own subprocess calls
- Path traversal in JANISSARY's file operations
- Credential leakage in JANISSARY's logs or reports
- Remote code execution via JANISSARY's parsing logic

## Disclosure

We follow a 90-day coordinated disclosure policy. We will credit
reporters in the release notes unless they request anonymity.
