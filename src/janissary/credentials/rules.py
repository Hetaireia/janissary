"""Credential detection rule set.

Three engines run over every scanned text:

  GITLEAKS_RULES      provider-specific regexes with optional entropy floors.
  KEYHUNTER_PATTERNS  high-signal provider segments (e.g. OpenAI's unique
                      "T3BlbkFJ" mid-string) that a generic regex misses.
  Entropy fallback    TruffleHog-style Shannon entropy over base64 and hex
                      strings with no provider context at all.

Each rule is a dict:

    id           stable machine identifier; appears in findings and exports
    description  human-readable label
    regex        compiled pattern
    secret_group capture group that yields the secret (0 = whole match)
    entropy      Shannon threshold over base64 charset; 0.0 disables the check
    allowlist    list of compiled patterns; a match is dropped if any matches

Rules are data only. All evaluation lives in scanner.py.
"""

from __future__ import annotations

import re

GITLEAKS_RULES: list[dict] = [
    {
        "id": "generic-api-key",
        "description": "Generic API Key",
        "regex": re.compile(
            r"(?i)(api[_\-\s]?key|apikey|api[_\-\s]?secret|"
            r"api[_\-\s]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"
        ),
        "secret_group": 2,
        "entropy": 3.5,
        "allowlist": [re.compile(r".+EXAMPLE$"), re.compile(r"YOUR_")],
    },
    {
        "id": "aws-access-token",
        "description": "AWS Access Key",
        "regex": re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"),
        "secret_group": 1,
        "entropy": 3.0,
        "allowlist": [re.compile(r".+EXAMPLE$")],
    },
    {
        "id": "aws-secret-key",
        "description": "AWS Secret Key",
        "regex": re.compile(
            r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        "secret_group": 1,
        "entropy": 4.0,
        "allowlist": [],
    },
    {
        "id": "github-pat",
        "description": "GitHub Personal Access Token",
        "regex": re.compile(r"\b(ghp_[a-zA-Z0-9]{36})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "github-oauth",
        "description": "GitHub OAuth Access Token",
        "regex": re.compile(r"\b(gho_[a-zA-Z0-9]{36})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "github-app-token",
        "description": "GitHub App Token",
        "regex": re.compile(r"\b(ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "gitlab-pat",
        "description": "GitLab Personal Access Token",
        "regex": re.compile(r"\b(glpat-[a-zA-Z0-9\-_]{20})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "slack-token",
        "description": "Slack Token",
        "regex": re.compile(r"\b(xox[baprs]-[0-9a-zA-Z\-]{10,72})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "stripe-key",
        "description": "Stripe API Key",
        "regex": re.compile(r"\b((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [re.compile(r".+EXAMPLE$")],
    },
    {
        "id": "twilio-key",
        "description": "Twilio API Key",
        "regex": re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "sendgrid-key",
        "description": "SendGrid API Key",
        "regex": re.compile(r"\b(SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "private-key",
        "description": "Private Key",
        "regex": re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        ),
        "secret_group": 0,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "jwt-token",
        "description": "JSON Web Token",
        "regex": re.compile(
            r"\b(eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)\b"
        ),
        "secret_group": 1,
        "entropy": 4.0,
        "allowlist": [],
    },
    {
        "id": "shopify-token",
        "description": "Shopify Access Token",
        "regex": re.compile(r"\b(shpat_[a-fA-F0-9]{32})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "shopify-private-app",
        "description": "Shopify Private App Token",
        "regex": re.compile(r"\b(shppa_[a-fA-F0-9]{32})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "shopify-custom-app",
        "description": "Shopify Custom App Token",
        "regex": re.compile(r"\b(shpca_[a-fA-F0-9]{32})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "shopify-shared-secret",
        "description": "Shopify Shared Secret",
        "regex": re.compile(r"\b(shpss_[a-fA-F0-9]{32})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "google-api-key",
        "description": "Google API Key",
        "regex": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "openai-api-key",
        "description": "OpenAI API Key",
        "regex": re.compile(r"\b(sk-[a-zA-Z0-9]{48})\b"),
        "secret_group": 1,
        "entropy": 3.5,
        "allowlist": [re.compile(r"sk-proj-")],
    },
    {
        "id": "anthropic-api-key",
        "description": "Anthropic API Key",
        "regex": re.compile(r"\b(sk-ant-[a-zA-Z0-9\-_]{40,})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "discord-token",
        "description": "Discord Bot Token",
        "regex": re.compile(r"\b([MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "telegram-bot-token",
        "description": "Telegram Bot Token",
        "regex": re.compile(r"\b(\d{8,10}:[a-zA-Z0-9_-]{35})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "facebook-token",
        "description": "Facebook Access Token",
        "regex": re.compile(r"\b(EAA[0-9A-Za-z]{60,})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "heroku-api-key",
        "description": "Heroku API Key",
        "regex": re.compile(
            r"(?i)heroku[a-z0-9_ .\-,]{0,25}(?:=|>|:=|\|\|:|<=|=>|:)\s*"
            r"['\"]?([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})"
        ),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "mailgun-key",
        "description": "Mailgun API Key",
        "regex": re.compile(r"\b(key-[0-9a-f]{32})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "npm-token",
        "description": "NPM Access Token",
        "regex": re.compile(r"\b(npm_[a-zA-Z0-9]{36})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "pypi-token",
        "description": "PyPI Upload Token",
        "regex": re.compile(r"\b(pypi-[a-zA-Z0-9_\-]{50,})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "sentry-auth-token",
        "description": "Sentry Auth Token",
        "regex": re.compile(
            r"(?i)sentry[^\n]{0,50}(?:=|>|:=|\|\|:|<=|=>|:)\s*"
            r"['\"]?([0-9a-f]{64})['\"]?"
        ),
        "secret_group": 1,
        "entropy": 3.0,
        "allowlist": [],
    },
    {
        "id": "datadog-api-key",
        "description": "Datadog API Key",
        "regex": re.compile(
            r"(?i)datadog[^\n]{0,50}(?:=|>|:=|\|\|:|<=|=>|:)\s*"
            r"['\"]?([0-9a-f]{32})['\"]?"
        ),
        "secret_group": 1,
        "entropy": 3.0,
        "allowlist": [],
    },
    {
        "id": "algolia-api-key",
        "description": "Algolia API Key",
        "regex": re.compile(r"\b([A-Z0-9]{10}\.[A-Z0-9]{32})\b"),
        "secret_group": 1,
        "entropy": 3.0,
        "allowlist": [],
    },
    {
        "id": "mapbox-token",
        "description": "Mapbox Access Token",
        "regex": re.compile(r"\b(pk\.[a-zA-Z0-9_\-]{60,})\b"),
        "secret_group": 1,
        "entropy": 3.5,
        "allowlist": [],
    },
    {
        "id": "dropbox-token",
        "description": "Dropbox Access Token",
        "regex": re.compile(r"\b(sl\.[a-zA-Z0-9_\-]{130,})\b"),
        "secret_group": 1,
        "entropy": 3.5,
        "allowlist": [],
    },
]


KEYHUNTER_PATTERNS: list[dict] = [
    {
        "id": "openai-unique",
        "description": "OpenAI key (unique Base64 segment)",
        "regex": re.compile(r"\b(sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,})\b"),
        "secret_group": 1,
        "entropy": 3.5,
        "allowlist": [],
    },
    {
        "id": "anthropic-unique",
        "description": "Anthropic key (real prefix)",
        "regex": re.compile(r"\b(sk-ant-api03-[a-zA-Z0-9\-_]{40,})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "stripe-live",
        "description": "Stripe live key",
        "regex": re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
        "secret_group": 1,
        "entropy": 3.0,
        "allowlist": [],
    },
    {
        "id": "aws-secret-unique",
        "description": "AWS secret key (40 chars, high entropy)",
        "regex": re.compile(r"\b([A-Za-z0-9/+=]{40})\b"),
        "secret_group": 1,
        "entropy": 4.5,
        "allowlist": [re.compile(r"^[A-Z]+$")],
    },
    {
        "id": "huggingface-token",
        "description": "HuggingFace token",
        "regex": re.compile(r"\b(hf_[a-zA-Z0-9]{34,})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "replicate-token",
        "description": "Replicate API token",
        "regex": re.compile(r"\b(r8_[a-zA-Z0-9]{36,})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "perplexity-key",
        "description": "Perplexity API key",
        "regex": re.compile(r"\b(pplx-[a-zA-Z0-9]{48,})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "groq-key",
        "description": "Groq API key",
        "regex": re.compile(r"\b(gsk_[a-zA-Z0-9]{40,})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
    {
        "id": "xai-key",
        "description": "xAI (Grok) API key",
        "regex": re.compile(r"\b(xai-[a-zA-Z0-9]{40,})\b"),
        "secret_group": 1,
        "entropy": 0.0,
        "allowlist": [],
    },
]


ALL_RULES: list[dict] = GITLEAKS_RULES + KEYHUNTER_PATTERNS
