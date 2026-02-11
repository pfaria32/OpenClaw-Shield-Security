"""
OpenClaw Shield — Sanitizer

Secret redaction for output sanitization.

Detects and redacts common secret patterns:
- API keys (OpenAI, Anthropic, AWS, etc.)
- Private keys (RSA, EC, OPENSSH)
- JWTs
- Other credential patterns

NOTE: These are heuristic patterns. Add organization-specific
formats as needed. False positives are preferable to leaks.
"""
from __future__ import annotations

import re
from typing import List, Tuple, Pattern

# Replacement text for redacted secrets
REPLACEMENT = "[REDACTED]"

# Secret detection patterns
# Format: (name, compiled regex pattern)
_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    # OpenAI API keys (sk-...)
    (
        "openai_api_key",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    ),
    # Anthropic API keys (sk-ant-...)
    (
        "anthropic_api_key",
        re.compile(r"\b(?:sk-ant|ant)[A-Za-z0-9\-_]{10,}\b", re.IGNORECASE),
    ),
    # AWS Access Key ID (AKIA...)
    (
        "aws_access_key_id",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    # AWS Secret Access Key (40 chars, base64-ish)
    # Note: This can have false positives; adjust threshold as needed
    (
        "aws_secret_access_key",
        re.compile(r"\b[0-9A-Za-z/+]{40}\b"),
    ),
    # Generic API key patterns
    (
        "generic_api_key",
        re.compile(r"\b[a-zA-Z0-9]{32,64}\b(?=.*(?:key|token|secret|api))", re.IGNORECASE),
    ),
    # Private key blocks (PEM format)
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
            r".*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    # JWTs (three base64url segments separated by dots)
    (
        "jwt",
        re.compile(r"\beyJ[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\b"),
    ),
    # GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
    (
        "github_token",
        re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
    ),
    # GitLab tokens
    (
        "gitlab_token",
        re.compile(r"\bglpat-[A-Za-z0-9\-]{20,}\b"),
    ),
    # Slack tokens
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    ),
    # Discord tokens
    (
        "discord_token",
        re.compile(r"\b[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}\b"),
    ),
    # Stripe keys
    (
        "stripe_key",
        re.compile(r"\b(sk|pk)_(test|live)_[A-Za-z0-9]{24,}\b"),
    ),
    # SendGrid API keys
    (
        "sendgrid_key",
        re.compile(r"\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}\b"),
    ),
    # Twilio tokens
    (
        "twilio_token",
        re.compile(r"\b(AC|SK)[a-f0-9]{32}\b"),
    ),
    # Database connection strings (redact password portion)
    (
        "database_url",
        re.compile(
            r"(?:postgres|mysql|mongodb|redis)(?:ql)?://[^:]+:([^@]+)@",
            re.IGNORECASE,
        ),
    ),
    # Bearer tokens in headers
    (
        "bearer_token",
        re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]{20,}", re.IGNORECASE),
    ),
    # Basic auth in URLs
    (
        "basic_auth_url",
        re.compile(r"https?://[^:]+:([^@]+)@"),
    ),
]


def sanitize_text(text: str) -> str:
    """
    Sanitize text by redacting detected secrets.

    Args:
        text: Input text that may contain secrets

    Returns:
        Text with secrets replaced by [REDACTED]
    """
    out = text

    for _name, pattern in _PATTERNS:
        out = pattern.sub(REPLACEMENT, out)

    return out


def find_secrets(text: str) -> List[Tuple[str, str, int, int]]:
    """
    Find secrets in text without redacting.

    Args:
        text: Input text to scan

    Returns:
        List of tuples: (pattern_name, matched_text, start_pos, end_pos)
    """
    findings: List[Tuple[str, str, int, int]] = []

    for name, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            findings.append((name, match.group(), match.start(), match.end()))

    return findings


def is_potentially_secret(text: str) -> bool:
    """
    Quick check if text might contain a secret.

    Args:
        text: Input text to check

    Returns:
        True if any secret pattern matches
    """
    for _name, pattern in _PATTERNS:
        if pattern.search(text):
            return True
    return False


def add_custom_pattern(name: str, pattern: str, flags: int = 0) -> None:
    """
    Add a custom secret detection pattern.

    Args:
        name: Identifier for the pattern
        pattern: Regex pattern string
        flags: Optional regex flags (e.g., re.IGNORECASE)
    """
    _PATTERNS.append((name, re.compile(pattern, flags)))


def get_pattern_names() -> List[str]:
    """Get list of all active pattern names."""
    return [name for name, _ in _PATTERNS]
