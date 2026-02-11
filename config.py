"""
OpenClaw Shield — Configuration

Enterprise defaults with security-first settings.
Customize for your environment, keeping allowlists tight.
"""
from __future__ import annotations

# Project identification
PROJECT_NAME = "OpenClaw Shield"
VERSION = "1.0.0"

# ============================================================================
# RUNTIME GUARD SETTINGS
# ============================================================================

# Continuous runtime guard must be OFF by default.
# Set to True in production after configuring allowlists.
RUNTIME_GUARD_ENABLED_DEFAULT = False

# ============================================================================
# STATIC SCANNER SETTINGS
# ============================================================================

# Directories to skip during static scan
SKIP_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    "eggs",
    ".eggs",
    "*.egg-info",
}

# File size cap for scanning (bytes) — skip larger files
MAX_FILE_BYTES = 2_000_000  # 2MB

# Extensions to include in static scan
INCLUDE_EXTS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".sh",
    ".bash",
    ".zsh",
    ".rb",
    ".go",
    ".rs",
    ".swift",
    ".json",
    ".txt",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".mk",
    ".env",
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
}

# Specific filenames to always include
INCLUDE_FILENAMES = {
    "package.json",
    "requirements.txt",
    "Pipfile",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "makefile",
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".env",
    ".env.local",
    ".env.production",
}

# ============================================================================
# SECRET DETECTION
# ============================================================================

# Common secret environment variable names (extend per environment)
SUSPECT_ENV_VARS = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_OPENAI_API_KEY",
    "AZURE_API_KEY",
    "HF_TOKEN",
    "HUGGINGFACE_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "DATABASE_URL",
    "DB_PASSWORD",
    "REDIS_URL",
    "STRIPE_SECRET_KEY",
    "STRIPE_API_KEY",
    "TWILIO_AUTH_TOKEN",
    "SENDGRID_API_KEY",
    "SLACK_TOKEN",
    "SLACK_BOT_TOKEN",
    "DISCORD_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "JWT_SECRET",
    "SECRET_KEY",
    "ENCRYPTION_KEY",
    "PRIVATE_KEY",
]

# ============================================================================
# RUNTIME POLICY DEFAULTS
# ============================================================================

# Default policy allowlists (runtime guard)
# NOTE: Keep tight; expand only with explicit human approval.

DEFAULT_ALLOWED_READ_PATHS: list[str] = [
    # Example: project working directory is allowed at runtime
    # Add your workspace path here: "/app/workspace/*"
]

DEFAULT_ALLOWED_WRITE_PATHS: list[str] = [
    # Example: logs directory only
    # Add paths here: "/app/logs/*"
]

DEFAULT_ALLOWED_DOMAINS: list[str] = [
    # Example: "api.openai.com", "api.anthropic.com"
    # Add allowed domains here
]

# ============================================================================
# AUDIT LOGGING
# ============================================================================

# Path for audit log output (JSONL format)
AUDIT_LOG_PATH = "shield_audit.jsonl"

# ============================================================================
# SEVERITY LEVELS
# ============================================================================

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

# Severity ordering for comparisons
SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 4,
    SEVERITY_HIGH: 3,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 1,
}
