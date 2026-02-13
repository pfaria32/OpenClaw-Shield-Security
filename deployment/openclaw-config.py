"""
OpenClaw Shield — Deployment Configuration

Custom configuration for Pedro's OpenClaw instance.
"""
from __future__ import annotations

# ============================================================================
# DEPLOYMENT IDENTIFICATION
# ============================================================================

DEPLOYMENT_NAME = "clawdbot-toronto"
DEPLOYMENT_ENV = "production"
OWNER = "Pedro Bento de Faria"

# ============================================================================
# RUNTIME GUARD SETTINGS
# ============================================================================

# Runtime guard is NOW ENABLED (2026-02-13)
# Activated after ClamAV installation and policy review
RUNTIME_GUARD_ENABLED = True

# ============================================================================
# STATIC SCANNER SETTINGS
# ============================================================================

# Workspace to scan
WORKSPACE_PATH = "/home/node/.openclaw/workspace"

# Scan schedule: Daily at 3:00 AM UTC (after memory embeddings)
# Configured via OpenClaw cron job

# Scan output
SCAN_REPORT_DIR = "/home/node/.openclaw/workspace/security-reports"
SCAN_LOG_FILE = "/home/node/.openclaw/workspace/security-reports/shield-scan.log"

# Skip additional directories (beyond defaults)
CUSTOM_SKIP_DIRS = {
    "node_modules",
    ".git",
    "__pycache__",
    "venv",
    ".venv",
    "dist",
    "build",
    ".cache",
    ".bun",
    "github-memory-project/.git",  # Nested git repos
    "projects/openclaw/.git",
    "projects/token-economy/.git",
    "projects/OpenClaw-Shield/.git",
}

# ============================================================================
# RUNTIME POLICY DEFAULTS (for future activation)
# ============================================================================

# File access allowlists
ALLOWED_READ_PATHS = [
    # Workspace (read-only for most operations)
    "/home/node/.openclaw/workspace/*",
    
    # User files (for USER.md, AGENTS.md, etc.)
    "/home/node/.openclaw/workspace/AGENTS.md",
    "/home/node/.openclaw/workspace/SOUL.md",
    "/home/node/.openclaw/workspace/TOOLS.md",
    "/home/node/.openclaw/workspace/USER.md",
    "/home/node/.openclaw/workspace/IDENTITY.md",
    "/home/node/.openclaw/workspace/MEMORY.md",
    "/home/node/.openclaw/workspace/HEARTBEAT.md",
    
    # Memory system
    "/home/node/.openclaw/workspace/memory/*",
    
    # Skills
    "/home/node/.openclaw/workspace/skills/*",
    
    # Projects
    "/home/node/.openclaw/workspace/projects/*",
    
    # Scripts
    "/home/node/.openclaw/workspace/scripts/*",
    
    # System config (read-only)
    "/home/node/.openclaw/openclaw.json",
    "/home/node/.ssh/config",
    "/home/node/.ssh/*.pub",  # Public keys only
    
    # Temporary files
    "/tmp/*",
]

ALLOWED_WRITE_PATHS = [
    # Memory system writes
    "/home/node/.openclaw/workspace/memory/daily/*",
    "/home/node/.openclaw/workspace/memory/inbox/*",
    "/home/node/.openclaw/workspace/memory/ops/scripts/logs/*",
    
    # Project work
    "/home/node/.openclaw/workspace/projects/*",
    
    # Security reports
    "/home/node/.openclaw/workspace/security-reports/*",
    
    # Logs
    "/home/node/.openclaw/workspace/*.log",
    
    # Temporary files
    "/tmp/*",
    
    # Git operations
    "/home/node/.openclaw/workspace/projects/*/.git/*",
]

# Network access allowlists
ALLOWED_DOMAINS = [
    # LLM providers
    "api.openai.com",
    "api.anthropic.com",
    
    # GitHub (for git operations)
    "github.com",
    "api.github.com",
    "ssh.github.com",  # Port 443 SSH
    
    # Search
    "api.search.brave.com",
    
    # Todoist
    "api.todoist.com",
    
    # Microsoft Graph (Outlook)
    "graph.microsoft.com",
    "login.microsoftonline.com",
    
    # Groq (Whisper)
    "api.groq.com",
    
    # Strava (fitness tracking)
    "www.strava.com",
    "api.strava.com",
    
    # Package managers (for updates)
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "files.pythonhosted.org",
    
    # Bun runtime
    "bun.sh",
    "github.com",  # For bun install from GitHub
    
    # Model downloads (HuggingFace)
    "huggingface.co",
    "cdn.huggingface.co",
    
    # Documentation
    "docs.openclaw.ai",
    
    # Localhost (for local services)
    "localhost",
    "127.0.0.1",
    "::1",
]

# ============================================================================
# AUDIT LOGGING
# ============================================================================

# Audit log location
AUDIT_LOG_PATH = "/home/node/.openclaw/workspace/security-reports/shield_audit.jsonl"

# ============================================================================
# ALERT THRESHOLDS
# ============================================================================

# Alert on any CRITICAL findings
ALERT_ON_CRITICAL = True

# Alert if HIGH findings exceed threshold
ALERT_HIGH_THRESHOLD = 3

# Alert if total findings exceed threshold
ALERT_TOTAL_THRESHOLD = 10

# ============================================================================
# NOTIFICATION SETTINGS
# ============================================================================

# How to notify on security alerts
NOTIFY_METHOD = "openclaw_message"  # Use OpenClaw's message system
NOTIFY_CHANNEL = "telegram"  # Primary channel

# Notification message template
ALERT_MESSAGE_TEMPLATE = """
🛡️ **OpenClaw Shield Security Alert**

**Scan:** {scan_timestamp}
**Findings:** {total_findings} total ({critical} critical, {high} high)

**Critical issues:**
{critical_list}

**Action required:** Review security report at:
`{report_path}`

**Command to view:**
```bash
cat {report_path} | jq
```
"""

# ============================================================================
# CLAMAV INTEGRATION (Host-Level Antivirus)
# ============================================================================

# ClamAV daemon configuration
CLAMAV_ENABLED = True
CLAMAV_SOCKET = "/run/clamav/clamd.ctl"  # Socket path on host
CLAMAV_TIMEOUT = 120  # Scan timeout in seconds

# ClamAV installation details (2026-02-13)
# Version: 1.4.3+dfsg-0ubuntu0.24.04.1
# Signatures: ~3.6M (daily: 354,987 + main: 3,287,027 + bytecode: 80)
# Services:
#   - clamav-daemon: Active (clamd scanner)
#   - clamav-freshclam: Active (signature updates)
#   - clamav-daemon.socket: Active (socket activation)

# When to scan with ClamAV
CLAMAV_SCAN_ON_FILE_READ = False  # Too slow for every read
CLAMAV_SCAN_ON_FILE_WRITE = True  # Scan files before writing
CLAMAV_SCAN_DOWNLOADS = True      # Scan network-fetched files
CLAMAV_SCAN_UPLOADS = True        # Scan before uploading files

# What to scan
CLAMAV_MAX_FILE_SIZE = 50_000_000  # 50MB max (larger files skipped)
CLAMAV_SCAN_ARCHIVES = True        # Scan inside .zip, .tar, etc.

# Actions on virus detection
CLAMAV_ACTION_ON_VIRUS = "block"   # block | quarantine | log
CLAMAV_QUARANTINE_DIR = "/home/node/.openclaw/workspace/security-reports/quarantine"

# Notification on virus detection
CLAMAV_ALERT_ON_VIRUS = True
CLAMAV_ALERT_METHOD = "openclaw_message"
CLAMAV_ALERT_CHANNEL = "telegram"
