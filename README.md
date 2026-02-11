# OpenClaw Shield 🛡️

**Enterprise Security Subsystem for AI Agent Deployments**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![No Dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-green.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## Overview

OpenClaw Shield is a **Tier-0 security control** designed to protect AI agent deployments from:

- 🔑 **Credential theft** (API keys, tokens, SSH keys)
- 📤 **Data exfiltration** (sensitive files → external servers)
- 💥 **Destructive operations** (rm -rf, file deletion)
- 🚪 **Persistence mechanisms** (LaunchAgents, cron, shell profiles)
- 🌐 **Network backdoors** (reverse shells, listening sockets)
- 🎭 **Obfuscation** (base64+eval, dynamic code execution)

### Core Principles

```
Security > Features
Integrity > Convenience  
Human Oversight > Autonomous Action
```

### Key Features

| Feature | Description |
|---------|-------------|
| **Static Scanner** | Pre-execution scan of repositories and code |
| **Runtime Guard** | Continuous middleware protection (disabled by default) |
| **Output Sanitization** | Automatic secret redaction |
| **Audit Logging** | Tamper-evident hash-chained logs |
| **Zero Dependencies** | Python standard library only |

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/pfaria32/OpenClaw-Shield.git
cd OpenClaw-Shield
```

### 2. Run Static Scan

```bash
# Scan a directory
python3 shield_scan.py /path/to/scan

# Output JSON report
python3 shield_scan.py /path/to/scan > report.json

# Check exit code
echo $?  # 0=clean, 2=findings
```

### 3. Review Findings

```json
{
  "status": "flagged",
  "scanned_files": 42,
  "findings": [
    {
      "file": "/path/to/suspicious.py",
      "line": 15,
      "pattern": "possible_exfiltration_combo",
      "severity": "critical",
      "description": "File includes secret access and network activity",
      "code_snippet": "requests.post(url, data={'key': api_key})"
    }
  ]
}
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      OpenClaw Shield                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────┐         ┌──────────────────┐             │
│  │  shield_scan.py  │         │ runtime_guard.py │             │
│  │  (Static Scan)   │         │ (Runtime Guard)  │             │
│  │                  │         │                  │             │
│  │  • File scanning │         │  • Tool hooks    │             │
│  │  • Pattern match │         │  • Policy check  │             │
│  │  • Correlation   │         │  • Sanitization  │             │
│  └────────┬─────────┘         └────────┬─────────┘             │
│           │                            │                        │
│           ▼                            ▼                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    policies.py                           │   │
│  │  • FileAccessPolicy (read/write allowlists)              │   │
│  │  • NetworkPolicy (domain allowlists)                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│           │                            │                        │
│           ▼                            ▼                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    logger.py                             │   │
│  │  • JSONL audit logs                                      │   │
│  │  • Hash chain (tamper-evident)                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────┐         ┌──────────────────┐             │
│  │  sanitizer.py    │         │    config.py     │             │
│  │  (Secret Redact) │         │  (Settings)      │             │
│  └──────────────────┘         └──────────────────┘             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Static Scanner

### What It Detects

| Pattern | Severity | Description |
|---------|----------|-------------|
| `env_secret_read` | MEDIUM | Reads environment variables like API keys |
| `sensitive_path_access` | MEDIUM | References ~/.ssh, ~/.aws, keychains |
| `network_activity` | LOW | HTTP calls, external URLs |
| `possible_exfiltration_combo` | CRITICAL | Secret access + network in same file |
| `destructive_rm_rf` | CRITICAL | rm -rf on home/system paths |
| `destructive_fs_ops` | HIGH | shutil.rmtree, os.remove, etc. |
| `persistence_launch_agents` | HIGH | macOS LaunchAgent references |
| `persistence_cron` | HIGH | Crontab manipulation |
| `shell_profile_mod` | MEDIUM | .bashrc/.zshrc references |
| `reverse_shell` | CRITICAL | nc -e, bash -i, /dev/tcp patterns |
| `listening_socket` | MEDIUM | bind(), listen(), createServer() |
| `obfuscation_eval_base64` | HIGH | base64 + eval/exec combination |
| `obfuscation_long_line` | LOW | Very long JS/TS lines |

### Usage

```bash
# Basic scan
python3 shield_scan.py ./my-project

# Save report
python3 shield_scan.py ./my-project > shield_report.json

# Check specific severity in CI
python3 shield_scan.py ./my-project | jq '.findings[] | select(.severity == "critical")'
```

### Configuration

Edit `config.py` to customize:

```python
# Directories to skip
SKIP_DIRS = {".git", "node_modules", "venv", "__pycache__"}

# File extensions to scan
INCLUDE_EXTS = {".py", ".js", ".ts", ".sh", ".rb", ".go"}

# Suspicious environment variable names
SUSPECT_ENV_VARS = ["OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", ...]
```

---

## Runtime Guard

### Overview

The Runtime Guard provides **continuous protection** as middleware around tool calls. It enforces:

- **File access policies** (allowlists for read/write paths)
- **Network policies** (allowlists for outbound domains)
- **Tool justification** (require explanation for tool usage)
- **Output sanitization** (redact secrets from responses)

### ⚠️ Disabled by Default

```python
# config.py
RUNTIME_GUARD_ENABLED_DEFAULT = False  # Must explicitly enable
```

### Integration

```python
from runtime_guard import RuntimeGuard, ToolCall
from policies import FileAccessPolicy, NetworkPolicy
from logger import AuditLogger
from config import (
    AUDIT_LOG_PATH,
    DEFAULT_ALLOWED_READ_PATHS,
    DEFAULT_ALLOWED_WRITE_PATHS,
    DEFAULT_ALLOWED_DOMAINS,
)

# Initialize
audit_logger = AuditLogger(AUDIT_LOG_PATH)
file_policy = FileAccessPolicy(
    allowed_read=DEFAULT_ALLOWED_READ_PATHS + ["/app/workspace"],
    allowed_write=DEFAULT_ALLOWED_WRITE_PATHS + ["/app/workspace/output"],
)
net_policy = NetworkPolicy(
    allowed_domains=DEFAULT_ALLOWED_DOMAINS + ["api.openai.com"],
)

guard = RuntimeGuard(
    enabled=True,  # Enable in production
    audit_logger=audit_logger,
    file_policy=file_policy,
    net_policy=net_policy,
)

# Use in your agent loop
def execute_tool(tool_name: str, args: dict, justification: str):
    call = ToolCall(tool=tool_name, args=args, justification=justification)
    
    # Pre-execution check
    guard.before_tool_call(call)  # Raises PermissionError if blocked
    
    # Execute tool
    result = actual_tool_execution(tool_name, args)
    
    # Post-execution sanitization
    result = guard.after_tool_call(call, result)
    
    return result

# Sanitize all outputs
def send_response(text: str):
    safe_text = guard.sanitize_output(text)
    return safe_text
```

### Policy Examples

```python
# Tight production policy
file_policy = FileAccessPolicy(
    allowed_read=[
        "/app/workspace/*",
        "/app/config/settings.json",
    ],
    allowed_write=[
        "/app/workspace/output/*",
        "/app/logs/*",
    ],
)

net_policy = NetworkPolicy(
    allowed_domains=[
        "api.openai.com",
        "api.anthropic.com",
        ".amazonaws.com",  # Subdomains allowed with leading dot
    ],
)
```

---

## Audit Logging

### Format

Logs are written to `shield_audit.jsonl` in JSONL format with hash chaining:

```json
{"ts":1707654321.123,"event_type":"tool_call_allowed","severity":"low","message":"Tool call permitted","details":{"tool":"read_file"},"prev_hash":"abc123...","hash":"def456..."}
{"ts":1707654322.456,"event_type":"file_read_blocked","severity":"high","message":"read path not in allowlist","details":{"tool":"read_file","path":"/etc/passwd"},"prev_hash":"def456...","hash":"789abc..."}
```

### Tamper Evidence

Each log entry includes:
- `prev_hash`: SHA-256 of previous entry
- `hash`: SHA-256 of current entry (computed over canonical JSON)

To verify chain integrity:

```python
import json
import hashlib

def verify_chain(log_path: str) -> bool:
    prev = "0" * 64
    with open(log_path) as f:
        for line in f:
            entry = json.loads(line)
            if entry["prev_hash"] != prev:
                return False  # Chain broken
            # Recompute hash
            base = {k: v for k, v in entry.items() if k != "hash"}
            canon = json.dumps(base, sort_keys=True, separators=(",", ":"))
            expected = hashlib.sha256(canon.encode()).hexdigest()
            if entry["hash"] != expected:
                return False  # Hash mismatch
            prev = entry["hash"]
    return True
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  shield-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Run OpenClaw Shield
        run: |
          python shield_scan.py . > shield_report.json
          
      - name: Check for critical findings
        run: |
          CRITICAL=$(cat shield_report.json | python -c "import sys,json; d=json.load(sys.stdin); print(len([f for f in d['findings'] if f['severity']=='critical']))")
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ Found $CRITICAL critical security findings"
            cat shield_report.json | python -c "import sys,json; [print(f'{f[\"file\"]}:{f[\"line\"]} - {f[\"pattern\"]}') for f in json.load(sys.stdin)['findings'] if f['severity']=='critical']"
            exit 1
          fi
          echo "✅ No critical findings"
          
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: shield-report
          path: shield_report.json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings |
| 1 | Error — invalid path or scan failure |
| 2 | Flagged — findings detected |

### Block on Severity

```bash
# Block on any critical
python3 shield_scan.py . | jq -e '.findings | map(select(.severity == "critical")) | length == 0'

# Block on critical or high
python3 shield_scan.py . | jq -e '.findings | map(select(.severity == "critical" or .severity == "high")) | length == 0'
```

---

## Compliance Mapping

### SOC 2

| Trust Service Criteria | OpenClaw Shield Control |
|------------------------|-------------------------|
| CC6.1 — Logical Access | Runtime Guard allowlists |
| CC6.6 — Boundary Protection | Network domain restrictions |
| CC6.7 — Restrict Data Movement | Exfiltration detection |
| CC7.2 — Monitoring | Hash-chained audit logs |

### ISO 27001

| Control | OpenClaw Shield Mapping |
|---------|-------------------------|
| A.9.1.2 — Access to Networks | Network policy allowlists |
| A.9.4.1 — Information Access | File access policies |
| A.12.4.1 — Event Logging | Audit logger with hash chain |
| A.12.6.1 — Vulnerability Management | Static scanner in CI |

### NIST Cybersecurity Framework

| Function | Category | OpenClaw Shield |
|----------|----------|-----------------|
| Protect | PR.AC — Access Control | Runtime Guard policies |
| Protect | PR.DS — Data Security | Output sanitization |
| Detect | DE.CM — Monitoring | Continuous runtime guard |
| Detect | DE.AE — Anomalies | Static scan findings |

---

## Threat Model Summary

See `THREAT_MODEL.md` for the complete analysis. Key threats addressed:

| Threat | Attack Vector | Mitigation |
|--------|---------------|------------|
| Credential Theft | Read env vars → send to attacker | Correlation detection + network allowlist |
| Data Exfiltration | Read files → encode → HTTP POST | Path allowlist + domain allowlist |
| Destruction | rm -rf ~ or shutil.rmtree | Static detection + write restrictions |
| Persistence | LaunchAgent, cron, .bashrc backdoor | Static pattern detection |
| Reverse Shell | nc -e, bash -i /dev/tcp | Critical severity detection |

---

## Project Structure

```
OpenClaw-Shield/
├── shield_scan.py      # Static scanner (main entry point)
├── runtime_guard.py    # Continuous runtime protection
├── policies.py         # Access control policies
├── sanitizer.py        # Secret redaction
├── logger.py           # Tamper-evident audit logs
├── config.py           # Configuration settings
├── tests/
│   ├── fixtures/       # Safe test files
│   │   ├── good_example.py
│   │   ├── suspicious_strings.txt
│   │   └── benign_network.py
│   └── test_shield_scan.py
├── README.md           # This file
├── SECURITY.md         # Security policy
├── THREAT_MODEL.md     # Threat analysis
├── CONTRIBUTING.md     # Contribution guidelines
└── .gitignore
```

---

## Manual Deployment

### Prerequisites Checklist

- [ ] Python 3.9+ installed
- [ ] Repository cloned to target system
- [ ] Tests pass: `python3 -m pytest tests/ -v`
- [ ] Configuration reviewed and customized
- [ ] Audit log path is writable
- [ ] Integration code reviewed by security team

### Deployment Steps

1. **Review configuration** (`config.py`)
2. **Customize allowlists** for your environment
3. **Enable runtime guard** by setting `enabled=True`
4. **Integrate** with your agent framework
5. **Verify** audit logs are being written
6. **Monitor** for findings and policy violations

---

## FAQ

### Q: Why stdlib only?

External dependencies introduce supply chain risk. OpenClaw Shield protects against that exact threat — it would be ironic to be vulnerable to it ourselves.

### Q: Will this catch all attacks?

No. OpenClaw Shield uses deterministic regex patterns. Sophisticated attackers may evade detection. It's one layer in defense-in-depth, not a complete solution.

### Q: Is the runtime guard a sandbox?

No. It's a policy enforcement layer that can block operations, but it doesn't isolate execution. Use OS-level sandboxing (containers, VMs) for true isolation.

### Q: How do I add custom patterns?

Add new regex patterns to `shield_scan.py`, update `THREAT_MODEL.md`, add test fixtures, and submit a PR. See `CONTRIBUTING.md`.

---

## License

MIT License — See LICENSE file.

---

## Acknowledgments

Built for the OpenClaw community. Security is a shared responsibility.

---

*"The only truly secure system is one that is powered off, cast in a block of concrete, and sealed in a lead-lined room with armed guards."* — Gene Spafford

*OpenClaw Shield aims for the next best thing.*