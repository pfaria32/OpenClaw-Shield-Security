# ClamAV Integration

**OpenClaw Shield + ClamAV: Layered Defense**

---

## Overview

OpenClaw Shield now integrates with ClamAV for comprehensive malware protection:

- **Shield Static Scanner:** Detects novel threats via pattern analysis
- **ClamAV:** Detects known threats via signature database (~3.6M signatures)
- **Runtime Guard:** Enforces behavioral policies

---

## ClamAV Installation Status

**Host:** clawdbot-toronto  
**Installed:** 2026-02-13 04:30 UTC  
**Version:** 1.4.3+dfsg-0ubuntu0.24.04.1

**Services:**
- ✅ `clamav-daemon` - Active (scanning daemon)
- ✅ `clamav-freshclam` - Active (signature updates)
- ✅ `clamav-daemon.socket` - Active (socket activation)

**Signatures:** ~3,642,094 total
- daily.cvd: 354,987
- main.cvd: 3,287,027
- bytecode.cvd: 80

---

## Integration Architecture

```
┌──────────────────────────────────────┐
│ AI Agent Tool Call                   │
└────────────┬─────────────────────────┘
             ↓
┌──────────────────────────────────────┐
│ OpenClaw Shield Runtime Guard        │
├──────────────────────────────────────┤
│ 1. Policy Check (allowlists)         │
│ 2. Pre-execution validation          │
└────────────┬─────────────────────────┘
             ↓
        [File Write?]
             │
             ├─ Yes ──→ ┌────────────────────┐
             │          │ ClamAV Scan         │
             │          ├────────────────────┤
             │          │ • Load from socket  │
             │          │ • Scan for malware  │
             │          │ • Check signatures  │
             │          └───┬────────────────┘
             │              │
             │              ├─ Clean ──→ Allow
             │              │
             │              └─ Infected ──→ Block + Alert
             │
             └─ No ──→ Continue
```

---

## Configuration

**File:** `deployment/openclaw-config.py`

### ClamAV Settings

```python
# ClamAV daemon configuration
CLAMAV_ENABLED = True
CLAMAV_SOCKET = "/run/clamav/clamd.ctl"
CLAMAV_TIMEOUT = 120  # seconds

# When to scan
CLAMAV_SCAN_ON_FILE_READ = False   # Too slow
CLAMAV_SCAN_ON_FILE_WRITE = True   # Before writing
CLAMAV_SCAN_DOWNLOADS = True       # Network-fetched files
CLAMAV_SCAN_UPLOADS = True         # Before uploading

# Limits
CLAMAV_MAX_FILE_SIZE = 50_000_000  # 50MB max
CLAMAV_SCAN_ARCHIVES = True        # Scan .zip, .tar, etc.

# Actions
CLAMAV_ACTION_ON_VIRUS = "block"   # block | quarantine | log
CLAMAV_QUARANTINE_DIR = "/home/node/.openclaw/workspace/security-reports/quarantine"

# Alerting
CLAMAV_ALERT_ON_VIRUS = True
CLAMAV_ALERT_METHOD = "openclaw_message"
CLAMAV_ALERT_CHANNEL = "telegram"
```

---

## Usage

### Automatic Scanning

ClamAV scans automatically when:

**File writes:**
```python
# Agent writes a file
tool_call = ToolCall(tool="write_file", args={"path": "/workspace/script.sh", "content": "..."})
guard.before_tool_call(tool_call)
# → ClamAV scans content before write
# → Blocks if virus detected
```

**Downloads:**
```python
# Agent downloads a file
tool_call = ToolCall(tool="fetch_url", args={"url": "https://...", "save_to": "/workspace/download.zip"})
guard.before_tool_call(tool_call)
# → ClamAV scans downloaded content
# → Blocks if virus detected
```

**Uploads:**
```python
# Agent uploads a file
tool_call = ToolCall(tool="upload_file", args={"path": "/workspace/data.txt", ...})
guard.before_tool_call(tool_call)
# → ClamAV scans file before upload
# → Blocks if virus detected
```

### Manual Scanning

```bash
# Scan a file via daemon (fast)
clamdscan /path/to/file

# Scan a directory
clamdscan -r /path/to/directory

# Scan from container (if socket mounted)
docker exec openclaw-gateway clamdscan /workspace/file.sh
```

---

## Virus Detection Flow

### 1. Detection

```
Agent → Write file "/workspace/suspicious.sh"
   ↓
Runtime Guard → Check policy (write allowed?)
   ↓
ClamAV → Scan content via clamd socket
   ↓
Match found: "Trojan.Script.Generic"
```

### 2. Action

**Block mode (default):**
1. Prevent write operation
2. Raise `PermissionError("Virus detected: Trojan.Script.Generic")`
3. Log to audit trail
4. Send Telegram alert
5. Operation fails safely

**Quarantine mode:**
1. Move file to quarantine directory
2. Log to audit trail
3. Send Telegram alert
4. Operation succeeds (file quarantined)

**Log mode (audit only):**
1. Log virus detection
2. Send Telegram alert
3. Allow operation to proceed (risky!)

### 3. Alert

**Telegram message:**
```
🦠 VIRUS DETECTED - ClamAV

File: /workspace/suspicious.sh
Virus: Trojan.Script.Generic
Action: Blocked
Source: Agent tool call (write_file)

The file was NOT written to disk.
No further action needed.
```

---

## Performance

### Scanning Speed

**Measured via clamdscan:**
- Small files (<1MB): 50-100ms
- Medium files (1-10MB): 100-500ms
- Large files (10-50MB): 0.5-5 seconds
- Archives: 2-10 seconds

**Optimization:** Daemon-based scanning (clamdscan) is 10x faster than CLI (clamscan)

### Resource Usage

**Host-level (constant):**
- clamav-daemon: ~68MB RAM
- clamav-freshclam: ~117MB RAM
- Total: ~185MB

**Per-scan (temporary):**
- CPU: 10-30% for scan duration
- Memory: +20-50MB during scan

### Limitations

**Skipped scans:**
- Files >50MB (configurable via `CLAMAV_MAX_FILE_SIZE`)
- Read-only operations (too slow to scan every read)
- Trusted system files (outside workspace)

---

## Testing

### Test Virus Detection

**EICAR test file** (safe test virus):

```bash
# Create EICAR test file (will be detected as virus)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt

# Scan it
clamdscan /tmp/eicar.txt
# Expected: "Eicar-Signature FOUND"

# Try to write via OpenClaw (should be blocked)
# Agent tool call: write_file("/workspace/eicar.txt", content=eicar_string)
# Expected: PermissionError("Virus detected: Eicar-Signature")
```

### Verify Integration

```bash
# Check ClamAV daemon status
sudo systemctl status clamav-daemon

# Test socket connection
clamdscan --ping
# Expected: "PONG"

# Check signature version
clamdscan --version
```

---

## Troubleshooting

### "Connection refused" Error

**Cause:** ClamAV socket not accessible

**Fix:**
```bash
# Check if daemon is running
sudo systemctl status clamav-daemon

# Restart if needed
sudo systemctl restart clamav-daemon

# Verify socket exists
ls -la /run/clamav/clamd.ctl
```

### "Timeout" Error

**Cause:** Large file taking too long to scan

**Fix:**
```python
# Increase timeout in config
CLAMAV_TIMEOUT = 300  # 5 minutes
```

### False Positives

**Cause:** Legitimate file flagged as malware

**Fix:**
1. Review file manually
2. If confirmed clean, report to ClamAV team
3. Temporarily add to exclusion list (not recommended)
4. Consider switching to `log` mode for that file type

---

## Security Considerations

### What ClamAV Protects Against

**✅ Effective:**
- Known viruses, trojans, backdoors
- Malicious scripts (bash, php, powershell)
- Ransomware, spyware, adware
- Macro viruses in documents
- Infected archives

**❌ Limited:**
- Zero-day exploits (no signature yet)
- Polymorphic malware (changes signature)
- Fileless attacks (in-memory only)
- Business logic exploits
- Social engineering

### Layered Defense

**Why both Shield and ClamAV?**

| Layer | Detects | Strengths | Limitations |
|-------|---------|-----------|-------------|
| **Shield Static Scanner** | Novel patterns | Zero-day detection, code analysis | False positives, heuristic-based |
| **ClamAV** | Known malware | 3.6M signatures, proven threats | Only known threats, signature updates needed |
| **Runtime Guard** | Policy violations | Behavioral control, allowlists | Requires policy configuration |

**Result:** Comprehensive protection against both known and novel threats

---

## Maintenance

### Daily (Automatic)

- ✅ Signature updates (clamav-freshclam)
- ✅ Service health monitoring (systemd)

### Weekly (Manual)

- Review quarantine directory
- Check ClamAV logs for trends
- Verify no false positives

### Monthly (Manual)

- Update ClamAV package (apt-get update)
- Review integration with Shield
- Test EICAR file detection

---

## Future Enhancements

### Planned

1. **On-access scanning** - Scan files when accessed (if performance allows)
2. **Heuristic analysis** - Enable ClamAV's behavior-based detection
3. **Cloud signatures** - Integrate cloud-based threat intelligence
4. **Automatic quarantine review** - AI-assisted false positive detection

### Under Consideration

1. **Container scanning** - Scan Docker images before deployment
2. **Archive password protection** - Handle encrypted archives
3. **Custom signatures** - Create organization-specific detection rules

---

## Related Documentation

- **Main README:** `../README.md`
- **Deployment Guide:** `deployment/README.md`
- **Runtime Guard:** `runtime_guard.py`
- **Configuration:** `deployment/openclaw-config.py`

---

**Status:** ✅ Active and integrated  
**Last updated:** 2026-02-13  
**ClamAV version:** 1.4.3  
**Signatures:** ~3.6M (auto-updating)
