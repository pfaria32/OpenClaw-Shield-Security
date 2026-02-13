# OpenClaw Shield Deployment

**Instance:** clawdbot-toronto (production)  
**Owner:** Pedro Bento de Faria  
**Deployed:** 2026-02-13 04:30 UTC

---

## Deployment Status

✅ **Static Scanner:** Active (daily cron at 3:00 AM UTC)  
⏸️ **Runtime Guard:** Configured but disabled (by design)  
✅ **Audit Logging:** Configured  
✅ **Alerting:** Active (Telegram notifications on critical findings)

---

## What's Deployed

### 1. Static Scanner (Active)

**Purpose:** Daily security scan of workspace for threats

**Schedule:** 3:00 AM UTC daily (via OpenClaw cron)

**Scan targets:**
- `/home/node/.openclaw/workspace/` (entire workspace)
- Excludes: node_modules, .git, __pycache__, etc.

**Output:**
- Reports: `/home/node/.openclaw/workspace/security-reports/scan_YYYYMMDD_HHMMSS.json`
- Latest: `/home/node/.openclaw/workspace/security-reports/latest.json`
- Logs: `/home/node/.openclaw/workspace/security-reports/shield-scan.log`

**Alert thresholds:**
- Any CRITICAL findings → Alert
- ≥3 HIGH findings → Alert
- ≥10 total findings → Alert

**Cron job ID:** `7db5c193-6bff-4444-89b9-113af508cdcb`

### 2. Runtime Guard (Configured but Disabled)

**Purpose:** Continuous middleware protection for tool calls

**Status:** DISABLED by design (must be explicitly enabled)

**Why disabled:**
- Requires deeper OpenClaw integration
- Adds execution overhead
- Current workspace patterns are trusted
- Can be enabled when handling sensitive operations

**To enable:** Edit `openclaw-config.py` and set `RUNTIME_GUARD_ENABLED = True`

**Policies configured:**
- Read allowlist: Workspace, memory, skills, projects, config files
- Write allowlist: Memory/daily, inbox, projects, logs, tmp
- Network allowlist: LLM APIs, GitHub, Outlook, Todoist, etc.

---

## Initial Scan Results (2026-02-13)

**Files scanned:** 6,087  
**Total findings:** 9,689

**By severity:**
- Critical: 127
- High: 129
- Medium: 595
- Low: 8,838

**Critical patterns:**
- `possible_exfiltration_combo`: 92 (mostly false positives - legitimate API scripts)
- `destructive_rm_rf`: 33 (cleanup scripts)
- `reverse_shell`: 2 (needs review)

**Assessment:** Most critical findings are **false positives** from legitimate scripts that:
- Use env vars for API credentials (correct practice)
- Make network calls to trusted APIs (Microsoft, GitHub, etc.)
- Perform cleanup operations (rm in scripts)

**Action:** Review report and create allowlist for known-good patterns.

**Report location:** `/home/node/.openclaw/workspace/security-reports/initial-scan.json`

---

## Usage

### Manual Scan

```bash
# Run scan manually
bash /home/node/.openclaw/workspace/projects/OpenClaw-Shield/deployment/run-scan.sh

# View latest report
cat /home/node/.openclaw/workspace/security-reports/latest.json | python3 -m json.tool | less

# Check critical findings
python3 << 'EOF'
import json
with open('/home/node/.openclaw/workspace/security-reports/latest.json') as f:
    data = json.load(f)
critical = [f for f in data['findings'] if f['severity'] == 'critical']
for f in critical[:10]:
    print(f"{f['file']}:{f['line']} - {f['description']}")
EOF
```

### View Logs

```bash
# Scan log
tail -f /home/node/.openclaw/workspace/security-reports/shield-scan.log

# Audit log (when runtime guard enabled)
tail -f /home/node/.openclaw/workspace/security-reports/shield_audit.jsonl
```

### Cron Job Management

```bash
# Check cron status
openclaw cron list | grep -i shield

# Disable cron
openclaw cron update 7db5c193-6bff-4444-89b9-113af508cdcb --enabled false

# Re-enable cron
openclaw cron update 7db5c193-6bff-4444-89b9-113af508cdcb --enabled true

# Manual trigger
openclaw cron run 7db5c193-6bff-4444-89b9-113af508cdcb
```

---

## Configuration

**Deployment config:** `openclaw-config.py`

**Key settings:**
- `RUNTIME_GUARD_ENABLED`: false (disabled)
- `WORKSPACE_PATH`: /home/node/.openclaw/workspace
- `SCAN_REPORT_DIR`: /home/node/.openclaw/workspace/security-reports
- Alert thresholds: 1 critical, 3 high, or 10 total

**To modify:**
1. Edit `openclaw-config.py`
2. No restart needed (config read per scan)

---

## Alerting

**Method:** OpenClaw message system → Telegram

**Alert format:**
```
🛡️ OpenClaw Shield Security Alert

Scan: 2026-02-13 04:30 UTC
Findings: 127 total (92 critical, 35 high)

Critical issues:
- /path/to/file.js:15 - possible_exfiltration_combo
- /path/to/script.sh:42 - destructive_rm_rf

Action required: Review security report
```

**Notification settings:**
- Channel: Telegram (primary)
- Delivery: OpenClaw isolated agent → announcement

---

## Threat Detection

### What Shield Detects

**1. Credential Theft**
- Hardcoded API keys, tokens, passwords
- SSH key access
- Secret env var references

**2. Data Exfiltration**
- Credential access + network activity combination
- File read + HTTP POST patterns
- Database dumps + external sends

**3. Destructive Operations**
- `rm -rf` commands
- Mass file deletion
- System file modifications

**4. Persistence Mechanisms**
- Cron job creation
- LaunchAgents/daemons
- Shell profile modifications

**5. Network Backdoors**
- Reverse shell patterns
- Listening sockets
- nc/netcat usage

**6. Obfuscation**
- base64 + eval combinations
- Dynamic code execution
- Packed/encrypted scripts

### False Positives

**Common false positives:**
- Legitimate API scripts (credential + network is expected)
- Cleanup scripts (rm -rf in controlled context)
- Development tools (netcat for testing)
- OAuth flows (token refresh with network calls)

**Handling false positives:**
- Review and document in security notes
- Consider allowlist for known-good patterns (future feature)
- Adjust alert thresholds if needed

---

## Runtime Guard (When Enabled)

### How It Works

```python
from runtime_guard import RuntimeGuard, ToolCall

# Initialize guard
guard = RuntimeGuard(enabled=True, ...)

# Before tool execution
call = ToolCall(tool="read_file", args={"path": "/app/data.txt"})
guard.before_tool_call(call)  # Raises PermissionError if blocked

# Execute tool
result = execute_tool(call)

# After execution
result = guard.after_tool_call(call, result)  # Sanitizes output
```

### Integration Points

**For future runtime guard activation:**

1. **Hook into OpenClaw tool execution**
   - Wrap `exec`, `read`, `write`, `browser`, etc.
   - Add Shield checks before execution

2. **Configure policies**
   - Review and tighten `ALLOWED_READ_PATHS`
   - Review and tighten `ALLOWED_WRITE_PATHS`
   - Review and tighten `ALLOWED_DOMAINS`

3. **Test in monitoring mode**
   - Set `enforce=False` initially
   - Log decisions without blocking
   - Review logs for 48 hours

4. **Enable enforcement**
   - Set `enforce=True` in config
   - Monitor for false positives
   - Adjust policies as needed

---

## Maintenance

### Regular Tasks

**Weekly:**
- Review security reports for trends
- Check for new critical findings
- Update allowlists if needed

**Monthly:**
- Review false positive patterns
- Tune alert thresholds
- Update Shield to latest version

**As needed:**
- Investigate critical alerts immediately
- Document false positives
- Adjust policies for new workflows

### Updating Shield

```bash
cd /home/node/.openclaw/workspace/projects/OpenClaw-Shield
git pull origin main

# If config changes needed
# Review and merge with deployment/openclaw-config.py
```

---

## Troubleshooting

### Scan Fails

```bash
# Check logs
cat /home/node/.openclaw/workspace/security-reports/shield-scan.log

# Verify Shield installation
python3 /home/node/.openclaw/workspace/projects/OpenClaw-Shield/shield_scan.py --help

# Test scan on small directory
python3 /home/node/.openclaw/workspace/projects/OpenClaw-Shield/shield_scan.py /tmp
```

### No Alerts Received

```bash
# Check if findings exceeded threshold
python3 << 'EOF'
import json
with open('/home/node/.openclaw/workspace/security-reports/latest.json') as f:
    data = json.load(f)
critical = len([f for f in data['findings'] if f['severity'] == 'critical'])
print(f"Critical: {critical} (threshold: 1)")
EOF

# Check cron job status
openclaw cron list | grep -i shield

# Manually trigger alert
bash /home/node/.openclaw/workspace/projects/OpenClaw-Shield/deployment/alert-findings.sh \
  /home/node/.openclaw/workspace/security-reports/latest.json
```

### Runtime Guard Issues (if enabled)

```bash
# Check audit log
tail /home/node/.openclaw/workspace/security-reports/shield_audit.jsonl

# Disable if causing problems
# Edit openclaw-config.py: RUNTIME_GUARD_ENABLED = False
```

---

## Security Notes

**Shield is disabled by default for runtime protection:**
- Static scans are safe (read-only)
- Runtime guard requires careful policy configuration
- False positives can break workflows

**Current posture:**
- **Static scans:** Active and safe
- **Runtime guard:** Prepared but disabled
- **Audit logging:** Ready when guard enabled

**Threat model:**
- Primary threats: Credential leaks, data exfiltration
- Secondary threats: Destructive operations, persistence
- Unlikely threats: Sophisticated obfuscation (low surface)

**Risk acceptance:**
- Personal use case = lower risk than multi-tenant
- Trusted workspace = can tolerate false positives
- Human oversight = final security layer

---

## Next Steps

**Immediate:**
- ✅ Static scanner deployed
- ✅ Daily cron job active
- ✅ Alerting configured

**Short-term (1-2 weeks):**
- Review initial scan findings
- Document false positive patterns
- Create security baseline report

**Long-term (as needed):**
- Enable runtime guard for sensitive operations
- Fine-tune policies based on usage patterns
- Consider allowlist for known-good patterns

---

**Deployment complete:** 2026-02-13 04:30 UTC  
**Next scan:** 2026-02-14 03:00 UTC  
**Monitoring:** Active via OpenClaw cron
