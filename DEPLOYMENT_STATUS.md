# Deployment Status

**Instance:** clawdbot-toronto (production)  
**Deployed:** 2026-02-13 04:30 UTC  
**Status:** ✅ Active (Static Scanner)

---

## Components

### Static Scanner ✅ ACTIVE
- **Schedule:** Daily at 3:00 AM UTC
- **Cron Job:** 7db5c193-6bff-4444-89b9-113af508cdcb
- **Output:** /home/node/.openclaw/workspace/security-reports/
- **Alerting:** Telegram (on critical findings)

### ClamAV Antivirus ✅ ACTIVE (Host-Level)
- **Version:** 1.4.3+dfsg-0ubuntu0.24.04.1
- **Signatures:** ~3.6M (auto-updating)
- **Services:** clamav-daemon, clamav-freshclam, clamav-daemon.socket
- **Socket:** /run/clamav/clamd.ctl
- **Integration:** Scans files before write/upload operations

### Runtime Guard ✅ ENABLED
- **Status:** Active and operational
- **Activated:** 2026-02-13 04:39 UTC
- **Config:** deployment/openclaw-config.py
- **ClamAV Integration:** Active (host-level malware scanning)

---

## Initial Scan Results

**Date:** 2026-02-13 04:31 UTC  
**Files scanned:** 6,087  
**Findings:** 9,689 total (127 critical, 129 high)

**Assessment:** Most critical findings are false positives from legitimate API scripts.

**Report:** security-reports/initial-scan.json

---

## Documentation

- **Deployment Guide:** deployment/README.md
- **Configuration:** deployment/openclaw-config.py
- **Scripts:** deployment/*.sh

---

## Next Scan

**Scheduled:** 2026-02-14 03:00 UTC (automatic)

**Manual trigger:**
```bash
openclaw cron run 7db5c193-6bff-4444-89b9-113af508cdcb
```
