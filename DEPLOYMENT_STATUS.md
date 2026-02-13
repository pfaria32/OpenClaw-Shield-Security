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

### Runtime Guard ⏸️ CONFIGURED BUT DISABLED
- **Status:** Prepared but not enabled (by design)
- **Reason:** Requires explicit activation + policy review
- **Config:** deployment/openclaw-config.py
- **To enable:** Set RUNTIME_GUARD_ENABLED = True

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
