#!/bin/bash
# cron-scan-and-alert.sh - Periodic security scan with alerting
#
# This script is invoked by OpenClaw cron job.
# It runs Shield scan and alerts on findings.

set -e

SHIELD_DEPLOY="/home/node/.openclaw/workspace/projects/OpenClaw-Shield/deployment"
REPORT_DIR="/home/node/.openclaw/workspace/security-reports"

# Run scan
bash "${SHIELD_DEPLOY}/run-scan.sh"
SCAN_EXIT=$?

# Get latest report
LATEST_REPORT="${REPORT_DIR}/latest.json"

if [ ! -f "$LATEST_REPORT" ]; then
    echo "ERROR: No scan report found at $LATEST_REPORT"
    exit 1
fi

# Parse findings
CRITICAL_COUNT=$(jq -r '[.findings[] | select(.severity == "critical")] | length' "$LATEST_REPORT" 2>/dev/null || echo "0")
HIGH_COUNT=$(jq -r '[.findings[] | select(.severity == "high")] | length' "$LATEST_REPORT" 2>/dev/null || echo "0")
TOTAL_FINDINGS=$(jq -r '.findings | length' "$LATEST_REPORT" 2>/dev/null || echo "0")

# Determine if alert is needed
SHOULD_ALERT=false

if [ "$CRITICAL_COUNT" -gt 0 ]; then
    SHOULD_ALERT=true
elif [ "$HIGH_COUNT" -ge 3 ]; then
    SHOULD_ALERT=true
elif [ "$TOTAL_FINDINGS" -ge 10 ]; then
    SHOULD_ALERT=true
fi

# Generate alert message if needed
if [ "$SHOULD_ALERT" = true ]; then
    ALERT_MSG=$(bash "${SHIELD_DEPLOY}/alert-findings.sh" "$LATEST_REPORT")
    
    # Output alert (will be captured by cron and sent via OpenClaw)
    echo "ALERT_NEEDED=true"
    echo "$ALERT_MSG"
    exit 2  # Exit code 2 = findings present
elif [ "$SCAN_EXIT" -eq 2 ]; then
    # Findings but below alert threshold
    echo "✅ Shield scan complete: ${TOTAL_FINDINGS} findings (below alert threshold)"
    echo "Report: ${LATEST_REPORT}"
    exit 0
else
    # Clean scan
    echo "✅ Shield scan complete: No findings"
    echo "Report: ${LATEST_REPORT}"
    exit 0
fi
