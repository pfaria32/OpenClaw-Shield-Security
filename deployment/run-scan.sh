#!/bin/bash
# run-scan.sh - Run OpenClaw Shield static scan on workspace
# 
# This script is invoked by OpenClaw cron to perform periodic security scans.
# It scans the workspace for security issues and generates reports.

set -e

SHIELD_DIR="/home/node/.openclaw/workspace/projects/OpenClaw-Shield"
REPORT_DIR="/home/node/.openclaw/workspace/security-reports"
TIMESTAMP=$(date -u +%Y-%m-%d_%H%M%S)
REPORT_FILE="${REPORT_DIR}/scan_${TIMESTAMP}.json"
LOG_FILE="${REPORT_DIR}/shield-scan.log"

# Ensure report directory exists
mkdir -p "$REPORT_DIR"

# Log start
echo "=== Shield Scan Started: $(date -u '+%Y-%m-%d %H:%M:%S UTC') ===" >> "$LOG_FILE"

# Run scan
cd "$SHIELD_DIR"
python3 shield_scan.py /home/node/.openclaw/workspace > "$REPORT_FILE" 2>> "$LOG_FILE"
EXIT_CODE=$?

# Log completion
echo "=== Shield Scan Completed: $(date -u '+%Y-%m-%d %H:%M:%S UTC') | Exit Code: $EXIT_CODE ===" >> "$LOG_FILE"

# Parse results
TOTAL_FINDINGS=$(jq -r '.findings | length' "$REPORT_FILE" 2>/dev/null || echo "0")
CRITICAL_COUNT=$(jq -r '[.findings[] | select(.severity == "critical")] | length' "$REPORT_FILE" 2>/dev/null || echo "0")
HIGH_COUNT=$(jq -r '[.findings[] | select(.severity == "high")] | length' "$REPORT_FILE" 2>/dev/null || echo "0")

echo "Total findings: $TOTAL_FINDINGS (Critical: $CRITICAL_COUNT, High: $HIGH_COUNT)" >> "$LOG_FILE"

# Create symlink to latest report
ln -sf "$REPORT_FILE" "${REPORT_DIR}/latest.json"

# Exit with scan's exit code
# 0 = clean, 2 = findings
exit $EXIT_CODE
