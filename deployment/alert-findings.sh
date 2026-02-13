#!/bin/bash
# alert-findings.sh - Send alert when Shield finds security issues
#
# Usage: alert-findings.sh <report-file>

set -e

REPORT_FILE="${1:-}"

if [ -z "$REPORT_FILE" ] || [ ! -f "$REPORT_FILE" ]; then
    echo "Usage: alert-findings.sh <report-file>"
    exit 1
fi

# Parse report
TOTAL_FINDINGS=$(jq -r '.findings | length' "$REPORT_FILE")
CRITICAL_COUNT=$(jq -r '[.findings[] | select(.severity == "critical")] | length' "$REPORT_FILE")
HIGH_COUNT=$(jq -r '[.findings[] | select(.severity == "high")] | length' "$REPORT_FILE")
MEDIUM_COUNT=$(jq -r '[.findings[] | select(.severity == "medium")] | length' "$REPORT_FILE")

# Extract critical findings
CRITICAL_LIST=$(jq -r '[.findings[] | select(.severity == "critical")] | map("- \(.file):\(.line) - \(.description)") | join("\n")' "$REPORT_FILE")

# Build alert message
ALERT_MESSAGE="🛡️ **OpenClaw Shield Security Alert**

**Scan:** $(date -u '+%Y-%m-%d %H:%M UTC')
**Findings:** ${TOTAL_FINDINGS} total (${CRITICAL_COUNT} critical, ${HIGH_COUNT} high, ${MEDIUM_COUNT} medium)

**Critical issues:**
${CRITICAL_LIST}

**Action required:** Review full report at:
\`${REPORT_FILE}\`

**Quick view:**
\`\`\`bash
cat ${REPORT_FILE} | jq '.findings[] | select(.severity == \"critical\")'
\`\`\`

**Latest report:** \`/home/node/.openclaw/workspace/security-reports/latest.json\`"

# Output message (will be captured by calling script/cron)
echo "$ALERT_MESSAGE"
