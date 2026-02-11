# Security Policy — OpenClaw Shield

**Document Version:** 1.0.0  
**Last Updated:** 2026-02-11  
**Classification:** Public

---

## 1. Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 1.0.x   | ✅ Yes    | Current stable release |
| < 1.0   | ❌ No     | Pre-release, not supported |

Security updates are provided for the latest minor version only.

---

## 2. Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in OpenClaw Shield, please follow responsible disclosure practices.

### 2.1 How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

**Instead, please:**

1. **Email:** Send details to the repository maintainer privately
2. **Subject Line:** `[SECURITY] OpenClaw Shield - <Brief Description>`
3. **Encrypt:** Use PGP if available (key in maintainer profile)

### 2.2 What to Include

- **Description:** Clear explanation of the vulnerability
- **Impact:** What an attacker could achieve
- **Reproduction Steps:** Detailed steps to reproduce
- **Affected Versions:** Which versions are impacted
- **Suggested Fix:** If you have one (optional)
- **Your Contact:** How we can reach you for follow-up

### 2.3 Response Timeline

| Stage | Target Time |
|-------|-------------|
| Initial Acknowledgment | 48 hours |
| Severity Assessment | 5 business days |
| Fix Development | Depends on severity |
| Coordinated Disclosure | 90 days max |

---

## 3. Severity Classification

We use the following severity levels:

### CRITICAL
- Remote code execution
- Credential exfiltration that bypasses all controls
- Complete bypass of security controls
- System compromise

**Response:** Immediate patch, notify all users

### HIGH
- Partial bypass of security controls
- Information disclosure of sensitive data
- Persistence mechanism installation
- Privilege escalation

**Response:** Patch within 7 days

### MEDIUM
- Information disclosure of non-sensitive data
- Detection evasion for specific patterns
- Denial of service (local)

**Response:** Patch within 30 days

### LOW
- Minor information leakage
- Theoretical attacks with limited impact
- Documentation issues

**Response:** Address in next regular release

---

## 4. Security Design Principles

OpenClaw Shield is built on these principles:

### 4.1 Defense in Depth
Multiple layers of protection:
- Static analysis (pre-execution)
- Runtime guards (continuous)
- Output sanitization
- Audit logging

### 4.2 Fail-Closed
When in doubt, deny:
- Unknown paths → blocked
- Unknown domains → blocked
- Missing justification → blocked

### 4.3 Least Privilege
Minimal access by default:
- Empty allowlists require explicit configuration
- Runtime guard disabled by default
- No auto-execution of any kind

### 4.4 Auditability
Everything is logged:
- Hash-chained audit logs
- Tamper-evident design
- Structured JSON format

### 4.5 No External Dependencies
Entire codebase uses Python standard library only:
- No supply chain risk from Shield itself
- Auditable codebase
- Predictable behavior

---

## 5. Known Limitations

OpenClaw Shield has known limitations that users should understand:

### 5.1 Detection Limitations
- **Regex-based:** Novel obfuscation may evade detection
- **No ML/AI:** Deterministic patterns only
- **File-scoped:** Cross-file attacks harder to detect

### 5.2 Runtime Limitations
- **Convention-based:** Relies on tool call conventions
- **Not a sandbox:** Does not isolate execution
- **Bypass with root:** Admin users can disable

### 5.3 Scope Limitations
- **Application-layer:** Does not protect OS
- **Single-machine:** Not distributed security
- **Agent-focused:** Not general-purpose security tool

---

## 6. Security Updates

### 6.1 Notification Channels
- GitHub Security Advisories
- Repository releases page
- CHANGELOG.md updates

### 6.2 Update Process
1. Pull latest from repository
2. Review CHANGELOG for security notes
3. Run tests: `python -m pytest tests/`
4. Update in staging first
5. Deploy to production

---

## 7. Hardening Recommendations

### 7.1 Deployment
- [ ] Run with minimal filesystem permissions
- [ ] Use read-only configuration files
- [ ] Enable runtime guard in production
- [ ] Configure tight allowlists
- [ ] Ship audit logs to external SIEM

### 7.2 Configuration
- [ ] Remove all paths from allowlists, add only needed
- [ ] Restrict network to specific API domains
- [ ] Require justification for all tool calls
- [ ] Set `RUNTIME_GUARD_ENABLED_DEFAULT = True` in production

### 7.3 Operations
- [ ] Monitor audit logs for anomalies
- [ ] Review `CRITICAL` and `HIGH` findings immediately
- [ ] Verify hash chain integrity periodically
- [ ] Keep Shield updated

---

## 8. Compliance Mapping

OpenClaw Shield supports compliance with:

| Framework | Relevant Controls |
|-----------|-------------------|
| SOC 2 | CC6.1 (Logical Access), CC6.6 (Boundary Protection) |
| ISO 27001 | A.9 (Access Control), A.12 (Operations Security) |
| NIST CSF | PR.AC (Access Control), PR.DS (Data Security) |
| CIS Controls | Control 3 (Data Protection), Control 6 (Access Management) |

---

## 9. Contact

For security-related inquiries:
- **Repository:** https://github.com/pfaria32/OpenClaw-Shield
- **Issues:** Non-security issues only
- **Security:** Private disclosure via email

---

*This security policy may be updated. Check the repository for the latest version.*
