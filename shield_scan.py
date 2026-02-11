#!/usr/bin/env python3
"""
OpenClaw Shield — Static Scanner

Pre-execution security scanner for code repositories.

Detects:
- Credential/secret access patterns
- Data exfiltration indicators
- Destructive filesystem operations
- Persistence mechanisms
- Network backdoors
- Obfuscation techniques

Usage:
    python shield_scan.py /path/to/scan
    python shield_scan.py /path/to/scan > report.json

Exit Codes:
    0 - Clean (no findings)
    1 - Error (invalid path, etc.)
    2 - Flagged (findings detected)
"""
from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import config

# Maximum characters to include in code snippet
SNIPPET_MAX_CHARS = 240


@dataclass
class Finding:
    """Represents a security finding in scanned code."""
    file: str
    line: int
    pattern: str
    severity: str
    description: str
    code_snippet: str


def _is_binary_bytes(data: bytes) -> bool:
    """Check if data appears to be binary (not text)."""
    if b"\x00" in data:
        return True
    # Check ratio of non-text bytes in first 4KB
    sample = data[:4096]
    if not sample:
        return False
    non_text = sum(
        1 for x in sample
        if x < 9 or (x > 13 and x < 32) or x > 126
    )
    return non_text / len(sample) > 0.30


def _should_scan_file(path: Path) -> bool:
    """Determine if a file should be scanned based on extension/name."""
    if path.name in config.INCLUDE_FILENAMES:
        return True
    return path.suffix.lower() in config.INCLUDE_EXTS


def _iter_files(root: Path) -> Iterable[Path]:
    """Recursively iterate through scannable files."""
    for dirpath, dirnames, filenames in os.walk(root):
        # Filter out skip directories (in-place modification)
        dirnames[:] = [
            d for d in dirnames
            if d not in config.SKIP_DIRS and not d.startswith(".git")
        ]
        for filename in filenames:
            filepath = Path(dirpath) / filename
            if _should_scan_file(filepath):
                yield filepath


def _safe_read_text(path: Path) -> Optional[List[str]]:
    """
    Safely read a text file, returning lines or None if unreadable.
    
    Skips:
    - Files larger than MAX_FILE_BYTES
    - Binary files
    - Unreadable files
    """
    try:
        stat = path.stat()
        if stat.st_size > config.MAX_FILE_BYTES:
            return None
        
        data = path.read_bytes()
        if _is_binary_bytes(data):
            return None
        
        # Try UTF-8 first, fall back to latin-1
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1", errors="replace")
        
        return text.splitlines()
    except (OSError, IOError):
        return None


def _clamp_snippet(text: str) -> str:
    """Truncate snippet to max length."""
    text = text.strip()
    if len(text) <= SNIPPET_MAX_CHARS:
        return text
    return text[:SNIPPET_MAX_CHARS] + "…"


def _add_finding(
    findings: List[Finding],
    file: Path,
    line_no: int,
    pattern: str,
    severity: str,
    description: str,
    snippet: str,
) -> None:
    """Add a finding to the list."""
    findings.append(Finding(
        file=str(file),
        line=line_no,
        pattern=pattern,
        severity=severity,
        description=description,
        code_snippet=_clamp_snippet(snippet),
    ))


# =============================================================================
# DETECTION PATTERNS
# =============================================================================

# Environment variable reads for secrets
RE_ENV_READ = re.compile(
    r"\bos\.environ(?:\.get)?\s*\[\s*['\"]([A-Z0-9_]{6,})['\"]\s*\]"
    r"|\bprocess\.env\.([A-Z0-9_]{6,})"
)

# Sensitive file paths
RE_SECRET_FILE = re.compile(
    r"~/(?:\.aws/|\.ssh/|\.config/|\.gnupg/|"
    r"Library/Keychains/|Library/Application Support/|"
    r"\.clawdbot/|\.openai/|\.anthropic/)",
    re.IGNORECASE,
)

# Network calls
RE_NETWORK_CALL = re.compile(
    r"\b(requests\.(?:post|get|put|delete|patch)|"
    r"fetch\(|axios\.|http\.request|https\.request|"
    r"urllib\.request|httpx\.|aiohttp\.|"
    r"curl\s|wget\s)",
    re.IGNORECASE,
)

# External URLs
RE_EXTERNAL_URL = re.compile(
    r"https?://[a-z0-9][\w\.\-]*[a-z0-9](?::\d+)?(?:/[^\s\"']*)?",
    re.IGNORECASE,
)

# Dangerous rm commands
RE_RM_RISKY = re.compile(
    r"\brm\s+(-[rf]+\s+)*(-[rf]+\s+)*(~/?\b|/etc\b|/usr\b|/var\b|"
    r"/System\b|/\s|/\"|/\'|~/?\*)",
    re.IGNORECASE,
)

# Destructive filesystem operations
RE_DESTRUCTIVE_FS = re.compile(
    r"\b(shutil\.rmtree|os\.remove|os\.unlink|os\.rmdir|"
    r"pathlib\.Path\([^)]*\)\.unlink|"
    r"rm\s+-rf|del\s+/s|EraseDisk)\b",
    re.IGNORECASE,
)

# macOS persistence mechanisms
RE_PERSIST_MAC = re.compile(
    r"~/Library/LaunchAgents/|"
    r"/Library/LaunchAgents/|"
    r"/Library/LaunchDaemons/|"
    r"\blaunchctl\s",
    re.IGNORECASE,
)

# Shell profile files
RE_SHELL_PROFILE = re.compile(
    r"\.(?:bashrc|zshrc|profile|bash_profile|zprofile)\b",
    re.IGNORECASE,
)

# Cron manipulation
RE_CRON = re.compile(
    r"\bcrontab\s|/etc/cron\.|/var/spool/cron",
    re.IGNORECASE,
)

# Listening sockets / servers
RE_LISTEN_BIND = re.compile(
    r"\b(\.bind\(|\.listen\(|createServer\(|"
    r"net\.createServer|socket\.bind|"
    r"TCPServer|HTTPServer|BaseHTTPServer)\b",
    re.IGNORECASE,
)

# Reverse shell indicators
RE_REVERSE_SHELL = re.compile(
    r"\b(nc\s+-[^|]*-e|bash\s+-i\s*>&|"
    r"/dev/tcp/|/dev/udp/|"
    r"powershell\s+-enc|"
    r"python\s+-c\s+['\"]import socket)",
    re.IGNORECASE,
)

# Base64 encoding/decoding
RE_BASE64 = re.compile(
    r"\b(base64|b64decode|b64encode|atob|btoa)\b",
    re.IGNORECASE,
)

# Dynamic code execution
RE_EVAL = re.compile(
    r"\b(eval\(|exec\(|compile\(|Function\(|"
    r"child_process\.exec|subprocess\.Popen|"
    r"os\.system\(|os\.popen\(|"
    r"subprocess\.call|subprocess\.run|"
    r"__import__\()",
    re.IGNORECASE,
)

# Very long lines (possible obfuscation)
RE_LONG_LINE = re.compile(r"^.{400,}$")

# Keychain/credential store access
RE_KEYCHAIN = re.compile(
    r"\b(keyring\.|SecKeychainFindGenericPassword|"
    r"security\s+find-generic-password|"
    r"credentialManager)",
    re.IGNORECASE,
)


def _scan_lines(file: Path, lines: List[str]) -> List[Finding]:
    """
    Scan file lines for security patterns.
    
    Uses correlation detection: some patterns alone are low severity,
    but combined (e.g., secret read + network) become critical.
    """
    findings: List[Finding] = []
    
    # Track patterns for correlation
    saw_env: List[Tuple[int, str]] = []
    saw_secret_path: List[Tuple[int, str]] = []
    saw_network: List[Tuple[int, str]] = []
    
    is_test_file = "test" in str(file).lower()
    
    for line_no, line in enumerate(lines, start=1):
        
        # --- Obfuscation: Very long lines ---
        if RE_LONG_LINE.match(line) and file.suffix.lower() in {".js", ".ts"}:
            _add_finding(
                findings, file, line_no,
                "obfuscation_long_line", "low",
                "Very long JS/TS line may indicate minified/obfuscated code; verify intent.",
                line,
            )
        
        # --- Obfuscation: Base64 + Eval ---
        if RE_BASE64.search(line) and RE_EVAL.search(line):
            _add_finding(
                findings, file, line_no,
                "obfuscation_eval_base64", "high",
                "Base64 decoding combined with eval/exec is a common obfuscation/hidden execution pattern.",
                line,
            )
        
        # --- Environment variable reads ---
        env_match = RE_ENV_READ.search(line)
        if env_match:
            key = env_match.group(1) or env_match.group(2) or ""
            saw_env.append((line_no, key))
            if key in config.SUSPECT_ENV_VARS:
                _add_finding(
                    findings, file, line_no,
                    "env_secret_read", "medium",
                    f"Reads environment variable that looks like a secret: {key}",
                    line,
                )
        
        # --- Sensitive file path access ---
        if RE_SECRET_FILE.search(line):
            saw_secret_path.append((line_no, line))
            _add_finding(
                findings, file, line_no,
                "sensitive_path_access", "medium",
                "References a sensitive user path (SSH/AWS/config/keychain). Verify necessity.",
                line,
            )
        
        # --- Keychain/credential store ---
        if RE_KEYCHAIN.search(line):
            saw_secret_path.append((line_no, line))
            _add_finding(
                findings, file, line_no,
                "keychain_access", "high",
                "Accesses system keychain or credential store.",
                line,
            )
        
        # --- Network activity ---
        if RE_NETWORK_CALL.search(line) or RE_EXTERNAL_URL.search(line):
            saw_network.append((line_no, line))
            _add_finding(
                findings, file, line_no,
                "network_activity", "low",
                "Network call or URL detected. Confirm domains and data sent are expected.",
                line,
            )
        
        # --- Destructive rm commands ---
        if RE_RM_RISKY.search(line):
            _add_finding(
                findings, file, line_no,
                "destructive_rm_rf", "critical",
                "High-risk deletion command (rm -rf on home/system paths).",
                line,
            )
        
        # --- Destructive filesystem operations ---
        elif RE_DESTRUCTIVE_FS.search(line) and not is_test_file:
            _add_finding(
                findings, file, line_no,
                "destructive_fs_ops", "high",
                "Potentially destructive filesystem operation detected; verify path constraints.",
                line,
            )
        
        # --- Persistence: LaunchAgents ---
        if RE_PERSIST_MAC.search(line):
            _add_finding(
                findings, file, line_no,
                "persistence_launch_agents", "high",
                "Persistence mechanism (LaunchAgents/launchctl) detected.",
                line,
            )
        
        # --- Shell profile modification ---
        if RE_SHELL_PROFILE.search(line):
            _add_finding(
                findings, file, line_no,
                "shell_profile_mod", "medium",
                "References shell profile files; could be setup or persistence.",
                line,
            )
        
        # --- Cron persistence ---
        if RE_CRON.search(line):
            _add_finding(
                findings, file, line_no,
                "persistence_cron", "high",
                "Cron usage detected; could be persistence if used for auto-run.",
                line,
            )
        
        # --- Reverse shell ---
        if RE_REVERSE_SHELL.search(line):
            _add_finding(
                findings, file, line_no,
                "reverse_shell", "critical",
                "Reverse shell indicator detected.",
                line,
            )
        
        # --- Listening sockets ---
        if RE_LISTEN_BIND.search(line):
            _add_finding(
                findings, file, line_no,
                "listening_socket", "medium",
                "Code appears to open a listening socket/server; verify necessity and exposure.",
                line,
            )
    
    # === CORRELATION DETECTION ===
    # Secret access + network activity in same file = possible exfiltration
    if saw_network and (saw_env or saw_secret_path):
        # Find the first network line for the finding
        net_line, net_snippet = saw_network[0]
        
        # Build details about what secrets were accessed
        secret_details = []
        if saw_env:
            secret_details.append(f"env vars: {[k for _, k in saw_env[:3]]}")
        if saw_secret_path:
            secret_details.append("sensitive paths")
        
        _add_finding(
            findings, file, net_line,
            "possible_exfiltration_combo", "critical",
            f"File includes secret access ({', '.join(secret_details)}) and network activity — possible exfiltration.",
            net_snippet,
        )
    
    return findings


def scan_directory(root: Path) -> Tuple[int, List[Finding]]:
    """
    Scan a directory for security issues.
    
    Args:
        root: Directory path to scan
        
    Returns:
        Tuple of (files_scanned, findings)
    """
    findings: List[Finding] = []
    scanned = 0
    
    for filepath in _iter_files(root):
        lines = _safe_read_text(filepath)
        if lines is None:
            continue
        scanned += 1
        findings.extend(_scan_lines(filepath, lines))
    
    return scanned, findings


def generate_report(scanned: int, findings: List[Finding]) -> Dict:
    """Generate JSON report structure."""
    return {
        "status": "flagged" if findings else "clean",
        "scanned_files": scanned,
        "findings_count": len(findings),
        "findings_by_severity": {
            "critical": len([f for f in findings if f.severity == "critical"]),
            "high": len([f for f in findings if f.severity == "high"]),
            "medium": len([f for f in findings if f.severity == "medium"]),
            "low": len([f for f in findings if f.severity == "low"]),
        },
        "findings": [asdict(f) for f in findings],
    }


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="OpenClaw Shield — Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit Codes:
  0  Clean — no findings
  1  Error — invalid path or scan failure
  2  Flagged — findings detected

Examples:
  python shield_scan.py ./my-project
  python shield_scan.py ./my-project > report.json
  python shield_scan.py ./my-project | jq '.findings[] | select(.severity == "critical")'
        """,
    )
    parser.add_argument(
        "path",
        help="Directory to scan",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=True,
        help="Output as JSON (default)",
    )
    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        help="Filter findings by minimum severity",
    )
    
    args = parser.parse_args()
    
    # Validate path
    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(json.dumps({
            "status": "error",
            "error": f"Path does not exist: {root}",
        }))
        return 1
    
    if not root.is_dir():
        print(json.dumps({
            "status": "error",
            "error": "Path must be a directory",
        }))
        return 1
    
    # Run scan
    try:
        scanned, findings = scan_directory(root)
    except Exception as e:
        print(json.dumps({
            "status": "error",
            "error": f"Scan failed: {e}",
        }))
        return 1
    
    # Filter by severity if requested
    if args.severity:
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        min_level = severity_order.get(args.severity, 0)
        findings = [
            f for f in findings
            if severity_order.get(f.severity, 0) >= min_level
        ]
    
    # Generate and output report
    report = generate_report(scanned, findings)
    print(json.dumps(report, indent=2))
    
    # Return appropriate exit code
    return 2 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())