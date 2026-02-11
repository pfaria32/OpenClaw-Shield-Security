"""
OpenClaw Shield — Scanner Tests

Tests for the static security scanner.

Run with: python -m pytest tests/test_shield_scan.py -v
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from shield_scan import (
    scan_directory,
    generate_report,
    _scan_lines,
    _safe_read_text,
    Finding,
)

# Path to test fixtures
FIXTURES = Path(__file__).parent / "fixtures"


class TestScanDirectory:
    """Tests for directory scanning."""

    def test_scan_fixtures_directory(self):
        """Scanning fixtures directory should work."""
        scanned, findings = scan_directory(FIXTURES)
        assert scanned > 0, "Should scan at least one file"
        # We expect findings from our test fixtures
        assert isinstance(findings, list)

    def test_scan_returns_findings(self):
        """Suspicious fixtures should produce findings."""
        scanned, findings = scan_directory(FIXTURES)
        # Our fixtures contain intentional patterns
        assert len(findings) > 0, "Expected findings from test fixtures"

    def test_scan_good_file_no_critical(self):
        """Good example file should have no critical findings."""
        lines = _safe_read_text(FIXTURES / "good_example.py")
        assert lines is not None
        findings = _scan_lines(FIXTURES / "good_example.py", lines)
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) == 0, "Good file should have no critical findings"


class TestPatternDetection:
    """Tests for specific pattern detection."""

    def test_network_activity_detected(self):
        """Network patterns should be detected."""
        lines = _safe_read_text(FIXTURES / "benign_network.py")
        assert lines is not None
        findings = _scan_lines(FIXTURES / "benign_network.py", lines)
        network_findings = [f for f in findings if f.pattern == "network_activity"]
        assert len(network_findings) > 0, "Should detect network activity"

    def test_exfiltration_combo_detected(self):
        """Exfiltration combo (secret + network) should be detected."""
        lines = _safe_read_text(FIXTURES / "exfiltration_example.py")
        assert lines is not None
        findings = _scan_lines(FIXTURES / "exfiltration_example.py", lines)
        exfil_findings = [f for f in findings if f.pattern == "possible_exfiltration_combo"]
        assert len(exfil_findings) > 0, "Should detect exfiltration combo"
        # Should be critical severity
        assert exfil_findings[0].severity == "critical"


class TestReportGeneration:
    """Tests for report generation."""

    def test_report_structure(self):
        """Report should have expected structure."""
        findings = [
            Finding(
                file="/test/file.py",
                line=10,
                pattern="test_pattern",
                severity="high",
                description="Test finding",
                code_snippet="test code",
            )
        ]
        report = generate_report(5, findings)
        
        assert report["status"] == "flagged"
        assert report["scanned_files"] == 5
        assert report["findings_count"] == 1
        assert "findings_by_severity" in report
        assert report["findings_by_severity"]["high"] == 1

    def test_clean_report(self):
        """Report with no findings should be clean."""
        report = generate_report(10, [])
        assert report["status"] == "clean"
        assert report["findings_count"] == 0

    def test_report_is_json_serializable(self):
        """Report should be JSON serializable."""
        findings = [
            Finding(
                file="/test/file.py",
                line=10,
                pattern="test_pattern",
                severity="medium",
                description="Test finding",
                code_snippet="test code",
            )
        ]
        report = generate_report(1, findings)
        # Should not raise
        json_str = json.dumps(report)
        assert len(json_str) > 0


class TestSeverityClassification:
    """Tests for severity classification."""

    def test_severity_counts(self):
        """Severity counts should be accurate."""
        findings = [
            Finding("a.py", 1, "p1", "critical", "d1", "c1"),
            Finding("b.py", 2, "p2", "critical", "d2", "c2"),
            Finding("c.py", 3, "p3", "high", "d3", "c3"),
            Finding("d.py", 4, "p4", "medium", "d4", "c4"),
            Finding("e.py", 5, "p5", "low", "d5", "c5"),
            Finding("f.py", 6, "p6", "low", "d6", "c6"),
        ]
        report = generate_report(6, findings)
        
        assert report["findings_by_severity"]["critical"] == 2
        assert report["findings_by_severity"]["high"] == 1
        assert report["findings_by_severity"]["medium"] == 1
        assert report["findings_by_severity"]["low"] == 2


class TestFileReading:
    """Tests for safe file reading."""

    def test_read_text_file(self):
        """Should read text files successfully."""
        lines = _safe_read_text(FIXTURES / "good_example.py")
        assert lines is not None
        assert len(lines) > 0

    def test_read_nonexistent_file(self):
        """Should return None for nonexistent files."""
        lines = _safe_read_text(FIXTURES / "does_not_exist.py")
        assert lines is None


class TestFindingDataclass:
    """Tests for Finding dataclass."""

    def test_finding_creation(self):
        """Should create Finding with all fields."""
        f = Finding(
            file="/path/to/file.py",
            line=42,
            pattern="test_pattern",
            severity="high",
            description="Test description",
            code_snippet="code here",
        )
        assert f.file == "/path/to/file.py"
        assert f.line == 42
        assert f.pattern == "test_pattern"
        assert f.severity == "high"


# Run tests if executed directly
if __name__ == "__main__":
    import subprocess
    sys.exit(subprocess.call([sys.executable, "-m", "pytest", __file__, "-v"]))
