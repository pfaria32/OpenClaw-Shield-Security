"""
OpenClaw Shield — Audit Logger

Tamper-evident JSONL audit logging with hash chaining.

Each event includes:
- prev_hash: SHA-256 of previous entry
- hash: SHA-256 of current entry (computed over canonical JSON)

This makes the log tamper-evident (not tamper-proof):
- Modifications break the chain
- Deletions break the chain
- Additions at the end are detectable via external chain verification
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


def _sha256_hex(s: str) -> str:
    """Compute SHA-256 hash of a string, return hex digest."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@dataclass
class AuditEvent:
    """Represents a single audit log event."""
    ts: float
    event_type: str
    severity: str
    message: str
    details: Dict[str, Any]
    prev_hash: str
    hash: str


class AuditLogger:
    """
    JSONL audit logger with hash chaining for tamper-evidence.

    Usage:
        logger = AuditLogger("shield_audit.jsonl")
        logger.log("tool_call", "low", "Tool executed", {"tool": "read_file"})

    Each event is immediately written to disk.
    """

    def __init__(self, path: str):
        """
        Initialize the audit logger.

        Args:
            path: File path for the JSONL audit log
        """
        self.path = Path(path)
        self._prev_hash = "0" * 64  # Genesis hash

        # If log exists, read last hash to continue chain
        if self.path.exists():
            self._load_last_hash()

    def _load_last_hash(self) -> None:
        """Load the hash of the last entry to continue the chain."""
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                last_line = None
                for line in f:
                    line = line.strip()
                    if line:
                        last_line = line
                if last_line:
                    entry = json.loads(last_line)
                    self._prev_hash = entry.get("hash", "0" * 64)
        except (json.JSONDecodeError, KeyError, IOError):
            # If we can't read, start fresh
            self._prev_hash = "0" * 64

    def log(
        self,
        event_type: str,
        severity: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """
        Log an audit event with hash chain.

        Args:
            event_type: Category of event (e.g., "tool_call_blocked")
            severity: Severity level (critical, high, medium, low)
            message: Human-readable description
            details: Optional dictionary of additional context

        Returns:
            The created AuditEvent
        """
        if details is None:
            details = {}

        ts = time.time()

        # Build base structure for hashing (excludes final hash)
        base = {
            "ts": ts,
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "details": details,
            "prev_hash": self._prev_hash,
        }

        # Canonical JSON for deterministic hashing
        canon = json.dumps(base, sort_keys=True, separators=(",", ":"))
        h = _sha256_hex(canon)

        # Create event
        evt = AuditEvent(
            ts=ts,
            event_type=event_type,
            severity=severity,
            message=message,
            details=details,
            prev_hash=self._prev_hash,
            hash=h,
        )

        # Write to file
        line = json.dumps(
            {
                "ts": evt.ts,
                "event_type": evt.event_type,
                "severity": evt.severity,
                "message": evt.message,
                "details": evt.details,
                "prev_hash": evt.prev_hash,
                "hash": evt.hash,
            },
            sort_keys=True,
        )

        # Ensure parent directory exists
        self.path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

        # Update chain
        self._prev_hash = evt.hash

        return evt

    def verify_chain(self) -> tuple[bool, Optional[int], Optional[str]]:
        """
        Verify the integrity of the hash chain.

        Returns:
            Tuple of (is_valid, failed_line_number, error_message)
            If valid, returns (True, None, None)
        """
        if not self.path.exists():
            return True, None, None

        prev = "0" * 64
        line_num = 0

        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line_num += 1
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError as e:
                        return False, line_num, f"Invalid JSON: {e}"

                    # Check prev_hash matches
                    if entry.get("prev_hash") != prev:
                        return False, line_num, "Chain broken: prev_hash mismatch"

                    # Recompute hash
                    base = {
                        "ts": entry["ts"],
                        "event_type": entry["event_type"],
                        "severity": entry["severity"],
                        "message": entry["message"],
                        "details": entry["details"],
                        "prev_hash": entry["prev_hash"],
                    }
                    canon = json.dumps(base, sort_keys=True, separators=(",", ":"))
                    expected = _sha256_hex(canon)

                    if entry.get("hash") != expected:
                        return False, line_num, "Hash mismatch: entry may be tampered"

                    prev = entry["hash"]

            return True, None, None

        except IOError as e:
            return False, None, f"IO error: {e}"

    def get_events(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[AuditEvent]:
        """
        Read events from the log with optional filtering.

        Args:
            event_type: Filter by event type
            severity: Filter by severity
            limit: Maximum number of events to return (most recent first)

        Returns:
            List of AuditEvent objects
        """
        if not self.path.exists():
            return []

        events: List[AuditEvent] = []

        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                    
                    # Apply filters
                    if event_type and entry.get("event_type") != event_type:
                        continue
                    if severity and entry.get("severity") != severity:
                        continue

                    events.append(
                        AuditEvent(
                            ts=entry["ts"],
                            event_type=entry["event_type"],
                            severity=entry["severity"],
                            message=entry["message"],
                            details=entry.get("details", {}),
                            prev_hash=entry["prev_hash"],
                            hash=entry["hash"],
                        )
                    )
                except (json.JSONDecodeError, KeyError):
                    continue

        # Return most recent first if limit specified
        if limit:
            events = events[-limit:]

        return events
