"""
OpenClaw Shield — Runtime Guard

Continuous middleware protection for AI agent tool calls.

Provides:
- Pre-execution policy enforcement
- Post-execution output sanitization
- Comprehensive audit logging

IMPORTANT: Disabled by default. Enable explicitly in production
after configuring appropriate allowlists.

Usage:
    from runtime_guard import RuntimeGuard, ToolCall
    from policies import FileAccessPolicy, NetworkPolicy
    from logger import AuditLogger

    guard = RuntimeGuard(
        enabled=True,
        audit_logger=AuditLogger("shield_audit.jsonl"),
        file_policy=FileAccessPolicy(["/app/*"], ["/app/output/*"]),
        net_policy=NetworkPolicy(["api.openai.com"]),
    )

    # In your agent loop:
    call = ToolCall(tool="read_file", args={"path": "/app/data.txt"}, justification="User requested file")
    guard.before_tool_call(call)  # Raises PermissionError if blocked
    result = execute_tool(call)
    result = guard.after_tool_call(call, result)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from logger import AuditLogger
from policies import FileAccessPolicy, NetworkPolicy, ToolPolicy, Decision
from sanitizer import sanitize_text


@dataclass
class ToolCall:
    """Represents a tool invocation to be guarded."""
    tool: str
    args: Dict[str, Any] = field(default_factory=dict)
    justification: str = ""


class RuntimeGuard:
    """
    Enterprise runtime guard for AI agent tool calls.

    Integrates as middleware around tool execution:
    1. before_tool_call() - Check policies, block if denied
    2. Execute tool (by your framework)
    3. after_tool_call() - Sanitize output, log results

    All decisions are logged to the audit trail.
    """

    # Common argument names that indicate file paths
    PATH_ARG_NAMES = frozenset({
        "path", "pathname", "file", "filename", "filepath",
        "src", "dst", "source", "destination", "target",
        "input", "output", "dir", "directory",
    })

    # Common argument names that indicate network destinations
    NETWORK_ARG_NAMES = frozenset({
        "host", "hostname", "domain", "url", "endpoint",
        "server", "address", "uri",
    })

    # Tool name patterns that suggest write operations
    WRITE_TOOL_PATTERNS = frozenset({
        "write", "save", "create", "update", "put", "post",
        "upload", "store", "set", "modify", "edit", "append",
    })

    def __init__(
        self,
        enabled: bool,
        audit_logger: AuditLogger,
        file_policy: Optional[FileAccessPolicy] = None,
        net_policy: Optional[NetworkPolicy] = None,
        tool_policy: Optional[ToolPolicy] = None,
        require_justification: bool = True,
    ):
        """
        Initialize the runtime guard.

        Args:
            enabled: Whether enforcement is active (MUST be explicitly True)
            audit_logger: Logger for audit trail
            file_policy: File access allowlists (optional)
            net_policy: Network access allowlists (optional)
            tool_policy: Tool usage allowlists (optional)
            require_justification: Require justification for all tool calls
        """
        self.enabled = enabled
        self.log = audit_logger
        self.file_policy = file_policy
        self.net_policy = net_policy
        self.tool_policy = tool_policy
        self.require_justification = require_justification

        # Log initialization
        self.log.log(
            "guard_initialized",
            "low",
            f"Runtime guard initialized (enabled={enabled})",
            {
                "enabled": enabled,
                "has_file_policy": file_policy is not None,
                "has_net_policy": net_policy is not None,
                "has_tool_policy": tool_policy is not None,
                "require_justification": require_justification,
            },
        )

    def _is_write_operation(self, tool: str, arg_name: str) -> bool:
        """Heuristically determine if this is a write operation."""
        tool_lower = tool.lower()
        for pattern in self.WRITE_TOOL_PATTERNS:
            if pattern in tool_lower:
                return True
        # dst/destination typically indicates write target
        if arg_name in ("dst", "destination", "output", "target"):
            return True
        return False

    def _extract_host_from_url(self, url: str) -> Optional[str]:
        """Extract hostname from URL without external dependencies."""
        try:
            # Remove protocol
            if "://" in url:
                url = url.split("://", 1)[1]
            # Remove path
            url = url.split("/", 1)[0]
            # Remove port
            url = url.split(":", 1)[0]
            # Remove auth
            if "@" in url:
                url = url.split("@", 1)[1]
            return url if url else None
        except Exception:
            return None

    def before_tool_call(self, call: ToolCall) -> None:
        """
        Pre-execution policy check.

        Call this BEFORE executing any tool. Raises PermissionError
        if the call is blocked by policy.

        Args:
            call: The ToolCall to check

        Raises:
            PermissionError: If the call violates policy
        """
        if not self.enabled:
            return

        tool = call.tool
        args = call.args or {}
        tool_lower = tool.lower()

        # === Justification check ===
        if self.require_justification:
            if not call.justification or not call.justification.strip():
                self.log.log(
                    "tool_call_blocked",
                    "high",
                    "Missing justification for tool call",
                    {"tool": tool, "args": args},
                )
                raise PermissionError(
                    f"Blocked: tool call '{tool}' requires justification"
                )

        # === Tool policy check ===
        if self.tool_policy:
            decision = self.tool_policy.can_use(tool)
            if not decision.allowed:
                self.log.log(
                    "tool_blocked",
                    "high",
                    decision.reason,
                    {"tool": tool},
                )
                raise PermissionError(f"Blocked: {decision.reason} ({tool})")

        # === File policy checks ===
        if self.file_policy:
            for arg_name, arg_value in args.items():
                if arg_name.lower() not in self.PATH_ARG_NAMES:
                    continue
                if not isinstance(arg_value, str):
                    continue

                is_write = self._is_write_operation(tool, arg_name.lower())

                if is_write:
                    decision = self.file_policy.can_write(arg_value)
                    if not decision.allowed:
                        self.log.log(
                            "file_write_blocked",
                            "critical",
                            decision.reason,
                            {"tool": tool, "path": arg_value},
                        )
                        raise PermissionError(
                            f"Blocked: {decision.reason} ({arg_value})"
                        )
                else:
                    decision = self.file_policy.can_read(arg_value)
                    if not decision.allowed:
                        self.log.log(
                            "file_read_blocked",
                            "high",
                            decision.reason,
                            {"tool": tool, "path": arg_value},
                        )
                        raise PermissionError(
                            f"Blocked: {decision.reason} ({arg_value})"
                        )

        # === Network policy checks ===
        if self.net_policy:
            for arg_name, arg_value in args.items():
                if arg_name.lower() not in self.NETWORK_ARG_NAMES:
                    continue
                if not isinstance(arg_value, str):
                    continue

                # Extract host from URL if needed
                if arg_name.lower() == "url":
                    host = self._extract_host_from_url(arg_value)
                    if not host:
                        continue
                else:
                    host = arg_value

                decision = self.net_policy.can_connect(host)
                if not decision.allowed:
                    self.log.log(
                        "network_blocked",
                        "critical",
                        decision.reason,
                        {"tool": tool, arg_name: arg_value, "host": host},
                    )
                    raise PermissionError(
                        f"Blocked: {decision.reason} ({host})"
                    )

        # All checks passed
        self.log.log(
            "tool_call_allowed",
            "low",
            "Tool call permitted",
            {"tool": tool, "justification": call.justification[:100] if call.justification else ""},
        )

    def after_tool_call(
        self,
        call: ToolCall,
        result: Any,
    ) -> Any:
        """
        Post-execution processing.

        Call this AFTER tool execution to sanitize results.

        Args:
            call: The executed ToolCall
            result: The tool's return value

        Returns:
            Sanitized result
        """
        if not self.enabled:
            return result

        # Sanitize string results
        if isinstance(result, str):
            clean = sanitize_text(result)
            if clean != result:
                self.log.log(
                    "output_sanitized",
                    "medium",
                    "Tool result contained redactable material",
                    {"tool": call.tool},
                )
            return clean

        # Handle dict results (sanitize string values)
        if isinstance(result, dict):
            return self._sanitize_dict(result, call.tool)

        # Handle list results
        if isinstance(result, list):
            return self._sanitize_list(result, call.tool)

        return result

    def _sanitize_dict(self, d: Dict[str, Any], tool: str) -> Dict[str, Any]:
        """Recursively sanitize string values in a dict."""
        result = {}
        for k, v in d.items():
            if isinstance(v, str):
                clean = sanitize_text(v)
                if clean != v:
                    self.log.log(
                        "output_sanitized",
                        "medium",
                        f"Dict value sanitized",
                        {"tool": tool, "key": k},
                    )
                result[k] = clean
            elif isinstance(v, dict):
                result[k] = self._sanitize_dict(v, tool)
            elif isinstance(v, list):
                result[k] = self._sanitize_list(v, tool)
            else:
                result[k] = v
        return result

    def _sanitize_list(self, lst: List[Any], tool: str) -> List[Any]:
        """Recursively sanitize string values in a list."""
        result = []
        for item in lst:
            if isinstance(item, str):
                clean = sanitize_text(item)
                if clean != item:
                    self.log.log(
                        "output_sanitized",
                        "medium",
                        "List item sanitized",
                        {"tool": tool},
                    )
                result.append(clean)
            elif isinstance(item, dict):
                result.append(self._sanitize_dict(item, tool))
            elif isinstance(item, list):
                result.append(self._sanitize_list(item, tool))
            else:
                result.append(item)
        return result

    def sanitize_output(self, text: str) -> str:
        """
        Sanitize arbitrary output text.

        Use this for any text being sent to users or logs.

        Args:
            text: Text to sanitize

        Returns:
            Text with secrets redacted
        """
        if not self.enabled:
            return text

        clean = sanitize_text(text)
        if clean != text:
            self.log.log(
                "output_sanitized",
                "medium",
                "Outbound output contained redactable material",
                {},
            )
        return clean

    def log_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a custom event to the audit trail.

        Useful for logging application-specific security events.

        Args:
            event_type: Category of event
            severity: Severity level (critical, high, medium, low)
            message: Human-readable description
            details: Optional additional context
        """
        self.log.log(event_type, severity, message, details)
