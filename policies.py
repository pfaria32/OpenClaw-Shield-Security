"""
OpenClaw Shield — Policies

Access control policies for runtime guard enforcement.

Provides:
- FileAccessPolicy: Read/write path allowlists
- NetworkPolicy: Outbound domain allowlists
- ToolPolicy: Tool name allowlists (optional)

Policies use a deny-by-default model: if not explicitly allowed, access is denied.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse


@dataclass
class Decision:
    """Result of a policy check."""
    allowed: bool
    reason: str
    policy: Optional[str] = None  # Which policy made the decision


class FileAccessPolicy:
    """
    Allowlist-based file access control.

    Supports:
    - Exact path matches
    - Glob patterns (*, ?)
    - Directory prefixes (allow all under a directory)

    Usage:
        policy = FileAccessPolicy(
            allowed_read=["/app/workspace/*", "/app/config/"],
            allowed_write=["/app/workspace/output/*"],
        )
        decision = policy.can_read("/app/workspace/file.txt")
    """

    def __init__(self, allowed_read: List[str], allowed_write: List[str]):
        """
        Initialize file access policy.

        Args:
            allowed_read: List of paths/patterns allowed for reading
            allowed_write: List of paths/patterns allowed for writing
        """
        # Normalize and expand paths
        self.allowed_read = [self._normalize(p) for p in allowed_read]
        self.allowed_write = [self._normalize(p) for p in allowed_write]

    def _normalize(self, path: str) -> str:
        """Normalize a path for consistent matching."""
        # Expand user home directory
        expanded = str(Path(path).expanduser())
        # Resolve .. and . but don't require existence
        try:
            return str(Path(expanded).resolve())
        except (OSError, ValueError):
            return expanded

    def _match(self, target: str, allowlist: List[str]) -> tuple[bool, str]:
        """
        Check if target path matches any entry in allowlist.

        Returns:
            Tuple of (matched, matching_rule)
        """
        # Normalize target
        try:
            t = str(Path(target).expanduser().resolve())
        except (OSError, ValueError):
            t = str(Path(target).expanduser())

        for rule in allowlist:
            # Glob pattern matching
            if fnmatch.fnmatch(t, rule):
                return True, rule

            # Directory prefix matching
            rule_path = rule.rstrip("/")
            if t == rule_path:
                return True, rule
            if t.startswith(rule_path + "/"):
                return True, rule

        return False, ""

    def can_read(self, path: str) -> Decision:
        """
        Check if reading from path is allowed.

        Args:
            path: File path to check

        Returns:
            Decision with allowed status and reason
        """
        matched, rule = self._match(path, self.allowed_read)
        if matched:
            return Decision(
                allowed=True,
                reason=f"read path allowed by rule: {rule}",
                policy="file_read",
            )
        return Decision(
            allowed=False,
            reason="read path not in allowlist",
            policy="file_read",
        )

    def can_write(self, path: str) -> Decision:
        """
        Check if writing to path is allowed.

        Args:
            path: File path to check

        Returns:
            Decision with allowed status and reason
        """
        matched, rule = self._match(path, self.allowed_write)
        if matched:
            return Decision(
                allowed=True,
                reason=f"write path allowed by rule: {rule}",
                policy="file_write",
            )
        return Decision(
            allowed=False,
            reason="write path not in allowlist",
            policy="file_write",
        )


class NetworkPolicy:
    """
    Allowlist-based network access control.

    Supports:
    - Exact domain matches
    - Subdomain wildcards (prefix with '.')

    Usage:
        policy = NetworkPolicy(
            allowed_domains=["api.openai.com", ".amazonaws.com"]
        )
        decision = policy.can_connect("api.openai.com")
    """

    def __init__(self, allowed_domains: List[str]):
        """
        Initialize network policy.

        Args:
            allowed_domains: List of allowed domains
                            Prefix with '.' to allow subdomains
        """
        self.allowed_domains = [d.lower().strip() for d in allowed_domains]

    def can_connect(self, host: str) -> Decision:
        """
        Check if connecting to host is allowed.

        Args:
            host: Hostname or domain to check

        Returns:
            Decision with allowed status and reason
        """
        h = host.lower().strip()

        # Exact match
        if h in self.allowed_domains:
            return Decision(
                allowed=True,
                reason=f"domain allowed: {h}",
                policy="network",
            )

        # Subdomain match (rules starting with '.')
        for domain in self.allowed_domains:
            if domain.startswith(".") and h.endswith(domain):
                return Decision(
                    allowed=True,
                    reason=f"subdomain allowed by rule: {domain}",
                    policy="network",
                )
            # Also match if h is exactly the domain without leading dot
            if domain.startswith(".") and h == domain[1:]:
                return Decision(
                    allowed=True,
                    reason=f"domain allowed by rule: {domain}",
                    policy="network",
                )

        return Decision(
            allowed=False,
            reason="domain not in allowlist",
            policy="network",
        )

    def can_connect_url(self, url: str) -> Decision:
        """
        Check if connecting to URL is allowed (extracts host).

        Args:
            url: Full URL to check

        Returns:
            Decision with allowed status and reason
        """
        try:
            parsed = urlparse(url)
            host = parsed.hostname or parsed.netloc.split(":")[0]
            if not host:
                return Decision(
                    allowed=False,
                    reason="could not extract host from URL",
                    policy="network",
                )
            return self.can_connect(host)
        except Exception:
            return Decision(
                allowed=False,
                reason="invalid URL format",
                policy="network",
            )


class ToolPolicy:
    """
    Allowlist-based tool access control.

    Usage:
        policy = ToolPolicy(allowed_tools=["read_file", "search_web"])
        decision = policy.can_use("read_file")
    """

    def __init__(self, allowed_tools: List[str]):
        """
        Initialize tool policy.

        Args:
            allowed_tools: List of tool names that can be used
        """
        self.allowed_tools = [t.lower().strip() for t in allowed_tools]

    def can_use(self, tool: str) -> Decision:
        """
        Check if using a tool is allowed.

        Args:
            tool: Tool name to check

        Returns:
            Decision with allowed status and reason
        """
        t = tool.lower().strip()
        if t in self.allowed_tools:
            return Decision(
                allowed=True,
                reason=f"tool allowed: {tool}",
                policy="tool",
            )
        return Decision(
            allowed=False,
            reason="tool not in allowlist",
            policy="tool",
        )


class CombinedPolicy:
    """
    Combines multiple policies for convenience.

    Usage:
        policy = CombinedPolicy(
            file_policy=FileAccessPolicy(...),
            net_policy=NetworkPolicy(...),
            tool_policy=ToolPolicy(...),
        )
    """

    def __init__(
        self,
        file_policy: Optional[FileAccessPolicy] = None,
        net_policy: Optional[NetworkPolicy] = None,
        tool_policy: Optional[ToolPolicy] = None,
    ):
        self.file_policy = file_policy
        self.net_policy = net_policy
        self.tool_policy = tool_policy

    def can_read(self, path: str) -> Decision:
        if self.file_policy is None:
            return Decision(allowed=True, reason="no file policy configured")
        return self.file_policy.can_read(path)

    def can_write(self, path: str) -> Decision:
        if self.file_policy is None:
            return Decision(allowed=True, reason="no file policy configured")
        return self.file_policy.can_write(path)

    def can_connect(self, host: str) -> Decision:
        if self.net_policy is None:
            return Decision(allowed=True, reason="no network policy configured")
        return self.net_policy.can_connect(host)

    def can_use_tool(self, tool: str) -> Decision:
        if self.tool_policy is None:
            return Decision(allowed=True, reason="no tool policy configured")
        return self.tool_policy.can_use(tool)
