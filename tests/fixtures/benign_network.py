"""
OpenClaw Shield Test Fixture — Benign Network Code

This file contains LEGITIMATE network code that WILL trigger
low-severity network_activity findings. This is expected behavior.

The scanner flags all network activity for review — it's up to
the operator to verify the domains are expected.

THIS IS A TEST FIXTURE — SAFE TO SCAN
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib.request import urlopen, Request


def fetch_json(url: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Fetch JSON from a URL.
    
    This is legitimate network code that should trigger:
    - network_activity (low severity)
    
    The operator should verify the URL is expected.
    """
    request = Request(url, headers={"Accept": "application/json"})
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def check_api_health(base_url: str) -> bool:
    """
    Check if an API is healthy.
    
    Example URL pattern that triggers detection:
    https://api.example.com/health
    """
    try:
        result = fetch_json(f"{base_url}/health")
        return result.get("status") == "ok"
    except Exception:
        return False


# Example URLs that will be detected (this is expected):
EXAMPLE_URLS = [
    "https://api.example.com/v1/data",
    "https://cdn.example.org/assets/",
    "http://localhost:8080/api/",
]


class APIClient:
    """
    Simple API client for demonstration.
    
    Network calls in this class will trigger low-severity findings.
    This is intentional — the scanner wants human review of all
    network destinations.
    """
    
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url
        self.api_key = api_key
    
    def get(self, endpoint: str) -> Dict[str, Any]:
        """Make a GET request."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        return fetch_json(url)
    
    def list_items(self) -> list:
        """List items from API."""
        result = self.get("/items")
        return result.get("items", [])


def main():
    """Example usage."""
    client = APIClient("https://api.example.com")
    
    # This will trigger network_activity finding
    if check_api_health("https://api.example.com"):
        items = client.list_items()
        print(f"Found {len(items)} items")
    else:
        print("API is not healthy")


if __name__ == "__main__":
    main()
