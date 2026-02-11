"""
OpenClaw Shield Test Fixture — Clean Code Example

This file contains SAFE, BENIGN code that should NOT trigger
any security findings. Used to test false positive rates.

THIS IS A TEST FIXTURE — SAFE TO SCAN
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional


def read_config_file(config_path: str) -> dict:
    """Read a JSON configuration file."""
    import json
    
    path = Path(config_path)
    if not path.exists():
        return {}
    
    with open(path, "r") as f:
        return json.load(f)


def get_app_name() -> str:
    """Get application name from environment or default."""
    # This reads a non-sensitive env var - should not trigger
    return os.environ.get("APP_NAME", "MyApp")


def get_log_level() -> str:
    """Get logging level from environment."""
    # Non-sensitive environment variable
    return os.environ.get("LOG_LEVEL", "INFO")


def calculate_sum(numbers: List[int]) -> int:
    """Calculate sum of numbers."""
    return sum(numbers)


def format_message(template: str, **kwargs) -> str:
    """Format a message template."""
    return template.format(**kwargs)


def save_data(data: dict, output_path: str) -> None:
    """Save data to a JSON file."""
    import json
    
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)


class DataProcessor:
    """Example data processor class."""
    
    def __init__(self, name: str):
        self.name = name
        self.processed_count = 0
    
    def process(self, items: List[str]) -> List[str]:
        """Process a list of items."""
        result = [item.strip().lower() for item in items]
        self.processed_count += len(result)
        return result
    
    def get_stats(self) -> dict:
        """Get processing statistics."""
        return {
            "name": self.name,
            "processed": self.processed_count,
        }


def main():
    """Example main function."""
    processor = DataProcessor("example")
    data = ["Hello", "World", "Test"]
    result = processor.process(data)
    print(f"Processed: {result}")
    print(f"Stats: {processor.get_stats()}")


if __name__ == "__main__":
    main()
