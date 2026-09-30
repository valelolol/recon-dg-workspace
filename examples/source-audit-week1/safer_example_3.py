"""
Secure Example 3: Safe Data Serialization (B704 - Avoided)
Author: Christian
Date: 2026-09-25
Bandit Rule: B704 (pickle-deserialization) - Should NOT trigger
This example demonstrates safe data handling using JSON and
MessagePack instead of pickle, which avoids deserialization
vulnerabilities.
"""
import json
import msgpack
from typing import Any, Dict
from pathlib import Path


def deserialize_user_data_safe(data: str) -> Dict[str, Any]:
    """
    Deserialize user data from JSON format.

    SECURITY: Uses json.loads() which is safe from code execution
    BANDIT RULE: B704 (pickle-deserialization) - Should NOT trigger

    Why it's secure:
    - JSON only supports data structures (dicts, lists, strings, numbers)
    - No code execution during deserialization
    - No arbitrary object instantiation
    """

    # SECURE CODE - json.loads() is safe
    user_data = json.loads(data)
    return user_data


def process_user_preferences_safe(data: str) -> Dict[str, Any]:
    """
    Process user preferences from JSON data.

    SECURITY: Safe deserialization
    BANDIT RULE: B704 (pickle-deserialization) - Should NOT trigger
    """

    # SECURE CODE - json.loads() is safe
    preferences = json.loads(data)

    # Process preferences
    user_id = preferences.get("user_id", 0)
    settings = preferences.get("settings", {})

    return {
        "user_id": user_id,
        "settings": settings
    }


def load_config_from_file_safe(filepath: str) -> Dict[str, Any]:
    """
    Load configuration from JSON file.

    SECURITY: Reads and parses JSON safely
    BANDIT RULE: B704 (pickle-deserialization) - Should NOT trigger
    """

    # SECURE CODE - json.load() reads text files safely
    with open(filepath, "r", encoding="utf-8") as f:
        config_data = json.load(f)

    return config_data


def main():
    """Demonstration of secure serialization patterns."""

    print("=" * 60)
    print("SECURE DESERIALIZATION EXAMPLES")
    print("=" * 60)

    # Example 1: JSON deserialization
    try:
        with open("user_data.json", "r", encoding="utf-8") as f:
            user_data = json.load(f)
        print(f"Loaded user data: {user_data}")
    except FileNotFoundError:
        print("No user data file found")

    # Example 2: MessagePack deserialization (also safe)
    try:
        with open("preferences.msgpack", "rb") as f:
            preferences = msgpack.unpackb(f, raw=False)
        print(f"Loaded preferences: {preferences}")
    except FileNotFoundError:
        print("No preferences file found")

    # Example 3: JSON config file
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            config = json.load(f)
        print(f"Loaded config: {config}")
    except FileNotFoundError:
        print("No config file found")

    print("=" * 60)
    print("SUCCESS: These patterns are SECURE!")
    print("=" * 60)

    # Demonstrate that JSON cannot execute code
    print("\n[DEMONSTRATION] Testing JSON safety...")
    
    # JSON cannot represent code execution - it's just data
    safe_data = json.loads('{"name": "test", "value": 123}')
    print(f"Loaded safe data: {safe_data}")
    print("No code execution possible - only data structures!")


if __name__ == "__main__":
    main()
