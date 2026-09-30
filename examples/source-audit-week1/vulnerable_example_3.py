"""
Vulnerable Example 3: Unsafe Deserialization (B704)
Author: Christian
Date: 2026-09-25
Bandit Rule: B704 (pickle-deserialization)
This example demonstrates unsafe deserialization with pickle,
which can lead to remote code execution when processing
untrusted data.
"""
import pickle
import sys
from typing import Any, Dict
from pathlib import Path


def deserialize_user_data(data: bytes) -> Dict[str, Any]:
    """
    Deserialize user data from pickle format.

    VULNERABILITY: Uses pickle.loads() with untrusted data
    BANDIT RULE: B704 (pickle-deserialization)
    SEVERITY: HIGH

    Attack Scenario:
    1. Attacker creates malicious pickle payload
    2. Payload executes arbitrary code during deserialization
    3. Server processes payload and executes attacker's code

    Example exploit:
    payload = pickle.loads(pickle.dumps(__import__('os').system('whoami')))
    """

    # VULNERABLE CODE - pickle.loads() with untrusted data
    user_data = pickle.loads(data)
    return user_data


def process_user_preferences(data: bytes) -> Dict[str, Any]:
    """
    Process user preferences from serialized data.

    VULNERABILITY: Unsafe deserialization with pickle
    BANDIT RULE: B704 (pickle-deserialization)
    """

    # VULNERABLE CODE - pickle.loads() with untrusted data
    preferences = pickle.loads(data)

    # Process preferences
    user_id = preferences.get("user_id", 0)
    settings = preferences.get("settings", {})

    return {
        "user_id": user_id,
        "settings": settings
    }


def load_config_from_file(filepath: str) -> Dict[str, Any]:
    """
    Load configuration from serialized file.

    VULNERABILITY: Deserializes from potentially untrusted file
    BANDIT RULE: B704 (pickle-deserialization)
    """

    # VULNERABLE CODE - pickle.load() from file
    with open(filepath, "rb") as f:
        config_data = pickle.load(f)

    return config_data


def main():
    """Demonstration of vulnerable deserialization patterns."""

    print("=" * 60)
    print("VULNERABLE DESERIALIZATION EXAMPLES")
    print("=" * 60)

    # Example 1: Deserializing user data
    try:
        with open("user_data.pkl", "rb") as f:
            user_data = pickle.load(f)
        print(f"Loaded user data: {user_data}")
    except FileNotFoundError:
        print("No user data file found")

    # Example 2: Processing serialized preferences
    try:
        with open("preferences.pkl", "rb") as f:
            preferences = pickle.load(f)
        print(f"Loaded preferences: {preferences}")
    except FileNotFoundError:
        print("No preferences file found")

    # Example 3: Loading serialized configuration
    try:
        with open("config.pkl", "rb") as f:
            config = pickle.load(f)
        print(f"Loaded config: {config}")
    except FileNotFoundError:
        print("No config file found")

    print("=" * 60)
    print("WARNING: These patterns are VULNERABLE to RCE!")
    print("=" * 60)

    # Demonstrate the vulnerability with a simple payload
    print("\n[DEMONSTRATION] Creating malicious payload...")
    
    # This is what an attacker could send
    malicious_payload = pickle.loads(
        pickle.dumps((lambda: print("[ATTACK] Code executed!"))())
    )
    
    print("\n[DEMONSTRATION] If this code executed, it would show: [ATTACK] Code executed!")


if __name__ == "__main__":
    main()
