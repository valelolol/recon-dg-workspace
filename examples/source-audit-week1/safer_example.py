#!/usr/bin/env python3
"""
Safer example: Parses numeric input without eval().
Demonstrates safe input handling by:
- Using int() with explicit base and error handling
- Never executing arbitrary code
- Providing clear error messages for invalid input
"""

def parse_value(user_input):
    """
    SAFE: Parses user input as an integer without eval().
    
    Raises ValueError if input cannot be parsed.
    Does not execute arbitrary code.
    """
    try:
        # Explicit base=10 prevents octal/hex injection
        return int(user_input, 10)
    except ValueError:
        # Clear error message for invalid input
        raise ValueError(f"Invalid integer: {user_input!r}")
