#!/usr/bin/env python3
"""
Vulnerable example: Uses eval() on user input.
This demonstrates unsafe input handling.
"""

def calculate_value(user_input):
    """
    DANGEROUS: Evaluates user-supplied string as Python code.
    An attacker could inject malicious code.
    
    Example attack:
    calculate_value("__import__('os').system('id')")
    """
    return eval(user_input)
