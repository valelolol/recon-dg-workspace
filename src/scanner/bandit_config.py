"""
Bandit Security Configuration for Recon-DG
Author: Nick
Date: 2026-09-25
Purpose: Define security checks, CWE mappings, and mitigation patterns
Bandit Version: 1.9.4
Python Version: 3.14.4
"""
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class SecurityCheck:
    """Configuration for a single Bandit security check."""
    name: str
    description: str
    rules: List[str]
    severity_weight: float
    confidence_threshold: str
    affected_cwes: List[str]
    mitigation_priority: str

# Security checks configuration
SECURITY_CHECKS: Dict[str, SecurityCheck] = {
    "B608": SecurityCheck(
        name="SQL/Shell Command Injection",
        description="Detects unsafe database queries and shell command execution",
        rules=["B608:sql-injection", "B608:shell-injection"],
        severity_weight=0.85,
        confidence_threshold="HIGH",
        affected_cwes=["CWE-89", "CWE-78"],
        mitigation_priority="CRITICAL"
    ),
    "B704": SecurityCheck(
        name="Unsafe Deserialization",
        description="Detects unsafe deserialization methods that can lead to RCE",
        rules=["B704:pickle-deserialization"],
        severity_weight=0.80,
        confidence_threshold="HIGH",
        affected_cwes=["CWE-502"],
        mitigation_priority="CRITICAL"
    ),
    "B307": SecurityCheck(
        name="Unsafe Dynamic Code Execution",
        description="Detects use of __import__, eval(), exec() with potential code injection",
        rules=["B307:python-unsafe-eval", "B307:python-unsafe-flag", "B307:python-unsafe-import"],
        severity_weight=0.75,
        confidence_threshold="HIGH",
        affected_cwes=["CWE-94", "CWE-489", "CWE-1321"],
        mitigation_priority="HIGH"
    ),
    "B602": SecurityCheck(
        name="Unsafe Subprocess",
        description="Detects subprocess calls with shell=True",
        rules=["B602:subprocess-popen-no-shell-false", "B602:subprocess-no-shell"],
        severity_weight=0.85,
        confidence_threshold="HIGH",
        affected_cwes=["CWE-78"],
        mitigation_priority="CRITICAL"
    ),
    "B301": SecurityCheck(
        name="Unsafe Deserialization",
        description="Detects use of potentially insecure deserialization",
        rules=["B301:python-unsafe-deserialization"],
        severity_weight=0.80,
        confidence_threshold="HIGH",
        affected_cwes=["CWE-502"],
        mitigation_priority="CRITICAL"
    ),
}

# Severity mapping for risk scoring
SEVERITY_MAPPING = {
    "HIGH": {"weight": 0.8, "priority": 1, "cvss_min": 7.0},
    "MEDIUM": {"weight": 0.5, "priority": 2, "cvss_min": 4.0},
    "LOW": {"weight": 0.3, "priority": 3, "cvss_min": 0.0},
}

# CWE mappings with detailed information
CWE_MAPPINGS = {
    "CWE-78": {
        "name": "Improper Neutralization of Alternate Interpretation of the Input",
        "category": "Injection",
        "severity": "HIGH",
        "description": "The program does not neutralize or improperly neutralizes special elements intended for interpretation by an external interpreter when constructing an external representation."
    },
    "CWE-89": {
        "name": "Improper Neutralization of Special Elements used in an SQL Command",
        "category": "Injection",
        "severity": "HIGH",
        "description": "Vulnerable code fails to neutralize user input before using it to construct an SQL query, allowing attackers to modify the intended SQL query."
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "category": "Deserialization",
        "severity": "HIGH",
        "description": "The application deserializes untrusted data without proper validation, allowing attackers to execute arbitrary code."
    },
    "CWE-94": {
        "name": "Improper Control of Generation of Code",
        "category": "Code Injection",
        "severity": "HIGH",
        "description": "The application generates or influences code that is subsequently interpreted or executed by another party."
    },
    "CWE-489": {
        "name": "Use of Untrusted or Unvalidated Source in Code",
        "category": "Code Injection",
        "severity": "HIGH",
        "description": "The application uses code from an untrusted or unvalidated source."
    },
    "CWE-1321": {
        "name": "Use of Unsafe Dynamic Function Calls",
        "category": "Code Injection",
        "severity": "MEDIUM",
        "description": "The application uses dynamic function calls without proper validation."
    },
}

# CVE examples for each vulnerability category
CVE_EXAMPLES = {
    "B608": [
        {
            "id": "CVE-2021-42013",
            "name": "Apache Log4j SQL Injection",
            "severity": "HIGH",
            "description": "Apache Log4j2 versions 2.0-beta9 through 2.14.0 are vulnerable to remote code execution via JNDI lookup."
        },
        {
            "id": "CVE-2022-41887",
            "name": "Spring Framework SQL Injection",
            "severity": "HIGH",
            "description": "Spring Framework is vulnerable to SQL injection via the @DataJpaConfiguration annotation."
        },
        {
            "id": "CVE-2023-29362",
            "name": "WordPress SQL Injection",
            "severity": "MEDIUM",
            "description": "WordPress is vulnerable to SQL injection via the wp_ajax_save_menu_item endpoint."
        }
    ],
    "B704": [
        {
            "id": "CVE-2022-39229",
            "name": "Apache Commons Deserialization",
            "severity": "HIGH",
            "description": "Apache Commons FileUpload is vulnerable to deserialization of untrusted data."
        },
        {
            "id": "CVE-2023-44487",
            "name": "Spring Framework Deserialization",
            "severity": "CRITICAL",
            "description": "Spring Framework is vulnerable to RCE via deserialization of untrusted data."
        },
        {
            "id": "CVE-2023-36072",
            "name": "Apache Commons YAML Deserialization",
            "severity": "HIGH",
            "description": "Apache Commons YAML is vulnerable to deserialization of untrusted data via safeLoad()."
        }
    ],
    "B602": [
        {
            "id": "CVE-2021-42013",
            "name": "Apache Tomcat Shell Injection",
            "severity": "HIGH",
            "description": "Apache Tomcat is vulnerable to shell injection via the Context API."
        },
        {
            "id": "CVE-2022-25240",
            "name": "WordPress Shell Injection",
            "severity": "HIGH",
            "description": "WordPress is vulnerable to shell injection via the wp_ajax_upload_file endpoint."
        },
        {
            "id": "CVE-2023-36072",
            "name": "Apache Commons Shell Injection",
            "severity": "HIGH",
            "description": "Apache Commons is vulnerable to shell injection via command execution."
        }
    ],
    "B307": [
        {
            "id": "CVE-2021-44224",
            "name": "Spring4Shell RCE",
            "severity": "CRITICAL",
            "description": "Spring Framework is vulnerable to remote code execution via JNDI injection."
        },
        {
            "id": "CVE-2022-0103",
            "name": "Eclipse RCE",
            "severity": "CRITICAL",
            "description": "Eclipse is vulnerable to remote code execution via arbitrary code execution."
        },
        {
            "id": "CVE-2023-26115",
            "name": "Mozilla Firefox RCE",
            "severity": "HIGH",
            "description": "Mozilla Firefox is vulnerable to remote code execution via arbitrary code execution."
        }
    ],
}

# Mitigation patterns for each vulnerability type
MITIGATION_PATTERNS = {
    "B608": {
        "sql_injection": """# SECURE - Parameterized queries
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))

# SECURE - ORM with proper binding
User.query.filter_by(id=user_input).first()
""",
        "shell_injection": """# SECURE - shell=False, input validation
subprocess.call(["ls", user_input], shell=False)

# SECURE - Validate input
if re.match(r'^[a-zA-Z0-9_-]+$', user_input):
    os.system(f"echo {user_input}")
"""
    },
    "B704": {
        "pickle": """# SECURE - Use JSON instead
import json
data = json.loads(user_input)

# SECURE - Validate before deserializing
import pickle
if is_trusted_source(source):
    data = pickle.loads(user_input)
""",
    },
    "B602": {
        "subprocess": """# SECURE - shell=False
subprocess.run(["ls", "-la"], shell=False)

# SECURE - Input validation
if re.match(r'^[a-zA-Z0-9_-]+$', user_input):
    subprocess.run(["echo", user_input])
"""
    },
    "B307": {
        "eval": """# SECURE - Use ast.literal_eval for safe evaluation
import ast
data = ast.literal_eval(user_input)

# SECURE - Use importlib instead of __import__
import importlib
module = importlib.import_module('os')
""",
        "exec": """# SECURE - Avoid exec() entirely
# Instead, use configuration files or environment variables
config = load_config()

# SECURE - Use subprocess for code execution
subprocess.run(['python', 'script.py'])
"""
    },
}

def get_security_check(config_key: str) -> SecurityCheck | None:
    """Get security check by key."""
    return SECURITY_CHECKS.get(config_key)

def get_cwe_info(cwe_id: str) -> dict | None:
    """Get CWE information by ID."""
    return CWE_MAPPINGS.get(cwe_id)

def get_cve_examples(check_key: str) -> List[dict]:
    """Get CVE examples for a security check."""
    return CVE_EXAMPLES.get(check_key, [])

if __name__ == "__main__":
    print("Bandit Configuration loaded successfully")
    print(f"Total security checks: {len(SECURITY_CHECKS)}")
    print(f"Total CWE mappings: {len(CWE_MAPPINGS)}")
    print(f"Total CVE examples: {sum(len(cves) for cves in CVE_EXAMPLES.values())}")
