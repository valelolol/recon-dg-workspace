# Recon-DG Scanner: Limitations and Known Issues

**Author:** Nick & Christian  
**Date:** 2026-09-25  
**Version:** 1.0

---

## Overview

This document tracks known limitations, false positives, and false negatives in the Recon-DG scanner implementation. Transparency about these limitations is critical for accurate risk assessment and future improvements.

---

## Week 1: Bandit Configuration Limitations

### False Positive Cases

#### Case 1: Legitimate `eval()` Usage

**Description:**
Bandit flags all uses of `eval()` as dangerous, even when used safely for string formatting or safe expression parsing.

**Example Code:**
```python
# This is safe - string formatting, not code execution
template = "SELECT * FROM users WHERE id = "
value = "123"
result = template + str(value)  # No eval() needed

# This is also safe - using eval for safe literal evaluation
import ast
data = ast.literal_eval(user_input)  # Safe for strings, numbers, lists
```

**Why It's a False Positive:**
- No actual code execution occurs
- String concatenation, not dynamic evaluation
- Context matters but Bandit treats all `eval()` equally
- `ast.literal_eval()` is safe but flagged as dangerous

**Bandit Output:**
```
[main] B307:python-unsafe-eval
...
eval() found: ast.literal_eval(user_input)
```

**Rationale:**
- Bandit's B307 rule is overly broad
- Doesn't distinguish between code execution and safe evaluation
- Context-aware detection is not implemented

**Mitigation:**
- Add context-aware detection
- Filter out `ast.literal_eval()` usage
- Require explicit code execution patterns (e.g., `exec()`)

**Priority:** High — reduces false positive rate significantly

---

#### Case 2: ORM Parameterized Queries

**Description:**
Bandit doesn't distinguish between raw SQL and ORM parameterized queries, flagging safe ORM usage as vulnerable.

**Example Code:**
```python
# SECURE - SQLAlchemy ORM (should NOT trigger B608)
query = db.session.query(User).filter_by(id=user_input).first()

# SECURE - Django ORM (should NOT trigger B608)
user = User.objects.get(pk=user_input)

# SECURE - Peewee ORM (should NOT trigger B608)
user = User.get(User.id == user_input)
```

**Why It's a False Positive:**
- ORM frameworks automatically parameterize queries
- No user input is directly concatenated into SQL
- Bandit cannot distinguish ORM from raw queries syntactically

**Bandit Output:**
```
[main] B608:sql-injection
...
raw SQL query detected
```

**Rationale:**
- Bandit's SQL injection detection is pattern-based
- Cannot analyze ORM library behavior
- Requires AST-level analysis of query construction

**Mitigation:**
- Add ORM-specific rules (SQLAlchemy, Django, Peewee)
- Use AST analysis to detect parameter binding
- Add whitelist for known-safe ORM patterns

**Priority:** High — reduces false positives in modern frameworks

---

### False Negative Cases

#### Case 1: Indirect SQL Injection

**Description:**
Bandit doesn't detect SQL injection when table names or column names are dynamic.

**Example Code:**
```python
# VULNERABLE - Dynamic table name (may not be detected)
cursor.execute(f"SELECT * FROM {table_name}")

# VULNERABLE - Dynamic column name (not detected)
column = "username"
cursor.execute(f"SELECT {column} FROM users")

# VULNERABLE - Dynamic WHERE clause (not detected)
cursor.execute(f"SELECT * FROM users WHERE table = '{table_name}'")
```

**Why It's a False Negative:**
- Not a standard SQL injection pattern
- Requires table/column name validation checks
- Bandit focuses on value injection, not structural injection
- AST analysis cannot detect table name concatenation reliably

**Bandit Output:**
```
No findings detected
```

**Rationale:**
- B608 rule focuses on value-based injection
- Doesn't detect table name manipulation
- Requires specialized pattern matching

**Mitigation:**
- Add table name allowlist check
- Implement additional validation rules
- Flag dynamic table names as suspicious

**Priority:** Medium — important for advanced attacks

---

#### Case 2: Context-Aware Subprocess Usage

**Description:**
Bandit may miss safe subprocess usage when input is validated elsewhere.

**Example Code:**
```python
# VULNERABLE by default (Bandit will flag)
def process_command(cmd: str) -> str:
    result = subprocess.run(["bash", "-c", cmd], capture_output=True)
    return result.stdout.decode()

# But with validation elsewhere, this might be safe
def process_user_command(user_input: str) -> str:
    # Validation in calling code
    if is_safe_command(user_input):
        result = subprocess.run(["bash", "-c", user_input])
        return result.stdout.decode()
```

**Why It's a False Negative:**
- Bandit cannot see the validation context
- Assumes all subprocess usage is dangerous
- Cannot analyze cross-function data flow

**Bandit Output:**
```
[main] B602:subprocess-popen-no-shell-false
...
subprocess with shell=True detected
```

**Rationale:**
- Bandit performs local analysis only
- Cannot track data flow across functions
- Requires inter-procedural analysis

**Mitigation:**
- Add data flow analysis
- Track validation context
- Use control flow graphs

**Priority:** Medium — requires significant implementation effort

---

## Recommendations for Improvement

### Short-term (Week 1-2)

1. **Add context-aware detection for `eval()`**
   - Distinguish `ast.literal_eval()` from `eval()`
   - Filter out safe string operations

2. **Filter ORM parameterized queries**
   - Add SQLAlchemy, Django, Peewee detection
   - Use AST analysis for parameter binding

3. **Document all false positives/negatives**
   - Create comprehensive limitations documentation
   - Track known issues in a changelog

### Medium-term (Week 3-4)

1. **Implement custom detection rules**
   - Add project-specific patterns
   - Create custom Bandit plugins

2. **Add confidence scoring**
   - Weight findings by confidence level
   - Provide uncertainty estimates

3. **Create regression test suite**
   - Add more test cases
   - Cover edge cases

### Long-term (Month 2+)

1. **Multi-language support**
   - Add JavaScript/TypeScript
   - Add Java/Kotlin
   - Add Go/Rust

2. **LLM-based analysis**
   - Use LLM for context understanding
   - Generate explanations for findings

3. **Continuous learning from false positives**
   - Track user feedback
   - Auto-tune detection thresholds

---

## Testing Methodology

### Test Environment

- **Python:** 3.14.4
- **Bandit:** 1.9.4
- **OS:** Linux

### Test Cases

- **Vulnerable examples:** 3
- **Secure examples:** 3
- **Total:** 6 test cases

### Success Criteria

- **True Positives:** All vulnerabilities detected
- **True Negatives:** All secure code passes
- **False Positives:** < 2
- **False Negatives:** < 2

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-09-25 | Nick & Christian | Initial limitations documentation |

---

## References

- [Bandit False Positives Discussion](https://github.com/PyCQA/bandit/issues)
- [SQL Injection Detection](https://bandit.readthedocs.io/en/latest/plugins/b608_sql_injection.html)
- [Deserialization Detection](https://bandit.readthedocs.io/en/latest/plugins/b704_pickle_deserialization.html)
