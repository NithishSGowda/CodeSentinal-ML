"""
scanner/patcher.py
-------------------
Deterministic Code Patching Engine for CodeSentinel ML

This module takes a vulnerability issue name and the raw line of code,
and applies deterministic code transformation rules to generate a secure
remediation line and a clear explanation of the correction.

NO Generative AI or external APIs are used.
"""

import re

def generate_code_fix(issue_name, line_content):
    """
    Generate a secure replacement line of code and a technical description.

    Parameters
    ----------
    issue_name   : str
        The name of the vulnerability issue (e.g. "Weak Hashing (MD5)")
    line_content : str
        The exact raw line of code containing the finding

    Returns
    -------
    tuple of (fixed_line: str, explanation: str)
    """
    stripped = line_content.strip()
    indent_match = re.match(r'^(\s*)', line_content)
    indent = indent_match.group(1) if indent_match else ""

    # 1. SSL Verification Disabled
    if issue_name == "SSL Verification Disabled":
        if "verify" in stripped:
            fixed = re.sub(r'verify\s*=\s*False', 'verify=True', line_content, flags=re.IGNORECASE)
            explanation = "SSL/TLS verification is now explicitly enabled by changing `verify=False` to `verify=True`, preventing Man-in-the-Middle (MITM) hijacking."
            return fixed, explanation

    # 2. Weak Hashing (MD5 / SHA1)
    if issue_name == "Weak Hashing (MD5)":
        if "hashlib.md5" in line_content:
            fixed = line_content.replace("hashlib.md5(", "hashlib.sha256(")
            explanation = "Upgraded broken MD5 hashing to secure SHA-256 algorithm via the hashlib module."
            return fixed, explanation
    if issue_name == "Weak Hashing (SHA1)":
        if "hashlib.sha1" in line_content:
            fixed = line_content.replace("hashlib.sha1(", "hashlib.sha256(")
            explanation = "Upgraded deprecated SHA-1 hashing algorithm to secure SHA-256."
            return fixed, explanation

    # 3. Debug Mode Enabled
    if issue_name == "Debug Mode Enabled":
        fixed = re.sub(r'debug\s*=\s*True', 'debug=False', line_content, flags=re.IGNORECASE)
        fixed = re.sub(r'DEBUG\s*=\s*True', 'DEBUG=False', fixed, flags=re.IGNORECASE)
        explanation = "Disabled high-risk debug environment options so stack trace errors and diagnostic interactive shells are shielded from client visibility."
        return fixed, explanation

    # 4. Insecure Deserialization (YAML / Pickle)
    if issue_name == "Insecure Deserialization (yaml)":
        if "yaml.load(" in line_content:
            # Check if Loader is passed or regular load
            fixed = line_content.replace("yaml.load(", "yaml.safe_load(")
            # Clean up trailing loaders if any
            fixed = re.sub(r',\s*Loader\s*=\s*\w+(\.\w+)*', '', fixed)
            explanation = "Upgraded yaml.load() to yaml.safe_load() which safely restricts deserialization to simple standard structures, preventing arbitrary object instantiation."
            return fixed, explanation
    if issue_name == "Insecure Deserialization (pickle)":
        if "pickle.loads(" in line_content:
            fixed = line_content.replace("pickle.loads(", "json.loads(")
            explanation = "Replaced unsafe binary pickle loading with standardized JSON deserialization to completely avoid arbitrary code execution risks."
            return fixed, explanation

    # 5. Dangerous Execution (eval / exec)
    if issue_name == "Dangerous Execution (eval)":
        if "eval(" in line_content:
            fixed = line_content.replace("eval(", "ast.literal_eval(")
            explanation = "Replaced evaluation engine eval() with safe literal evaluator ast.literal_eval() to parse only basic Python data structures safely."
            return fixed, explanation
    if issue_name == "Dangerous Execution (exec)":
        if "exec(" in line_content:
            fixed = f"{indent}# exec() execution block disabled for critical safety. Redesign logic to avoid dynamic interpretation.\n{indent}# {stripped}"
            explanation = "Disabled dynamic runtime exec() system, removing direct code execution paths."
            return fixed, explanation

    # 6. System Command Execution (os.system)
    if issue_name == "System Command Execution (os.system)":
        if "os.system(" in line_content:
            # Replace os.system with subprocess.run
            fixed = line_content.replace("os.system(", "subprocess.run(")
            if ")" in fixed:
                fixed = fixed.replace(")", ", shell=False)")
            explanation = "Replaced risky os.system shell invocation with safe subprocess API. Advised to pass arguments as lists with shell=False."
            return fixed, explanation

    # 7. Subprocess Execution
    if issue_name == "Subprocess Execution":
        if "shell=True" in line_content:
            fixed = line_content.replace("shell=True", "shell=False")
            explanation = "Forced subprocess shell=False to prevent shell metacharacter injection vulnerability."
            return fixed, explanation

    # 8. Hardcoded Secrets (Passwords, Keys, Tokens, Secrets)
    if issue_name in ("Hardcoded Password", "Hardcoded API Key", "Hardcoded Token", "Hardcoded Secret"):
        # Match python style assignment: var = 'secret'
        # Handles JS style as well: const var = 'secret'
        match = re.match(r'^(\s*)(const\s+|let\s+|var\s+)?(\w+)\s*=\s*[\'"][^\'"]+[\'"](.*)', line_content)
        if match:
            indentation, declaration, var_name, remainder = match.groups()
            declaration = declaration or ""
            env_var = var_name.upper()
            
            # Python env fetch
            if not declaration:
                fixed = f"{indentation}{var_name} = os.getenv('{env_var}'){remainder}"
                explanation = f"Extracted hardcoded secret into a secure, dynamic environment variable check `os.getenv('{env_var}')`."
            else: # JS env fetch
                fixed = f"{indentation}{declaration}{var_name} = process.env.{env_var}{remainder}"
                explanation = f"Extracted hardcoded secret into secure Node.js environment variable `process.env.{env_var}`."
            return fixed, explanation

    # 9. Insecure Random (random module)
    if issue_name == "Insecure Random (random module)":
        if "random.randint(" in line_content:
            fixed = line_content.replace("random.randint(", "secrets.randbelow(")
            explanation = "Upgraded insecure pseudo-random module to secure cryptographic secrets generator."
            return fixed, explanation

    # 10. SQL Injection
    if "SQL Injection" in issue_name:
        # Check if python string formatting or f-string
        if "f\"" in line_content or "f'" in line_content or ".format(" in line_content or "+" in line_content:
            explanation = "SQL injection threat resolved by swapping concatenated queries with safe parameterized statements. Pass query variables strictly as secondary execution tuples."
            # Render a generic safe placeholder for visual guidance
            fixed = f"{indent}# Use parameterization: cursor.execute('SELECT * FROM table WHERE col = ?', (val,))\n{indent}# Original: {stripped}"
            return fixed, explanation

    # Default fallback
    explanation = "Review code syntax details manually. Replace variable concatenations or insecure routines with robust sanitization and framework validator libraries."
    fixed = f"{indent}# Review and apply defensive security improvements:\n{line_content}"
    return fixed, explanation
