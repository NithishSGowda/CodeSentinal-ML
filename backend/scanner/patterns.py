"""
scanner/patterns.py
--------------------
Central Pattern Registry for Static Analysis

Contains all regex patterns used for:
  1. Vulnerability detection
  2. Hardcoded secret detection
  3. Attacker entry-point detection
"""

import re

# =======================================================================
# 1. VULNERABILITY PATTERNS
# =======================================================================
# Each entry is a dict with: name, regex, severity, description
# Severity levels: "High" | "Medium" | "Low"

VULNERABILITY_PATTERNS = [

    # ── Dangerous Code Execution ─────────────────────────────────────────
    {
        "name": "Dangerous Execution (eval)",
        "regex": r"\beval\s*\(",
        "severity": "High",
        "description": "eval() executes arbitrary code strings — a direct path to Remote Code Execution."
    },
    {
        "name": "Dangerous Execution (exec)",
        "regex": r"\bexec\s*\(",
        "severity": "High",
        "description": "exec() runs dynamically created Python code. Never use with user-controlled data."
    },
    {
        "name": "System Command Execution (os.system)",
        "regex": r"os\.system\s*\(",
        "severity": "High",
        "description": "os.system() passes a string to the OS shell — vulnerable to command injection."
    },
    {
        "name": "Subprocess Execution",
        "regex": r"subprocess\.(Popen|call|run|check_output|getoutput)\s*\(",
        "severity": "High",
        "description": "Subprocess spawning with shell=True or user input leads to command injection."
    },
    {
        "name": "Insecure Deserialization (pickle)",
        "regex": r"pickle\.loads\s*\(",
        "severity": "High",
        "description": "pickle.loads() on untrusted data can execute arbitrary code on load."
    },
    {
        "name": "Insecure Deserialization (yaml)",
        "regex": r"yaml\.load\s*\(",
        "severity": "High",
        "description": "yaml.load() without Loader=yaml.SafeLoader can deserialise arbitrary Python objects."
    },
    {
        "name": "Insecure Template Rendering",
        "regex": r"render_template_string\s*\(",
        "severity": "High",
        "description": "render_template_string() with user input causes Server-Side Template Injection (SSTI)."
    },
    {
        "name": "Open Redirect",
        "regex": r"redirect\s*\(\s*request\.(args|form|json|values)",
        "severity": "High",
        "description": "Redirecting to a user-supplied URL enables phishing and open-redirect attacks."
    },

    # ── SQL Injection ─────────────────────────────────────────────────────
    # NOTE: Patterns are anchored to string literals to avoid false positives
    # on NoSQL codebases (MongoDB, DynamoDB, etc.) that use Python dicts/objects.
    {
        "name": "SQL Injection (Concatenation)",
        # Must be inside a string literal (quote before keyword) AND use + concatenation
        # Excludes lines that look like NoSQL (no quotes around SQL keyword)
        "regex": r"['\"].*(SELECT|INSERT|UPDATE|DELETE).*['\"]\s*\+|\+\s*['\"].*(SELECT|INSERT|UPDATE|DELETE)",
        "severity": "High",
        "description": "String-concatenation in SQL queries enables injection — use parameterised queries."
    },
    {
        "name": "SQL Injection (f-string)",
        # f-string must contain a SQL keyword AND a { interpolation
        "regex": r"f['\"].*(SELECT|INSERT|UPDATE|DELETE|FROM\s+\w+\s+WHERE).*\{",
        "severity": "High",
        "description": "f-strings in SQL are not sanitised — use parameterised queries instead."
    },
    {
        "name": "SQL Injection (.format)",
        # .format() call on a string containing a SQL keyword
        "regex": r"['\"].*(SELECT|INSERT|UPDATE|DELETE).*['\"]\s*\.format\s*\(",
        "severity": "High",
        "description": ".format() in SQL is vulnerable to injection. Use ? / %s placeholders."
    },
    {
        "name": "SQL Injection (% formatting)",
        # Old-style % formatting on SQL strings
        "regex": r"['\"].*(SELECT|INSERT|UPDATE|DELETE).*['\"](\s*%\s*|\s*%\s*\()",
        "severity": "High",
        "description": "%-formatting in SQL queries is vulnerable to injection. Use parameterised queries."
    },
    # ── NoSQL Injection ───────────────────────────────────────────────────
    {
        "name": "NoSQL Injection (MongoDB $where)",
        # $where with user-controlled input is a NoSQL injection vector
        "regex": r"\$where.*?(request|req|input|args|params|body|query|user|data)",
        "severity": "High",
        "description": "MongoDB $where with user input enables NoSQL injection — use $eq/$in operators instead."
    },
    {
        "name": "NoSQL Injection (dynamic operator)",
        # Building a MongoDB query dict with user-supplied keys (enables operator injection)
        "regex": r"\{\s*(request|req|input|args|params|body|user).*\$|\.find\s*\(\s*(request|req|input|args|body)",
        "severity": "High",
        "description": "Passing user input directly as MongoDB query keys allows operator injection attacks."
    },

    # ── Hardcoded Secrets ─────────────────────────────────────────────────
    {
        "name": "Hardcoded Password",
        "regex": r"(password|passwd|pwd)\s*=\s*['\"][^'\"]{3,}['\"]",
        "severity": "Medium",
        "description": "Plain-text passwords in source code can be trivially extracted by anyone with file access."
    },
    {
        "name": "Hardcoded API Key",
        "regex": r"(api_key|apikey|api[-_]key)\s*=\s*['\"][^'\"]{6,}['\"]",
        "severity": "Medium",
        "description": "Hardcoded API keys grant access to external services and billing accounts."
    },
    {
        "name": "Hardcoded Token",
        "regex": r"(token|auth_token|access_token|bearer)\s*=\s*['\"][^'\"]{6,}['\"]",
        "severity": "Medium",
        "description": "Authentication tokens in code enable session hijacking and impersonation."
    },
    {
        "name": "Hardcoded Secret",
        "regex": r"(secret|secret_key|private_key)\s*=\s*['\"][^'\"]{3,}['\"]",
        "severity": "Medium",
        "description": "Exposed secret keys allow session forgery and cryptographic attacks."
    },

    # ── Unsafe Practices ──────────────────────────────────────────────────
    {
        "name": "SSL Verification Disabled",
        "regex": r"verify\s*=\s*False",
        "severity": "Medium",
        "description": "Disabling SSL verification allows man-in-the-middle attacks on HTTPS connections."
    },
    {
        "name": "Weak Hashing (MD5)",
        "regex": r"hashlib\.md5\s*\(",
        "severity": "Medium",
        "description": "MD5 is cryptographically broken. Use SHA-256 or bcrypt for passwords."
    },
    {
        "name": "Weak Hashing (SHA1)",
        "regex": r"hashlib\.sha1\s*\(",
        "severity": "Medium",
        "description": "SHA-1 is deprecated for security use. Use SHA-256 or stronger."
    },
    {
        "name": "Insecure Random (random module)",
        "regex": r"\brandom\.(randint|random|choice|shuffle)\s*\(",
        "severity": "Low",
        "description": "The 'random' module is not cryptographically secure. Use 'secrets' for tokens/IDs."
    },
    {
        "name": "Debug Mode Enabled",
        "regex": r"(app\.run\s*\(.*debug\s*=\s*True|DEBUG\s*=\s*True)",
        "severity": "Medium",
        "description": "Debug mode exposes stack traces and an interactive debugger to anyone on the network."
    },
    {
        "name": "Wildcard CORS / Allowed Hosts",
        "regex": r"(ALLOWED_HOSTS|cors.*origin|Access-Control-Allow-Origin)\s*[=:]\s*['\"]?\*",
        "severity": "Medium",
        "description": "Wildcard CORS allows any origin to make cross-site requests to your API."
    },

    # ── Suspicious Developer Notes ─────────────────────────────────────────
    {
        "name": "Suspicious Keyword",
        "regex": r"\b(TODO|FIXME|DEBUG|TEMP|HACK|XXX)\b",
        "severity": "Low",
        "description": "Dev markers like TODO/FIXME/DEBUG often indicate unfinished security tasks."
    },
]


# =======================================================================
# 2. ENTRY POINT PATTERNS
# =======================================================================
# Where attacker-controlled data enters the application.

ENTRY_POINT_PATTERNS = [

    # Web framework inputs
    {
        "name": "API JSON Body",
        "regex": r"(request\.json|request\.get_json|req\.body|json\(\))",
        "type": "API Input",
        "severity": "High"
    },
    {
        "name": "Form Data",
        "regex": r"(request\.form|request\.values|\$_POST|req\.body)",
        "type": "Form Data",
        "severity": "High"
    },
    {
        "name": "Query Parameters",
        "regex": r"(request\.args|request\.params|\$_GET|\$_REQUEST|req\.query)",
        "type": "Query Parameter",
        "severity": "Medium"
    },
    {
        "name": "File Upload Handler",
        "regex": r"(request\.files|\$_FILES|upload_folder|\.save\s*\()",
        "type": "File Upload",
        "severity": "High"
    },
    {
        "name": "HTTP Headers",
        "regex": r"request\.(headers|cookies)",
        "type": "HTTP Header/Cookie",
        "severity": "Medium"
    },
    {
        "name": "Console Input",
        "regex": r"(\binput\s*\(|sys\.argv|Scanner\s*\(\s*System\.in\s*\))",
        "type": "User Input",
        "severity": "Low"
    },

    # Route / endpoint definitions (used for attack surface mapping)
    {
        "name": "Flask/FastAPI Route",
        "regex": r"@(app|router|blueprint|api)\.(route|get|post|put|delete|patch)\s*\(",
        "type": "Route Handler",
        "severity": "Info"
    },
    {
        "name": "Express.js Route",
        "regex": r"(app|router)\.(get|post|put|delete|all)\s*\(",
        "type": "Route Handler",
        "severity": "Info"
    },
    {
        "name": "PHP Superglobal Input",
        "regex": r"\$_(GET|POST|REQUEST|FILES|COOKIE|SERVER)\[",
        "type": "PHP Input",
        "severity": "High"
    },
]


# =======================================================================
# 3. LANGUAGE MAP
# =======================================================================

LANGUAGE_MAP = {
    ".py":   "Python",
    ".js":   "JavaScript",
    ".php":  "PHP",
    ".java": "Java",
    ".txt":  "Text/Unknown",
}


# =======================================================================
# 4. VIBE CODING RISK INDICATORS
# =======================================================================
# Patterns that suggest "vibe coding" — rushing without security thinking.

VIBE_CODING_PATTERNS = [
    # No input validation
    {"name": "No Input Validation (direct use)",
     "regex": r"(eval|exec|os\.system)\s*\(\s*\w*(input|request|req|args|form|json|body)\w*",
     "weight": 15},
    # Hardcoded credentials
    {"name": "Hardcoded Credential",
     "regex": r"(password|secret|api_key|token)\s*=\s*['\"][^'\"]{3,}['\"]",
     "weight": 10},
    # Bare except (swallowing errors silently)
    {"name": "Bare Except Clause",
     "regex": r"except\s*:",
     "weight": 5},
    # Shell=True
    {"name": "Shell=True in Subprocess",
     "regex": r"shell\s*=\s*True",
     "weight": 12},
    # Debug left in code
    {"name": "Debug Code in Production",
     "regex": r"(print\s*\(.*password|debug\s*=\s*True|console\.log.*token)",
     "weight": 7},
    # SQL concatenation (must be inside a string literal to avoid NoSQL false positives)
    {"name": "SQL Concatenation",
     "regex": r"['\"].*(SELECT|INSERT|UPDATE|DELETE).*['\"]\s*\+|\+\s*['\"].*(SELECT|INSERT|UPDATE|DELETE)",
     "weight": 15},
    # Disable SSL
    {"name": "SSL Disabled",
     "regex": r"verify\s*=\s*False",
     "weight": 10},
    # Wildcard CORS
    {"name": "Wildcard CORS",
     "regex": r"Access-Control-Allow-Origin.*\*",
     "weight": 8},
    # Using MD5 for passwords
    {"name": "MD5 for Passwords",
     "regex": r"md5\s*\(.*password",
     "weight": 12},
    # TODO auth bypass
    {"name": "Auth Bypass Comment",
     "regex": r"(#|//|/\*).*?(bypass|skip|remove).*?(auth|login|check)",
     "weight": 8},
]
