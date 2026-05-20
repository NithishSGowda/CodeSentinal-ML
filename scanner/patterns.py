"""
This module contains patterns and regex rules used for static analysis.
"""

# Dictionary of vulnerability patterns for detection
# Each pattern includes: name, regex, severity, and description
VULNERABILITY_PATTERNS = [
    # 1. Dangerous Code Execution Functions (High Severity)
    {
        "name": "Dangerous Execution (eval)",
        "regex": r"eval\(",
        "severity": "High",
        "description": "The eval() function can execute arbitrary code strings, leading to Remote Code Execution (RCE) vulnerabilities."
    },
    {
        "name": "Dangerous Execution (exec)",
        "regex": r"exec\(",
        "severity": "High",
        "description": "The exec() function executes dynamically created Python code, which is highly risky if input is untrusted."
    },
    {
        "name": "System Command Execution (os.system)",
        "regex": r"os\.system\(",
        "severity": "High",
        "description": "Using os.system() to run shell commands is prone to command injection vulnerabilities."
    },
    {
        "name": "Subprocess Execution",
        "regex": r"subprocess\.(Popen|call|run|check_output|getoutput)\(",
        "severity": "High",
        "description": "Spawning subprocesses with shell=True or untrusted input can lead to system-level exploits."
    },
    {
        "name": "Insecure Deserialization (pickle)",
        "regex": r"pickle\.loads\(",
        "severity": "High",
        "description": "Deserializing untrusted data with pickle.loads() can execute arbitrary code during the process."
    },

    # 2. Hardcoded Secrets (Medium Severity)
    {
        "name": "Hardcoded Password",
        "regex": r"(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]",
        "severity": "Medium",
        "description": "Storing passwords in plain text within source code is a significant security risk."
    },
    {
        "name": "Hardcoded API Key",
        "regex": r"(api_key|apikey|api-key)\s*=\s*['\"][^'\"]+['\"]",
        "severity": "Medium",
        "description": "Hardcoded API keys can be easily extracted and used by unauthorized parties."
    },
    {
        "name": "Hardcoded Token",
        "regex": r"(token|auth_token|access_token)\s*=\s*['\"][^'\"]+['\"]",
        "severity": "Medium",
        "description": "Authentication tokens should never be stored directly in the source code."
    },
    {
        "name": "Hardcoded Secret",
        "regex": r"(secret|secret_key|private_key)\s*=\s*['\"][^'\"]+['\"]",
        "severity": "Medium",
        "description": "Hardcoded secrets expose sensitive credentials to anyone with access to the code."
    },

    # 3. Unsafe SQL Construction (Medium/High Severity)
    {
        "name": "SQL Injection (Concatenation)",
        "regex": r"(SELECT|INSERT|UPDATE|DELETE).*\+.*",
        "severity": "High",
        "description": "Building SQL queries using string concatenation is a primary cause of SQL Injection."
    },
    {
        "name": "SQL Injection (f-string)",
        "regex": r"f['\"].*(SELECT|INSERT|UPDATE|DELETE).*{.*}",
        "severity": "High",
        "description": "Using f-strings to insert variables directly into SQL queries is unsafe."
    },
    {
        "name": "SQL Injection (.format)",
        "regex": r"['\"].*(SELECT|INSERT|UPDATE|DELETE).*['\"].*\.format\(",
        "severity": "High",
        "description": "Using .format() to build SQL queries is vulnerable to injection attacks."
    },

    # 4. Suspicious Keywords (Low Severity)
    {
        "name": "Suspicious Keyword",
        "regex": r"(TODO|FIXME|DEBUG|TEMP)",
        "severity": "Low",
        "description": "Developer comments like TODO or DEBUG may indicate unfinished security tasks or exposed debug paths."
    }
]

# Mapping of file extensions to programming languages
LANGUAGE_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".php": "PHP",
    ".java": "Java",
    ".txt": "Text/Unknown"
}

# ---------------------------------------------------------
# DAY 3: ATTACKER ENTRY POINT & ATTACK SURFACE PATTERNS
# ---------------------------------------------------------

ENTRY_POINT_PATTERNS = [
    # 1. API & Web Inputs (High Severity - Direct Control)
    {
        "name": "API JSON Body",
        "regex": r"(request\.json|req\.body|json\(\))",
        "type": "API Input",
        "severity": "High"
    },
    {
        "name": "Form Data",
        "regex": r"(request\.form|\$_POST|req\.body)",
        "type": "Form Data",
        "severity": "High"
    },
    {
        "name": "Query Parameters",
        "regex": r"(request\.args|\$_GET|\$_REQUEST|req\.query)",
        "type": "Query Parameter",
        "severity": "Medium"
    },
    
    # 2. File Uploads (High Severity - Remote Execution Risk)
    {
        "name": "File Upload Handler",
        "regex": r"(request\.files|\$_FILES|upload_folder|save\(.*file\))",
        "type": "File Upload",
        "severity": "High"
    },

    # 3. Console/CLI Inputs (Low Severity - Local Control)
    {
        "name": "Console Input",
        "regex": r"(input\(|sys\.argv|Scanner\(System\.in\))",
        "type": "User Input",
        "severity": "Low"
    },

    # 4. Route/Endpoint Definitions (Used for surface mapping)
    {
        "name": "Flask/FastAPI Route",
        "regex": r"@(app|router|blueprint)\.(route|get|post|put|delete|patch)\(",
        "type": "Route Handler",
        "severity": "Info"
    },
    {
        "name": "Express.js Route",
        "regex": r"(app|router)\.(get|post|put|delete|all)\(",
        "type": "Route Handler",
        "severity": "Info"
    }
]
