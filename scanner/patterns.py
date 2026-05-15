"""
This module contains patterns and keywords used for static analysis.
"""

# List of suspicious keywords to monitor for potential security risks
SUSPICIOUS_KEYWORDS = [
    "eval",
    "exec",
    "os.system",
    "subprocess",
    "pickle.loads",
    "password",
    "token",
    "api_key",
    "secret"
]

# Mapping of file extensions to programming languages
LANGUAGE_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".php": "PHP",
    ".java": "Java",
    ".txt": "Text/Unknown"
}
