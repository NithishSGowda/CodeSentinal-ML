"""
scanner/attack_chain.py
-----------------------
Advanced Attack Chain Intelligence Engine (Day 5 Enhanced)

This module correlates attacker-controlled inputs (sources) with dangerous
execution functions (sinks) to identify potential attack chains.

An "attack chain" means:
  User-controlled input → (possibly through a variable) → dangerous function
  e.g.  request.args   →  eval()  =  Remote Code Execution risk

Day 5 Enhancements:
  - Multi-stage flow detection (source → intermediate variable → sink)
  - Intelligent alert messages per chain type
  - Stricter chain classification into RCE / Command Injection / SQL Injection /
    Unsafe File Upload / Unsafe Deserialization
  - alert_message field added to every chain
"""

import re

# -----------------------------------------------------------------------
# SOURCE PATTERNS — where attacker data can enter the program
# -----------------------------------------------------------------------
SOURCE_PATTERNS = [
    # Web framework inputs
    {"name": "request.args",  "regex": r"request\.args",        "category": "Web Input"},
    {"name": "request.form",  "regex": r"request\.form",        "category": "Web Input"},
    {"name": "request.json",  "regex": r"request\.json",        "category": "Web Input"},
    {"name": "request.files", "regex": r"request\.files",       "category": "Web Input"},
    {"name": "req.body",      "regex": r"req\.body",            "category": "Web Input"},
    {"name": "$_GET",         "regex": r"\$_GET",               "category": "PHP Input"},
    {"name": "$_POST",        "regex": r"\$_POST",              "category": "PHP Input"},
    {"name": "$_REQUEST",     "regex": r"\$_REQUEST",           "category": "PHP Input"},
    # CLI input
    {"name": "input()",       "regex": r"\binput\s*\(",         "category": "CLI Input"},
    {"name": "sys.argv",      "regex": r"sys\.argv",            "category": "CLI Input"},
    # Common user-controlled variable names (multi-stage detection)
    {"name": "user_input",    "regex": r"\buser_input\b",       "category": "Variable"},
    {"name": "user_data",     "regex": r"\buser_data\b",        "category": "Variable"},
    {"name": "data",          "regex": r"\bdata\s*=",           "category": "Variable"},
    {"name": "payload",       "regex": r"\bpayload\b",          "category": "Variable"},
    {"name": "cmd",           "regex": r"\bcmd\s*=",            "category": "Variable"},
    {"name": "query",         "regex": r"\bquery\s*=",          "category": "Variable"},
]

# -----------------------------------------------------------------------
# SINK PATTERNS — dangerous functions that can be exploited
# -----------------------------------------------------------------------
SINK_PATTERNS = [
    # Code execution → RCE
    {"name": "eval()",          "regex": r"\beval\s*\(",            "attack_type": "Remote Code Execution (RCE)"},
    {"name": "exec()",          "regex": r"\bexec\s*\(",            "attack_type": "Remote Code Execution (RCE)"},
    # Shell execution → Command Injection
    {"name": "os.system()",     "regex": r"os\.system\s*\(",        "attack_type": "Command Injection"},
    {"name": "subprocess",      "regex": r"subprocess\.(Popen|call|run|check_output)\s*\(", "attack_type": "Command Injection"},
    {"name": "os.popen()",      "regex": r"os\.popen\s*\(",         "attack_type": "Command Injection"},
    # Deserialization → RCE via pickle
    {"name": "pickle.loads()",  "regex": r"pickle\.loads\s*\(",     "attack_type": "Unsafe Deserialization"},
    {"name": "yaml.load()",     "regex": r"yaml\.load\s*\(",        "attack_type": "Unsafe Deserialization"},
    # SQL injection
    {"name": "SQL f-string",    "regex": r"f['\"].*(SELECT|INSERT|UPDATE|DELETE).*{", "attack_type": "SQL Injection"},
    {"name": "SQL concatenation","regex": r"(SELECT|INSERT|UPDATE|DELETE).*\+",        "attack_type": "SQL Injection"},
    # File operations
    {"name": "file open()",     "regex": r"\bopen\s*\(\s*(request|req|\$_)",           "attack_type": "Unsafe File Handling"},
    {"name": "file.save()",     "regex": r"\.save\s*\(",                                "attack_type": "Unsafe File Upload"},
    # Template injection
    {"name": "render_template_string()", "regex": r"render_template_string\s*\(",       "attack_type": "Server-Side Template Injection"},
]

# -----------------------------------------------------------------------
# ATTACK CHAIN DESCRIPTIONS (beginner-friendly)
# -----------------------------------------------------------------------
CHAIN_DESCRIPTIONS = {
    "Remote Code Execution (RCE)": (
        "Attacker-controlled input reaches a code-execution function. "
        "The attacker can run ANY command on your server."
    ),
    "Command Injection": (
        "User input is passed to a shell command. "
        "An attacker can append '; rm -rf /' or similar destructive commands."
    ),
    "SQL Injection": (
        "User input is inserted directly into an SQL query without sanitisation. "
        "An attacker can read, modify, or delete database records."
    ),
    "Unsafe Deserialization": (
        "Untrusted data is deserialized with pickle or yaml.load. "
        "Specially crafted payloads can execute arbitrary code on load."
    ),
    "Unsafe File Upload": (
        "User-supplied files are saved without validation. "
        "An attacker may upload a malicious script and execute it remotely."
    ),
    "Unsafe File Handling": (
        "User input controls which file is opened. "
        "An attacker can read sensitive files via path traversal."
    ),
    "Server-Side Template Injection": (
        "User input is passed into a server-side template renderer. "
        "An attacker can inject template directives to execute code or exfiltrate data."
    ),
}

# -----------------------------------------------------------------------
# INTELLIGENT ALERT MESSAGES per attack type
# These are the highlighted alert banners shown in the UI.
# -----------------------------------------------------------------------
ALERT_MESSAGES = {
    "Remote Code Execution (RCE)": (
        "⚡ CRITICAL ALERT: Potential Remote Code Execution chain detected! "
        "Attacker-controlled input flows directly into a code-execution sink."
    ),
    "Command Injection": (
        "🔥 HIGH ALERT: Potential Command Injection chain identified! "
        "User input reaches shell execution — arbitrary OS commands may be injected."
    ),
    "SQL Injection": (
        "💉 HIGH ALERT: Possible SQL Injection attack flow detected! "
        "User input is concatenated into raw SQL without parameterisation."
    ),
    "Unsafe Deserialization": (
        "☠ CRITICAL ALERT: Dangerous Deserialization risk detected! "
        "Untrusted data reaching pickle.loads() can execute arbitrary code on load."
    ),
    "Unsafe File Upload": (
        "📂 HIGH ALERT: Unsafe File Upload chain identified! "
        "Unvalidated user files are saved server-side — malicious scripts may be uploaded."
    ),
    "Unsafe File Handling": (
        "📂 MEDIUM ALERT: Path Traversal risk detected! "
        "User input controls which file is opened — sensitive files may be exposed."
    ),
    "Server-Side Template Injection": (
        "🧨 CRITICAL ALERT: Server-Side Template Injection (SSTI) chain detected! "
        "User input in a template renderer can leak data or execute code."
    ),
}

# -----------------------------------------------------------------------
# MAIN FUNCTION
# -----------------------------------------------------------------------

def detect_attack_chains(all_files_data):
    """
    Detect attack chains across the entire repository.

    Parameters
    ----------
    all_files_data : list of dict
        Each dict has keys 'file' (relative path) and 'lines' (list of str).

    Returns
    -------
    chains : list of dict
        Each chain has: source, sink, file, line, matched_code, attack_type,
        description, alert_message, severity_label.
    """
    chains = []

    for file_data in all_files_data:
        rel_path = file_data["file"]
        lines    = file_data["lines"]

        # --- Pass 1: Build per-line source and sink maps ---
        line_sources = {}  # line_number → list of source name strings
        line_sinks   = {}  # line_number → list of sink dicts

        for line_num, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            for src in SOURCE_PATTERNS:
                if re.search(src["regex"], line, re.IGNORECASE):
                    line_sources.setdefault(line_num, []).append(src["name"])

            for snk in SINK_PATTERNS:
                if re.search(snk["regex"], line, re.IGNORECASE):
                    line_sinks.setdefault(line_num, []).append(snk)

        # --- Strategy 1: Source and Sink on the SAME line ---
        for line_num in line_sources:
            if line_num in line_sinks:
                for src_name in line_sources[line_num]:
                    for snk in line_sinks[line_num]:
                        chains.append(_build_chain(
                            rel_path, line_num,
                            lines[line_num - 1].strip(),
                            src_name, snk
                        ))

        # --- Strategy 2: Source within 15 lines BEFORE a sink (same scope) ---
        # Window extended from 10 → 15 to catch more multi-stage flows
        source_line_nums = sorted(line_sources.keys())
        for snk_line in line_sinks:
            for src_line in source_line_nums:
                if 0 < (snk_line - src_line) <= 15:
                    for src_name in line_sources[src_line]:
                        for snk in line_sinks[snk_line]:
                            if src_line != snk_line:   # avoid duplicates from Strategy 1
                                chains.append(_build_chain(
                                    rel_path, snk_line,
                                    lines[snk_line - 1].strip(),
                                    src_name, snk,
                                    src_line=src_line
                                ))

    # --- De-duplicate by (file, line, source, sink) ---
    seen = set()
    unique_chains = []
    for c in chains:
        key = (c["file"], c["line"], c["source"], c["sink"])
        if key not in seen:
            seen.add(key)
            unique_chains.append(c)

    # Sort: most dangerous first
    severity_order = {
        "Remote Code Execution (RCE)": 0,
        "Server-Side Template Injection": 1,
        "Unsafe Deserialization": 2,
        "Command Injection": 3,
        "SQL Injection": 4,
        "Unsafe File Upload": 5,
        "Unsafe File Handling": 6,
    }
    unique_chains.sort(key=lambda c: severity_order.get(c["attack_type"], 99))

    return unique_chains


def _build_chain(file, sink_line, matched_code, src_name, snk, src_line=None):
    """
    Helper to assemble a chain dictionary with all required fields.

    Now includes:
        alert_message   : highlighted banner message for the UI
        severity_label  : "Critical" / "High" / "Medium"
    """
    attack_type   = snk["attack_type"]
    description   = CHAIN_DESCRIPTIONS.get(attack_type, "User-controlled input reaches a dangerous function.")
    alert_message = ALERT_MESSAGES.get(attack_type, "⚠ Attack chain detected between an input source and dangerous sink.")

    # Assign a severity label to the chain itself
    if attack_type in ("Remote Code Execution (RCE)", "Unsafe Deserialization", "Server-Side Template Injection"):
        severity_label = "Critical"
    elif attack_type in ("Command Injection", "SQL Injection", "Unsafe File Upload"):
        severity_label = "High"
    else:
        severity_label = "Medium"

    chain = {
        "file":           file,
        "line":           sink_line,
        "matched_code":   matched_code[:120],
        "source":         src_name,
        "sink":           snk["name"],
        "attack_type":    attack_type,
        "description":    description,
        "alert_message":  alert_message,
        "severity_label": severity_label,
    }

    # Optional: include source line if it's a multi-line chain
    if src_line and src_line != sink_line:
        chain["source_line"] = src_line

    return chain


# -----------------------------------------------------------------------
# HELPER: summarise chains by attack type (used in dashboard analytics)
# -----------------------------------------------------------------------

def summarise_chains(attack_chains):
    """
    Return a dict of attack_type → count for all chains.
    Useful for bar charts and pie charts.
    """
    summary = {}
    for chain in attack_chains:
        atype = chain.get("attack_type", "Unknown")
        summary[atype] = summary.get(atype, 0) + 1
    return summary
