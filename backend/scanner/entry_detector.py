"""
scanner/entry_detector.py
--------------------------
Attacker Entry-Point Detection Engine

Scans source code for locations where attacker-controlled data
can enter the application:
  - HTTP request parameters
  - Form / JSON body inputs
  - File upload handlers
  - CLI inputs
  - PHP superglobals

Also summarises the total attack surface exposed.
"""

import re
from .patterns import ENTRY_POINT_PATTERNS


def scan_entry_points(lines):
    """
    Scan source code line-by-line for attacker entry points.

    Parameters
    ----------
    lines : list of str
        Lines of source code from readlines().

    Returns
    -------
    list of dicts, each with:
        type, name, severity, line, matched_code
    """
    entry_findings = []

    for line_num, raw_line in enumerate(lines, 1):
        line = raw_line.strip()

        # Skip blank lines and comments
        if not line or line.startswith(("#", "//", "/*")):
            continue

        for pattern in ENTRY_POINT_PATTERNS:
            if re.search(pattern["regex"], line, re.IGNORECASE):
                entry_findings.append({
                    "type":         pattern["type"],
                    "name":         pattern["name"],
                    "severity":     pattern["severity"],
                    "line":         line_num,
                    "matched_code": line[:120],
                })
                break   # one entry-point finding per line

    return entry_findings


def generate_attack_surface_summary(entry_findings):
    """
    Summarise all entry-point findings into an attack surface overview.

    Returns
    -------
    dict with:
        total_entry_points   : int  (inputs, excluding route definitions)
        total_endpoints      : int  (route/handler definitions)
        risky_uploads        : int  (file upload handlers)
        high_severity_inputs : int  (High-severity input sources)
        exposed_apis         : int  (API-type inputs)
        php_inputs           : int  (PHP superglobal usage)
    """
    summary = {
        "total_entry_points":   0,
        "total_endpoints":      0,
        "risky_uploads":        0,
        "high_severity_inputs": 0,
        "exposed_apis":         0,
        "php_inputs":           0,
    }

    if not entry_findings:
        return summary

    for f in entry_findings:
        if f["type"] == "Route Handler":
            summary["total_endpoints"] += 1
        else:
            summary["total_entry_points"] += 1

        if f["type"] == "File Upload":
            summary["risky_uploads"] += 1

        if f["severity"] == "High" and f["type"] != "Route Handler":
            summary["high_severity_inputs"] += 1

        if f["type"] == "API Input":
            summary["exposed_apis"] += 1

        if f["type"] == "PHP Input":
            summary["php_inputs"] += 1

    return summary
