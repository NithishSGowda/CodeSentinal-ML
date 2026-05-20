import re
from .patterns import ENTRY_POINT_PATTERNS

def scan_entry_points(lines):
    """
    Scan source code line-by-line to find attacker entry points,
    route definitions, and file upload handlers.
    """
    entry_findings = []
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
            
        for pattern in ENTRY_POINT_PATTERNS:
            if re.search(pattern["regex"], line, re.IGNORECASE):
                entry_findings.append({
                    "type": pattern["type"],
                    "name": pattern["name"],
                    "severity": pattern["severity"],
                    "line": line_num,
                    "matched_code": line[:100]  # Truncate to avoid huge strings
                })
                
    return entry_findings

def generate_attack_surface_summary(entry_findings):
    """
    Summarize the findings into an attack surface overview.
    """
    summary = {
        "total_entry_points": 0,
        "total_endpoints": 0,
        "risky_uploads": 0,
        "high_severity_inputs": 0
    }
    
    if not entry_findings:
        return summary
        
    for finding in entry_findings:
        if finding["type"] == "Route Handler":
            summary["total_endpoints"] += 1
        else:
            summary["total_entry_points"] += 1
            
        if finding["type"] == "File Upload":
            summary["risky_uploads"] += 1
            
        if finding["severity"] == "High" and finding["type"] != "Route Handler":
            summary["high_severity_inputs"] += 1
            
    return summary
