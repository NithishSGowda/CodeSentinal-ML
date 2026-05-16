import os
import re
from .patterns import VULNERABILITY_PATTERNS, LANGUAGE_MAP

def get_language(filename):
    """Detect the programming language based on the file extension."""
    _, ext = os.path.splitext(filename)
    return LANGUAGE_MAP.get(ext.lower(), "Unknown")

def extract_metadata(filepath, original_filename):
    """Extract metadata from the uploaded file."""
    try:
        size_kb = os.path.getsize(filepath) / 1024
    except Exception:
        size_kb = 0.0

    _, ext = os.path.splitext(original_filename)
    
    return {
        "filename": original_filename,
        "extension": ext.lower(),
        "size_kb": round(size_kb, 2),
        "language": get_language(original_filename)
    }

def analyze_code_statistics(lines):
    """Calculate basic static code statistics."""
    stats = {
        "total_lines": len(lines),
        "blank_lines": 0,
        "comments": 0,
        "imports": 0,
        "functions": 0,
        "classes": 0,
        "total_characters": sum(len(line) for line in lines)
    }

    for line in lines:
        stripped = line.strip()
        if not stripped:
            stats["blank_lines"] += 1
            continue
        
        # Basic comment detection
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            stats["comments"] += 1
            
        # Basic import detection
        if stripped.startswith("import ") or stripped.startswith("from ") or stripped.startswith("include") or stripped.startswith("require"):
            stats["imports"] += 1
            
        # Basic function/method definition detection
        if stripped.startswith("def ") or "function " in stripped or stripped.startswith("public void ") or stripped.startswith("private void "):
            stats["functions"] += 1
            
        # Basic class definition detection
        if stripped.startswith("class "):
            stats["classes"] += 1

    return stats

def scan_vulnerabilities(lines):
    """
    Scan code line-by-line using regex patterns.
    Returns a list of structured findings.
    """
    findings = []
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"): # Skip empty lines and full comments
            continue
            
        for pattern in VULNERABILITY_PATTERNS:
            # Case insensitive search
            if re.search(pattern["regex"], line, re.IGNORECASE):
                findings.append({
                    "issue": pattern["name"],
                    "severity": pattern["severity"],
                    "line": line_num,
                    "matched_code": line[:100], # Truncate long lines
                    "description": pattern["description"]
                })
                
    return findings

def generate_security_summary(findings):
    """Generate a rule-based security summary and calculate security score."""
    if not findings:
        return "No significant vulnerabilities detected. Code appears clean.", "success", 100
    
    severity_counts = {
        "High": len([f for f in findings if f["severity"] == "High"]),
        "Medium": len([f for f in findings if f["severity"] == "Medium"]),
        "Low": len([f for f in findings if f["severity"] == "Low"])
    }
    
    # Calculate simple security score (0-100)
    score = 100 - (severity_counts["High"] * 25 + severity_counts["Medium"] * 10 + severity_counts["Low"] * 2)
    score = max(0, score)
    
    if severity_counts["High"] > 0:
        return f"CRITICAL: {severity_counts['High']} high-severity vulnerabilities detected. Immediate action required.", "error", score
    elif severity_counts["Medium"] > 0:
        return f"WARNING: {severity_counts['Medium']} medium-severity issues found. Potential security risks identified.", "warning", score
    else:
        return f"NOTICE: {len(findings)} low-severity findings. General code quality improvements suggested.", "info", score
