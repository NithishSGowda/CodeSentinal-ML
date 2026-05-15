"""
This module performs static analysis on the source code.
It extracts metadata, calculates code statistics, and finds suspicious keywords.
"""

import os
from .patterns import SUSPICIOUS_KEYWORDS, LANGUAGE_MAP

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
        
        # Basic comment detection (handles Python, JS, Java, PHP partially)
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

def find_suspicious_keywords(content):
    """Count occurrences of suspicious keywords in the source code."""
    findings = {}
    content_lower = content.lower()
    
    for keyword in SUSPICIOUS_KEYWORDS:
        count = content_lower.count(keyword.lower())
        if count > 0:
            findings[keyword] = count
            
    return findings

def generate_security_summary(findings_count):
    """Generate a simple rule-based security summary."""
    if findings_count == 0:
        return "Low suspicious activity detected.", "success"
    elif findings_count <= 2:
        return "Potentially risky code indicators present.", "warning"
    else:
        return "Multiple dangerous keywords found. Review recommended.", "error"
