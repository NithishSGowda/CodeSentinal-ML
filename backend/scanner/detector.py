"""
scanner/detector.py
--------------------
Core Static Analysis Engine

Responsibilities:
  - Extract file metadata
  - Compute code statistics
  - Run vulnerability pattern matching (line-by-line)
  - Generate security score and vibe coding risk index
  - Compute security maturity level
"""

import os
import re
from .patterns import (
    VULNERABILITY_PATTERNS,
    VIBE_CODING_PATTERNS,
    LANGUAGE_MAP
)


# =======================================================================
# FILE UTILITIES
# =======================================================================

def get_language(filename):
    """Return the programming language name for a given filename."""
    _, ext = os.path.splitext(filename)
    return LANGUAGE_MAP.get(ext.lower(), "Unknown")


def extract_metadata(filepath, original_filename):
    """
    Extract basic file metadata.

    Returns a dict with: filename, extension, size_kb, language.
    """
    try:
        size_kb = os.path.getsize(filepath) / 1024
    except Exception:
        size_kb = 0.0

    _, ext = os.path.splitext(original_filename)
    return {
        "filename": original_filename,
        "extension": ext.lower(),
        "size_kb": round(size_kb, 2),
        "language": get_language(original_filename),
    }


# =======================================================================
# CODE STATISTICS
# =======================================================================

def analyze_code_statistics(lines):
    """
    Compute basic static metrics from a list of source-code lines.

    Returns a dict with: total_lines, blank_lines, comments, imports,
    functions, classes, total_characters.
    """
    stats = {
        "total_lines":      len(lines),
        "blank_lines":      0,
        "comments":         0,
        "imports":          0,
        "functions":        0,
        "classes":          0,
        "total_characters": sum(len(l) for l in lines),
    }

    for line in lines:
        stripped = line.strip()
        if not stripped:
            stats["blank_lines"] += 1
            continue

        # Comments
        if stripped.startswith(("#", "//", "/*", "*", "<!--")):
            stats["comments"] += 1

        # Imports
        if re.match(r"^(import |from |include |require |#include)", stripped):
            stats["imports"] += 1

        # Function definitions
        if re.match(r"^(def |function |public |private |protected |async function )", stripped):
            stats["functions"] += 1

        # Class definitions
        if re.match(r"^class ", stripped):
            stats["classes"] += 1

    return stats


# =======================================================================
# VULNERABILITY SCANNING
# =======================================================================

def scan_vulnerabilities(lines):
    """
    Scan source code lines for vulnerability patterns.

    Parameters
    ----------
    lines : list of str
        Lines of source code (from readlines()).

    Returns
    -------
    list of dicts, each with:
        issue, severity, line, matched_code, description
    """
    findings = []

    for line_num, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        # Skip blank lines and full-line comments
        if not line or line.startswith(("#", "//", "/*")):
            continue

        for pattern in VULNERABILITY_PATTERNS:
            if re.search(pattern["regex"], line, re.IGNORECASE):
                findings.append({
                    "issue":        pattern["name"],
                    "severity":     pattern["severity"],
                    "line":         line_num,
                    "matched_code": line[:120],      # truncate very long lines
                    "description":  pattern["description"],
                })
                break   # one finding per line per scan pass (avoids duplicates)

    return findings


# =======================================================================
# SECURITY SCORE
# =======================================================================

def generate_security_summary(findings):
    """
    Calculate a rule-based security score (0–100) and return a summary message.

    Scoring:
        Each High vulnerability  → -25 pts
        Each Medium vulnerability → -10 pts
        Each Low vulnerability   →  -2 pts

    Returns
    -------
    (message: str, alert_type: str, score: int)
    """
    if not findings:
        return "No significant vulnerabilities detected. Code appears clean.", "success", 100

    high   = sum(1 for f in findings if f["severity"] == "High")
    medium = sum(1 for f in findings if f["severity"] == "Medium")
    low    = sum(1 for f in findings if f["severity"] == "Low")

    score = 100 - (high * 25 + medium * 10 + low * 2)
    score = max(0, score)

    if high > 0:
        return (
            f"CRITICAL: {high} high-severity vulnerabilities detected. Immediate action required.",
            "error",
            score
        )
    elif medium > 0:
        return (
            f"WARNING: {medium} medium-severity issues found. Potential security risks present.",
            "warning",
            score
        )
    else:
        return (
            f"NOTICE: {len(findings)} low-severity findings. Code quality improvements suggested.",
            "info",
            score
        )


def compute_per_file_score(findings_for_file):
    """
    Compute a security score (0–100) for a single file's findings list.
    """
    if not findings_for_file:
        return 100
    high   = sum(1 for f in findings_for_file if f["severity"] == "High")
    medium = sum(1 for f in findings_for_file if f["severity"] == "Medium")
    low    = sum(1 for f in findings_for_file if f["severity"] == "Low")
    score  = 100 - (high * 25 + medium * 10 + low * 2)
    return max(0, score)


# =======================================================================
# VIBE CODING RISK INDEX
# =======================================================================

def compute_vibe_risk(all_findings, all_entry_points, attack_chains, code_content=""):
    """
    Compute the Vibe Coding Risk Index — a custom score (0–100) that reflects
    how many insecure 'vibe coding' shortcuts appear in the project.

    Scoring factors:
        - High severity vulnerabilities
        - Hardcoded secrets
        - Attack chains (source → sink)
        - Insecure shortcuts (shell=True, bare except, MD5, etc.)
        - Attack surface size (number of exposed entry points)

    Returns
    -------
    dict with: score (int), category (str), breakdown (dict)
    """
    score = 0
    breakdown = {}

    # Factor 1: High-severity vulnerabilities (capped at 35 pts)
    high_count = sum(1 for f in all_findings if f["severity"] == "High")
    pts_high   = min(high_count * 7, 35)
    score     += pts_high
    breakdown["High Severity Issues"] = pts_high

    # Factor 2: Hardcoded secrets (capped at 20 pts)
    secret_keywords = {"Hardcoded Password", "Hardcoded API Key",
                       "Hardcoded Token", "Hardcoded Secret"}
    secret_count = sum(1 for f in all_findings if f["issue"] in secret_keywords)
    pts_secrets  = min(secret_count * 8, 20)
    score       += pts_secrets
    breakdown["Hardcoded Secrets"] = pts_secrets

    # Factor 3: Detected attack chains (capped at 25 pts)
    pts_chains = min(len(attack_chains) * 10, 25)
    score     += pts_chains
    breakdown["Attack Chains"] = pts_chains

    # Factor 4: Vibe coding pattern matches in code (capped at 15 pts)
    vibe_pts = 0
    if code_content:
        for vp in VIBE_CODING_PATTERNS:
            if re.search(vp["regex"], code_content, re.IGNORECASE):
                vibe_pts += vp["weight"]
    pts_vibe = min(vibe_pts, 15)
    score   += pts_vibe
    breakdown["Insecure Shortcuts"] = pts_vibe

    # Factor 5: Large attack surface (many entry points) — capped at 5 pts
    high_entry = sum(1 for e in all_entry_points if e.get("severity") == "High")
    pts_surface = min(high_entry * 1, 5)
    score      += pts_surface
    breakdown["Exposed Attack Surface"] = pts_surface

    # Clamp to 0–100
    score = min(max(score, 0), 100)

    # Category
    if score <= 30:
        category = "Low Risk"
    elif score <= 70:
        category = "Medium Risk"
    else:
        category = "High Risk"

    return {
        "score":     score,
        "category":  category,
        "breakdown": breakdown,
    }


# =======================================================================
# SECURITY MATURITY SCORE
# =======================================================================

def compute_security_maturity(findings, stats, all_entry_points):
    """
    Assess the security maturity of the codebase.

    Levels:
        Advanced     — very few or no high/medium issues, good practices present
        Intermediate — some issues but not critical
        Beginner     — many high/medium vulnerabilities, no validation evident

    Returns
    -------
    dict with: level (str), score (int 0–100), indicators (list of str)
    """
    indicators = []
    maturity_score = 100   # start optimistic and subtract

    high   = sum(1 for f in findings if f["severity"] == "High")
    medium = sum(1 for f in findings if f["severity"] == "Medium")
    low    = sum(1 for f in findings if f["severity"] == "Low")

    # Negative indicators
    if high > 0:
        maturity_score -= high * 15
        indicators.append(f"⚠ {high} high-severity vulnerabilities detected")
    if medium > 0:
        maturity_score -= medium * 7
        indicators.append(f"⚠ {medium} medium-severity issues found")

    # Check for hardcoded secrets specifically
    secrets = sum(1 for f in findings
                  if "Hardcoded" in f["issue"])
    if secrets > 0:
        maturity_score -= secrets * 10
        indicators.append(f"⚠ {secrets} hardcoded secrets — not using env vars")

    # Check if any SQL or NoSQL injection patterns present
    sql_issues = sum(1 for f in findings if "SQL" in f["issue"] or "NoSQL" in f["issue"])
    if sql_issues > 0:
        maturity_score -= sql_issues * 8
        indicators.append("⚠ Raw query construction detected — use parameterised queries or safe ORM methods")

    # Large exposed attack surface
    high_entries = sum(1 for e in all_entry_points if e.get("severity") == "High")
    if high_entries > 5:
        maturity_score -= 10
        indicators.append(f"⚠ {high_entries} high-severity entry points — large attack surface")

    # Positive indicators (look for good practices in code stats)
    if stats.get("comments", 0) > 10:
        indicators.append("✓ Code contains documentation comments")
    if stats.get("functions", 0) > 3:
        indicators.append("✓ Code is organised into functions")
    if high == 0 and medium == 0:
        indicators.append("✓ No high or medium severity vulnerabilities found")
        maturity_score = min(maturity_score + 10, 100)

    maturity_score = max(0, maturity_score)

    if maturity_score >= 75:
        level = "Advanced"
    elif maturity_score >= 45:
        level = "Intermediate"
    else:
        level = "Beginner"

    return {
        "level":      level,
        "score":      maturity_score,
        "indicators": indicators,
    }
