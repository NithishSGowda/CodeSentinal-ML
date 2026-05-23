"""
scanner/intelligence.py
------------------------
Repository Security Intelligence Engine (Day 5)

This module generates rule-based, human-readable intelligence reports about
the entire scanned repository. It uses templates, conditions, and counting
logic — NOT generative AI or LLMs.

Functions in this module:
  - compute_security_grade()       → A / B / C / D / F grade
  - compute_repository_fingerprint() → headline stats dict
  - generate_intelligence_summary() → paragraph-form narrative
  - rank_files_by_risk()            → sorted list of file risk scores
  - generate_terminal_logs()        → list of SOC-style log messages

All output is deterministic given the same inputs.
"""

import re


# -----------------------------------------------------------------------
# SECTION 1: SECURITY GRADE
# -----------------------------------------------------------------------

def compute_security_grade(
    ml_adjusted_score,      # int 0-100: score from generate_security_summary + ML adjustment
    attack_chains,          # list of detected attack chains
    prioritized_findings,   # list of findings with "priority" key added by prioritizer.py
    vibe_risk_score,        # int 0-100: vibe coding risk index
):
    """
    Compute a letter grade (A/B/C/D/F) for the repository.

    Grading Logic:
        Start with the ml_adjusted_score, then apply penalties:
          - Each Critical finding  → -8 pts
          - Each High finding      → -3 pts
          - Each attack chain      → -5 pts
          - Vibe risk > 60         → -10 pts
          - Vibe risk > 80         → additional -5 pts

        Final Grade Thresholds:
          A  ≥ 90   Excellent security posture
          B  ≥ 75   Good — minor issues only
          C  ≥ 55   Average — needs attention
          D  ≥ 35   Poor — significant risk
          F  < 35   Failing — critical vulnerabilities

    Returns
    -------
    dict with:
        grade       : str — "A" / "B" / "C" / "D" / "F"
        grade_score : int — 0–100 composite
        label       : str — human readable label
        color       : str — hex color for display
        explanation : str — one-line explanation
    """
    # Start with the health score
    grade_score = ml_adjusted_score

    # Penalty per critical finding
    critical_count = sum(1 for f in prioritized_findings if f.get("priority") == "Critical")
    grade_score -= critical_count * 8

    # Penalty per high finding
    high_count = sum(1 for f in prioritized_findings if f.get("priority") == "High")
    grade_score -= high_count * 3

    # Penalty per attack chain
    grade_score -= len(attack_chains) * 5

    # Vibe risk penalty
    if vibe_risk_score > 80:
        grade_score -= 15
    elif vibe_risk_score > 60:
        grade_score -= 10

    # Clamp to 0–100
    grade_score = max(0, min(100, grade_score))

    # Assign letter grade
    if grade_score >= 90:
        return {
            "grade": "A",
            "grade_score": grade_score,
            "label": "Excellent",
            "color": "#10B981",    # emerald green
            "explanation": "Repository demonstrates strong security practices with minimal risk exposure."
        }
    elif grade_score >= 75:
        return {
            "grade": "B",
            "grade_score": grade_score,
            "label": "Good",
            "color": "#34D399",    # light green
            "explanation": "Repository is generally secure with a few minor issues to address."
        }
    elif grade_score >= 55:
        return {
            "grade": "C",
            "grade_score": grade_score,
            "label": "Average",
            "color": "#FBBF24",    # amber
            "explanation": "Repository has moderate vulnerabilities that require scheduled remediation."
        }
    elif grade_score >= 35:
        return {
            "grade": "D",
            "grade_score": grade_score,
            "label": "Poor",
            "color": "#F87171",    # red
            "explanation": "Repository has significant security issues. Prioritize critical findings immediately."
        }
    else:
        return {
            "grade": "F",
            "grade_score": grade_score,
            "label": "Failing",
            "color": "#EF4444",    # bright red
            "explanation": "Repository is critically vulnerable. Multiple exploit paths detected. Halt deployment."
        }


# -----------------------------------------------------------------------
# SECTION 2: REPOSITORY SECURITY FINGERPRINT
# -----------------------------------------------------------------------

def compute_repository_fingerprint(
    stats,                  # dict from scan_project() project_stats
    all_findings,           # list of raw findings
    all_entry_points,       # list of entry point dicts
    attack_chains,          # list of attack chain dicts
    file_risks,             # list of ML prediction dicts per file
    grade_info,             # dict from compute_security_grade()
    ml_adjusted_score,      # int
):
    """
    Build a repository-wide security fingerprint with headline metrics.

    Returns
    -------
    dict with many named integer / string fields describing the repo security posture.
    """
    # Count secrets specifically
    secret_issues = {"Hardcoded Password", "Hardcoded API Key", "Hardcoded Token", "Hardcoded Secret"}
    secret_count  = sum(1 for f in all_findings if f.get("issue") in secret_issues)

    # Count dangerous functions specifically
    dangerous_issues = {
        "Dangerous Execution (eval)", "Dangerous Execution (exec)",
        "System Command Execution (os.system)", "Subprocess Execution",
        "Insecure Deserialization (pickle)", "Insecure Deserialization (yaml)",
        "Insecure Template Rendering"
    }
    dangerous_count = sum(1 for f in all_findings if f.get("issue") in dangerous_issues)

    # Count high-severity entry points (real exposed inputs)
    exposed_inputs = sum(1 for ep in all_entry_points if ep.get("severity") in ("High", "Medium"))

    # ML stats
    high_risk_files = sum(1 for fr in file_risks if fr.get("ml_prediction") == "High Risk")
    medium_risk_files = sum(1 for fr in file_risks if fr.get("ml_prediction") == "Medium Risk")

    return {
        "total_files":        stats.get("total_files", 0),
        "total_lines":        stats.get("total_lines", 0),
        "total_vulnerabilities": len(all_findings),
        "critical_count":     sum(1 for f in all_findings if f.get("severity") == "High"),
        "total_endpoints":    exposed_inputs,
        "dangerous_functions": dangerous_count,
        "attack_chains":      len(attack_chains),
        "secret_exposures":   secret_count,
        "high_risk_files":    high_risk_files,
        "medium_risk_files":  medium_risk_files,
        "risk_score":         100 - ml_adjusted_score,
        "security_grade":     grade_info["grade"],
        "grade_label":        grade_info["label"],
        "grade_color":        grade_info["color"],
        "health_score":       ml_adjusted_score,
    }


# -----------------------------------------------------------------------
# SECTION 3: INTELLIGENCE NARRATIVE GENERATOR
# -----------------------------------------------------------------------

# Template sentences keyed by condition name.
# Each template is a string that may have placeholders filled with .format()
NARRATIVE_TEMPLATES = {
    "has_rce_chains": (
        "🔴 CRITICAL: {count} Remote Code Execution attack chain(s) detected. "
        "Attacker-controlled input reaches dangerous code-execution functions (eval/exec). "
        "This represents an immediate exploitation risk."
    ),
    "has_cmd_injection": (
        "🟠 HIGH RISK: {count} Command Injection flow(s) identified. "
        "User input reaches shell execution functions (os.system / subprocess). "
        "An attacker can append shell metacharacters to run arbitrary OS commands."
    ),
    "has_sql_injection": (
        "🟠 HIGH RISK: {count} SQL Injection attack path(s) detected. "
        "Attacker-controlled input is inserted into raw SQL queries without sanitisation. "
        "An attacker may dump, modify, or destroy database records."
    ),
    "has_deserialization": (
        "🟠 HIGH RISK: Unsafe deserialization detected. "
        "Untrusted data is passed to pickle.loads() or yaml.load(). "
        "Specially crafted payloads can execute arbitrary code on load."
    ),
    "has_file_upload": (
        "🟡 MEDIUM RISK: Unsafe file upload pattern(s) found. "
        "Files are saved without MIME-type or extension validation. "
        "An attacker may upload a malicious script and execute it server-side."
    ),
    "has_secrets": (
        "🟡 MEDIUM RISK: {count} hardcoded credential(s) found in source files. "
        "Secrets committed to repositories are accessible to anyone with code access. "
        "Treat exposed credentials as compromised and rotate them immediately."
    ),
    "large_attack_surface": (
        "⚠ NOTICE: {count} attacker-reachable input entry points mapped. "
        "A large attack surface increases the probability that at least one input path is exploitable."
    ),
    "many_dangerous_functions": (
        "⚠ NOTICE: Repository contains {count} uses of dangerous execution functions. "
        "Code relying on eval/exec/os.system should be refactored to remove dynamic execution."
    ),
    "no_issues": (
        "✅ Repository appears clean. "
        "No high-severity vulnerabilities, attack chains, or secret exposures were detected. "
        "Maintain this standard by continuing to follow secure-coding practices."
    ),
    "ml_high_risk": (
        "🧠 ML INSIGHT: The machine learning classifier flagged {count} file(s) as High Risk. "
        "These files share syntactic patterns with known vulnerable code samples in the training set."
    ),
}


def generate_intelligence_summary(
    all_findings,
    attack_chains,
    all_entry_points,
    file_risks,
    fingerprint,
):
    """
    Generate a list of rule-based intelligence sentences describing the
    repository's security posture.

    Returns
    -------
    list of str — each string is one intelligence statement.
    """
    messages = []

    # Classify attack chains by type
    rce_chains = [c for c in attack_chains if "RCE" in c.get("attack_type", "") or "Remote Code" in c.get("attack_type", "")]
    cmd_chains  = [c for c in attack_chains if "Command Injection" in c.get("attack_type", "")]
    sql_chains  = [c for c in attack_chains if "SQL" in c.get("attack_type", "")]
    deser_chains = [c for c in attack_chains if "Deserialization" in c.get("attack_type", "")]
    upload_chains = [c for c in attack_chains if "File Upload" in c.get("attack_type", "")]

    # Check findings for patterns
    secret_count    = fingerprint.get("secret_exposures", 0)
    dangerous_count = fingerprint.get("dangerous_functions", 0)
    entry_count     = fingerprint.get("total_endpoints", 0)
    ml_high         = fingerprint.get("high_risk_files", 0)

    # RCE chains
    if rce_chains:
        messages.append(NARRATIVE_TEMPLATES["has_rce_chains"].format(count=len(rce_chains)))

    # Command injection chains
    if cmd_chains:
        messages.append(NARRATIVE_TEMPLATES["has_cmd_injection"].format(count=len(cmd_chains)))

    # SQL injection chains
    if sql_chains:
        messages.append(NARRATIVE_TEMPLATES["has_sql_injection"].format(count=len(sql_chains)))

    # Deserialization
    if deser_chains:
        messages.append(NARRATIVE_TEMPLATES["has_deserialization"])

    # File upload risk
    if upload_chains:
        messages.append(NARRATIVE_TEMPLATES["has_file_upload"])

    # Secrets
    if secret_count > 0:
        messages.append(NARRATIVE_TEMPLATES["has_secrets"].format(count=secret_count))

    # Large attack surface
    if entry_count >= 5:
        messages.append(NARRATIVE_TEMPLATES["large_attack_surface"].format(count=entry_count))

    # Many dangerous functions (even without a chain)
    if dangerous_count >= 3:
        messages.append(NARRATIVE_TEMPLATES["many_dangerous_functions"].format(count=dangerous_count))

    # ML high risk files
    if ml_high > 0:
        messages.append(NARRATIVE_TEMPLATES["ml_high_risk"].format(count=ml_high))

    # All-clear case
    if not messages:
        messages.append(NARRATIVE_TEMPLATES["no_issues"])

    return messages


# -----------------------------------------------------------------------
# SECTION 4: FILE RISK RANKING
# -----------------------------------------------------------------------

def rank_files_by_risk(files_data, all_findings, attack_chains, file_risks):
    """
    Score every scanned file and return them sorted most-dangerous first.

    Scoring per file (additive):
        +25  per High-severity vulnerability
        +10  per Medium-severity vulnerability
        +2   per Low-severity vulnerability
        +30  if file is part of any attack chain
        +20  if ML prediction is "High Risk"
        +10  if ML prediction is "Medium Risk"

    Returns
    -------
    list of dicts, sorted by composite_score descending. Each dict:
        file          : str
        composite_score : int
        vuln_count    : int
        chain_count   : int
        ml_prediction : str
        risk_label    : str  — "Critical" / "High" / "Medium" / "Low"
    """
    # Build lookup structures for fast per-file access
    # 1. Count chain appearances per file
    chain_file_counts = {}
    for chain in attack_chains:
        cf = chain.get("file", "").replace("\\", "/").lower()
        chain_file_counts[cf] = chain_file_counts.get(cf, 0) + 1

    # 2. ML prediction per file
    ml_map = {}
    for fr in file_risks:
        fr_file = fr.get("file", "").replace("\\", "/").lower()
        ml_map[fr_file] = fr.get("ml_prediction", "Safe")

    # 3. Count findings per file by severity
    finding_map = {}   # file → {"High": n, "Medium": n, "Low": n}
    for f in all_findings:
        ff = f.get("file", "").replace("\\", "/").lower()
        if ff not in finding_map:
            finding_map[ff] = {"High": 0, "Medium": 0, "Low": 0}
        sev = f.get("severity", "Low")
        finding_map[ff][sev] = finding_map[ff].get(sev, 0) + 1

    ranked = []
    for fd in files_data:
        rel_path = fd.get("file", "")
        norm = rel_path.replace("\\", "/").lower()

        # Vulnerability contribution
        counts = finding_map.get(norm, {"High": 0, "Medium": 0, "Low": 0})
        vuln_score = counts["High"] * 25 + counts["Medium"] * 10 + counts["Low"] * 2
        total_vulns = counts["High"] + counts["Medium"] + counts["Low"]

        # Attack chain contribution
        chain_count = chain_file_counts.get(norm, 0)
        chain_score = min(chain_count * 30, 60)   # cap at 60

        # ML contribution
        ml_pred = ml_map.get(norm, "Safe")
        ml_score = 20 if ml_pred == "High Risk" else (10 if ml_pred == "Medium Risk" else 0)

        # Total composite score
        composite = vuln_score + chain_score + ml_score

        # Map composite score to risk label
        if composite >= 80:
            risk_label = "Critical"
        elif composite >= 45:
            risk_label = "High"
        elif composite >= 15:
            risk_label = "Medium"
        else:
            risk_label = "Low"

        ranked.append({
            "file":            rel_path,
            "composite_score": composite,
            "vuln_count":      total_vulns,
            "high_vulns":      counts["High"],
            "medium_vulns":    counts["Medium"],
            "low_vulns":       counts["Low"],
            "chain_count":     chain_count,
            "ml_prediction":   ml_pred,
            "risk_label":      risk_label,
        })

    # Sort descending by composite score
    ranked.sort(key=lambda x: x["composite_score"], reverse=True)
    return ranked


# -----------------------------------------------------------------------
# SECTION 5: TERMINAL INTELLIGENCE CONSOLE LOGS
# -----------------------------------------------------------------------

def generate_terminal_logs(
    stats,
    all_findings,
    attack_chains,
    all_entry_points,
    file_risks,
    fingerprint,
    grade_info,
):
    """
    Generate a list of SOC-style terminal log messages describing the scan.
    These are displayed in the Terminal Intelligence Console tab.

    Each entry is a dict with:
        level   : str  — "INFO" / "WARNING" / "CRITICAL" / "SUCCESS" / "ERROR"
        message : str  — the log line text
    """
    logs = []

    # -- Startup phase --
    logs.append({"level": "INFO",    "message": "CodeSentinel ML Intelligence Engine initializing..."})
    logs.append({"level": "INFO",    "message": f"Repository loaded. {stats.get('total_files', 0)} source files identified."})
    logs.append({"level": "INFO",    "message": f"Total lines of code in scope: {stats.get('total_lines', 0):,}"})

    # -- Scanning phase --
    logs.append({"level": "INFO",    "message": "Executing recursive directory traversal..."})
    logs.append({"level": "INFO",    "message": "Scanning attack surface — mapping all input entry points..."})
    logs.append({"level": "INFO",    "message": f"Entry point mapping complete. {fingerprint.get('total_endpoints', 0)} input vectors identified."})

    # -- Vulnerability findings --
    total_vulns = len(all_findings)
    if total_vulns > 0:
        logs.append({"level": "WARNING", "message": f"Vulnerability scanner found {total_vulns} issue(s) across {stats.get('total_files', 0)} file(s)."})

        high_count = sum(1 for f in all_findings if f.get("severity") == "High")
        if high_count > 0:
            logs.append({"level": "CRITICAL", "message": f"{high_count} HIGH-severity vulnerability pattern(s) detected — immediate review required."})

        secret_count = fingerprint.get("secret_exposures", 0)
        if secret_count > 0:
            logs.append({"level": "WARNING", "message": f"{secret_count} hardcoded credential(s) found. Treat as compromised."})

        dangerous_count = fingerprint.get("dangerous_functions", 0)
        if dangerous_count > 0:
            logs.append({"level": "WARNING", "message": f"Dangerous execution function(s) detected: {dangerous_count} occurrence(s). (eval/exec/os.system/subprocess)"})
    else:
        logs.append({"level": "SUCCESS", "message": "No high-severity vulnerabilities detected in static scan."})

    # -- Attack chain analysis --
    logs.append({"level": "INFO",    "message": "Running attack chain correlation engine..."})
    if attack_chains:
        logs.append({"level": "CRITICAL", "message": f"{len(attack_chains)} source → sink attack chain(s) correlated. Exploit paths exist!"})
        # Classify chain types
        rce_count = sum(1 for c in attack_chains if "RCE" in c.get("attack_type", "") or "Remote Code" in c.get("attack_type", ""))
        cmd_count = sum(1 for c in attack_chains if "Command" in c.get("attack_type", ""))
        sql_count = sum(1 for c in attack_chains if "SQL" in c.get("attack_type", ""))

        if rce_count:
            logs.append({"level": "CRITICAL", "message": f"Potential Remote Code Execution (RCE) chain detected: {rce_count} path(s)."})
        if cmd_count:
            logs.append({"level": "CRITICAL", "message": f"Potential Command Injection chain identified: {cmd_count} path(s)."})
        if sql_count:
            logs.append({"level": "WARNING",  "message": f"Possible SQL Injection attack flow detected: {sql_count} path(s)."})
    else:
        logs.append({"level": "SUCCESS", "message": "Attack chain correlation complete. No source → sink paths found."})

    # -- ML classification --
    logs.append({"level": "INFO",    "message": "Running TF-IDF Logistic Regression risk classifier..."})
    ml_high = fingerprint.get("high_risk_files", 0)
    if ml_high > 0:
        logs.append({"level": "WARNING", "message": f"ML model flagged {ml_high} file(s) as High Risk."})
    else:
        logs.append({"level": "SUCCESS", "message": "ML classification complete. No files classified as High Risk."})

    # -- Grading --
    logs.append({"level": "INFO",    "message": "Computing repository security grade..."})
    grade  = grade_info.get("grade", "?")
    label  = grade_info.get("label", "")
    if grade in ("A", "B"):
        logs.append({"level": "SUCCESS", "message": f"Security grade assigned: {grade} ({label}). Repository is in good shape."})
    elif grade == "C":
        logs.append({"level": "WARNING", "message": f"Security grade assigned: {grade} ({label}). Moderate vulnerabilities need attention."})
    else:
        logs.append({"level": "CRITICAL", "message": f"Security grade assigned: {grade} ({label}). Critical risk — review required before deployment."})

    # -- Done --
    logs.append({"level": "INFO", "message": "Intelligence report generation complete."})
    logs.append({"level": "INFO", "message": "CodeSentinel ML scan session finished."})

    return logs


# -----------------------------------------------------------------------
# SECTION 6: EXPLAINABLE ML INSIGHTS
# -----------------------------------------------------------------------

def generate_ml_explanation(file_name, ml_prediction, confidence, all_findings, attack_chains):
    """
    Generate a human-readable explanation of why the ML model made its prediction
    for a specific file. Uses rule-based logic — NOT generative AI.

    Parameters
    ----------
    file_name       : str  — relative path of the file
    ml_prediction   : str  — "High Risk" / "Medium Risk" / "Safe"
    confidence      : float — model confidence (0.0–1.0)
    all_findings    : list — all vulnerability findings (across all files)
    attack_chains   : list — all detected attack chains

    Returns
    -------
    dict with:
        prediction       : str
        confidence_pct   : int (0–100)
        key_indicators   : list of str
        risk_summary     : str
    """
    # Normalize file name for comparison
    norm = file_name.replace("\\", "/").lower()

    # Gather file-specific findings
    file_findings = [f for f in all_findings
                     if f.get("file", "").replace("\\", "/").lower() == norm]

    # Gather file-specific chains
    file_chains = [c for c in attack_chains
                   if c.get("file", "").replace("\\", "/").lower() == norm]

    # Build indicator list
    indicators = []

    # Check finding types
    has_dangerous_exec = any(
        "eval" in f.get("issue", "").lower() or "exec" in f.get("issue", "").lower()
        or "os.system" in f.get("issue", "").lower() or "subprocess" in f.get("issue", "").lower()
        for f in file_findings
    )
    has_sql = any("SQL" in f.get("issue", "") for f in file_findings)
    has_secret = any(
        f.get("issue", "") in {"Hardcoded Password", "Hardcoded API Key", "Hardcoded Token", "Hardcoded Secret"}
        for f in file_findings
    )
    has_deser = any("pickle" in f.get("issue", "").lower() or "yaml" in f.get("issue", "").lower()
                    for f in file_findings)
    has_chain = len(file_chains) > 0
    high_vuln_count = sum(1 for f in file_findings if f.get("severity") == "High")

    if has_dangerous_exec:
        indicators.append("Multiple dangerous execution functions detected (eval / exec / os.system)")
    if has_sql:
        indicators.append("Raw SQL query construction patterns identified")
    if has_secret:
        indicators.append("Hardcoded credential or secret key exposure found")
    if has_deser:
        indicators.append("Unsafe deserialization (pickle / yaml.load) detected")
    if has_chain:
        indicators.append(f"{len(file_chains)} source→sink attack chain(s) traced through this file")
    if high_vuln_count >= 3:
        indicators.append(f"High density of high-severity findings ({high_vuln_count}) in one file")

    # If no specific indicators found but model still flagged it
    if not indicators and ml_prediction != "Safe":
        indicators.append("Code structure and token frequency match high-risk patterns in training data")

    # Risk summary
    if ml_prediction == "High Risk":
        risk_summary = (
            f"The ML model classified this file as HIGH RISK with {confidence:.0%} confidence. "
            "The TF-IDF vectorizer identified token patterns strongly associated with vulnerable code "
            "in the training dataset."
        )
    elif ml_prediction == "Medium Risk":
        risk_summary = (
            f"The ML model flagged this file as MEDIUM RISK with {confidence:.0%} confidence. "
            "Some suspicious code patterns were found but the overall risk is moderate."
        )
    else:
        risk_summary = (
            f"The ML model classified this file as SAFE with {confidence:.0%} confidence. "
            "The code structure does not strongly match known vulnerable patterns."
        )

    return {
        "prediction":     ml_prediction,
        "confidence_pct": int(confidence * 100),
        "key_indicators": indicators,
        "risk_summary":   risk_summary,
    }
