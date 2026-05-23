"""
scanner/prioritizer.py
-----------------------
Vulnerability Prioritization Engine (Day 5)

This module assigns a final PRIORITY LEVEL to each vulnerability finding.
Priority is determined by combining several factors:
  - How severe the vulnerability itself is (High / Medium / Low)
  - Whether an attack chain exists that involves this finding
  - Whether an attacker-controlled input reaches this finding
  - Whether the finding is a secret exposure
  - The ML model's predicted risk level for the file

Priority Levels (from most to least urgent):
  Critical → act NOW — direct exploit path confirmed
  High     → serious risk — fix before next release
  Medium   → moderate risk — schedule for remediation
  Low      → informational — review when time allows

No generative AI / LLM is used. All logic is pure rule-based.
"""

# -----------------------------------------------------------------------
# PRIORITY WEIGHTS — how much each factor contributes to the final score
# -----------------------------------------------------------------------

# These severity labels map to a base score used during prioritization
SEVERITY_BASE_SCORE = {
    "High":   50,   # dangerous function, SQL injection, etc.
    "Medium": 25,   # hardcoded secrets, debug mode, etc.
    "Low":    5,    # TODO comments, insecure random, etc.
}

# Bonus points added when special conditions are true
BONUS_ATTACK_CHAIN  = 30   # a source → sink chain links to this file/area
BONUS_INPUT_EXPOSED = 15   # an attacker-controlled input exists nearby
BONUS_SECRET        = 20   # finding is a hardcoded secret
BONUS_ML_HIGH       = 15   # ML model predicted the file as "High Risk"
BONUS_ML_MEDIUM     = 7    # ML model predicted the file as "Medium Risk"


# -----------------------------------------------------------------------
# HELPER: classify total score into a priority label
# -----------------------------------------------------------------------

def score_to_priority(score):
    """
    Convert a numeric priority score into a priority label string.

    Thresholds (tuned so that eval+request.args → Critical):
        Critical : score >= 80
        High     : score >= 50
        Medium   : score >= 20
        Low      : score < 20
    """
    if score >= 80:
        return "Critical"
    elif score >= 50:
        return "High"
    elif score >= 20:
        return "Medium"
    else:
        return "Low"


# -----------------------------------------------------------------------
# HELPER: check if a finding's file has a related attack chain
# -----------------------------------------------------------------------

def _file_has_chain(finding_file, attack_chains):
    """
    Return True if the given file path appears in any detected attack chain.
    We match by normalized path to avoid OS separator mismatches.
    """
    norm = finding_file.replace("\\", "/").lower()
    for chain in attack_chains:
        chain_file = chain.get("file", "").replace("\\", "/").lower()
        if norm == chain_file:
            return True
    return False


# -----------------------------------------------------------------------
# HELPER: check if a finding's file has exposed input entry points
# -----------------------------------------------------------------------

def _file_has_input_source(finding_file, all_entry_points):
    """
    Return True if any HIGH-severity entry point exists in the same file.
    High-severity entry points include API JSON body, form data, file uploads, PHP superglobals.
    """
    norm = finding_file.replace("\\", "/").lower()
    for ep in all_entry_points:
        ep_file = ep.get("file", "").replace("\\", "/").lower()
        if norm == ep_file and ep.get("severity") in ("High", "Medium"):
            return True
    return False


# -----------------------------------------------------------------------
# HELPER: look up the ML prediction for a specific file
# -----------------------------------------------------------------------

def _get_ml_prediction(finding_file, file_risks):
    """
    Return the ML prediction string for the file.
    file_risks is a list of dicts with keys: file, ml_prediction, confidence.
    Returns "Safe" if not found.
    """
    norm = finding_file.replace("\\", "/").lower()
    for fr in file_risks:
        fr_file = fr.get("file", "").replace("\\", "/").lower()
        if norm == fr_file:
            return fr.get("ml_prediction", "Safe")
    return "Safe"


# -----------------------------------------------------------------------
# SECRET ISSUE NAMES — findings that represent credential exposure
# -----------------------------------------------------------------------

SECRET_ISSUES = {
    "Hardcoded Password",
    "Hardcoded API Key",
    "Hardcoded Token",
    "Hardcoded Secret",
}

# -----------------------------------------------------------------------
# MAIN PUBLIC FUNCTION
# -----------------------------------------------------------------------

def prioritize_findings(all_findings, attack_chains, all_entry_points, file_risks):
    """
    Assign a priority level (Critical / High / Medium / Low) to every finding.

    Parameters
    ----------
    all_findings    : list of dicts — vulnerability findings from scan_vulnerabilities()
    attack_chains   : list of dicts — detected attack chains from detect_attack_chains()
    all_entry_points: list of dicts — entry points from scan_entry_points()
    file_risks      : list of dicts — ML predictions per file from predict_risk()

    Returns
    -------
    list of dicts — same as all_findings but with two extra keys added:
        "priority"       : str  — "Critical" | "High" | "Medium" | "Low"
        "priority_score" : int  — raw numeric score (useful for sorting)
    """
    prioritized = []

    for finding in all_findings:
        # --- Step 1: Start with the base score from raw severity ---
        base = SEVERITY_BASE_SCORE.get(finding.get("severity", "Low"), 5)
        score = base

        # --- Step 2: Bonus if file is part of an attack chain ---
        file_path = finding.get("file", "")
        if _file_has_chain(file_path, attack_chains):
            score += BONUS_ATTACK_CHAIN

        # --- Step 3: Bonus if attacker-controlled input exists in the same file ---
        if _file_has_input_source(file_path, all_entry_points):
            score += BONUS_INPUT_EXPOSED

        # --- Step 4: Bonus if this is a hardcoded secret exposure ---
        if finding.get("issue") in SECRET_ISSUES:
            score += BONUS_SECRET

        # --- Step 5: Bonus based on ML model prediction for the file ---
        ml_pred = _get_ml_prediction(file_path, file_risks)
        if ml_pred == "High Risk":
            score += BONUS_ML_HIGH
        elif ml_pred == "Medium Risk":
            score += BONUS_ML_MEDIUM

        # --- Step 6: Convert total score to a priority label ---
        priority_label = score_to_priority(score)

        # --- Build the enriched finding dict ---
        enriched = dict(finding)         # copy all existing keys
        enriched["priority"]       = priority_label
        enriched["priority_score"] = score

        prioritized.append(enriched)

    # Sort results: Critical first, then High, Medium, Low
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    prioritized.sort(key=lambda f: order.get(f["priority"], 4))

    return prioritized


# -----------------------------------------------------------------------
# CONVENIENCE: return only findings above a given priority level
# -----------------------------------------------------------------------

def get_critical_findings(prioritized_findings):
    """Return only Critical-priority findings."""
    return [f for f in prioritized_findings if f["priority"] == "Critical"]


def get_high_and_above(prioritized_findings):
    """Return Critical and High priority findings."""
    return [f for f in prioritized_findings if f["priority"] in ("Critical", "High")]
