"""
scanner/gemini_patcher.py
-------------------
Online AI (Google Gemini) Security Code Remediation Engine

Interfaces with Google Gemini API to generate context-aware, secure code fixes
and rich explanations. Fully stateless and secure.
"""

import os
import json
import requests
import traceback
import re

def generate_gemini_fix(issue_name, file_path, line_num, line_content, context_lines):
    """
    Generate a secure code patch using Google Gemini API.

    Parameters
    ----------
    issue_name    : str
        The name/type of the vulnerability (e.g., SQL Injection, Debug Mode Enabled)
    file_path     : str
        Relative path of the target file
    line_num      : int or str
        The 1-indexed line number in the source file
    line_content  : str
        The exact raw line content containing the finding
    context_lines : list of str
        Surrounding code lines to give context to the AI (e.g., 5 lines before/after)

    Returns
    -------
    tuple of (fixed_line: str, explanation: str) or (None, None) if not configured / failed.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[GEMINI_AI] Warning: GEMINI_API_KEY environment variable is not configured. Falling back to local engine.")
        return None, None

    # Construct the context block
    context_block = ""
    for idx, line in enumerate(context_lines, 1):
        context_block += f"  {idx}: {line.rstrip()}\n"

    # Construct system instructions and prompt
    prompt = f"""You are a senior secure-coding architect and static code repair bot.
Your objective is to fix a security vulnerability found in a source code file.

CONTEXT & LOCATION:
- File Path: {file_path}
- Target Line Number: {line_num}
- Target Insecure Code Line: {line_content.strip()}

SURROUNDING FILE CONTEXT:
{context_block}

VULNERABILITY THREAT:
- Vulnerability Type: {issue_name}

INSTRUCTIONS:
1. Generate an EXACT single-line replacement for the target line that completely remediates the security vulnerability.
2. The replacement MUST preserve the exact indentation of the original line.
3. The replacement must be syntactically correct and seamlessly integrate with the surrounding file context.
4. Provide a rich, highly precise 2-3 sentence technical explanation of why the original line was unsafe and how your patch secures it.
5. Return ONLY a valid JSON object matching this schema:
{{
  "fixed_line": "repaired single-line code string (preserving original indentation)",
  "explanation": "advisory explanation details"
}}
"""

    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json"
        }
    }

    # Using Gemini 2.5 Flash as it is highly performant and perfect for coding utilities
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"

    try:
        print(f"[GEMINI_AI] Dispatching patch request for issue '{issue_name}' in {file_path}:{line_num}...")
        resp = requests.post(url, json=payload, headers=headers, timeout=12)
        
        if resp.status_code != 200:
            print(f"[GEMINI_AI_ERROR] API returned status code {resp.status_code}: {resp.text}")
            return None, None
            
        data = resp.json()
        candidates = data.get("candidates", [])
        if not candidates:
            print("[GEMINI_AI_ERROR] No response candidates returned from the model.")
            return None, None
            
        raw_text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "").strip()
        if not raw_text:
            print("[GEMINI_AI_ERROR] Response candidate content parts are empty.")
            return None, None
            
        # Parse JSON output
        result = json.loads(raw_text)
        fixed_line = result.get("fixed_line")
        explanation = result.get("explanation")
        
        if fixed_line is None or explanation is None:
            print(f"[GEMINI_AI_ERROR] Missing expected JSON keys. Raw text: {raw_text}")
            return None, None
            
        # If Gemini returned fixed_line without the original leading indentation, let's restore it
        indent_match = re.match(r'^(\s*)', line_content)
        indent = indent_match.group(1) if indent_match else ""
        if not fixed_line.startswith(indent):
            fixed_line = indent + fixed_line.lstrip()
            
        print("[GEMINI_AI] AI Patch generated successfully.")
        return fixed_line, explanation

    except Exception as e:
        print(f"[GEMINI_AI_ERROR] Request failed or JSON parse error: {e}")
        traceback.print_exc()
        return None, None
