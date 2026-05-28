# -*- coding: utf-8 -*-
"""
ml/ingest_kaggle_data.py
-------------------------
Processes the 3 downloaded Kaggle datasets and merges them into dataset.csv.

Datasets:
  1. jiscecseaiml/vulnerability-fix-dataset
     -> kaggle_data/vuln-fix/vulnerability_fix_dataset.csv
     Columns: CVE_ID, vuln_type, language, file_name, function_name,
              vulnerable_code, patched_code, ...
     Label: vulnerable_code -> High Risk (using vuln_type for CWE mapping)
            patched_code    -> Safe

  2. maratsaratov/source-code-vulnerability
     -> kaggle_data/src-vuln/dataset.csv
     Columns: need to inspect at runtime

  3. hasaber8/cve-fix-pairs
     -> kaggle_data/cve-fix-pairs/cve_fix_pairs.csv
     Columns: need to inspect at runtime

Run:
    python backend/ml/ingest_kaggle_data.py
    python backend/ml/ingest_kaggle_data.py --retrain
"""

import os
import sys
import csv
import argparse
from collections import Counter

try:
    import pandas as pd
except ImportError:
    print("ERROR: pandas not installed.")
    sys.exit(1)

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH  = os.path.join(BASE_DIR, 'dataset.csv')
KAGGLE_DIR    = os.path.join(BASE_DIR, 'kaggle_data')

# Maximum snippet length (chars) to avoid huge function bodies
MAX_LEN = 1500
# Max samples per source to avoid overwhelming the dataset with one source
MAX_PER_SOURCE = 800

# ── CWE/vuln_type → label mapping ────────────────────────────────────────────
HIGH_RISK_TYPES = {
    'sql injection', 'sqli', 'command injection', 'code injection',
    'os command injection', 'xss', 'cross-site scripting', 'ssrf',
    'path traversal', 'directory traversal', 'lfi', 'rfi',
    'template injection', 'ssti', 'xml injection', 'xxe',
    'deserialization', 'ldap injection', 'nosql injection',
    'open redirect', 'buffer overflow', 'format string',
    'heap overflow', 'use after free', 'integer overflow',
    'remote code execution', 'rce', 'arbitrary code',
    'cwe-89', 'cwe-78', 'cwe-79', 'cwe-94', 'cwe-502',
    'cwe-611', 'cwe-918', 'cwe-22', 'cwe-90', 'cwe-601',
    'cwe-943', 'cwe-917', 'cwe-77', 'cwe-119', 'cwe-120',
    'cwe-122', 'cwe-190', 'cwe-125',
}
MEDIUM_RISK_TYPES = {
    'hardcoded', 'hardcoded credential', 'weak crypto', 'insecure random',
    'cleartext', 'missing authentication', 'csrf', 'idor',
    'information disclosure', 'sensitive data exposure',
    'security misconfiguration', 'debug', 'timing',
    'cwe-798', 'cwe-330', 'cwe-326', 'cwe-312', 'cwe-327',
    'cwe-778', 'cwe-209', 'cwe-523', 'cwe-614',
}

def infer_label_from_vuln_type(vuln_type: str) -> str:
    """Map vulnerability type string to High/Medium Risk."""
    s = str(vuln_type).strip().lower()
    for t in HIGH_RISK_TYPES:
        if t in s:
            return 'High Risk'
    for t in MEDIUM_RISK_TYPES:
        if t in s:
            return 'Medium Risk'
    # Default: if it's explicitly labelled as a vulnerability, High Risk
    return 'High Risk'


def clean_code(raw: str) -> str | None:
    """Strip, truncate, and validate a code snippet."""
    if not raw or str(raw).strip() in ('', 'nan', 'None'):
        return None
    code = str(raw).replace('\\n', '\n').strip()
    if len(code) < 5:
        return None
    return code[:MAX_LEN]


# ── Dataset 1: Vulnerability Fix Dataset ─────────────────────────────────────
def ingest_vuln_fix(path: str) -> list:
    """
    Columns: CVE_ID, vuln_type, language, file_name, function_name,
             vulnerable_code, patched_code, commit_hash, repo_url,
             commit_message, granularity
    """
    print(f'\n[INGEST] Vulnerability Fix Dataset: {path}')
    samples = []

    ALLOWED_LANGS = {'python', 'javascript', 'java', 'php', 'go', 'ruby',
                     'c', 'c++', 'cpp', 'typescript', 'kotlin', 'scala'}

    try:
        df = pd.read_csv(path, encoding='utf-8', on_bad_lines='skip',
                         usecols=lambda c: c in {
                             'CVE_ID', 'vuln_type', 'language',
                             'vulnerable_code', 'patched_code'
                         })
        total = len(df)
        print(f'  Rows: {total:,}')
        print(f'  Columns: {list(df.columns)}')
        print(f'  Vuln types: {df["vuln_type"].value_counts().head(10).to_dict() if "vuln_type" in df.columns else "N/A"}')

        # Sample evenly across vuln types (balanced)
        if 'vuln_type' in df.columns:
            df = df.groupby('vuln_type', group_keys=False).apply(
                lambda g: g.sample(min(len(g), 80), random_state=42)
            ).reset_index(drop=True)

        for _, row in df.iterrows():
            lang = str(row.get('language', '')).strip().lower()
            if lang and lang not in ALLOWED_LANGS:
                continue

            vuln_type = str(row.get('vuln_type', 'unknown')).strip()
            label = infer_label_from_vuln_type(vuln_type)

            # Vulnerable code → High/Medium Risk
            code = clean_code(row.get('vulnerable_code', ''))
            if code:
                samples.append((code, label))

            # Patched code → Safe
            fixed = clean_code(row.get('patched_code', ''))
            if fixed and fixed != code:
                samples.append((fixed, 'Safe'))

            if len(samples) >= MAX_PER_SOURCE * 2:
                break

        print(f'  Extracted: {len(samples)} samples')
    except Exception as e:
        print(f'  ERROR: {e}')
        import traceback; traceback.print_exc()

    return samples[:MAX_PER_SOURCE * 2]


# ── Dataset 2: Source Code Vulnerability ─────────────────────────────────────
def ingest_src_vuln(path: str) -> list:
    """Auto-detect columns and extract labeled code samples."""
    print(f'\n[INGEST] Source Code Vulnerability: {path}')
    samples = []

    try:
        df = pd.read_csv(path, encoding='utf-8', on_bad_lines='skip', nrows=5000)
        print(f'  Rows: {len(df):,} (sample)')
        print(f'  Columns: {list(df.columns)}')

        # Detect code and label columns
        code_col = next((c for c in df.columns
                         if any(k in c.lower() for k in ['code', 'snippet', 'source', 'func', 'function', 'text'])), None)
        label_col = next((c for c in df.columns
                          if any(k in c.lower() for k in ['label', 'vuln', 'cwe', 'type', 'class', 'target', 'vul', 'vulnerable'])), None)

        print(f'  Code col: {code_col}, Label col: {label_col}')

        if not code_col:
            print('  SKIP: no code column detected')
            return []

        for _, row in df.iterrows():
            code = clean_code(row.get(code_col, ''))
            if not code:
                continue

            if label_col:
                raw_label = str(row[label_col]).strip()
                # Binary label
                if raw_label in ('1', 'True', 'true', 'vulnerable', 'Vulnerable'):
                    label = 'High Risk'
                elif raw_label in ('0', 'False', 'false', 'safe', 'Safe', 'clean'):
                    label = 'Safe'
                else:
                    label = infer_label_from_vuln_type(raw_label)
            else:
                label = 'High Risk'  # assume vulnerable if unlabeled

            samples.append((code, label))
            if len(samples) >= MAX_PER_SOURCE:
                break

        print(f'  Extracted: {len(samples)} samples')
        dist = Counter(label for _, label in samples)
        for label, cnt in dist.items():
            print(f'    {label}: {cnt}')

    except Exception as e:
        print(f'  ERROR: {e}')
        import traceback; traceback.print_exc()

    return samples


# ── Dataset 3: CVE Fix Pairs ──────────────────────────────────────────────────
def ingest_cve_fix_pairs(path: str) -> list:
    """
    Small curated dataset of real CVE vulnerability / fix code pairs.
    """
    print(f'\n[INGEST] CVE Fix Pairs: {path}')
    samples = []

    try:
        df = pd.read_csv(path, encoding='utf-8', on_bad_lines='skip')
        print(f'  Rows: {len(df):,}')
        print(f'  Columns: {list(df.columns)}')

        # Detect columns flexibly
        vuln_col  = next((c for c in df.columns if any(k in c.lower() for k in ['vuln', 'before', 'old', 'vulnerable', 'unsafe'])), None)
        fixed_col = next((c for c in df.columns if any(k in c.lower() for k in ['fix', 'after', 'patch', 'safe', 'secure', 'new'])), None)
        type_col  = next((c for c in df.columns if any(k in c.lower() for k in ['type', 'cwe', 'vuln_type', 'category'])), None)

        print(f'  Vuln col: {vuln_col}, Fixed col: {fixed_col}, Type col: {type_col}')

        for _, row in df.iterrows():
            vuln_type = str(row.get(type_col, 'unknown')).strip() if type_col else 'unknown'
            label = infer_label_from_vuln_type(vuln_type)

            if vuln_col:
                code = clean_code(row.get(vuln_col, ''))
                if code:
                    samples.append((code, label))

            if fixed_col:
                fixed = clean_code(row.get(fixed_col, ''))
                if fixed:
                    samples.append((fixed, 'Safe'))

        print(f'  Extracted: {len(samples)} samples')

    except Exception as e:
        print(f'  ERROR: {e}')
        import traceback; traceback.print_exc()

    return samples


# ── Merge & save ──────────────────────────────────────────────────────────────
def load_existing(path: str) -> list:
    rows = []
    with open(path, 'r', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            code  = str(row.get('code',  '')).strip()
            label = str(row.get('label', '')).strip()
            if code and label:
                rows.append((code, label))
    return rows


def save_dataset(samples: list, path: str) -> int:
    seen = set()
    unique = []
    for code, label in samples:
        key = code.strip()[:400]
        if key and key not in seen:
            seen.add(key)
            unique.append((code, label))
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(['code', 'label'])
        for code, label in unique:
            writer.writerow([code, label])
    return len(unique)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--retrain', action='store_true')
    args = parser.parse_args()

    print('=' * 60)
    print('  CodeSentinel ML — Kaggle Dataset Ingestor')
    print('=' * 60)

    existing = load_existing(DATASET_PATH)
    print(f'\n[INFO] Existing samples: {len(existing)}')

    new_samples = []

    # Dataset 1
    p1 = os.path.join(KAGGLE_DIR, 'vuln-fix', 'vulnerability_fix_dataset.csv')
    if os.path.exists(p1):
        new_samples += ingest_vuln_fix(p1)
    else:
        print(f'\n[SKIP] {p1} not found')

    # Dataset 2
    p2 = os.path.join(KAGGLE_DIR, 'src-vuln', 'dataset.csv')
    if os.path.exists(p2):
        new_samples += ingest_src_vuln(p2)
    else:
        print(f'\n[SKIP] {p2} not found')

    # Dataset 3
    p3 = os.path.join(KAGGLE_DIR, 'cve-fix-pairs', 'cve_fix_pairs.csv')
    if os.path.exists(p3):
        new_samples += ingest_cve_fix_pairs(p3)
    else:
        print(f'\n[SKIP] {p3} not found')

    nc = Counter(label for _, label in new_samples)
    print(f'\n[INFO] Total new samples from Kaggle: {len(new_samples)}')
    for label, cnt in sorted(nc.items()):
        print(f'  {label:<15}: {cnt:>5}')

    # Merge
    total = save_dataset(existing + new_samples, DATASET_PATH)
    final = load_existing(DATASET_PATH)
    fc = Counter(label for _, label in final)

    print(f'\n[OK] Dataset saved: {total} unique rows -> {DATASET_PATH}')
    print('[INFO] Final distribution:')
    for label, cnt in sorted(fc.items()):
        pct = cnt / total * 100
        print(f'  {label:<15}: {cnt:>5} ({pct:.1f}%)')

    if args.retrain:
        print('\n[INFO] Retraining...')
        import subprocess
        subprocess.run([sys.executable, '-X', 'utf8',
                        os.path.join(BASE_DIR, 'retrain.py')],
                       cwd=os.path.dirname(BASE_DIR))


if __name__ == '__main__':
    main()
