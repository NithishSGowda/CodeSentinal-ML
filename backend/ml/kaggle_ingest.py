# -*- coding: utf-8 -*-
"""
ml/kaggle_ingest.py
--------------------
Downloads real security vulnerability datasets from Kaggle,
processes them into (code, label) pairs compatible with our
training pipeline, and merges with the existing dataset.csv.

Prerequisites:
    pip install kaggle
    Place kaggle.json at ~/.kaggle/kaggle.json
    (or set KAGGLE_USERNAME and KAGGLE_KEY env vars)

Targeted Kaggle datasets:
  1. "code-vulnerabilities"       - 1,000 SQLi + XSS labeled snippets
  2. "vulnerability-fix-dataset"  - 35,000 vulnerable vs fixed code pairs
  3. "source-code-vulnerabilities" - 4,500+ multi-language labeled snippets

Usage:
    python backend/ml/kaggle_ingest.py
    python backend/ml/kaggle_ingest.py --dry-run   # show what would be downloaded
    python backend/ml/kaggle_ingest.py --retrain   # also retrain after merging
"""

import os
import sys
import csv
import json
import argparse
import tempfile
import shutil
import zipfile
from collections import Counter

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, 'dataset.csv')
OUTPUT_PATH  = os.path.join(BASE_DIR, 'dataset.csv')

# ── Label normalization ───────────────────────────────────────────────────────
# Map Kaggle dataset labels → our 3 classes

HIGH_RISK_KEYWORDS = {
    'sql injection', 'sqli', 'sql_injection', 'command injection', 'os command',
    'code injection', 'remote code execution', 'rce', 'xss', 'cross-site scripting',
    'ssrf', 'server-side request forgery', 'path traversal', 'directory traversal',
    'lfi', 'rfi', 'local file inclusion', 'remote file inclusion',
    'template injection', 'ssti', 'ldap injection', 'xml injection', 'xxe',
    'deserialization', 'unsafe deserialization', 'insecure deserialization',
    'nosql injection', 'buffer overflow', 'heap overflow', 'format string',
    'high', 'critical', 'high_risk', 'vulnerable', 'vulnerability',
    'cwe-89', 'cwe-78', 'cwe-79', 'cwe-94', 'cwe-502', 'cwe-611', 'cwe-918',
    'injection', 'exploit',
}

MEDIUM_RISK_KEYWORDS = {
    'hardcoded', 'hardcoded credential', 'weak crypto', 'weak cryptography',
    'insecure random', 'cleartext', 'plaintext password', 'debug enabled',
    'missing authentication', 'missing authorization', 'idor',
    'information disclosure', 'sensitive data exposure', 'csrf',
    'security misconfiguration', 'medium', 'medium_risk', 'warning',
    'cwe-798', 'cwe-330', 'cwe-326', 'cwe-312', 'cwe-327',
    'weak password', 'insecure cookie', 'timing attack',
}

SAFE_KEYWORDS = {
    'safe', 'clean', 'fixed', 'secure', 'patched', 'remediated',
    'parameterized', 'prepared statement', 'sanitized', 'validated',
    'safe_', 'not vulnerable', 'benign', 'no vulnerability',
}


def normalize_label(raw_label: str) -> str | None:
    """Map a raw Kaggle label to 'High Risk', 'Medium Risk', or 'Safe'. Returns None to skip."""
    if not raw_label:
        return None
    s = str(raw_label).strip().lower()
    for kw in HIGH_RISK_KEYWORDS:
        if kw in s:
            return 'High Risk'
    for kw in SAFE_KEYWORDS:
        if kw in s or s == kw:
            return 'Safe'
    for kw in MEDIUM_RISK_KEYWORDS:
        if kw in s:
            return 'Medium Risk'
    return None


def normalize_label_binary(is_vulnerable) -> str:
    """For datasets with binary 0/1 labels (0=safe, 1=vulnerable)."""
    try:
        v = int(is_vulnerable)
        return 'High Risk' if v == 1 else 'Safe'
    except (ValueError, TypeError):
        s = str(is_vulnerable).strip().lower()
        if s in ('1', 'true', 'yes', 'vulnerable'):
            return 'High Risk'
        if s in ('0', 'false', 'no', 'safe', 'clean'):
            return 'Safe'
        return None


# ── Kaggle dataset processors ─────────────────────────────────────────────────

def process_code_vulnerabilities(data_dir: str) -> list:
    """
    Kaggle: 'code-vulnerabilities'
    Columns: code, vulnerability_type, simulated_line, preprocessed_tokens
    Labels: sql_injection, xss (both -> High Risk)
    """
    samples = []
    for fname in os.listdir(data_dir):
        if not fname.endswith('.csv'):
            continue
        fpath = os.path.join(data_dir, fname)
        try:
            import pandas as pd
            df = pd.read_csv(fpath, encoding='utf-8', on_bad_lines='skip')
            # Try common column names
            code_col  = next((c for c in df.columns if 'code' in c.lower()), None)
            label_col = next((c for c in df.columns if any(k in c.lower() for k in ['vuln', 'type', 'label', 'class'])), None)
            if not code_col:
                print(f'  [SKIP] {fname}: no code column found (cols={list(df.columns)})')
                continue
            for _, row in df.iterrows():
                code = str(row[code_col]).strip()
                if not code or code == 'nan' or len(code) < 5:
                    continue
                if label_col:
                    label = normalize_label(str(row[label_col]))
                else:
                    label = 'High Risk'  # dataset is all-vulnerable if no label col
                if label:
                    samples.append((code[:2000], label))
            print(f'  [OK] {fname}: extracted {len(samples)} samples')
        except Exception as e:
            print(f'  [ERROR] {fname}: {e}')
    return samples


def process_vulnerability_fix_dataset(data_dir: str) -> list:
    """
    Kaggle: 'vulnerability-fix-dataset'
    Columns: vulnerability_type, vulnerable_code, fixed_code
    -> vulnerable_code = High Risk, fixed_code = Safe
    """
    samples = []
    for fname in os.listdir(data_dir):
        if not fname.endswith('.csv'):
            continue
        fpath = os.path.join(data_dir, fname)
        try:
            import pandas as pd
            df = pd.read_csv(fpath, encoding='utf-8', on_bad_lines='skip')
            vuln_col  = next((c for c in df.columns if 'vuln' in c.lower() and 'type' not in c.lower()), None)
            fixed_col = next((c for c in df.columns if 'fix' in c.lower() or 'patch' in c.lower() or 'safe' in c.lower()), None)
            type_col  = next((c for c in df.columns if 'type' in c.lower() or 'category' in c.lower()), None)

            before = len(samples)
            for _, row in df.iterrows():
                # Add vulnerable version
                if vuln_col:
                    code = str(row[vuln_col]).strip()
                    if code and code != 'nan' and len(code) >= 5:
                        if type_col:
                            label = normalize_label(str(row[type_col])) or 'High Risk'
                        else:
                            label = 'High Risk'
                        samples.append((code[:2000], label))
                # Add fixed version
                if fixed_col:
                    code = str(row[fixed_col]).strip()
                    if code and code != 'nan' and len(code) >= 5:
                        samples.append((code[:2000], 'Safe'))

            print(f'  [OK] {fname}: extracted {len(samples) - before} samples')
        except Exception as e:
            print(f'  [ERROR] {fname}: {e}')
    return samples


def process_source_code_vulnerabilities(data_dir: str) -> list:
    """
    Kaggle: multi-language vulnerability datasets
    Common columns: code/snippet, label/vulnerable/cwe/type
    """
    samples = []
    for fname in os.listdir(data_dir):
        if not (fname.endswith('.csv') or fname.endswith('.json')):
            continue
        fpath = os.path.join(data_dir, fname)
        try:
            import pandas as pd
            if fname.endswith('.json'):
                with open(fpath, encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    df = pd.DataFrame(data)
                else:
                    df = pd.DataFrame([data])
            else:
                df = pd.read_csv(fpath, encoding='utf-8', on_bad_lines='skip')

            code_col  = next((c for c in df.columns if any(k in c.lower() for k in ['code', 'snippet', 'source', 'func', 'function'])), None)
            label_col = next((c for c in df.columns if any(k in c.lower() for k in ['label', 'vuln', 'cwe', 'type', 'class', 'target', 'vul'])), None)

            if not code_col:
                print(f'  [SKIP] {fname}: no code column (cols={list(df.columns[:6])})')
                continue

            before = len(samples)
            for _, row in df.iterrows():
                code = str(row[code_col]).strip()
                if not code or code == 'nan' or len(code) < 5:
                    continue
                if label_col:
                    raw = str(row[label_col])
                    # Try binary first (0/1)
                    label = normalize_label_binary(raw) if raw in ('0', '1') else normalize_label(raw)
                else:
                    label = None
                if label:
                    samples.append((code[:2000], label))

            print(f'  [OK] {fname}: extracted {len(samples) - before} samples')
        except Exception as e:
            print(f'  [ERROR] {fname}: {e}')
    return samples


# ── Kaggle download helper ────────────────────────────────────────────────────

DATASETS = [
    # (owner/dataset-slug, processor_function)
    ('CoderSahib/code-vulnerabilities',          process_code_vulnerabilities),
    ('sathwikk/vulnerability-fix-dataset',       process_vulnerability_fix_dataset),
    ('rabiyasalehjee/source-code-vulnerabilities', process_source_code_vulnerabilities),
    ('sureshkumarg/vulnerable-code-dataset',     process_source_code_vulnerabilities),
    ('ashfakshibli/cybersecurity-attack-dataset', process_source_code_vulnerabilities),
]


def download_and_process(dry_run: bool = False) -> list:
    """Download all configured Kaggle datasets and return (code, label) pairs."""
    try:
        import kaggle
    except ImportError:
        print('[ERROR] kaggle package not installed. Run: pip install kaggle')
        return []

    all_samples = []
    tmp_root = tempfile.mkdtemp()

    for dataset_slug, processor in DATASETS:
        owner, name = dataset_slug.split('/', 1)
        dl_dir = os.path.join(tmp_root, name)
        os.makedirs(dl_dir, exist_ok=True)

        print(f'\n[KAGGLE] Downloading: {dataset_slug}')
        if dry_run:
            print(f'  [DRY-RUN] Would download {dataset_slug} -> {dl_dir}')
            continue

        try:
            import subprocess
            result = subprocess.run(
                ['python', '-m', 'kaggle', 'datasets', 'download',
                 '-d', dataset_slug, '-p', dl_dir, '--unzip', '--quiet'],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                print(f'  [WARN] kaggle download failed: {result.stderr.strip()[:200]}')
                # Still try to process in case files were partially extracted
            else:
                print(f'  [OK] Downloaded to {dl_dir}')

            samples = processor(dl_dir)
            print(f'  [TOTAL] Got {len(samples)} samples from {dataset_slug}')
            all_samples.extend(samples)

        except Exception as e:
            print(f'  [ERROR] Failed to download/process {dataset_slug}: {e}')

    shutil.rmtree(tmp_root, ignore_errors=True)
    return all_samples


# ── CSV merge ─────────────────────────────────────────────────────────────────

def load_existing_dataset(path: str) -> list:
    """Load existing dataset.csv as (code, label) list."""
    if not os.path.exists(path):
        return []
    samples = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                code  = str(row.get('code',  '')).strip()
                label = str(row.get('label', '')).strip()
                if code and label:
                    samples.append((code, label))
    except Exception as e:
        print(f'[ERROR] Could not load existing dataset: {e}')
    return samples


def merge_and_save(existing: list, new_samples: list, output_path: str) -> int:
    """Deduplicate and save merged dataset. Returns count of unique rows."""
    seen = set()
    unique = []
    for code, label in existing + new_samples:
        key = code.strip()[:500]  # fingerprint first 500 chars
        if key and key not in seen:
            seen.add(key)
            unique.append((code, label))

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(['code', 'label'])
        for code, label in unique:
            writer.writerow([code, label])

    return len(unique)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Kaggle dataset ingest for CodeSentinel ML')
    parser.add_argument('--dry-run',  action='store_true', help='Show what would be downloaded without downloading')
    parser.add_argument('--retrain',  action='store_true', help='Retrain model after successful merge')
    parser.add_argument('--kaggle-username', default=os.environ.get('KAGGLE_USERNAME', ''), help='Kaggle username')
    parser.add_argument('--kaggle-key',      default=os.environ.get('KAGGLE_KEY', ''),      help='Kaggle API key')
    args = parser.parse_args()

    # Inject credentials into env if provided via CLI
    if args.kaggle_username:
        os.environ['KAGGLE_USERNAME'] = args.kaggle_username
    if args.kaggle_key:
        os.environ['KAGGLE_KEY'] = args.kaggle_key

    print('=' * 60)
    print('  CodeSentinel ML -- Kaggle Dataset Ingest')
    print('=' * 60)
    print(f'  Existing dataset : {DATASET_PATH}')
    print(f'  Output           : {OUTPUT_PATH}')
    print()

    # Load existing
    existing = load_existing_dataset(DATASET_PATH)
    print(f'[INFO] Loaded {len(existing)} existing samples')
    ec = Counter(label for _, label in existing)
    for label, cnt in sorted(ec.items()):
        print(f'  {label:<15}: {cnt}')
    print()

    # Download new data from Kaggle
    new_samples = download_and_process(dry_run=args.dry_run)

    if args.dry_run:
        print('\n[DRY-RUN] No changes made.')
        return

    if not new_samples:
        print('[WARN] No new samples were collected from Kaggle.')
        print('       Check your kaggle.json credentials or dataset slugs.')
        print('\nTo configure Kaggle API:')
        print('  1. Go to https://www.kaggle.com/account')
        print('  2. Click "Create New API Token" -> downloads kaggle.json')
        print('  3. Place kaggle.json at: C:\\Users\\<you>\\.kaggle\\kaggle.json')
        print('  4. Or set KAGGLE_USERNAME and KAGGLE_KEY environment variables')
        return

    # Merge
    nc = Counter(label for _, label in new_samples)
    print(f'\n[INFO] New samples collected: {len(new_samples)}')
    for label, cnt in sorted(nc.items()):
        print(f'  {label:<15}: {cnt}')

    total = merge_and_save(existing, new_samples, OUTPUT_PATH)
    print(f'\n[OK] Dataset saved: {total} unique rows -> {OUTPUT_PATH}')

    # Verify final distribution
    final = load_existing_dataset(OUTPUT_PATH)
    fc = Counter(label for _, label in final)
    print('\n[INFO] Final distribution:')
    for label, cnt in sorted(fc.items()):
        pct = cnt / total * 100
        print(f'  {label:<15}: {cnt:>5} ({pct:.1f}%)')

    if args.retrain:
        print('\n[INFO] Retraining model...')
        import subprocess
        result = subprocess.run(
            [sys.executable, '-X', 'utf8', os.path.join(BASE_DIR, 'retrain.py')],
            cwd=os.path.dirname(BASE_DIR)
        )
        if result.returncode == 0:
            print('[OK] Retraining complete!')
        else:
            print('[ERROR] Retraining failed. Run retrain.py manually.')


if __name__ == '__main__':
    main()
