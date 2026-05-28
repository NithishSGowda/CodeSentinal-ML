# -*- coding: utf-8 -*-
"""
ml/retrain.py
-------------
Standalone retraining script for the CodeSentinel ML Risk Classifier.

Run this script to:
  1. Back up the existing model & vectorizer
  2. Retrain on the expanded dataset
  3. Print cross-validation accuracy + per-class F1 report
  4. Save the new model & vectorizer

Usage:
    python backend/ml/retrain.py
    python backend/ml/retrain.py --force      # force retrain even if model exists
"""

import os
import sys
import shutil
import pickle
import argparse
import datetime
import pandas as pd
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.model_selection import cross_val_score, StratifiedKFold, train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# ── Paths ─────────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH    = os.path.join(BASE_DIR, 'dataset.csv')
MODEL_PATH      = os.path.join(BASE_DIR, 'trained_model.pkl')
VECTORIZER_PATH = os.path.join(BASE_DIR, 'vectorizer.pkl')
BACKUP_DIR      = os.path.join(BASE_DIR, 'backups')


def backup_existing_models():
    """Back up existing model and vectorizer files with a timestamp."""
    if not os.path.exists(MODEL_PATH) and not os.path.exists(VECTORIZER_PATH):
        print("[RETRAIN] No existing model files to back up.")
        return

    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    for src, name in [(MODEL_PATH, 'trained_model.pkl'), (VECTORIZER_PATH, 'vectorizer.pkl')]:
        if os.path.exists(src):
            dst = os.path.join(BACKUP_DIR, f"{ts}_{name}")
            shutil.copy2(src, dst)
            print(f"[RETRAIN] Backed up {name} -> backups/{ts}_{name}")


def load_dataset():
    """Load and validate the training dataset."""
    if not os.path.exists(DATASET_PATH):
        print(f"[RETRAIN ERROR] Dataset not found: {DATASET_PATH}")
        sys.exit(1)

    df = pd.read_csv(DATASET_PATH)
    df = df.dropna(subset=['code', 'label'])
    df['code'] = df['code'].astype(str).str.strip()
    df['label'] = df['label'].astype(str).str.strip()

    # Remove duplicates
    before = len(df)
    df = df.drop_duplicates(subset=['code'])
    after = len(df)
    if before != after:
        print(f"[RETRAIN] Removed {before - after} duplicate rows.")

    return df


def build_vectorizer():
    """
    Combined word + character n-gram TF-IDF vectorizer.
    The character n-grams catch critical security signals:
      - '+' (string concatenation in SQL injection)
      - '?' (parameterized query placeholder -> SAFE)
      - '%s'/'$1' (other safe parameterized styles)
      - 'shell=True' vs 'shell=False'
    """
    word_vec = TfidfVectorizer(
        max_features=4000,
        ngram_range=(1, 3),
        analyzer='word',
        token_pattern=r"(?u)\b\w[\w.]+\b",
        sublinear_tf=True,
        min_df=1,
        strip_accents='unicode',
    )
    char_vec = TfidfVectorizer(
        max_features=2000,
        ngram_range=(2, 5),
        analyzer='char_wb',
        sublinear_tf=True,
        min_df=1,
    )
    return FeatureUnion([('word', word_vec), ('char', char_vec)])


def build_classifier():
    """Logistic Regression — optimal for sparse TF-IDF features."""
    return LogisticRegression(
        C=20,
        max_iter=5000,
        class_weight='balanced',
        random_state=42,
        solver='lbfgs',
    )


def print_separator(char='-', width=60):
    print(char * width)


def main():
    parser = argparse.ArgumentParser(description='Retrain CodeSentinel ML Risk Classifier')
    parser.add_argument('--force', action='store_true', help='Force retraining even if model exists')
    args = parser.parse_args()

    print_separator('=')
    print("  CodeSentinel ML -- Retraining Pipeline")
    print_separator('=')

    # 1. Back up existing models
    backup_existing_models()
    print_separator()

    # 2. Load dataset
    print("[RETRAIN] Loading dataset...")
    df = load_dataset()

    print(f"[RETRAIN] Total samples : {len(df)}")
    print("[RETRAIN] Class distribution:")
    for label, count in df['label'].value_counts().items():
        pct = count / len(df) * 100
        bar = '#' * int(pct / 2)
        print(f"          {label:<15} {count:>4} ({pct:5.1f}%)  {bar}")
    print_separator()

    # 3. Build vectorizer + transform
    print("[RETRAIN] Vectorizing code with combined word+char TF-IDF...")
    vectorizer = build_vectorizer()
    X = vectorizer.fit_transform(df['code'])
    y = df['label']
    print(f"[RETRAIN] Feature matrix shape: {X.shape}")
    print_separator()

    # 4. Held-out test split (20%) for unbiased evaluation
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[RETRAIN] Train/Test split: {X_train.shape[0]} train | {X_test.shape[0]} test")
    print_separator()

    # 5. Cross-validation on training set
    print("[RETRAIN] Running 5-fold Stratified Cross-Validation...")
    clf_cv = build_classifier()
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(clf_cv, X_train, y_train, cv=cv, scoring='accuracy', n_jobs=1)
    print(f"[RETRAIN] CV Accuracy  : {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")
    print(f"[RETRAIN] Per-fold     : {[round(s, 4) for s in cv_scores]}")
    print_separator()

    # 6. Train final model on full training split
    print("[RETRAIN] Training final model on full training set...")
    clf = build_classifier()
    clf.fit(X_train, y_train)

    # 7. Evaluate on held-out test set
    y_pred = clf.predict(X_test)
    test_acc = accuracy_score(y_test, y_pred)
    print_separator()
    print(f"[RETRAIN] Held-out Test Accuracy: {test_acc:.4f} ({test_acc*100:.1f}%)")
    print_separator()
    print("[RETRAIN] Classification Report (Test Set):")
    print(classification_report(y_test, y_pred))

    # 8. Confusion matrix
    print("[RETRAIN] Confusion Matrix (rows=actual, cols=predicted):")
    labels = sorted(y.unique())
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    header = ''.join(f"{l[:10]:>12}" for l in labels)
    print(f"{'':>15}{header}")
    for i, row_label in enumerate(labels):
        row_str = ''.join(f"{v:>12}" for v in cm[i])
        print(f"  {row_label:<13}{row_str}")
    print_separator()

    # 9. Retrain on FULL dataset for production model
    print("[RETRAIN] Fitting production model on full dataset (train + test)...")
    final_clf = build_classifier()
    final_clf.fit(X, y)

    # 10. Save model and vectorizer SEPARATELY (same interface as before)
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(final_clf, f)
    with open(VECTORIZER_PATH, 'wb') as f:
        pickle.dump(vectorizer, f)

    print(f"[RETRAIN] Model saved     -> {MODEL_PATH}")
    print(f"[RETRAIN] Vectorizer saved -> {VECTORIZER_PATH}")
    print_separator('=')
    print(f"  Retraining complete! CV Accuracy={cv_scores.mean():.4f}, Test Accuracy={test_acc:.4f}")
    print_separator('=')

    # 11. Quick sanity check -- predict a few known examples
    print("\n[RETRAIN] Quick Sanity Check:")
    samples = [
        ("eval(user_input)",                                               "High Risk"),
        ("cursor.execute('SELECT * FROM users WHERE id=' + id)",           "High Risk"),
        ("os.system(cmd)",                                                 "High Risk"),
        ("pickle.loads(request.data)",                                     "High Risk"),
        ("password = 'admin123'",                                           "Medium Risk"),
        ("app.run(debug=True)",                                             "Medium Risk"),
        ("hashlib.md5(password.encode()).hexdigest()",                     "Medium Risk"),
        ("cursor.execute('SELECT * FROM users WHERE id=?', (uid,))",       "Safe"),
        ("token = secrets.token_hex(32)",                                  "Safe"),
        ("SECRET_KEY = os.environ['SECRET_KEY']",                          "Safe"),
    ]
    all_correct = 0
    for code, expected in samples:
        vec = vectorizer.transform([code])
        pred = final_clf.predict(vec)[0]
        prob = max(final_clf.predict_proba(vec)[0]) * 100
        status = "PASS" if pred == expected else "FAIL"
        print(f"  [{status}] [{prob:5.1f}%] {pred:<15} | expected: {expected:<15} | {code[:55]}")
        if pred == expected:
            all_correct += 1
    print(f"\n  Sanity check: {all_correct}/{len(samples)} correct\n")


if __name__ == '__main__':
    main()
