"""
ml/model.py
-----------
ML Risk Classification Engine

Uses combined word+character TF-IDF vectorization + Logistic Regression to classify
code snippets into: Safe | Medium Risk | High Risk

The combined vectorizer is key:
  - Word n-grams (1-3): captures function names, API calls, patterns
  - Char n-grams (2-5): captures '+' concatenation vs '?' placeholders,
    'shell=True' vs 'shell=False', format strings vs parameterized queries

No generative AI or LLMs are used — this is a classic supervised ML pipeline.
Dataset: 465+ rows across Python, JavaScript, Java, PHP, Go covering CWE/OWASP patterns.
Test accuracy: ~82% | CV accuracy: ~78%
"""

import os
import pickle
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report

# ── File Paths ───────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH    = os.path.join(BASE_DIR, 'dataset.csv')
MODEL_PATH      = os.path.join(BASE_DIR, 'trained_model.pkl')
VECTORIZER_PATH = os.path.join(BASE_DIR, 'vectorizer.pkl')

# ── Training ─────────────────────────────────────────────────────────────

def _build_vectorizer():
    """
    Combined word + character TF-IDF feature union.
    Character n-grams (2-5) catch critical security signals:
      '+' string concatenation  => SQL injection risk
      '?' placeholder           => parameterized query (safe)
      'shell=True'              => command injection risk
      'verify=False'            => SSL bypass risk
    """
    word_vec = TfidfVectorizer(
        max_features=4000,
        ngram_range=(1, 3),
        analyzer='word',
        token_pattern=r"(?u)\b\w[\w.]+\b",   # keep dots (os.system, cursor.execute)
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


def train_model(force=False):
    """
    Train the risk classifier on the dataset and save it to disk.

    Parameters
    ----------
    force : bool
        If True, retrain even if a saved model already exists.

    Returns
    -------
    bool : True if training succeeded, False otherwise.
    """
    # Skip re-training if models already exist and we're not forcing
    if not force and os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        return True

    print("[ML_CORE] Training Code Risk Classifier...")

    # 1. Load dataset
    if not os.path.exists(DATASET_PATH):
        print(f"[ML_CORE_ERROR] Dataset not found at {DATASET_PATH}")
        return False

    df = pd.read_csv(DATASET_PATH)

    # Drop rows with missing values and duplicates
    df = df.dropna(subset=['code', 'label'])
    df = df.drop_duplicates(subset=['code'])
    print(f"[ML_CORE] Loaded {len(df)} training samples across {df['label'].nunique()} classes.")
    print(f"[ML_CORE] Class distribution:\n{df['label'].value_counts().to_string()}")

    # 2. Combined word + character n-gram TF-IDF
    vectorizer = _build_vectorizer()
    X = vectorizer.fit_transform(df['code'])
    y = df['label']
    print(f"[ML_CORE] Feature matrix: {X.shape}")

    # 3. Logistic Regression — optimal for sparse TF-IDF features
    model = LogisticRegression(
        C=20,
        max_iter=5000,
        class_weight='balanced',
        random_state=42,
        solver='lbfgs',
    )

    # 4. 5-fold cross-validation (for reporting)
    print("[ML_CORE] Running 5-fold cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring='accuracy', n_jobs=1)
    print(f"[ML_CORE] CV Accuracy: {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")

    # 5. Final fit on full dataset
    model.fit(X, y)

    # 6. Training-set classification report (in-sample sanity check)
    y_pred = model.predict(X)
    classes = np.unique(y)
    print("[ML_CORE] Training Classification Report:")
    print(classification_report(y, y_pred, target_names=sorted(classes)))

    # 7. Save model and vectorizer
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)

    with open(VECTORIZER_PATH, 'wb') as f:
        pickle.dump(vectorizer, f)

    print("[ML_CORE] Training Complete. Model saved.")
    return True


# ── Prediction ───────────────────────────────────────────────────────────

def predict_risk(code_snippet):
    """
    Predict the risk level of a source-code string.

    Parameters
    ----------
    code_snippet : str
        Raw source code text (can be a whole file or a single snippet).

    Returns
    -------
    dict with keys:
        - prediction  : str  ('Safe' | 'Medium Risk' | 'High Risk')
        - confidence  : float (0-100, confidence for the predicted class)
        - all_scores  : dict  {label: confidence_pct}
    """
    # Auto-train if model files are missing
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        success = train_model(force=True)
        if not success:
            return {"prediction": "Unknown", "confidence": 0.0, "all_scores": {}}

    try:
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)

        with open(VECTORIZER_PATH, 'rb') as f:
            vectorizer = pickle.load(f)

        # Vectorise input — use first 8000 chars (increased from 5000)
        X_input = vectorizer.transform([code_snippet[:8000]])

        # Predict label
        prediction = model.predict(X_input)[0]

        # Get per-class confidence probabilities
        probabilities  = model.predict_proba(X_input)[0]
        classes        = model.classes_
        confidence_map = {classes[i]: round(float(p) * 100, 1) for i, p in enumerate(probabilities)}

        return {
            "prediction": prediction,
            "confidence": confidence_map.get(prediction, 0.0),
            "all_scores": confidence_map
        }

    except Exception as e:
        print(f"[ML_CORE_ERROR] Prediction failed: {e}")
        return {"prediction": "Unknown", "confidence": 0.0, "all_scores": {}}


# ── Batch Prediction ─────────────────────────────────────────────────────

def predict_risk_batch(code_snippets):
    """
    Predict risk for a list of code snippets efficiently (single vectorizer call).

    Parameters
    ----------
    code_snippets : list of str

    Returns
    -------
    list of dicts (same format as predict_risk)
    """
    if not code_snippets:
        return []

    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        train_model(force=True)

    try:
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        with open(VECTORIZER_PATH, 'rb') as f:
            vectorizer = pickle.load(f)

        # Truncate each snippet to 8000 chars
        truncated = [s[:8000] for s in code_snippets]
        X = vectorizer.transform(truncated)

        predictions  = model.predict(X)
        probabilities = model.predict_proba(X)
        classes       = model.classes_

        results = []
        for pred, probs in zip(predictions, probabilities):
            conf_map = {classes[i]: round(float(p) * 100, 1) for i, p in enumerate(probs)}
            results.append({
                "prediction": pred,
                "confidence": conf_map.get(pred, 0.0),
                "all_scores": conf_map
            })
        return results

    except Exception as e:
        print(f"[ML_CORE_ERROR] Batch prediction failed: {e}")
        return [{"prediction": "Unknown", "confidence": 0.0, "all_scores": {}}] * len(code_snippets)
