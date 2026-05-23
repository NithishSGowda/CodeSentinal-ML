"""
ml/model.py
-----------
ML Risk Classification Engine

Uses TF-IDF vectorization + Logistic Regression to classify code snippets
into: Safe | Medium Risk | High Risk

No generative AI or LLMs are used — this is a classic supervised ML pipeline.
"""

import os
import pandas as pd
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# ── File Paths ───────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH    = os.path.join(BASE_DIR, 'dataset.csv')
MODEL_PATH      = os.path.join(BASE_DIR, 'trained_model.pkl')
VECTORIZER_PATH = os.path.join(BASE_DIR, 'vectorizer.pkl')

# ── Training ─────────────────────────────────────────────────────────────

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

    # Drop rows with missing values
    df = df.dropna(subset=['code', 'label'])

    # 2. Vectorise source code with TF-IDF
    #    max_features=2000 captures more vocabulary than before
    #    ngram_range=(1,2) captures pairs of tokens (e.g. "os.system", "eval user")
    vectorizer = TfidfVectorizer(
        max_features=2000,
        ngram_range=(1, 2),
        analyzer='word',
        token_pattern=r"(?u)\b\w[\w.]+\b"   # keep dots in tokens (os.system)
    )
    X = vectorizer.fit_transform(df['code'])
    y = df['label']

    # 3. Train Logistic Regression
    #    C=5 allows slightly more flexibility than default C=1
    model = LogisticRegression(
        random_state=42,
        max_iter=1000,
        C=5
    )
    model.fit(X, y)

    # 4. Save model and vectorizer
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
        - confidence  : float (0–100, confidence for the predicted class)
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

        # Vectorise input — use first 5000 chars to avoid memory issues on large files
        X_input = vectorizer.transform([code_snippet[:5000]])

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

        # Truncate each snippet to 5000 chars
        truncated = [s[:5000] for s in code_snippets]
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
