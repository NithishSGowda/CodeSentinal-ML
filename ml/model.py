import os
import pandas as pd
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, 'dataset.csv')
MODEL_PATH = os.path.join(BASE_DIR, 'trained_model.pkl')
VECTORIZER_PATH = os.path.join(BASE_DIR, 'vectorizer.pkl')

def train_model(force=False):
    """
    Train the ML model to classify source code snippets.
    Saves the trained model and vectorizer to disk.
    """
    # Skip training if models already exist and we are not forcing a retrain
    if not force and os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        return True

    print("[ML_CORE] Training Code Risk Classifier...")
    
    # 1. Load Dataset
    if not os.path.exists(DATASET_PATH):
        print(f"[ML_CORE_ERROR] Dataset not found at {DATASET_PATH}")
        return False
        
    df = pd.read_csv(DATASET_PATH)
    
    # 2. Extract Features using TF-IDF
    vectorizer = TfidfVectorizer(max_features=1000)
    X = vectorizer.fit_transform(df['code'])
    y = df['label']
    
    # 3. Train Logistic Regression Model
    model = LogisticRegression(random_state=42, max_iter=1000)
    model.fit(X, y)
    
    # 4. Save Model and Vectorizer
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
        
    with open(VECTORIZER_PATH, 'wb') as f:
        pickle.dump(vectorizer, f)
        
    print("[ML_CORE] Training Complete. Model saved successfully.")
    return True

def predict_risk(code_snippet):
    """
    Predict the risk level of a given code snippet.
    Returns the predicted label and confidence scores.
    """
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        train_model()
        
    try:
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
            
        with open(VECTORIZER_PATH, 'rb') as f:
            vectorizer = pickle.load(f)
            
        # Vectorize input
        X_input = vectorizer.transform([code_snippet])
        
        # Predict
        prediction = model.predict(X_input)[0]
        
        # Get confidence probabilities
        probabilities = model.predict_proba(X_input)[0]
        classes = model.classes_
        
        confidence_scores = {classes[i]: round(prob * 100, 2) for i, prob in enumerate(probabilities)}
        
        return {
            "prediction": prediction,
            "confidence": confidence_scores.get(prediction, 0.0),
            "all_scores": confidence_scores
        }
    except Exception as e:
        print(f"[ML_CORE_ERROR] Prediction failed: {e}")
        return {
            "prediction": "Unknown",
            "confidence": 0.0,
            "all_scores": {}
        }
