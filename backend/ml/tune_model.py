# -*- coding: utf-8 -*-
"""
ml/tune_model.py
----------------
Finds the best hyperparameters for the word+char TF-IDF + LR pipeline
using grid search. Run once to find optimal C and TF-IDF settings.

Usage:
    python backend/ml/tune_model.py
"""

import os
import sys
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, 'dataset.csv')

df = pd.read_csv(DATASET_PATH).dropna(subset=['code', 'label']).drop_duplicates(subset=['code'])
print(f"Samples: {len(df)}")
print(df['label'].value_counts())

X_train, X_test, y_train, y_test = train_test_split(
    df['code'], df['label'], test_size=0.20, random_state=42, stratify=df['label']
)

# Build the pipeline
word_vec = TfidfVectorizer(
    analyzer='word',
    token_pattern=r"(?u)\b\w[\w.]+\b",
    sublinear_tf=True,
    min_df=1,
    strip_accents='unicode',
)
char_vec = TfidfVectorizer(
    analyzer='char_wb',
    sublinear_tf=True,
    min_df=1,
)
features = FeatureUnion([('word', word_vec), ('char', char_vec)])
clf = LogisticRegression(max_iter=5000, class_weight='balanced', random_state=42, solver='lbfgs')

pipe = Pipeline([('features', features), ('clf', clf)])

param_grid = {
    'features__word__max_features': [3000, 5000],
    'features__word__ngram_range': [(1, 2), (1, 3)],
    'features__char__max_features': [1000, 2000, 3000],
    'features__char__ngram_range': [(2, 4), (2, 5), (3, 6)],
    'clf__C': [1, 5, 10, 20],
}

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
grid = GridSearchCV(pipe, param_grid, cv=cv, scoring='accuracy', n_jobs=1, verbose=1)
grid.fit(X_train, y_train)

print(f"\nBest CV Accuracy: {grid.best_score_:.4f}")
print(f"Best params: {grid.best_params_}")

y_pred = grid.predict(X_test)
print(f"\nTest Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(classification_report(y_test, y_pred))
