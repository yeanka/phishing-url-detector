"""
PhishGuard — Model Training Pipeline
======================================
Trains and compares three classifiers on URL features + TF-IDF:
  1. Random Forest (primary model)
  2. Logistic Regression
  3. Naive Bayes

Saves the best model to models/phishguard_model.pkl

Usage:
    python src/train.py
    python src/train.py --data data/urls_dataset.csv --output models/
"""

import os
import sys
import pickle
import argparse
import warnings
warnings.filterwarnings("ignore")

import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, roc_auc_score
)
from sklearn.base import BaseEstimator, TransformerMixin
import scipy.sparse as sp

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.features import extract_features_batch, get_feature_names


# ── Custom Transformers ────────────────────────────────────────────────────────

class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    """Sklearn-compatible transformer that extracts numerical features from URLs."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        feature_dicts = extract_features_batch(list(X))
        feature_names = get_feature_names()
        matrix = [[d[f] for f in feature_names] for d in feature_dicts]
        return np.array(matrix, dtype=float)


class URLTextExtractor(BaseEstimator, TransformerMixin):
    """Passes raw URL strings through for TF-IDF processing."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return list(X)


# ── Training Function ──────────────────────────────────────────────────────────

def load_data(filepath: str):
    """Load and validate the URL dataset."""
    print(f"[*] Loading dataset: {filepath}")
    df = pd.read_csv(filepath)
    assert "url" in df.columns and "label" in df.columns, \
        "Dataset must have 'url' and 'label' columns"

    print(f"    Total samples : {len(df)}")
    print(f"    Legitimate    : {(df.label == 0).sum()}")
    print(f"    Phishing      : {(df.label == 1).sum()}")
    return df["url"].values, df["label"].values


def build_pipeline(classifier):
    """
    Build a full sklearn Pipeline combining:
    - Numerical URL features (length, entropy, etc.)
    - TF-IDF character n-grams from the URL string
    """
    # TF-IDF on URL characters (3-5 char n-grams capture patterns like "login", "verify")
    tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=3000,
        sublinear_tf=True,
    )

    # Combine feature types
    feature_union = FeatureUnion([
        ("tfidf", Pipeline([
            ("extract_text", URLTextExtractor()),
            ("tfidf_vec",    tfidf),
        ])),
        ("numeric", Pipeline([
            ("extract_feats", URLFeatureExtractor()),
            ("scaler",        MinMaxScaler()),
        ])),
    ])

    return Pipeline([
        ("features",   feature_union),
        ("classifier", classifier),
    ])


def train_and_evaluate(X_train, X_test, y_train, y_test, name, classifier):
    """Train a classifier and print its evaluation metrics."""
    print(f"\n{'─'*50}")
    print(f"  Training: {name}")
    print(f"{'─'*50}")

    pipeline = build_pipeline(classifier)
    pipeline.fit(X_train, y_train)

    y_pred  = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1] if hasattr(classifier, "predict_proba") else None

    acc    = accuracy_score(y_test, y_pred)
    roc    = roc_auc_score(y_test, y_proba) if y_proba is not None else None
    report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])
    cm     = confusion_matrix(y_test, y_pred)

    print(f"  Accuracy : {acc:.4f} ({acc*100:.1f}%)")
    if roc:
        print(f"  ROC-AUC  : {roc:.4f}")
    print(f"\n{report}")
    print(f"  Confusion Matrix:")
    print(f"    TN={cm[0,0]}  FP={cm[0,1]}")
    print(f"    FN={cm[1,0]}  TP={cm[1,1]}")

    return pipeline, acc, roc


def main(data_path="data/urls_dataset.csv", output_dir="models/"):
    print("\n" + "="*60)
    print("  PhishGuard — Model Training Pipeline")
    print("="*60)

    # ── Load data ────────────────────────────────────────────────
    X, y = load_data(data_path)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n[*] Train size : {len(X_train)}")
    print(f"[*] Test size  : {len(X_test)}")

    # ── Define classifiers ───────────────────────────────────────
    classifiers = {
        "Random Forest": RandomForestClassifier(
            n_estimators=100, max_depth=20,
            random_state=42, n_jobs=-1
        ),
        "Logistic Regression": LogisticRegression(
            max_iter=1000, C=1.0, random_state=42
        ),
    }

    # ── Train & compare ──────────────────────────────────────────
    results = {}
    for name, clf in classifiers.items():
        pipeline, acc, roc = train_and_evaluate(
            X_train, X_test, y_train, y_test, name, clf
        )
        results[name] = {"pipeline": pipeline, "accuracy": acc, "roc": roc}

    # ── Pick best model ──────────────────────────────────────────
    best_name = max(results, key=lambda k: results[k]["accuracy"])
    best      = results[best_name]
    print(f"\n{'='*60}")
    print(f"  🏆 Best model: {best_name}")
    print(f"     Accuracy : {best['accuracy']*100:.1f}%")
    print(f"     ROC-AUC  : {best['roc']:.4f}" if best["roc"] else "")
    print(f"{'='*60}")

    # ── Save model ───────────────────────────────────────────────
    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, "phishguard_model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(best["pipeline"], f)
    print(f"\n[+] Model saved → {model_path}")

    # Save metadata
    meta_path = os.path.join(output_dir, "model_meta.txt")
    with open(meta_path, "w") as f:
        f.write(f"Best Model   : {best_name}\n")
        f.write(f"Accuracy     : {best['accuracy']*100:.2f}%\n")
        f.write(f"ROC-AUC      : {best['roc']:.4f}\n" if best["roc"] else "")
        f.write(f"Train samples: {len(X_train)}\n")
        f.write(f"Test samples : {len(X_test)}\n")
    print(f"[+] Metadata  → {meta_path}")
    print(f"\n[*] Run prediction with:")
    print(f"    python src/predict.py --url \"http://suspicious-site.xyz/login\"")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhishGuard — Train the URL classifier")
    parser.add_argument("--data",   default="data/urls_dataset.csv", help="Path to labelled CSV dataset")
    parser.add_argument("--output", default="models/",               help="Directory to save the trained model")
    args = parser.parse_args()
    main(data_path=args.data, output_dir=args.output)
