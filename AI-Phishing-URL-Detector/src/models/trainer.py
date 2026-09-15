"""
Model Training & Evaluation Pipeline for AI-Powered Phishing URL Detector.

Trains an ensemble Random Forest classifier on extracted URL feature vectors,
evaluates precision, recall, F1, ROC-AUC, confusion matrix, and serializes
the production model artifact and metrics.
"""

import os
import sys
import csv
import json
import time
from typing import Dict, Any, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

from src.features.extractor import FeatureExtractor
from src.data.generate_dataset import create_dataset_file


def load_dataset(csv_path: str) -> Tuple[np.ndarray, np.ndarray]:
    """
    Loads URLs and labels from CSV, extracts feature vectors, and returns X and y.
    """
    if not os.path.exists(csv_path):
        print(f"[*] Dataset not found at {csv_path}, generating fresh dataset...")
        create_dataset_file(csv_path, total_samples=6000)

    print(f"[*] Reading dataset from: {csv_path}")
    urls = []
    labels = []
    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row["url"])
            labels.append(int(row["label"]))

    print(f"[*] Extracting features for {len(urls)} URLs...")
    start_time = time.time()
    feature_matrix = []
    for url in urls:
        vec = FeatureExtractor.extract_vector(url)
        feature_matrix.append(vec)

    duration = time.time() - start_time
    print(f"[+] Feature extraction completed in {duration:.2f}s")
    return np.array(feature_matrix, dtype=np.float32), np.array(labels, dtype=np.int32)


def train_and_evaluate(
    csv_path: str = None,
    output_model_path: str = None,
    output_metrics_path: str = None
) -> Dict[str, Any]:
    """
    Runs the full model training and evaluation lifecycle.
    """
    if csv_path is None:
        csv_path = os.path.join(PROJECT_ROOT, "src", "data", "dataset.csv")
    if output_model_path is None:
        output_model_path = os.path.join(PROJECT_ROOT, "saved_models", "phishing_detector.pkl")
    if output_metrics_path is None:
        output_metrics_path = os.path.join(PROJECT_ROOT, "saved_models", "model_metrics.json")

    os.makedirs(os.path.dirname(output_model_path), exist_ok=True)

    X, y = load_dataset(csv_path)

    print(f"[*] Splitting dataset: 80% Train, 20% Test (Stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[*] Training Random Forest Classifier (n_estimators=100)...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    print(f"[*] Evaluating model on test set ({len(y_test)} samples)...")
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    auc = float(roc_auc_score(y_test, y_proba))
    cm = confusion_matrix(y_test, y_pred).tolist()

    # Feature Importance ranking
    importances = model.feature_importances_
    feat_names = FeatureExtractor.FEATURE_NAMES
    sorted_idx = np.argsort(importances)[::-1]
    feature_ranking = [
        {"feature": feat_names[i], "importance": round(float(importances[i]), 4)}
        for i in sorted_idx
    ]

    metrics_report = {
        "model_type": "RandomForestClassifier",
        "dataset_size": len(y),
        "test_size": len(y_test),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(auc, 4),
        "confusion_matrix": {
            "true_negatives": cm[0][0],
            "false_positives": cm[0][1],
            "false_negatives": cm[1][0],
            "true_positives": cm[1][1]
        },
        "feature_importances": feature_ranking,
        "feature_names": feat_names
    }

    # Save trained model
    joblib.dump(model, output_model_path)
    print(f"[+] Model saved to: {output_model_path}")

    # Save metrics JSON
    with open(output_metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics_report, f, indent=2)
    print(f"[+] Metrics saved to: {output_metrics_path}")

    # Print summary table
    print("\n" + "=" * 55)
    print("      AI PHISHING URL DETECTOR - EVALUATION REPORT")
    print("=" * 55)
    print(f" Accuracy : {acc * 100:.2f}%")
    print(f" Precision: {prec * 100:.2f}%")
    print(f" Recall   : {rec * 100:.2f}%")
    print(f" F1-Score : {f1 * 100:.2f}%")
    print(f" ROC-AUC  : {auc * 100:.2f}%")
    print("-" * 55)
    print(f" Confusion Matrix:")
    print(f"  [TN: {cm[0][0]}  |  FP: {cm[0][1]}]")
    print(f"  [FN: {cm[1][0]}  |  TP: {cm[1][1]}]")
    print("-" * 55)
    print(" Top 5 Discriminative Features:")
    for item in feature_ranking[:5]:
        print(f"  • {item['feature'].ljust(25)} : {item['importance'] * 100:.2f}%")
    print("=" * 55 + "\n")

    return metrics_report


if __name__ == "__main__":
    train_and_evaluate()
