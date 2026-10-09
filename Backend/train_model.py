"""
LinkShield - Machine Learning Training Pipeline

Purpose:
    Train a RandomForestClassifier on labeled phishing and legitimate URLs,
    evaluate model performance (Accuracy, Precision, Recall, F1),
    and save the trained model artifact to Backend/analysis/phishing_model.pkl.
"""

import sys
import os
import csv
import io
import urllib.request
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score

# Ensure analysis package is importable
CURRENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CURRENT_DIR))

from analysis.ml_model import extract_features, FEATURE_NAMES, MODEL_PATH

DATASET_URL = (
    "https://huggingface.co/datasets/Mitake/PhishingURLsANDBenignURLs/resolve/main/PhishBenignDataset.csv"
)

def fetch_and_prepare_dataset(sample_size_per_class: int = 15000):
    """
    Stream and collect a balanced dataset from the online repository.
    """
    print(f"[*] Fetching dataset from Hugging Face ({DATASET_URL})...")
    req = urllib.request.Request(
        DATASET_URL,
        headers={"User-Agent": "Mozilla/5.0 (LinkShield-ML-Trainer)"}
    )

    benign_samples = []
    phish_samples = []

    with urllib.request.urlopen(req, timeout=30) as response:
        # Stream lines to avoid reading all 42MB at once if not needed
        reader = csv.reader(io.TextIOWrapper(response, encoding="utf-8", errors="ignore"))
        header = next(reader, None)
        print(f"[*] Dataset Header: {header}")

        for row in reader:
            if len(row) < 2:
                continue
            url = row[0].strip()
            label_str = row[1].strip()

            try:
                label = int(label_str)
            except ValueError:
                continue

            if label == 0 and len(benign_samples) < sample_size_per_class:
                benign_samples.append((url, 0))
            elif label == 1 and len(phish_samples) < sample_size_per_class:
                phish_samples.append((url, 1))

            if len(benign_samples) >= sample_size_per_class and len(phish_samples) >= sample_size_per_class:
                break

    print(f"[+] Downloaded {len(benign_samples)} legitimate URLs and {len(phish_samples)} phishing URLs.")
    all_data = benign_samples + phish_samples
    np.random.seed(42)
    np.random.shuffle(all_data)
    return all_data


def train():
    print("=" * 60)
    print("LINKSHIELD AI/ML PHISHING CLASSIFIER - TRAINING PIPELINE")
    print("=" * 60)

    data = fetch_and_prepare_dataset(sample_size_per_class=15000)

    print(f"[*] Extracting features ({len(FEATURE_NAMES)} features per URL)...")
    X = []
    y = []

    for idx, (url, label) in enumerate(data):
        features = extract_features(url)
        X.append(features)
        y.append(label)

    X = np.array(X, dtype=np.float64)
    y = np.array(y, dtype=np.int64)

    print(f"[*] Dataset matrix shape: {X.shape}")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"[*] Training RandomForestClassifier on {len(X_train)} samples...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    print("[*] Evaluating on test set...")
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("\n--- Model Evaluation Metrics ---")
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall:    {rec * 100:.2f}%")
    print(f"F1-Score:  {f1 * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # Save model artifact
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_PATH, compress=3)
    print(f"[✓] Successfully saved trained model artifact to {MODEL_PATH}")

    # Feature Importance
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("\nTop Feature Importances:")
    for rank, idx in enumerate(sorted_idx[:8], 1):
        print(f"  {rank}. {FEATURE_NAMES[idx]}: {importances[idx]:.4f}")

    # Validation tests
    test_urls = [
        "https://www.google.com",
        "https://github.com/codeaditi25/PHISHGUARD",
        "http://192.168.1.1/secure-login/verify.php?account=update",
        "http://paypal-account-update-security-check.xyz/login.html",
    ]
    print("\nSample Inferences:")
    for u in test_urls:
        feats = np.array([extract_features(u)], dtype=np.float64)
        prob = clf.predict_proba(feats)[0][1]
        print(f"  URL: {u}")
        print(f"  -> Phishing Probability: {prob:.4f} (Score: {int(round(prob*100))}/100)")


if __name__ == "__main__":
    train()
