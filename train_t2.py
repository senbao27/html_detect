
"""
Train a T2 URL classifier:
- Input CSV must have columns: url, type
- Label mapping: benign -> 0 (safe), everything else -> 1 (unsafe)
- Model: Tfidf(char 3-5) + SGDClassifier(log_loss)  (fast, robust, probabilities)
- Outputs: url_model.joblib (pipeline), metrics.json
"""

import argparse, json, os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import roc_auc_score, average_precision_score, confusion_matrix
from sklearn.calibration import CalibratedClassifierCV
from joblib import dump
from datetime import datetime

def build_pipeline(max_features=300000):
    vect = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3,5),
        min_df=2,
        max_features=max_features,
        lowercase=True,
        strip_accents="unicode",
        sublinear_tf=True,
    )
    # Fast linear classifier with log_loss approximating logistic regression
    base = SGDClassifier(
        loss="log_loss",      # probabilistic outputs via predict_proba in CalibratedCV
        class_weight="balanced",
        max_iter=30,
        tol=1e-3,
        random_state=42,
    )
    # Calibrate for better probability estimates (sigmoid/Platt)
    clf = CalibratedClassifierCV(base, method="sigmoid", cv=3)
    pipe = Pipeline([
        ("tfidf", vect),
        ("clf", clf),
    ])
    return pipe

def compute_tpr_at_fpr(y_true, y_score, target_fpr=0.001):
    # Sort by score descending
    order = np.argsort(-y_score)
    y_true = np.asarray(y_true)[order]
    y_score = np.asarray(y_score)[order]
    P = y_true.sum()
    N = len(y_true) - P
    fp = 0
    tp = 0
    best_tpr = 0.0
    best_thresh = 1.0
    prev_score = None
    for i, s in enumerate(y_score):
        if prev_score is None or s != prev_score:
            # At this threshold, FPR = fp/N
            fpr = fp / max(N, 1)
            tpr = tp / max(P, 1)
            if fpr <= target_fpr and tpr > best_tpr:
                best_tpr = tpr
                best_thresh = s
            prev_score = s
        # include this sample
        if y_true[i] == 1:
            tp += 1
        else:
            fp += 1
    # final check at the lowest threshold
    fpr = fp / max(N, 1)
    tpr = tp / max(P, 1)
    if fpr <= target_fpr and tpr > best_tpr:
        best_tpr = tpr
        best_thresh = y_score[-1]
    return float(best_tpr), float(best_thresh)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="/mnt/data/malicious_phish.csv", help="path to CSV with columns: url,type")
    ap.add_argument("--out", default="/mnt/data/url_model.joblib", help="output joblib path")
    ap.add_argument("--metrics", default="/mnt/data/metrics.json", help="metrics output json path")
    ap.add_argument("--max_features", type=int, default=300000, help="TF-IDF max features")
    ap.add_argument("--test_size", type=float, default=0.2, help="test size for split")
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    if "url" not in df.columns or "type" not in df.columns:
        raise ValueError("CSV must contain columns: url, type")

    # Label mapping: benign -> 0, others -> 1
    y = (df["type"].astype(str).str.lower() != "benign").astype(int).values
    X = df["url"].astype(str).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )

    pipe = build_pipeline(max_features=args.max_features)
    pipe.fit(X_train, y_train)

    # Evaluate
    # CalibratedClassifierCV exposes predict_proba
    y_prob = pipe.predict_proba(X_test)[:,1]
    roc = roc_auc_score(y_test, y_prob)
    pr = average_precision_score(y_test, y_prob)

    # Default threshold 0.5
    y_pred = (y_prob >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel().tolist()
    tpr = tp / max(tp+fn,1)
    fpr = fp / max(fp+tn,1)

    # TPR at very low FPR (e.g., 0.1%)
    tpr001, thr001 = compute_tpr_at_fpr(y_test, y_prob, target_fpr=0.001)

    metrics = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "roc_auc": float(roc),
        "pr_auc": float(pr),
        "threshold_default": 0.5,
        "confusion_default": {"tn": tn, "fp": fp, "fn": fn, "tp": tp, "tpr": float(tpr), "fpr": float(fpr)},
        "tpr_at_fpr_0.1%": {"tpr": tpr001, "threshold": thr001},
        "label_mapping": {"benign": 0, "others": 1},
    }
    os.makedirs(os.path.dirname(args.metrics), exist_ok=True)
    with open(args.metrics, "w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)

    dump(pipe, args.out)
    print(f"[OK] Saved model to {args.out}")
    print(f"[OK] Saved metrics to {args.metrics}")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
