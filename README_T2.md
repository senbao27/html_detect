# T2 URL Classifier (Training)

This script trains a **T2** classifier for URLs using the dataset at `malicious_phish.csv`.

## Label policy
- `benign` → **0** (safe)
- **everything else** (e.g., `phishing`, `defacement`, `malware`) → **1** (unsafe)

## Model
- `TfidfVectorizer` (char 3–5 n-grams) → `SGDClassifier(loss="log_loss")`  
- Calibrated with Platt scaling for probability outputs
- Fast, works well as a strong lexical baseline for URLs

## Outputs
- `url_model.joblib` – scikit-learn Pipeline (vectorizer + calibrated classifier)
- `metrics.json` – basic metrics: ROC AUC, PR AUC, confusion matrix at 0.5, TPR@FPR=0.1%

