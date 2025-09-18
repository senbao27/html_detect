# T2 URL Classifier (Training)

This script trains a **T2** classifier for URLs using the dataset at `malicious_phish.csv`.

## Label policy
- `benign` → **0** (safe)
- **everything else** (e.g., `phishing`, `defacement`, `malware`) → **1** (unsafe)

## Model
- `TfidfVectorizer` (char 3–5 n-grams) → `SGDClassifier(loss="log_loss")`  
- Calibrated with Platt scaling for probability outputs
- Fast, works well as a strong lexical baseline for URLs

## Scores
- sender.score — Sender/header risk (0–1).
- content.score — Email/message body risk (0–1).

- URL risk (per link)
- risk — Rule-based URL risk (0–1).
- risk_t2 — Model risk (0–1, only for non-official URLs when model is loaded).
- risk_blended — 0.6*risk + 0.4*risk_t2 (non-official URLs only).
- overall_risk — Final message/email risk (0–1). Use this for message-level decisions.

- Suggested thresholds (for any 0–1 score)
- < 0.20 → Safe
- 0.20 – 0.60 → Caution (step-up or warn)
- ≥ 0.60 → High risk (block)

