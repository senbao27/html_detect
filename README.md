# T1 URL Scorer (Rules, No Network)

This module assigns a **rule-based risk score** to a URL using only lexical/structural features (no DNS/HTTP). Fast, deterministic, and ideal as a primary guardrail + input to T2 blending.

## Inputs

* Absolute URL string (`http://` or `https://`).
* Internal config:
  `OFFICIAL_DOMAINS` (eTLD+1 allowlist), `TRUSTED_PUBLIC_SUFFIXES` (e.g., `.gov.au`, `.edu.au`), UGC hosts/patterns, risk keywords, suspicious TLDs, brand tokens.

## Output (per URL)

* `official` — `true/false` (early exit to `risk=0.0` when official & not UGC).
* `etld1` — eTLD+1.
* `risk` — **T1** rule score in `[0,1]`.
* `reasons` — brief, deduped flags (human-readable).

## Signals (no network)

* **UGC platform** (forms/file-sharing/site-builders; specific Google subdomains/paths).
* **Brand similarity** (hostname vs known brand tokens).
* **Punycode** (`xn--`, possible homograph).
* **Risky keywords** in path/query (e.g., `login`, `verify`, `refund`, `bank`, …).
* **Suspicious TLD** (e.g., `zip`, `top`, `xyz`, `gq`, `click`, …).
* **Deep subdomain** (≥3 labels before eTLD+1; excludes trusted public suffixes).
* **IP host**, **‘@’ in URL**, **very long URL**, **many hyphens in host**.

## Scoring

* Weighted linear combo of the above signals → normalized to `[0,1]` (sigmoid).
* Reasons ordered with UGC first, then Punycode, then others.

## Blend with T2

* For **non-official** URLs (when T2 is loaded):
  *  risk — Rule-based URL risk (0–1).
  * `risk_t2` — Model risk (0–1, only for non-official URLs when model is loaded).
  * `risk_blended` — `0.6*risk + 0.4*risk_t2`.
  * sender.score — Sender/header risk (0–1).
  * content.score — Email/message body risk (0–1).
* Message/email endpoints compute `overall_risk` from **sender/content/url** with dynamic weights and a hard gate (overall ≥ worst URL).

## Suggested thresholds (0–1)

* `< 0.20` → **Safe**
* `0.20 – 0.60` → **Caution** (step-up / warn)
* `≥ 0.60` → **High risk** (block)

# T2 URL Classifier (Training)

This script trains a **T2** classifier for URLs using the dataset at `malicious_phish.csv`.

## Label policy
- `benign` → **0** (safe)
- **everything else** (e.g., `phishing`, `defacement`, `malware`) → **1** (unsafe)

## Model
- `TfidfVectorizer` (char 3–5 n-grams) → `SGDClassifier(loss="log_loss")`  
- Calibrated with Platt scaling for probability outputs
- Fast, works well as a strong lexical baseline for URLs


