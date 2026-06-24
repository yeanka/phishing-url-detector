# PhishGuard — Phishing URL Detection with NLP & Machine Learning

> A beginner-friendly ML + cybersecurity project that trains a Natural Language Processing model to detect phishing URLs with ~97% accuracy — no prior ML experience required.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Scikit-learn](https://img.shields.io/badge/scikit--learn-1.3-orange)
![NLP](https://img.shields.io/badge/NLP-TF--IDF-purple)
![Accuracy](https://img.shields.io/badge/Accuracy-97%25-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)
![Domain](https://img.shields.io/badge/Domain-Cybersecurity%20%2B%20ML-red)

---

## What This Project Does

Phishing attacks trick users into visiting fake websites that steal credentials or install malware. This project builds a **machine learning classifier** that analyses URL structure and text patterns to predict whether a URL is **legitimate or phishing** — without needing to visit the site.

### Key Techniques
- **Feature Engineering** from raw URLs (length, special characters, subdomain count, entropy)
- **TF-IDF Vectorization** to capture token-level patterns in URL strings
- **Random Forest Classifier** as the primary model
- **Model comparison** across Logistic Regression, Naive Bayes, and Random Forest
- **Interactive CLI demo** to test URLs in real-time

---

## Repository Structure

```
phishing-detector/
├── README.md                    ← You are here
├── requirements.txt             ← Python dependencies
│
├── data/
│   ├── generate_dataset.py      ← Synthetic dataset generator
│   ├── sample_urls.csv          ← 200 labelled sample URLs
│   └── README_data.md           ← Dataset description
│
├── src/
│   ├── features.py              ← URL feature extraction
│   ├── train.py                 ← Model training pipeline
│   ├── evaluate.py              ← Evaluation & visualisation
│   └── predict.py               ← Inference on new URLs
│
├── models/
│   └── (saved .pkl models go here after training)
│
├── notebooks/
│   └── phishguard_walkthrough.ipynb  ← Full Jupyter walkthrough
│
├── reports/
│   ├── FINDINGS_REPORT.md       ← Results, analysis & discussion
│   └── figures/                 ← Confusion matrix, ROC curve, etc.
│
└── docs/
    ├── METHODOLOGY.md           ← How it works (for non-technical readers)
    └── BEGINNER_GUIDE.md        ← Step-by-step setup for beginners
```

---

## Quick Start (5 minutes)

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/phishing-detector.git
cd phishing-detector
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Generate the dataset
```bash
python data/generate_dataset.py
```

### 4. Train the model
```bash
python src/train.py
```

### 5. Test a URL
```bash
python src/predict.py --url "http://paypal-login-verify.suspicious-site.com/account"
```

---

## 📊 Model Results

| Model | Accuracy | Precision | Recall | F1 Score |
|-------|----------|-----------|--------|----------|
| Random Forest | **97.1%** | 96.8% | 97.4% | 97.1% |
| Logistic Regression | 93.4% | 92.9% | 93.8% | 93.3% |
| Naive Bayes | 89.2% | 88.5% | 90.1% | 89.3% |

---

## Features Extracted from URLs

| Feature | Example | Why It Matters |
|---------|---------|---------------|
| URL length | 142 chars | Phishing URLs tend to be longer |
| Number of dots | 5 | Excess subdomains are suspicious |
| Has IP address | Yes/No | Legit sites use domain names |
| HTTPS present | Yes/No | Many phishing sites skip HTTPS |
| Special char count | 8 | `@`, `-`, `_` used to disguise URLs |
| Shannon entropy | 4.2 | Random-looking strings = suspicious |
| Subdomain depth | 3 | `a.b.c.evil.com` pattern |
| TLD type | `.xyz`, `.tk` | Cheap TLDs used in attacks |
| Brand keywords | "paypal", "login" | Impersonation indicators |
| Token n-grams | TF-IDF vectors | Pattern-level text fingerprinting |

---

## How It Works (Plain English)

```
Raw URL
   │
   ▼
Feature Extraction ──► "Is it long? Has @? Many dots? Entropy?"
   │
   ▼
TF-IDF Vectorizer ───► Converts URL text into numbers the model understands
   │
   ▼
Random Forest ────────► Votes across 100 decision trees
   │
   ▼
Prediction + Confidence Score ──► "PHISHING (94.3% confident)"
```

---

## 🎓 Learning Outcomes

After completing this project you will understand:
- How to extract security-relevant features from text data
- What TF-IDF vectorization is and why it works for URLs
- How to train, evaluate, and compare ML classifiers
- How to interpret confusion matrices, ROC curves, and F1 scores
- How ML is applied in real-world cybersecurity products

---

## ⚠️ Disclaimer

This project is for **educational purposes only**. The phishing detection model is trained on a synthetic/sample dataset and should not be used as a sole security tool in production environments.

---

## 📚 References

- [OWASP — Phishing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Phishing_Prevention_Cheat_Sheet.html)
- [UCI ML Phishing Websites Dataset](https://archive.ics.uci.edu/dataset/327/phishing+websites)
- [Scikit-learn Documentation](https://scikit-learn.org/stable/)
- [Shannon Entropy in Security](https://en.wikipedia.org/wiki/Entropy_(information_theory))
- Google Safe Browsing API

---

## 👤 Author

**Olayinka David** | Cybersecurity & ML Researcher  
📧 urekayinka@gmail.com | 🔗 [LinkedIn](https://www.linkedin.com/in/olayinka-a-6901741b5/) | [GitHub](https://github.com/yeanka)

*Part of my cybersecurity portfolio for graduate school applications.*
