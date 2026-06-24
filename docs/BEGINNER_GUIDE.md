# 🚀 Beginner's Guide — Getting PhishGuard Running

No ML experience required. This guide walks you through every step.

---

## What You'll Need

- A computer with Python installed (Windows, Mac, or Linux)
- An internet connection (for installing packages)
- About 15 minutes

---

## Step 1: Install Python

Check if Python is already installed:
```bash
python --version
# Should show Python 3.10 or higher
```

If not, download it from **python.org** → Downloads → Python 3.11.

---

## Step 2: Get the Project

```bash
git clone https://github.com/YOUR_USERNAME/phishing-detector.git
cd phishing-detector
```

Or download the ZIP from GitHub and unzip it.

---

## Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `scikit-learn` — the machine learning library
- `pandas` — for data handling
- `numpy` — for numerical operations

---

## Step 4: Generate the Training Data

```bash
python data/generate_dataset.py
```

You'll see output like:
```
✅ Dataset saved → data/urls_dataset.csv
   Total URLs  : 1000
   Legitimate  : 500
   Phishing    : 500
```

A file `data/urls_dataset.csv` is created with 1,000 labelled URLs.

---

## Step 5: Train the Model

```bash
python src/train.py
```

The model will:
1. Load the dataset
2. Extract 28 features from each URL
3. Train a Random Forest classifier
4. Show you accuracy results
5. Save the model to `models/phishguard_model.pkl`

Training takes about 10–30 seconds depending on your computer.

---

## Step 6: Test a URL

```bash
python src/predict.py --url "http://paypal-login-verify.xyz/confirm.php"
```

Output:
```
──────────────────────────────────────────────────────────
  URL: http://paypal-login-verify.xyz/confirm.php
──────────────────────────────────────────────────────────
  🎣 Verdict    : PHISHING
  📊 Confidence : 96.3%
  🟢 Legit prob : 3.7%
  🔴 Phish prob : 96.3%

  Key signals:
    ⚠️  Contains 3 brand/phishing keywords (e.g. 'paypal', 'verify')
    ⚠️  Uses a suspicious top-level domain (.xyz, .tk, etc.)
    ⚠️  Many hyphens (3) — common in fake domains
──────────────────────────────────────────────────────────
```

---

## Step 7: Try Interactive Mode

```bash
python src/predict.py --interactive
```

Type any URL and press Enter to analyse it. Type `quit` to exit.

---

## Understanding the Results

| Term | Meaning |
|------|---------|
| **Verdict** | PHISHING or LEGITIMATE |
| **Confidence** | How sure the model is (higher = more certain) |
| **Phish prob** | Probability the URL is a phishing attempt |
| **Key signals** | Specific reasons the model made its decision |

---

## Common Questions

**Q: What if I get "Module not found"?**
Run `pip install -r requirements.txt` again.

**Q: What if training fails?**
Make sure you ran `generate_dataset.py` first to create the data file.

**Q: Can I test my own URLs?**
Yes! Use `--url` or `--interactive` mode with any URL you want to check.

**Q: Why is it sometimes wrong?**
No ML model is perfect. This one achieves ~97% accuracy, meaning about 3 in 100 URLs may be misclassified. See the Findings Report for a full error analysis.

---

## Project Files Explained

| File | What it does |
|------|-------------|
| `data/generate_dataset.py` | Creates the training data |
| `src/features.py` | Extracts 28 features from each URL |
| `src/train.py` | Trains the ML model |
| `src/predict.py` | Uses the trained model to classify new URLs |
| `reports/FINDINGS_REPORT.md` | Full research analysis and results |

---

*Still stuck? Open an issue on the GitHub repository.*
