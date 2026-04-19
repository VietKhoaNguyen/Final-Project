# Low-Entropy Attacks on 6-Digit PINs

This repository contains the implementation for a bachelor thesis project on analyzing the security of human-chosen 6-digit PINs under low-entropy attacks.

---

## 📌 Project Overview

Although a 6-digit PIN has a theoretical space of 1,000,000 combinations, real users do not choose PINs uniformly at random. Instead, they prefer predictable and memorable patterns such as:

* Birthdates (e.g., DDMMYY)
* Repeated digits (e.g., 111111)
* Sequential numbers (e.g., 123456)
* Culturally significant numbers

This project models realistic PIN distributions and evaluates how different attack strategies can exploit these patterns under limited guessing attempts.

---

## 🎯 Objectives

* Model realistic (human-biased) PIN distributions
* Simulate multiple PIN guessing strategies
* Evaluate attack success under limited attempts (Top-k)
* Analyze entropy-based security metrics
* Study the impact of personal-information leakage (e.g., date of birth)

---

## 🧠 System Pipeline

The system follows a full experimental pipeline:

1. Generate PIN dataset

   * Uniform
   * Biased (human behavior)
   * Leakage-based (with DOB)

2. Compute frequency distribution

3. Compute security metrics

   * Shannon Entropy
   * Min-Entropy
   * Expected Number of Guesses

4. Simulate attack strategies

   * Random
   * Frequency-ranked
   * Rule-based
   * Leakage-assisted

5. Evaluate Top-k success rates

6. Compare across models

7. Generate plots and summary tables

---

## ⚙️ Project Structure

```text
Final_Project/
│
├── src/
│   ├── pin_generator.py     # PIN generation logic
│   ├── analysis.py          # Frequency + entropy + metrics
│   ├── attack.py            # Attack strategies
│   ├── plot.py              # Visualization
│
├── data/                    # Generated datasets
├── results/                 # Frequencies, summaries, plots
│
├── main.py                  # Main pipeline (CLI-supported)
├── README.md
└── requirements.txt
```

---

## 🔢 PIN Generation Models

### 1. Uniform Model

* Randomly generates PINs
* Represents ideal secure behavior

### 2. Biased Model

* Simulates human behavior using weighted patterns:

  * Birthdates
  * Repeated digits
  * Sequential numbers
  * Significant numbers
* Supports survey-based weights

### 3. Leakage Model

* Incorporates personal information (DOB)
* Generates candidate PINs derived from DOB
* Boosts probability of those PINs
* Simulates real-world information leakage

---

## ⚔️ Attack Strategies

### 1. Random Attack

* Random guess order
* Baseline strategy

### 2. Frequency-Ranked Attack

* Guess PINs in descending probability order
* Optimal when distribution is known

### 3. Rule-Based Attack

Prioritizes common human patterns:

* Repeated digits
* Sequential patterns
* Date-like PINs
* Significant numbers

### 4. Leakage-Assisted Attack

* Uses leaked personal information (DOB)
* Prioritizes candidate PINs derived from DOB
* Then continues with frequency-ranked guesses

---

## 📊 Evaluation Metrics

The system computes:

### 🔹 Shannon Entropy

* Measures average uncertainty of the distribution

### 🔹 Min-Entropy

* Measures worst-case predictability
* Focuses on the most likely PIN

### 🔹 Expected Number of Guesses

* Average number of attempts required to guess correctly

---

## 📈 Outputs & Visualization

### 📌 Summary Table

Stored at:

```text
results/summary_all_models.csv
```

Includes:

* Entropy metrics
* Attack success (Top-1, Top-3, Top-5, Top-10)

---

### 📊 Generated Plots

* Entropy comparison
* Min-entropy comparison
* Expected guesses comparison
* Attack success comparison (Top-k)
* Rank-probability curves (log-log)
* Combined rank curves across models
* Cumulative success curves
* Entropy vs attack success

---

## 🚀 How to Run

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 2. Run default (all models)

```bash
python main.py
```

---

### 3. Run a single model

```bash
python main.py --run_mode one --model biased
```

---

### 4. Run leakage model with custom DOB

```bash
python main.py --run_mode one --model leakage --dob 2005-02-09
```

---

### 5. Change dataset size

```bash
python main.py --n 50000
```

---

## 🔧 Configuration Options

| Argument               | Description                          |
| ---------------------- | ------------------------------------ |
| `--run_mode`           | `"one"` or `"all"`                   |
| `--model`              | `"uniform"`, `"biased"`, `"leakage"` |
| `--dob`                | Date of birth (YYYY-MM-DD)           |
| `--n`                  | Dataset size                         |
| `--seed`               | Random seed                          |
| `--use_survey_weights` | Enable survey-based weights          |

---

## 🧪 Example Research Questions

* How much does human bias reduce PIN entropy?
* How effective is a frequency-ranked attack vs random?
* How much does leakage (DOB) improve attack success?
* What is the relationship between entropy and guessability?

---

## 📚 Technologies Used

* Python
* Pandas
* Matplotlib

---

## 👤 Author

Nguyễn Việt Khoa
Bachelor Thesis – ICT
University of Science and Technology of Hanoi

---

## 📌 Notes

* This project is intended for academic research purposes only
* It aims to understand weaknesses in human-chosen PINs
* It is not intended for real-world exploitation

---
