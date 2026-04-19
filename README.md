# Low-Entropy Attacks on 6-Digit PINs

This repository contains the implementation for a bachelor thesis project on analyzing the security of human-chosen 6-digit PINs under low-entropy attacks.

---

## 📌 Project Overview

Although a 6-digit PIN has a theoretical space of 1,000,000 combinations, real users do not choose PINs uniformly at random. Instead, they prefer memorable patterns such as:

* Birthdates
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

The system follows a complete experimental pipeline:

1. Generate PIN dataset (uniform / biased / leakage)
2. Compute frequency distribution
3. Compute security metrics:

   * Shannon Entropy
   * Min-Entropy
   * Expected Number of Guesses
4. Simulate attacks:

   * Random
   * Frequency-ranked
   * Rule-based
   * Leakage-assisted
5. Evaluate Top-k success rates
6. Compare across models
7. Generate plots and summary tables

---

## ⚙️ Project Structure

```
Final_Project/
│
├── src/
│   ├── pin_generator.py     # PIN generation (uniform, biased, leakage)
│   ├── analysis.py          # Frequency + entropy + metrics
│   ├── attack.py            # Attack strategies + evaluation
│   ├── plot.py              # Visualization & plotting
│
├── data/                    # Generated datasets
├── results/                 # Output results + plots
│
├── main.py                  # Main pipeline
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
  * Sequential patterns
  * Significant numbers
* Supports survey-based weights

### 3. Leakage Model

* Incorporates personal information (e.g., date of birth)
* Boosts probability of DOB-related PINs
* Simulates real-world data leakage scenarios

---

## ⚔️ Attack Strategies

### 1. Random Attack

* Random guess order
* Baseline strategy

### 2. Frequency-Ranked Attack

* Guess PINs in descending probability order
* Optimal strategy under known distribution

### 3. Rule-Based Attack

* Prioritizes human patterns:

  * Repeated digits
  * Sequential patterns
  * Date-like PINs
  * Significant numbers

### 4. Leakage-Assisted Attack

* Uses leaked personal information (DOB)
* Prioritizes candidate PINs derived from DOB
* Then falls back to frequency-ranked order

---

## 📊 Evaluation Metrics

The system computes:

* **Shannon Entropy**

  * Measures average uncertainty
* **Min-Entropy**

  * Measures worst-case predictability
* **Expected Number of Guesses**

  * Average effort required to guess correctly

---

## 📈 Output & Visualization

The system automatically generates:

### 📌 Summary Table

* Stored at:

```
results/summary_all_models.csv
```

### 📊 Plots

* Entropy comparison
* Min-entropy comparison
* Expected guesses comparison
* Attack success (Top-1, Top-3, Top-5, Top-10)
* Rank-probability curves (log-log)
* Cumulative success curves
* Entropy vs attack success

---

## 🚀 How to Run

### 1. Install dependencies

```
pip install -r requirements.txt
```

### 2. Run the system

```
python main.py
```

### 3. Output will be generated in:

* `data/` → datasets
* `results/` → frequencies, summary, plots

---

## 🔧 Configuration

In `main.py`, you can modify:

* `run_mode = "one" | "all"`
* `model_name = "uniform" | "biased" | "leakage"`
* `dob = "YYYY-MM-DD"`
* dataset size (default: 100000)
* random seed

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

* This project is for academic and research purposes only.
* The goal is to understand weaknesses in human-chosen PINs, not to exploit real systems.

---
