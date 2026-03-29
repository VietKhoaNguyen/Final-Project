# Low-Entropy Attacks on 6-Digit PINs

This repository contains the implementation for a bachelor thesis project on analyzing the security of human-chosen 6-digit PINs under low-entropy attacks.

---

## Project Overview

Although a 6-digit PIN has a theoretical space of 1,000,000 combinations, real users often choose predictable patterns such as birthdays, repeated digits, and simple sequences. This reduces the effective security of PIN-based authentication.

This project models human PIN selection behavior and evaluates how different attack strategies can exploit these patterns under limited guessing attempts.

---

## Objectives

- Model human-biased PIN distributions
- Simulate PIN-guessing attacks
- Evaluate attack success under limited attempts
- Analyze the impact of personal-information bias

---

## Project Structure

```
Final_Project/
│
├── src/
│   ├── pin_generator.py
│   ├── analysis.py
│   ├── attack.py
│
├── data/
│
├── results/
│
├── main.py
├── .gitignore
├── README.md
└── requirements.txt
```

---

## How to Run

1. Install dependencies:

```
pip install -r requirements.txt
```

2. Run the main script:

```
python main.py
```

---

## Current Features

- PIN dataset generation (human-biased)
- Frequency analysis
- Basic attack simulation (top-k success)

---

## Future Work

- Personal-information-based attack modeling
- Advanced guessing strategies
- Defense mechanisms evaluation

---

## Technologies

* Python
* NumPy
* Pandas
* Matplotlib

---

## Author

Nguyễn Việt Khoa - 23BI14223
Bachelor Thesis - ICT