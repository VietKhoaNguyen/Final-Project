# Low-Entropy Attacks on 6-Digit PINs

This repository contains the implementation for a bachelor thesis project on the security of human-chosen 6-digit PINs. The project studies how non-uniform user behavior reduces practical PIN security, especially when users choose memorable PINs such as repeated digits, dates, sequential patterns, or values related to personal information.

The project does not use a machine learning model. It is a simulation-based security analysis project.

---

## Thesis Title

Low-Entropy Attacks on 6-Digit PINs: Modeling Guessability under Personal-Information Bias

---

## Author

Nguyen Viet Khoa  
Bachelor Thesis Project  
ICT Department  
University of Science and Technology of Hanoi

---

## Project Overview

A 6-digit PIN has a theoretical key space of 1,000,000 possible values, from 000000 to 999999. However, this does not mean that all PINs are equally secure in practice. Real users often choose PINs that are easy to remember, and these choices create bias in the distribution.

For example, users may choose:

- repeated digits such as 000000, 111111, 888888;
- sequential digits such as 123456 or 654321;
- date-based PINs;
- year-based PINs;
- PINs related to personal information such as date of birth.

Because of this behavior, attackers can guess some PINs much earlier than others. Therefore, the practical security of a PIN should be evaluated by guessability, entropy, and attack success rate, not only by the size of the theoretical key space.

This project compares three PIN models:

1. Uniform PIN model
2. Biased PIN model
3. Leakage-based PIN model

It also evaluates four attack strategies:

1. Random attack
2. Frequency-ranked attack
3. Rule-based attack
4. Leakage-assisted attack

In addition, the project includes one defense study:

1. Weak PIN blacklisting

---

## Main Objectives

The main objectives of this project are:

- to generate synthetic 6-digit PIN datasets;
- to model different PIN selection behaviors;
- to compare uniform, biased, and leakage-based PIN distributions;
- to compute security metrics such as Shannon entropy, min-entropy, and expected guesses;
- to simulate different guessing attacks;
- to evaluate Top-k attack success rates;
- to study the effect of personal-information leakage;
- to evaluate whether weak PIN blacklisting can reduce attack success.

---

## Project Scope

The project focuses on:

- 6-digit PINs only;
- synthetic or literature-grounded PIN distributions;
- simulation-based attacks;
- entropy and guessability analysis;
- limited-attempt attack success;
- one defense study using weak PIN blacklisting.

The project does not include:

- real user account attacks;
- real banking system attacks;
- online attacks against deployed systems;
- machine learning models;
- password cracking tools;
- biometric authentication.

---

## Project Structure

```
Final_Project/
├── src/
│   ├── pin_generator.py
│   ├── analysis.py
│   ├── attack.py
│   ├── defense.py
│   └── plot.py
│
├── data/
│   ├── generated_uniform_pins.csv
│   ├── generated_biased_pins.csv
│   └── generated_leakage_pins.csv
│
├── results/
│   ├── frequency_uniform.csv
│   ├── frequency_biased.csv
│   ├── frequency_leakage.csv
│   ├── summary_uniform.csv
│   ├── summary_biased.csv
│   ├── summary_leakage.csv
│   ├── summary_all_models.csv
│   ├── defense_blacklist.csv
│   └── figures/
│
├── main.py
├── README.md
└── requirements.txt
```

---

## File Descriptions

---

### main.py

This is the main experimental pipeline. It controls the full workflow of the project:

1. generate PIN datasets;
2. save generated datasets;
3. compute frequency distributions;
4. compute security metrics;
5. run attack simulations;
6. save per-model summaries;
7. save the global summary table;
8. generate result plots;
9. run the weak PIN blacklisting defense study.

---

### src/pin_generator.py

This file contains the PIN generation logic. It supports three PIN generation models:

1. uniform model;
2. biased model;
3. leakage model.

It also contains helper functions for converting a date of birth into possible 6-digit PIN candidates.

---

### src/analysis.py

This file contains the security analysis functions. It computes:

1. frequency tables;
2. Shannon entropy;
3. min-entropy;
4. expected guesses;
5. probability distributions.

It also provides functions for saving frequency results and printing important summary values.

---

### src/attack.py

This file contains the attack simulation logic. It evaluates multiple attack strategies:

1. random attack;
2. frequency-ranked attack;
3. rule-based attack;
4. leakage-assisted attack.

It computes Top-k success rates for different values of k, such as Top-1, Top-3, Top-5, and Top-10.

---

### src/defense.py

This file contains the weak PIN blacklisting defense study. The defense removes the most frequent PINs from the distribution, renormalizes the remaining probabilities, and evaluates the new attack success rate.

The defense study evaluates blacklist sizes such as:

- 10;
- 50;
- 100;
- 500

The purpose is to test whether blocking very common PINs can reduce the success rate of frequency-ranked attacks.

---

### src/plot.py

This file generates visualizations for the project. It creates plots such as:

1. entropy comparison;
2. min-entropy comparison;
3. expected guesses comparison;
4. attack success comparison;
5. cumulative success curves;
6. rank-probability curves;
7. entropy versus attack success;
8. weak PIN blacklisting defense plot.

---

## PIN Generation Models

---

## 1. Uniform Model

The uniform model represents the ideal case where each 6-digit PIN has approximately equal probability.

In theory, if all 1,000,000 possible PINs are equally likely, then guessing the correct PIN within a small number of attempts should be very difficult.

This model is used as the baseline for comparison.

Example PINs from the uniform model may look like:

```
864278
130889
918398
241292
598782
```

These PINs do not follow a specific human pattern.

---

## 2. Biased Model

The biased model represents human PIN selection behavior. Users often choose PINs that are easy to remember. Therefore, some PINs become much more common than others.

The biased model gives higher probability to patterns such as:

- repeated digits;
- sequential digits;
- date-like numbers;
- year-like numbers;
- culturally familiar numbers;
- simple memorable values.

Examples of common biased PINs include:

```
888888
999999
666666
000000
777777
444444
222222
111111
333333
555555
```

This model shows that human behavior can significantly reduce practical PIN security.

---

## 3. Leakage Model

The leakage model represents a stronger attacker scenario. In this case, the attacker may know some personal information about the target user.

In this project, the main leaked information is date of birth.

For example, if the date of birth is:

```
1998-03-05
```

The system can generate possible DOB-related PIN candidates such as:

```
050398
980305
030598
199800
001998
050305
030505
```

These candidates are then given higher priority in the leakage model.

The leakage model is important because many users choose PINs related to personal information, and attackers may obtain such information from social media, public records, or prior knowledge.

---

## Attack Strategies

---

## 1. Random Attack

The random attack guesses PINs in random order.

This is the simplest attack strategy. It does not use any knowledge about the PIN distribution. Therefore, it usually performs poorly compared with more informed attacks.

The random attack is used as a baseline.

---

## 2. Frequency-Ranked Attack

The frequency-ranked attack guesses PINs from the most frequent to the least frequent.

This attack assumes that the attacker knows or can estimate the target PIN distribution.

For biased and leakage-based PIN models, this attack is effective because many users concentrate on a small number of common PINs.

---

## 3. Rule-Based Attack

The rule-based attack uses known human PIN selection rules. It prioritizes PINs with common patterns such as:

- repeated digits;
- sequential digits;
- date-like values;
- year-like values;
- simple memorable combinations.

This attack does not need the exact frequency table, but it exploits predictable human behavior.

---

## 4. Leakage-Assisted Attack

The leakage-assisted attack uses personal information, especially date of birth.

The attacker first generates DOB-based candidate PINs and prioritizes them. After that, the attack can continue using frequency-ranked guessing.

This attack represents a realistic threat model where the attacker knows some personal information about the victim.

---

## Defense Study

---

## Weak PIN Blacklisting

The project includes one defense study: weak PIN blacklisting.

The idea is simple: if some PINs are extremely common, the system can reject those PINs during PIN creation.

For example, the system may blacklist:

```
000000
111111
123456
888888
999999
```

The defense process is:

1. load the PIN distribution;
2. rank PINs by probability;
3. remove the top N most frequent PINs;
4. renormalize the remaining probability distribution;
5. run the frequency-ranked attack again;
6. measure the new Top-10 success rate.

The tested blacklist sizes are:

```
10
50
100
500
```

The purpose of this defense study is to evaluate whether removing the most predictable PINs can reduce attack success.

This defense is not a complete security solution. However, it is a practical and understandable defense mechanism for reducing the risk caused by very weak PIN choices.

---

## Security Metrics

---

## 1. Shannon Entropy

Shannon entropy measures the average uncertainty of a distribution.

If PINs are close to uniformly distributed, Shannon entropy is higher.

If users concentrate on a small number of common PINs, Shannon entropy becomes lower.

In this project, Shannon entropy is measured in bits.

---

## 2. Min-Entropy

Min-entropy focuses on the most likely PIN.

It measures worst-case predictability.

If one PIN is very common, min-entropy becomes low, even if the rest of the distribution is diverse.

Min-entropy is important because attackers usually try the most likely PINs first.

---

## 3. Expected Guesses

Expected guesses estimate the average number of guesses needed to find the correct PIN under an optimal ranked guessing strategy.

A higher expected number of guesses means stronger practical security.

A lower expected number of guesses means the PIN distribution is easier to attack.

---

## 4. Top-k Success Rate

Top-k success rate measures the probability that an attacker succeeds within k guesses.

This project evaluates:

```
Top-1
Top-3
Top-5
Top-10
```

This metric is important because real systems usually limit the number of login attempts.

For example, if a system allows only 3 attempts, then Top-3 success rate is more meaningful than full brute-force success.

---

## Experimental Workflow

The experiment follows this workflow:

1. The user selects the model type.
2. The system generates PINs.
3. The system computes the frequency table.
4. The system computes entropy and guessability metrics.
5. The system runs attack simulations.
6. The system computes Top-k success rates.
7. The system saves CSV summaries.
8. The system generates plots.
9. The system runs the weak PIN blacklisting defense study.
10. The system saves defense results and defense plots.

---

## Input Parameters

The main configurable parameters are:

- model type;
- date of birth;
- dataset size;
- random seed;
- use of survey-based weights;
- blacklist sizes for defense study.

---

## Default Configuration

The default configuration in `main.py` is:

```python
DATA_DIR = "data"
RESULTS_DIR = "results"
DEFAULT_RUN_MODE = "all"
DEFAULT_MODEL = "biased"
DEFAULT_DOB = "1998-03-05"
DEFAULT_N = 100000
DEFAULT_SEED = 42
DEFAULT_USE_SURVEY_WEIGHTS = True
```

---

## How to Install

First, clone or download the project folder.

Then install the required Python packages:

```bash
pip install -r requirements.txt
```

---

## How to Run the Project

---

### Run All Models

To run the full experiment for all three models:

```bash
python main.py
```

This will run:

```
uniform
biased
leakage
```

It will generate datasets, frequency tables, summary files, plots, and defense results.

---

### Run One Model Only

To run only one model:

```bash
python main.py --run_mode one --model biased
```

Available models are:

```
uniform
biased
leakage
```

---

### Run Uniform Model

```bash
python main.py --run_mode one --model uniform
```

---

### Run Biased Model

```bash
python main.py --run_mode one --model biased
```

---

### Run Leakage Model

```bash
python main.py --run_mode one --model leakage
```

---

### Run Leakage Model with Custom Date of Birth

```bash
python main.py --run_mode one --model leakage --dob 2005-02-09
```

The required DOB format is:

```
YYYY-MM-DD
```

---

### Change Dataset Size

```bash
python main.py --n 50000
```

The default dataset size is:

```
100000
```

---

### Change Random Seed

```bash
python main.py --seed 123
```

The random seed is used for reproducibility.

Using the same seed should produce the same or very similar results.

---

### Use Survey-Based Weights

```bash
python main.py --use_survey_weights
```

Survey-based weights are used to make the biased and leakage models more realistic.

---

## Output Files

---

### Generated PIN Datasets

The generated PIN datasets are saved in the `data` folder:

```
data/generated_uniform_pins.csv
data/generated_biased_pins.csv
data/generated_leakage_pins.csv
```

Each file contains generated 6-digit PIN samples.

---

### Frequency Tables

The frequency tables are saved in the `results` folder:

```
results/frequency_uniform.csv
results/frequency_biased.csv
results/frequency_leakage.csv
```

Each frequency table contains:

- PIN;
- count;
- probability.

---

### Summary Files

Each model has its own summary file:

```
results/summary_uniform.csv
results/summary_biased.csv
results/summary_leakage.csv
```

The combined summary file is:

```
results/summary_all_models.csv
```

The summary files contain:

- Shannon entropy;
- min-entropy;
- expected guesses;
- Top-1 success rate;
- Top-3 success rate;
- Top-5 success rate;
- Top-10 success rate;
- attack results for each strategy.

---

### Defense Result File

The weak PIN blacklisting defense result is saved as:

```
results/defense_blacklist.csv
```

This file contains:

- model name;
- blacklist size;
- original Top-10 attack success rate;
- new Top-10 attack success rate after blacklisting;
- absolute reduction;
- relative reduction percentage.

---

### Plots

The project generates multiple plots, including:

- Shannon entropy comparison across PIN models;
- min-entropy comparison across PIN models;
- expected guesses comparison across PIN models;
- attack success comparison for Top-1;
- attack success comparison for Top-3;
- attack success comparison for Top-5;
- attack success comparison for Top-10;
- cumulative success curves;
- rank-probability curve for the uniform model;
- rank-probability curve for the biased model;
- rank-probability curve for the leakage model;
- combined rank-probability curves;
- entropy versus attack success;
- weak PIN blacklisting defense plot.

These plots are saved in the `results` folder.

---

## Example Results Interpretation

---

### Uniform Model

The uniform model has the highest entropy because PINs are close to evenly distributed.

Attack success is very low because there are no strong patterns to exploit.

This model represents ideal random PIN selection.

---

### Biased Model

The biased model has lower entropy than the uniform model.

Some PINs appear much more frequently than others.

Frequency-ranked and rule-based attacks perform much better against this model than random guessing.

This shows that human bias reduces practical security.

---

### Leakage Model

The leakage model has the lowest security among the three models.

Personal-information-based PINs become highly probable.

Leakage-assisted attacks and frequency-ranked attacks achieve higher success rates.

This shows that personal information can significantly increase attack effectiveness.

---

### Defense Study Interpretation

Weak PIN blacklisting reduces the success rate of frequency-ranked attacks by removing the most common PINs.

The larger the blacklist size, the more the attacker loses access to high-probability guesses.

However, blacklisting does not completely solve the problem because users may still choose other predictable PINs.

Therefore, weak PIN blacklisting should be considered a simple defensive improvement, not a complete security mechanism.

---

## UML Diagrams

The project includes UML diagrams for system explanation and thesis documentation.

The diagrams include:

1. Use Case Diagram
2. Class Diagram
3. Component Diagram
4. Activity Diagram - Generate PIN Distribution
5. Activity Diagram - Run Attack Simulation
6. Activity Diagram - Compute Security Metrics
7. Activity Diagram - Weak PIN Blacklisting Defense
8. Sequence Diagram - Generate PIN Distribution
9. Sequence Diagram - Run Attack Simulation
10. Sequence Diagram - Leakage-Assisted Attack
11. Sequence Diagram - Weak PIN Blacklisting Defense

These diagrams describe the system from different perspectives, including user interaction, system structure, workflow, and object communication.

---

## Key Findings

The expected findings of this project are:

1. Uniform PINs provide the strongest theoretical baseline.
2. Human-biased PINs have lower entropy and higher attack success.
3. Leakage-based PINs are more vulnerable because attackers can prioritize personal-information-based candidates.
4. Frequency-ranked attacks are highly effective when the distribution is non-uniform.
5. Rule-based attacks can exploit common human patterns.
6. Leakage-assisted attacks can significantly improve success when date-of-birth information is known.
7. Weak PIN blacklisting can reduce attack success by removing the most predictable PINs.
8. Entropy alone is useful but not sufficient; Top-k success rate is more practical for limited-attempt systems.

---

## Research Questions

This project can answer the following research questions:

1. How much does human bias reduce the security of 6-digit PINs?
2. How different is a biased PIN distribution from a uniform distribution?
3. How effective are frequency-ranked attacks against human-biased PINs?
4. How much does personal-information leakage improve guessing success?
5. Which metric better reflects real-world PIN security: entropy or Top-k success rate?
6. Can weak PIN blacklisting reduce attacker success under limited attempts?

---

## Technologies Used

The project uses:

- Python;
- pandas;
- matplotlib;
- numpy;
- CSV files for storing datasets and results;
- synthetic data generation;
- UML diagrams for system modeling.

---

## Requirements

The required Python packages are listed in `requirements.txt`.

Typical dependencies include:

```
pandas
matplotlib
numpy
```

---

## Reproducibility

The project supports reproducible experiments through a random seed.

The default seed is:

```
42
```

To reproduce the default experiment:

```bash
python main.py --seed 42 --n 100000
```

Using the same configuration helps ensure that the generated datasets and results are consistent across runs.

---

## Ethical Use

This project is for academic and educational purposes only.

It does not attack real users or real systems.

The goal is to understand why human-chosen PINs can be weak and how simple defenses may reduce risk.

The code should not be used for unauthorized access, real account attacks, or malicious purposes.

---

## References

The project is based on research related to PIN security, password guessability, and entropy.

Main references include:

1. Ding Wang, Ping Wang, Jing-Hua Guo, and Zi-Wei Lan. Behind the PIN: An Analysis of 6-Digit PIN Selection and Guessability. ASIACCS, 2017.

2. Joseph Bonneau. The Science of Guessing: Analyzing an Anonymized Corpus of 70 Million Passwords. IEEE Symposium on Security and Privacy, 2012.

3. Dinei Florencio and Cormac Herley. A Large-Scale Study of Web Password Habits. WWW, 2007.

4. Claude E. Shannon. A Mathematical Theory of Communication. Bell System Technical Journal, 1948.

5. National Institute of Standards and Technology. Digital Identity Guidelines: Authentication and Authenticator Management. NIST Special Publication 800-63B.

---

## License

This project is created for academic thesis work.

Unless otherwise specified, it is intended for educational and research use only.

---

## Final Note

This project demonstrates that the theoretical size of the 6-digit PIN space is not enough to evaluate real security. Human behavior, biased choices, and personal-information leakage can greatly reduce practical security.

By comparing uniform, biased, and leakage-based models, the project shows that guessability-based metrics such as Top-k success rate, expected guesses, Shannon entropy, and min-entropy provide a more realistic view of PIN security.

The weak PIN blacklisting defense study further shows that simple defensive rules can reduce the success of ranked attacks, although they cannot fully eliminate the risk of predictable PIN selection.

---
