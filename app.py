import os
from datetime import datetime

import pandas as pd
import matplotlib.pyplot as plt
import streamlit as st

# ============================================================
# Import from src/ — same logic as main.py
# ============================================================

from src.pin_generator import generate_dataset, dob_to_candidate_pins # PIN dataset generation and DOB-candidate helper
from src.analysis import ( # analysis helpers: frequency building, security metrics, train/test split
    compute_frequency_from_pins,
    compute_security_metrics,
    train_test_split_pins,
    compute_test_distribution,
    save_frequency,
)
from src.attack import evaluate_all_attacks # runs all attack strategies and returns their Top-k success rates
from src.defense import run_weak_pin_blacklisting_study # runs the weak PIN blacklisting defense sweep

# ============================================================
# App Configuration
# ============================================================

st.set_page_config( # configure the Streamlit page's browser tab title, icon, and layout
    page_title="PIN Security Analysis System",
    page_icon="🔐",
    layout="wide"
)

DATA_DIR = "data" # directory where generated PIN datasets are stored
RESULTS_DIR = "results" # directory where all output tables and plots are stored

DEFAULT_DOB = "1998-03-05" # default demo date-of-birth pre-filled in the sidebar input
DEFAULT_N = 100000 # default number of PINs to generate
DEFAULT_SEED = 42 # default random seed for reproducibility

K_VALUES = [1, 3, 5, 10] # the Top-k thresholds evaluated throughout the app
BLACKLIST_SIZES = [10, 50, 100, 500] # the blacklist sizes swept in the defense study

# ============================================================
# Session State
# ============================================================

# Streamlit re-runs the whole script on every interaction, so persistent state
# across reruns must be stored explicitly in st.session_state
if "experiment_results" not in st.session_state: # initialize the list of per-model experiment results if not already set
    st.session_state.experiment_results = [] # empty list until the user runs an experiment

if "summary_df" not in st.session_state: # initialize the combined summary table if not already set
    st.session_state.summary_df = pd.DataFrame() # empty DataFrame placeholder

if "defense_summary_df" not in st.session_state: # initialize the combined defense summary table if not already set
    st.session_state.defense_summary_df = pd.DataFrame() # empty DataFrame placeholder

if "has_run" not in st.session_state: # initialize the flag tracking whether an experiment has been run yet
    st.session_state.has_run = False # False until the user clicks "Run Experiment"

# ============================================================
# Utility Functions
# ============================================================

def ensure_dirs() -> None: # creates the data/results output directories if they don't already exist
    os.makedirs(DATA_DIR, exist_ok=True) # create the data directory (no error if it already exists)
    os.makedirs(RESULTS_DIR, exist_ok=True) # create the results directory (no error if it already exists)

def save_dataset(pins: list, output_path: str) -> None: # saves a list of generated PINs to a CSV file
    df = pd.DataFrame({"pin": pins}) # wrap the list of PINs into a single-column DataFrame
    df.to_csv(output_path, index=False) # write the DataFrame to CSV, omitting the row index

# ============================================================
# Plotting Functions
# ============================================================

# Each function below renders a matplotlib figure directly into the Streamlit page.
def plot_top_pins(freq: pd.DataFrame, title: str, top_n: int = 10) -> None: # bar chart of the top-n most common PINs
    top = freq.head(top_n).copy() # take the first top_n rows (assumes freq already sorted by probability descending)
    fig, ax = plt.subplots(figsize=(12, 5)) # create a new figure and axis with the given size in inches
    ax.bar(top["pin"].astype(str), top["probability"]) # draw one bar per pin, height = its probability
    ax.set_title(title) # set the chart title
    ax.set_xlabel("PIN")
    ax.set_ylabel("Probability")
    ax.tick_params(axis="x", rotation=45) # rotate x-axis tick labels 45 degrees so PIN strings don't overlap
    st.pyplot(fig) # render the matplotlib figure into the Streamlit page
    plt.close(fig) # close the figure to free memory

def plot_attack_results(attack_results: dict, metric_key: str) -> None: # bar chart comparing attack strategies at one Top-k metric
    labels = list(attack_results.keys()) # attack strategy names become the x-axis categories
    values = [attack_results[a].get(metric_key, 0.0) for a in labels] # extract each attack's success rate at the chosen metric
    fig, ax = plt.subplots(figsize=(10, 5)) # create a new figure and axis with the given size in inches
    ax.bar(labels, values) # draw one bar per attack strategy, height = its success rate
    ax.set_title(f"Attack Success Comparison ({metric_key})") # set the chart title, including the chosen metric
    ax.set_xlabel("Attack Strategy")
    ax.set_ylabel("Success Rate")
    ax.tick_params(axis="x", rotation=15) # slightly rotate x-axis tick labels for readability
    st.pyplot(fig) # render the matplotlib figure into the Streamlit page
    plt.close(fig) # close the figure to free memory

def plot_defense_curve(defense_df: pd.DataFrame) -> None: # line chart showing attack success rate vs blacklist size
    if defense_df.empty: # guard against an empty defense results table
        st.warning("No defense data available.") # show a warning message in the UI
        return # exit early, nothing to plot
    fig, ax = plt.subplots(figsize=(10, 5)) # create a new figure and axis with the given size in inches
    ax.plot( # plot success rate after blacklisting as a function of blacklist size
        defense_df["Blacklist Size"],
        defense_df["New Top-10 Success Rate"],
        marker="o", # mark each data point with a circle
        label="After Blacklisting" # legend label for this line
    )
    ax.axhline( # draw a horizontal reference line showing the pre-defense success rate
        y=defense_df["Original Top-10 Success Rate"].iloc[0], # use the first row's original success rate as the baseline
        linestyle="--", # dashed line style to distinguish it from the main curve
        label="Before Defense" # legend label for this reference line
    )
    ax.set_title("Defense Study: Weak PIN Blacklisting") # set the chart title
    ax.set_xlabel("Number of Most Frequent PINs Blacklisted")
    ax.set_ylabel("Top-10 Attack Success Rate")
    ax.legend() # show the legend distinguishing the two lines
    ax.grid(True, alpha=0.3) # add a light grid for easier reading
    st.pyplot(fig) # render the matplotlib figure into the Streamlit page
    plt.close(fig) # close the figure to free memory

def plot_entropy_summary(summary_df: pd.DataFrame) -> None: # bar chart comparing Shannon entropy across all run experiments
    if summary_df.empty: # guard against an empty summary table
        return # nothing to plot yet
    fig, ax = plt.subplots(figsize=(10, 5)) # create a new figure and axis with the given size in inches
    ax.bar(summary_df["Experiment"], summary_df["Shannon Entropy (bits)"]) # draw one bar per experiment, height = its Shannon entropy
    ax.set_title("Shannon Entropy Comparison") # set the chart title
    ax.set_xlabel("Experiment")
    ax.set_ylabel("Shannon Entropy (bits)")
    ax.tick_params(axis="x", rotation=30) # rotate x-axis tick labels for readability
    st.pyplot(fig) # render the matplotlib figure into the Streamlit page
    plt.close(fig) # close the figure to free memory

def plot_min_entropy_summary(summary_df: pd.DataFrame) -> None: # bar chart comparing min-entropy across all run experiments
    if summary_df.empty: # guard against an empty summary table
        return # nothing to plot yet
    fig, ax = plt.subplots(figsize=(10, 5)) # create a new figure and axis with the given size in inches
    ax.bar(summary_df["Experiment"], summary_df["Min-Entropy (bits)"]) # draw one bar per experiment, height = its min-entropy
    ax.set_title("Min-Entropy Comparison") # set the chart title
    ax.set_xlabel("Experiment")
    ax.set_ylabel("Min-Entropy (bits)")
    ax.tick_params(axis="x", rotation=30) # rotate x-axis tick labels for readability
    st.pyplot(fig) # render the matplotlib figure into the Streamlit page
    plt.close(fig) # close the figure to free memory

def plot_expected_guesses_summary(summary_df: pd.DataFrame) -> None: # bar chart comparing expected guesses across all run experiments
    if summary_df.empty: # guard against an empty summary table
        return # nothing to plot yet
    fig, ax = plt.subplots(figsize=(10, 5)) # create a new figure and axis with the given size in inches
    ax.bar(summary_df["Experiment"], summary_df["Expected Guesses"]) # draw one bar per experiment, height = its expected guesses
    ax.set_title("Expected Guesses Comparison") # set the chart title
    ax.set_xlabel("Experiment")
    ax.set_ylabel("Expected Number of Guesses")
    ax.tick_params(axis="x", rotation=30) # rotate x-axis tick labels for readability
    st.pyplot(fig) # render the matplotlib figure into the Streamlit page
    plt.close(fig) # close the figure to free memory

# ============================================================
# Interpretation Functions
# ============================================================

# Functions that turn raw numeric results into human-readable narrative text for the UI.
def get_best_attack(attack_results: dict, metric_key: str = "Top-10") -> tuple: # finds which attack strategy performed best at a given metric
    best_name = max(attack_results, key=lambda a: attack_results[a].get(metric_key, 0.0)) # find the attack name with the highest success rate
    best_value = attack_results[best_name].get(metric_key, 0.0) # look up that attack's success rate value
    return best_name, best_value # return both the name and the value of the strongest attack

def generate_attack_conclusion(model: str, metrics: dict, attack_results: dict) -> str: # builds a markdown summary of attack results for one model
    best_attack, best_success = get_best_attack(attack_results, "Top-10") # identify the strongest attack at Top-10
    shannon = metrics["Shannon Entropy (bits)"] # extract the Shannon entropy value
    min_ent = metrics["Min-Entropy (bits)"] # extract the min-entropy value
    expected = metrics["Expected Guesses"] # extract the expected number of guesses

    if model == "uniform": # narrative text specific to the uniform (ideal random) model
        interpretation = (
            "The uniform model behaves closest to an ideal random PIN selection process. "
            "Attack success remains very low because probability is spread evenly across the key space."
        )
    elif model == "biased": # narrative text specific to the biased (human-like) model
        interpretation = (
            "The biased model shows that human-like PIN choices reduce practical security. "
            "Common patterns such as repeated digits, sequences, and date-like values "
            "increase the probability of successful guessing."
        )
    else:
        interpretation = ( # narrative text for the leakage model (attacker knows the target's DOB)
            "The leakage model is the riskiest setting because the attacker can prioritize "
            "DOB-related candidates. This strongly increases the success rate under a small "
            "number of allowed guesses."
        )

    return f"""
**Attack conclusion for 6-digit {model} model**

- Shannon entropy: **{shannon:.4f} bits**
- Min-entropy: **{min_ent:.4f} bits**
- Expected guesses: **{expected:.2f}**
- Strongest Top-10 attack: **{best_attack}**
- Top-10 success rate: **{best_success:.4f}** ({best_success * 100:.2f}%)

{interpretation}
""" # formatted markdown block combining the numeric metrics with the narrative interpretation

def generate_defense_conclusion(defense_df: pd.DataFrame, blacklist_size: int) -> str: # builds a markdown summary of the defense study for a chosen blacklist size
    row = defense_df[defense_df["Blacklist Size"] == blacklist_size] # find the row matching the user-selected blacklist size
    if row.empty: # if that exact size wasn't evaluated
        row = defense_df.iloc[-1] # fall back to the last (largest) blacklist size row
    else:
        row = row.iloc[0] # take the single matching row

    original = float(row["Original Top-10 Success Rate"]) # extract the pre-defense success rate
    new = float(row["New Top-10 Success Rate"]) # extract the post-defense success rate
    abs_red = float(row["Absolute Reduction"]) # extract the absolute reduction in success rate
    rel_red = float(row["Relative Reduction"]) # extract the relative (proportional) reduction in success rate

    return f"""
**Defense conclusion**

Using weak PIN blacklisting with the top **{blacklist_size}** most frequent PINs removed:

- Original Top-10 success rate: **{original:.4f}** ({original * 100:.2f}%)
- New Top-10 success rate: **{new:.4f}** ({new * 100:.2f}%)
- Absolute reduction: **{abs_red:.4f}**
- Relative reduction: **{rel_red * 100:.2f}%**

Blacklisting common weak PINs can significantly reduce guessability, especially for biased and leakage-based PIN distributions.
""" # formatted markdown block summarizing the defense's effectiveness

def compute_attempt_limit_from_topk(attack_results: dict, threshold: float = 0.05) -> int:
    """
    Method 1: Top-k success rate.
    Find the first measured k where the strongest attack exceeds threshold.
    Recommend k-1 as the safe limit.
    """
    max_at_k = {} # will hold, for each k, the best (highest) success rate across all attack strategies
    for k in K_VALUES: # iterate over each measured Top-k threshold
        key = f"Top-{k}" # build the corresponding result dict key
        max_at_k[k] = max(v.get(key, 0.0) for v in attack_results.values()) # find the strongest attack's success rate at this k
    for k in sorted(max_at_k): # check k values in ascending order
        if max_at_k[k] >= threshold: # if the strongest attack's success rate at this k crosses the risk threshold
            return max(k - 1, 0) # recommend the previous (safe) k as the attempt limit, not below zero
    return max(K_VALUES)  # if threshold is never crossed, allow up to the largest measured k

def compute_attempt_limit_from_expected_guesses(expected_guesses: float) -> int:
    """
    Method 2: Expected guesses.
    Use 1% of expected guesses as a conservative bound, capped between 1 and 20.
    """
    return max(1, min(int(expected_guesses * 0.01), 20)) # take 1% of expected guesses, clamp the result into the range [1, 20]

def compute_attempt_limit_from_cumulative(
    freq: pd.DataFrame, # training frequency table used to build guess orders
    leaked_candidates: list, # DOB-derived candidate PINs for the leakage-assisted attack
    test_distribution: dict, # ground-truth test-set distribution used to evaluate cumulative success
    threshold: float = 0.05, # risk threshold; recommend the last k below this cumulative success rate
    max_k: int = 30, # maximum number of attempts to simulate
) -> tuple:
    """
    Method 3: Cumulative success curve.
    Rank order built from TRAIN freq; cumulative success evaluated on TEST distribution.
    Returns (curves_dict, limits_dict, worst_case_limit).
    """
    from src.attack import ( # local import of guess-order builders and helpers, scoped to this function
        build_frequency_ranked_guess_order,
        build_rule_based_guess_order,
        build_random_guess_order,
        build_leakage_guess_order,
        _get_distribution_dict,
        _normalize_pin,
    )

    train_distribution = _get_distribution_dict(freq) # convert the training frequency table into a pin->probability dict

    def cumulative(order): # helper: computes the cumulative success rate at each attempt count for a given guess order
        return [
            sum(test_distribution.get(_normalize_pin(p), 0.0) for p in order[:k]) # sum test-set probability of the first k guesses
            for k in range(1, max_k + 1) # for every attempt count from 1 to max_k
        ]

    curves = { # compute the cumulative success curve for each of the four attack strategies
        "Frequency-Ranked": cumulative(build_frequency_ranked_guess_order(freq)), # curve for the frequency-ranked attack
        "Rule-Based":        cumulative(build_rule_based_guess_order(freq)), # curve for the rule-based attack
        "Leakage-Assisted":  cumulative(build_leakage_guess_order(freq, leaked_candidates)), # curve for the leakage-assisted attack
        "Random":            cumulative(build_random_guess_order(train_distribution, seed=42)), # curve for the random-guessing attack
    }

    def safe_limit(curve): # helper: finds the last attempt count before the cumulative success rate crosses the threshold
        for k, val in enumerate(curve, start=1): # walk through the curve, tracking the attempt number (starting at 1)
            if val >= threshold: # if cumulative success at this attempt count reaches/exceeds the threshold
                return k - 1 # recommend the previous attempt count as the safe limit
        return max_k # if threshold is never crossed within max_k attempts, allow the full max_k

    limits = {name: safe_limit(c) for name, c in curves.items()} # compute the safe attempt limit for each attack strategy
    return curves, limits, min(limits.values()) # return all curves, per-attack limits, and the most conservative (minimum) limit

def plot_cumulative_curves_inline(curves: dict, threshold: float, model: str) -> None: # renders the cumulative success curves for all attacks on one charts
    colors = { # fixed color mapping so each attack strategy is consistently colored across charts
        "Frequency-Ranked": "#e74c3c",
        "Rule-Based":        "#e67e22",
        "Leakage-Assisted":  "#8e44ad",
        "Random":            "#95a5a6",
    }
    max_k = len(next(iter(curves.values()))) # determine the number of attempts plotted, from the length of any one curve
    x = list(range(1, max_k + 1)) # x-axis values: attempt counts from 1 to max_k
    fig, ax = plt.subplots(figsize=(11, 5)) # create a new figure and axis with the given size in inches
    for name, vals in curves.items(): # loop over each attack strategy's cumulative success curve
        ax.plot(x, [v * 100 for v in vals], # plot cumulative success as a percentage
                label=name, color=colors.get(name), linewidth=2) # use the fixed color and a thicker line width
    ax.axhline(y=threshold * 100, color="#27ae60", linestyle="--", linewidth=1.8, # draw a horizontal line marking the risk threshold
               label=f"Risk threshold ({threshold * 100:.0f}%)") # label the threshold line with its percentage value
    ax.set_title(f"Cumulative Attack Success vs. Number of Attempts — {model} model") # set the chart title, including the model name
    ax.set_xlabel("Number of Attempts (k)") 
    ax.set_ylabel("Cumulative Success Rate (%)") 
    ax.legend() # show the legend distinguishing each attack strategy and the threshold line
    ax.grid(True, alpha=0.25) # add a light grid for easier reading
    ax.set_xlim(1, max_k) # constrain the x-axis range to exactly the plotted attempts
    st.pyplot(fig) # render the matplotlib figure into the Streamlit page
    plt.close(fig) # close the figure to free memory

def render_final_recommendation(
    model: str, # which PIN model this recommendation is for
    metrics: dict, # security metrics dict for this model
    attack_results: dict, # attack simulation results for this model
    defense_df: pd.DataFrame, # defense study results for this model
    blacklist_size: int, # user-selected blacklist size for the defense conclusion
    leaked_candidates: list, # DOB-derived candidate PINs for the leakage-assisted attack
    freq: pd.DataFrame, # training frequency table for this model   
    test_distribution: dict, # ground-truth test-set distribution for evaluation
) -> None:
    """
    Section 5: Final Recommendation.
    Combines attack/defense summary with attempt limit analysis
    using three methods; takes the most conservative result.
    Train freq used for ranking; test_distribution used for cumulative evaluation.
    """
    THRESHOLD = 0.05 # fixed risk threshold: an attacker success rate above 5% is considered unacceptable

    best_attack, best_success = get_best_attack(attack_results, "Top-10") # identify the strongest attack at Top-10
    expected = metrics["Expected Guesses"] # extract the expected guesses metric

    defense_row = defense_df[defense_df["Blacklist Size"] == blacklist_size] # find the defense row matching the selected blacklist size
    defense_row = defense_row.iloc[0] if not defense_row.empty else defense_df.iloc[-1] # use the matching row, or fall back to the last row
    new_success = float(defense_row["New Top-10 Success Rate"]) # extract the post-defense success rate

    # Three methods
    limit_topk     = compute_attempt_limit_from_topk(attack_results, threshold=THRESHOLD) # attempt limit derived from Top-k success rates
    limit_expected = compute_attempt_limit_from_expected_guesses(expected) # attempt limit derived from expected guesses
    curves, limits_per_attack, limit_cumulative = compute_attempt_limit_from_cumulative( # attempt limit derived from cumulative success curves
        freq, leaked_candidates, test_distribution=test_distribution, threshold=THRESHOLD
    )

    # Final: most conservative across all three
    final_limit = max(min(limit_topk, limit_expected, limit_cumulative), 0) # take the minimum (most conservative) of the three methods, floor at 0

    if final_limit == 0: # if even a single attempt already exceeds the risk threshold
        verdict_icon, verdict = "⚠️", (
            "Even **1 attempt** may already exceed the 5% risk threshold for the strongest "
            "attack. This PIN distribution is critically weak. "
            "Weak PIN blacklisting alone is insufficient — a very strict lockout policy is required."
        )
    elif final_limit <= 3: # if the safe limit is very low (1-3 attempts)
        verdict_icon, verdict = "🔴", (
            f"The system should lock after **no more than {final_limit} attempt(s)**. "
            f"Beyond this, the attacker's cumulative success exceeds 5%. "
            f"Weak PIN blacklisting can reduce this risk further by removing the most predictable PINs."
        )
    elif final_limit <= 5: # if the safe limit is moderate (4-5 attempts)   
        verdict_icon, verdict = "🟠", (
            f"A limit of **{final_limit} attempts** is the maximum safe setting for this distribution. "
            f"Weak PIN blacklisting (evaluated in Section 4) can lower the success rate further, "
            f"allowing a slightly more relaxed lockout policy."
        )
    else: # if the safe limit is relatively generous (6+ attempts)
        verdict_icon, verdict = "🟢", (
            f"The distribution tolerates up to **{final_limit} attempts** before the 5% threshold "
            f"is reached. Combined with weak PIN blacklisting, this distribution is relatively "
            f"resistant to low-attempt guessing attacks."
        )

    st.markdown(f"""
**Final Recommendation — 6-digit {model} model**

**Attack & defense summary**
- Strongest Top-10 attack: **{best_attack}** ({best_success * 100:.2f}%)
- After blacklisting top {blacklist_size} PINs: **{new_success * 100:.2f}%**
- Expected guesses under optimal attack: **{expected:.2f}**

---

**Attempt limit analysis** *(risk threshold: >5% attacker success = unacceptable)*

| Method | Recommended limit |
|--------|------------------|
| Top-k success rate (from measured k values) | {limit_topk} attempt(s) |
| Expected guesses (1% of {expected:.0f}) | {limit_expected} attempt(s) |
| Cumulative success curve (exact per-attempt) | {limit_cumulative} attempt(s) |
| **→ Final recommendation (most conservative)** | **{final_limit} attempt(s)** |

{verdict_icon} {verdict}
""") # render the full recommendation summary, table, and verdict as markdown

    st.markdown("**Cumulative success curve by attack strategy:**") # sub-heading before the cumulative curve chart
    plot_cumulative_curves_inline(curves, THRESHOLD, model) # render the cumulative success curves for all attack strategies

    limit_rows = [ # build a small table of per-attack safe attempt limits for display
        {"Attack Strategy": name, "Safe Attempt Limit": lim if lim > 0 else "< 1"} # show "< 1" when the limit rounds down to zero
        for name, lim in limits_per_attack.items() # iterate over each attack strategy's computed limit
    ]
    st.dataframe(pd.DataFrame(limit_rows), use_container_width=True) # display the per-attack limit table, stretched to the container width

    st.caption( # small caption text explaining the methodology beneath the table
        "Risk threshold is fixed at 5%. The final limit is the minimum across all three "
        "analysis methods, ensuring the most conservative and defensible recommendation."
    )

# ============================================================
# Core Experiment Runner
# ============================================================

def run_experiment(model: str, dob: str, n: int, seed: int, use_survey_weights: bool, blacklist_size: int) -> dict:
    """Run one full experiment using src/ pipeline — consistent with main.py (80/20 train/test split)."""
    ensure_dirs() # make sure output directories exist before writing any files

    # 1. Generate pins
    pins = generate_dataset( # generate the full synthetic PIN dataset for this model
        n=n, model=model, seed=seed, dob=dob,
        use_survey_weights=use_survey_weights,
        randomize_dob=True,
    )

    # 2. Save full dataset
    data_path = os.path.join(DATA_DIR, f"generated_{model}_pins.csv") # build path for this model's raw dataset file
    save_dataset(pins, data_path) # write the generated PINs to disk

    # 3. Train/test split (80/20) — same as main.py
    train_pins, test_pins = train_test_split_pins(pins, train_ratio=0.80, seed=seed) # split PINs into train/test sets

    # 4. Build frequency from TRAIN set only
    train_freq = compute_frequency_from_pins(train_pins) # compute PIN frequency/probability table from the training data only
    freq_path = os.path.join(RESULTS_DIR, f"frequency_{model}.csv") # build path for this model's frequency table file
    save_frequency(train_freq, output_path=freq_path) # save the training frequency table to disk
 
    # 5. Security metrics from TRAIN distribution
    metrics = compute_security_metrics(train_freq) # compute entropy, min-entropy, and expected guesses from the training distribution

    # 6. Test distribution for Top-k evaluation
    test_dist = compute_test_distribution(test_pins) # build the ground-truth probability distribution from the held-out test set

    # 7. Attacks: rank on TRAIN, evaluate on TEST
    leaked_candidates = dob_to_candidate_pins(dob) # derive DOB-based candidate guesses for the leakage attack
    attack_results = evaluate_all_attacks( # run all four attack strategies and evaluate their Top-k success rates
        train_freq_df=train_freq,
        test_distribution=test_dist,
        leaked_candidates=leaked_candidates,
        k_values=K_VALUES,
        seed=seed,
    )

    # 8. Defense on TRAIN distribution
    defense_df = run_weak_pin_blacklisting_study(freq=train_freq, model_name=model, blacklist_sizes=BLACKLIST_SIZES, k=10) # run the blacklisting defense sweep
    defense_path = os.path.join(RESULTS_DIR, f"app_defense_{model}.csv") # build path for this model's defense results file
    defense_df.to_csv(defense_path, index=False) # save the defense results to disk

    return { # package all computed results into a single dict for downstream display and storage
        "experiment_name": f"6-digit {model}", # human-readable label for this experiment run
        "model": model, # the model name (uniform/biased/leakage)
        "freq": train_freq, # the training frequency table
        "metrics": metrics, # the security metrics dict
        "attack_results": attack_results, # the attack simulation results
        "defense_df": defense_df, # the defense study results table
        "leaked_candidates": leaked_candidates, # DOB-derived candidates used by the leakage attack
        "blacklist_size": blacklist_size, # the blacklist size selected for this run
        "train_size": len(train_pins), # number of PINs in the training set
        "test_size": len(test_pins), # number of PINs in the test set
        "test_distribution": test_dist, # the test-set ground-truth distribution
        "saved_files": {"data_path": data_path, "freq_path": freq_path, "defense_path": defense_path}, # paths of all files saved during this run
    }

# ============================================================
# Sidebar
# ============================================================

# Widgets in the sidebar let the user configure the experiment before running it.
st.sidebar.title("Experiment Configuration") # sidebar section title

model_mode = st.sidebar.selectbox( # dropdown to choose which model(s) to run
    "Select PIN model",
    ["All models", "uniform", "biased", "leakage"],
    index=0, # default selection is "All models"
)

dob = st.sidebar.text_input("Date of Birth (leakage model)", value=DEFAULT_DOB, help="Format: YYYY-MM-DD") # text input for the demo DOB used by the leakage model

n = st.sidebar.number_input("Dataset size", min_value=1000, max_value=1000000, value=DEFAULT_N, step=1000) # numeric input for how many PINs to generate

seed = st.sidebar.number_input("Random seed", min_value=0, max_value=999999, value=DEFAULT_SEED, step=1) # numeric input for the random seed

use_survey_weights = st.sidebar.checkbox( # checkbox toggling whether to use survey-derived strategy weights
    "Use survey-based weights",
    value=True, # checked by default
    help="Makes biased and leakage models more realistic based on survey data.",
)

blacklist_size = st.sidebar.selectbox("Defense blacklist size (for conclusion)", BLACKLIST_SIZES, index=3) # dropdown to pick which blacklist size drives the narrative conclusion

run_button = st.sidebar.button("Run Experiment", type="primary") # primary action button that triggers the experiment run

# ============================================================
# Main Page
# ============================================================

st.title("PIN Security Analysis System") # main page title
st.markdown("""
This application demonstrates low-entropy attacks on **6-digit PINs** by comparing
uniform, biased, and leakage-based PIN models, and evaluates **weak PIN blacklisting** as a defense.

> Uses the same `src/` pipeline as `main.py` — results are fully consistent.
> Frequency rankings are built on the **training set (80%)** and Top-k success rates are evaluated on the **test set (20%)**, avoiding evaluation leakage.
""") # introductory description shown at the top of the page

# ============================================================
# Run Experiment
# ============================================================

if run_button: # only execute the experiment pipeline when the user clicks the "Run Experiment" button
    try:
        datetime.strptime(dob, "%Y-%m-%d") # validate that the entered DOB string matches the expected YYYY-MM-DD format (raises ValueError if not)

        models = ["uniform", "biased", "leakage"] if model_mode == "All models" else [model_mode] # decide which model(s) to run based on the sidebar selection

        st.session_state.experiment_results = [] # reset stored experiment results before this new run
        st.session_state.summary_df = pd.DataFrame() # reset the combined summary table
        st.session_state.defense_summary_df = pd.DataFrame() # reset the combined defense summary table
        st.session_state.has_run = False # mark that no completed run exists yet (will be set True on success)

        all_summary_rows = [] # accumulator list for each model's flattened summary row
        all_defense_rows = [] # accumulator list for every defense-study row across all models

        with st.spinner("Running experiment..."): # show a loading spinner while the experiment(s) run
            for model in models: # loop over each selected model
                result = run_experiment( # run the full experiment pipeline for this model
                    model=model, dob=dob, n=int(n), seed=int(seed),
                    use_survey_weights=use_survey_weights, blacklist_size=int(blacklist_size),
                )

                metrics = result["metrics"] # extract this model's security metrics
                attack_results = result["attack_results"] # extract this model's attack results
                defense_df = result["defense_df"] # extract this model's defense study table

                summary_row = { # build a flattened summary row combining metrics and attack results for this model
                    "Experiment": result["experiment_name"],
                    "Model": model,
                    "Shannon Entropy (bits)": metrics["Shannon Entropy (bits)"],
                    "Min-Entropy (bits)": metrics["Min-Entropy (bits)"],
                    "Expected Guesses": metrics["Expected Guesses"],
                }
                for attack_name, topk_dict in attack_results.items(): # iterate over each attack strategy's results
                    for k in K_VALUES: # iterate over each Top-k threshold
                        summary_row[f"{attack_name} - Top-{k}"] = topk_dict.get(f"Top-{k}", 0.0) # flatten into a named column

                all_summary_rows.append(summary_row) # collect this model's summary row
                all_defense_rows.extend(defense_df.to_dict("records")) # collect this model's defense rows into the combined list   
                st.session_state.experiment_results.append(result) # store the full result dict for later display

        summary_df = pd.DataFrame(all_summary_rows) # combine all models' summary rows into one DataFrame
        defense_summary_df = pd.DataFrame(all_defense_rows) # combine all models' defense rows into one DataFrame

        summary_df.to_csv(os.path.join(RESULTS_DIR, "app_summary_all_models.csv"), index=False) # persist the combined summary to disk
        defense_summary_df.to_csv(os.path.join(RESULTS_DIR, "app_defense_all_models.csv"), index=False) # persist the combined defense summary to disk
 
        st.session_state.summary_df = summary_df # store the combined summary in session state for display
        st.session_state.defense_summary_df = defense_summary_df # store the combined defense summary in session state for display
        st.session_state.has_run = True # mark that a successful run has completed

        st.success("Experiment completed successfully.") # show a success message in the UI

    except ValueError as ve: # catch invalid input errors (e.g. malformed DOB string)
        st.error(f"Invalid input: {ve}") # show the validation error message in the UI
    except Exception as e: # catch any other unexpected error during the experiment run
        st.error(f"Error: {e}") # show the generic error message in the UI

# ============================================================
# Display Results
# ============================================================

if st.session_state.has_run and st.session_state.experiment_results: # only render results if an experiment has successfully completed

    st.header("Overall Summary") # section header for the combined overview

    if not st.session_state.summary_df.empty: # only render summary content if the summary table has data
        st.dataframe(st.session_state.summary_df, use_container_width=True) # display the full combined summary table
        col_a, col_b = st.columns(2) # create a two-column layout for side-by-side charts
        with col_a: # left column
            plot_entropy_summary(st.session_state.summary_df) # render the Shannon entropy comparison chart
        with col_b: # right column
            plot_min_entropy_summary(st.session_state.summary_df) # render the min-entropy comparison chart
        plot_expected_guesses_summary(st.session_state.summary_df) # render the expected guesses comparison chart, full width

    if not st.session_state.defense_summary_df.empty: # only render defense summary content if it has data
        st.subheader("Defense Summary (All Models)") # sub-header for the defense summary section
        st.dataframe(st.session_state.defense_summary_df, use_container_width=True) # display the full combined defense summary table

    for result in st.session_state.experiment_results: # iterate over each model's detailed results to render its own section
        experiment_name = result["experiment_name"] # this experiment's display name
        model = result["model"] # this experiment's model name
        freq = result["freq"] # this experiment's training frequency table
        metrics = result["metrics"] # this experiment's security metrics
        attack_results = result["attack_results"] # this experiment's attack results
        defense_df = result["defense_df"] # this experiment's defense study table 
        bsize = result["blacklist_size"] # this experiment's selected blacklist size
        saved_files = result["saved_files"] # this experiment's saved file paths

        st.markdown("---") # horizontal divider between experiment sections
        st.header(experiment_name) # section header naming this specific experiment

        # 1. Security Metrics
        st.subheader("1. Security Metrics") # sub-section header
        col1, col2, col3 = st.columns(3) # three-column layout for the three headline metrics
        with col1:
            st.metric("Shannon Entropy", f"{metrics['Shannon Entropy (bits)']:.4f} bits") # display the Shannon entropy as a metric widget
        with col2:
            st.metric("Min-Entropy", f"{metrics['Min-Entropy (bits)']:.4f} bits") # display the min-entropy as a metric widget
        with col3:
            st.metric("Expected Guesses", f"{metrics['Expected Guesses']:.2f}") # display the expected guesses as a metric widget

        # 2. Top 10 PINs
        st.subheader("2. Top 10 Most Common PINs") # sub-section header
        st.dataframe(freq.head(10), use_container_width=True) # display the top-10 PIN table
        plot_top_pins(freq, title=f"Top 10 Most Common PINs — {experiment_name}") # render the top-10 PIN bar chart

        # 3. Attack Results
        st.subheader("3. Attack Success Comparison") # sub-section header
        attack_rows = [] # accumulator list for building a display-friendly attack results table
        for attack_name, topk_dict in attack_results.items(): # iterate over each attack strategy's results
            row = {"Attack Strategy": attack_name} # start the row with the attack's name
            for k in K_VALUES: # iterate over each Top-k threshold
                row[f"Top-{k}"] = topk_dict.get(f"Top-{k}", 0.0) # add this attack's success rate at this k
            attack_rows.append(row) # add the completed row to the table
        attack_display_df = pd.DataFrame(attack_rows) # convert the rows into a DataFrame for display
        st.dataframe(attack_display_df, use_container_width=True) # display the attack comparison table

        selected_k = st.selectbox( # dropdown letting the user choose which Top-k metric to visualize
            f"Select Top-k metric to visualize — {experiment_name}",
            [f"Top-{k}" for k in K_VALUES],
            index=3, # default to the last option (Top-10)
            key=f"metric_selector_{model}", # unique widget key so multiple model sections don't conflict
        )
        plot_attack_results(attack_results, selected_k) # render the bar chart for the selected Top-k metric
        st.markdown(generate_attack_conclusion(model, metrics, attack_results)) # render the narrative attack conclusion text
 
        # 4. Defense Study
        st.subheader("4. Defense Study: Weak PIN Blacklisting") # sub-section header
        st.dataframe(defense_df, use_container_width=True) # display the full defense study results table
        plot_defense_curve(defense_df) # render the defense success-rate-vs-blacklist-size chart
        st.markdown(generate_defense_conclusion(defense_df, bsize)) # render the narrative defense conclusion text

        # 5. Final Recommendation & Attempt Limit Analysis
        st.subheader("5. Final Recommendation") # sub-section header
        render_final_recommendation( # render the combined attack/defense recommendation and attempt-limit analysis
            model=model,
            metrics=metrics,
            attack_results=attack_results,
            defense_df=defense_df,
            blacklist_size=bsize,
            leaked_candidates=result["leaked_candidates"],
            freq=freq,
            test_distribution=result["test_distribution"],
        )

        st.info( # informational footer summarizing the train/test split and where files were saved
            f"Train/test split: **{result['train_size']:,}** train / **{result['test_size']:,}** test (80/20). "
            f"Frequency ranking built on train set; Top-k success rates evaluated on test set. "
            f"Saved: `{saved_files['data_path']}`, `{saved_files['freq_path']}`, `{saved_files['defense_path']}`"
        )

else: # if no experiment has been run yet
    st.info("Configure the experiment in the sidebar, then click **Run Experiment**.") # prompt the user to start an experiment
    st.markdown("""
### What this app does

This app runs an interactive PIN security experiment using the same `src/` pipeline as `main.py`.

It supports:

- **Uniform model** — ideal random baseline
- **Biased model** — human PIN selection behavior  
- **Leakage model** — attacker knows date of birth
- **Random attack**
- **Frequency-ranked attack**
- **Rule-based attack**
- **Leakage-assisted attack**
- **Weak PIN blacklisting defense**

The thesis focuses on **6-digit PINs only**.
""") # landing-page description shown before the first experiment run