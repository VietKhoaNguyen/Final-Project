import os
from datetime import datetime

import pandas as pd
import matplotlib.pyplot as plt
import streamlit as st

# ============================================================
# Import from src/ — same logic as main.py
# ============================================================

from src.pin_generator import generate_dataset, dob_to_candidate_pins
from src.analysis import (
    compute_frequency_from_pins,
    compute_security_metrics,
    train_test_split_pins,
    compute_test_distribution,
    save_frequency,
)
from src.attack import evaluate_all_attacks
from src.defense import run_weak_pin_blacklisting_study

# ============================================================
# App Configuration
# ============================================================

st.set_page_config(
    page_title="PIN Security Analysis System",
    page_icon="🔐",
    layout="wide"
)

DATA_DIR = "data"
RESULTS_DIR = "results"

DEFAULT_DOB = "1998-03-05"
DEFAULT_N = 100000
DEFAULT_SEED = 42

K_VALUES = [1, 3, 5, 10]
BLACKLIST_SIZES = [10, 50, 100, 500]

# ============================================================
# Session State
# ============================================================

if "experiment_results" not in st.session_state:
    st.session_state.experiment_results = []

if "summary_df" not in st.session_state:
    st.session_state.summary_df = pd.DataFrame()

if "defense_summary_df" not in st.session_state:
    st.session_state.defense_summary_df = pd.DataFrame()

if "has_run" not in st.session_state:
    st.session_state.has_run = False

# ============================================================
# Utility Functions
# ============================================================

def ensure_dirs() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)


def save_dataset(pins: list, output_path: str) -> None:
    df = pd.DataFrame({"pin": pins})
    df.to_csv(output_path, index=False)


# ============================================================
# Plotting Functions
# ============================================================

def plot_top_pins(freq: pd.DataFrame, title: str, top_n: int = 10) -> None:
    top = freq.head(top_n).copy()
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.bar(top["pin"].astype(str), top["probability"])
    ax.set_title(title)
    ax.set_xlabel("PIN")
    ax.set_ylabel("Probability")
    ax.tick_params(axis="x", rotation=45)
    st.pyplot(fig)
    plt.close(fig)


def plot_attack_results(attack_results: dict, metric_key: str) -> None:
    labels = list(attack_results.keys())
    values = [attack_results[a].get(metric_key, 0.0) for a in labels]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(labels, values)
    ax.set_title(f"Attack Success Comparison ({metric_key})")
    ax.set_xlabel("Attack Strategy")
    ax.set_ylabel("Success Rate")
    ax.tick_params(axis="x", rotation=15)
    st.pyplot(fig)
    plt.close(fig)


def plot_defense_curve(defense_df: pd.DataFrame) -> None:
    if defense_df.empty:
        st.warning("No defense data available.")
        return
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(
        defense_df["Blacklist Size"],
        defense_df["New Top-10 Success Rate"],
        marker="o",
        label="After Blacklisting"
    )
    ax.axhline(
        y=defense_df["Original Top-10 Success Rate"].iloc[0],
        linestyle="--",
        label="Before Defense"
    )
    ax.set_title("Defense Study: Weak PIN Blacklisting")
    ax.set_xlabel("Number of Most Frequent PINs Blacklisted")
    ax.set_ylabel("Top-10 Attack Success Rate")
    ax.legend()
    ax.grid(True, alpha=0.3)
    st.pyplot(fig)
    plt.close(fig)


def plot_entropy_summary(summary_df: pd.DataFrame) -> None:
    if summary_df.empty:
        return
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(summary_df["Experiment"], summary_df["Shannon Entropy (bits)"])
    ax.set_title("Shannon Entropy Comparison")
    ax.set_xlabel("Experiment")
    ax.set_ylabel("Shannon Entropy (bits)")
    ax.tick_params(axis="x", rotation=30)
    st.pyplot(fig)
    plt.close(fig)


def plot_min_entropy_summary(summary_df: pd.DataFrame) -> None:
    if summary_df.empty:
        return
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(summary_df["Experiment"], summary_df["Min-Entropy (bits)"])
    ax.set_title("Min-Entropy Comparison")
    ax.set_xlabel("Experiment")
    ax.set_ylabel("Min-Entropy (bits)")
    ax.tick_params(axis="x", rotation=30)
    st.pyplot(fig)
    plt.close(fig)


def plot_expected_guesses_summary(summary_df: pd.DataFrame) -> None:
    if summary_df.empty:
        return
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(summary_df["Experiment"], summary_df["Expected Guesses"])
    ax.set_title("Expected Guesses Comparison")
    ax.set_xlabel("Experiment")
    ax.set_ylabel("Expected Number of Guesses")
    ax.tick_params(axis="x", rotation=30)
    st.pyplot(fig)
    plt.close(fig)


# ============================================================
# Interpretation Functions
# ============================================================

def get_best_attack(attack_results: dict, metric_key: str = "Top-10") -> tuple:
    best_name = max(attack_results, key=lambda a: attack_results[a].get(metric_key, 0.0))
    best_value = attack_results[best_name].get(metric_key, 0.0)
    return best_name, best_value


def generate_attack_conclusion(model: str, metrics: dict, attack_results: dict) -> str:
    best_attack, best_success = get_best_attack(attack_results, "Top-10")
    shannon = metrics["Shannon Entropy (bits)"]
    min_ent = metrics["Min-Entropy (bits)"]
    expected = metrics["Expected Guesses"]

    if model == "uniform":
        interpretation = (
            "The uniform model behaves closest to an ideal random PIN selection process. "
            "Attack success remains very low because probability is spread evenly across the key space."
        )
    elif model == "biased":
        interpretation = (
            "The biased model shows that human-like PIN choices reduce practical security. "
            "Common patterns such as repeated digits, sequences, and date-like values "
            "increase the probability of successful guessing."
        )
    else:
        interpretation = (
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
"""


def generate_defense_conclusion(defense_df: pd.DataFrame, blacklist_size: int) -> str:
    row = defense_df[defense_df["Blacklist Size"] == blacklist_size]
    if row.empty:
        row = defense_df.iloc[-1]
    else:
        row = row.iloc[0]

    original = float(row["Original Top-10 Success Rate"])
    new = float(row["New Top-10 Success Rate"])
    abs_red = float(row["Absolute Reduction"])
    rel_red = float(row["Relative Reduction"])

    return f"""
**Defense conclusion**

Using weak PIN blacklisting with the top **{blacklist_size}** most frequent PINs removed:

- Original Top-10 success rate: **{original:.4f}** ({original * 100:.2f}%)
- New Top-10 success rate: **{new:.4f}** ({new * 100:.2f}%)
- Absolute reduction: **{abs_red:.4f}**
- Relative reduction: **{rel_red * 100:.2f}%**

Blacklisting common weak PINs can significantly reduce guessability, especially for biased and leakage-based PIN distributions.
"""


def compute_attempt_limit_from_topk(attack_results: dict, threshold: float = 0.05) -> int:
    """
    Method 1: Top-k success rate.
    Find the first measured k where the strongest attack exceeds threshold.
    Recommend k-1 as the safe limit.
    """
    max_at_k = {}
    for k in K_VALUES:
        key = f"Top-{k}"
        max_at_k[k] = max(v.get(key, 0.0) for v in attack_results.values())
    for k in sorted(max_at_k):
        if max_at_k[k] >= threshold:
            return max(k - 1, 0)
    return max(K_VALUES)


def compute_attempt_limit_from_expected_guesses(expected_guesses: float) -> int:
    """
    Method 2: Expected guesses.
    Use 1% of expected guesses as a conservative bound, capped between 1 and 20.
    """
    return max(1, min(int(expected_guesses * 0.01), 20))


def compute_attempt_limit_from_cumulative(
    freq: pd.DataFrame,
    leaked_candidates: list,
    test_distribution: dict,
    threshold: float = 0.05,
    max_k: int = 30,
) -> tuple:
    """
    Method 3: Cumulative success curve.
    Rank order built from TRAIN freq; cumulative success evaluated on TEST distribution.
    Returns (curves_dict, limits_dict, worst_case_limit).
    """
    from src.attack import (
        build_frequency_ranked_guess_order,
        build_rule_based_guess_order,
        build_random_guess_order,
        build_leakage_guess_order,
        _get_distribution_dict,
        _normalize_pin,
    )

    train_distribution = _get_distribution_dict(freq)

    def cumulative(order):
        return [
            sum(test_distribution.get(_normalize_pin(p), 0.0) for p in order[:k])
            for k in range(1, max_k + 1)
        ]

    curves = {
        "Frequency-Ranked": cumulative(build_frequency_ranked_guess_order(freq)),
        "Rule-Based":        cumulative(build_rule_based_guess_order(freq)),
        "Leakage-Assisted":  cumulative(build_leakage_guess_order(freq, leaked_candidates)),
        "Random":            cumulative(build_random_guess_order(train_distribution, seed=42)),
    }

    def safe_limit(curve):
        for k, val in enumerate(curve, start=1):
            if val >= threshold:
                return k - 1
        return max_k

    limits = {name: safe_limit(c) for name, c in curves.items()}
    return curves, limits, min(limits.values())


def plot_cumulative_curves_inline(curves: dict, threshold: float, model: str) -> None:
    colors = {
        "Frequency-Ranked": "#e74c3c",
        "Rule-Based":        "#e67e22",
        "Leakage-Assisted":  "#8e44ad",
        "Random":            "#95a5a6",
    }
    max_k = len(next(iter(curves.values())))
    x = list(range(1, max_k + 1))
    fig, ax = plt.subplots(figsize=(11, 5))
    for name, vals in curves.items():
        ax.plot(x, [v * 100 for v in vals],
                label=name, color=colors.get(name), linewidth=2)
    ax.axhline(y=threshold * 100, color="#27ae60", linestyle="--", linewidth=1.8,
               label=f"Risk threshold ({threshold * 100:.0f}%)")
    ax.set_title(f"Cumulative Attack Success vs. Number of Attempts — {model} model")
    ax.set_xlabel("Number of Attempts (k)")
    ax.set_ylabel("Cumulative Success Rate (%)")
    ax.legend()
    ax.grid(True, alpha=0.25)
    ax.set_xlim(1, max_k)
    st.pyplot(fig)
    plt.close(fig)


def render_final_recommendation(
    model: str,
    metrics: dict,
    attack_results: dict,
    defense_df: pd.DataFrame,
    blacklist_size: int,
    leaked_candidates: list,
    freq: pd.DataFrame,
    test_distribution: dict,
) -> None:
    """
    Section 5: Final Recommendation.
    Combines attack/defense summary with attempt limit analysis
    using three methods; takes the most conservative result.
    Train freq used for ranking; test_distribution used for cumulative evaluation.
    """
    THRESHOLD = 0.05

    best_attack, best_success = get_best_attack(attack_results, "Top-10")
    expected = metrics["Expected Guesses"]

    defense_row = defense_df[defense_df["Blacklist Size"] == blacklist_size]
    defense_row = defense_row.iloc[0] if not defense_row.empty else defense_df.iloc[-1]
    new_success = float(defense_row["New Top-10 Success Rate"])

    # Three methods
    limit_topk     = compute_attempt_limit_from_topk(attack_results, threshold=THRESHOLD)
    limit_expected = compute_attempt_limit_from_expected_guesses(expected)
    curves, limits_per_attack, limit_cumulative = compute_attempt_limit_from_cumulative(
        freq, leaked_candidates, test_distribution=test_distribution, threshold=THRESHOLD
    )

    # Final: most conservative across all three
    final_limit = max(min(limit_topk, limit_expected, limit_cumulative), 0)

    if final_limit == 0:
        verdict_icon, verdict = "⚠️", (
            "Even **1 attempt** may already exceed the 5% risk threshold for the strongest "
            "attack. This PIN distribution is critically weak. "
            "Weak PIN blacklisting alone is insufficient — a very strict lockout policy is required."
        )
    elif final_limit <= 3:
        verdict_icon, verdict = "🔴", (
            f"The system should lock after **no more than {final_limit} attempt(s)**. "
            f"Beyond this, the attacker's cumulative success exceeds 5%. "
            f"Weak PIN blacklisting can reduce this risk further by removing the most predictable PINs."
        )
    elif final_limit <= 5:
        verdict_icon, verdict = "🟠", (
            f"A limit of **{final_limit} attempts** is the maximum safe setting for this distribution. "
            f"Weak PIN blacklisting (evaluated in Section 4) can lower the success rate further, "
            f"allowing a slightly more relaxed lockout policy."
        )
    else:
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
""")

    st.markdown("**Cumulative success curve by attack strategy:**")
    plot_cumulative_curves_inline(curves, THRESHOLD, model)

    limit_rows = [
        {"Attack Strategy": name, "Safe Attempt Limit": lim if lim > 0 else "< 1"}
        for name, lim in limits_per_attack.items()
    ]
    st.dataframe(pd.DataFrame(limit_rows), use_container_width=True)

    st.caption(
        "Risk threshold is fixed at 5%. The final limit is the minimum across all three "
        "analysis methods, ensuring the most conservative and defensible recommendation."
    )




# ============================================================
# Core Experiment Runner
# ============================================================

def run_experiment(model: str, dob: str, n: int, seed: int, use_survey_weights: bool, blacklist_size: int) -> dict:
    """Run one full experiment using src/ pipeline — consistent with main.py (80/20 train/test split)."""
    ensure_dirs()

    # 1. Generate pins
    pins = generate_dataset(
        n=n, model=model, seed=seed, dob=dob,
        use_survey_weights=use_survey_weights,
        randomize_dob=True,
    )

    # 2. Save full dataset
    data_path = os.path.join(DATA_DIR, f"generated_{model}_pins.csv")
    save_dataset(pins, data_path)

    # 3. Train/test split (80/20) — same as main.py
    train_pins, test_pins = train_test_split_pins(pins, train_ratio=0.80, seed=seed)

    # 4. Build frequency from TRAIN set only
    train_freq = compute_frequency_from_pins(train_pins)
    freq_path = os.path.join(RESULTS_DIR, f"frequency_{model}.csv")
    save_frequency(train_freq, output_path=freq_path)

    # 5. Security metrics from TRAIN distribution
    metrics = compute_security_metrics(train_freq)

    # 6. Test distribution for Top-k evaluation
    test_dist = compute_test_distribution(test_pins)

    # 7. Attacks: rank on TRAIN, evaluate on TEST
    leaked_candidates = dob_to_candidate_pins(dob)
    attack_results = evaluate_all_attacks(
        train_freq_df=train_freq,
        test_distribution=test_dist,
        leaked_candidates=leaked_candidates,
        k_values=K_VALUES,
        seed=seed,
    )

    # 8. Defense on TRAIN distribution
    defense_df = run_weak_pin_blacklisting_study(freq=train_freq, model_name=model, blacklist_sizes=BLACKLIST_SIZES, k=10)
    defense_path = os.path.join(RESULTS_DIR, f"app_defense_{model}.csv")
    defense_df.to_csv(defense_path, index=False)

    return {
        "experiment_name": f"6-digit {model}",
        "model": model,
        "freq": train_freq,
        "metrics": metrics,
        "attack_results": attack_results,
        "defense_df": defense_df,
        "leaked_candidates": leaked_candidates,
        "blacklist_size": blacklist_size,
        "train_size": len(train_pins),
        "test_size": len(test_pins),
        "test_distribution": test_dist,
        "saved_files": {"data_path": data_path, "freq_path": freq_path, "defense_path": defense_path},
    }


# ============================================================
# Sidebar
# ============================================================

st.sidebar.title("Experiment Configuration")

model_mode = st.sidebar.selectbox(
    "Select PIN model",
    ["All models", "uniform", "biased", "leakage"],
    index=0,
)

dob = st.sidebar.text_input("Date of Birth (leakage model)", value=DEFAULT_DOB, help="Format: YYYY-MM-DD")

n = st.sidebar.number_input("Dataset size", min_value=1000, max_value=1000000, value=DEFAULT_N, step=1000)

seed = st.sidebar.number_input("Random seed", min_value=0, max_value=999999, value=DEFAULT_SEED, step=1)

use_survey_weights = st.sidebar.checkbox(
    "Use survey-based weights",
    value=True,
    help="Makes biased and leakage models more realistic based on survey data.",
)

blacklist_size = st.sidebar.selectbox("Defense blacklist size (for conclusion)", BLACKLIST_SIZES, index=3)

run_button = st.sidebar.button("Run Experiment", type="primary")


# ============================================================
# Main Page
# ============================================================

st.title("PIN Security Analysis System")
st.markdown("""
This application demonstrates low-entropy attacks on **6-digit PINs** by comparing
uniform, biased, and leakage-based PIN models, and evaluates **weak PIN blacklisting** as a defense.

> Uses the same `src/` pipeline as `main.py` — results are fully consistent.
> Frequency rankings are built on the **training set (80%)** and Top-k success rates are evaluated on the **test set (20%)**, avoiding evaluation leakage.
""")


# ============================================================
# Run Experiment
# ============================================================

if run_button:
    try:
        datetime.strptime(dob, "%Y-%m-%d")

        models = ["uniform", "biased", "leakage"] if model_mode == "All models" else [model_mode]

        st.session_state.experiment_results = []
        st.session_state.summary_df = pd.DataFrame()
        st.session_state.defense_summary_df = pd.DataFrame()
        st.session_state.has_run = False

        all_summary_rows = []
        all_defense_rows = []

        with st.spinner("Running experiment..."):
            for model in models:
                result = run_experiment(
                    model=model, dob=dob, n=int(n), seed=int(seed),
                    use_survey_weights=use_survey_weights, blacklist_size=int(blacklist_size),
                )

                metrics = result["metrics"]
                attack_results = result["attack_results"]
                defense_df = result["defense_df"]

                summary_row = {
                    "Experiment": result["experiment_name"],
                    "Model": model,
                    "Shannon Entropy (bits)": metrics["Shannon Entropy (bits)"],
                    "Min-Entropy (bits)": metrics["Min-Entropy (bits)"],
                    "Expected Guesses": metrics["Expected Guesses"],
                }
                for attack_name, topk_dict in attack_results.items():
                    for k in K_VALUES:
                        summary_row[f"{attack_name} - Top-{k}"] = topk_dict.get(f"Top-{k}", 0.0)

                all_summary_rows.append(summary_row)
                all_defense_rows.extend(defense_df.to_dict("records"))
                st.session_state.experiment_results.append(result)

        summary_df = pd.DataFrame(all_summary_rows)
        defense_summary_df = pd.DataFrame(all_defense_rows)

        summary_df.to_csv(os.path.join(RESULTS_DIR, "app_summary_all_models.csv"), index=False)
        defense_summary_df.to_csv(os.path.join(RESULTS_DIR, "app_defense_all_models.csv"), index=False)

        st.session_state.summary_df = summary_df
        st.session_state.defense_summary_df = defense_summary_df
        st.session_state.has_run = True

        st.success("Experiment completed successfully.")

    except ValueError as ve:
        st.error(f"Invalid input: {ve}")
    except Exception as e:
        st.error(f"Error: {e}")


# ============================================================
# Display Results
# ============================================================

if st.session_state.has_run and st.session_state.experiment_results:

    st.header("Overall Summary")

    if not st.session_state.summary_df.empty:
        st.dataframe(st.session_state.summary_df, use_container_width=True)
        col_a, col_b = st.columns(2)
        with col_a:
            plot_entropy_summary(st.session_state.summary_df)
        with col_b:
            plot_min_entropy_summary(st.session_state.summary_df)
        plot_expected_guesses_summary(st.session_state.summary_df)

    if not st.session_state.defense_summary_df.empty:
        st.subheader("Defense Summary (All Models)")
        st.dataframe(st.session_state.defense_summary_df, use_container_width=True)

    for result in st.session_state.experiment_results:
        experiment_name = result["experiment_name"]
        model = result["model"]
        freq = result["freq"]
        metrics = result["metrics"]
        attack_results = result["attack_results"]
        defense_df = result["defense_df"]
        bsize = result["blacklist_size"]
        saved_files = result["saved_files"]

        st.markdown("---")
        st.header(experiment_name)

        # 1. Security Metrics
        st.subheader("1. Security Metrics")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Shannon Entropy", f"{metrics['Shannon Entropy (bits)']:.4f} bits")
        with col2:
            st.metric("Min-Entropy", f"{metrics['Min-Entropy (bits)']:.4f} bits")
        with col3:
            st.metric("Expected Guesses", f"{metrics['Expected Guesses']:.2f}")

        # 2. Top 10 PINs
        st.subheader("2. Top 10 Most Common PINs")
        st.dataframe(freq.head(10), use_container_width=True)
        plot_top_pins(freq, title=f"Top 10 Most Common PINs — {experiment_name}")

        # 3. Attack Results
        st.subheader("3. Attack Success Comparison")
        attack_rows = []
        for attack_name, topk_dict in attack_results.items():
            row = {"Attack Strategy": attack_name}
            for k in K_VALUES:
                row[f"Top-{k}"] = topk_dict.get(f"Top-{k}", 0.0)
            attack_rows.append(row)
        attack_display_df = pd.DataFrame(attack_rows)
        st.dataframe(attack_display_df, use_container_width=True)

        selected_k = st.selectbox(
            f"Select Top-k metric to visualize — {experiment_name}",
            [f"Top-{k}" for k in K_VALUES],
            index=3,
            key=f"metric_selector_{model}",
        )
        plot_attack_results(attack_results, selected_k)
        st.markdown(generate_attack_conclusion(model, metrics, attack_results))

        # 4. Defense Study
        st.subheader("4. Defense Study: Weak PIN Blacklisting")
        st.dataframe(defense_df, use_container_width=True)
        plot_defense_curve(defense_df)
        st.markdown(generate_defense_conclusion(defense_df, bsize))

        # 5. Final Recommendation & Attempt Limit Analysis
        st.subheader("5. Final Recommendation")
        render_final_recommendation(
            model=model,
            metrics=metrics,
            attack_results=attack_results,
            defense_df=defense_df,
            blacklist_size=bsize,
            leaked_candidates=result["leaked_candidates"],
            freq=freq,
            test_distribution=result["test_distribution"],
        )

        st.info(
            f"Train/test split: **{result['train_size']:,}** train / **{result['test_size']:,}** test (80/20). "
            f"Frequency ranking built on train set; Top-k success rates evaluated on test set. "
            f"Saved: `{saved_files['data_path']}`, `{saved_files['freq_path']}`, `{saved_files['defense_path']}`"
        )

else:
    st.info("Configure the experiment in the sidebar, then click **Run Experiment**.")
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
""")