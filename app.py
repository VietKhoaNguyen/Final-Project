import os
import math
import random
from datetime import datetime

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import streamlit as st


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


def safe_parse_dob(dob: str) -> datetime:
    try:
        return datetime.strptime(dob, "%Y-%m-%d")
    except ValueError:
        raise ValueError("DOB must be in YYYY-MM-DD format, for example: 1998-03-05")


def format_pin(value: int | str, pin_length: int) -> str:
    return str(value).zfill(pin_length)[-pin_length:]


def get_pin_space_size(pin_length: int) -> int:
    return 10 ** pin_length


def get_pin_lengths_from_mode(pin_mode: str) -> list[int]:
    if pin_mode == "4-digit PIN only":
        return [4]
    if pin_mode == "6-digit PIN only":
        return [6]
    return [4, 6]


def get_models_from_mode(model_mode: str) -> list[str]:
    if model_mode == "All models":
        return ["uniform", "biased", "leakage"]
    return [model_mode.lower()]


def save_dataset(pins: list[str], output_path: str) -> None:
    df = pd.DataFrame({"pin": pins})
    df.to_csv(output_path, index=False)


def save_dataframe(df: pd.DataFrame, output_path: str) -> None:
    df.to_csv(output_path, index=False)


# ============================================================
# DOB Candidate Generation
# ============================================================

def dob_to_candidate_pins(dob: str, pin_length: int) -> list[str]:
    """
    Generate DOB-related candidate PINs.

    For 4-digit:
    - DDMM
    - MMDD
    - YYMM
    - MMYY
    - YYYY

    For 6-digit:
    - DDMMYY
    - MMDDYY
    - YYMMDD
    - YYYYMM
    - MMYYYY
    - YYYYDD
    - DDYYYY
    - YYDDMM
    - DDYYMM
    """
    date = safe_parse_dob(dob)

    dd = f"{date.day:02d}"
    mm = f"{date.month:02d}"
    yy = f"{date.year % 100:02d}"
    yyyy = f"{date.year:04d}"

    if pin_length == 4:
        candidates = [
            dd + mm,
            mm + dd,
            yy + mm,
            mm + yy,
            yyyy,
        ]
    elif pin_length == 6:
        candidates = [
            dd + mm + yy,
            mm + dd + yy,
            yy + mm + dd,
            yyyy + mm,
            mm + yyyy,
            yyyy + dd,
            dd + yyyy,
            yy + dd + mm,
            dd + yy + mm,
            mm + yy + dd,
        ]
    else:
        raise ValueError("pin_length must be either 4 or 6")

    cleaned = []
    for pin in candidates:
        pin = format_pin(pin, pin_length)
        if pin not in cleaned:
            cleaned.append(pin)

    return cleaned


def common_rule_based_pins(pin_length: int) -> list[str]:
    if pin_length == 4:
        base = [
            "0000", "1111", "2222", "3333", "4444",
            "5555", "6666", "7777", "8888", "9999",
            "1234", "4321", "0123", "3210", "2580",
            "0852", "1212", "6969", "2000", "2020",
            "1998", "2001", "2002", "2003", "2004",
        ]
    else:
        base = [
            "000000", "111111", "222222", "333333", "444444",
            "555555", "666666", "777777", "888888", "999999",
            "123456", "654321", "012345", "543210", "112233",
            "121212", "696969", "010101", "101010", "200000",
            "202020", "199800", "001998", "200100", "002001",
        ]

    return list(dict.fromkeys(base))


# ============================================================
# PIN Generation Models
# ============================================================

def generate_uniform_dataset(n: int, pin_length: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    max_value = get_pin_space_size(pin_length) - 1

    return [
        format_pin(rng.randint(0, max_value), pin_length)
        for _ in range(n)
    ]


def generate_biased_dataset(
    n: int,
    pin_length: int,
    seed: int,
    dob: str
) -> list[str]:
    """
    Synthetic biased model.

    Bias sources:
    - repeated digits
    - sequential patterns
    - DOB-related patterns
    - random fallback
    """
    rng = random.Random(seed)

    repeated = [str(d) * pin_length for d in range(10)]

    if pin_length == 4:
        sequences = ["1234", "4321", "0123", "3210", "2580", "0852"]
        cultural = ["0000", "8888", "9999", "1212", "6969", "2020"]
    else:
        sequences = ["123456", "654321", "012345", "543210"]
        cultural = ["000000", "888888", "999999", "121212", "696969", "202020"]

    dob_candidates = dob_to_candidate_pins(dob, pin_length)

    pins = []
    max_value = get_pin_space_size(pin_length) - 1

    for _ in range(n):
        r = rng.random()

        if r < 0.30:
            pins.append(rng.choice(repeated))
        elif r < 0.50:
            pins.append(rng.choice(dob_candidates))
        elif r < 0.65:
            pins.append(rng.choice(sequences))
        elif r < 0.78:
            pins.append(rng.choice(cultural))
        else:
            pins.append(format_pin(rng.randint(0, max_value), pin_length))

    return pins


def generate_leakage_dataset(
    n: int,
    pin_length: int,
    seed: int,
    dob: str
) -> list[str]:
    """
    Leakage model.

    This model assumes the attacker has partial personal information,
    especially DOB. Therefore DOB-related PINs receive a much higher
    probability mass than in the general biased model.
    """
    rng = random.Random(seed)

    dob_candidates = dob_to_candidate_pins(dob, pin_length)
    rule_pins = common_rule_based_pins(pin_length)

    pins = []
    max_value = get_pin_space_size(pin_length) - 1

    for _ in range(n):
        r = rng.random()

        if r < 0.55:
            pins.append(rng.choice(dob_candidates))
        elif r < 0.75:
            pins.append(rng.choice(rule_pins))
        elif r < 0.90:
            pins.append(rng.choice(dob_candidates + rule_pins))
        else:
            pins.append(format_pin(rng.randint(0, max_value), pin_length))

    return pins


def generate_dataset(
    n: int,
    model: str,
    pin_length: int,
    seed: int,
    dob: str
) -> list[str]:
    if model == "uniform":
        return generate_uniform_dataset(n=n, pin_length=pin_length, seed=seed)

    if model == "biased":
        return generate_biased_dataset(
            n=n,
            pin_length=pin_length,
            seed=seed,
            dob=dob
        )

    if model == "leakage":
        return generate_leakage_dataset(
            n=n,
            pin_length=pin_length,
            seed=seed,
            dob=dob
        )

    raise ValueError("model must be one of: uniform, biased, leakage")


# ============================================================
# Frequency and Security Metrics
# ============================================================

def compute_frequency_from_pins(pins: list[str]) -> pd.DataFrame:
    df = pd.DataFrame({"PIN": pins})
    freq = (
        df["PIN"]
        .value_counts()
        .reset_index()
    )

    freq.columns = ["PIN", "Count"]
    freq["Probability"] = freq["Count"] / freq["Count"].sum()
    freq = freq.sort_values(
        by=["Probability", "PIN"],
        ascending=[False, True]
    ).reset_index(drop=True)

    return freq


def compute_security_metrics(freq: pd.DataFrame, pin_length: int) -> dict:
    probabilities = freq["Probability"].astype(float).to_numpy()

    shannon_entropy = -np.sum(probabilities * np.log2(probabilities))
    max_probability = float(np.max(probabilities))
    min_entropy = -math.log2(max_probability)

    ranked_probs = probabilities
    ranks = np.arange(1, len(ranked_probs) + 1)
    expected_guesses = float(np.sum(ranks * ranked_probs))

    return {
        "PIN Length": pin_length,
        "Shannon Entropy (bits)": float(shannon_entropy),
        "Min-Entropy (bits)": float(min_entropy),
        "Expected Guesses": expected_guesses,
        "Max Probability": max_probability,
    }


# ============================================================
# Attack Simulation
# ============================================================

def evaluate_top_k_success(
    freq: pd.DataFrame,
    guess_order: list[str],
    k_values: list[int]
) -> dict:
    probability_map = dict(zip(freq["PIN"], freq["Probability"]))

    results = {}

    for k in k_values:
        guesses = guess_order[:k]
        success = sum(probability_map.get(pin, 0.0) for pin in guesses)
        results[f"Top-{k} Success Rate"] = float(success)

    return results


def random_guess_order(pin_length: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    pin_space_size = get_pin_space_size(pin_length)

    all_pins = [format_pin(i, pin_length) for i in range(pin_space_size)]
    rng.shuffle(all_pins)

    return all_pins


def frequency_ranked_guess_order(freq: pd.DataFrame) -> list[str]:
    return freq["PIN"].astype(str).tolist()


def rule_based_guess_order(pin_length: int, freq: pd.DataFrame) -> list[str]:
    rules = common_rule_based_pins(pin_length)

    ranked = frequency_ranked_guess_order(freq)
    ordered = []

    for pin in rules:
        if pin not in ordered:
            ordered.append(pin)

    for pin in ranked:
        if pin not in ordered:
            ordered.append(pin)

    return ordered


def leakage_assisted_guess_order(
    dob: str,
    pin_length: int,
    freq: pd.DataFrame
) -> list[str]:
    candidates = dob_to_candidate_pins(dob, pin_length)
    ranked = frequency_ranked_guess_order(freq)

    ordered = []

    for pin in candidates:
        if pin not in ordered:
            ordered.append(pin)

    for pin in ranked:
        if pin not in ordered:
            ordered.append(pin)

    return ordered


def evaluate_all_attacks(
    freq: pd.DataFrame,
    pin_length: int,
    dob: str,
    seed: int,
    k_values: list[int]
) -> pd.DataFrame:
    attacks = {
        "Random": random_guess_order(pin_length, seed),
        "Frequency-Ranked": frequency_ranked_guess_order(freq),
        "Rule-Based": rule_based_guess_order(pin_length, freq),
        "Leakage-Assisted": leakage_assisted_guess_order(dob, pin_length, freq),
    }

    rows = []

    for attack_name, guess_order in attacks.items():
        row = {"Attack Strategy": attack_name}
        row.update(evaluate_top_k_success(freq, guess_order, k_values))
        rows.append(row)

    return pd.DataFrame(rows)


# ============================================================
# Defense Study: Weak PIN Blacklisting
# ============================================================

def remove_top_frequent_pins(freq: pd.DataFrame, blacklist_size: int) -> pd.DataFrame:
    filtered = freq.iloc[blacklist_size:].copy()

    if filtered.empty:
        return filtered

    total_probability = filtered["Probability"].sum()

    if total_probability > 0:
        filtered["Probability"] = filtered["Probability"] / total_probability

    filtered = filtered.reset_index(drop=True)
    return filtered


def run_weak_pin_blacklisting_study(
    freq: pd.DataFrame,
    model: str,
    pin_length: int,
    blacklist_sizes: list[int],
    k: int = 10
) -> tuple[pd.DataFrame, dict]:
    original_top_k_success = float(freq.head(k)["Probability"].sum())

    rows = []

    for size in blacklist_sizes:
        filtered_freq = remove_top_frequent_pins(freq, size)

        if filtered_freq.empty:
            new_top_k_success = 0.0
        else:
            new_top_k_success = float(filtered_freq.head(k)["Probability"].sum())

        absolute_reduction = original_top_k_success - new_top_k_success

        relative_reduction = (
            absolute_reduction / original_top_k_success
            if original_top_k_success > 0
            else 0.0
        )

        rows.append({
            "Model": model,
            "PIN Length": pin_length,
            "Defense Type": "Weak PIN Blacklisting",
            "Blacklist Size": size,
            "Original Top-10 Success Rate": original_top_k_success,
            "New Top-10 Success Rate": new_top_k_success,
            "Absolute Reduction": absolute_reduction,
            "Relative Reduction": relative_reduction,
        })

    defense_df = pd.DataFrame(rows)

    selected_row = defense_df[
        defense_df["Blacklist Size"] == max(blacklist_sizes)
    ].iloc[0].to_dict()

    return defense_df, selected_row


# ============================================================
# Plotting Functions
# ============================================================

def plot_top_pins(freq: pd.DataFrame, title: str, top_n: int = 10) -> None:
    top = freq.head(top_n).copy()

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.bar(top["PIN"], top["Probability"])
    ax.set_title(title)
    ax.set_xlabel("PIN")
    ax.set_ylabel("Probability")
    ax.tick_params(axis="x", rotation=45)
    st.pyplot(fig)


def plot_attack_results(attack_df: pd.DataFrame, metric_name: str) -> None:
    if metric_name not in attack_df.columns:
        st.warning(f"No data found for {metric_name}.")
        return

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.bar(attack_df["Attack Strategy"], attack_df[metric_name])
    ax.set_title(f"Attack Success Comparison ({metric_name})")
    ax.set_xlabel("Attack Strategy")
    ax.set_ylabel("Success Rate")
    ax.tick_params(axis="x", rotation=20)
    st.pyplot(fig)


def plot_defense_curve(defense_df: pd.DataFrame) -> None:
    if defense_df.empty:
        st.warning("No defense data available.")
        return

    fig, ax = plt.subplots(figsize=(12, 5))
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


def plot_entropy_summary(summary_df: pd.DataFrame) -> None:
    if summary_df.empty:
        return

    fig, ax = plt.subplots(figsize=(12, 5))
    labels = summary_df["Experiment"]
    values = summary_df["Shannon Entropy (bits)"]

    ax.bar(labels, values)
    ax.set_title("Shannon Entropy Comparison")
    ax.set_xlabel("Experiment")
    ax.set_ylabel("Shannon Entropy (bits)")
    ax.tick_params(axis="x", rotation=45)
    st.pyplot(fig)


def plot_min_entropy_summary(summary_df: pd.DataFrame) -> None:
    if summary_df.empty:
        return

    fig, ax = plt.subplots(figsize=(12, 5))
    labels = summary_df["Experiment"]
    values = summary_df["Min-Entropy (bits)"]

    ax.bar(labels, values)
    ax.set_title("Min-Entropy Comparison")
    ax.set_xlabel("Experiment")
    ax.set_ylabel("Min-Entropy (bits)")
    ax.tick_params(axis="x", rotation=45)
    st.pyplot(fig)


def plot_expected_guesses_summary(summary_df: pd.DataFrame) -> None:
    if summary_df.empty:
        return

    fig, ax = plt.subplots(figsize=(12, 5))
    labels = summary_df["Experiment"]
    values = summary_df["Expected Guesses"]

    ax.bar(labels, values)
    ax.set_title("Expected Guesses Comparison")
    ax.set_xlabel("Experiment")
    ax.set_ylabel("Expected Number of Guesses")
    ax.tick_params(axis="x", rotation=45)
    st.pyplot(fig)


# ============================================================
# Interpretation Functions
# ============================================================

def get_best_attack(attack_df: pd.DataFrame, metric: str = "Top-10 Success Rate") -> tuple[str, float]:
    if metric not in attack_df.columns:
        return "N/A", 0.0

    row = attack_df.sort_values(by=metric, ascending=False).iloc[0]
    return str(row["Attack Strategy"]), float(row[metric])


def generate_attack_conclusion(
    pin_length: int,
    model: str,
    metrics: dict,
    attack_df: pd.DataFrame
) -> str:
    best_attack, best_success = get_best_attack(attack_df, "Top-10 Success Rate")

    shannon = metrics["Shannon Entropy (bits)"]
    min_entropy = metrics["Min-Entropy (bits)"]
    expected = metrics["Expected Guesses"]

    if model == "uniform":
        interpretation = (
            "The uniform model behaves closest to an ideal random PIN selection process. "
            "Attack success remains very low because probability is spread across a large key space."
        )
    elif model == "biased":
        interpretation = (
            "The biased model shows that human-like PIN choices reduce practical security. "
            "Common patterns such as repeated digits, sequences, and date-like values increase the probability of successful guessing."
        )
    else:
        interpretation = (
            "The leakage model is the riskiest setting because the attacker can prioritize DOB-related candidates. "
            "This strongly increases the success rate under a small number of allowed guesses."
        )

    return f"""
**Attack conclusion for {pin_length}-digit {model} model**

- Shannon entropy: **{shannon:.4f} bits**
- Min-entropy: **{min_entropy:.4f} bits**
- Expected guesses: **{expected:.2f}**
- Strongest Top-10 attack: **{best_attack}**
- Top-10 success rate: **{best_success:.4f}** ({best_success * 100:.2f}%)

{interpretation}
"""


def generate_defense_conclusion(
    defense_result: dict,
    blacklist_size: int
) -> str:
    original = float(defense_result["Original Top-10 Success Rate"])
    new = float(defense_result["New Top-10 Success Rate"])
    abs_reduction = float(defense_result["Absolute Reduction"])
    rel_reduction = float(defense_result["Relative Reduction"])

    return f"""
**Defense conclusion**

Using weak PIN blacklisting with the top **{blacklist_size}** most frequent PINs removed:

- Original Top-10 success rate: **{original:.4f}** ({original * 100:.2f}%)
- New Top-10 success rate: **{new:.4f}** ({new * 100:.2f}%)
- Absolute reduction: **{abs_reduction:.4f}**
- Relative reduction: **{rel_reduction * 100:.2f}%**

This shows that blacklisting common weak PINs can significantly reduce guessability, especially for biased and leakage-based PIN distributions.
"""


def generate_final_recommendation(
    pin_length: int,
    model: str,
    attack_df: pd.DataFrame,
    defense_result: dict
) -> str:
    best_attack, best_success = get_best_attack(attack_df, "Top-10 Success Rate")
    new_success = float(defense_result["New Top-10 Success Rate"])

    if best_success >= 0.20:
        limit_advice = "A strict attempt limit of around **3 to 5 attempts** is recommended."
    elif best_success >= 0.05:
        limit_advice = "A moderate attempt limit such as **5 attempts** is recommended."
    else:
        limit_advice = "The attack success rate is low, but an attempt limit is still necessary."

    return f"""
**Final recommendation**

For the **{pin_length}-digit {model}** setting, the strongest observed attack is **{best_attack}**.

Before defense, the Top-10 success rate is **{best_success * 100:.2f}%**.  
After weak PIN blacklisting, the Top-10 success rate becomes **{new_success * 100:.2f}%**.

Therefore, the system should avoid allowing many repeated attempts. {limit_advice}

The result supports the thesis argument that PIN security should not be evaluated only by theoretical key-space size. Practical guessability, user bias, and personal-information leakage must also be considered.
"""


# ============================================================
# Sidebar
# ============================================================

st.sidebar.title("Experiment Configuration")

pin_mode = st.sidebar.selectbox(
    "Select PIN length",
    [
        "6-digit PIN only",
        "4-digit PIN only",
        "Both 4-digit and 6-digit"
    ],
    index=0
)

model_mode = st.sidebar.selectbox(
    "Select PIN model",
    [
        "All models",
        "uniform",
        "biased",
        "leakage"
    ],
    index=0
)

dob = st.sidebar.text_input(
    "Date of Birth for leakage model",
    value=DEFAULT_DOB,
    help="Format: YYYY-MM-DD"
)

n = st.sidebar.number_input(
    "Dataset size",
    min_value=1000,
    max_value=1000000,
    value=DEFAULT_N,
    step=1000
)

seed = st.sidebar.number_input(
    "Random seed",
    min_value=0,
    max_value=999999,
    value=DEFAULT_SEED,
    step=1
)

blacklist_size = st.sidebar.selectbox(
    "Defense blacklist size used for conclusion",
    BLACKLIST_SIZES,
    index=3
)

run_button = st.sidebar.button("Run Experiment", type="primary")


# ============================================================
# Main Page
# ============================================================

st.title("PIN Security Analysis System")
st.markdown(
    """
This application demonstrates low-entropy attacks on PINs by comparing uniform, biased, and leakage-based PIN models.
It also evaluates a simple defense strategy: **weak PIN blacklisting**.
"""
)


# ============================================================
# Run Experiment
# ============================================================

if run_button:
    try:
        ensure_dirs()
        safe_parse_dob(dob)

        pin_lengths = get_pin_lengths_from_mode(pin_mode)
        models = get_models_from_mode(model_mode)

        st.session_state.experiment_results = []
        st.session_state.summary_df = pd.DataFrame()
        st.session_state.defense_summary_df = pd.DataFrame()
        st.session_state.has_run = False

        all_summary_rows = []
        all_defense_rows = []

        with st.spinner("Running experiment..."):
            for pin_length in pin_lengths:
                for model in models:
                    pins = generate_dataset(
                        n=int(n),
                        model=model,
                        pin_length=pin_length,
                        seed=int(seed),
                        dob=dob
                    )

                    freq = compute_frequency_from_pins(pins)
                    metrics = compute_security_metrics(freq, pin_length)

                    attack_df = evaluate_all_attacks(
                        freq=freq,
                        pin_length=pin_length,
                        dob=dob,
                        seed=int(seed),
                        k_values=K_VALUES
                    )

                    defense_curve_df, selected_defense_result = run_weak_pin_blacklisting_study(
                        freq=freq,
                        model=model,
                        pin_length=pin_length,
                        blacklist_sizes=BLACKLIST_SIZES,
                        k=10
                    )

                    experiment_name = f"{pin_length}-digit {model}"

                    data_path = os.path.join(DATA_DIR, f"generated_{pin_length}digit_{model}_pins.csv")
                    freq_path = os.path.join(RESULTS_DIR, f"frequency_{pin_length}digit_{model}.csv")
                    attack_path = os.path.join(RESULTS_DIR, f"attack_{pin_length}digit_{model}.csv")
                    defense_path = os.path.join(RESULTS_DIR, f"defense_{pin_length}digit_{model}.csv")

                    save_dataset(pins, data_path)
                    save_dataframe(freq, freq_path)
                    save_dataframe(attack_df, attack_path)
                    save_dataframe(defense_curve_df, defense_path)

                    summary_row = {
                        "Experiment": experiment_name,
                        "PIN Length": pin_length,
                        "Model": model,
                        "Shannon Entropy (bits)": metrics["Shannon Entropy (bits)"],
                        "Min-Entropy (bits)": metrics["Min-Entropy (bits)"],
                        "Expected Guesses": metrics["Expected Guesses"],
                        "Max Probability": metrics["Max Probability"],
                    }

                    for _, row in attack_df.iterrows():
                        attack_name = row["Attack Strategy"]
                        for k in K_VALUES:
                            metric_name = f"Top-{k} Success Rate"
                            summary_row[f"{attack_name} - {metric_name}"] = row[metric_name]

                    all_summary_rows.append(summary_row)
                    all_defense_rows.extend(defense_curve_df.to_dict("records"))

                    st.session_state.experiment_results.append({
                        "experiment_name": experiment_name,
                        "pin_length": pin_length,
                        "model": model,
                        "pins": pins,
                        "freq": freq,
                        "metrics": metrics,
                        "attack_df": attack_df,
                        "defense_curve_df": defense_curve_df,
                        "defense_result": selected_defense_result,
                        "blacklist_size": int(blacklist_size),
                        "saved_files": {
                            "data_path": data_path,
                            "freq_path": freq_path,
                            "attack_path": attack_path,
                            "defense_path": defense_path,
                        }
                    })

        summary_df = pd.DataFrame(all_summary_rows)
        defense_summary_df = pd.DataFrame(all_defense_rows)

        summary_path = os.path.join(RESULTS_DIR, "summary_all_models.csv")
        defense_summary_path = os.path.join(RESULTS_DIR, "defense_summary_all_models.csv")

        save_dataframe(summary_df, summary_path)
        save_dataframe(defense_summary_df, defense_summary_path)

        st.session_state.summary_df = summary_df
        st.session_state.defense_summary_df = defense_summary_df
        st.session_state.has_run = True

        st.success("Experiment completed successfully.")

    except Exception as e:
        st.error(f"Error: {e}")


# ============================================================
# Display Results from Session State
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
        st.subheader("Defense Summary")
        st.dataframe(st.session_state.defense_summary_df, use_container_width=True)

    for result in st.session_state.experiment_results:
        experiment_name = result["experiment_name"]
        pin_length = result["pin_length"]
        model = result["model"]
        freq = result["freq"]
        metrics = result["metrics"]
        attack_df = result["attack_df"]
        defense_curve_df = result["defense_curve_df"]
        defense_result = result["defense_result"]
        saved_files = result["saved_files"]

        st.markdown("---")
        st.header(experiment_name)

        st.subheader("1. Security Metrics")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "Shannon Entropy",
                f"{metrics['Shannon Entropy (bits)']:.4f} bits"
            )

        with col2:
            st.metric(
                "Min-Entropy",
                f"{metrics['Min-Entropy (bits)']:.4f} bits"
            )

        with col3:
            st.metric(
                "Expected Guesses",
                f"{metrics['Expected Guesses']:.2f}"
            )

        with col4:
            st.metric(
                "Max Probability",
                f"{metrics['Max Probability']:.4f}"
            )

        st.subheader("2. Top 10 Most Common PINs")
        st.dataframe(freq.head(10), use_container_width=True)

        plot_top_pins(
            freq=freq,
            title=f"Top 10 Most Common PINs - {experiment_name}",
            top_n=10
        )

        st.subheader("3. Attack Success Comparison")
        st.dataframe(attack_df, use_container_width=True)

        selected_metric = st.selectbox(
            f"Select Top-k metric for {experiment_name}",
            [f"Top-{k} Success Rate" for k in K_VALUES],
            index=3,
            key=f"metric_selector_{pin_length}_{model}"
        )

        plot_attack_results(attack_df, selected_metric)

        st.markdown(
            generate_attack_conclusion(
                pin_length=pin_length,
                model=model,
                metrics=metrics,
                attack_df=attack_df
            )
        )

        st.subheader("4. Defense Study: Weak PIN Blacklisting")
        st.dataframe(defense_curve_df, use_container_width=True)

        plot_defense_curve(defense_curve_df)

        st.markdown(
            generate_defense_conclusion(
                defense_result=defense_result,
                blacklist_size=int(defense_result["Blacklist Size"])
            )
        )

        st.subheader("5. Final Recommendation")
        st.markdown(
            generate_final_recommendation(
                pin_length=pin_length,
                model=model,
                attack_df=attack_df,
                defense_result=defense_result
            )
        )

        st.info(
            f"Saved files: `{saved_files['data_path']}`, "
            f"`{saved_files['freq_path']}`, "
            f"`{saved_files['attack_path']}`, "
            f"`{saved_files['defense_path']}`"
        )

else:
    st.info("Configure the experiment in the sidebar, then click **Run Experiment**.")

    st.markdown(
        """
### What this app does

This app runs an interactive PIN security experiment.

It supports:

- **4-digit PINs**
- **6-digit PINs**
- **Uniform model**
- **Biased model**
- **Leakage model**
- **Random attack**
- **Frequency-ranked attack**
- **Rule-based attack**
- **Leakage-assisted attack**
- **Weak PIN blacklisting defense**

The main thesis still focuses on **6-digit PINs**, while the 4-digit option is useful as an additional demonstration of DOB-based weakness.
"""
    )