import os
from typing import Dict, Iterable, Tuple

import matplotlib.pyplot as plt
import pandas as pd

DEFAULT_MODELS = ["uniform", "biased", "leakage"]

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def load_frequency_distribution(csv_path: str) -> pd.DataFrame:
    """
    Load a frequency CSV produced by the main pipeline.

    Expected columns:
        pin, count, probability
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Missing frequency file: {csv_path}")

    df = pd.read_csv(csv_path, dtype={"pin": str})
    df["pin"] = df["pin"].astype(str).str.zfill(6)

    required_columns = {"pin", "probability"}
    missing = required_columns - set(df.columns)

    if missing:
        raise ValueError(
            f"{csv_path} is missing required columns: {missing}. "
            "Expected at least: pin, probability"
        )

    df["probability"] = df["probability"].astype(float)
    df = df.sort_values(by="probability", ascending=False).reset_index(drop=True)

    return df

def compute_attempt_limit_defense(
    freq_df: pd.DataFrame,
    attempt_limits: Iterable[int] = (1, 3, 5, 10)
) -> pd.DataFrame:
    """
    Defense 1: Attempt limitation.

    If a system allows only k guesses, then the success rate of a ranked attacker
    is the cumulative probability of the top-k most likely PINs.
    """
    rows = []

    for k in attempt_limits:
        success_rate = freq_df.head(k)["probability"].sum()

        rows.append({
            "defense": "attempt_limit",
            "parameter": k,
            "success_rate": success_rate
        })

    return pd.DataFrame(rows)

def compute_blacklist_defense(
    freq_df: pd.DataFrame,
    blacklist_sizes: Iterable[int] = (10, 50, 100, 500),
    evaluation_k: int = 10
) -> pd.DataFrame:
    """
    Defense 2: Weak PIN blacklisting.

    The system blocks the top-N most frequent PINs.
    After removing them, the remaining probability distribution is normalized,
    then Top-k success is recomputed.
    """
    rows = []

    original_topk_success = freq_df.head(evaluation_k)["probability"].sum()

    for n in blacklist_sizes:
        filtered = freq_df.iloc[n:].copy()

        if filtered.empty:
            continue

        remaining_mass = filtered["probability"].sum()

        if remaining_mass <= 0:
            continue

        filtered["normalized_probability"] = (
            filtered["probability"] / remaining_mass
        )

        new_topk_success = (
            filtered.head(evaluation_k)["normalized_probability"].sum()
        )

        rows.append({
            "defense": "blacklist_top_pins",
            "parameter": n,
            "evaluation_k": evaluation_k,
            "original_topk_success": original_topk_success,
            "new_topk_success": new_topk_success,
            "absolute_reduction": original_topk_success - new_topk_success,
            "relative_reduction_percent": (
                (original_topk_success - new_topk_success)
                / original_topk_success * 100
                if original_topk_success > 0 else 0
            )
        })

    return pd.DataFrame(rows)

def plot_attempt_limit(
    attempt_results: pd.DataFrame,
    output_path: str
) -> None:
    plt.figure(figsize=(9, 5))

    for model in attempt_results["model"].unique():
        subset = attempt_results[attempt_results["model"] == model]

        plt.plot(
            subset["parameter"],
            subset["success_rate"],
            marker="o",
            label=model
        )

    plt.xlabel("Maximum Number of Allowed Attempts")
    plt.ylabel("Attack Success Rate")
    plt.title("Defense Study: Attack Success under Attempt Limits")
    plt.xticks([1, 3, 5, 10])
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def plot_blacklist_defense(
    blacklist_results: pd.DataFrame,
    output_path: str
) -> None:
    plt.figure(figsize=(9, 5))

    for model in blacklist_results["model"].unique():
        subset = blacklist_results[blacklist_results["model"] == model]

        plt.plot(
            subset["parameter"],
            subset["new_topk_success"],
            marker="o",
            label=model
        )

    plt.xlabel("Number of Most Frequent PINs Blacklisted")
    plt.ylabel("New Top-10 Attack Success Rate")
    plt.title("Defense Study: Weak PIN Blacklisting")
    plt.xticks([10, 50, 100, 500])
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def run_defense_study(
    data_dir: str = "data",
    results_dir: str = "results",
    figures_dir: str = "results/figures",
    models: Iterable[str] = DEFAULT_MODELS,
    attempt_limits: Tuple[int, ...] = (1, 3, 5, 10),
    blacklist_sizes: Tuple[int, ...] = (10, 50, 100, 500),
    evaluation_k: int = 10
) -> Dict[str, pd.DataFrame]:
    """
    Run the full defense study.

    This function uses frequency files generated by the main pipeline:
        results/frequency_uniform.csv
        results/frequency_biased.csv
        results/frequency_leakage.csv

    Outputs:
        results/defense_attempt_limit.csv
        results/defense_blacklist.csv
        results/figures/defense_attempt_limit.png
        results/figures/defense_blacklist.png
    """
    ensure_dir(results_dir)
    ensure_dir(figures_dir)

    all_attempt_results = []
    all_blacklist_results = []

    for model in models:
        frequency_path = os.path.join(results_dir, f"frequency_{model}.csv")

        print(f"[Defense] Loading distribution: {frequency_path}")
        freq_df = load_frequency_distribution(frequency_path)

        attempt_df = compute_attempt_limit_defense(
            freq_df=freq_df,
            attempt_limits=attempt_limits
        )
        attempt_df.insert(0, "model", model)
        all_attempt_results.append(attempt_df)

        blacklist_df = compute_blacklist_defense(
            freq_df=freq_df,
            blacklist_sizes=blacklist_sizes,
            evaluation_k=evaluation_k
        )
        blacklist_df.insert(0, "model", model)
        all_blacklist_results.append(blacklist_df)

    if not all_attempt_results:
        raise RuntimeError("No attempt-limit defense results were generated.")

    if not all_blacklist_results:
        raise RuntimeError("No blacklist defense results were generated.")

    attempt_results = pd.concat(all_attempt_results, ignore_index=True)
    blacklist_results = pd.concat(all_blacklist_results, ignore_index=True)

    attempt_csv = os.path.join(results_dir, "defense_attempt_limit.csv")
    blacklist_csv = os.path.join(results_dir, "defense_blacklist.csv")

    attempt_results.to_csv(attempt_csv, index=False)
    blacklist_results.to_csv(blacklist_csv, index=False)

    attempt_plot = os.path.join(figures_dir, "defense_attempt_limit.png")
    blacklist_plot = os.path.join(figures_dir, "defense_blacklist.png")

    plot_attempt_limit(attempt_results, attempt_plot)
    plot_blacklist_defense(blacklist_results, blacklist_plot)

    print("[OK] Defense study completed.")
    print(f"[OK] Saved CSV: {attempt_csv}")
    print(f"[OK] Saved CSV: {blacklist_csv}")
    print(f"[OK] Saved plot: {attempt_plot}")
    print(f"[OK] Saved plot: {blacklist_plot}")

    return {
        "attempt_limit": attempt_results,
        "blacklist": blacklist_results
    }

if __name__ == "__main__":
    run_defense_study()