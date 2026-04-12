import os
from typing import List

import matplotlib.pyplot as plt
import pandas as pd

def ensure_results_dir(results_dir: str = "results") -> None:
    os.makedirs(results_dir, exist_ok=True)

def load_summary(summary_path: str = "results/summary_all_models.csv") -> pd.DataFrame:
    return pd.read_csv(summary_path)

def load_frequency(model_name: str, results_dir: str = "results") -> pd.DataFrame:
    path = os.path.join(results_dir, f"frequency_{model_name}.csv")
    df = pd.read_csv(path, dtype={"pin": str})
    df["pin"] = df["pin"].str.zfill(6)
    return df

def plot_entropy_comparison(summary_df: pd.DataFrame, results_dir: str = "results") -> str:
    plt.figure(figsize=(8, 5))
    plt.bar(summary_df["Model"], summary_df["Shannon Entropy (bits)"])
    plt.xlabel("Model")
    plt.ylabel("Shannon Entropy (bits)")
    plt.title("Shannon Entropy Comparison Across PIN Models")
    plt.tight_layout()

    output_path = os.path.join(results_dir, "plot_entropy_comparison.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    return output_path

def plot_min_entropy_comparison(summary_df: pd.DataFrame, results_dir: str = "results") -> str:
    plt.figure(figsize=(8, 5))
    plt.bar(summary_df["Model"], summary_df["Min-Entropy (bits)"])
    plt.xlabel("Model")
    plt.ylabel("Min-Entropy (bits)")
    plt.title("Min-Entropy Comparison Across PIN Models")
    plt.tight_layout()

    output_path = os.path.join(results_dir, "plot_min_entropy_comparison.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    return output_path

def plot_expected_guesses_comparison(summary_df: pd.DataFrame, results_dir: str = "results") -> str:
    plt.figure(figsize=(8, 5))
    plt.bar(summary_df["Model"], summary_df["Expected Guesses"])
    plt.xlabel("Model")
    plt.ylabel("Expected Number of Guesses")
    plt.title("Expected Guesses Comparison Across PIN Models")
    plt.tight_layout()

    output_path = os.path.join(results_dir, "plot_expected_guesses_comparison.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    return output_path

def plot_top10_pins(model_name: str, freq_df: pd.DataFrame, results_dir: str = "results") -> str:
    top10 = freq_df.head(10).copy()

    plt.figure(figsize=(10, 5))
    plt.bar(top10["pin"], top10["probability"])
    plt.xlabel("PIN")
    plt.ylabel("Probability")
    plt.title(f"Top 10 Most Common PINs - {model_name.capitalize()} Model")
    plt.xticks(rotation=45)
    plt.tight_layout()

    output_path = os.path.join(results_dir, f"plot_top10_{model_name}.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    return output_path

def plot_rank_probability_curve(model_name: str, freq_df: pd.DataFrame, results_dir: str = "results") -> str:
    ranked = freq_df.sort_values(by="probability", ascending=False).reset_index(drop=True)
    ranked["rank"] = ranked.index + 1

    plt.figure(figsize=(8, 5))
    plt.plot(ranked["rank"], ranked["probability"])
    plt.xscale("log")
    plt.yscale("log")
    plt.xlabel("Rank (log scale)")
    plt.ylabel("Probability (log scale)")
    plt.title(f"Rank-Probability Curve - {model_name.capitalize()} Model")
    plt.tight_layout()

    output_path = os.path.join(results_dir, f"plot_rank_probability_{model_name}.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    return output_path

def plot_attack_success_by_model(summary_df: pd.DataFrame, results_dir: str = "results") -> List[str]:
    """
    Generate 4 separate plots:
    Top-1, Top-3, Top-5, Top-10
    Each plot compares all attacks across the three models.
    """
    output_paths = []

    attack_prefixes = [
        "Random",
        "Frequency-Ranked",
        "Rule-Based",
        "Leakage-Assisted",
    ]

    for k in ["Top-1", "Top-3", "Top-5", "Top-10"]:
        plt.figure(figsize=(10, 5))

        x = range(len(summary_df["Model"]))
        width = 0.2

        for i, attack_name in enumerate(attack_prefixes):
            col = f"{attack_name} - {k}"
            offsets = [v + (i - 1.5) * width for v in x]
            plt.bar(offsets, summary_df[col], width=width, label=attack_name)

        plt.xticks(list(x), summary_df["Model"])
        plt.xlabel("Model")
        plt.ylabel("Success Rate")
        plt.title(f"Attack Success Comparison ({k})")
        plt.legend()
        plt.tight_layout()

        output_path = os.path.join(results_dir, f"plot_attack_comparison_{k.lower()}.png")
        plt.savefig(output_path, dpi=300)
        plt.close()
        output_paths.append(output_path)

    return output_paths

def generate_all_plots(
    summary_path: str = "results/summary_all_models.csv",
    results_dir: str = "results"
) -> List[str]:
    ensure_results_dir(results_dir)
    saved_files = []

    summary_df = load_summary(summary_path)

    saved_files.append(plot_entropy_comparison(summary_df, results_dir))
    saved_files.append(plot_min_entropy_comparison(summary_df, results_dir))
    saved_files.append(plot_expected_guesses_comparison(summary_df, results_dir))

    saved_files.extend(plot_attack_success_by_model(summary_df, results_dir))

    for model_name in ["uniform", "biased", "leakage"]:
        freq_df = load_frequency(model_name, results_dir)
        saved_files.append(plot_top10_pins(model_name, freq_df, results_dir))
        saved_files.append(plot_rank_probability_curve(model_name, freq_df, results_dir))

    return saved_files