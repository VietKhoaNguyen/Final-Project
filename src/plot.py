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

def plot_combined_rank_probability(results_dir: str = "results") -> str:
    plt.figure(figsize=(8, 5))

    for model_name in ["uniform", "biased", "leakage"]:
        freq_df = load_frequency(model_name, results_dir)
        ranked = freq_df.sort_values(by="probability", ascending=False).reset_index(drop=True)
        ranked["rank"] = ranked.index + 1
        plt.plot(ranked["rank"], ranked["probability"], label=model_name)

    plt.xscale("log")
    plt.yscale("log")
    plt.xlabel("Rank (log scale)")
    plt.ylabel("Probability (log scale)")
    plt.title("Combined Rank-Probability Curves Across Models")
    plt.legend()
    plt.tight_layout()

    output_path = os.path.join(results_dir, "plot_rank_probability_combined.png")
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

def plot_cumulative_success_curve(results_dir: str = "results", max_k: int = 1000) -> str:
    """
    Plot cumulative success curve for frequency-ranked attack:
    x = number of guesses
    y = cumulative success probability
    """
    plt.figure(figsize=(8, 5))

    for model_name in ["uniform", "biased", "leakage"]:
        freq_df = load_frequency(model_name, results_dir)
        ranked = freq_df.sort_values(by="probability", ascending=False).reset_index(drop=True)
        ranked["cumulative_success"] = ranked["probability"].cumsum()

        max_index = min(max_k, len(ranked))
        x_vals = list(range(1, max_index + 1))
        y_vals = ranked["cumulative_success"].iloc[:max_index]

        plt.plot(x_vals, y_vals, label=model_name)

    plt.xscale("log")
    plt.xlabel("Number of Guesses (log scale)")
    plt.ylabel("Cumulative Success Probability")
    plt.title("Cumulative Success Curves (Frequency-Ranked Attack)")
    plt.legend()
    plt.tight_layout()

    output_path = os.path.join(results_dir, "plot_cumulative_success_curve.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    return output_path

def plot_entropy_vs_attack_success(summary_df: pd.DataFrame, results_dir: str = "results") -> str:
    """
    Scatter plot:
    x = Shannon entropy
    y = Frequency-Ranked Top-10 success
    """
    plt.figure(figsize=(8, 5))

    x = summary_df["Shannon Entropy (bits)"]
    y = summary_df["Frequency-Ranked - Top-10"]

    plt.scatter(x, y)

    for _, row in summary_df.iterrows():
        plt.annotate(row["Model"], (row["Shannon Entropy (bits)"], row["Frequency-Ranked - Top-10"]))

    plt.xlabel("Shannon Entropy (bits)")
    plt.ylabel("Top-10 Success Rate (Frequency-Ranked)")
    plt.title("Entropy vs Attack Success")
    plt.tight_layout()

    output_path = os.path.join(results_dir, "plot_entropy_vs_attack_success.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    return output_path

def generate_all_plots(
    summary_path: str = "results/summary_all_models.csv",
    results_dir: str = "results"
) -> List[str]:
    ensure_results_dir(results_dir)
    saved_files = []

    summary_df = load_summary(summary_path)

    # Metric comparison plots
    saved_files.append(plot_entropy_comparison(summary_df, results_dir))
    saved_files.append(plot_min_entropy_comparison(summary_df, results_dir))
    saved_files.append(plot_expected_guesses_comparison(summary_df, results_dir))

    # Attack comparison plots
    saved_files.extend(plot_attack_success_by_model(summary_df, results_dir))

    # Per-model distribution plots
    for model_name in ["uniform", "biased", "leakage"]:
        freq_df = load_frequency(model_name, results_dir)
        saved_files.append(plot_top10_pins(model_name, freq_df, results_dir))
        saved_files.append(plot_rank_probability_curve(model_name, freq_df, results_dir))

    # Additional combined / thesis-strength plots
    saved_files.append(plot_combined_rank_probability(results_dir))
    saved_files.append(plot_cumulative_success_curve(results_dir, max_k=1000))
    saved_files.append(plot_entropy_vs_attack_success(summary_df, results_dir))

    return saved_files