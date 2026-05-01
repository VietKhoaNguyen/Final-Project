import os
import argparse
import pandas as pd

from src.pin_generator import generate_dataset, dob_to_candidate_pins
from src.analysis import (
    compute_frequency,
    save_frequency,
    print_top_pins,
    compute_security_metrics,
    print_security_metrics,
)
from src.attack import evaluate_all_attacks, print_attack_results
from src.plot import generate_all_plots
from src.defense import (
    run_weak_pin_blacklisting_study,
    save_defense_results,
    print_defense_results,
)


# ============================================================
# Default Configuration
# ============================================================

DATA_DIR = "data"
RESULTS_DIR = "results"

DEFAULT_RUN_MODE = "all"          # "one" or "all"
DEFAULT_MODEL = "biased"          # "uniform", "biased", "leakage"
DEFAULT_DOB = "1998-03-05"
DEFAULT_N = 100000
DEFAULT_SEED = 42
DEFAULT_USE_SURVEY_WEIGHTS = True

DEFAULT_RUN_DEFENSE = True
DEFAULT_BLACKLIST_SIZES = [10, 50, 100, 500]


# ============================================================
# Utility Functions
# ============================================================

def ensure_dirs() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)


def save_dataset(pins: list[str], output_path: str) -> None:
    df = pd.DataFrame(pins, columns=["pin"])
    df.to_csv(output_path, index=False)


def save_model_summary(
    model_name: str,
    metrics: dict,
    attack_results: dict,
    output_path: str
) -> None:
    """
    Save per-model summary to CSV.
    """
    row = {
        "Model": model_name,
        "Shannon Entropy (bits)": metrics["Shannon Entropy (bits)"],
        "Min-Entropy (bits)": metrics["Min-Entropy (bits)"],
        "Expected Guesses": metrics["Expected Guesses"],
    }

    for attack_name, result_dict in attack_results.items():
        for metric_name, value in result_dict.items():
            row[f"{attack_name} - {metric_name}"] = value

    df = pd.DataFrame([row])
    df.to_csv(output_path, index=False)


# ============================================================
# Core Experimental Pipeline
# ============================================================

def run_one_model(
    model_name: str,
    dob: str = DEFAULT_DOB,
    n: int = DEFAULT_N,
    seed: int = DEFAULT_SEED,
    use_survey_weights: bool = DEFAULT_USE_SURVEY_WEIGHTS
) -> dict:
    print(f"\n{'=' * 60}")
    print(f"=== Generating {model_name} PIN dataset ===")
    print(f"{'=' * 60}")

    pins = generate_dataset(
        n=n,
        model=model_name,
        seed=seed,
        dob=dob,
        use_survey_weights=use_survey_weights
    )

    dataset_path = os.path.join(DATA_DIR, f"generated_{model_name}_pins.csv")
    save_dataset(pins, dataset_path)
    print(f"Dataset saved to {dataset_path}")

    print("\n=== Computing frequency ===")
    freq = compute_frequency(dataset_path)

    freq_path = os.path.join(RESULTS_DIR, f"frequency_{model_name}.csv")
    save_frequency(freq, output_path=freq_path)
    print(f"Frequency saved to {freq_path}")

    print_top_pins(freq, 10)

    print("\n=== Computing security metrics ===")
    metrics = compute_security_metrics(freq)
    print_security_metrics(metrics)

    print("\n=== Running attack simulation ===")
    leaked_candidates = dob_to_candidate_pins(dob)

    attack_results = evaluate_all_attacks(
        freq,
        leaked_candidates=leaked_candidates,
        k_values=[1, 3, 5, 10],
        seed=seed
    )

    print_attack_results(attack_results)

    per_model_summary_path = os.path.join(
        RESULTS_DIR,
        f"summary_{model_name}.csv"
    )

    save_model_summary(
        model_name=model_name,
        metrics=metrics,
        attack_results=attack_results,
        output_path=per_model_summary_path
    )

    print(f"\nPer-model summary saved to {per_model_summary_path}")

    summary_row = {
        "Model": model_name,
        "Shannon Entropy (bits)": metrics["Shannon Entropy (bits)"],
        "Min-Entropy (bits)": metrics["Min-Entropy (bits)"],
        "Expected Guesses": metrics["Expected Guesses"],
    }

    for attack_name, result_dict in attack_results.items():
        for metric_name, value in result_dict.items():
            summary_row[f"{attack_name} - {metric_name}"] = value

    return {
        "summary_row": summary_row,
        "frequency": freq,
    }


def run_defense_for_all_models(
    model_frequencies: dict,
    blacklist_sizes: list[int],
) -> pd.DataFrame:
    """
    Run weak PIN blacklisting defense study for all available models.
    """
    defense_tables = []

    print("\n=== Running Defense Study: Weak PIN Blacklisting ===")

    for model_name, freq in model_frequencies.items():
        print(f"\n--- Defense study for {model_name} model ---")

        defense_df = run_weak_pin_blacklisting_study(
            freq=freq,
            model_name=model_name,
            blacklist_sizes=blacklist_sizes,
            k=10
        )

        print_defense_results(defense_df)
        defense_tables.append(defense_df)

    all_defense_df = pd.concat(defense_tables, ignore_index=True)

    defense_output_path = os.path.join(
        RESULTS_DIR,
        "defense_weak_blacklisting.csv"
    )

    save_defense_results(
        defense_df=all_defense_df,
        output_path=defense_output_path
    )

    print(f"\nDefense results saved to {defense_output_path}")

    return all_defense_df


# ============================================================
# CLI
# ============================================================

def parse_blacklist_sizes(value: str) -> list[int]:
    """
    Convert command-line input like:
    10,50,100,500
    into:
    [10, 50, 100, 500]
    """
    try:
        return [int(x.strip()) for x in value.split(",") if x.strip()]
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Blacklist sizes must be comma-separated integers, e.g. 10,50,100,500"
        )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Low-Entropy Attacks on 6-Digit PINs"
    )

    parser.add_argument(
        "--run_mode",
        choices=["one", "all"],
        default=DEFAULT_RUN_MODE,
        help="Run one model or all models"
    )

    parser.add_argument(
        "--model",
        choices=["uniform", "biased", "leakage"],
        default=DEFAULT_MODEL,
        help="Model to run when run_mode=one"
    )

    parser.add_argument(
        "--dob",
        type=str,
        default=DEFAULT_DOB,
        help="Date of birth used for leakage modeling, format: YYYY-MM-DD"
    )

    parser.add_argument(
        "--n",
        type=int,
        default=DEFAULT_N,
        help="Dataset size"
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="Random seed"
    )

    parser.add_argument(
        "--use_survey_weights",
        action="store_true",
        help="Use survey-based weights for biased/leakage models"
    )

    parser.add_argument(
        "--no_defense",
        action="store_true",
        help="Disable weak PIN blacklisting defense study"
    )

    parser.add_argument(
        "--blacklist_sizes",
        type=parse_blacklist_sizes,
        default=DEFAULT_BLACKLIST_SIZES,
        help="Comma-separated blacklist sizes, e.g. 10,50,100,500"
    )

    return parser.parse_args()


# ============================================================
# Main
# ============================================================

def main():
    args = parse_args()
    ensure_dirs()

    use_survey_weights = (
        args.use_survey_weights
        if args.use_survey_weights
        else DEFAULT_USE_SURVEY_WEIGHTS
    )

    run_defense = not args.no_defense

    summaries = []
    model_frequencies = {}

    if args.run_mode == "one":
        result = run_one_model(
            model_name=args.model,
            dob=args.dob,
            n=args.n,
            seed=args.seed,
            use_survey_weights=use_survey_weights
        )

        summaries.append(result["summary_row"])
        model_frequencies[args.model] = result["frequency"]

    elif args.run_mode == "all":
        for model in ["uniform", "biased", "leakage"]:
            result = run_one_model(
                model_name=model,
                dob=args.dob,
                n=args.n,
                seed=args.seed,
                use_survey_weights=use_survey_weights
            )

            summaries.append(result["summary_row"])
            model_frequencies[model] = result["frequency"]

    else:
        raise ValueError("run_mode must be either 'one' or 'all'")

    summary_df = pd.DataFrame(summaries)

    summary_path = os.path.join(
        RESULTS_DIR,
        "summary_all_models.csv"
    )

    summary_df.to_csv(summary_path, index=False)

    print(f"\nSummary saved to {summary_path}")
    print("\n=== Summary Table ===")
    print(summary_df)

    print("\n=== Generating plots ===")

    saved_plot_files = generate_all_plots(
        summary_path=summary_path,
        results_dir=RESULTS_DIR
    )

    for f in saved_plot_files:
        print(f"Saved plot: {f}")

    if run_defense:
        defense_df = run_defense_for_all_models(
            model_frequencies=model_frequencies,
            blacklist_sizes=args.blacklist_sizes
        )

        defense_plot_path = os.path.join(
            RESULTS_DIR,
            "defense_weak_blacklisting_plot.png"
        )

        try:
            import matplotlib.pyplot as plt

            plt.figure(figsize=(10, 6))

            for model_name in defense_df["Model"].unique():
                model_df = defense_df[defense_df["Model"] == model_name]

                plt.plot(
                    model_df["Blacklist Size"],
                    model_df["New Top-10 Success Rate"],
                    marker="o",
                    label=model_name
                )

            plt.title("Defense Study: Weak PIN Blacklisting")
            plt.xlabel("Number of Most Frequent PINs Blacklisted")
            plt.ylabel("New Top-10 Attack Success Rate")
            plt.grid(alpha=0.3)
            plt.legend()
            plt.tight_layout()
            plt.savefig(defense_plot_path, dpi=300)
            plt.close()

            print(f"Saved defense plot: {defense_plot_path}")

        except Exception as e:
            print(f"Could not generate defense plot: {e}")

    print("\nExperiment completed successfully.")


if __name__ == "__main__":
    main()