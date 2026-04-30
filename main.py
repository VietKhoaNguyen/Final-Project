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

# import defense
from src.defense import run_defense_study

# Default Configuration
DATA_DIR = "data"
RESULTS_DIR = "results"

DEFAULT_RUN_MODE = "all"
DEFAULT_MODEL = "biased"
DEFAULT_DOB = "1998-03-05"
DEFAULT_N = 100000
DEFAULT_SEED = 42
DEFAULT_USE_SURVEY_WEIGHTS = True

# Utility Functions
def ensure_dirs() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(os.path.join(RESULTS_DIR, "figures"), exist_ok=True)

def save_dataset(pins: list[str], output_path: str) -> None:
    df = pd.DataFrame(pins, columns=["pin"])
    df.to_csv(output_path, index=False)

def save_model_summary(
    model_name: str,
    metrics: dict,
    attack_results: dict,
    output_path: str
) -> None:
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

# Core Experimental Pipeline
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

    per_model_summary_path = os.path.join(RESULTS_DIR, f"summary_{model_name}.csv")
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

    return summary_row

# CLI
def parse_args():
    parser = argparse.ArgumentParser(
        description="Low-Entropy Attacks on 6-Digit PINs"
    )

    parser.add_argument("--run_mode", choices=["one", "all"], default=DEFAULT_RUN_MODE)
    parser.add_argument("--model", choices=["uniform", "biased", "leakage"], default=DEFAULT_MODEL)
    parser.add_argument("--dob", type=str, default=DEFAULT_DOB)
    parser.add_argument("--n", type=int, default=DEFAULT_N)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--use_survey_weights", action="store_true")

    return parser.parse_args()

# Main
def main():
    args = parse_args()
    ensure_dirs()

    use_survey_weights = (
        args.use_survey_weights if args.use_survey_weights else DEFAULT_USE_SURVEY_WEIGHTS
    )

    if args.run_mode == "one":
        run_one_model(
            model_name=args.model,
            dob=args.dob,
            n=args.n,
            seed=args.seed,
            use_survey_weights=use_survey_weights
        )

        # DEFENSE 
        print("\n=== Running Defense Study ===")
        run_defense_study(DATA_DIR, RESULTS_DIR, os.path.join(RESULTS_DIR, "figures"))

        return

    if args.run_mode == "all":
        summaries = []

        for model in ["uniform", "biased", "leakage"]:
            summary = run_one_model(
                model_name=model,
                dob=args.dob,
                n=args.n,
                seed=args.seed,
                use_survey_weights=use_survey_weights
            )
            summaries.append(summary)

        summary_df = pd.DataFrame(summaries)
        summary_path = os.path.join(RESULTS_DIR, "summary_all_models.csv")
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

        # DEFENSE 
        print("\n=== Running Defense Study ===")
        run_defense_study(DATA_DIR, RESULTS_DIR, os.path.join(RESULTS_DIR, "figures"))

        return

    raise ValueError("run_mode must be either 'one' or 'all'")

if __name__ == "__main__":
    main()