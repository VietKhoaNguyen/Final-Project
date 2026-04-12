import os
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

DATA_DIR = "data"
RESULTS_DIR = "results"

def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

def run_one_model(model_name: str, dob: str = "1998-03-05", use_survey_weights: bool = True):
    print(f"\n{'=' * 60}")
    print(f"=== Generating {model_name} PIN dataset ===")
    print(f"{'=' * 60}")

    pins = generate_dataset(
        100000,
        model=model_name,
        seed=42,
        dob=dob,
        use_survey_weights=use_survey_weights
    )

    dataset_path = os.path.join(DATA_DIR, f"generated_{model_name}_pins.csv")
    df = pd.DataFrame(pins, columns=["pin"])
    df.to_csv(dataset_path, index=False)
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
    attack_results = evaluate_all_attacks(freq, leaked_candidates=leaked_candidates)
    print_attack_results(attack_results)

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

def main():
    ensure_dirs()

    run_mode = "all"   # "one" or "all"
    model_name = "biased"
    dob = "1998-03-05"

    if run_mode == "one":
        run_one_model(model_name=model_name, dob=dob, use_survey_weights=True)
        return

    if run_mode == "all":
        summaries = []
        for model in ["uniform", "biased", "leakage"]:
            summary = run_one_model(model_name=model, dob=dob, use_survey_weights=True)
            summaries.append(summary)

        summary_df = pd.DataFrame(summaries)
        summary_path = os.path.join(RESULTS_DIR, "summary_all_models.csv")
        summary_df.to_csv(summary_path, index=False)

        print(f"\nSummary saved to {summary_path}")
        print("\n=== Summary Table ===")
        print(summary_df)

        print("\n=== Generating plots ===")
        saved_plot_files = generate_all_plots(summary_path=summary_path, results_dir=RESULTS_DIR)
        for f in saved_plot_files:
            print(f"Saved plot: {f}")
        return

    raise ValueError("run_mode must be either 'one' or 'all'")

if __name__ == "__main__":
    main()