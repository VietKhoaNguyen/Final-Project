import os
import argparse
import pandas as pd

from src.pin_generator import generate_dataset, dob_to_candidate_pins
from src.analysis import (
    compute_frequency_from_pins,
    save_frequency,
    print_top_pins,
    compute_security_metrics,
    print_security_metrics,
    train_test_split_pins,
    compute_test_distribution,
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

DATA_DIR    = "data"
RESULTS_DIR = "results"

DEFAULT_RUN_MODE          = "all"
DEFAULT_MODEL             = "biased"
DEFAULT_DOB               = "1998-03-05"
DEFAULT_N                 = 100000
DEFAULT_SEED              = 42
DEFAULT_USE_SURVEY_WEIGHTS = True
DEFAULT_TRAIN_RATIO       = 0.80   # 80% train / 20% test
DEFAULT_RUN_DEFENSE       = True
DEFAULT_BLACKLIST_SIZES   = [10, 50, 100, 500]


# ============================================================
# Utility Functions
# ============================================================

def ensure_dirs() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)


def save_dataset(pins: list, output_path: str) -> None:
    df = pd.DataFrame(pins, columns=["pin"])
    df.to_csv(output_path, index=False)


def save_model_summary(
    model_name: str,
    metrics: dict,
    attack_results: dict,
    output_path: str
) -> None:
    row = {
        "Model":                  model_name,
        "Shannon Entropy (bits)": metrics["Shannon Entropy (bits)"],
        "Min-Entropy (bits)":     metrics["Min-Entropy (bits)"],
        "Expected Guesses":       metrics["Expected Guesses"],
    }
    for attack_name, result_dict in attack_results.items():
        for metric_name, value in result_dict.items():
            row[f"{attack_name} - {metric_name}"] = value

    pd.DataFrame([row]).to_csv(output_path, index=False)


# ============================================================
# Core Experimental Pipeline
# ============================================================

def run_one_model(
    model_name:         str,
    dob:                str   = DEFAULT_DOB,
    n:                  int   = DEFAULT_N,
    seed:               int   = DEFAULT_SEED,
    use_survey_weights: bool  = DEFAULT_USE_SURVEY_WEIGHTS,
    train_ratio:        float = DEFAULT_TRAIN_RATIO,
) -> dict:
    print(f"\n{'=' * 60}")
    print(f"=== {model_name.upper()} model  (n={n}, seed={seed}) ===")
    print(f"{'=' * 60}")

    # 1. Generate full dataset
    pins = generate_dataset(
        n=n, model=model_name, seed=seed, dob=dob,
        use_survey_weights=use_survey_weights,
        randomize_dob=True,       # always randomise DOB per user in leakage model
    )

    # 2. Save full dataset
    dataset_path = os.path.join(DATA_DIR, f"generated_{model_name}_pins.csv")
    save_dataset(pins, dataset_path)
    print(f"Dataset saved  → {dataset_path}")

    # 3. Train / test split (80 / 20)
    train_pins, test_pins = train_test_split_pins(pins, train_ratio=train_ratio, seed=seed)
    print(f"Split: {len(train_pins)} train  /  {len(test_pins)} test  "
          f"({train_ratio*100:.0f}/{(1-train_ratio)*100:.0f})")

    # 4. Build frequency table from TRAIN set only
    train_freq = compute_frequency_from_pins(train_pins)

    freq_path = os.path.join(RESULTS_DIR, f"frequency_{model_name}.csv")
    save_frequency(train_freq, output_path=freq_path)
    print(f"Frequency saved → {freq_path}")

    print_top_pins(train_freq, 10)

    # 5. Security metrics computed on TRAIN frequency
    print("\n=== Security Metrics (empirical, train set) ===")
    metrics = compute_security_metrics(train_freq)
    print_security_metrics(metrics)

    # 6. Test distribution (ground truth for Top-k evaluation)
    test_dist = compute_test_distribution(test_pins)

    # 7. Attack simulation: rank from TRAIN, evaluate on TEST
    print("\n=== Attack Simulation (ranked on train, evaluated on test) ===")
    leaked_candidates = dob_to_candidate_pins(dob)   # attacker knows the demo DOB

    attack_results = evaluate_all_attacks(
        train_freq_df=train_freq,
        test_distribution=test_dist,
        leaked_candidates=leaked_candidates,
        k_values=[1, 3, 5, 10],
        seed=seed,
    )
    print_attack_results(attack_results)

    # 8. Save per-model summary
    summary_path = os.path.join(RESULTS_DIR, f"summary_{model_name}.csv")
    save_model_summary(
        model_name=model_name,
        metrics=metrics,
        attack_results=attack_results,
        output_path=summary_path,
    )
    print(f"Summary saved   → {summary_path}")

    summary_row = {
        "Model":                  model_name,
        "Shannon Entropy (bits)": metrics["Shannon Entropy (bits)"],
        "Min-Entropy (bits)":     metrics["Min-Entropy (bits)"],
        "Expected Guesses":       metrics["Expected Guesses"],
    }
    for attack_name, result_dict in attack_results.items():
        for metric_name, value in result_dict.items():
            summary_row[f"{attack_name} - {metric_name}"] = value

    return {
        "summary_row": summary_row,
        "train_freq":  train_freq,
    }


def run_defense_for_all_models(
    model_frequencies: dict,
    blacklist_sizes:   list,
) -> pd.DataFrame:
    defense_tables = []
    print("\n=== Defense Study: Weak PIN Blacklisting ===")

    for model_name, freq in model_frequencies.items():
        print(f"\n--- {model_name} ---")
        defense_df = run_weak_pin_blacklisting_study(
            freq=freq,
            model_name=model_name,
            blacklist_sizes=blacklist_sizes,
            k=10,
        )
        print_defense_results(defense_df)
        defense_tables.append(defense_df)

    all_defense_df = pd.concat(defense_tables, ignore_index=True)
    defense_path   = os.path.join(RESULTS_DIR, "defense_weak_blacklisting.csv")
    save_defense_results(all_defense_df, output_path=defense_path)
    print(f"\nDefense results saved → {defense_path}")
    return all_defense_df


# ============================================================
# CLI
# ============================================================

def parse_blacklist_sizes(value: str) -> list:
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
    parser.add_argument("--run_mode",  choices=["one", "all"], default=DEFAULT_RUN_MODE)
    parser.add_argument("--model",     choices=["uniform", "biased", "leakage"], default=DEFAULT_MODEL)
    parser.add_argument("--dob",       type=str,   default=DEFAULT_DOB)
    parser.add_argument("--n",         type=int,   default=DEFAULT_N)
    parser.add_argument("--seed",      type=int,   default=DEFAULT_SEED)
    parser.add_argument("--train_ratio", type=float, default=DEFAULT_TRAIN_RATIO,
                        help="Fraction of dataset used for training (default 0.80)")
    parser.add_argument("--use_survey_weights", action="store_true")
    parser.add_argument("--no_defense",         action="store_true")
    parser.add_argument("--blacklist_sizes", type=parse_blacklist_sizes,
                        default=DEFAULT_BLACKLIST_SIZES)
    return parser.parse_args()


# ============================================================
# Main
# ============================================================

def main():
    args = parse_args()
    ensure_dirs()

    use_survey_weights = args.use_survey_weights or DEFAULT_USE_SURVEY_WEIGHTS
    run_defense        = not args.no_defense

    summaries         = []
    model_frequencies = {}

    models = ["uniform", "biased", "leakage"] if args.run_mode == "all" else [args.model]

    for model in models:
        result = run_one_model(
            model_name         = model,
            dob                = args.dob,
            n                  = args.n,
            seed               = args.seed,
            use_survey_weights = use_survey_weights,
            train_ratio        = args.train_ratio,
        )
        summaries.append(result["summary_row"])
        model_frequencies[model] = result["train_freq"]

    # Save combined summary
    summary_df   = pd.DataFrame(summaries)
    summary_path = os.path.join(RESULTS_DIR, "summary_all_models.csv")
    summary_df.to_csv(summary_path, index=False)
    print(f"\nCombined summary → {summary_path}")
    print("\n=== Summary Table ===")
    print(summary_df.to_string())

    # Plots
    print("\n=== Generating Plots ===")
    saved = generate_all_plots(summary_path=summary_path, results_dir=RESULTS_DIR)
    for f in saved:
        print(f"  Saved: {f}")

    # Defense
    if run_defense:
        defense_df = run_defense_for_all_models(
            model_frequencies=model_frequencies,
            blacklist_sizes=args.blacklist_sizes,
        )

        try:
            import matplotlib.pyplot as plt
            plt.figure(figsize=(10, 6))
            for model_name in defense_df["Model"].unique():
                sub = defense_df[defense_df["Model"] == model_name]
                plt.plot(sub["Blacklist Size"], sub["New Top-10 Success Rate"],
                         marker="o", label=model_name)
            plt.title("Defense Study: Weak PIN Blacklisting")
            plt.xlabel("Number of Most Frequent PINs Blacklisted")
            plt.ylabel("New Top-10 Attack Success Rate")
            plt.legend()
            plt.grid(alpha=0.3)
            plt.tight_layout()
            plot_path = os.path.join(RESULTS_DIR, "defense_weak_blacklisting_plot.png")
            plt.savefig(plot_path, dpi=300)
            plt.close()
            print(f"\nDefense plot saved → {plot_path}")
        except Exception as e:
            print(f"Could not generate defense plot: {e}")

    print("\nExperiment completed successfully.")


if __name__ == "__main__":
    main()
