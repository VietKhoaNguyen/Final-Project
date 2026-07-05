import os
import argparse
import pandas as pd

from src.pin_generator import generate_dataset, dob_to_candidate_pins # PIN dataset generation and DOB-candidate helper
from src.analysis import ( # analysis helpers: frequency building, security metrics, train/test split
    compute_frequency_from_pins,
    save_frequency,
    print_top_pins,
    compute_security_metrics,
    print_security_metrics,
    train_test_split_pins,
    compute_test_distribution,
)
from src.attack import evaluate_all_attacks, print_attack_results # attack simulation and result printing
from src.plot import generate_all_plots # generates all chart/figure outputs
from src.defense import ( # defense study: weak PIN blacklisting evaluation
    run_weak_pin_blacklisting_study,
    save_defense_results,
    print_defense_results,
)

# ============================================================
# Default Configuration
# ============================================================

DATA_DIR    = "data" # directory where generated PIN datasets are stored
RESULTS_DIR = "results" # directory where all output tables and plots are stored

DEFAULT_RUN_MODE          = "all" # default: run all three models (uniform, biased, leakage)
DEFAULT_MODEL             = "biased" # default single model to run if run_mode="one"
DEFAULT_DOB               = "1998-03-05" # default demo date-of-birth used for the leakage-attack scenario
DEFAULT_N                 = 100000 # default number of PINs to generate per model
DEFAULT_SEED              = 42 # default random seed for reproducibility
DEFAULT_USE_SURVEY_WEIGHTS = True # default: use survey-derived strategy weights instead of hardcoded defaults
DEFAULT_TRAIN_RATIO       = 0.80   # 80% train / 20% test: default fraction of data used for training
DEFAULT_RUN_DEFENSE       = True # default: run the blacklisting defense study after the main experiment
DEFAULT_BLACKLIST_SIZES   = [10, 50, 100, 500] # default set of blacklist sizes to sweep in the defense study

# ============================================================
# Utility Functions
# ============================================================

def ensure_dirs() -> None: # creates the data/results output directories if they don't already exist
    os.makedirs(DATA_DIR, exist_ok=True) # create the data directory (no error if it already exists)
    os.makedirs(RESULTS_DIR, exist_ok=True) # create the results directory (no error if it already exists)

def save_dataset(pins: list, output_path: str) -> None: # saves a list of generated PINs to a CSV file
    df = pd.DataFrame(pins, columns=["pin"]) # wrap the list of PINs into a single-column DataFrame
    df.to_csv(output_path, index=False) # write the DataFrame to CSV, omitting the row index

def save_model_summary(
    model_name: str, # name of the PIN model this summary belongs to
    metrics: dict, # security metrics dict (entropy, min-entropy, expected guesses)
    attack_results: dict, # nested dict of attack name -> {Top-k metric -> value}
    output_path: str # destination CSV file path
) -> None:
    row = { # build a single flat row combining model name and its core security metrics
        "Model":                  model_name,
        "Shannon Entropy (bits)": metrics["Shannon Entropy (bits)"],
        "Min-Entropy (bits)":     metrics["Min-Entropy (bits)"],
        "Expected Guesses":       metrics["Expected Guesses"],
    }
    for attack_name, result_dict in attack_results.items(): # iterate over each attack strategy's results
        for metric_name, value in result_dict.items(): # iterate over each Top-k metric within that attack
            row[f"{attack_name} - {metric_name}"] = value # flatten into a single column named "AttackName - MetricName"

    pd.DataFrame([row]).to_csv(output_path, index=False) # wrap the single row into a DataFrame and save as CSV

# ============================================================
# Core Experimental Pipeline
# ============================================================

def run_one_model(
    model_name:         str, # which PIN model to run: "uniform", "biased", or "leakage"
    dob:                str   = DEFAULT_DOB, # demo DOB used for the leakage-attack scenario
    n:                  int   = DEFAULT_N, # number of PINs to generate
    seed:               int   = DEFAULT_SEED, # random seed for reproducibility
    use_survey_weights: bool  = DEFAULT_USE_SURVEY_WEIGHTS, # whether to use survey-derived strategy weights
    train_ratio:        float = DEFAULT_TRAIN_RATIO, # fraction of data used for training
) -> dict: 
    print(f"\n{'=' * 60}") # print a visual separator line
    print(f"=== {model_name.upper()} model  (n={n}, seed={seed}) ===") # print a header identifying this model run
    print(f"{'=' * 60}") # print a visual separator line

    # 1. Generate full dataset
    pins = generate_dataset( # generate the full synthetic PIN dataset for this model
        n=n, model=model_name, seed=seed, dob=dob,
        use_survey_weights=use_survey_weights,
        randomize_dob=True,       # always randomise DOB per user in leakage model
    )

    # 2. Save full dataset
    dataset_path = os.path.join(DATA_DIR, f"generated_{model_name}_pins.csv") # build path for this model's raw dataset file
    save_dataset(pins, dataset_path) # write the generated PINs to disk
    print(f"Dataset saved  → {dataset_path}") # confirm the dataset was saved

    # 3. Train / test split (80 / 20)
    train_pins, test_pins = train_test_split_pins(pins, train_ratio=train_ratio, seed=seed) # split PINs into train/test sets
    print(f"Split: {len(train_pins)} train  /  {len(test_pins)} test  " # report the split sizes
          f"({train_ratio*100:.0f}/{(1-train_ratio)*100:.0f})") # report the split ratio as percentages

    # 4. Build frequency table from TRAIN set only
    train_freq = compute_frequency_from_pins(train_pins) # compute PIN frequency/probability table from the training data only

    freq_path = os.path.join(RESULTS_DIR, f"frequency_{model_name}.csv") # build path for this model's frequency table file
    save_frequency(train_freq, output_path=freq_path) # save the training frequency table to disk
    print(f"Frequency saved → {freq_path}") # confirm the frequency table was saved

    print_top_pins(train_freq, 10) # print the top 10 most common PINs from the training set

    # 5. Security metrics computed on TRAIN frequency
    print("\n=== Security Metrics (empirical, train set) ===") # section header
    metrics = compute_security_metrics(train_freq) # compute entropy, min-entropy, and expected guesses from the training distribution
    print_security_metrics(metrics) # print the computed security metrics

    # 6. Test distribution (ground truth for Top-k evaluation)
    test_dist = compute_test_distribution(test_pins) # build the ground-truth probability distribution from the held-out test set   

    # 7. Attack simulation: rank from TRAIN, evaluate on TEST
    print("\n=== Attack Simulation (ranked on train, evaluated on test) ===") # section header
    leaked_candidates = dob_to_candidate_pins(dob) # attacker knows the demo DOB  # derive DOB-based candidate guesses for the leakage attack

    attack_results = evaluate_all_attacks( # run all four attack strategies and evaluate their Top-k success rates
        train_freq_df=train_freq,
        test_distribution=test_dist,
        leaked_candidates=leaked_candidates,
        k_values=[1, 3, 5, 10],
        seed=seed,
    )
    print_attack_results(attack_results) # print the results of all attack simulations

    # 8. Save per-model summary
    summary_path = os.path.join(RESULTS_DIR, f"summary_{model_name}.csv") # build path for this model's summary CSV
    save_model_summary( # save a single-row summary combining metrics and attack results
        model_name=model_name,
        metrics=metrics,
        attack_results=attack_results,
        output_path=summary_path,
    )
    print(f"Summary saved   → {summary_path}") # confirm the summary was saved

    summary_row = { # rebuild the same flattened summary row so it can be returned and combined across models later
        "Model":                  model_name,
        "Shannon Entropy (bits)": metrics["Shannon Entropy (bits)"],
        "Min-Entropy (bits)":     metrics["Min-Entropy (bits)"],
        "Expected Guesses":       metrics["Expected Guesses"],
    }
    for attack_name, result_dict in attack_results.items(): # iterate over each attack strategy's results
        for metric_name, value in result_dict.items(): # iterate over each Top-k metric within that attack
            summary_row[f"{attack_name} - {metric_name}"] = value # flatten into the summary row

    return { # return both the flattened summary row and the raw frequency table for downstream use
        "summary_row": summary_row,
        "train_freq":  train_freq,
    }

def run_defense_for_all_models(
    model_frequencies: dict, # mapping of model_name -> training frequency table
    blacklist_sizes:   list, # list of blacklist sizes to evaluate
) -> pd.DataFrame:
    defense_tables = [] # accumulator list for each model's defense study results
    print("\n=== Defense Study: Weak PIN Blacklisting ===") # section header

    for model_name, freq in model_frequencies.items(): # iterate over each model's frequency table
        print(f"\n--- {model_name} ---") # sub-header identifying the current model
        defense_df = run_weak_pin_blacklisting_study( # run the blacklisting defense sweep for this model
            freq=freq,
            model_name=model_name,
            blacklist_sizes=blacklist_sizes,
            k=10,
        )
        print_defense_results(defense_df) # print this model's defense study results
        defense_tables.append(defense_df) # add this model's results table to the accumulator

    all_defense_df = pd.concat(defense_tables, ignore_index=True) # combine all models' defense tables into one DataFrame
    defense_path   = os.path.join(RESULTS_DIR, "defense_weak_blacklisting.csv") # build path for the combined defense results file
    save_defense_results(all_defense_df, output_path=defense_path) # save the combined defense results to CSV
    print(f"\nDefense results saved → {defense_path}") # confirm the combined results were saved
    return all_defense_df # return the combined defense results DataFrame

# ============================================================
# CLI
# ============================================================

def parse_blacklist_sizes(value: str) -> list: # custom argparse type: parses a comma-separated string into a list of ints
    try:
        return [int(x.strip()) for x in value.split(",") if x.strip()] # split on commas, strip whitespace, convert each to int
    except ValueError: # if any piece fails to convert to an integer
        raise argparse.ArgumentTypeError( # raise argparse's expected error type with a helpful message
            "Blacklist sizes must be comma-separated integers, e.g. 10,50,100,500"
        )

def parse_args(): # defines and parses all command-line arguments for this script
    parser = argparse.ArgumentParser( # create the argument parser with a description shown in --help
        description="Low-Entropy Attacks on 6-Digit PINs"
    )
    parser.add_argument("--run_mode",  choices=["one", "all"], default=DEFAULT_RUN_MODE) # whether to run one model or all three
    parser.add_argument("--model",     choices=["uniform", "biased", "leakage"], default=DEFAULT_MODEL) # which single model to run if run_mode="one"
    parser.add_argument("--dob",       type=str,   default=DEFAULT_DOB) # demo date-of-birth for the leakage scenario
    parser.add_argument("--n",         type=int,   default=DEFAULT_N) # number of PINs to generate
    parser.add_argument("--seed",      type=int,   default=DEFAULT_SEED) # random seed for reproducibility
    parser.add_argument("--train_ratio", type=float, default=DEFAULT_TRAIN_RATIO, # fraction of data used for training
                        help="Fraction of dataset used for training (default 0.80)") 
    parser.add_argument("--use_survey_weights", action="store_true") # flag: force use of survey-derived weights
    parser.add_argument("--no_defense",         action="store_true") # flag: skip running the defense study
    parser.add_argument("--blacklist_sizes", type=parse_blacklist_sizes, # comma-separated list of blacklist sizes, parsed via helper above
                        default=DEFAULT_BLACKLIST_SIZES) 
    return parser.parse_args() # parse sys.argv and return the resulting namespace

# ============================================================
# Main
# ============================================================

def main(): # top-level orchestration function that runs the full experiment pipeline
    args = parse_args() # parse command-line arguments
    ensure_dirs() # make sure output directories exist

    use_survey_weights = args.use_survey_weights or DEFAULT_USE_SURVEY_WEIGHTS # combine CLI flag with the module default
    run_defense        = not args.no_defense # invert the --no_defense flag into a positive "should run defense" boolean

    summaries         = [] # accumulator list for each model's flattened summary row
    model_frequencies = {} # accumulator dict mapping model_name -> training frequency table

    models = ["uniform", "biased", "leakage"] if args.run_mode == "all" else [args.model] # decide which model(s) to run based on run_mode

    for model in models: # loop over each model to run the full experimental pipeline
        result = run_one_model( # run dataset generation, metrics, and attack evaluation for this model
            model_name         = model,
            dob                = args.dob,
            n                  = args.n,
            seed               = args.seed,
            use_survey_weights = use_survey_weights,
            train_ratio        = args.train_ratio,
        )
        summaries.append(result["summary_row"]) # collect this model's summary row
        model_frequencies[model] = result["train_freq"] # collect this model's training frequency table

    # Save combined summary
    summary_df   = pd.DataFrame(summaries) # combine all models' summary rows into one DataFrame
    summary_path = os.path.join(RESULTS_DIR, "summary_all_models.csv") # build path for the combined summary file
    summary_df.to_csv(summary_path, index=False) # save the combined summary to CSV
    print(f"\nCombined summary → {summary_path}") # confirm the combined summary was saved
    print("\n=== Summary Table ===") # section header
    print(summary_df.to_string()) # print the full combined summary table to the console

    # Plots
    print("\n=== Generating Plots ===" )# section header
    saved = generate_all_plots(summary_path=summary_path, results_dir=RESULTS_DIR) # generate every chart/figure from the combined summary
    for f in saved: # iterate over each saved plot path
        print(f"  Saved: {f}") # confirm each plot was saved

    # Defense
    if run_defense: # only run the defense study if it wasn't disabled via --no_defense
        defense_df = run_defense_for_all_models( # run the blacklisting defense sweep across all models
            model_frequencies=model_frequencies,
            blacklist_sizes=args.blacklist_sizes,
        )

        try: # wrap the defense plot generation in a try/except so a plotting failure doesn't crash the whole run
            import matplotlib.pyplot as plt # local import of the plotting library, scoped to this block
            plt.figure(figsize=(10, 6)) # create a new figure with the given size in inches
            for model_name in defense_df["Model"].unique(): # loop over each unique model present in the defense results
                sub = defense_df[defense_df["Model"] == model_name] # filter rows belonging to this model
                plt.plot(sub["Blacklist Size"], sub["New Top-10 Success Rate"], # plot success rate vs blacklist size for this model
                         marker="o", label=model_name) # mark each data point with a circle, label for the legend
            plt.title("Defense Study: Weak PIN Blacklisting") # set the chart title
            plt.xlabel("Number of Most Frequent PINs Blacklisted") 
            plt.ylabel("New Top-10 Attack Success Rate") 
            plt.legend() # show the legend distinguishing each model's curve
            plt.grid(alpha=0.3) # add a light grid for easier reading
            plt.tight_layout() # adjust spacing so labels/titles aren't clipped
            plot_path = os.path.join(RESULTS_DIR, "defense_weak_blacklisting_plot.png") # build path for the defense plot file
            plt.savefig(plot_path, dpi=300) # save the figure to disk at high resolution
            plt.close() # close the figure to free memory
            print(f"\nDefense plot saved → {plot_path}") # confirm the defense plot was saved
        except Exception as e: # catch any error during defense plot generation
            print(f"Could not generate defense plot: {e}") # report the error without stopping the rest of the pipeline

    print("\nExperiment completed successfully.") # final confirmation message


if __name__ == "__main__": # standard Python entry-point guard, ensures main() only runs when executed as a script
    main() # run the full experiment pipeline
