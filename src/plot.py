import os
from typing import List

import matplotlib.pyplot as plt
import pandas as pd

def ensure_results_dir(results_dir: str = "results") -> None: # makes sure the output directory exists before saving plots
    os.makedirs(results_dir, exist_ok=True) # create the directory (and parents) if missing; do nothing if it already exists

def load_summary(summary_path: str = "results/summary_all_models.csv") -> pd.DataFrame: #  loads the combined summary metrics CSV
    return pd.read_csv(summary_path) # read the CSV file into a DataFrame

def load_frequency(model_name: str, results_dir: str = "results") -> pd.DataFrame: # loads the per-model frequency CSV
    path = os.path.join(results_dir, f"frequency_{model_name}.csv") # build the file path for this model's frequency table
    df = pd.read_csv(path, dtype={"pin": str}) # read the CSV, forcing pin column to load as string (preserve leading zeros)
    df["pin"] = df["pin"].str.zfill(6) # zero-pad every pin to exactly 6 digits
    return df # return the loaded frequency table

def plot_entropy_comparison(summary_df: pd.DataFrame, results_dir: str = "results") -> str: # bar chart comparing Shannon entropy across models
    plt.figure(figsize=(8, 5)) # create a new figure with the given size in inches
    plt.bar(summary_df["Model"], summary_df["Shannon Entropy (bits)"]) # draw one bar per model, height = its Shannon entropy
    plt.xlabel("Model")
    plt.ylabel("Shannon Entropy (bits)")
    plt.title("Shannon Entropy Comparison Across PIN Models")
    plt.tight_layout() # adjust spacing so labels/titles aren't clipped

    output_path = os.path.join(results_dir, "plot_entropy_comparison.png") # build the destination file path for this plot
    plt.savefig(output_path, dpi=300) # save the figure to disk at high resolution
    plt.close() # close the figure to free memory and avoid overlapping with the next plot
    return output_path # adjust spacing so labels/titles aren't clipped

def plot_min_entropy_comparison(summary_df: pd.DataFrame, results_dir: str = "results") -> str: # bar chart comparing min-entropy across models
    plt.figure(figsize=(8, 5)) # create a new figure with the given size in inches
    plt.bar(summary_df["Model"], summary_df["Min-Entropy (bits)"]) # draw one bar per model, height = its min-entropy
    plt.xlabel("Model")
    plt.ylabel("Min-Entropy (bits)")
    plt.title("Min-Entropy Comparison Across PIN Models")
    plt.tight_layout() # adjust spacing so labels/titles aren't clipped

    output_path = os.path.join(results_dir, "plot_min_entropy_comparison.png") # build the destination file path for this plot
    plt.savefig(output_path, dpi=300) # save the figure to disk at high resolution
    plt.close() # close the figure to free memory and avoid overlapping with the next plot
    return output_path # adjust spacing so labels/titles aren't clipped

def plot_expected_guesses_comparison(summary_df: pd.DataFrame, results_dir: str = "results") -> str: # bar chart comparing expected guesses across models
    plt.figure(figsize=(8, 5)) # create a new figure with the given size in inches
    plt.bar(summary_df["Model"], summary_df["Expected Guesses"]) # draw one bar per model, height = its expected guesses
    plt.xlabel("Model")
    plt.ylabel("Expected Number of Guesses")
    plt.title("Expected Guesses Comparison Across PIN Models")
    plt.tight_layout() # adjust spacing so labels/titles aren't clipped

    output_path = os.path.join(results_dir, "plot_expected_guesses_comparison.png") # build the destination file path for this plot
    plt.savefig(output_path, dpi=300) # save the figure to disk at high resolution
    plt.close() # close the figure to free memory and avoid overlapping with the next plot
    return output_path # adjust spacing so labels/titles aren't clipped

def plot_top10_pins(model_name: str, freq_df: pd.DataFrame, results_dir: str = "results") -> str: # bar chart of the top 10 most common PINs for 1 model
    top10 = freq_df.head(10).copy() # take the first 10 rows (assumes freq_df already sorted by probability descending)

    plt.figure(figsize=(10, 5)) # create a new figure with the given size in inches
    plt.bar(top10["pin"], top10["probability"]) # draw one bar per top-10 pin, height = its expected guesses
    plt.xlabel("PIN")
    plt.ylabel("Probability")
    plt.title(f"Top 10 Most Common PINs - {model_name.capitalize()} Model") # set the chart title, including the model name
    plt.xticks(rotation=45) # rotate x-axis tick labels 45 degrees so PIN strings don't overlap
    plt.tight_layout() # adjust spacing so labels/titles aren't clipped

    output_path = os.path.join(results_dir, f"plot_top10_{model_name}.png") # build the destination file path for this plot
    plt.savefig(output_path, dpi=300) # save the figure to disk at high resolution
    plt.close() # close the figure to free memory and avoid overlapping with the next plot
    return output_path # adjust spacing so labels/titles aren't clipped

def plot_rank_probability_curve(model_name: str, freq_df: pd.DataFrame, results_dir: str = "results") -> str: # log-log rank vs probability curve for one model
    ranked = freq_df.sort_values(by="probability", ascending=False).reset_index(drop=True) # sort PINs by probability descending, reset index
    ranked["rank"] = ranked.index + 1 # assign rank 1, 2, 3... based on sorted position

    plt.figure(figsize=(8, 5)) # create a new figure with the given size in inches
    plt.plot(ranked["rank"], ranked["probability"]) # plot probability as a function of rank
    plt.xscale("log") # use logarithmic scale on the x-axis (rank)
    plt.yscale("log") # use logarithmic scale on the y-axis (probability)
    plt.xlabel("Rank (log scale)")
    plt.ylabel("Probability (log scale)")
    plt.title(f"Rank-Probability Curve - {model_name.capitalize()} Model") # set the chart title, including the model name
    plt.tight_layout() # adjust spacing so labels/titles aren't clipped

    output_path = os.path.join(results_dir, f"plot_rank_probability_{model_name}.png") # build the destination file path for this plot
    plt.savefig(output_path, dpi=300) # save the figure to disk at high resolution
    plt.close() # close the figure to free memory and avoid overlapping with the next plot
    return output_path # adjust spacing so labels/titles aren't clipped

def plot_combined_rank_probability(results_dir: str = "results") -> str: # overlays the rank-probability curves of all three models on one chart
    plt.figure(figsize=(8, 5)) # create a new figure with the given size in inches

    for model_name in ["uniform", "biased", "leakage"]: # loop over each PIN generation model
        freq_df = load_frequency(model_name, results_dir) # load this model's frequency table
        ranked = freq_df.sort_values(by="probability", ascending=False).reset_index(drop=True) # sort by probability descending, reset index
        ranked["rank"] = ranked.index + 1 # assign rank 1, 2, 3... based on sorted position
        plt.plot(ranked["rank"], ranked["probability"], label=model_name) # plot this model's curve, labeled by model name for the legend

    plt.xscale("log") # use logarithmic scale on the x-axis (rank)
    plt.yscale("log") # use logarithmic scale on the y-axis (probability)
    plt.xlabel("Rank (log scale)")
    plt.ylabel("Probability (log scale)")
    plt.title("Combined Rank-Probability Curves Across Models")
    plt.legend() # show the legend distinguishing each model's curve
    plt.tight_layout() # adjust spacing so labels/titles aren't clipped

    output_path = os.path.join(results_dir, "plot_rank_probability_combined.png") # build the destination file path for this plot
    plt.savefig(output_path, dpi=300) # save the figure to disk at high resolution
    plt.close() # close the figure to free memory and avoid overlapping with the next plot
    return output_path # return the path where the plot was saved

def plot_attack_success_by_model(summary_df: pd.DataFrame, results_dir: str = "results") -> List[str]:
    """
    Generate 4 separate plots:
    Top-1, Top-3, Top-5, Top-10
    Each plot compares all attacks across the three models.
    """
    output_paths = [] # accumulator list for the paths of all generated plots

    attack_prefixes = [ # names of the four attack strategies, used to look up their result columns
        "Random",
        "Frequency-Ranked",
        "Rule-Based",
        "Leakage-Assisted",
    ]

    for k in ["Top-1", "Top-3", "Top-5", "Top-10"]: # generate one grouped-bar chart per Top-k threshold
        plt.figure(figsize=(10, 5)) # create a new figure with the given size in inches

        x = range(len(summary_df["Model"])) # base x positions, one per model
        width = 0.2 # width of each individual bar within a group

        for i, attack_name in enumerate(attack_prefixes): # loop over each attack strategy, tracking its index for bar offset
            col = f"{attack_name} - {k}" # build the column name holding this attack's success rate at this k
            offsets = [v + (i - 1.5) * width for v in x] # shift each bar's x position so the 4 attacks form a grouped cluster per model
            plt.bar(offsets, summary_df[col], width=width, label=attack_name) # draw this attack's bars across all models

        plt.xticks(list(x), summary_df["Model"]) # label each group of bars with its model name
        plt.xlabel("Model")
        plt.ylabel("Success Rate")
        plt.title(f"Attack Success Comparison ({k})")
        plt.legend() # show the legend distinguishing each attack strategy
        plt.tight_layout() # adjust spacing so labels/titles aren't clipped

        output_path = os.path.join(results_dir, f"plot_attack_comparison_{k.lower()}.png") # build the destination file path for this plot
        plt.savefig(output_path, dpi=300) # save the figure to disk at high resolution
        plt.close() # close the figure to free memory and avoid overlapping with the next plot
        output_paths.append(output_path) # record this plot's path in the accumulator list

    return output_paths # return the list of all four generated plot paths

def plot_cumulative_success_curve(results_dir: str = "results", max_k: int = 1000) -> str:
    """
    Plot cumulative success curve for frequency-ranked attack:
    x = number of guesses
    y = cumulative success probability
    """
    plt.figure(figsize=(8, 5)) # create a new figure with the given size in inches

    for model_name in ["uniform", "biased", "leakage"]: # loop over each PIN generation model
        freq_df = load_frequency(model_name, results_dir) # load this model's frequency table
        ranked = freq_df.sort_values(by="probability", ascending=False).reset_index(drop=True) # sort by probability descending, reset index
        ranked["cumulative_success"] = ranked["probability"].cumsum() # compute running cumulative sum of probability (success rate as guesses increase)

        max_index = min(max_k, len(ranked)) # cap the number of guesses plotted at either max_k or the dataset size, whichever is smaller
        x_vals = list(range(1, max_index + 1)) # x-axis values: guess counts from 1 to max_index
        y_vals = ranked["cumulative_success"].iloc[:max_index] # y-axis values: cumulative success probability up to max_index guesses

        plt.plot(x_vals, y_vals, label=model_name) # plot this model's cumulative success curve, labeled for the legend

    plt.xscale("log") # use logarithmic scale on the x-axis (number of guesses)
    plt.xlabel("Number of Guesses (log scale)")
    plt.ylabel("Cumulative Success Probability")
    plt.title("Cumulative Success Curves (Frequency-Ranked Attack)")
    plt.legend() # show the legend distinguishing each model
    plt.tight_layout() # adjust spacing so labels/titles aren't clipped

    output_path = os.path.join(results_dir, "plot_cumulative_success_curve.png") # build the destination file path for this plot
    plt.savefig(output_path, dpi=300) # save the figure to disk at high resolution
    plt.close() # close the figure to free memory and avoid overlapping with the next plot
    return output_path # adjust spacing so labels/titles aren't clipped

def plot_entropy_vs_attack_success(summary_df: pd.DataFrame, results_dir: str = "results") -> str:
    """
    Scatter plot:
    x = Shannon entropy
    y = Frequency-Ranked Top-10 success
    """
    plt.figure(figsize=(8, 5)) # create a new figure with the given size in inches

    x = summary_df["Shannon Entropy (bits)"] # x-axis values: each model's Shannon entropy
    y = summary_df["Frequency-Ranked - Top-10"] # y-axis values: each model's Top-10 success rate under the frequency-ranked attack

    plt.scatter(x, y) # draw a scatter point for each model

    for _, row in summary_df.iterrows(): # loop over each row (model) to annotate its point
        plt.annotate(row["Model"], (row["Shannon Entropy (bits)"], row["Frequency-Ranked - Top-10"])) # label the point with the model's name

    plt.xlabel("Shannon Entropy (bits)")
    plt.ylabel("Top-10 Success Rate (Frequency-Ranked)")
    plt.title("Entropy vs Attack Success")
    plt.tight_layout() # adjust spacing so labels/titles aren't clipped

    output_path = os.path.join(results_dir, "plot_entropy_vs_attack_success.png") # build the destination file path for this plot
    plt.savefig(output_path, dpi=300) # save the figure to disk at high resolution
    plt.close() # close the figure to free memory and avoid overlapping with the next plot
    return output_path # return the path where the plot was saved

def generate_all_plots(
    summary_path: str = "results/summary_all_models.csv", # path to the combined summary metrics CSV
    results_dir: str = "results" # directory where all generated plots will be saved
) -> List[str]:
    ensure_results_dir(results_dir) # make sure the output directory exists
    saved_files = [] # accumulator list for the paths of every plot generated in this run

    summary_df = load_summary(summary_path) # load the combined summary metrics table

    # Metric comparison plots
    saved_files.append(plot_entropy_comparison(summary_df, results_dir)) # generate and record the Shannon entropy comparison plot
    saved_files.append(plot_min_entropy_comparison(summary_df, results_dir)) # generate and record the min-entropy comparison plot
    saved_files.append(plot_expected_guesses_comparison(summary_df, results_dir)) # generate and record the expected-guesses comparison plot

    # Attack comparison plots
    saved_files.extend(plot_attack_success_by_model(summary_df, results_dir))# generate and record 4 Top-k attack comparison plots

    # Per-model distribution plots
    for model_name in ["uniform", "biased", "leakage"]: # loop over each PIN generation model
        freq_df = load_frequency(model_name, results_dir) # load this model's frequency table
        saved_files.append(plot_top10_pins(model_name, freq_df, results_dir)) # generate and record this model's top-10 PIN bar chart
        saved_files.append(plot_rank_probability_curve(model_name, freq_df, results_dir)) # generate and record this model's rank-probability curve

    # Additional combined / thesis-strength plots
    saved_files.append(plot_combined_rank_probability(results_dir)) # generate and record the combined rank-probability overlay plot
    saved_files.append(plot_cumulative_success_curve(results_dir, max_k=1000)) # generate and record the cumulative success curve plot
    saved_files.append(plot_entropy_vs_attack_success(summary_df, results_dir)) # generate and record the entropy-vs-attack-success scatter plot

    return saved_files # return the full list of all generated plot file paths