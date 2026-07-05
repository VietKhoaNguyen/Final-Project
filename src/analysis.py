import math
import pandas as pd
from typing import Tuple

# ============================================================
# Frequency Computation
# ============================================================

def compute_frequency(file_path: str) -> pd.DataFrame: # builds a frequency table from a CSV file of PINs
    df = pd.read_csv(file_path, dtype={"pin": str}) # load the CSV, forcing the pin column to be read as string (avoids losing leading zeros)
    df["pin"] = df["pin"].str.zfill(6) # zero-pad every pin to exactly 6 digits

    freq = df["pin"].value_counts().reset_index() # count occurrences of each unique pin, turn into a DataFrame
    freq.columns = ["pin", "count"] # rename the resulting columns to "pin" and "count"
    freq["probability"] = freq["count"] / len(df) # compute each pin's probability as its share of the total dataset
    return freq # return the frequency table with pin, count, and probability columns

def save_frequency(freq_df: pd.DataFrame, output_path: str = "results/frequency.csv") -> None: # writes a frequency table to disk
    freq_df.to_csv(output_path, index=False) # save as CSV, omitting the row index

def print_top_pins(freq_df: pd.DataFrame, k: int = 10) -> None: # prints the k most common PINs to the console
    print(f"\nTop {k} most common PINs:") # header line
    print(freq_df.head(k)) # print the first k rows (assumes freq_df is already sorted by frequency)s

# ============================================================
# Train/Test Split
# ============================================================

def train_test_split_pins(
    pins: list, # full list of generated PIN strings
    train_ratio: float = 0.80, # fraction of data to allocate to the training set
    seed: int = 42 # random seed controlling the shuffle, for reproducibility
) -> Tuple[list, list]: 
    """
    Split a list of PIN strings into train and test sets.

    - The train set is used to build frequency distributions and ranked
      guess orders (attacker's knowledge base).
    - The test set is used to evaluate Top-k success rates (evaluation target).

    This avoids optimistic evaluation caused by testing on seen data.

    Parameters
    ----------
    pins : list of str
        Full generated PIN dataset.
    train_ratio : float
        Fraction of data used for training (default 0.80).
    seed : int
        Random seed for reproducibility.

    Returns
    -------
    train_pins, test_pins : tuple of lists
    """
    import random # local import of the RNG module, scoped to this function
    rng = random.Random(seed) # create a seeded random number generator instance
    shuffled = pins[:] # make a shallow copy of the pins list so the original is not mutated
    rng.shuffle(shuffled) # randomly shuffle the copied list in place
    split = int(len(shuffled) * train_ratio) # compute the index that divides train and test portions
    return shuffled[:split], shuffled[split:] # return the first part as train set, the rest as test set

def compute_frequency_from_pins(pins: list) -> pd.DataFrame:
    """
    Build a frequency table directly from a list of PIN strings,
    without requiring an intermediate CSV file.
    """
    import pandas as pd # local import of pandas, scoped to this function
    from collections import Counter # local import of Counter, scoped to this function
    counts = Counter(str(p).zfill(6) for p in pins) # count occurrences of each normalized (zero-padded) PIN
    total  = len(pins) # total number of PINs in the input list
    rows   = [{"pin": pin, "count": cnt, "probability": cnt / total} # build one row dict per unique pin
              for pin, cnt in counts.items()] # iterate over each unique pin and its count
    freq   = pd.DataFrame(rows).sort_values("probability", ascending=False).reset_index(drop=True) # build DataFrame, sort by probability descending, reset index
    return freq # return the resulting frequency table

def compute_test_distribution(test_pins: list) -> dict:
    """
    Build a probability distribution dict from the test set.
    Used as the evaluation target for Top-k success rate computation.
    """
    from collections import Counter # local import of Counter, scoped to this function
    counts = Counter(str(p).zfill(6) for p in test_pins) # count occurrences of each normalized (zero-padded) test PIN 
    total  = len(test_pins) # total number of PINs in the test set
    return {pin: cnt / total for pin, cnt in counts.items()} # convert counts into a pin->probability dict

# ============================================================
# Security Metrics
# ============================================================

def shannon_entropy(freq_df: pd.DataFrame) -> float:
    """
    Empirical Shannon entropy computed from the sampled distribution.

    H(X) = -sum p(x) log2 p(x)

    Note: this is the empirical entropy of the generated sample, not the
    theoretical entropy of the 6-digit PIN space (log2(10^6) ≈ 19.93 bits).
    """
    probabilities = freq_df["probability"] # extract the probability column as a Series
    return -sum(p * math.log2(p) for p in probabilities if p > 0) # compute -sum(p*log2(p)) over all nonzero probabilities

def min_entropy(freq_df: pd.DataFrame) -> float:
    """
    Empirical min-entropy: H_inf(X) = -log2(max p(x))

    Measures worst-case predictability based on the most probable PIN
    in the sampled distribution.
    """
    max_p = freq_df["probability"].max() # find the highest single-PIN probability in the distribution
    return -math.log2(max_p) # compute min-entropy as negative log2 of that maximum probability

def expected_guesses(freq_df: pd.DataFrame) -> float:
    """
    Expected number of guesses under optimal ranked guessing strategy.

    G(X) = sum_{i=1}^{N} i * p_i

    where p_i is the probability of the PIN at rank i (sorted descending).
    This measures the average number of guesses needed to find the target PIN
    if the attacker guesses in frequency-ranked order.
    """
    sorted_df = freq_df.sort_values( # sort the frequency table
        by="probability", ascending=False # by probability, highest first (optimal guessing order)
    ).reset_index(drop=True) # reset the row index after sorting
    sorted_df["rank"] = sorted_df.index + 1 # assign rank 1, 2, 3... based on the new sorted position
    return (sorted_df["probability"] * sorted_df["rank"]).sum() # sum of (probability * rank) across all PINs, i.e. expected guess count

def compute_security_metrics(freq_df: pd.DataFrame) -> dict: # bundles all three security metrics into one dict
    return {
        "Shannon Entropy (bits)": shannon_entropy(freq_df), # overall uncertainty/randomness of the distribution
        "Min-Entropy (bits)":     min_entropy(freq_df), # worst-case predictability metric
        "Expected Guesses":       expected_guesses(freq_df), # average number of guesses needed under optimal strategy
    }

def print_security_metrics(metrics: dict) -> None: # pretty-prints a security metrics dict to the console
    print("\nSecurity Metrics:") # header line
    for name, value in metrics.items(): # iterate over each metric name/value pair
        if "Guesses" in name: # if this metric is the expected-guesses count
            print(f"  {name}: {value:.2f}") # print with 2 decimal places (it's a guess count, not bits)
        else: # otherwise it's an entropy metric measured in bits
            print(f"  {name}: {value:.4f} bits") # print with 4 decimal places and a "bits" unit label
