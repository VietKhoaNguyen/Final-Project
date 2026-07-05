import pandas as pd

def _detect_pin_column(freq: pd.DataFrame) -> str:
    """
    Detect the PIN column name from a frequency dataframe.
    Compatible with common column names: pin, PIN.
    """
    possible_columns = ["pin", "PIN", "Pin"] # list of accepted column-name spellings for the PIN column

    for col in possible_columns: # try each accepted spelling in order
        if col in freq.columns: # if this spelling exists in the DataFrame's columns
            return col # return the matching column name

    raise ValueError( # if none of the accepted spellings were found, fail loudly
        "Could not find PIN column in frequency dataframe. "
        "Expected one of: pin, PIN, Pin."
    )

def _detect_probability_column(freq: pd.DataFrame) -> str:
    """
    Detect the probability column name from a frequency dataframe.
    Compatible with common column names: probability, Probability, Frequency, frequency.
    """
    possible_columns = [ # list of accepted column-name spellings for a probability-like column
        "probability",
        "Probability",
        "frequency",
        "Frequency",
        "prob",
        "Prob",
    ]

    for col in possible_columns: # try each accepted probability spelling in order
        if col in freq.columns: # if this spelling exists in the DataFrame's columns
            return col # return the matching column name

    # If only count exists, probability can be computed from count.
    possible_count_columns = ["count", "Count", "counts", "Counts"] # fallback: accepted spellings for a raw count column

    for col in possible_count_columns: # try each accepted count spelling in order
        if col in freq.columns: # if this spelling exists in the DataFrame's columns
            return col # return the matching column name (caller will convert counts to probabilities)

    raise ValueError( # if neither a probability-like nor count-like column was found, fail loudly
        "Could not find probability or count column in frequency dataframe. "
        "Expected one of: probability, Probability, frequency, Frequency, count, Count."
    )

def prepare_frequency_dataframe(freq: pd.DataFrame) -> pd.DataFrame:
    """
    Standardize a frequency dataframe into columns:
    - pin
    - probability

    This makes the defense code robust even if the original frequency table
    uses slightly different column names.
    """
    if freq is None or freq.empty: # guard against missing or empty input data
        raise ValueError("Frequency dataframe is empty.") # fail loudly if there's nothing to process

    freq = freq.copy() # work on a copy so the caller's original DataFrame is not mutated

    pin_col = _detect_pin_column(freq) # figure out which column holds the PIN values
    prob_col = _detect_probability_column(freq) # figure out which column holds probability or count values

    standardized = pd.DataFrame() # new DataFrame that will hold the standardized output
    standardized["pin"] = freq[pin_col].astype(str).str.zfill(6) # copy PIN column, cast to string, zero-pad to 6 digits

    # If the detected column is count-like, convert to probability.
    if prob_col.lower() in ["count", "counts"]: # check whether the detected column is a raw count rather than a probability
        total = freq[prob_col].sum() # sum all counts to get the total number of observations
        if total == 0: # guard against dividing by zero
            raise ValueError("Total count is zero. Cannot compute probabilities.") # fail loudly if counts sum to zero
        standardized["probability"] = freq[prob_col] / total # convert counts into probabilities by dividing by the total
    else: # otherwise the column is already probability-like
        standardized["probability"] = freq[prob_col].astype(float) # copy the column, ensuring it's a float type

        total_prob = standardized["probability"].sum() # sum the probabilities to check they form a valid distribution

        # Renormalize if needed.
        if total_prob <= 0: # guard against a degenerate all-zero distribution
            raise ValueError("Total probability is zero. Cannot normalize.") # fail loudly if probabilities sum to zero

        standardized["probability"] = standardized["probability"] / total_prob # renormalize so probabilities sum to 1

    standardized = standardized.sort_values( # sort the standardized table
        by="probability", # sort by the probability column
        ascending=False # highest probability first
    ).reset_index(drop=True) # reset row index after sorting, discarding the old index

    return standardized # return the cleaned, standardized, sorted frequency table

def compute_top_k_success_rate(freq: pd.DataFrame, k: int = 10) -> float:
    """
    Compute Top-k success rate for a frequency-ranked attacker.

    Meaning:
    The attacker guesses the k most probable PINs.
    The success rate is the sum of probabilities of those k PINs.
    """
    standardized = prepare_frequency_dataframe(freq) # normalize the input frequency table into pin/probability columns

    if k <= 0: # guard against a non-positive k (no guesses allowed)
        return 0.0 # zero guesses means zero success probability

    return float(standardized.head(k)["probability"].sum()) # sum the probabilities of the top-k most likely PINs

def apply_weak_pin_blacklist( 
    freq: pd.DataFrame, # input frequency table to apply the blacklist defense to
    blacklist_size: int # number of most-frequent PINs to remove
) -> pd.DataFrame:
    """
    Remove the most frequent PINs from the distribution and renormalize
    the remaining probabilities.

    Example:
    blacklist_size = 10 means remove the top 10 most common PINs.
    """
    standardized = prepare_frequency_dataframe(freq) # normalize the input frequency table into pin/probability columns

    if blacklist_size < 0: # guard against a negative blacklist size
        raise ValueError("blacklist_size must be non-negative.") # fail loudly on invalid input

    if blacklist_size >= len(standardized): # guard against blacklisting the entire PIN space
        raise ValueError(
            "blacklist_size is too large. It would remove all PINs."
        )

    filtered = standardized.iloc[blacklist_size:].copy() # drop the top `blacklist_size` most frequent PINs (rows are already sorted descending)

    remaining_probability = filtered["probability"].sum() # sum the probability mass of the PINs that remain after blacklisting

    if remaining_probability <= 0: # guard against a degenerate case where nothing remains
        raise ValueError(
            "Remaining probability is zero after blacklisting. "
            "Cannot renormalize distribution."
        )

    filtered["probability"] = filtered["probability"] / remaining_probability # renormalize remaining probabilities so they sum to 1

    filtered = filtered.sort_values( # re-sort the filtered table
        by="probability", # sort by the probability column
        ascending=False # highest probability first
    ).reset_index(drop=True) # reset row index after sorting, discarding the old index

    return filtered # return the blacklisted and renormalized frequency table

def evaluate_weak_pin_blacklisting(
    freq: pd.DataFrame, # original (non-blacklisted) frequency table
    blacklist_size: int, # number of top PINs to blacklist
    k: int = 10 # Top-k threshold used to measure attack success
) -> dict:
    """
    Evaluate one weak PIN blacklist size.

    It computes:
    - original Top-k success rate
    - new Top-k success rate after removing frequent PINs
    - absolute reduction
    - relative reduction
    """
    original_success_rate = compute_top_k_success_rate(freq, k=k) # measure attacker success rate before applying the defense

    filtered_freq = apply_weak_pin_blacklist( # apply the blacklist defense to the frequency table
        freq=freq,
        blacklist_size=blacklist_size
    )

    new_success_rate = compute_top_k_success_rate(filtered_freq, k=k) # measure attacker success rate after applying the defense

    absolute_reduction = original_success_rate - new_success_rate # compute how much the success rate dropped in absolute terms

    if original_success_rate > 0: # guard against dividing by zero when computing relative reduction
        relative_reduction = absolute_reduction / original_success_rate # compute the reduction as a fraction of the original rate
    else: # if there was no original success rate to begin with
        relative_reduction = 0.0 # relative reduction is undefined/zero in this edge case

    return { # package all computed metrics into a result dict
        "Blacklist Size": blacklist_size, # the blacklist size that was evaluated
        "Original Top-10 Success Rate": original_success_rate, # attacker success rate before the defense
        "New Top-10 Success Rate": new_success_rate, # attacker success rate after the defense
        "Absolute Reduction": absolute_reduction, # absolute drop in success rate
        "Relative Reduction": relative_reduction, # proportional drop in success rate
    }

def run_weak_pin_blacklisting_study(
    freq: pd.DataFrame, # frequency table of the PIN model being studied
    model_name: str, # label identifying which PIN model this is (uniform/biased/leakage)
    blacklist_sizes: list[int], # list of blacklist sizes to sweep over
    k: int = 10 # Top-k threshold used to measure attack success
) -> pd.DataFrame:
    """
    Run weak PIN blacklisting defense study for one PIN model.

    This is the main function imported by app.py.

    Parameters
    ----------
    freq:
        Frequency table of one PIN model.
    model_name:
        Name of the model: uniform, biased, or leakage.
    blacklist_sizes:
        List of blacklist sizes, e.g. [10, 50, 100, 500].
    k:
        Top-k attack success rate to evaluate. Default is 10.

    Returns
    -------
    pd.DataFrame
        Defense result table.
    """
    results = [] # accumulator list for per-blacklist-size result dicts

    for size in blacklist_sizes: # iterate over each blacklist size to evaluate
        result = evaluate_weak_pin_blacklisting( # evaluate the defense at this specific blacklist size
            freq=freq,
            blacklist_size=size,
            k=k
        )

        result["Model"] = model_name # tag the result with which PIN model it belongs to
        result["Defense Type"] = "Weak PIN Blacklisting" # tag the result with the defense strategy name
        
        results.append(result) # add this size's result to the accumulator list

    defense_df = pd.DataFrame(results) # convert the list of result dicts into a DataFrame

    defense_df = defense_df[ # reorder/select columns into a consistent, readable order
        [
            "Model",
            "Defense Type",
            "Blacklist Size",
            "Original Top-10 Success Rate",
            "New Top-10 Success Rate",
            "Absolute Reduction",
            "Relative Reduction",
        ]
    ]

    return defense_df # return the full defense study result table


def save_defense_results(
    defense_df: pd.DataFrame, # defense study results to persist
    output_path: str # destination CSV file path
) -> None:
    """
    Save defense study results to CSV.
    """
    defense_df.to_csv(output_path, index=False) # write the DataFrame to CSV without including the row index


def print_defense_results(defense_df: pd.DataFrame) -> None:
    """
    Print defense study results in terminal.
    """
    print("\n=== Defense Study: Weak PIN Blacklisting ===") # section header for console output
    print(defense_df.to_string(index=False)) # print the full table without the row index column