import pandas as pd


def _detect_pin_column(freq: pd.DataFrame) -> str:
    """
    Detect the PIN column name from a frequency dataframe.
    Compatible with common column names: pin, PIN.
    """
    possible_columns = ["pin", "PIN", "Pin"]

    for col in possible_columns:
        if col in freq.columns:
            return col

    raise ValueError(
        "Could not find PIN column in frequency dataframe. "
        "Expected one of: pin, PIN, Pin."
    )


def _detect_probability_column(freq: pd.DataFrame) -> str:
    """
    Detect the probability column name from a frequency dataframe.
    Compatible with common column names: probability, Probability, Frequency, frequency.
    """
    possible_columns = [
        "probability",
        "Probability",
        "frequency",
        "Frequency",
        "prob",
        "Prob",
    ]

    for col in possible_columns:
        if col in freq.columns:
            return col

    # If only count exists, probability can be computed from count.
    possible_count_columns = ["count", "Count", "counts", "Counts"]

    for col in possible_count_columns:
        if col in freq.columns:
            return col

    raise ValueError(
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
    if freq is None or freq.empty:
        raise ValueError("Frequency dataframe is empty.")

    freq = freq.copy()

    pin_col = _detect_pin_column(freq)
    prob_col = _detect_probability_column(freq)

    standardized = pd.DataFrame()
    standardized["pin"] = freq[pin_col].astype(str).str.zfill(6)

    # If the detected column is count-like, convert to probability.
    if prob_col.lower() in ["count", "counts"]:
        total = freq[prob_col].sum()
        if total == 0:
            raise ValueError("Total count is zero. Cannot compute probabilities.")
        standardized["probability"] = freq[prob_col] / total
    else:
        standardized["probability"] = freq[prob_col].astype(float)

        total_prob = standardized["probability"].sum()

        # Renormalize if needed.
        if total_prob <= 0:
            raise ValueError("Total probability is zero. Cannot normalize.")

        standardized["probability"] = standardized["probability"] / total_prob

    standardized = standardized.sort_values(
        by="probability",
        ascending=False
    ).reset_index(drop=True)

    return standardized


def compute_top_k_success_rate(freq: pd.DataFrame, k: int = 10) -> float:
    """
    Compute Top-k success rate for a frequency-ranked attacker.

    Meaning:
    The attacker guesses the k most probable PINs.
    The success rate is the sum of probabilities of those k PINs.
    """
    standardized = prepare_frequency_dataframe(freq)

    if k <= 0:
        return 0.0

    return float(standardized.head(k)["probability"].sum())


def apply_weak_pin_blacklist(
    freq: pd.DataFrame,
    blacklist_size: int
) -> pd.DataFrame:
    """
    Remove the most frequent PINs from the distribution and renormalize
    the remaining probabilities.

    Example:
    blacklist_size = 10 means remove the top 10 most common PINs.
    """
    standardized = prepare_frequency_dataframe(freq)

    if blacklist_size < 0:
        raise ValueError("blacklist_size must be non-negative.")

    if blacklist_size >= len(standardized):
        raise ValueError(
            "blacklist_size is too large. It would remove all PINs."
        )

    filtered = standardized.iloc[blacklist_size:].copy()

    remaining_probability = filtered["probability"].sum()

    if remaining_probability <= 0:
        raise ValueError(
            "Remaining probability is zero after blacklisting. "
            "Cannot renormalize distribution."
        )

    filtered["probability"] = filtered["probability"] / remaining_probability

    filtered = filtered.sort_values(
        by="probability",
        ascending=False
    ).reset_index(drop=True)

    return filtered


def evaluate_weak_pin_blacklisting(
    freq: pd.DataFrame,
    blacklist_size: int,
    k: int = 10
) -> dict:
    """
    Evaluate one weak PIN blacklist size.

    It computes:
    - original Top-k success rate
    - new Top-k success rate after removing frequent PINs
    - absolute reduction
    - relative reduction
    """
    original_success_rate = compute_top_k_success_rate(freq, k=k)

    filtered_freq = apply_weak_pin_blacklist(
        freq=freq,
        blacklist_size=blacklist_size
    )

    new_success_rate = compute_top_k_success_rate(filtered_freq, k=k)

    absolute_reduction = original_success_rate - new_success_rate

    if original_success_rate > 0:
        relative_reduction = absolute_reduction / original_success_rate
    else:
        relative_reduction = 0.0

    return {
        "Blacklist Size": blacklist_size,
        "Original Top-10 Success Rate": original_success_rate,
        "New Top-10 Success Rate": new_success_rate,
        "Absolute Reduction": absolute_reduction,
        "Relative Reduction": relative_reduction,
    }


def run_weak_pin_blacklisting_study(
    freq: pd.DataFrame,
    model_name: str,
    blacklist_sizes: list[int],
    k: int = 10
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
    results = []

    for size in blacklist_sizes:
        result = evaluate_weak_pin_blacklisting(
            freq=freq,
            blacklist_size=size,
            k=k
        )

        result["Model"] = model_name
        result["Defense Type"] = "Weak PIN Blacklisting"

        results.append(result)

    defense_df = pd.DataFrame(results)

    defense_df = defense_df[
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

    return defense_df


def save_defense_results(
    defense_df: pd.DataFrame,
    output_path: str
) -> None:
    """
    Save defense study results to CSV.
    """
    defense_df.to_csv(output_path, index=False)


def print_defense_results(defense_df: pd.DataFrame) -> None:
    """
    Print defense study results in terminal.
    """
    print("\n=== Defense Study: Weak PIN Blacklisting ===")
    print(defense_df.to_string(index=False))