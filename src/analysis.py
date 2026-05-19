import math
import pandas as pd
from typing import Tuple

# ============================================================
# Frequency Computation
# ============================================================

def compute_frequency(file_path: str) -> pd.DataFrame:
    df = pd.read_csv(file_path, dtype={"pin": str})
    df["pin"] = df["pin"].str.zfill(6)

    freq = df["pin"].value_counts().reset_index()
    freq.columns = ["pin", "count"]
    freq["probability"] = freq["count"] / len(df)
    return freq


def save_frequency(freq_df: pd.DataFrame, output_path: str = "results/frequency.csv") -> None:
    freq_df.to_csv(output_path, index=False)


def print_top_pins(freq_df: pd.DataFrame, k: int = 10) -> None:
    print(f"\nTop {k} most common PINs:")
    print(freq_df.head(k))


# ============================================================
# Train/Test Split
# ============================================================

def train_test_split_pins(
    pins: list,
    train_ratio: float = 0.80,
    seed: int = 42
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
    import random
    rng = random.Random(seed)
    shuffled = pins[:]
    rng.shuffle(shuffled)
    split = int(len(shuffled) * train_ratio)
    return shuffled[:split], shuffled[split:]


def compute_frequency_from_pins(pins: list) -> pd.DataFrame:
    """
    Build a frequency table directly from a list of PIN strings,
    without requiring an intermediate CSV file.
    """
    import pandas as pd
    from collections import Counter
    counts = Counter(str(p).zfill(6) for p in pins)
    total  = len(pins)
    rows   = [{"pin": pin, "count": cnt, "probability": cnt / total}
              for pin, cnt in counts.items()]
    freq   = pd.DataFrame(rows).sort_values("probability", ascending=False).reset_index(drop=True)
    return freq


def compute_test_distribution(test_pins: list) -> dict:
    """
    Build a probability distribution dict from the test set.
    Used as the evaluation target for Top-k success rate computation.
    """
    from collections import Counter
    counts = Counter(str(p).zfill(6) for p in test_pins)
    total  = len(test_pins)
    return {pin: cnt / total for pin, cnt in counts.items()}


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
    probabilities = freq_df["probability"]
    return -sum(p * math.log2(p) for p in probabilities if p > 0)


def min_entropy(freq_df: pd.DataFrame) -> float:
    """
    Empirical min-entropy: H_inf(X) = -log2(max p(x))

    Measures worst-case predictability based on the most probable PIN
    in the sampled distribution.
    """
    max_p = freq_df["probability"].max()
    return -math.log2(max_p)


def expected_guesses(freq_df: pd.DataFrame) -> float:
    """
    Expected number of guesses under optimal ranked guessing strategy.

    G(X) = sum_{i=1}^{N} i * p_i

    where p_i is the probability of the PIN at rank i (sorted descending).
    This measures the average number of guesses needed to find the target PIN
    if the attacker guesses in frequency-ranked order.
    """
    sorted_df = freq_df.sort_values(
        by="probability", ascending=False
    ).reset_index(drop=True)
    sorted_df["rank"] = sorted_df.index + 1
    return (sorted_df["probability"] * sorted_df["rank"]).sum()


def compute_security_metrics(freq_df: pd.DataFrame) -> dict:
    return {
        "Shannon Entropy (bits)": shannon_entropy(freq_df),
        "Min-Entropy (bits)":     min_entropy(freq_df),
        "Expected Guesses":       expected_guesses(freq_df),
    }


def print_security_metrics(metrics: dict) -> None:
    print("\nSecurity Metrics:")
    for name, value in metrics.items():
        if "Guesses" in name:
            print(f"  {name}: {value:.2f}")
        else:
            print(f"  {name}: {value:.4f} bits")
