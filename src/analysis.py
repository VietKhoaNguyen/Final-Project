import math
import pandas as pd

def compute_frequency(file_path):
    df = pd.read_csv(file_path, dtype={"pin": str})
    df["pin"] = df["pin"].str.zfill(6)

    freq = df["pin"].value_counts().reset_index()
    freq.columns = ["pin", "count"]

    freq["probability"] = freq["count"] / len(df)
    return freq

def save_frequency(freq_df, output_path="results/frequency.csv"):
    freq_df.to_csv(output_path, index=False)

def print_top_pins(freq_df, k=10):
    print(f"\nTop {k} most common PINs:")
    print(freq_df.head(k))

def shannon_entropy(freq_df):
    """
    H(X) = - sum p(x) log2 p(x)
    """
    probabilities = freq_df["probability"]
    return -sum(p * math.log2(p) for p in probabilities if p > 0)

def min_entropy(freq_df):
    """
    H_inf(X) = -log2(max p(x))
    """
    max_p = freq_df["probability"].max()
    return -math.log2(max_p)

def expected_guesses(freq_df):
    """
    G(X) = sum p_i * i
    where i is the rank in descending probability order.
    """
    sorted_df = freq_df.sort_values(by="probability", ascending=False).reset_index(drop=True)
    sorted_df["rank"] = sorted_df.index + 1
    return (sorted_df["probability"] * sorted_df["rank"]).sum()

def compute_security_metrics(freq_df):
    return {
        "Shannon Entropy (bits)": shannon_entropy(freq_df),
        "Min-Entropy (bits)": min_entropy(freq_df),
        "Expected Guesses": expected_guesses(freq_df),
    }

def print_security_metrics(metrics):
    print("\nSecurity Metrics:")
    for name, value in metrics.items():
        if "Guesses" in name:
            print(f"{name}: {value:.2f}")
        else:
            print(f"{name}: {value:.4f}")