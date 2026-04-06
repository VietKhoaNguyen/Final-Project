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