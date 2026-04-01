def top_k_success(freq_df, k):
    top_k = freq_df.head(k)
    return top_k['probability'].sum()

def evaluate_attacks(freq_df):
    results = {
        "Top-1": top_k_success(freq_df, 1),
        "Top-3": top_k_success(freq_df, 3),
        "Top-5": top_k_success(freq_df, 5),
        "Top-10": top_k_success(freq_df, 10),
    }
    return results

def print_attack_results(results):
    print("\nAttack Success Rates:")
    for k, v in results.items():
        print(f"{k}: {v:.4f}")