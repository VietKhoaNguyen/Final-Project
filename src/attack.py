def top_k_success(freq_df, k):
    top_k = freq_df.head(k)
    return top_k['probability'].sum()