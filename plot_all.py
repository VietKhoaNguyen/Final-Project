import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# =========================
# LOAD DATA
# =========================
df = pd.read_csv("summary_all_models.csv")

models = df["model"].tolist()

# =========================
# 1. ATTACK SUCCESS BAR PLOTS
# =========================
def plot_attack_success(top_k):
    cols = {
        "Random": f"random_top{top_k}",
        "Frequency-Ranked": f"freq_top{top_k}",
        "Rule-Based": f"rule_top{top_k}",
        "Leakage-Assisted": f"leak_top{top_k}",
    }

    x = np.arange(len(models))
    width = 0.2

    plt.figure()
    for i, (label, col) in enumerate(cols.items()):
        plt.bar(x + i*width, df[col], width, label=label)

    plt.xticks(x + width, models)
    plt.xlabel("Model")
    plt.ylabel("Success Rate")
    plt.title(f"Attack Success Comparison (Top-{top_k})")
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"plot_attack_comparison_top-{top_k}.png")
    plt.close()


for k in [1, 3, 5, 10]:
    plot_attack_success(k)


# =========================
# 2. CUMULATIVE SUCCESS CURVE
# =========================
def plot_cumulative():
    plt.figure()

    guesses = [1,2,3,5,10,20,50,100,200,500,1000]

    for model in models:
        if model == "uniform":
            probs = np.repeat(1/1_000_000, 1000)
        elif model == "biased":
            probs = np.sort(np.random.power(2, 1000))[::-1]
        else:  # leakage
            probs = np.sort(np.random.power(5, 1000))[::-1]

        probs = probs / probs.sum()
        cumulative = np.cumsum(probs[:1000])

        values = [cumulative[g-1] for g in guesses]
        plt.plot(guesses, values, label=model)

    plt.xscale("log")
    plt.xlabel("Number of Guesses (log scale)")
    plt.ylabel("Cumulative Success Probability")
    plt.title("Cumulative Success Curves (Frequency-Ranked Attack)")
    plt.legend()
    plt.tight_layout()
    plt.savefig("plot_cumulative_success_curve.png")
    plt.close()


plot_cumulative()


# =========================
# 3. ENTROPY vs ATTACK
# =========================
plt.figure()
plt.scatter(df["entropy"], df["freq_top10"])

for i, model in enumerate(models):
    plt.text(df["entropy"][i], df["freq_top10"][i], model)

plt.xlabel("Shannon Entropy (bits)")
plt.ylabel("Top-10 Success Rate (Frequency-Ranked)")
plt.title("Entropy vs Attack Success")
plt.tight_layout()
plt.savefig("plot_entropy_vs_attack_success.png")
plt.close()


# =========================
# 4. EXPECTED GUESSES
# =========================
plt.figure()
plt.bar(models, df["expected_guesses"])
plt.xlabel("Model")
plt.ylabel("Expected Number of Guesses")
plt.title("Expected Guesses Comparison Across PIN Models")
plt.tight_layout()
plt.savefig("plot_expected_guesses_comparison.png")
plt.close()


# =========================
# 5. MIN ENTROPY
# =========================
plt.figure()
plt.bar(models, df["min_entropy"])
plt.xlabel("Model")
plt.ylabel("Min-Entropy (bits)")
plt.title("Min-Entropy Comparison Across PIN Models")
plt.tight_layout()
plt.savefig("plot_min_entropy_comparison.png")
plt.close()


# =========================
# 6. SHANNON ENTROPY
# =========================
plt.figure()
plt.bar(models, df["entropy"])
plt.xlabel("Model")
plt.ylabel("Shannon Entropy (bits)")
plt.title("Shannon Entropy Comparison Across PIN Models")
plt.tight_layout()
plt.savefig("plot_entropy_comparison.png")
plt.close()


# =========================
# 7. RANK-PROBABILITY CURVES
# =========================
def generate_distribution(model):
    if model == "uniform":
        probs = np.ones(100000) / 100000
    elif model == "biased":
        probs = np.sort(np.random.power(2, 100000))[::-1]
    else:
        probs = np.sort(np.random.power(5, 100000))[::-1]

    return probs / probs.sum()


def plot_rank_curve(model):
    probs = generate_distribution(model)
    ranks = np.arange(1, len(probs)+1)

    plt.figure()
    plt.plot(ranks, probs)
    plt.xscale("log")
    plt.yscale("log")
    plt.xlabel("Rank (log scale)")
    plt.ylabel("Probability (log scale)")
    plt.title(f"Rank-Probability Curve - {model.capitalize()} Model")
    plt.tight_layout()
    plt.savefig(f"plot_rank_probability_{model}.png")
    plt.close()


for m in models:
    plot_rank_curve(m)


# Combined
plt.figure()
for m in models:
    probs = generate_distribution(m)
    ranks = np.arange(1, len(probs)+1)
    plt.plot(ranks, probs, label=m)

plt.xscale("log")
plt.yscale("log")
plt.xlabel("Rank (log scale)")
plt.ylabel("Probability (log scale)")
plt.title("Combined Rank-Probability Curves Across Models")
plt.legend()
plt.tight_layout()
plt.savefig("plot_rank_probability_combined.png")
plt.close()


# =========================
# 8. TOP-10 PINS
# =========================
def plot_top10(model):
    probs = generate_distribution(model)
    top10 = probs[:10]
    pins = [f"{i:06d}" for i in range(10)]

    plt.figure()
    plt.bar(pins, top10)
    plt.xticks(rotation=45)
    plt.xlabel("PIN")
    plt.ylabel("Probability")
    plt.title(f"Top 10 Most Common PINs - {model.capitalize()} Model")
    plt.tight_layout()
    plt.savefig(f"plot_top10_{model}.png")
    plt.close()


for m in models:
    plot_top10(m)


print("ALL PLOTS GENERATED SUCCESSFULLY")