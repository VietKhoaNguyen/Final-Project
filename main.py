import pandas as pd

from src.pin_generator import generate_dataset, dob_to_candidate_pins
from src.analysis import (
    compute_frequency,
    save_frequency,
    print_top_pins,
    compute_security_metrics,
    print_security_metrics,
)
from src.attack import evaluate_all_attacks, print_attack_results

def main():
    model_name = "leakage"   # đổi thử: uniform / biased / leakage
    dob = "1998-03-05"

    print(f"=== Generating {model_name} PIN dataset ===")
    pins = generate_dataset(100000, model=model_name, seed=42, dob=dob)

    df = pd.DataFrame(pins, columns=["pin"])
    df.to_csv(f"data/generated_{model_name}_pins.csv", index=False)
    print(f"Dataset saved to data/generated_{model_name}_pins.csv")

    print("\n=== Computing frequency ===")
    freq = compute_frequency(f"data/generated_{model_name}_pins.csv")

    save_frequency(freq, output_path=f"results/frequency_{model_name}.csv")
    print(f"Frequency saved to results/frequency_{model_name}.csv")

    print_top_pins(freq, 10)

    print("\n=== Computing security metrics ===")
    metrics = compute_security_metrics(freq)
    print_security_metrics(metrics)

    print("\n=== Running attack simulation ===")
    leaked_candidates = dob_to_candidate_pins(dob)
    results = evaluate_all_attacks(freq, leaked_candidates=leaked_candidates)
    print_attack_results(results)

if __name__ == "__main__":
    main()