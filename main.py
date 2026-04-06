import pandas as pd
from src.pin_generator import generate_dataset
from src.analysis import compute_frequency, save_frequency, print_top_pins
from src.attack import evaluate_attacks, print_attack_results

def main():
    model_name = "biased"   # đổi thử: uniform / biased / leakage

    print(f"=== Generating {model_name} PIN dataset ===")
    pins = generate_dataset(100000, model=model_name, seed=42, dob="1998-03-05")

    df = pd.DataFrame(pins, columns=["pin"])
    df.to_csv(f"data/generated_{model_name}_pins.csv", index=False)
    print(f"Dataset saved to data/generated_{model_name}_pins.csv")

    print("\n=== Computing frequency ===")
    freq = compute_frequency(f"data/generated_{model_name}_pins.csv")

    save_frequency(freq, output_path=f"results/frequency_{model_name}.csv")
    print(f"Frequency saved to results/frequency_{model_name}.csv")

    print_top_pins(freq, 10)

    print("\n=== Running attack simulation ===")
    results = evaluate_attacks(freq)
    print_attack_results(results)

if __name__ == "__main__":
    main()