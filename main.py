import pandas as pd
from src.pin_generator import generate_dataset
from src.analysis import compute_frequency, save_frequency, print_top_pins
from src.attack import evaluate_attacks, print_attack_results

def main():
    print("=== Generating PIN dataset ===")
    pins = generate_dataset(100000)

    df = pd.DataFrame(pins, columns=["pin"])
    df.to_csv("data/generated_pins.csv", index=False)
    print("Dataset saved to data/generated_pins.csv")

    print("\n=== Computing frequency ===")
    freq = compute_frequency("data/generated_pins.csv")

    save_frequency(freq)
    print("Frequency saved to results/frequency.csv")

    print_top_pins(freq, 10)

    print("\n=== Running attack simulation ===")
    results = evaluate_attacks(freq)

    print_attack_results(results)

if __name__ == "__main__":
    main()