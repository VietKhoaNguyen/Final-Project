from src.pin_generator import generate_dataset
from src.analysis import compute_frequency
from src.attack import top_k_success
import pandas as pd

pins = generate_dataset(100000)
df = pd.DataFrame(pins, columns=["pin"])
df.to_csv("data/generated_pins.csv", index=False)

freq = compute_frequency("data/generated_pins.csv")

print("Top 1 success:", top_k_success(freq, 1))
print("Top 3 success:", top_k_success(freq, 3))
print("Top 10 success:", top_k_success(freq, 10))