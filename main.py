from src.pin_generator import generate_dataset
import pandas as pd

pins = generate_dataset(100000)

df = pd.DataFrame(pins, columns=["pin"])
df.to_csv("data/generated_pins.csv", index=False)

print("Dataset saved!")