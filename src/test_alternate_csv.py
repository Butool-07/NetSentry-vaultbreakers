
import pandas as pd
from pathlib import Path
from normalize_data import normalize_network_data

project_folder = Path(__file__).resolve().parent.parent
csv_file = project_folder / "data" / "alternate_traffic.csv"

# Load the actual CSV file.
df = pd.read_csv(csv_file)

print("Original columns:")
print(list(df.columns))

# Convert alternate column names to NetSentry's standard names.
normalized_df = normalize_network_data(df)

print("\nNormalized columns:")
print(list(normalized_df.columns))

print("\nNormalized traffic data:")
print(normalized_df)

print("\nTotal records:", len(normalized_df))
print("\nAlternate CSV normalization successful!")
