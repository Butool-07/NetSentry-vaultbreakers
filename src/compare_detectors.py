
import pandas as pd
from pathlib import Path

# Find the NetSentry project folder
project_folder = Path(__file__).resolve().parent.parent

# Load the results from both detectors
threshold_file = project_folder / "reports" / "traffic_analysis.csv"
ml_file = project_folder / "reports" / "ml_anomaly_results.csv"

threshold_df = pd.read_csv(threshold_file)
ml_df = pd.read_csv(ml_file)

# Combine the results using each record's timestamp
# and source IP address
keys = ["timestamp", "source_ip"]

threshold_results = threshold_df[
    keys + ["unusual"]
].rename(columns={"unusual": "threshold_flag"})

ml_results = ml_df[
    keys + ["ml_anomaly"]
]

comparison = threshold_results.merge(
    ml_results,
    on=keys,
    how="inner",
    validate="one_to_one",
)

# Identify records flagged by both methods
comparison["both_flagged"] = (
    comparison["threshold_flag"] & comparison["ml_anomaly"]
)

comparison["disagreement"] = (
    comparison["threshold_flag"] != comparison["ml_anomaly"]
)

print("====================================")
print(" NETSENTRY DETECTOR COMPARISON")
print("====================================")

print(f"Records compared: {len(comparison)}")
print(f"Threshold flags: {comparison['threshold_flag'].sum()}")
print(f"ML flags: {comparison['ml_anomaly'].sum()}")
print(f"Flagged by both: {comparison['both_flagged'].sum()}")
print(f"Methods disagree: {comparison['disagreement'].sum()}")

print("\nDetailed comparison:")
print(comparison.to_string(index=False))

# Save the comparison report
output_file = project_folder / "reports" / "detector_comparison.csv"
comparison.to_csv(output_file, index=False)

print(f"\nComparison saved to: {output_file}")
print("\nFlags indicate unusual patterns, not confirmed attacks.")
