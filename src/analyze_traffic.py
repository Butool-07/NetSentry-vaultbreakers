
import pandas as pd
from pathlib import Path

# Find the sample traffic dataset
project_folder = Path(__file__).resolve().parent.parent
csv_file = project_folder / "data" / "network_traffic.csv"

# Load the CSV file
df = pd.read_csv(csv_file)

print("====================================")
print("       NETSENTRY TRAFFIC ANALYSIS")
print("====================================")

print(f"\nTotal traffic records: {len(df)}")

print("\nFirst five records:")
print(df.head().to_string(index=False))

# Define simple screening thresholds for this demo
packet_limit = 100
byte_limit = 20000
connection_limit = 50

# Flag records exceeding any threshold
df["unusual"] = (
    (df["packets"] > packet_limit)
    | (df["bytes"] > byte_limit)
    | (df["connection_count"] > connection_limit)
)

print("\n====================================")
print("         SCREENING RESULTS")
print("====================================")

unusual_traffic = df[df["unusual"]]

print(f"\nRecords screened: {len(df)}")
print(f"Records flagged for review: {len(unusual_traffic)}")

if unusual_traffic.empty:
    print("\nNo records exceeded the demo thresholds.")
else:
    print("\nUnusual records requiring review:")
    print(
        unusual_traffic[
            ["timestamp", "source_ip", "packets", "bytes", "connection_count"]
        ].to_string(index=False)
    )

# Save results for later inspection
report_file = project_folder / "reports" / "traffic_analysis.csv"
df.to_csv(report_file, index=False)

print(f"\nFull results saved to: {report_file}")
print("\nNote: A flagged record is not proof of an attack.")
print("====================================")