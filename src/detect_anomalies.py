
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Locate the project folder
project_folder = Path(__file__).resolve().parent.parent
csv_file = project_folder / "data" / "network_traffic.csv"

# Load sample traffic
df = pd.read_csv(csv_file)

# Select numeric traffic measurements
features = [
    "packets",
    "bytes",
    "duration_seconds",
    "connection_count",
]

X = df[features].copy()

# Scale the features so their different units
# do not dominate the distance calculations
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train an unsupervised anomaly detector
model = IsolationForest(
    n_estimators=100,
    contamination=0.2,
    random_state=42,
)

model.fit(X_scaled)

# Isolation Forest returns 1 for typical records
# and -1 for records it considers unusual
df["ml_result"] = model.predict(X_scaled)
df["ml_anomaly"] = df["ml_result"] == -1

print("====================================")
print(" NETSENTRY MACHINE-LEARNING SCREEN")
print("====================================")
print(f"Records analyzed: {len(df)}")
print(f"Records flagged by model: {df['ml_anomaly'].sum()}")

print("\nModel results:")
print(
    df[
        [
            "timestamp",
            "source_ip",
            "packets",
            "bytes",
            "connection_count",
            "ml_anomaly",
        ]
    ].to_string(index=False)
)

# Save the results
report_file = project_folder / "reports" / "ml_anomaly_results.csv"
df.to_csv(report_file, index=False)

print(f"\nResults saved to: {report_file}")
print("\nImportant: These are experimental anomaly flags,")
print("not confirmed attacks or a measure of network security.")
