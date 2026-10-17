
import pandas as pd
from pathlib import Path

from normalize_data import normalize_network_data
from advanced_detection import (
    detect_port_scans,
    detect_network_sweeps,
    detect_lateral_movement,
)
from load_config import load_config

project_folder = Path(__file__).resolve().parent.parent
csv_file = project_folder / "data" / "alternate_traffic.csv"

# Step 1: Load the alternate CSV.
df = pd.read_csv(csv_file)

# Step 2: Normalize its column names.
df = normalize_network_data(df)

# Step 3: Load detection thresholds.
settings = load_config()
thresholds = settings["detection_thresholds"]

# Step 4: Run the three detection rules.
port_results = detect_port_scans(
    df,
    threshold=thresholds["port_scan_unique_ports"],
)
sweep_results = detect_network_sweeps(
    df,
    threshold=thresholds["network_sweep_unique_hosts"],
)
lateral_results = detect_lateral_movement(
    df,
    threshold=thresholds["lateral_movement_unique_hosts"],
)

# Step 5: Display the results.
print("Alternate CSV analysis complete.")
print("Records analyzed:", len(df))
print("Port scan alerts:", len(port_results))
print("Network sweep alerts:", len(sweep_results))
print("Lateral movement alerts:", len(lateral_results))

# Step 6: Save the combined report.

all_results = pd.concat(
    [port_results, sweep_results, lateral_results],
    ignore_index=True,
)

# Ensure the report has column headers even when there are no alerts.
report_columns = [
    "source_ip",
    "rule",
    "evidence",
    "risk_score",
]

all_results = all_results.reindex(columns=report_columns)


report_file = project_folder / "reports" / "alternate_csv_analysis.csv"
report_file.parent.mkdir(exist_ok=True)

all_results.to_csv(report_file, index=False)

print("Report saved to:", report_file)
print("This report contains rule-based indicators, not confirmed attacks.")
