
import pandas as pd
from pathlib import Path

project_folder = Path(__file__).resolve().parent.parent
data_folder = project_folder / "data"
data_folder.mkdir(exist_ok=True)

rows = []

# Simulated traffic from an unknown source.
for i in range(12):
    rows.append({
        "timestamp": f"2026-10-16 10:{i:02d}:00",
        "source_ip": "192.168.1.50",
        "destination_ip": f"192.168.1.{100 + i}",
        "destination_port": 8000 + i,
        "protocol": "TCP",
        "packets": 20,
        "bytes": 1500,
        "duration_seconds": 5,
        "connection_count": 1,
    })

# Simulated traffic from the configured approved scanner.
for i in range(12):
    rows.append({
        "timestamp": f"2026-10-16 11:{i:02d}:00",
        "source_ip": "192.168.1.20",
        "destination_ip": f"192.168.2.{100 + i}",
        "destination_port": 9000 + i,
        "protocol": "TCP",
        "packets": 20,
        "bytes": 1500,
        "duration_seconds": 5,
        "connection_count": 1,
    })

df = pd.DataFrame(rows)

output_file = data_folder / "advanced_traffic.csv"
df.to_csv(output_file, index=False)

print(f"Created test dataset: {output_file}")
print(f"Total simulated records: {len(df)}")
print("This dataset contains fictional traffic for testing only.")
