
import pandas as pd
from pathlib import Path

project_folder = Path(__file__).resolve().parent.parent
data_folder = project_folder / "data"
data_folder.mkdir(exist_ok=True)

# This dataset deliberately uses alternate column names.
rows = [
    {
        "time": "2026-10-16 13:00:00",
        "src_ip": "192.168.1.70",
        "dst_ip": "192.168.1.10",
        "protocol_type": "TCP",
        "packet_count": 15,
        "byte_count": 1200,
        "flow_duration": 3,
        "connections": 1,
    },
    {
        "time": "2026-10-16 13:01:00",
        "src_ip": "192.168.1.70",
        "dst_ip": "192.168.1.11",
        "protocol_type": "TCP",
        "packet_count": 18,
        "byte_count": 1500,
        "flow_duration": 4,
        "connections": 1,
    },
    {
        "time": "2026-10-16 13:02:00",
        "src_ip": "192.168.1.70",
        "dst_ip": "192.168.1.12",
        "protocol_type": "UDP",
        "packet_count": 10,
        "byte_count": 800,
        "flow_duration": 2,
        "connections": 1,
    },
]

df = pd.DataFrame(rows)

output_file = data_folder / "alternate_traffic.csv"
df.to_csv(output_file, index=False)

print(f"Created alternate dataset: {output_file}")
print("Original columns:", list(df.columns))
print(f"Records created: {len(df)}")
