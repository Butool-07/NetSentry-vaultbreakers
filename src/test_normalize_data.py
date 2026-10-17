
import pandas as pd
from normalize_data import normalize_network_data

# Dataset 1: Your existing NetSentry column names
dataset_one = pd.DataFrame([{
    "timestamp": "2026-10-16 10:00:00",
    "source_ip": "192.168.1.10",
    "destination_ip": "192.168.1.1",
    "protocol": "TCP",
    "packets": 12,
    "bytes": 1500,
    "duration_seconds": 2.1,
    "connection_count": 3,
}])

# Dataset 2: Different column names
dataset_two = pd.DataFrame([{
    "time": "2026-10-16 10:00:00",
    "src_ip": "192.168.1.10",
    "dst_ip": "192.168.1.1",
    "protocol_type": "TCP",
    "packet_count": 12,
    "byte_count": 1500,
    "flow_duration": 2.1,
    "connections": 3,
}])

# Normalize both datasets
normalized_one = normalize_network_data(dataset_one)
normalized_two = normalize_network_data(dataset_two)

# Check that the column names match
assert list(normalized_one.columns) == list(normalized_two.columns)

print("Dataset 1 normalized successfully.")
print("Dataset 2 normalized successfully.")
print("Both datasets now use the same column names.")
print(normalized_two.columns.tolist())
