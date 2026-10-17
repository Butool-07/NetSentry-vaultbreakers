
import pandas as pd
from normalize_data import normalize_network_data

sample = pd.DataFrame([
    {
        "timestamp": "2026-10-16 10:00:00",
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "packets": 15,
        "bytes": 1200,
        "duration_seconds": 3,
        "connection_count": 1,
    },
    {
        "timestamp": "2026-10-16 10:01:00",
        "source_ip": None,
        "destination_ip": "192.168.1.11",
        "protocol": "TCP",
        "packets": "invalid",
        "bytes": 1500,
        "duration_seconds": 4,
        "connection_count": 1,
    },
])

print("Original records:", len(sample))

try:
    cleaned = normalize_network_data(sample)
    print("Normalization completed.")
    print("Records returned:", len(cleaned))
    print(cleaned)
except Exception as error:
    print("Data-quality issue found:", error)
