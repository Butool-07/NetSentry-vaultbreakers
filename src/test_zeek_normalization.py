
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from normalize_data import normalize_network_data


# Simulated Zeek conn.log-style records.
zeek_data = pd.DataFrame({
    "ts": [
        "2026-10-16T10:00:00",
        "2026-10-16T10:01:00",
    ],
    "id.orig_h": [
        "192.168.1.50",
        "192.168.1.50",
    ],
    "id.resp_h": [
        "203.0.113.10",
        "203.0.113.11",
    ],
    "id.orig_p": [51500, 51501],
    "id.resp_p": [443, 8080],
    "proto": ["tcp", "tcp"],
    "orig_pkts": [12, 18],
    "orig_bytes": [1400, 2200],
    "duration": [2.5, 4.0],
})

normalized = normalize_network_data(zeek_data)

required_columns = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "packets",
    "bytes",
    "duration_seconds",
    "connection_count",
    "destination_port",
]

missing = [
    column for column in required_columns
    if column not in normalized.columns
]

print("Input format: simulated Zeek-style columns")
print("Records supplied:", len(zeek_data))
print("Records normalized:", len(normalized))
print("Normalized columns:", normalized.columns.tolist())

if missing:
    print("FAIL: Missing expected columns:", missing)
    raise SystemExit(1)

if len(normalized) != 2:
    print("FAIL: Expected 2 normalized records.")
    raise SystemExit(1)

if normalized["destination_port"].tolist() != [443, 8080]:
    print("FAIL: Destination ports were not preserved.")
    raise SystemExit(1)

if normalized["connection_count"].tolist() != [1, 1]:
    print("FAIL: Default connection counts are incorrect.")
    raise SystemExit(1)

print("\nPASS: Zeek-style column normalization succeeded.")
print(normalized[required_columns].to_string(index=False))
