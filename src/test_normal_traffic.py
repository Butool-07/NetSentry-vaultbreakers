
import pandas as pd

from advanced_detection import (
    detect_port_scans,
    detect_network_sweeps,
    detect_lateral_movement,
)

# Simulate ordinary traffic to a small number of destinations.
normal_rows = []

for i in range(6):
    normal_rows.append({
        "timestamp": f"2026-10-16 12:0{i}:00",
        "source_ip": "192.168.1.60",
        "destination_ip": "192.168.1.10",
        "destination_port": 443,
        "protocol": "TCP",
        "packets": 15,
        "bytes": 1200,
        "duration_seconds": 3,
        "connection_count": 1,
    })

normal_df = pd.DataFrame(normal_rows)

port_results = detect_port_scans(normal_df, threshold=10)
sweep_results = detect_network_sweeps(normal_df, threshold=10)
lateral_results = detect_lateral_movement(normal_df, threshold=5)

print("Normal traffic test:")
print("Port scan alerts:", len(port_results))
print("Network sweep alerts:", len(sweep_results))
print("Lateral movement alerts:", len(lateral_results))

total_alerts = (
    len(port_results)
    + len(sweep_results)
    + len(lateral_results)
)

print("Total rule alerts:", total_alerts)
print("Expected result for this sample: 0 alerts")
