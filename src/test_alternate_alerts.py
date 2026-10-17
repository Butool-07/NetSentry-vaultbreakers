
import pandas as pd
from advanced_detection import (
    detect_port_scans,
    detect_network_sweeps,
    detect_lateral_movement,
)
from load_config import load_config

settings = load_config()
thresholds = settings["detection_thresholds"]

# Create simulated traffic with many ports and internal hosts.
rows = []

for i in range(12):
    rows.append({
        "source_ip": "192.168.1.80",
        "destination_ip": f"192.168.1.{100 + i}",
        "destination_port": 8000 + i,
    })

traffic = pd.DataFrame(rows)

port_alerts = detect_port_scans(
    traffic, thresholds["port_scan_unique_ports"]
)
sweep_alerts = detect_network_sweeps(
    traffic, thresholds["network_sweep_unique_hosts"]
)
lateral_alerts = detect_lateral_movement(
    traffic, thresholds["lateral_movement_unique_hosts"]
)

print("Simulated records:", len(traffic))
print("Port scan alerts:", len(port_alerts))
print("Network sweep alerts:", len(sweep_alerts))
print("Lateral movement alerts:", len(lateral_alerts))

assert len(port_alerts) > 0, "Port scan was not detected!"
assert len(sweep_alerts) > 0, "Network sweep was not detected!"
assert len(lateral_alerts) > 0, "Lateral movement was not detected!"

print("\nPASS: All three detection rules triggered.")
print("These are simulated indicators, not confirmed attacks.")
