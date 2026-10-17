
import pandas as pd
from advanced_detection import (
    detect_port_scans,
    detect_network_sweeps,
    detect_lateral_movement,
)

# Simulated traffic from one source contacting many ports and hosts.
rows = []

for i in range(12):
    rows.append({
        "source_ip": "192.168.1.50",
        "destination_ip": f"192.168.1.{100 + i}",
        "destination_port": 1000 + i,
        "protocol": "TCP",
        "packets": 5,
        "bytes": 500,
        "duration_seconds": 0.2,
        "connection_count": 1,
        "timestamp": f"2026-10-16 10:{i:02d}:00",
    })

test_df = pd.DataFrame(rows)
# Test the same traffic using our approved scanner IP.
approved_df = test_df.copy()
approved_df["source_ip"] = "192.168.1.20"

approved_port_results = detect_port_scans(
    approved_df, threshold=10
)
approved_sweep_results = detect_network_sweeps(
    approved_df, threshold=10
)
approved_lateral_results = detect_lateral_movement(
    approved_df, threshold=5
)

print("\nApproved scanner test:")
print("Port scan alerts:", len(approved_port_results))
print("Network sweep alerts:", len(approved_sweep_results))
print("Lateral movement alerts:", len(approved_lateral_results))


from load_config import load_config

settings = load_config()
thresholds = settings["detection_thresholds"]

port_results = detect_port_scans(
    test_df,
    threshold=thresholds["port_scan_unique_ports"],
)

sweep_results = detect_network_sweeps(
    test_df,
    threshold=thresholds["network_sweep_unique_hosts"],
)

lateral_results = detect_lateral_movement(
    test_df,
    threshold=thresholds["lateral_movement_unique_hosts"],
)


print("Port scan rule triggered:", not port_results.empty)
print("Network sweep rule triggered:", not sweep_results.empty)
print("Lateral movement rule triggered:", not lateral_results.empty)

print("\nPort scan evidence:")
print(port_results.to_string(index=False))

print("\nNetwork sweep evidence:")
print(sweep_results.to_string(index=False))

print("\nLateral movement evidence:")
print(lateral_results.to_string(index=False))

# Mission 04: Verify that approved patch-server activity is suppressed.
patch_df = test_df.copy()
patch_df["source_ip"] = "192.168.1.30"

patch_port_results = detect_port_scans(
    patch_df, threshold=thresholds["port_scan_unique_ports"]
)
patch_sweep_results = detect_network_sweeps(
    patch_df, threshold=thresholds["network_sweep_unique_hosts"]
)
patch_lateral_results = detect_lateral_movement(
    patch_df, threshold=thresholds["lateral_movement_unique_hosts"]
)

patch_alert_count = (
    len(patch_port_results)
    + len(patch_sweep_results)
    + len(patch_lateral_results)
)

print("\nMission 04 patch-server test:")
print("Expected alerts: 0")
print("Actual alerts:", patch_alert_count)

if patch_alert_count == 0:
    print("PASS: Configured patch-server source was suppressed.")
else:
    print("FAIL: Patch-server source generated alerts.")
    raise SystemExit(1)

