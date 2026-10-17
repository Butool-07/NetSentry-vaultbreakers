
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from advanced_detection import (
    detect_port_scans,
    detect_network_sweeps,
    detect_lateral_movement,
)
from load_config import load_config


def main():
    input_file = PROJECT_ROOT / "data" / "advanced_traffic.csv"
    output_file = PROJECT_ROOT / "reports" / "incident_timeline.csv"

    traffic = pd.read_csv(input_file)

    traffic = traffic.rename(columns={
        "src_ip": "source_ip",
        "dst_ip": "destination_ip",
        "dst_port": "destination_port",
    })

    traffic["timestamp"] = pd.to_datetime(
        traffic["timestamp"], errors="coerce"
    )
    traffic = traffic.dropna(subset=["timestamp"])

    settings = load_config()
    thresholds = settings["detection_thresholds"]

    detections = [
        (
            detect_port_scans(
                traffic, thresholds["port_scan_unique_ports"]
            ),
            "port_scan",
            "The source contacted many unique destination ports.",
        ),
        (
            detect_network_sweeps(
                traffic, thresholds["network_sweep_unique_hosts"]
            ),
            "network_sweep",
            "The source contacted many unique destination hosts.",
        ),
        (
            detect_lateral_movement(
                traffic, thresholds["lateral_movement_unique_hosts"]
            ),
            "lateral_movement",
            "The source contacted many unique internal destination hosts.",
        ),
    ]

    incidents = []

    for alerts, rule_type, explanation in detections:
        for _, alert in alerts.iterrows():
            source_ip = alert["source_ip"]
            source_events = traffic[
                traffic["source_ip"] == source_ip
            ]

            incidents.append({
                "source_ip": source_ip,
                "rule": alert["rule"],
                "start_time": source_events["timestamp"].min(),
                "end_time": source_events["timestamp"].max(),
                "evidence": alert["evidence"],
                "risk_score": alert["risk_score"],
                "explanation": explanation,
            })

    columns = [
        "source_ip",
        "rule",
        "start_time",
        "end_time",
        "evidence",
        "risk_score",
        "explanation",
    ]

    report = pd.DataFrame(incidents, columns=columns)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    report.to_csv(output_file, index=False)

    print("Incident timeline report created.")
    print(f"Incidents: {len(report)}")
    print(f"Report saved to: {output_file}")
    print("These are simulated-traffic indicators, not confirmed attacks.")


if __name__ == "__main__":
    main()
