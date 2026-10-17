
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from normalize_data import normalize_network_data
from advanced_detection import (
    detect_port_scans,
    detect_network_sweeps,
    detect_lateral_movement,
)
from load_config import load_config


def main():
    input_file = PROJECT_ROOT / "data" / "advanced_traffic.csv"
    output_file = PROJECT_ROOT / "reports" / "advanced_detection_report.csv"

    if not input_file.exists():
        print(f"ERROR: Input file not found: {input_file}")
        return

    # Use the same normalizer as the alternate dataset workflow.
    traffic = pd.read_csv(input_file)
    traffic = normalize_network_data(traffic)

    settings = load_config()
    thresholds = settings["detection_thresholds"]

    port_alerts = detect_port_scans(
        traffic, thresholds["port_scan_unique_ports"]
    )
    sweep_alerts = detect_network_sweeps(
        traffic, thresholds["network_sweep_unique_hosts"]
    )
    lateral_alerts = detect_lateral_movement(
        traffic, thresholds["lateral_movement_unique_hosts"]
    )

    columns = ["source_ip", "rule", "evidence", "risk_score"]
    report = pd.concat(
        [port_alerts, sweep_alerts, lateral_alerts],
        ignore_index=True,
    ).reindex(columns=columns)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    report.to_csv(output_file, index=False)

    print("Advanced detection analysis complete.")
    print(f"Traffic records analyzed: {len(traffic)}")
    print(f"Port scan alerts: {len(port_alerts)}")
    print(f"Network sweep alerts: {len(sweep_alerts)}")
    print(f"Lateral movement alerts: {len(lateral_alerts)}")
    print(f"Total indicators in report: {len(report)}")
    print(f"Report saved to: {output_file}")
    print("These are rule-based indicators, not confirmed attacks.")


if __name__ == "__main__":
    main()
