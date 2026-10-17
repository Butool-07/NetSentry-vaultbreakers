
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


def make_traffic(source_ip, count, suspicious):
    """Build a controlled test scenario."""
    records = []

    for i in range(count):
        records.append({
            "timestamp": f"2026-10-16 10:{i:02d}:00",
            "source_ip": source_ip,
            "destination_ip": (
                f"192.168.1.{100 + i}" if suspicious
                else "192.168.1.100"
            ),
            "destination_port": 8000 + i if suspicious else 443,
            "protocol": "TCP",
            "packets": 20,
            "bytes": 1500,
            "duration_seconds": 5,
            "connection_count": 1,
        })

    return pd.DataFrame(records)


def main():
    settings = load_config()
    thresholds = settings["detection_thresholds"]

    scenarios = [
        (
            "Suspicious simulated traffic",
            make_traffic("192.168.1.50", 12, True),
            True,
        ),
        (
            "Normal traffic",
            make_traffic("192.168.1.60", 6, False),
            False,
        ),
        (
            "Approved scanner",
            make_traffic("192.168.1.20", 12, True),
            False,
        ),
    ]

    rules = [
        (
            "Possible Port Scan",
            detect_port_scans,
            thresholds["port_scan_unique_ports"],
        ),
        (
            "Possible Network Sweep",
            detect_network_sweeps,
            thresholds["network_sweep_unique_hosts"],
        ),
        (
            "Possible Lateral Movement",
            detect_lateral_movement,
            thresholds["lateral_movement_unique_hosts"],
        ),
    ]

    results = []

    for scenario_name, traffic, expected_alert in scenarios:
        for rule_name, detector, threshold in rules:
            alerts = detector(traffic, threshold=threshold)

            actual_alert = (
                not alerts.empty
                and rule_name in alerts["rule"].values
            )

            if expected_alert and actual_alert:
                outcome = "True Positive"
            elif expected_alert and not actual_alert:
                outcome = "False Negative"
            elif not expected_alert and actual_alert:
                outcome = "False Positive"
            else:
                outcome = "True Negative"

            results.append({
                "scenario": scenario_name,
                "rule": rule_name,
                "expected_alert": expected_alert,
                "actual_alert": actual_alert,
                "outcome": outcome,
            })

    report = pd.DataFrame(results)
    output_file = PROJECT_ROOT / "reports" / "detection_evaluation.csv"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    report.to_csv(output_file, index=False)

    tp = (report["outcome"] == "True Positive").sum()
    tn = (report["outcome"] == "True Negative").sum()
    fp = (report["outcome"] == "False Positive").sum()
    fn = (report["outcome"] == "False Negative").sum()

    total = len(report)
    accuracy = (tp + tn) / total if total else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0

    print("NetSentry controlled-scenario evaluation")
    print("----------------------------------------")
    print(f"Test cases: {total}")
    print(f"True positives: {tp}")
    print(f"True negatives: {tn}")
    print(f"False positives: {fp}")
    print(f"False negatives: {fn}")
    print(f"Accuracy on these scenarios: {accuracy:.1%}")
    print(f"False-positive rate on these scenarios: {fpr:.1%}")
    print(f"Recall on these scenarios: {recall:.1%}")
    print(f"Report saved to: {output_file}")
    print(
        "LIMITATION: These are small, constructed scenarios, "
        "not a measure of real-world detection accuracy."
    )


if __name__ == "__main__":
    main()
