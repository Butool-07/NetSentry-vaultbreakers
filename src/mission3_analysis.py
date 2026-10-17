
import sys
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
from load_config import load_config
from trusted_activity import is_trusted_activity
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
REPORT_DIR = PROJECT_ROOT / "reports"

DATA_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)


def create_demo_data():
    """Create clearly labelled simulated scenarios for Mission 03."""
    rows = []

    # Ordinary traffic: a small baseline for demonstration.
    for minute in range(10):
        rows.append({
            "timestamp": f"2026-10-16 10:{minute:02d}:00",
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.1",
            "packets": 12 + (minute % 3),
            "bytes": 1500 + (minute % 3) * 100,
            "scenario": "Normal simulated traffic",
        })

    # High-volume event.
    rows.append({
        "timestamp": "2026-10-16 10:10:00",
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.1",
        "packets": 500,
        "bytes": 75000,
        "scenario": "Suspicious simulated volume",
    })

    # Repeated connections to an external destination every 60 seconds.
    for minute in range(6):
        rows.append({
            "timestamp": f"2026-10-16 11:{minute:02d}:00",
            "source_ip": "192.168.1.60",
            "destination_ip": "203.0.113.25",
            "packets": 8,
            "bytes": 700,
            "scenario": "Simulated repeated external connections",
        })

    # Legitimate-looking scheduled backup scenario.
    for minute in range(3):
        rows.append({
            "timestamp": f"2026-10-16 02:{minute:02d}:00",
            "source_ip": "192.168.1.70",
            "destination_ip": "192.168.1.80",
            "packets": 300 + minute * 10,
            "bytes": 50000 + minute * 1000,
            "scenario": "Simulated scheduled backup",
        })

    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df.to_csv(DATA_DIR / "mission3_demo_traffic.csv", index=False)
    return df


def main():
    df = create_demo_data()

    # 1. Compare observed packet volume with a normal baseline.
    normal = df[df["scenario"] == "Normal simulated traffic"]
    baseline = normal["packets"].median()

    df["baseline_packets"] = baseline
    df["packet_deviation"] = df["packets"] - baseline

    settings = load_config()

    df["trusted_scheduled_activity"] = df.apply(
        lambda row: (
            row["scenario"] == "Simulated scheduled backup"
            and is_trusted_activity(
                row["source_ip"],
                "backup",
                row["timestamp"].isoformat(),
            )
        ),
        axis=1,
    )

    df["volume_indicator"] = (
        (df["packets"] > baseline * 5)
        & ~df["trusted_scheduled_activity"]
    )

    df.to_csv(REPORT_DIR / "mission3_deviations.csv", index=False)

    plt.figure(figsize=(10, 5))
    plt.plot(
        df.index, df["packets"], marker="o",
        label="Observed packets"
    )
    plt.axhline(
        baseline, linestyle="--",
        label=f"Normal demo baseline: {baseline:.0f}"
    )
    plt.xlabel("Record index")
    plt.ylabel("Packet count")
    plt.title("Mission 03: Traffic Volume vs Demo Baseline")
    plt.legend()
    plt.tight_layout()
    plt.savefig(REPORT_DIR / "mission3_deviation_chart.png")
    plt.close()

    # 2. Detect repeated external connections and calculate time gaps.
    external = df[
        ~df["destination_ip"].astype(str).str.startswith(
            ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
             "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
             "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
             "172.29.", "172.30.", "172.31.")
        )
    ].copy()

    external = external.sort_values("timestamp")
    external["gap_seconds"] = (
        external.groupby(["source_ip", "destination_ip"])["timestamp"]
        .diff().dt.total_seconds()
    )

    beaconing = external.groupby(
        ["source_ip", "destination_ip"]
    ).agg(
        connection_count=("timestamp", "count"),
        median_gap_seconds=("gap_seconds", "median"),
        gap_variation_seconds=("gap_seconds", "std"),
    ).reset_index()

    beaconing["possible_beaconing"] = (
        (beaconing["connection_count"] >= 4)
        & (beaconing["median_gap_seconds"] > 0)
        & (beaconing["gap_variation_seconds"].fillna(0) <= 5)
    )

    beaconing.to_csv(
        REPORT_DIR / "mission3_beaconing_report.csv", index=False
    )
    external.to_csv(
        REPORT_DIR / "mission3_connection_gaps.csv", index=False
    )

    plt.figure(figsize=(9, 4))
    plt.plot(
        external["timestamp"], external["gap_seconds"],
        marker="o"
    )
    plt.xlabel("Connection time")
    plt.ylabel("Gap from previous connection (seconds)")
    plt.title("Mission 03: Repeated External Connection Gaps")
    plt.xticks(rotation=30)
    plt.tight_layout()
    plt.savefig(REPORT_DIR / "mission3_beacon_gaps.png")
    plt.close()

    # 3. Group findings into a chronological incident timeline.
    incidents = []

    for _, row in df[df["volume_indicator"]].iterrows():
        incidents.append({
            "timestamp": row["timestamp"],
            "source_ip": row["source_ip"],
            "destination_ip": row["destination_ip"],
            "incident": "Unusual traffic volume",
            "possible_stage": "Unusual activity — stage unconfirmed",
            "evidence": (
                f"{row['packets']} packets versus "
                f"baseline {baseline:.0f}"
            ),
            "risk_score": 60,
        })

    for _, row in beaconing[beaconing["possible_beaconing"]].iterrows():
        incidents.append({
            "timestamp": external[
                external["source_ip"] == row["source_ip"]
            ]["timestamp"].min(),
            "source_ip": row["source_ip"],
            "destination_ip": row["destination_ip"],
            "incident": "Possible beaconing",
            "possible_stage": "Possible command-and-control pattern",
            "evidence": (
                f"{row['connection_count']} connections; "
                f"median gap {row['median_gap_seconds']:.0f} seconds"
            ),
            "risk_score": 65,
        })

    timeline = pd.DataFrame(incidents)
    if not timeline.empty:
        timeline = timeline.sort_values("timestamp")

    timeline.to_csv(
        REPORT_DIR / "mission3_incident_timeline.csv", index=False
    )

    # 4. Create a communication graph with labelled simulated traffic.
    edges = df.groupby(
        ["source_ip", "destination_ip"]
    ).size().reset_index(name="connections")

    plt.figure(figsize=(9, 6))
    nodes = sorted(
        set(edges["source_ip"]) | set(edges["destination_ip"])
    )
    positions = {
        node: (
            i % 4,
            -(i // 4)
        )
        for i, node in enumerate(nodes)
    }

    for _, edge in edges.iterrows():
        x1, y1 = positions[edge["source_ip"]]
        x2, y2 = positions[edge["destination_ip"]]
        plt.annotate(
            "",
            xy=(x2, y2),
            xytext=(x1, y1),
            arrowprops={"arrowstyle": "->", "alpha": 0.5},
        )

    for node, (x, y) in positions.items():
        plt.scatter(x, y, s=500)
        plt.text(x, y, node, ha="center", va="center", fontsize=8)

    plt.title("Mission 03: Simulated Network Communication Graph")
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(REPORT_DIR / "mission3_communication_graph.png")
    plt.close()

    # 5. Evaluate normal, high-volume, and scheduled-backup examples.
    summary = df.groupby("scenario").agg(
        records=("source_ip", "size"),
        maximum_packets=("packets", "max"),
        maximum_bytes=("bytes", "max"),
        volume_indicators=("volume_indicator", "sum"),
    ).reset_index()

    summary.to_csv(
        REPORT_DIR / "mission3_scenario_test_results.csv", index=False
    )

    print("Mission 03 analysis complete.")
    print("Simulated records:", len(df))
    print("Normal packet baseline:", baseline)
    print("Possible beaconing indicators:", int(
        beaconing["possible_beaconing"].sum()
    ))
    print("Incident timeline entries:", len(timeline))
    print("Scenario summary:")
    print(summary.to_string(index=False))
    print("Reports and charts saved in:", REPORT_DIR)
    print("All scenarios are simulated; indicators are not confirmed attacks.")


if __name__ == "__main__":
    main()
