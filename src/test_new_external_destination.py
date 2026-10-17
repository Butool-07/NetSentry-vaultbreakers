
import pandas as pd


def detect_new_external_destinations(baseline, current):
    """Find external destinations absent from a source's baseline history."""

    required = {"source_ip", "destination_ip"}

    for name, df in [("baseline", baseline), ("current", current)]:
        missing = required - set(df.columns)
        if missing:
            raise ValueError(f"{name} is missing columns: {missing}")

    def is_external(ip):
        ip = str(ip)
        return not ip.startswith(
            (
                "10.",
                "192.168.",
                "172.16.", "172.17.", "172.18.", "172.19.",
                "172.20.", "172.21.", "172.22.", "172.23.",
                "172.24.", "172.25.", "172.26.", "172.27.",
                "172.28.", "172.29.", "172.30.", "172.31.",
            )
        )

    known = set(
        zip(baseline["source_ip"], baseline["destination_ip"])
    )

    alerts = []

    for _, row in current.iterrows():
        source = row["source_ip"]
        destination = row["destination_ip"]

        if is_external(destination) and (source, destination) not in known:
            alerts.append({
                "source_ip": source,
                "destination_ip": destination,
                "rule": "New External Destination",
                "evidence": (
                    "External destination not present in supplied "
                    "baseline history"
                ),
                "risk_score": 35,
            })

    return pd.DataFrame(
        alerts,
        columns=[
            "source_ip",
            "destination_ip",
            "rule",
            "evidence",
            "risk_score",
        ],
    )


if __name__ == "__main__":
    baseline = pd.DataFrame({
        "source_ip": [
            "192.168.1.50",
            "192.168.1.50",
        ],
        "destination_ip": [
            "203.0.113.10",
            "203.0.113.10",
        ],
    })

    current = pd.DataFrame({
        "source_ip": [
            "192.168.1.50",
            "192.168.1.50",
            "192.168.1.50",
        ],
        "destination_ip": [
            "203.0.113.10",
            "203.0.113.25",
            "192.168.1.10",
        ],
    })

    alerts = detect_new_external_destinations(baseline, current)

    print("Baseline records:", len(baseline))
    print("Current records:", len(current))
    print("Expected alerts: 1")
    print("Actual alerts:", len(alerts))

    if (
        len(alerts) == 1
        and alerts.iloc[0]["destination_ip"] == "203.0.113.25"
    ):
        print("\nPASS: New external destination test succeeded.")
        print(alerts.to_string(index=False))
        print(
            "\nLimitation: a new destination can be legitimate; "
            "this is an investigation indicator."
        )
    else:
        print("\nFAIL: Unexpected detection result.")
        raise SystemExit(1)
