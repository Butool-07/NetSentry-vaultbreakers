
import pandas as pd


def detect_possible_exfiltration(df, byte_threshold=50000):
    """Flag large simulated outbound transfers for investigation."""

    required = {"source_ip", "destination_ip", "bytes"}

    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    traffic = df.copy()
    traffic["bytes"] = pd.to_numeric(
        traffic["bytes"], errors="coerce"
    )

    # Demonstration scope: outbound traffic to non-private IPv4 addresses.
    destination = traffic["destination_ip"].astype(str)

    is_external = ~destination.str.startswith(
        (
            "10.",
            "192.168.",
            "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
        )
    )

    alerts = traffic[
        is_external & (traffic["bytes"] >= byte_threshold)
    ].copy()

    alerts["rule"] = "Possible Large Outbound Transfer"
    alerts["evidence"] = (
        alerts["bytes"].astype("Int64").astype(str)
        + " bytes sent to an external destination"
    )
    alerts["risk_score"] = 50

    return alerts[
        [
            "source_ip",
            "destination_ip",
            "bytes",
            "rule",
            "evidence",
            "risk_score",
        ]
    ]


if __name__ == "__main__":
    sample = pd.DataFrame({
        "source_ip": [
            "192.168.1.50",
            "192.168.1.51",
            "192.168.1.52",
        ],
        "destination_ip": [
            "203.0.113.10",
            "203.0.113.11",
            "192.168.1.10",
        ],
        "bytes": [75000, 1200, 90000],
    })

    alerts = detect_possible_exfiltration(sample)

    print("Simulated records:", len(sample))
    print("Expected alerts: 1")
    print("Actual alerts:", len(alerts))

    if (
        len(alerts) == 1
        and alerts.iloc[0]["source_ip"] == "192.168.1.50"
    ):
        print("\nPASS: Large outbound-transfer test succeeded.")
        print(alerts.to_string(index=False))
        print(
            "\nLimitation: transfer size alone cannot establish "
            "data exfiltration."
        )
    else:
        print("\nFAIL: Unexpected detection result.")
        raise SystemExit(1)
