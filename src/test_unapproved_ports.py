

import pandas as pd

APPROVED_TCP_PORTS = {80, 443}


def detect_unapproved_ports(df):
    traffic = df.copy()
    traffic["destination_port"] = pd.to_numeric(
        traffic["destination_port"], errors="coerce"
    )
    traffic["protocol"] = traffic["protocol"].astype(str).str.lower()

    alerts = traffic[
        (traffic["protocol"] == "tcp")
        & (~traffic["destination_port"].isin(APPROVED_TCP_PORTS))
    ].copy()

    alerts["rule"] = "Unapproved TCP Destination Port"
    alerts["evidence"] = (
        "TCP destination port "
        + alerts["destination_port"].astype("Int64").astype(str)
        + " is not in the demo approved-port list"
    )
    alerts["risk_score"] = 40

    return alerts[
        ["source_ip", "destination_port", "rule", "evidence", "risk_score"]
    ]


if __name__ == "__main__":
    sample = pd.DataFrame({
        "source_ip": [
            "192.168.1.50",
            "192.168.1.50",
            "192.168.1.51",
        ],
        "destination_port": [443, 8080, 80],
        "protocol": ["tcp", "tcp", "tcp"],
    })

    alerts = detect_unapproved_ports(sample)

    print("Simulated records:", len(sample))
    print("Expected alerts: 1")
    print("Actual alerts:", len(alerts))

    if len(alerts) == 1 and alerts.iloc[0]["destination_port"] == 8080:
        print("\nPASS: Unapproved-port test succeeded.")
        print(alerts.to_string(index=False))
        print("\nThis is a demo policy indicator, not proof of an attack.")
    else:
        print("\nFAIL: Unexpected detection result.")
        raise SystemExit(1)
