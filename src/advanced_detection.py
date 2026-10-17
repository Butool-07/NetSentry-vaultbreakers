
import pandas as pd
from trusted_activity import is_trusted_activity

def detect_port_scans(df, threshold=10):
    """Flag a source contacting many different destination ports."""
    required = {"source_ip", "destination_port"}

    if not required.issubset(df.columns):
        return pd.DataFrame()

    results = []

    for source_ip, group in df.groupby("source_ip"):
        unique_ports = group["destination_port"].nunique()

        if (
    unique_ports >= threshold
    and not is_trusted_activity(source_ip, "port_scan")
):
            results.append({
                "source_ip": source_ip,
                "rule": "Possible Port Scan",
                "evidence": f"{unique_ports} unique destination ports",
                "risk_score": min(100, 40 + unique_ports),
            })

    return pd.DataFrame(results)


def detect_network_sweeps(df, threshold=10):
    """Flag a source contacting many different destination IPs."""
    required = {"source_ip", "destination_ip"}

    if not required.issubset(df.columns):
        return pd.DataFrame()

    results = []

    for source_ip, group in df.groupby("source_ip"):
        unique_hosts = group["destination_ip"].nunique()

        if (
    unique_hosts >= threshold
    and not is_trusted_activity(source_ip, "network_sweep")
):
            results.append({
                "source_ip": source_ip,
                "rule": "Possible Network Sweep",
                "evidence": f"{unique_hosts} unique destination hosts",
                "risk_score": min(100, 40 + unique_hosts),
            })

    return pd.DataFrame(results)


def detect_lateral_movement(df, threshold=5):
    """Flag a source contacting many internal destination hosts."""
    required = {"source_ip", "destination_ip"}

    if not required.issubset(df.columns):
        return pd.DataFrame()

    results = []

    for source_ip, group in df.groupby("source_ip"):
        # Only count destinations within the private IPv4 ranges.
        private_hosts = group["destination_ip"].astype(str).str.startswith(
            ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
             "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
             "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
             "172.29.", "172.30.", "172.31.")
        )

        unique_internal_hosts = group.loc[
            private_hosts, "destination_ip"
        ].nunique()

        if (
    unique_internal_hosts >= threshold
    and not is_trusted_activity(source_ip, "lateral_movement")
):
            results.append({
                "source_ip": source_ip,
                "rule": "Possible Lateral Movement",
                "evidence": (
                    f"{unique_internal_hosts} unique internal destination hosts"
                ),
                "risk_score": min(100, 50 + unique_internal_hosts),
            })

    return pd.DataFrame(results)


if __name__ == "__main__":
    print("Advanced detection rules loaded successfully.")
    print("Rules: port scans, network sweeps, and lateral movement.")
