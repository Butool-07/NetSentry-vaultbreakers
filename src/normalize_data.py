


import pandas as pd


def normalize_network_data(df):
    """Normalize supported network CSV formats and validate their values."""

    column_mapping = {
        # Existing alternate CSV format
        "src_ip": "source_ip",
        "dst_ip": "destination_ip",
        "src_port": "source_port",
        "dst_port": "destination_port",
        "protocol_type": "protocol",
        "packet_count": "packets",
        "byte_count": "bytes",
        "flow_duration": "duration_seconds",
        "connections": "connection_count",
        "time": "timestamp",

        # Zeek conn.log-style fields
        "ts": "timestamp",
        "id.orig_h": "source_ip",
        "id.resp_h": "destination_ip",
        "id.orig_p": "source_port",
        "id.resp_p": "destination_port",
        "proto": "protocol",
        "orig_pkts": "packets",
        "orig_bytes": "bytes",
        "duration": "duration_seconds",
    }

    df = df.rename(columns=column_mapping).copy()

    # Zeek records normally describe individual connections.
    if "connection_count" not in df.columns:
        df["connection_count"] = 1

    required_columns = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "packets",
        "bytes",
        "duration_seconds",
        "connection_count",
    ]

    missing = [col for col in required_columns if col not in df.columns]

    if missing:
        raise ValueError(
            f"Dataset is missing required columns: {missing}"
        )

    # Remove rows missing essential information.
    df = df.dropna(
        subset=[
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol",
        ]
    ).copy()

    # Convert timestamps and numeric columns.
    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce"
    )

    numeric_columns = [
        "packets",
        "bytes",
        "duration_seconds",
        "connection_count",
    ]

    for column in numeric_columns:
        df[column] = pd.to_numeric(df[column], errors="coerce")

    # Remove invalid or missing values.
    df = df.dropna(
        subset=["timestamp"] + numeric_columns
    ).copy()

    # Reject negative measurements and counts.
    for column in numeric_columns:
        df = df[df[column] >= 0]

    # Keep destination ports numeric when present.
    if "destination_port" in df.columns:
        df["destination_port"] = pd.to_numeric(
            df["destination_port"], errors="coerce"
        )

    return df.reset_index(drop=True)


if __name__ == "__main__":
    print("NetSentry data normalizer is ready.")
