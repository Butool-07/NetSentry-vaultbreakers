

import pandas as pd


def normalize_network_data(df):
    """Normalize supported network CSV columns and validate their values."""

    column_mapping = {
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
    }

    df = df.rename(columns=column_mapping).copy()

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
        raise ValueError(f"Dataset is missing required columns: {missing}")

    # Remove rows missing essential information.
    df = df.dropna(subset=[
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
    ]).copy()

    # Convert numeric columns; invalid values become NaN.
    numeric_columns = [
        "packets",
        "bytes",
        "duration_seconds",
        "connection_count",
    ]

    for column in numeric_columns:
        df[column] = pd.to_numeric(df[column], errors="coerce")

    # Remove rows with invalid or missing numeric values.
    df = df.dropna(subset=numeric_columns).copy()

    # Reject negative measurements and counts.
    for column in numeric_columns:
        df = df[df[column] >= 0]

    return df.reset_index(drop=True)


if __name__ == "__main__":
    print("NetSentry data normalizer is ready.")
