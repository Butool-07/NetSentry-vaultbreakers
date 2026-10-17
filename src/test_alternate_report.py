
import pandas as pd
from pathlib import Path

report_path = Path("reports/alternate_csv_analysis.csv")

df = pd.read_csv(report_path)

expected_columns = [
    "source_ip",
    "rule",
    "evidence",
    "risk_score",
]

assert list(df.columns) == expected_columns, "Report columns are incorrect!"

print("PASS: Report exists and opens correctly.")
print("PASS: All required columns are present.")
print("Alert records:", len(df))
print("Alternate CSV report test completed successfully.")
