
from pathlib import Path

import pandas as pd


report_path = (
    Path(__file__).resolve().parent.parent
    / "reports"
    / "advanced_detection_report.csv"
)

if not report_path.exists():
    raise SystemExit(f"FAIL: Report not found: {report_path}")

report = pd.read_csv(report_path)

required_columns = [
    "source_ip",
    "rule",
    "evidence",
    "risk_score",
]

missing = [
    column for column in required_columns
    if column not in report.columns
]

if missing:
    raise SystemExit(f"FAIL: Missing columns: {missing}")

expected_rules = {
    "Possible Port Scan",
    "Possible Network Sweep",
    "Possible Lateral Movement",
}

actual_rules = set(report["rule"].dropna())

if actual_rules != expected_rules:
    raise SystemExit(
        f"FAIL: Unexpected rule set: {sorted(actual_rules)}"
    )

if report.empty:
    raise SystemExit("FAIL: Report has no indicators.")

if report["evidence"].isna().any() or (
    report["evidence"].astype(str).str.strip() == ""
).any():
    raise SystemExit("FAIL: Missing evidence text.")

scores = pd.to_numeric(report["risk_score"], errors="coerce")

if scores.isna().any() or not scores.between(0, 100).all():
    raise SystemExit("FAIL: Risk scores must be numeric and 0-100.")

print("PASS: Report file exists and can be read.")
print("PASS: Required columns are present.")
print("PASS: All three expected detection rules are present.")
print("PASS: Evidence descriptions are populated.")
print("PASS: Risk scores are numeric and between 0 and 100.")
print("Indicators validated:", len(report))
