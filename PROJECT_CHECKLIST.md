# NetSentry — Project Completion Checklist

## A. Core Features

* \[x] Basic network traffic analysis
* \[x] Rule-based threshold screening
* \[x] ML anomaly detection using Isolation Forest
* \[x] Rule-based vs ML detector comparison
* \[x] Possible port-scan detection
* \[x] Possible network-sweep detection
* \[x] Possible lateral-movement detection
* \[x] Alternate CSV normalization
* \[x] Basic data-quality validation
* \[x] Advanced detection CSV report
* \[x] Traffic visualization
* \[x] Streamlit dashboard
* \[x] Dashboard report downloads

## B. Tests Run

* \[x] Dataset normalization test
* \[x] Normal-traffic detection test
* \[x] Simulated suspicious-traffic test
* \[x] Alternate report structure test
* \[x] Data-quality test
* \[x] Approved-scanner configuration test
* \[x] ML anomaly detector run
* \[x] Detector comparison run
* \[x] Basic traffic analysis run
* \[x] Traffic graph generated
* \[x] Alternate CSV analysis run
* \[x] Dashboard refreshed successfully

## C. Documentation

* \[x] README.md created
* \[ ] Review README instructions and file names
* \[ ] Review this checklist before the presentation
* \[ ] Prepare a short project explanation
* \[ ] Capture final dashboard screenshots

## D. Before Demonstrating

* \[ ] Activate the Python virtual environment
* \[ ] Start the dashboard successfully
* \[ ] Confirm all dashboard sections load
* \[ ] Confirm report downloads work
* \[ ] Keep sample data available
* \[ ] Explain what each detection rule identifies
* \[ ] Explain that alerts are indicators, not confirmed attacks

## E. Future Improvements

* \[ ] Test against larger, labeled datasets
* \[ ] Measure precision, recall, and false-positive rate
* \[ ] Validate input data more thoroughly
* \[ ] Evaluate trusted-source exclusions carefully
* \[ ] Integrate authorized live network traffic
* \[ ] Improve production logging and monitoring

## Important Note

Completed items reflect work performed during development. Passing sample-data tests does not establish real-world detection accuracy.

NetSentry is an educational prototype, not a production-grade intrusion detection system.





\## Mission 04 — Network Traffic Anomaly and Behaviour Analysis: Validation



\### Validation summary

\- Total test cases documented: 18

\- PASS: 15

\- PARTIAL: 1

\- NOT TESTED: 2

\- Validation report: `reports/mission4\_validation\_report.csv`



\### Verified areas

\- Normal traffic baseline testing

\- Simulated port scan, network sweep, and lateral movement indicators

\- Approved scanner and configured patch-server suppression tests

\- Alternate CSV column normalization and simulated Zeek-style column mapping

\- Isolated tests for unapproved ports, large outbound transfers, and new external destinations

\- Advanced detection report structure and risk-score range checks

\- Dashboard HTML and CSV exports

\- Simulated beaconing and scheduled-activity helper tests



\### Remaining limitations

\- Some new detection checks are isolated tests and are not integrated into the main detector.

\- Raw Zeek TSV ingestion has not been tested.

\- False-positive and missed-detection evaluation is limited to simulated cases.

\- Alerts are indicators requiring investigation, not confirmation of malicious activity.

\- Risk scores are prototype indicators, not calibrated probabilities.



\### Mission 04 status

Validation evidence has been recorded. Further integration and testing are required before treating the prototype as a complete or production-ready network monitoring system.



