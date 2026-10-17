
# NetSentry
### Network Traffic Anomaly Detection and Threat Screening

## 1. Project Overview

NetSentry is a student-level cybersecurity prototype that analyzes network traffic records, identifies unusual patterns, and generates reports to support further investigation.

It combines rule-based detection with machine-learning anomaly detection and presents results through a Streamlit dashboard.

## 2. Key Features

- Network traffic analysis using predefined thresholds
- Machine-learning anomaly detection using Isolation Forest
- Comparison of rule-based and ML results
- Possible port-scan detection
- Possible network-sweep detection
- Possible lateral-movement detection
- Support for alternate CSV column formats
- Basic data-quality validation
- CSV reports and traffic visualization
- Interactive dashboard with report downloads

## 3. Technologies Used

- Python
- Pandas
- Scikit-learn
- Streamlit
- Matplotlib
- CSV data processing
- JSON configuration

## 4. Project Structure

```text
NetSentry/
├── config/
│   └── settings.json
├── data/
│   ├── network_traffic.csv
│   ├── advanced_traffic.csv
│   └── alternate_traffic.csv
├── reports/
│   ├── traffic_analysis.csv
│   ├── ml_anomaly_results.csv
│   ├── detector_comparison.csv
│   ├── advanced_detection_report.csv
│   ├── alternate_csv_analysis.csv
│   └── traffic_graph.png
├── src/
│   ├── analyze_traffic.py
│   ├── detect_anomalies.py
│   ├── compare_detectors.py
│   ├── advanced_detection.py
│   ├── analyze_advanced_traffic.py
│   └── normalize_data.py
├── dashboard.py
└── README.md
```

## 5. How to Run

Open PowerShell in the project folder.

Activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the main dependencies if they are not already installed:

```powershell
python -m pip install pandas scikit-learn streamlit matplotlib
```

Start the dashboard:

```powershell
python -m streamlit run dashboard.py
```

Open the local URL shown in the terminal.

## 6. Example Results

## 6. Example Results

### Controlled Detection Evaluation

NetSentry was tested against three constructed traffic scenarios: suspicious simulated traffic, normal traffic, and traffic from a configured approved scanner.

The evaluation covered nine rule/scenario combinations across port-scan detection, network-sweep detection, and lateral-movement detection.

| Metric | Result |
|---|---:|
| Test cases | 9 |
| True positives | 3 |
| True negatives | 6 |
| False positives | 0 |
| False negatives | 0 |
| Accuracy on these scenarios | 100% |
| False-positive rate on these scenarios | 0% |
| Recall on these scenarios | 100% |

The evaluation report is saved as `reports/detection_evaluation.csv`.

### Interpretation and Limitations

These results apply only to the small, deliberately constructed test scenarios. They do not establish real-world detection accuracy or prove that false positives have been reduced compared with an earlier baseline.

The approved-scanner scenario tests configured source-IP suppression. The results should not be interpreted as proof that all legitimate scanner traffic is harmless.

NetSentry still requires broader evaluation using labeled datasets, more diverse normal and suspicious traffic, and measurements of false positives and false negatives.



## 7. Limitations

- This is an educational prototype, not a production-grade intrusion detection system.
- The current tests use sample or simulated traffic.
- An anomaly or rule-based alert does not confirm an attack.
- Agreement between detection methods does not prove accuracy.
- Approved-source exclusions may hide suspicious activity if a trusted device is compromised.
- Real-world deployment requires broader validation, suitable data sources, monitoring, and security review.

## 8. Future Improvements

- Integration with authorized live network traffic sources
- Testing against labeled normal and attack datasets
- Better event logging and alert explanations
- Additional data-quality and input validation
- Improved dashboard filtering and reporting
- Evaluation using precision, recall, and false-positive rates

## 9. Responsible Use

Use NetSentry only with network data you are authorized to access and analyze.

**NetSentry flags patterns for review; it does not confirm attacks or guarantee network security.**



## Mission 03 — Advanced Anomaly Visualization

### Objective
Mission 03 extends NetSentry with visual traffic-deviation analysis,
possible beaconing detection, incident timelines, and communication graphs.
It is a student-level investigation-support prototype.

### Methods
1. **Traffic-volume deviation:** Compare packet counts with a reference
   baseline derived from labelled simulated normal traffic. Flag unusually
   high volume using a configurable-style demonstration threshold.
2. **Possible beaconing:** Group external connections by source and
   destination. Calculate the number of connections, median time gap,
   and variation in connection intervals.
3. **Incident timeline:** Arrange detected indicators chronologically and
   record source, destination, evidence, a possible activity-stage label,
   and a prototype risk score.
4. **Communication graph:** Visualize simulated source-to-destination
   relationships to help investigators identify communication paths.
5. **Scenario evaluation:** Compare normal traffic, repeated external
   connections, scheduled backups, and suspicious high-volume activity.

### Demonstration Results
- Normal simulated traffic: 0 volume indicators.
- Repeated external connections: 1 possible beaconing indicator.
- Scheduled backup: 0 volume indicators after the schedule check.
- Suspicious simulated high-volume event: 1 volume indicator.
- Incident timeline: 2 findings.

### Investigation Value
The visualizations help an analyst see deviations from a reference baseline,
inspect repeated connection timing, compare evidence, and review events in
chronological order. Communication graphs can help identify which simulated
hosts communicated during a scenario.

### Limitations
- The Mission 03 scenarios are simulated and do not establish real-world
  detection performance.
- The baseline is a simple reference derived from labelled normal demo data;
  it is not a fully trained per-computer behavioural model.
- Regular connection timing alone cannot confirm malicious beaconing.
- Scheduled-activity suppression depends on correct configuration and
  accurate timestamps. Legitimate activity may still be flagged, and
  malicious activity may resemble legitimate traffic.
- Risk scores are prototype values, not calibrated probabilities.
- Possible attack-stage labels are hypotheses for investigation, not
  confirmed attribution or proof of an attack.
- Real deployment requires representative datasets, further testing,
  validated thresholds, and analyst review.

### Safety and Interpretation
NetSentry produces suspicious-activity indicators to support investigation.
It does not independently confirm an attack. Analysts should review the
underlying evidence before taking action.

## Mission 04: Network Traffic Anomaly and Behaviour Analysis

Mission 04 validates NetSentry's prototype detection and reporting workflows using simulated network traffic and test datasets.

### Validation results

- **15 PASS** — test checks recorded as passing
- **1 PARTIAL** — limited false-positive and missed-detection analysis
- **2 NOT TESTED** — complete integration of all new rules and raw Zeek TSV ingestion

The validation report is available at `reports/mission4_validation_report.csv`.

### Tested capabilities

- Simulated port scan, network sweep, and lateral movement indicators
- Normal traffic and approved-activity checks
- Network-flow column normalization
- Prototype checks for unapproved ports, large outbound transfers, and new external destinations
- Beaconing indicators and scheduled-activity helper tests
- Detection report validation and dashboard HTML/CSV exports

### Limitations

Some detection checks remain isolated tests rather than integrated features. Tests use limited or simulated data and do not establish real-world detection accuracy. A large outbound transfer, an unfamiliar destination, or an unusual connection pattern is not proof of an attack. Risk scores are prototype indicators, not calibrated probabilities.

**Disclaimer:** NetSentry is an educational prototype. Its alerts support investigation and do not independently confirm malicious activity.

