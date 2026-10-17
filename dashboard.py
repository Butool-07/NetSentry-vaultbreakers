
import streamlit as st
import pandas as pd
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from advanced_detection import (
    detect_port_scans,
    detect_network_sweeps,
    detect_lateral_movement,
)
from load_config import load_config
from pathlib import Path

# Find the project folder
PROJECT_FOLDER = Path(__file__).resolve().parent
REPORT_FILE = PROJECT_FOLDER / "reports" / "traffic_analysis.csv"
ML_FILE = PROJECT_FOLDER / "reports" / "ml_anomaly_results.csv"

st.set_page_config(
    page_title="NetSentry",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ NetSentry")
st.subheader("Network Traffic Anomaly and Behaviour Analysis")

st.header("About This Project")

st.write(
    "NetSentry analyzes network traffic records to identify unusual "
    "patterns that may need investigation."
)

st.write(
    "It uses two methods: rule-based detection and machine-learning "
    "anomaly detection. It compares their results and displays the "
    "findings in an interactive dashboard."
)

st.write(
    "This is an educational prototype using fictional sample data. "
    "It does not monitor a live network or confirm cyberattacks."
)


st.info(
    "Educational prototype using fictional sample traffic. "
    "An anomaly flag is not proof of a cyberattack."
)

if not REPORT_FILE.exists():
    st.error("Traffic report not found. Run the analysis program first.")
    st.stop()

df = pd.read_csv(REPORT_FILE)

st.header("Traffic by Source IP")

ip_summary = (
    df.groupby("source_ip")
    .agg(
        total_packets=("packets", "sum"),
        total_bytes=("bytes", "sum"),
        records=("source_ip", "count"),
        flagged_records=("unusual", "sum"),
    )
    .reset_index()
)

st.dataframe(ip_summary, use_container_width=True)


st.subheader("Busiest Source")

busiest_row = ip_summary.loc[ip_summary["total_packets"].idxmax()]

st.metric(
    "Source IP with Most Packets",
    busiest_row["source_ip"],
    help="The source with the highest total packet count in this sample.",
)

st.metric(
    "Total Packets from This Source",
    int(busiest_row["total_packets"]),
)

st.header("Traffic Protocol Distribution")

if "protocol" in df.columns:
    protocol_counts = df["protocol"].value_counts()
    st.bar_chart(protocol_counts)
else:
    st.warning("Protocol information is missing from the traffic data.")


# Summary metrics
total_records = len(df)
flagged_records = int(df["unusual"].sum())
normal_records = total_records - flagged_records

col1, col2, col3 = st.columns(3)

col1.metric("Total Records", total_records)
col2.metric("Flagged for Review", flagged_records)
col3.metric("Not Flagged", normal_records)

st.divider()

st.header("Traffic Records")

show_flagged_only = st.checkbox("Show only records flagged for review")

if show_flagged_only:
    displayed_df = df[df["unusual"]]
else:
    displayed_df = df

st.dataframe(displayed_df, use_container_width=True)

st.header("Packet Count by Record")

chart_df = df[["source_ip", "packets", "unusual"]].copy()
chart_df["Record"] = range(1, len(chart_df) + 1)

st.bar_chart(
    chart_df,
    x="Record",
    y="packets",
)

st.caption(
    "The chart shows packet counts. Use the table above to identify "
    "records flagged by the demo threshold rules."
)

st.header("Machine-Learning Results")

if ML_FILE.exists():
    ml_df = pd.read_csv(ML_FILE)
    ml_flagged = int(ml_df["ml_anomaly"].sum())

    st.metric("Records Flagged by Isolation Forest", ml_flagged)

    st.dataframe(
        ml_df[
            ["timestamp", "source_ip", "packets", "bytes", "connection_count", "ml_anomaly"]
        ],
        use_container_width=True,
    )
else:
    st.warning("Machine-learning report not found. Run detect_anomalies.py.")

st.divider()
st.caption(
    "NetSentry Mission 74 | Student prototype | "
    "Flags are for further investigation, not confirmed attacks."
)
st.header("Download Report")

report_csv = df.to_csv(index=False).encode("utf-8")

st.download_button(
    label="Download Traffic Analysis CSV",
    data=report_csv,
    file_name="netsentry_traffic_report.csv",
    mime="text/csv",
)

st.header("Detector Comparison")

COMPARISON_FILE = PROJECT_FOLDER / "reports" / "detector_comparison.csv"

if COMPARISON_FILE.exists():
    comparison_df = pd.read_csv(COMPARISON_FILE)

    both_flagged = int(comparison_df["both_flagged"].sum())
    disagreements = int(comparison_df["disagreement"].sum())

    col1, col2 = st.columns(2)
    col1.metric("Flagged by Both Methods", both_flagged)
    col2.metric("Disagreements", disagreements)

    st.dataframe(comparison_df, use_container_width=True)
    st.subheader("Filter Records Flagged by Both Methods")
    both_only = st.checkbox("Show only records flagged by both methods")

    if both_only:
        st.dataframe(
            comparison_df[comparison_df["both_flagged"]],
            use_container_width=True,
        )
    else:
        st.caption("Turn on the checkbox to view only jointly flagged records.")

else:
    st.warning("Comparison report not found. Run compare_detectors.py first.")

st.header("Security Summary")

if COMPARISON_FILE.exists():
    if both_flagged > 0:
        st.warning(
            f"Both methods flagged {both_flagged} record(s). "
            "These records need further investigation."
        )
    else:
        st.success("Neither method jointly flagged any records.")

    if disagreements > 0:
        st.info(
            f"The methods disagreed on {disagreements} record(s). "
            "Review these records manually."
        )
    else:
        st.info("Both methods gave matching results for this sample.")

    st.caption(
        "Educational demo using fictional traffic. "
        "Flags indicate unusual patterns, not confirmed cyberattacks."
    )

st.header("Download Comparison Report")

if COMPARISON_FILE.exists():
    comparison_csv = comparison_df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="Download Detector Comparison CSV",
        data=comparison_csv,
        file_name="netsentry_detector_comparison.csv",
        mime="text/csv",
    )

st.header("Download Filtered Traffic Records")

filtered_csv = displayed_df.to_csv(index=False).encode("utf-8")

st.download_button(
    label="Download Displayed Traffic Records",
    data=filtered_csv,
    file_name="netsentry_displayed_traffic.csv",
    mime="text/csv",
)

st.header("Advanced Threat Detection")

st.caption(
    "These rules identify suspicious traffic patterns for investigation. "
    "They do not confirm that an attack occurred."
)

ADVANCED_FILE = Path(__file__).resolve().parent / "data" / "advanced_traffic.csv"

if ADVANCED_FILE.exists():
    try:
        advanced_df = pd.read_csv(ADVANCED_FILE)
        advanced_df = advanced_df.rename(
            columns={
                "src_ip": "source_ip",
                "dst_ip": "destination_ip",
                "dst_port": "destination_port",
            }
        )

        settings = load_config()
        thresholds = settings["detection_thresholds"]

        port_results = detect_port_scans(
            advanced_df,
            threshold=thresholds["port_scan_unique_ports"],
        )
        sweep_results = detect_network_sweeps(
            advanced_df,
            threshold=thresholds["network_sweep_unique_hosts"],
        )
        lateral_results = detect_lateral_movement(
            advanced_df,
            threshold=thresholds["lateral_movement_unique_hosts"],
        )

        st.subheader("Possible Port Scans")
        if port_results.empty:
            st.success("No port-scan patterns detected.")
        else:
            st.dataframe(port_results, use_container_width=True)

        st.subheader("Possible Network Sweeps")
        if sweep_results.empty:
            st.success("No network-sweep patterns detected.")
        else:
            st.dataframe(sweep_results, use_container_width=True)

        st.subheader("Possible Lateral Movement")
        if lateral_results.empty:
            st.success("No lateral-movement patterns detected.")
        else:
            st.dataframe(lateral_results, use_container_width=True)

        all_results = pd.concat(
            [port_results, sweep_results, lateral_results],
            ignore_index=True,
        )
        st.subheader("Advanced Detection Summary")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Port Scan Alerts", len(port_results))
        col2.metric("Network Sweep Alerts", len(sweep_results))
        col3.metric("Lateral Movement Alerts", len(lateral_results))
        col4.metric("Total Rule Alerts", len(all_results))
        
        if not all_results.empty:
            def classify_severity(score):
                if score >= 70:
                    return "High"
                elif score >= 50:
                    return "Medium"
                return "Low"

            all_results["severity"] = all_results["risk_score"].apply(
                classify_severity
            )

            st.subheader("Alert Severity Breakdown")

            severity_counts = (
                all_results["severity"]
                .value_counts()
                .reindex(["High", "Medium", "Low"], fill_value=0)
            )

            severity_col1, severity_col2, severity_col3 = st.columns(3)

            severity_col1.metric("High", int(severity_counts["High"]))
            severity_col2.metric("Medium", int(severity_counts["Medium"]))
            severity_col3.metric("Low", int(severity_counts["Low"]))

            st.dataframe(
                all_results,
                use_container_width=True,
                hide_index=True,
            )
            
        st.subheader("Why Were These Alerts Triggered?")

        if all_results.empty:
            st.info("No advanced detection alerts to explain.")
        else:
            for _, alert in all_results.iterrows():
                st.markdown(
                    f"**{alert['rule']} — {alert['source_ip']}**"
                )
                st.write(f"Evidence: {alert['evidence']}")
                st.write(f"Risk score: {alert['risk_score']}/100")
                st.write(f"Prototype severity: {alert['severity']}")

                if alert["rule"] == "Possible Port Scan":
                    st.caption(
                        "Reason: this source contacted many unique destination ports."
                    )
                elif alert["rule"] == "Possible Network Sweep":
                    st.caption(
                        "Reason: this source contacted many unique destination hosts."
                    )
                elif alert["rule"] == "Possible Lateral Movement":
                    st.caption(
                        "Reason: this source contacted multiple internal destination hosts."
                    )

                st.divider()

            st.download_button(
                label="Download Advanced Detection Report",
                data=all_results.to_csv(index=False).encode("utf-8"),
                file_name="netsentry_advanced_detection.csv",
                mime="text/csv",
            )

    except Exception as error:
        st.error(f"Could not analyze advanced traffic: {error}")

else:
    st.info(
        "Advanced detection is ready, but data/advanced_traffic.csv "
        "has not been created yet."
    )
    st.caption(
        "The existing dashboard will continue to work. "
        "We will create the test dataset in the next step."
    )
    
st.header("Export Advanced Security Report")

if not all_results.empty:
    report_csv = all_results.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="Download Complete Advanced Security Report",
        data=report_csv,
        file_name="netsentry_advanced_security_report.csv",
        mime="text/csv",
    )
else:
    st.info("No alerts are available to export.")

# Mission 04: HTML Report Export
st.header("Mission 04: Download HTML Security Report")

if not all_results.empty:
    html_table = all_results.to_html(index=False, escape=True)

    html_report = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>NetSentry Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 30px; color: #222; }}
        h1, h2 {{ color: #17365d; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
        th {{ background-color: #e8eef7; }}
        .notice {{ padding: 12px; border: 1px solid #d6b656; margin-top: 20px; }}
    </style>
</head>
<body>
    <h1>NetSentry Security Report</h1>
    <p>Generated by the NetSentry educational prototype.</p>
    <h2>Detection Results</h2>
    {html_table}
    <div class="notice">
        <strong>Important limitation:</strong>
        Alerts are indicators for investigation, not confirmed attacks.
        Results from simulated data do not establish real-world detection
        accuracy. Review the underlying evidence before taking action.
    </div>
</body>
</html>"""

    st.download_button(
        label="Download HTML Security Report",
        data=html_report,
        file_name="netsentry_security_report.html",
        mime="text/html",
        key="mission4_html_report_download",
    )
else:
    st.info(
        "No advanced detection results are available to export as HTML."
    )

# Mission 2: Incident Timeline
st.header("Incident Timeline & Explanations")

timeline_file = "reports/incident_timeline.csv"

if os.path.exists(timeline_file):
    timeline_df = pd.read_csv(timeline_file)

    if timeline_df.empty:
        st.info("No incidents are currently recorded.")
    else:
        st.caption(
            "These are screening indicators from sample traffic, "
            "not confirmed attacks."
        )

        st.dataframe(timeline_df, use_container_width=True)

        st.download_button(
            label="Download Incident Timeline",
            data=timeline_df.to_csv(index=False),
            file_name="incident_timeline.csv",
            mime="text/csv",
        )
else:
    st.warning(
        "Incident timeline not found. "
        "Run: python src/create_incident_timeline.py"
    )

# ================= MISSION 03: ADVANCED VISUALIZATION =================

st.header("Mission 03: Advanced Anomaly Visualization")

st.info(
    "These charts use simulated demonstration data. "
    "Indicators support investigation and do not confirm an attack."
)

from pathlib import Path

mission3_reports = Path(__file__).resolve().parent / "reports"

# 1. Traffic volume compared with normal baseline
st.subheader("1. Traffic Volume vs Normal Baseline")

deviation_chart = mission3_reports / "mission3_deviation_chart.png"

if deviation_chart.exists():
    st.image(
        str(deviation_chart),
        caption="Observed packet counts compared with the simulated normal baseline."
    )
else:
    st.warning("Traffic deviation chart not found. Run the Mission 03 analysis script.")

deviation_csv = mission3_reports / "mission3_deviations.csv"

if deviation_csv.exists():
    deviation_df = pd.read_csv(deviation_csv)

    st.dataframe(
        deviation_df[
            [
                "timestamp",
                "source_ip",
                "destination_ip",
                "packets",
                "baseline_packets",
                "packet_deviation",
                "volume_indicator",
                "trusted_scheduled_activity",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "Download traffic deviation evidence",
        data=deviation_df.to_csv(index=False),
        file_name="mission3_deviations.csv",
        mime="text/csv",
        key="mission3_deviation_download",
    )

# 2. Possible beaconing and connection gaps
st.subheader("2. Repeated External Connections")

beacon_chart = mission3_reports / "mission3_beacon_gaps.png"

if beacon_chart.exists():
    st.image(
        str(beacon_chart),
        caption="Time gaps between repeated external connections."
    )
else:
    st.warning("Beaconing chart not found.")

beacon_csv = mission3_reports / "mission3_beaconing_report.csv"

if beacon_csv.exists():
    beacon_df = pd.read_csv(beacon_csv)
    st.write("Possible beaconing indicators")
    st.dataframe(beacon_df, use_container_width=True, hide_index=True)

gap_csv = mission3_reports / "mission3_connection_gaps.csv"

if gap_csv.exists():
    gap_df = pd.read_csv(gap_csv)
    st.write("Connection-by-connection timing evidence")
    st.dataframe(gap_df, use_container_width=True, hide_index=True)

# 3. Incident timeline with evidence and risk scores
st.subheader("3. Incident Timeline and Investigation Evidence")

timeline_csv = mission3_reports / "mission3_incident_timeline.csv"

if timeline_csv.exists():
    timeline_df = pd.read_csv(timeline_csv)

    if not timeline_df.empty:
        if "timestamp" in timeline_df.columns:
            timeline_df = timeline_df.sort_values("timestamp")

        st.dataframe(
            timeline_df,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download incident timeline",
            data=timeline_df.to_csv(index=False),
            file_name="mission3_incident_timeline.csv",
            mime="text/csv",
            key="mission3_timeline_download",
        )
    else:
        st.success("No incidents were generated by the current demonstration scenarios.")
else:
    st.warning("Incident timeline report not found.")

# 4. Network communication graph
st.subheader("4. Network Communication Graph")

graph_chart = mission3_reports / "mission3_communication_graph.png"

if graph_chart.exists():
    st.image(
        str(graph_chart),
        caption="Simulated source-to-destination communication relationships."
    )
else:
    st.warning("Communication graph not found.")

# 5. Scenario test results
st.subheader("5. Scenario Evaluation")

scenario_csv = mission3_reports / "mission3_scenario_test_results.csv"

if scenario_csv.exists():
    scenario_df = pd.read_csv(scenario_csv)
    st.dataframe(
        scenario_df,
        use_container_width=True,
        hide_index=True,
    )

st.caption(
    "Limitations: the baseline and scenarios are simplified demonstrations. "
    "A real deployment needs representative traffic, validated thresholds, "
    "and analyst review. Risk scores are prototype values, not calibrated "
    "probabilities of an attack."
)

