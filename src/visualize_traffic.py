
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# Locate the project folder and report
project_folder = Path(__file__).resolve().parent.parent
report_file = project_folder / "reports" / "traffic_analysis.csv"

# Load the analysis results
df = pd.read_csv(report_file)

# Create a graph of packet counts
colors = ["red" if unusual else "steelblue"
          for unusual in df["unusual"]]

plt.figure(figsize=(10, 5))
plt.bar(range(1, len(df) + 1), df["packets"], color=colors)

plt.axhline(
    y=100,
    linestyle="--",
    color="black",
    label="Demo threshold: 100 packets"
)

plt.xlabel("Traffic record number")
plt.ylabel("Packet count")
plt.title("NetSentry: Network Traffic Screening")
plt.xticks(range(1, len(df) + 1))
plt.legend()
plt.tight_layout()

# Save the graph
graph_file = project_folder / "reports" / "traffic_graph.png"
plt.savefig(graph_file)
print(f"Graph saved to: {graph_file}")

# Display the graph
plt.show()