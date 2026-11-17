import pandas as pd

from agents.coordinator_agent import CoordinatorAgent


# ============================================================
# LOAD DATASET
# ============================================================

df = pd.read_csv("data/security_logs.csv")

# Clean column names
df.columns = df.columns.str.strip()


# ============================================================
# SELECT REAL BENIGN AND DDOS EVENTS
# ============================================================

benign_events = df[df["Label"] == "BENIGN"].head(10)

ddos_events = df[df["Label"] == "DDoS"].head(10)


# Combine both types
sample_events = pd.concat(
    [benign_events, ddos_events]
)


# Remove the original label before sending to model
traffic_data = sample_events.drop(
    "Label",
    axis=1
)


print("\n===== TEST DATA =====")

print(
    "Total events:",
    len(traffic_data)
)

print(
    "BENIGN events:",
    len(benign_events)
)

print(
    "DDoS events:",
    len(ddos_events)
)


# ============================================================
# INITIALIZE COORDINATOR
# ============================================================

coordinator = CoordinatorAgent()


# ============================================================
# RUN MULTI-EVENT ANALYSIS
# ============================================================

result = coordinator.analyze_multiple(
    traffic_data
)


# ============================================================
# DISPLAY FINAL RESULTS
# ============================================================

print("\n==============================================")
print("       REAL MULTI-EVENT THREAT ANALYSIS")
print("==============================================")


print("\n===== EVENTS ANALYZED =====")

print(
    result["events_analyzed"]
)


# ============================================================
# DETECTION RESULTS
# ============================================================

print("\n===== DETECTION RESULTS =====")

for detection in result["detections"]:

    print(
        "Event:",
        detection["event_id"],
        "| Prediction:",
        detection["prediction"],
        "| Confidence:",
        detection["confidence"]
    )


# ============================================================
# CORRELATION
# ============================================================

print("\n===== CORRELATION =====")

print(
    "Correlated:",
    result["correlation"]["correlated"]
)

print(
    "Event Count:",
    result["correlation"]["event_count"]
)

if result["correlation"]["correlated"]:

    print("\nDetected Correlations:")

    for correlation in result["correlation"]["correlations"]:

        print(
            "-",
            correlation
        )


# ============================================================
# RISK ASSESSMENT
# ============================================================

print("\n===== RISK ASSESSMENT =====")

print(
    "Risk Score:",
    result["risk_assessment"]["risk_score"]
)

print(
    "Risk Level:",
    result["risk_assessment"]["risk_level"]
)


# ============================================================
# INVESTIGATION
# ============================================================

print("\n===== INVESTIGATION =====")

print(
    "Threat Type:",
    result["investigation"]["threat_type"]
)

print(
    "Summary:",
    result["investigation"]["summary"]
)

print("\nRecommendations:")

for recommendation in result[
    "investigation"
]["recommendations"]:

    print(
        "-",
        recommendation
    )


print("\n==============================================")
print("       REAL MULTI-EVENT ANALYSIS COMPLETED")
print("==============================================")