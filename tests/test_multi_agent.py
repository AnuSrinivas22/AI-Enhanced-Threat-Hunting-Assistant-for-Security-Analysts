
import pandas as pd

from agents.coordinator_agent import CoordinatorAgent


# ============================================================
# LOAD DATASET
# ============================================================

df = pd.read_csv("data/security_logs.csv")

df.columns = df.columns.str.strip()

# Remove target column
traffic_data = df.drop("Label", axis=1)

# Use one real network flow as a DataFrame
sample = traffic_data.iloc[[0]]


# ============================================================
# INITIALIZE COORDINATOR
# ============================================================

coordinator = CoordinatorAgent()


# ============================================================
# RUN COMPLETE MULTI-AGENT ANALYSIS
# ============================================================

result = coordinator.analyze_multiple(sample)


# ============================================================
# DISPLAY FINAL RESULTS
# ============================================================

print("\n==============================================")
print("       FINAL MULTI-AGENT THREAT ANALYSIS")
print("==============================================")


# Detection
print("\n===== THREAT DETECTION =====")

print("Events analyzed:", result["events_analyzed"])

for detection in result["detections"]:
    print("Event ID:", detection["event_id"])
    print("Prediction:", detection["prediction"])
    print("Confidence:", detection["confidence"])


# Correlation
print("\n===== EVENT CORRELATION =====")

print("Correlated:", result["correlation"]["correlated"])
print("Event Count:", result["correlation"]["event_count"])


# Risk
print("\n===== RISK ASSESSMENT =====")

print("Risk Score:", result["risk_assessment"]["risk_score"])
print("Risk Level:", result["risk_assessment"]["risk_level"])


# Investigation
print("\n===== INVESTIGATION =====")

print("Threat Type:", result["investigation"]["threat_type"])
print("Summary:", result["investigation"]["summary"])

print("\nRecommendations:")

for recommendation in result["investigation"]["recommendations"]:
    print("-", recommendation)


# LLM report
print("\n===== AI ANALYST REPORT =====")
print(result.get("llm_report", "No LLM report was generated."))


print("\n==============================================")
print("       MULTI-AGENT ANALYSIS COMPLETED")
print("==============================================")