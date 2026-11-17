import pandas as pd

from agents.coordinator_agent import CoordinatorAgent


print("\n==============================================")
print("          BENIGN EVENT TEST")
print("==============================================")


# Load dataset
df = pd.read_csv("data/security_logs.csv")
df.columns = df.columns.str.strip()


# Select 10 BENIGN events
benign_events = df[
    df["Label"] == "BENIGN"
].head(10)


traffic_data = benign_events.drop(
    "Label",
    axis=1
)


print("\n===== TEST DATA =====")
print("Total events:", len(traffic_data))
print("Expected classification: BENIGN")


# Start Coordinator
print("\n===== STARTING ANALYSIS =====")

coordinator = CoordinatorAgent()

result = coordinator.analyze_multiple(
    traffic_data
)


# Display results
print("\n==============================================")
print("             BENIGN TEST RESULT")
print("==============================================")

print(
    "Events analyzed:",
    result["events_analyzed"]
)

print(
    "Risk Score:",
    result["risk_assessment"]["risk_score"]
)

print(
    "Risk Level:",
    result["risk_assessment"]["risk_level"]
)

print(
    "Correlated:",
    result["correlation"]["correlated"]
)


print("\n===== LLM ANALYST REPORT =====")

print(
    result["llm_report"]
)


print("\n==============================================")
print("          BENIGN TEST COMPLETED")
print("==============================================")