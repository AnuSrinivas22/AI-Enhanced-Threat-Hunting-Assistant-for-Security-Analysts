import pandas as pd

from agents.coordinator_agent import CoordinatorAgent


print("\n==============================================")
print("           DDoS EVENT TEST")
print("==============================================")


# ==============================================
# LOAD DATASET
# ==============================================

df = pd.read_csv(
    "data/security_logs.csv"
)

df.columns = df.columns.str.strip()


# ==============================================
# SELECT 10 DDoS EVENTS
# ==============================================

ddos_events = df[
    df["Label"] == "DDoS"
].head(10)


traffic_data = ddos_events.drop(
    "Label",
    axis=1
)


# ==============================================
# DISPLAY TEST DATA
# ==============================================

print("\n===== TEST DATA =====")

print(
    "Total events:",
    len(traffic_data)
)

print(
    "Expected classification: DDoS"
)


# ==============================================
# START COORDINATOR
# ==============================================

print("\n===== STARTING ANALYSIS =====")

coordinator = CoordinatorAgent()

result = coordinator.analyze_multiple(
    traffic_data
)


# ==============================================
# DISPLAY RESULTS
# ==============================================

print("\n==============================================")
print("              DDoS TEST RESULT")
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


# ==============================================
# DISPLAY LLM REPORT
# ==============================================

print("\n===== LLM ANALYST REPORT =====")

print(
    result["llm_report"]
)


print("\n==============================================")
print("           DDoS TEST COMPLETED")
print("==============================================")