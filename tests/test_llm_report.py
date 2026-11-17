import pandas as pd

from agents.coordinator_agent import CoordinatorAgent


print("\n==============================================")
print("       MULTI-AGENT + RAG + LLM TEST")
print("==============================================")


# ==============================================
# LOAD DATASET
# ==============================================

df = pd.read_csv("data/security_logs.csv")

df.columns = df.columns.str.strip()


# ==============================================
# SELECT TEST EVENTS
# ==============================================

benign_events = df[
    df["Label"] == "BENIGN"
].head(10)

ddos_events = df[
    df["Label"] == "DDoS"
].head(10)


sample_events = pd.concat(
    [benign_events, ddos_events]
)


traffic_data = sample_events.drop(
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
    "BENIGN events:",
    len(benign_events)
)

print(
    "DDoS events:",
    len(ddos_events)
)


# ==============================================
# START COORDINATOR
# ==============================================

print("\n===== STARTING MULTI-AGENT ANALYSIS =====")

coordinator = CoordinatorAgent()

analysis_result = coordinator.analyze_multiple(
    traffic_data
)

print("\n===== EVENT-LEVEL DETECTION RESULTS =====")

for detection in analysis_result["detections"]:

    print(
        f"Event {detection['event_id']} "
        f"→ {detection['prediction']} "
        f"(confidence: {detection['confidence']})"
    )


# ==============================================
# DISPLAY FINAL LLM REPORT
# ==============================================

print("\n==============================================")
print("             FINAL LLM ANALYST REPORT")
print("==============================================")

print(
    analysis_result["llm_report"]
)


print("\n==============================================")
print("       MULTI-AGENT + RAG + LLM COMPLETED")
print("==============================================")