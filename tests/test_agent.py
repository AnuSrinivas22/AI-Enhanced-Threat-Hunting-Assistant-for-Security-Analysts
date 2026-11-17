import pandas as pd

from agents.threat_detection_agent import ThreatDetectionAgent


# ============================================================
# LOAD ONE REAL NETWORK FLOW
# ============================================================

df = pd.read_csv("data/security_logs.csv")

# Clean column names
df.columns = df.columns.str.strip()

# Remove the target column
traffic = df.drop("Label", axis=1)

# Take the first network flow
sample = traffic.iloc[0]


# ============================================================
# INITIALIZE THREAT DETECTION AGENT
# ============================================================

agent = ThreatDetectionAgent()


# ============================================================
# DETECT THREAT
# ============================================================

result = agent.detect(sample)


# ============================================================
# DISPLAY RESULT
# ============================================================

print("\n===== THREAT DETECTION RESULT =====")

print("Agent:", result["agent"])
print("Prediction:", result["prediction"])
print("Confidence:", result["confidence"])