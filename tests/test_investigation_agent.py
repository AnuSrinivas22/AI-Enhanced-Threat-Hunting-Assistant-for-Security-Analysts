from agents.investigation_agent import InvestigationAgent


# ============================================================
# DETECTION AGENT RESULT
# ============================================================

detection_result = {
    "agent": "Threat Detection Agent",
    "prediction": "DDoS",
    "confidence": 0.98
}


# ============================================================
# CORRELATION AGENT RESULT
# ============================================================

correlation_result = {
    "agent": "Correlation Agent",
    "correlated": True,
    "correlations": [
        {
            "type": "Repeated Destination Port",
            "values": [80]
        },
        {
            "type": "Repeated Threat Classification",
            "values": {
                "DDoS": 3
            }
        }
    ],
    "event_count": 4
}


# ============================================================
# RISK ASSESSMENT AGENT RESULT
# ============================================================

risk_result = {
    "agent": "Risk Assessment Agent",
    "risk_score": 100,
    "risk_level": "CRITICAL",
    "reason": {
        "prediction": "DDoS",
        "confidence": 0.98,
        "correlated": True
    }
}


# ============================================================
# INITIALIZE INVESTIGATION AGENT
# ============================================================

agent = InvestigationAgent()


# ============================================================
# INVESTIGATE
# ============================================================

result = agent.investigate(
    detection_result,
    correlation_result,
    risk_result
)


# ============================================================
# DISPLAY RESULT
# ============================================================

print("\n===== INVESTIGATION RESULT =====")

print("Agent:", result["agent"])
print("Threat Type:", result["threat_type"])
print("Confidence:", result["confidence"])
print("Risk Score:", result["risk_score"])
print("Risk Level:", result["risk_level"])
print("Correlated Events:", result["correlated_events"])

print("\n===== INVESTIGATION SUMMARY =====")
print(result["summary"])

print("\n===== THREAT DESCRIPTION =====")
print(result["description"])

print("\n===== INDICATORS =====")

for indicator in result["indicators"]:
    print("-", indicator)

print("\n===== RECOMMENDATIONS =====")

for recommendation in result["recommendations"]:
    print("-", recommendation)