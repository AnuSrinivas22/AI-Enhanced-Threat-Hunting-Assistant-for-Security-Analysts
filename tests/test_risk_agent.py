from agents.risk_assessment_agent import RiskAssessmentAgent


# ============================================================
# SAMPLE DETECTION RESULT
# ============================================================

detection_result = {
    "agent": "Threat Detection Agent",
    "prediction": "DDoS",
    "confidence": 0.98
}


# ============================================================
# SAMPLE CORRELATION RESULT
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
# INITIALIZE RISK ASSESSMENT AGENT
# ============================================================

agent = RiskAssessmentAgent()


# ============================================================
# ASSESS RISK
# ============================================================

result = agent.assess(
    detection_result,
    correlation_result
)


# ============================================================
# DISPLAY RESULT
# ============================================================

print("\n===== RISK ASSESSMENT RESULT =====")

print("Agent:", result["agent"])
print("Risk Score:", result["risk_score"])
print("Risk Level:", result["risk_level"])

print("\nReason:")
print("Prediction:", result["reason"]["prediction"])
print("Confidence:", result["reason"]["confidence"])
print("Correlated:", result["reason"]["correlated"])