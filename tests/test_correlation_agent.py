from agents.correlation_agent import CorrelationAgent


# Create sample security events
events = [
    {
        "Destination Port": 80,
        "prediction": "DDoS",
        "confidence": 0.98
    },
    {
        "Destination Port": 80,
        "prediction": "DDoS",
        "confidence": 0.97
    },
    {
        "Destination Port": 443,
        "prediction": "BENIGN",
        "confidence": 0.99
    },
    {
        "Destination Port": 80,
        "prediction": "DDoS",
        "confidence": 0.96
    }
]


# Initialize Correlation Agent
agent = CorrelationAgent()


# Perform correlation
result = agent.correlate(events)


# Display result
print("\n===== CORRELATION RESULT =====")

print("Agent:", result["agent"])
print("Correlated:", result["correlated"])
print("Event Count:", result["event_count"])

if result["correlated"]:
    print("\nDetected Correlations:")

    for correlation in result["correlations"]:
        print(correlation)