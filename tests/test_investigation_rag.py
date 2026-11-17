from agents.investigation_agent import InvestigationAgent


print("\n==============================================")
print("       INVESTIGATION + RAG TEST")
print("==============================================")


# Initialize Investigation Agent
agent = InvestigationAgent()


# Simulated results from previous agents
detection_result = {
    "prediction": "DDoS",
    "confidence": 0.98
}


correlation_result = {
    "correlated": True
}


risk_result = {
    "risk_score": 100,
    "risk_level": "CRITICAL"
}


# Run investigation
result = agent.investigate(
    detection_result,
    correlation_result,
    risk_result
)


# Display normal investigation result
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


# Display RAG information
print("\n===== RAG RETRIEVED KNOWLEDGE =====")

if not result["rag_context"]:

    print("No relevant knowledge retrieved.")

else:

    for i, item in enumerate(
        result["rag_context"],
        1
    ):

        print(f"\nKnowledge {i}")
        print(
            "Relevance Score:",
            item["relevance_score"]
        )

        print(
            "Information:",
            item["information"]
        )


print("\n==============================================")
print("       INVESTIGATION + RAG TEST COMPLETED")
print("==============================================")