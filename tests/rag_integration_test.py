from rag_module import RAGModule


def main():

    print("\n==============================================")
    print("       RAG THREAT INVESTIGATION")
    print("==============================================")

    # Initialize RAG
    rag = RAGModule()

    # Information received from our Multi-Agent system
    threat_type = "DDoS"
    risk_level = "CRITICAL"
    correlated = True

    print("\n===== THREAT INFORMATION =====")
    print("Threat Type:", threat_type)
    print("Risk Level:", risk_level)
    print("Correlated Events:", correlated)

    # Send threat information to RAG
    print("\n===== RETRIEVING CYBERSECURITY KNOWLEDGE =====")

    results = rag.generate_context(
        threat_type=threat_type,
        risk_level=risk_level,
        correlated=correlated
    )

    # Display retrieved information
    print("\n===== RAG CONTEXT =====")

    if not results:
        print("No relevant cybersecurity knowledge found.")

    else:

        for i, result in enumerate(results, 1):

            print(f"\nKnowledge {i}")
            print("Relevance Score:", result["score"])
            print("Information:")
            print(result["content"])

    print("\n==============================================")
    print("       RAG INTEGRATION TEST COMPLETED")
    print("==============================================")


if __name__ == "__main__":
    main()