class ReportGenerator:

    def __init__(self):
        print("Report Generator initialized.")

    def generate_report(self, analysis_result):

        risk = analysis_result.get("risk_assessment", {})
        investigation = analysis_result.get("investigation", {})
        correlation = analysis_result.get("correlation", {})

        threat_type = investigation.get(
            "threat_type",
            "Unknown"
        )

        risk_score = risk.get(
            "risk_score",
            0
        )

        risk_level = risk.get(
            "risk_level",
            "UNKNOWN"
        )

        correlated = correlation.get(
            "correlated",
            False
        )

        event_count = analysis_result.get(
            "events_analyzed",
            0
        )

        summary = investigation.get(
            "summary",
            "No investigation summary available."
        )

        recommendations = investigation.get(
            "recommendations",
            []
        )

        rag_context = investigation.get(
            "rag_context",
            []
        )

        print("\n")
        print("=" * 60)
        print("              SECURITY ANALYST REPORT")
        print("=" * 60)

        print("\n[1] ANALYSIS SUMMARY")

        print(f"Events Analyzed : {event_count}")
        print(f"Threat Type     : {threat_type}")
        print(f"Risk Score      : {risk_score}")
        print(f"Risk Level      : {risk_level}")
        print(f"Correlated      : {correlated}")

        print("\n[2] INVESTIGATION SUMMARY")

        print(summary)

        print("\n[3] RECOMMENDATIONS")

        if recommendations:

            for i, recommendation in enumerate(
                recommendations,
                start=1
            ):
                print(f"{i}. {recommendation}")

        else:
            print("No recommendations available.")

        print("\n[4] RETRIEVED KNOWLEDGE FROM RAG")

        if rag_context:

            for i, knowledge in enumerate(
                rag_context,
                start=1
            ):

                print(f"\nKnowledge {i}")

                print(
                    "Relevance Score:",
                    knowledge.get(
                        "score",
                        "N/A"
                    )
                )

                print(
                    knowledge.get(
                        "content",
                        "No information available."
                    )
                )

        else:

            print(
                "No RAG knowledge was retrieved."
            )

        print("\n[5] FINAL ASSESSMENT")

        if risk_level == "CRITICAL":

            print(
                "CRITICAL: Potential high-risk "
                "network activity detected. "
                "Further investigation is recommended."
            )

        elif risk_level == "HIGH":

            print(
                "HIGH: Suspicious network activity "
                "requires investigation."
            )

        elif risk_level == "MEDIUM":

            print(
                "MEDIUM: Some suspicious activity "
                "was detected. Continue monitoring."
            )

        else:

            print(
                "LOW: No significant threat "
                "was identified."
            )

        print("\n")
        print("=" * 60)
        print("          END OF SECURITY ANALYST REPORT")
        print("=" * 60)

        return {
            "threat_type": threat_type,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "events_analyzed": event_count,
            "correlated": correlated,
            "summary": summary,
            "recommendations": recommendations,
            "rag_context": rag_context
        }