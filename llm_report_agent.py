
import ollama


class LLMReportAgent:

    def __init__(self):
        print("LLM Report Agent initialized.")
        self.model = "llama3.2:3b"

    def generate_report(self, analysis_result):

        # Validate the main input
        if not isinstance(analysis_result, dict):
            raise TypeError(
                "Analysis result must be a dictionary."
            )

        # Safely read nested results
        risk = analysis_result.get("risk_assessment", {})
        investigation = analysis_result.get("investigation", {})
        correlation = analysis_result.get("correlation", {})

        if not isinstance(risk, dict):
            risk = {}

        if not isinstance(investigation, dict):
            investigation = {}

        if not isinstance(correlation, dict):
            correlation = {}

        # Event count
        try:
            event_count = int(
                analysis_result.get("events_analyzed", 0)
            )
        except (TypeError, ValueError):
            event_count = 0

        # Investigation details
        threat_type = investigation.get(
            "threat_type", "Unknown"
        )

        confidence = investigation.get(
            "confidence", "Not available"
        )

        summary = investigation.get(
            "summary",
            "No investigation summary is available."
        )

        # Risk details
        risk_score = risk.get("risk_score", 0)
        risk_level = risk.get("risk_level", "UNKNOWN")

        risk_reason = risk.get("reason", {})

        if not isinstance(risk_reason, dict):
            risk_reason = {}

        score_factors = risk_reason.get(
            "score_factors", {}
        )

        if not isinstance(score_factors, dict):
            score_factors = {}

        correlated = correlation.get(
            "correlated", False
        )

        # Event classification counts
        counts = analysis_result.get(
            "event_classification_counts", {}
        )

        if not isinstance(counts, dict):
            counts = {}

        # Derive counts from detections if not supplied
        if not counts and isinstance(
            analysis_result.get("detections"), list
        ):

            predictions = [
                str(item.get("prediction", "")).strip().upper()
                for item in analysis_result["detections"]
                if isinstance(item, dict)
            ]

            benign_count = predictions.count("BENIGN")
            ddos_count = predictions.count("DDOS")
            total_count = len(predictions)

        else:

            try:
                benign_count = int(counts.get("BENIGN", 0))
                ddos_count = int(counts.get("DDoS", 0))

                total_count = int(
                    counts.get("total", event_count)
                )

                if min(
                    benign_count,
                    ddos_count,
                    total_count
                ) < 0:
                    raise ValueError(
                        "Event counts cannot be negative."
                    )

            except (TypeError, ValueError) as e:
                raise ValueError(
                    f"Invalid event classification counts: {e}"
                ) from e

        # Prepare batch description
        if benign_count > 0 and ddos_count > 0:

            batch_description = (
                f"Mixed batch containing {benign_count} BENIGN "
                f"predictions and {ddos_count} DDoS predictions."
            )

        elif ddos_count > 0:

            batch_description = (
                f"{ddos_count} DDoS predictions and "
                f"{benign_count} BENIGN predictions."
            )

        elif benign_count > 0:

            batch_description = (
                f"{benign_count} BENIGN predictions and "
                "no counted DDoS predictions."
            )

        else:

            batch_description = (
                "Event-level classification counts are unavailable."
            )

        # Risk scoring breakdown
        risk_factors = []

        for key, value in score_factors.items():

            if key in (
                "ddos_percentage",
                "individual_prediction",
                "confidence"
            ):
                continue

            risk_factors.append(
                f"- {str(key).replace('_', ' ').title()}: "
                f"{value} points"
            )

        if "ddos_percentage" in score_factors:

            risk_factors.append(
                f"- DDoS prevalence: "
                f"{score_factors['ddos_percentage']}%"
            )

        risk_factors_text = "\n".join(risk_factors)

        if not risk_factors_text:
            risk_factors_text = (
                "Detailed risk scoring factors are unavailable."
            )

        # Correlation findings
        correlation_details = []

        correlation_items = correlation.get(
            "correlations", []
        )

        if isinstance(correlation_items, list):

            for item in correlation_items:

                if isinstance(item, dict):

                    correlation_details.append(
                        f"- {item.get('type', 'Correlation')}: "
                        f"{item.get('values', 'Not available')}"
                    )

        correlation_text = "\n".join(
            correlation_details
        ) or "No additional correlation findings are available."

        # RAG knowledge
        rag_context = investigation.get(
            "rag_context", []
        )

        rag_items = []

        if isinstance(rag_context, list):

            for item in rag_context:

                if isinstance(item, dict):

                    content = item.get(
                        "content",
                        item.get(
                            "information",
                            item.get("text", "")
                        )
                    )

                    score = item.get(
                        "score",
                        item.get("relevance_score", "N/A")
                    )

                else:
                    content = str(item)
                    score = "N/A"

                if content:
                    rag_items.append(
                        f"- {content} (relevance score: {score})"
                    )

        rag_text = "\n".join(rag_items) or (
            "No RAG knowledge was retrieved."
        )

        # Recommendations
        recommendations = investigation.get(
            "recommendations", []
        )

        if not isinstance(recommendations, list):
            recommendations = []

        recommendations_text = "\n".join(
            f"- {item}" for item in recommendations
        ) or "No recommendations are available."

        # Prepare correlation status
        correlation_status = (
            "True" if correlated is True
            else "False" if correlated is False
            else "Unavailable"
        )

        # LLM prompt
        prompt = f"""
You are a cybersecurity analyst assisting a Security Operations Center.

Generate a professional, factual threat analysis report.

Use only the supplied information.

IMPORTANT RULES:

1. ML predictions do not prove a real-world attack.
2. A risk score is an assessment, not an attack probability.
3. Correlation does not independently prove malicious activity.
4. RAG knowledge is supporting information, not direct evidence.
5. Never invent IP addresses, ports, traffic volumes or packet counts.
6. Never invent risk-scoring factors.
7. Use the exact supplied risk score and risk level.
8. Clearly distinguish mixed BENIGN and DDoS predictions.
9. Do not claim that all events are DDoS when predictions are mixed.
10. Recommend analyst validation.
11. Investigation classification refers to the selected primary
    detection, not necessarily the entire batch.

ANALYSIS RESULTS

Events analyzed: {event_count}

Event classification:
{batch_description}

BENIGN predictions: {benign_count}
DDoS predictions: {ddos_count}
Total predictions: {total_count}

Investigation classification: {threat_type}
Investigation confidence: {confidence}

Risk score: {risk_score}/100
Risk level: {risk_level}

Correlation status: {correlation_status}

ACTUAL RISK SCORING BREAKDOWN:

{risk_factors_text}

CORRELATION FINDINGS:

{correlation_text}

INVESTIGATION SUMMARY:

{summary}

RAG SUPPORTING KNOWLEDGE:

{rag_text}

RECOMMENDATIONS:

{recommendations_text}

Generate EXACTLY seven sections:

1. Threat Assessment
2. Evidence from Multi-Agent Analysis
3. Risk Assessment
4. RAG-Based Supporting Knowledge
5. Investigation Summary
6. Recommended Defensive Actions
7. Analyst Conclusion

Explain the actual event counts, investigation classification,
risk contributions, correlation findings and retrieved knowledge.

Use the supplied investigation summary and recommendations.
Do not invent missing scoring details.
Explain that the risk score is not an attack probability.
Clearly explain mixed-event results where applicable.

Return only the seven numbered sections.
Keep the report concise and professional.
"""

        try:

            response = ollama.chat(
                model=self.model,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            # Support dictionary and ChatResponse objects
            if isinstance(response, dict):
                message = response.get("message", {})
            else:
                message = getattr(
                    response, "message", None
                )

            if isinstance(message, dict):
                report = message.get("content", "")
            else:
                report = getattr(
                    message, "content", ""
                )

            # Validate generated report
            if not isinstance(report, str) or not report.strip():
                raise ValueError(
                    "The LLM returned an empty report."
                )

            return report.strip()

        except Exception as error:

            print(
                f"LLM report generation failed: {error}"
            )

            # Fallback report
            return f"""
1. Threat Assessment

{batch_description}

Investigation classification: {threat_type}
Investigation confidence: {confidence}
Risk score: {risk_score}/100
Risk level: {risk_level}

The investigation classification represents the selected
primary detection, not necessarily every event in the batch.

2. Evidence from Multi-Agent Analysis

Events analyzed: {event_count}
BENIGN predictions: {benign_count}
DDoS predictions: {ddos_count}
Total predictions: {total_count}

Correlation status: {correlation_status}

{correlation_text}

3. Risk Assessment

Risk score: {risk_score}/100
Risk level: {risk_level}

Actual scoring contributions:

{risk_factors_text}

The risk score is an assessment, not an attack probability.

4. RAG-Based Supporting Knowledge

RAG provides general cybersecurity guidance,
not direct evidence of an attack.

{rag_text}

5. Investigation Summary

{summary}

6. Recommended Defensive Actions

{recommendations_text}

7. Analyst Conclusion

{batch_description}

The assigned risk level is {risk_level}.
Further investigation and analyst validation are recommended.
The available predictions do not independently confirm an attack.
"""
