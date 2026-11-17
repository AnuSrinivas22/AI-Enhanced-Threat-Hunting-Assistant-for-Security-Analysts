
from rag_module import RAGModule


class InvestigationAgent:

    def __init__(self):
        print("Investigation Agent initialized.")

        # Initialize RAG with fallback
        self.rag = None
        self.rag_init_error = None

        try:
            self.rag = RAGModule()
            print("RAG Module initialized successfully.")

        except Exception as e:
            self.rag_init_error = str(e)
            print(f"RAG initialization failed: {e}")
            print("Local knowledge base will be used as fallback.")

        # Local threat knowledge base
        self.knowledge_base = {

            "DDoS": {
                "description": (
                    "Distributed Denial-of-Service activity attempts "
                    "to overwhelm a service or network with excessive traffic."
                ),
                "indicators": [
                    "High volume of network traffic",
                    "Repeated traffic patterns",
                    "Repeated destination ports",
                    "Multiple suspicious flows"
                ],
                "recommendations": [
                    "Investigate the source and destination traffic patterns",
                    "Check whether the targeted service is experiencing abnormal load",
                    "Correlate related network events",
                    "Review firewall and IDS/IPS alerts",
                    "Consider appropriate traffic filtering or rate limiting"
                ]
            },

            "BENIGN": {
                "description": (
                    "The network flow was classified as benign "
                    "by the threat detection model."
                ),
                "indicators": [
                    "No DDoS classification",
                    "Normal traffic classification"
                ],
                "recommendations": [
                    "No immediate threat response is required",
                    "Continue monitoring the network activity"
                ]
            }
        }

    def investigate(
        self,
        detection_result,
        correlation_result,
        risk_result
    ):

        try:
            # Validate inputs
            if not isinstance(detection_result, dict):
                raise TypeError(
                    "detection_result must be a dictionary."
                )

            if not isinstance(correlation_result, dict):
                raise TypeError(
                    "correlation_result must be a dictionary."
                )

            if not isinstance(risk_result, dict):
                raise TypeError(
                    "risk_result must be a dictionary."
                )

            # Read detection information
            if "prediction" not in detection_result:
                raise ValueError(
                    "Prediction field is required."
                )

            prediction = detection_result["prediction"]

            if not isinstance(prediction, str):
                raise ValueError(
                    "Prediction must be a string."
                )

            prediction = prediction.strip().upper()

            # Normalize prediction labels
            if prediction == "DDOS":
                prediction = "DDoS"

            if prediction not in ("DDoS", "BENIGN"):
                raise ValueError(
                    f"Unsupported prediction: {prediction}"
                )

            confidence = float(
                detection_result.get("confidence", 0)
            )

            if not 0 <= confidence <= 1:
                raise ValueError(
                    "Confidence must be between 0 and 1."
                )

            # Read correlation information
            correlated = correlation_result.get(
                "correlated", False
            )

            if not isinstance(correlated, bool):
                raise ValueError(
                    "Correlated must be True or False."
                )

            # Read risk information
            risk_level = risk_result.get(
                "risk_level", "UNKNOWN"
            )

            if not isinstance(risk_level, str):
                raise ValueError(
                    "Risk level must be a string."
                )

            risk_level = risk_level.strip().upper()

            if risk_level not in [
                "LOW", "MEDIUM", "HIGH", "CRITICAL"
            ]:
                raise ValueError(
                    "Risk level must be LOW, MEDIUM, HIGH, or CRITICAL."
                )

            risk_score = float(
                risk_result.get("risk_score", 0)
            )

            if not 0 <= risk_score <= 100:
                raise ValueError(
                    "Risk score must be between 0 and 100."
                )

            # Get local knowledge
            threat_info = self.knowledge_base.get(
                prediction,
                {
                    "description": "No knowledge-base entry available.",
                    "indicators": [],
                    "recommendations": []
                }
            )

            # Build investigation summary
            if prediction == "DDoS":

                if correlated:
                    summary = (
                        "Potential DDoS activity detected with "
                        "correlated network events. "
                        "Further investigation is recommended."
                    )

                else:
                    summary = (
                        "Potential DDoS activity detected. "
                        "Correlation with additional events is recommended."
                    )

            else:
                summary = (
                    "The network flow was classified as benign. "
                    "No immediate threat response is required."
                )

            # RAG retrieval with error handling
            rag_context = []
            rag_error = self.rag_init_error

            if self.rag is not None:

                try:
                    rag_results = self.rag.generate_context(
                        threat_type=prediction,
                        risk_level=risk_level,
                        correlated=correlated
                    )

                    if rag_results is None:
                        rag_results = []

                    if not isinstance(rag_results, list):
                        raise TypeError(
                            "RAG results must be a list."
                        )

                    for item in rag_results:

                        if not isinstance(item, dict):
                            continue

                        rag_context.append({
                            "relevance_score": float(
                                item.get("score", 0)
                            ),
                            "information": str(
                                item.get("content", "")
                            )
                        })

                    if not rag_context:
                        rag_error = (
                            "No RAG knowledge retrieved; "
                            "local knowledge used as fallback."
                        )
                    else:
                        rag_error = None

                except Exception as e:
                    print(f"RAG retrieval failed: {e}")

                    rag_error = (
                        "RAG retrieval unavailable; "
                        "local knowledge used as fallback."
                    )

            else:
                rag_error = (
                    "RAG initialization unavailable; "
                    "local knowledge used as fallback."
                )

            # Final investigation result
            result = {

                "agent": "Investigation Agent",
                "summary": summary,
                "threat_type": prediction,
                "confidence": confidence,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "correlated_events": correlated,
                "description": threat_info["description"],
                "indicators": threat_info["indicators"],
                "recommendations": threat_info["recommendations"],
                "rag_context": rag_context,

                "rag_status": (
                    "available" if rag_error is None else "fallback"
                ),

                "rag_error": rag_error
            }

            return result

        except Exception as e:
            print(f"Investigation Agent Error: {e}")

            raise RuntimeError(
                f"Investigation failed: {e}"
            ) from e
