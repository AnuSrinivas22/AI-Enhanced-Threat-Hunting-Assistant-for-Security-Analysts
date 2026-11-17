from agents.threat_detection_agent import ThreatDetectionAgent
from agents.correlation_agent import CorrelationAgent
from agents.risk_assessment_agent import RiskAssessmentAgent
from agents.investigation_agent import InvestigationAgent


class CoordinatorAgent:

    def __init__(self):

        print("Coordinator Agent initialized.")

        # Initialize agents with error handling
        self.detection_agent = ThreatDetectionAgent()
        self.correlation_agent = CorrelationAgent()
        self.risk_agent = RiskAssessmentAgent()
        self.investigation_agent = InvestigationAgent()

    def analyze_multiple(self, traffic_data):

        print("\n===== MULTI-EVENT ANALYSIS STARTED =====")

        # --------------------------------------------
        # VALIDATE INPUT
        # --------------------------------------------

        if traffic_data is None:
            raise ValueError("Traffic data cannot be None.")

        if traffic_data.empty:
            raise ValueError("No network events were provided.")

        if not hasattr(traffic_data, "iterrows"):
            raise TypeError(
                "Traffic data must be a pandas DataFrame."
            )

        detection_results = []
        detection_errors = []

        # --------------------------------------------
        # 1. THREAT DETECTION AGENT
        # --------------------------------------------

        print("\n[1] Running Threat Detection Agent...")

        for index, traffic in traffic_data.iterrows():

            try:

                detection_result = self.detection_agent.detect(
                    traffic
                )

                if not isinstance(detection_result, dict):
                    raise TypeError(
                        "Detection agent returned an invalid result."
                    )

                if "prediction" not in detection_result:
                    raise ValueError(
                        "Prediction is missing from detection result."
                    )

                detection_result["event_id"] = int(index)

                if "Destination Port" in traffic.index:
                    try:
                        detection_result["Destination Port"] = int(
                            traffic["Destination Port"]
                        )
                    except (ValueError, TypeError):
                        detection_result["Destination Port"] = None

                detection_results.append(detection_result)

            except Exception as e:

                error_message = (
                    f"Event {index} detection failed: {str(e)}"
                )

                detection_errors.append(error_message)

                print(f"WARNING: {error_message}")

        if not detection_results:
            raise RuntimeError(
                "Threat detection failed for all events. "
                "Analysis cannot continue."
            )

        print(
            f"Successfully detected {len(detection_results)} "
            f"out of {len(traffic_data)} events."
        )

        # --------------------------------------------
        # 2. CORRELATION AGENT
        # --------------------------------------------

        print("\n[2] Running Correlation Agent...")

        correlation_errors = []

        try:

            correlation_result = self.correlation_agent.correlate(
                detection_results
            )

            if not isinstance(correlation_result, dict):
                raise TypeError(
                    "Correlation agent returned an invalid result."
                )

        except Exception as e:

            correlation_errors.append(str(e))

            print(
                f"WARNING: Correlation Agent failed: {e}"
            )

            correlation_result = {
                "correlated": False,
                "error": str(e),
                "message": "Correlation analysis unavailable."
            }

        # --------------------------------------------
        # 3. RISK ASSESSMENT AGENT
        # --------------------------------------------

        print("\n[3] Running Risk Assessment Agent...")

        ddos_results = [
            result
            for result in detection_results
            if str(result.get("prediction", "")).strip().upper()
            == "DDOS"
        ]

        if ddos_results:

            primary_detection = max(
                ddos_results,
                key=lambda x: float(x.get("confidence", 0))
            )

        else:

            primary_detection = max(
                detection_results,
                key=lambda x: float(x.get("confidence", 0))
            )

        risk_errors = []

        try:

            risk_result = self.risk_agent.assess(
                primary_detection,
                correlation_result
            )

            if not isinstance(risk_result, dict):
                raise TypeError(
                    "Risk assessment agent returned an invalid result."
                )

        except Exception as e:

            risk_errors.append(str(e))

            print(
                f"WARNING: Risk Assessment Agent failed: {e}"
            )

            risk_result = {
                "risk_score": None,
                "risk_level": "UNAVAILABLE",
                "error": str(e),
                "message": (
                    "Risk assessment could not be completed. "
                    "Manual review is required."
                )
            }

        # --------------------------------------------
        # 4. INVESTIGATION AGENT
        # --------------------------------------------

        print("\n[4] Running Investigation Agent...")

        investigation_errors = []

        try:

            investigation_result = self.investigation_agent.investigate(
                primary_detection,
                correlation_result,
                risk_result
            )

            if not isinstance(investigation_result, dict):
                raise TypeError(
                    "Investigation agent returned an invalid result."
                )

        except Exception as e:

            investigation_errors.append(str(e))

            print(
                f"WARNING: Investigation Agent failed: {e}"
            )

            investigation_result = {
                "summary": (
                    "Automated investigation could not be completed."
                ),
                "threat_description": "",
                "indicators": [],
                "recommendations": [
                    "Review the detection results manually.",
                    "Check relevant firewall and IDS/IPS alerts."
                ],
                "rag_context": [],
                "error": str(e)
            }

        # --------------------------------------------
        # 5. PREPARE FINAL RESULT
        # --------------------------------------------

        final_result = {

            "events_analyzed": len(detection_results),

            "detections": detection_results,

            "correlation": correlation_result,

            "risk_assessment": risk_result,

            "investigation": investigation_result,

            "errors": {
                "detection": detection_errors,
                "correlation": correlation_errors,
                "risk_assessment": risk_errors,
                "investigation": investigation_errors
            },

            "analysis_status": (
                "COMPLETED"
                if not any([
                    detection_errors,
                    correlation_errors,
                    risk_errors,
                    investigation_errors
                ])
                else "PARTIALLY_COMPLETED"
            )
        }

        print("\n===== MULTI-EVENT ANALYSIS COMPLETED =====")

        return final_result