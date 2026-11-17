
class RiskAssessmentAgent:

    def __init__(self):
        print("Risk Assessment Agent initialized.")

    def assess(self, detection_result, correlation_result):

        try:
            # Validate input types
            if not isinstance(detection_result, dict):
                raise TypeError("detection_result must be a dictionary.")

            if not isinstance(correlation_result, dict):
                raise TypeError("correlation_result must be a dictionary.")

            # Read and validate detection information
            if "prediction" not in detection_result:
                raise ValueError(
                    "Prediction field is missing from detection_result."
                )

            prediction = detection_result["prediction"]

            if not isinstance(prediction, str):
                raise ValueError("Prediction must be a string.")

            prediction = prediction.strip().upper()

            if prediction not in ("BENIGN", "DDOS"):
                raise ValueError(
                    f"Unsupported prediction label: {prediction}"
                )

            confidence = float(detection_result.get("confidence", 0))

            if not 0 <= confidence <= 1:
                raise ValueError("Confidence must be between 0 and 1.")

            correlated = correlation_result.get("correlated", False)

            if not isinstance(correlated, bool):
                raise ValueError("Correlated must be True or False.")

            correlations = correlation_result.get("correlations", [])

            if not isinstance(correlations, list):
                raise TypeError("Correlations must be a list.")

            # Extract event counts
            ddos_count = 0
            benign_count = 0

            for correlation in correlations:

                if not isinstance(correlation, dict):
                    raise TypeError(
                        "Each correlation entry must be a dictionary."
                    )

                if correlation.get("type") == "Repeated Threat Classification":

                    values = correlation.get("values", {})

                    if not isinstance(values, dict):
                        raise TypeError(
                            "Threat classification values must be a dictionary."
                        )

                    ddos_count = int(values.get("DDoS", 0))
                    benign_count = int(values.get("BENIGN", 0))

                    if ddos_count < 0 or benign_count < 0:
                        raise ValueError("Event counts cannot be negative.")

            total_events = ddos_count + benign_count

            score_factors = {}

            # Batch-level risk calculation
            if total_events > 0:

                ddos_percentage = (ddos_count / total_events) * 100

                if ddos_count == 0:

                    risk_score = 5

                    score_factors = {
                        "base_score": 5,
                        "confidence_bonus": 0,
                        "correlation_bonus": 0,
                        "ddos_prevalence_bonus": 0
                    }

                else:

                    risk_score = 20
                    score_factors["base_score"] = 20

                    confidence_bonus = 0

                    if confidence >= 0.90:
                        confidence_bonus = 10
                    elif confidence >= 0.70:
                        confidence_bonus = 5

                    risk_score += confidence_bonus
                    score_factors["confidence_bonus"] = confidence_bonus

                    correlation_bonus = 10 if correlated else 0

                    risk_score += correlation_bonus
                    score_factors["correlation_bonus"] = correlation_bonus

                    prevalence_bonus = round(ddos_percentage * 0.4)

                    risk_score += prevalence_bonus
                    score_factors["ddos_prevalence_bonus"] = prevalence_bonus

                score_factors["ddos_percentage"] = round(
                    ddos_percentage, 2
                )

            # Individual-event risk calculation
            elif prediction == "BENIGN":

                risk_score = 5 if confidence >= 0.90 else 10

                score_factors = {
                    "individual_prediction": prediction,
                    "confidence": confidence
                }

            else:

                risk_score = 30

                confidence_bonus = 0

                if confidence >= 0.90:
                    confidence_bonus = 10
                elif confidence >= 0.70:
                    confidence_bonus = 5

                risk_score += confidence_bonus

                correlation_bonus = 10 if correlated else 0
                risk_score += correlation_bonus

                score_factors = {
                    "base_score": 30,
                    "confidence_bonus": confidence_bonus,
                    "correlation_bonus": correlation_bonus
                }

            # Keep score within 0-100
            risk_score = min(100, max(0, round(risk_score)))

            # Assign risk level
            if risk_score >= 80:
                risk_level = "CRITICAL"
            elif risk_score >= 60:
                risk_level = "HIGH"
            elif risk_score >= 30:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            return {
                "agent": "Risk Assessment Agent",
                "risk_score": risk_score,
                "risk_level": risk_level,
                "reason": {
                    "prediction": prediction,
                    "confidence": confidence,
                    "correlated": correlated,
                    "ddos_count": ddos_count,
                    "benign_count": benign_count,
                    "total_events": total_events,
                    "score_factors": score_factors
                }
            }

        except Exception as e:
            print(f"Risk Assessment Agent Error: {e}")
            raise RuntimeError(
                f"Risk assessment failed: {e}"
            ) from e
