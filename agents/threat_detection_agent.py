import pandas as pd
import joblib


class ThreatDetectionAgent:

    def __init__(self):

        self.model = None

        # --------------------------------------------
        # LOAD VALIDATED ML MODEL
        # --------------------------------------------

        try:

            self.model = joblib.load(
                "models/threat_detection_model_validated.pkl"
            )

            print("Threat Detection Agent initialized.")

        except FileNotFoundError as e:

            raise FileNotFoundError(
                "Validated threat detection model was not found. "
                "Check the models folder."
            ) from e

        except Exception as e:

            raise RuntimeError(
                f"Unable to load the threat detection model: {e}"
            ) from e

        # --------------------------------------------
        # VALIDATE MODEL
        # --------------------------------------------

        if not hasattr(self.model, "predict"):
            raise TypeError(
                "Loaded model does not support prediction."
            )

        if not hasattr(self.model, "predict_proba"):
            raise TypeError(
                "Loaded model does not support probability prediction."
            )

        if not hasattr(self.model, "classes_"):
            raise TypeError(
                "Loaded model does not contain class information."
            )

    # ========================================================
    # THREAT DETECTION
    # ========================================================

    def detect(self, traffic_data):

        try:

            # --------------------------------------------
            # VALIDATE INPUT
            # --------------------------------------------

            if traffic_data is None:
                raise ValueError(
                    "Traffic data cannot be None."
                )

            # --------------------------------------------
            # CONVERT INPUT INTO DATAFRAME
            # --------------------------------------------

            if isinstance(traffic_data, dict):

                traffic_data = pd.DataFrame([traffic_data])

            elif isinstance(traffic_data, pd.Series):

                traffic_data = traffic_data.to_frame().T

            elif isinstance(traffic_data, pd.DataFrame):

                traffic_data = traffic_data.copy()

            else:

                raise TypeError(
                    "Input must be a dictionary, pandas Series, "
                    "or pandas DataFrame."
                )

            if traffic_data.empty:
                raise ValueError(
                    "Traffic data is empty."
                )

            # --------------------------------------------
            # CLEAN COLUMN NAMES
            # --------------------------------------------

            traffic_data.columns = (
                traffic_data.columns.astype(str).str.strip()
            )

            if traffic_data.columns.duplicated().any():
                raise ValueError(
                    "Input contains duplicate column names."
                )

            # --------------------------------------------
            # VALIDATE MODEL FEATURES
            # --------------------------------------------

            expected_features = getattr(
                self.model,
                "feature_names_in_",
                None
            )

            if expected_features is not None:

                missing_features = [
                    feature
                    for feature in expected_features
                    if feature not in traffic_data.columns
                ]

                extra_features = [
                    feature
                    for feature in traffic_data.columns
                    if feature not in expected_features
                ]

                if missing_features:

                    raise ValueError(
                        "Missing required model features: "
                        f"{missing_features[:10]}"
                    )

                if extra_features:

                    raise ValueError(
                        "Unexpected input features: "
                        f"{extra_features[:10]}"
                    )

                traffic_data = traffic_data[
                    list(expected_features)
                ]

            # --------------------------------------------
            # CHECK FOR INVALID VALUES
            # --------------------------------------------

            if traffic_data.isnull().any().any():

                raise ValueError(
                    "Input contains missing values."
                )

            # --------------------------------------------
            # MAKE PREDICTION
            # --------------------------------------------

            prediction = self.model.predict(
                traffic_data
            )[0]

            # --------------------------------------------
            # GET PREDICTION PROBABILITIES
            # --------------------------------------------

            probabilities = self.model.predict_proba(
                traffic_data
            )[0]

            classes = list(self.model.classes_)

            if prediction not in classes:
                raise ValueError(
                    "Predicted class is not present in model classes."
                )

            confidence = probabilities[
                classes.index(prediction)
            ]

            # --------------------------------------------
            # CREATE RESULT
            # --------------------------------------------

            result = {

                "agent": "Threat Detection Agent",

                "prediction": str(prediction),

                "confidence": round(
                    float(confidence),
                    4
                )

            }

            return result

        except Exception as e:

            print(
                f"Threat Detection Agent Error: {e}"
            )

            raise RuntimeError(
                f"Threat detection failed: {e}"
            ) from e