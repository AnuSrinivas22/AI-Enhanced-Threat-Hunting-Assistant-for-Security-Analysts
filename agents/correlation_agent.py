import pandas as pd


class CorrelationAgent:

    def __init__(self):
        print("Correlation Agent initialized.")

    # ========================================================
    # CORRELATION ANALYSIS
    # ========================================================

    def correlate(self, events):

        try:

            # --------------------------------------------
            # VALIDATE INPUT
            # --------------------------------------------

            if events is None:
                raise ValueError(
                    "Events cannot be None."
                )

            # --------------------------------------------
            # CONVERT INPUT INTO DATAFRAME
            # --------------------------------------------

            if isinstance(events, list):

                events = pd.DataFrame(events)

            elif isinstance(events, pd.DataFrame):

                events = events.copy()

            else:

                raise TypeError(
                    "Events must be a list or pandas DataFrame."
                )

            # --------------------------------------------
            # CHECK EMPTY DATA
            # --------------------------------------------

            if events.empty:

                return {
                    "agent": "Correlation Agent",
                    "correlated": False,
                    "correlations": [],
                    "event_count": 0,
                    "error": None,
                    "message": "No events available for correlation."
                }

            # --------------------------------------------
            # CLEAN COLUMN NAMES
            # --------------------------------------------

            events.columns = (
                events.columns.astype(str).str.strip()
            )

            if events.columns.duplicated().any():
                raise ValueError(
                    "Duplicate column names found in event data."
                )

            correlations = []

            # --------------------------------------------
            # CHECK 1: SAME DESTINATION PORT
            # --------------------------------------------

            if "Destination Port" in events.columns:

                port_counts = events[
                    "Destination Port"
                ].dropna().value_counts()

                repeated_ports = port_counts[
                    port_counts > 1
                ].index.tolist()

                if repeated_ports:

                    correlations.append({
                        "type": "Repeated Destination Port",
                        "values": repeated_ports
                    })

            # --------------------------------------------
            # CHECK 2: SAME PREDICTION
            # --------------------------------------------

            if "prediction" in events.columns:

                prediction_counts = events[
                    "prediction"
                ].dropna().value_counts()

                repeated_predictions = (
                    prediction_counts[
                        prediction_counts > 1
                    ].to_dict()
                )

                if repeated_predictions:

                    correlations.append({
                        "type": "Repeated Threat Classification",
                        "values": repeated_predictions
                    })

            # --------------------------------------------
            # FINAL RESULT
            # --------------------------------------------

            return {
                "agent": "Correlation Agent",
                "correlated": bool(correlations),
                "correlations": correlations,
                "event_count": len(events),
                "error": None
            }

        except Exception as e:

            print(
                f"Correlation Agent Error: {e}"
            )

            raise RuntimeError(
                f"Correlation analysis failed: {e}"
            ) from e