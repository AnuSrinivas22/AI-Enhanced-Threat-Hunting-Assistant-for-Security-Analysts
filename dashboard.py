
import streamlit as st
import pandas as pd
from datetime import datetime

from agents.coordinator_agent import CoordinatorAgent
from llm_report_agent import LLMReportAgent


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AI Threat Hunting Assistant",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# TITLE
# ============================================================

st.title("🛡️ AI-Enhanced Threat Hunting Assistant")

st.markdown("### Multi-Agent AI System for Security Analysts")

st.markdown(
    "This dashboard analyzes selected network security dataset records using "
    "Machine Learning, Multi-Agent Analysis, RAG and a Local LLM."
)

st.info(
    "Demonstration note: this dashboard analyzes selected dataset records; "
    "it does not monitor live network traffic or automatically block attacks."
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.header("⚙️ Analysis Settings")

number_of_benign = st.sidebar.slider(
    "BENIGN Events",
    min_value=0,
    max_value=10,
    value=10
)

number_of_ddos = st.sidebar.slider(
    "DDoS Events",
    min_value=0,
    max_value=10,
    value=10
)


# ============================================================
# LOAD DATA
# ============================================================

@st.cache_data
def load_data():
    df = pd.read_csv("data/security_logs.csv")
    df.columns = df.columns.str.strip()
    return df


try:
    df = load_data()

except Exception as e:
    st.error(f"Unable to load dataset: {e}")
    st.stop()


# ============================================================
# VALIDATE DATASET
# ============================================================

if "Label" not in df.columns:
    st.error("The dataset does not contain a 'Label' column.")
    st.stop()


# ============================================================
# SELECT RANDOM EVENTS
# ============================================================

benign_data = df[
    df["Label"].astype(str).str.strip().str.upper() == "BENIGN"
]

ddos_data = df[
    df["Label"].astype(str).str.strip().str.upper() == "DDOS"
]

benign_events = benign_data.sample(
    n=min(number_of_benign, len(benign_data)),
    random_state=None
)

ddos_events = ddos_data.sample(
    n=min(number_of_ddos, len(ddos_data)),
    random_state=None
)

sample_events = pd.concat(
    [benign_events, ddos_events],
    ignore_index=True
)

traffic_data = sample_events.drop(
    columns=["Label"],
    errors="ignore"
)


# ============================================================
# RUN ANALYSIS
# ============================================================

st.markdown("---")
st.subheader("🔍 Threat Analysis")

if st.button(
    "🚀 Run Threat Analysis",
    use_container_width=True
):

    if traffic_data.empty:
        st.warning("Select at least one event to analyze.")

    else:

        with st.spinner("Running Multi-Agent Threat Analysis..."):

            try:

                # INITIALIZE COORDINATOR

                coordinator = CoordinatorAgent()

                analysis_result = coordinator.analyze_multiple(
                    traffic_data
                )

                if not isinstance(analysis_result, dict):
                    raise ValueError(
                        "Coordinator returned an invalid analysis result."
                    )

                # COUNT MODEL PREDICTIONS

                detections = analysis_result.get("detections", [])

                if not isinstance(detections, list):
                    raise ValueError(
                        "Detection results are not in the expected format."
                    )

                benign_count = sum(
                    1
                    for item in detections
                    if isinstance(item, dict)
                    and str(
                        item.get("prediction", "")
                    ).strip().upper() == "BENIGN"
                )

                ddos_count = sum(
                    1
                    for item in detections
                    if isinstance(item, dict)
                    and str(
                        item.get("prediction", "")
                    ).strip().upper() == "DDOS"
                )

                total_detections = len(detections)

                analysis_result["event_classification_counts"] = {
                    "BENIGN": benign_count,
                    "DDoS": ddos_count,
                    "total": total_detections
                }

                # PREPARE REPORT WITH BATCH COUNTS

                report_result = dict(analysis_result)

                original_investigation = analysis_result.get(
                    "investigation",
                    {}
                )

                if not isinstance(original_investigation, dict):
                    original_investigation = {}

                report_investigation = dict(
                    original_investigation
                )

                original_summary = report_investigation.get(
                    "summary",
                    "Not available from the current analysis."
                )

                report_investigation["summary"] = (
                    f"{original_summary}\n\n"
                    f"Batch classification counts from the "
                    f"event-level model predictions: "
                    f"{benign_count} BENIGN events, "
                    f"{ddos_count} DDoS events, "
                    f"{total_detections} total predictions. "
                    f"These are model predictions, not proof "
                    f"of an active attack."
                )

                report_result["investigation"] = (
                    report_investigation
                )

                # GENERATE AI REPORT

                analysis_result["llm_report"] = ""
                analysis_result["report_error"] = None

                try:

                    report_agent = LLMReportAgent()

                    generated_report = report_agent.generate_report(
                        report_result
                    )

                    if (
                        generated_report
                        and str(generated_report).strip()
                    ):

                        analysis_result["llm_report"] = (
                            generated_report
                        )

                    else:

                        analysis_result["report_error"] = (
                            "The AI report generator returned "
                            "an empty response."
                        )

                except Exception as report_error:

                    analysis_result["report_error"] = str(
                        report_error
                    )

                # SAVE RESULTS

                st.session_state["analysis_result"] = (
                    analysis_result
                )

                st.success(
                    "Threat analysis completed successfully!"
                )

                if analysis_result["report_error"]:
                    st.warning(
                        "Threat analysis completed, but the "
                        "AI Analyst Report could not be generated. "
                        "The analysis results are still available."
                    )

            except Exception as e:

                st.error(
                    f"Threat analysis failed: {e}"
                )

                st.stop()


# ============================================================
# DISPLAY RESULTS
# ============================================================

if "analysis_result" in st.session_state:

    analysis_result = st.session_state["analysis_result"]

    risk = analysis_result.get("risk_assessment", {})
    correlation = analysis_result.get("correlation", {})
    investigation = analysis_result.get("investigation", {})

    detections = analysis_result.get("detections", [])

    # COUNT EVENT-LEVEL PREDICTIONS

    benign_count = sum(
        1
        for item in detections
        if isinstance(item, dict)
        and str(item.get("prediction", "")).strip().upper()
        == "BENIGN"
    )

    ddos_count = sum(
        1
        for item in detections
        if isinstance(item, dict)
        and str(item.get("prediction", "")).strip().upper()
        == "DDOS"
    )

    classification_counts = analysis_result.get(
        "event_classification_counts",
        {
            "BENIGN": benign_count,
            "DDoS": ddos_count,
            "total": len(detections)
        }
    )

    # --------------------------------------------------------
    # SUMMARY METRICS
    # --------------------------------------------------------

    st.markdown("---")
    st.subheader("📊 Analysis Summary")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Events Analyzed",
        analysis_result.get("events_analyzed", len(detections))
    )

    col2.metric(
        "Risk Score",
        risk.get("risk_score", 0)
    )

    col3.metric(
        "Risk Level",
        risk.get("risk_level", "UNKNOWN")
    )

    col4.metric(
        "Correlated",
        str(correlation.get("correlated", False))
    )

    # --------------------------------------------------------
    # CLASSIFICATION COUNTS
    # --------------------------------------------------------

    st.markdown("---")
    st.subheader("📈 Event Classification Summary")

    count_col1, count_col2, count_col3 = st.columns(3)

    count_col1.metric(
        "Predicted BENIGN",
        classification_counts.get("BENIGN", 0)
    )

    count_col2.metric(
        "Predicted DDoS",
        classification_counts.get("DDoS", 0)
    )

    count_col3.metric(
        "Total Predictions",
        classification_counts.get("total", len(detections))
    )

    st.caption(
        "Counts reflect event-level model predictions, "
        "not confirmed real-world attacks."
    )

    # --------------------------------------------------------
    # EVENT-LEVEL DETECTION
    # --------------------------------------------------------

    st.markdown("---")
    st.subheader("🔎 Event-Level Detection Results")

    event_rows = []

    for detection in detections:

        if not isinstance(detection, dict):
            continue

        event_rows.append({
            "Event ID": detection.get("event_id", "N/A"),
            "Prediction": detection.get("prediction", "Unknown"),
            "Confidence": detection.get("confidence", 0)
        })

    if event_rows:

        event_df = pd.DataFrame(event_rows)

        st.dataframe(
            event_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No event-level detection results available."
        )

    # --------------------------------------------------------
    # INVESTIGATION
    # --------------------------------------------------------

    st.markdown("---")
    st.subheader("🔬 Investigation Summary")

    st.write(
        investigation.get(
            "summary",
            "Not available from the current analysis."
        )
    )

    # --------------------------------------------------------
    # THREAT DESCRIPTION
    # --------------------------------------------------------

    threat_description = investigation.get(
        "threat_description",
        ""
    )

    if threat_description:

        st.subheader("📌 Threat Description")
        st.write(threat_description)

    # --------------------------------------------------------
    # INDICATORS
    # --------------------------------------------------------

    indicators = investigation.get("indicators", [])

    if indicators:

        st.subheader("🚨 Indicators")

        for indicator in indicators:
            st.write(f"• {indicator}")

    # --------------------------------------------------------
    # RECOMMENDATIONS
    # --------------------------------------------------------

    recommendations = investigation.get(
        "recommendations",
        []
    )

    if recommendations:

        st.markdown("---")
        st.subheader("🛡️ Recommended Defensive Actions")

        for recommendation in recommendations:
            st.write(f"• {recommendation}")

    # --------------------------------------------------------
    # RAG KNOWLEDGE
    # --------------------------------------------------------

    rag_context = investigation.get("rag_context", [])

    if rag_context:

        st.markdown("---")
        st.subheader("📚 RAG-Based Supporting Knowledge")

        st.caption(
            "RAG = Retrieval-Augmented Generation. "
            "This is general cybersecurity knowledge supporting "
            "the analysis, not direct evidence of an attack."
        )

        for index, item in enumerate(rag_context, start=1):

            if not isinstance(item, dict):
                continue

            content = item.get(
                "content",
                item.get("information", "")
            )

            score = item.get(
                "score",
                item.get("relevance_score", "N/A")
            )

            if content:

                with st.expander(
                    f"Knowledge {index} "
                    f"(Relevance Score: {score})"
                ):

                    st.write(content)

    # --------------------------------------------------------
    # AI ANALYST REPORT
    # --------------------------------------------------------

    st.markdown("---")
    st.subheader("🤖 AI Analyst Report")

    llm_report = analysis_result.get("llm_report", "")
    report_error = analysis_result.get("report_error")

    if llm_report:

        st.markdown(llm_report)

    elif report_error:

        st.warning(
            "The AI Analyst Report is currently unavailable. "
            "You can still download the available analysis results."
        )

        with st.expander("View report generation error"):

            st.code(str(report_error))

    else:

        st.info(
            "No AI Analyst Report is available for this analysis. "
            "You can still download the available analysis results."
        )

    # --------------------------------------------------------
    # DOWNLOAD COMPLETE ANALYSIS REPORT
    # --------------------------------------------------------

    def report_value(value):
        """Convert report values safely into readable text."""
        if value is None or value == "":
            return "Not available"
        return str(value)

    # EVENT RESULTS FOR REPORT

    event_report_lines = []

    for detection in detections:

        if isinstance(detection, dict):

            event_report_lines.append(
                f"Event ID: {report_value(detection.get('event_id', 'N/A'))} | "
                f"Prediction: {report_value(detection.get('prediction', 'Unknown'))} | "
                f"Confidence: {report_value(detection.get('confidence', 'N/A'))}"
            )

    # INDICATORS

    indicator_lines = "\n".join(
        f"- {item}" for item in indicators
    ) if indicators else "None recorded"

    # RECOMMENDATIONS

    recommendation_lines = "\n".join(
        f"- {item}" for item in recommendations
    ) if recommendations else "None recorded"

    # RAG KNOWLEDGE

    rag_lines = []

    for index, item in enumerate(rag_context, start=1):

        if isinstance(item, dict):

            content = item.get(
                "content",
                item.get("information", "")
            )

            score = item.get(
                "score",
                item.get("relevance_score", "N/A")
            )

            if content:

                rag_lines.append(
                    f"{index}. {content} (Relevance: {score})"
                )

    # COMPLETE REPORT CONTENT

    complete_report = f"""
AI-ENHANCED THREAT HUNTING ASSISTANT
COMPLETE ANALYSIS REPORT

Generated on: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}

============================================================
1. ANALYSIS OVERVIEW
============================================================

Events analyzed: {analysis_result.get('events_analyzed', len(detections))}
Predicted BENIGN events: {classification_counts.get('BENIGN', benign_count)}
Predicted DDoS events: {classification_counts.get('DDoS', ddos_count)}
Total event predictions: {classification_counts.get('total', len(detections))}

Note: These are model predictions, not proof of an active attack.
The dashboard analyzes selected dataset records, not live traffic.

============================================================
2. RISK ASSESSMENT
============================================================

Risk score: {report_value(risk.get('risk_score', 'N/A'))}
Risk level: {report_value(risk.get('risk_level', 'N/A'))}

============================================================
3. EVENT CORRELATION
============================================================

Correlated events: {report_value(correlation.get('correlated', 'N/A'))}
Event count: {report_value(correlation.get('event_count', 'N/A'))}
Detected correlations: {report_value(correlation.get('correlations', correlation.get('detected_correlations', 'N/A')))}

============================================================
4. EVENT-LEVEL DETECTION RESULTS
============================================================

{chr(10).join(event_report_lines) if event_report_lines else 'No event-level detection details available.'}

============================================================
5. INVESTIGATION SUMMARY
============================================================

{report_value(investigation.get('summary', 'Not available'))}

Threat description:
{report_value(investigation.get('threat_description', 'Not available'))}

============================================================
6. INDICATORS
============================================================

{indicator_lines}

============================================================
7. RECOMMENDED DEFENSIVE ACTIONS
============================================================

{recommendation_lines}

============================================================
8. RAG-BASED SUPPORTING KNOWLEDGE
============================================================

{chr(10).join(rag_lines) if rag_lines else 'No supporting knowledge retrieved.'}

============================================================
9. AI-GENERATED ANALYST REPORT
============================================================

{llm_report if llm_report else 'AI Analyst Report was not generated.'}

============================================================
END OF REPORT
============================================================
"""

    st.download_button(
        label="📥 Download Complete Analysis Report",
        data=complete_report,
        file_name="AI_Threat_Hunting_Complete_Report.txt",
        mime="text/plain",
        use_container_width=True
    )

else:

    st.info(
        "Select the number of events and click "
        "'Run Threat Analysis' to start the analysis."
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.caption(
    "AI-Enhanced Threat Hunting Assistant | "
    "Random Forest + Multi-Agent AI + RAG + Llama 3.2 3B"
)
