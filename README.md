AI-Enhanced DDoS Threat Hunting Assistant for Security Analysts

An AI-powered threat hunting assistant designed to support Security Operations Center (SOC) analysts in identifying and investigating potential Distributed Denial of Service (DDoS) attacks using Machine Learning, Multi-Agent Architecture, Retrieval-Augmented Generation (RAG), and Large Language Models (LLMs).

📌 Project Overview

Distributed Denial of Service (DDoS) attacks are a major cybersecurity threat that can disrupt network services by overwhelming systems with malicious traffic.

This project introduces an AI-Enhanced DDoS Threat Hunting Assistant that analyzes network traffic records, identifies potential DDoS activity, correlates suspicious events, evaluates risk levels, and generates structured investigation reports.

The system combines a Random Forest classification model with a multi-agent workflow, a local cybersecurity knowledge base, and an LLM-based reporting component to provide meaningful insights to security analysts.

The system is designed to assist security analysts in investigation and decision-making. It does not independently confirm attacks or execute defensive actions.

🎯 Project Objectives

Detect potential DDoS activity using Machine Learning.

Classify network traffic as Benign or DDoS.

Correlate suspicious events to identify potentially related activities.

Calculate risk scores and assign severity levels.

Retrieve relevant cybersecurity knowledge using a local RAG module.

Generate structured threat investigation reports using an LLM.

Provide an interactive dashboard for security analysts.

🏗️ System Architecture

The project follows a modular, multi-agent architecture in which different components perform specific threat-hunting tasks.

Workflow

Data Input: Network traffic records are provided through a CSV file.

Data Preprocessing: Cleans the dataset by handling missing values, infinite values, duplicate records, and numeric conversion.

Threat Detection Agent: Uses a trained Random Forest model to classify network traffic as Benign or DDoS and generate prediction confidence.

Event Correlation: Identifies potentially related suspicious events based on predicted classes and repeated destination ports.

Risk Assessment: Calculates rule-based risk scores and assigns corresponding severity levels.

Knowledge Retrieval (RAG): Retrieves relevant cybersecurity information from a local knowledge base using keyword-overlap matching.

Report Generation Agent: Uses the locally hosted Llama 3.2 3B model to generate structured investigation reports.

Streamlit Dashboard: Displays classification results, correlated events, risk assessments, retrieved knowledge, and recommendations.

<img width="1153" height="641" alt="image" src="https://github.com/user-attachments/assets/ea0f351b-d3e3-4beb-af5a-d3fd4a539a87" />

🧠 Technologies Used

<img width="771" height="600" alt="image" src="https://github.com/user-attachments/assets/5ca4c88a-2071-46de-8c06-ee5443f78872" />


🔍 Key Features

1. Machine Learning-Based Threat Detection

Uses a Random Forest classifier with 100 decision trees.

Performs binary classification of network traffic.

Identifies Benign and DDoS traffic.

Provides prediction confidence.

2. Multi-Agent Architecture

Coordinator Agent manages the overall workflow.

Threat Detection Agent performs ML-based classification.

Event Correlation identifies potentially related suspicious events.

Risk Assessment evaluates the severity of detected activity.

Reporting Agent generates investigation summaries.

3. Event Correlation and Risk Assessment

Identifies repeated destination ports and predicted traffic classes.

Applies predefined rules to calculate risk scores.

Assigns severity levels to support investigation prioritization.

4. Retrieval-Augmented Generation (RAG)

Uses a local cybersecurity knowledge base.

Retrieves relevant information through keyword-overlap matching.

Returns relevant knowledge passages for report generation.

Does not depend on an embedding-based vector database.

5. LLM-Based Report Generation

Uses the locally hosted Llama 3.2 3B model.

Generates structured threat investigation reports.

Incorporates detection results, risk assessments, and retrieved knowledge.

Provides investigation recommendations for analyst review.

6. Interactive Streamlit Dashboard

Displays traffic classification results.

Presents threat detection confidence.

Shows event correlation and risk assessment.

Displays retrieved cybersecurity knowledge.

Presents generated investigation reports and recommendations.

📊 Dataset

Dataset: CIC-IDS2017

The CIC-IDS2017 dataset is used for training and evaluating the machine learning model.

Data Preprocessing

The preprocessing pipeline includes:

Removal of unnecessary columns.

Conversion of relevant features into numeric format.

Handling missing and infinite values.

Removal of exact duplicate records.

Stratified training and testing split.

Dataset Distribution

<img width="792" height="222" alt="image" src="https://github.com/user-attachments/assets/d9d6d04e-b1af-4a71-91e1-8fa8e937481d" />


The dataset is divided using an 80:20 stratified split with a random state of 42.

📈 Model Evaluation

The Random Forest classification model was evaluated using the following performance metrics:

<img width="790" height="330" alt="image" src="https://github.com/user-attachments/assets/90cc8595-4c86-4729-b356-26c61c33c585" />


Confusion Matrix

<img width="532" height="467" alt="Screenshot 2026-10-30 132829" src="https://github.com/user-attachments/assets/6e57335c-38e6-4975-9a58-d3196392c02e" />


These results represent the model's evaluation on the held-out test dataset.

📁 Project Structure

The repository is organized into the following modules:

AI-Enhanced-DDoS-Threat-Hunting-Assistant/
│
├── agents/
│
├── data/
│
├── knowledge_base/
│
├── models/
│
├── tests/
│
├── dashboard.py
├── main.py
├── llm_report_agent.py
├── rag_module.py
├── report_generator.py
├── validate_model.py
│
├── requirements.txt
├── .gitignore
└── README.md

Important Files and Directories

<img width="791" height="726" alt="image" src="https://github.com/user-attachments/assets/4628d675-03e3-49da-b1b6-de8274f7a0a3" />


⚙️ Installation and Setup

Follow these steps to set up the project locally.

Step 1: Clone the Repository

git clone <https://github.com/AnuSrinivas22/AI-Enhanced-Threat-Hunting-Assistant-for-Security-Analysts>

Navigate to the project directory:

cd AI-Enhanced-DDoS-Threat-Hunting-Assistant

Step 2: Create a Virtual Environment

python -m venv venv

Activate the virtual environment.

Windows:

venv\Scripts\activate

Linux / macOS:

source venv/bin/activate

Step 3: Install Dependencies

pip install -r requirements.txt

Step 4: Configure Project Resources

Place the required dataset CSV files in the data/ directory.

Ensure the trained model artifacts are available in the models/ directory.

Ensure the cybersecurity knowledge resources are available in the knowledge_base/ directory.

Configure the local Llama 3.2 3B model according to the settings used by the reporting module.

Step 5: Run the Application

Launch the Streamlit dashboard:

streamlit run dashboard.py

<img width="509" height="506" alt="Picture1" src="https://github.com/user-attachments/assets/f4d4cef5-4525-4bd7-9f05-3a5028e1e455" />

<img width="589" height="506" alt="Picture" src="https://github.com/user-attachments/assets/96616b01-3b50-4e67-a3bd-2b1cc59c68d9" />


Open the local URL displayed in the terminal to access the application.

🔬 Project Scope and Limitations

The system analyzes supplied CSV-based network traffic records rather than continuously monitoring live network traffic.

Threat classification is based on the trained Random Forest model.

Event correlation identifies potentially related events but does not establish definitive attack attribution.

Risk assessment is based on predefined rules.

RAG retrieval uses keyword-overlap matching rather than embedding-based semantic search.

LLM-generated reports are intended for analyst review and may require verification.

The system does not automatically block traffic or execute network defense mechanisms.

🚀 Future Enhancements

Integration with live network traffic monitoring.

Advanced semantic retrieval using vector databases and embeddings.

Integration with SIEM platforms.

Enhanced event correlation across multiple network sessions.

Improved threat intelligence integration.

Automated alert prioritization with analyst approval.

🎓 Project Information

Project Title: AI-Enhanced DDoS Threat Hunting Assistant for Security Analysts

Domain: Artificial Intelligence, Machine Learning and Cybersecurity

Dataset: CIC-IDS2017

Primary Focus: Machine Learning-Based DDoS Detection and AI-Assisted Threat Hunting

Developed as an academic project to explore the integration of Machine Learning, Multi-Agent Systems, RAG, and LLMs in cybersecurity threat investigation.

Note: This project is intended for academic and research purposes. Its outputs should be treated as decision-support information and reviewed by qualified security analysts.

👩‍💻 Authors:
Anushree S [20231CAI0111]
Gundigi Sreevalli [20231CAI0076]
Subashree S [20231CAI0116]
Varshini N [20231CAI0090]

B.Tech – Computer Science and Engineering  
Specialization: Artificial Intelligence and Advance Computing 
Presidency University, Bengaluru



