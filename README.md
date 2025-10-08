# WHISPR-Multi-Vector-AI-Threat-Detector-Wi-Fi-Bluetooth-
WHISPR (Wireless Hiding Protocol Scanner) is a full-stack security diagnostic tool built to detect subtle surveillance threats at the physical layer (Wi-Fi and Bluetooth). It operationalizes an Anomaly Detection model and integrates real-time scanning to provide immediate threat reports.

Core Features
AI Anomaly Scoring: Deploys a One-Class SVM model (joblib) to score Wi-Fi signals for subtle anomalies indicative of honeypots.

Real-Time Bluetooth Threat: Uses bleak to calculate distance from RSSI, classifying proximate devices (within 10m) as CRITICAL or HIGH threat risks.

Real-Time Dashboard: A Flask + SocketIO backend pushes live updates to a reactive, neon-themed web interface.

⚠️ Current Status: Surface Level PoC
This version is a Proof-of-Concept (PoC) focused on demonstrating the full application pipeline and model deployment. The advanced AI features (like RSSI variance and probe rate) are heuristically simulated in the Flask app and not calculated from raw scan data.

🚀 Get Started
Dependencies: pip install Flask numpy joblib bleak

Run: Launch local_data_bridge.py, bluetooth_detection_model.py, and app.py in three terminals.

View: Navigate to http://127.0.0.1:5000/scan.html

![Alt text](https://link-to-your-image.png)

