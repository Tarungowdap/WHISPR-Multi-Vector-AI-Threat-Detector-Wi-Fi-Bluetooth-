import numpy as np
import joblib
import pandas as pd
import os

# --- 1. FEATURE LIST CONFIGURATION (Must match training features) ---
FEATURE_COLUMNS = [
    'RSSI_MEAN', 'RSSI_VARIANCE', 'PROBE_FREQ_RATE', 
    'OUI_TRUST_SCORE', 'PROTOCOL_ANOMALY_FLAG',
]

# --- 2. LOAD AI COMPONENTS (Phase 4, Step 1) ---
try:
    # Load the saved transformation and model objects
    SCALER = joblib.load('whispr_scaler.pkl')
    PCA = joblib.load('whispr_pca.pkl')
    MODEL = joblib.load('whispr_model.pkl')
    print("AI Core components loaded successfully.")
except FileNotFoundError:
    print("ERROR: One or more .pkl model files not found. Ensure whispr_ai_training_core.py was run.")
    SCALER, PCA, MODEL = None, None, None

def assess_live_signal(raw_features: np.ndarray) -> tuple[str, float]:
    """
    Takes a new network signal's features and returns its threat assessment.
    
    Args:
        raw_features: A 1D NumPy array or list containing the 5 features 
                      in the exact order of FEATURE_COLUMNS.
                      Example: [-35.0, 15.0, 120, 2, 1]
    
    Returns:
        A tuple (risk_level, anomaly_score), where risk_level is 'THREAT' or 'BENIGN'.
    """
    if MODEL is None:
        return "ERROR", 999.0

    # Reshape for single-sample prediction
    signal_data = raw_features.reshape(1, -1) 

    # --- 3. APPLY SAVED TRANSFORMATIONS (Phase 4, Step 3) ---
    
    # 3.1 Scaling (Must use the saved scaler object)
    scaled_data = SCALER.transform(signal_data)
    
    # 3.2 Dimensionality Reduction (Must use the saved PCA object)
    processed_data = PCA.transform(scaled_data)
    
    # --- 4. SCORING & ALERTING (Phase 4, Step 4) ---
    
    # Get continuous score (distance to boundary). Negative is THREAT.
    anomaly_score = MODEL.decision_function(processed_data)[0]
    
    # Set the threshold based on the model's behavior. 
    # For a tight nu=0.01 model, anything less than 0 is a strong anomaly.
    # We lower the threshold to catch anomalies with less deviation.
    THREAT_THRESHOLD = -0.1  # Adjusted from -0.5 to make detection more sensitive
    
    if anomaly_score < THREAT_THRESHOLD:
        risk_level = "THREAT"  # Triggers vibration and Detailed Report link
    else:
        risk_level = "BENIGN"
        
    return risk_level, anomaly_score

# --- DEMONSTRATION OF LIVE USAGE ---
if __name__ == '__main__':
    print("\n--- WHISPR Live Signal Assessment Demonstration ---")
    
    # 1. Simulate a BENIGN Signal (Low Variance, High Trust)
    benign_signal = np.array([-60.0, 1.5, 10, 9, 0]) 
    level_b, score_b = assess_live_signal(benign_signal)
    
    print(f"\n[BENIGN SIMULATION]")
    print(f"Features: RSSI_VAR={benign_signal[1]}, OUI_SCORE={benign_signal[3]}")
    print(f"Result: {level_b} | Score: {score_b:.4f}")

    # 2. Simulate an ANOMALY Signal (High Variance, Low Trust, Aggressive)
    anomaly_signal = np.array([-30.0, 20.0, 150, 1, 1]) 
    level_a, score_a = assess_live_signal(anomaly_signal)
    
    print(f"\n[THREAT SIMULATION (Honeypot/Sniffer)]")
    print(f"Features: RSSI_VAR={anomaly_signal[1]}, OUI_SCORE={anomaly_signal[3]}")
    print(f"Result: {level_a} | Score: {score_a:.4f}")
    
    if level_a == 'THREAT':
        print("\nSUCCESS: Model correctly identified the high-risk anomaly.")
    else:
        print("\nFAILURE: Model failed to detect the anomaly.")