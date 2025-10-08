import numpy as np
import joblib
import json
from flask import Flask, request, jsonify
from flask_cors import CORS 
from datetime import datetime
import os
import time
import threading # New: For background file monitoring
from flask_socketio import SocketIO, emit # New: For real-time updates

# --- Initialize Flask App ---
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}) # Ensure CORS allows SocketIO connection
socketio = SocketIO(app, cors_allowed_origins="*") # Initialize SocketIO

# --- 1. CONFIGURATION ---

WIFI_DATA_FILE = 'scan_results.json' 
BT_DATA_FILE = 'threat_results.json'
THREAT_THRESHOLD = -0.01 
MAX_FILE_READ_ATTEMPTS = 5 
BT_PROXIMITY_LIMIT = 10.0

# --- 2. AI & THREADING COMPONENTS ---
MODEL, SCALER, PCA = None, None, None 
# Variables for file monitoring
last_modified_time = 0.0
stop_event = threading.Event()


try:
    SCALER = joblib.load('whispr_scaler.pkl')
    PCA = joblib.load('whispr_pca.pkl')
    MODEL = joblib.load('whispr_model.pkl')
    print("AI Core components loaded successfully. Server starting...")
except FileNotFoundError as e:
    print(f"\n[CRITICAL ERROR] Failed to load model files: {e}")
    exit(1)
except Exception as e:
    print(f"[CRITICAL ERROR] An unexpected error occurred during model loading: {e}")


# --- 3. DATA ACQUISITION HELPER FUNCTIONS ---

def get_latest_data(file_path):
    """Reads the entire content of a specified JSON file."""
    for attempt in range(MAX_FILE_READ_ATTEMPTS):
        try:
            if not os.path.exists(file_path):
                 return None
                 
            with open(file_path, 'r') as f:
                data = json.load(f) 
                return data
                
        except (IOError, json.JSONDecodeError):
            time.sleep(0.1) 
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] FATAL READ ERROR for {file_path}: {e}")
            break
    return None

def get_latest_scan_data():
    """Reads Wi-Fi scan data from the main bridge file."""
    return get_latest_data(WIFI_DATA_FILE)


# --- 4. WI-FI PROCESSING ---

def assess_signal(raw_features: np.ndarray):
    """Scores a single 5-feature vector using the loaded OC-SVM model."""
    if MODEL is None:
        return "PROCESSING_ERROR", 999.0
    try:
        signal_data = raw_features.reshape(1, -1) 
        scaled_data = SCALER.transform(signal_data)
        processed_data = PCA.transform(scaled_data)
        anomaly_score = MODEL.decision_function(processed_data)[0]
        risk_level = "THREAT" if anomaly_score < THREAT_THRESHOLD else "BENIGN"
        return risk_level, anomaly_score
    except Exception as e:
        print(f"Prediction processing error: {e}")
        return "PROCESSING_ERROR", 999.0

def process_wifi_data(full_network_list):
    """Runs the AI scoring on the connected Wi-Fi network and structures the output."""
    
    if not full_network_list:
        return {
            "result": "NO_NETWORKS_FOUND", 
            "score": 0.0, 
            "raw_features": [-1.0]*5,
            "ssid": "N/A",
            "networks": [],
            "threat_tier": "LOW"
        }

    connected_network = full_network_list[0]
    
    security_value = str(connected_network.get('Authentication', 'N/A')).lower()
    signal_percent_str = str(connected_network.get('Signal (%)', '70%')).replace('%', '').strip()
    ssid_value = connected_network.get('SSID', '').lower()
    
    try:
        signal_percent = float(signal_percent_str)
    except ValueError:
        signal_percent = 70.0
        
    # Security/Threat Tier Logic
    is_secure = 'wpa' in security_value or 'wpa2' in security_value or 'wpa3' in security_value
    is_open = not is_secure
    
    public_keywords = ['guest', 'free', 'public', 'cafe', 'airport', 'hotel']
    is_public_open = is_open and any(k in ssid_value for k in public_keywords)
    
    # Initialize features for BENIGN/SECURE
    rssi_variance = 1.5
    probe_rate = 10
    oui_trust = 9
    anomaly_flag = 0
    threat_tier = "LOW"
    
    if is_open:
        # If open, inject suspicious features unless it's a known public type
        if is_public_open:
            # Mild Threat (Known public Wi-Fi, low anomaly score)
            rssi_variance = 5.0 # Slightly higher variance for busy public area
            probe_rate = 30
            oui_trust = 7
            threat_tier = "MILD" 
        else:
            # High Threat (Generic open network, high anomaly score expected)
            rssi_variance = 25.0
            probe_rate = 150
            oui_trust = 1
            anomaly_flag = 1
            threat_tier = "HIGH"
            
    # Simulate RSSI Mean based on Signal (%)
    rssi_mean = -100 + (signal_percent * 0.7)
    
    raw_features_to_score = np.array([
        rssi_mean,
        rssi_variance,
        probe_rate,
        oui_trust,
        anomaly_flag
    ])

    risk_level, score = assess_signal(raw_features_to_score)

    # If AI flags it as a THREAT (highest tier), override security logic
    if risk_level == "THREAT":
        threat_tier = "CRITICAL"
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Wi-Fi Processed -> Network: {connected_network['SSID']}, AI Result: {risk_level}, Threat Tier: {threat_tier}")

    return {
        "result": risk_level,
        "score": float(score),
        "raw_features": raw_features_to_score.tolist(),
        "ssid": connected_network['SSID'],
        "networks": full_network_list,
        "threat_tier": threat_tier # New field to drive UI severity
    }


# --- 5. BACKGROUND FILE MONITORING THREAD (WebSockets) ---

def check_for_file_updates():
    """Runs in a background thread to check the file for changes and push updates."""
    global last_modified_time
    
    while not stop_event.is_set():
        try:
            current_modified_time = os.path.getmtime(WIFI_DATA_FILE)
            
            # Check if the file has been modified since the last check
            if current_modified_time > last_modified_time:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] FILE CHANGE DETECTED. Processing and pushing new data...")
                
                # 1. Process the new data
                full_network_list = get_latest_scan_data()
                if full_network_list:
                    # 2. Process and score the network data
                    report_data = process_wifi_data(full_network_list)
                    
                    # 3. Emit the data to all connected clients
                    socketio.emit('new_wifi_data', report_data)
                    
                    # 4. Update the last known modified time
                    last_modified_time = current_modified_time
                
            time.sleep(1) # Check the file once every second
            
        except FileNotFoundError:
            # Handle case where the file hasn't been created yet
            time.sleep(5) 
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Background thread error: {e}")
            time.sleep(5)


# --- 6. FLASK API ENDPOINTS ---

@app.route('/score_signal', methods=['POST'])
def score_signal_endpoint():
    """
    Initial Endpoint for Wi-Fi ONLY (called once by scan.html on initial load).
    This endpoint performs the first scan and starts the background thread if not running.
    """
    global last_modified_time
    
    # 1. Perform the initial scan processing
    wifi_raw = get_latest_scan_data()
    wifi_processed = process_wifi_data(wifi_raw) if wifi_raw else process_wifi_data([])
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] API SUCCESS -> Initial Wi-Fi Scan returned.")

    # 2. Start the background thread if it's not already running
    if not any(t.name == 'file_monitor' for t in threading.enumerate()):
        try:
            if os.path.exists(WIFI_DATA_FILE):
                 last_modified_time = os.path.getmtime(WIFI_DATA_FILE)
            
            monitor_thread = threading.Thread(target=check_for_file_updates, name='file_monitor')
            monitor_thread.daemon = True # Important: allows program to exit if main thread stops
            monitor_thread.start()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Started background file monitor thread.")
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Failed to start thread: {e}")

    return jsonify(wifi_processed)


# Existing Bluetooth endpoint (retained for scan2.html)
@app.route('/bluetooth_scan', methods=['GET'])
def bluetooth_scan_endpoint():
    """
    Endpoint for Bluetooth ONLY (called by scan2.html).
    """
    bt_raw_data = get_latest_data(BT_DATA_FILE) 

    if not bt_raw_data:
        return jsonify({
            "metadata": { "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "iteration": 0 },
            "bluetooth": { "devices_detected": 0, "devices": [], "max_threat": "LOW" }
        })

    # 1. Apply 10m Proximity Filter
    filtered_devices = [
        device for device in bt_raw_data.get('devices', [])
        if device.get('distance_m', BT_PROXIMITY_LIMIT + 1) <= BT_PROXIMITY_LIMIT
    ]

    # 2. Determine Max Threat
    max_threat = "LOW"
    for device in filtered_devices:
        if device['status'] == 'CRITICAL':
            max_threat = 'CRITICAL'
            break
        elif device['status'] == 'HIGH':
            max_threat = 'HIGH'

    # 3. Structure the output for scan2.html
    output = {
        "metadata": {
            "scan_time": bt_raw_data.get('scan_time', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "iteration": bt_raw_data.get('iteration', 1)
        },
        "bluetooth": {
            "devices_detected": len(filtered_devices),
            "devices": filtered_devices,
            "max_threat": max_threat
        }
    }
    
    return jsonify(output)


# --- 7. RUN SERVER ---

if __name__ == '__main__':
    # Use socketio.run instead of app.run for WebSockets to work
    print(f"\n[SERVER] Starting SocketIO server on http://127.0.0.1:5000")
    socketio.run(app, host='127.0.0.1', port=5000, debug=True, use_reloader=False)