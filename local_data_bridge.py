import subprocess
import platform
import re
from datetime import datetime
import time 
import sys
import json # <-- NEW: Import for JSON output
import csv  # <-- NEW: Import for reading/writing CSV

# --- AI Model Functions (unchanged) ---
def classify_security(security_type):
    # ... (Keep classify_security function here) ...
    if security_type is None or str(security_type).strip().upper() in ['N/A', 'NONE', 'OPEN', '']:
        return 0 
    
    security_type = str(security_type).upper()
    
    if 'WEP' in security_type:
        return 0
    
    if 'WPA2' in security_type or 'WPA3' in security_type:
        return 1
    
    return 0

def classify_ssid_type(ssid):
    # ... (Keep classify_ssid_type function here) ...
    if not ssid or ssid.strip() == '<Hidden SSID>' or ssid.strip().upper() == 'N/A':
        return 'Hidden/Unknown'
    
    ssid_lower = ssid.lower()
    
    public_keywords = ['guest', 'free', 'public', 'library', 'cafe', 'airport', 'hotel', 'starbucks', 'mcdonalds']
    if any(k in ssid_lower for k in public_keywords):
        return 'Public/Guest'
        
    mobile_keywords = ['iphone', 'androidap', 'tether', 'hotspot', 'samsung', 'mobile']
    if any(k in ssid_lower for k in mobile_keywords):
        return 'Mobile Hotspot'
        
    corporate_keywords = ['corp', 'ent', 'internal', 'office', 'server', 'hosp', 'bank', 'secure']
    if any(k in ssid_lower for k in corporate_keywords):
        return 'Corporate/Enterprise'
        
    return 'Personal/Residential'

# --- Parsing Functions (unchanged) ---
# ... (Keep parse_windows_output and parse_linux_output functions here) ...

def parse_windows_output(output, timestamp):
    """Parses netsh wlan show networks output."""
    networks = []
    current_network = {"Timestamp": timestamp}
    security_key = "Authentication" 
    
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("SSID "):
            if 'SSID' in current_network: 
                networks.append(current_network)
            current_network = {"Timestamp": timestamp}
            parts = line.split(":", 1)
            if len(parts) == 2:
                current_network["SSID"] = parts[1].strip()
        
        elif "BSSID" in line and "Interface" not in line: 
            parts = line.split(":", 1)
            if len(parts) == 2:
                current_network["BSSID"] = parts[1].strip()
        elif "Signal" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                current_network["Signal (%)"] = parts[1].strip()
        elif security_key in line: 
            parts = line.split(":", 1)
            if len(parts) == 2:
                current_network[security_key] = parts[1].strip()
        elif "Radio type" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                current_network["Radio Type"] = parts[1].strip()
    
    if 'SSID' in current_network:
        networks.append(current_network)

    return networks

def parse_linux_output(output, timestamp):
    """Parses nmcli device wifi list output."""
    networks = []
    lines = output.strip().split('\n')
    
    if len(lines) <= 1:
        return []

    for line in lines[1:]: 
        fields = re.split(r'\s{2,}', line.strip())
        
        if len(fields) >= 8: 
            network = {
                "Timestamp": timestamp,
                "BSSID": fields[0],
                "SSID": fields[1],
                "Channel": fields[3],
                "Signal (%)": fields[5], 
                "Security": fields[7]
            }
            networks.append(network)
    
    return networks


# --- NEW FUNCTION: CSV to JSON Converter ---

def write_to_json(data, json_filename="scan_results.json"):
    """
    Writes the list of network dictionaries directly to a JSON file.
    This file is what the browser will read.
    """
    try:
        with open(json_filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Successfully created JSON file for browser: {json_filename}")
    except Exception as e:
        print(f"Error writing to JSON file: {e}")

# --- Modified Scan Function ---

def scan_and_store_wifi_networks(filename="wifi_scan_data.csv", json_filename="scan_results.json"):
    """
    Scans, classifies, stores to CSV (overwriting), and converts to JSON.
    """
    os_name = platform.system()
    # ... (Command determination logic - UNCHANGED) ...
    if os_name == "Windows":
        command = ['netsh', 'wlan', 'show', 'networks', 'mode=bssid']
        security_column = "Authentication"
    elif os_name == "Linux":
        command = ['nmcli', '-t', '-f', 'BSSID,SSID,CHAN,SIGNAL,SECURITY', 'device', 'wifi', 'list']
        security_column = "Security"
    elif os_name == "Darwin": # macOS
        print("macOS Wi-Fi scan parsing is complex and has been skipped.")
        return
    else:
        print(f"Unsupported OS for structured Wi-Fi scanning: {os_name}")
        return

    print(f"Host OS: {os_name}. Executing command: {' '.join(command)}")

    try:
        # 2. Execute the command
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 3. Parse the output
        if os_name == "Windows":
            parsed_data = parse_windows_output(result.stdout, timestamp)
        elif os_name == "Linux":
            parsed_data = parse_linux_output(result.stdout, timestamp)
        else:
             parsed_data = []

        if not parsed_data:
            print("No Wi-Fi networks found or parsing failed.")
            # Clear previous JSON output if no networks found
            write_to_json([], json_filename) 
            return
            
        # 4. Apply AI Models (Classification)
        for network in parsed_data:
            security_string = network.get(security_column, 'N/A')
            network['Is_Secure'] = classify_security(security_string) 
            ssid_string = network.get("SSID", '')
            network['SSID_Type'] = classify_ssid_type(ssid_string) 


        # 5. Write to CSV file (OVERWRITING)
        fieldnames = ["Timestamp", "OS", "SSID", "BSSID", "Signal (%)", "Authentication", "Security", "Channel", "Radio Type", "Is_Secure", "SSID_Type"]
        
        with open(filename, 'w', newline='') as f: # Added newline='' for better CSV compatibility
            writer = csv.writer(f)
            # Write the header
            writer.writerow(fieldnames)

            for network in parsed_data:
                # Use a dict comprehension to get values in the correct order for the CSV writer
                row = [network.get(field, 'N/A') for field in fieldnames]
                writer.writerow(row)

        print(f"\nSuccessfully stored {len(parsed_data)} network records to CSV: {filename}")
        
        # 6. Write the same data to JSON for the browser
        write_to_json(parsed_data, json_filename)
        

    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        # ... (error handling) ...
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    try:
        while True:
            print("\n==================================================")
            print("--- Starting Wi-Fi Scan Cycle (Overwriting files) ---")
            print("==================================================")
            # Pass the JSON filename to the scan function
            scan_and_store_wifi_networks(json_filename="scan_results.json") 
            print("--- Scan Cycle Complete. Waiting 3 seconds... ---")
            time.sleep(3) 
    except KeyboardInterrupt:
        print("\nWi-Fi scanning stopped by user (Ctrl+C). Exiting.")
        sys.exit(0)