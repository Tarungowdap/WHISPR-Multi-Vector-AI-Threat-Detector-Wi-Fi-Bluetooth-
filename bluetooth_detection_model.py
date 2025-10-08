import numpy as np
import json
import time
import datetime
import asyncio
import random
from bleak import BleakScanner, BLEDevice, AdvertisementData # Import AdvertisementData
from typing import Dict, Any, List

# --- 1. CORE DISTANCE CALCULATION CONSTANTS ---
RSSI_AT_1M = -59.0 
PATH_LOSS_EXPONENT = 2.8 

# Bluetooth Major Device Classes (CoD >> 8 & 0b11111)
MAJOR_CLASS_AUDIO_VIDEO = 0x04 
MAJOR_CLASS_PHONE = 0x02

# Placeholder for class determination based on device name
def get_major_class_from_name(device_name: str) -> int:
    """Estimates major class based on device name keywords for threat modeling."""
    if not device_name:
        return 0x00
    name_lower = device_name.lower()
    if "mic" in name_lower or "headset" in name_lower or "speaker" in name_lower:
        return MAJOR_CLASS_AUDIO_VIDEO
    return MAJOR_CLASS_PHONE # Default to phone/generic

def calculate_distance(rssi: float) -> float:
    """Estimates distance (in meters) from RSSI (in dBm) using Log-Distance Path Loss Model."""
    if rssi >= RSSI_AT_1M:
        return 0.1
    
    power = (RSSI_AT_1M - rssi) / (10.0 * PATH_LOSS_EXPONENT)
    distance = 10 ** power
    return distance

# --- 2. THREAT LEVELS & ASSESSMENT ---
def assess_bluetooth_threat(rssi: float, device_class_major: int, device_name: str) -> Dict[str, Any]:
    """Classifies the security threat level based on signal strength and device type."""
    
    distance = calculate_distance(rssi)
    device_name_lower = device_name.lower()
    
    threat_level = "LOW"
    description = f"Safe distance ({distance:.2f}m). Minimal threat risk."
    
    if distance < 0.5:
        if device_class_major == MAJOR_CLASS_AUDIO_VIDEO or "sniffer" in device_name_lower or "mic" in device_name_lower:
            threat_level = "CRITICAL"
            description = f"Proximate Audio/Video, Sniffer, or Mic detected ({distance:.2f}m). IMMEDIATE DANGER."
        else:
            threat_level = "HIGH"
            description = f"Unusually close device ({distance:.2f}m). Potential for proximity attack (e.g., unauthorized pairing)."
            
    elif distance < 3.0:
        if "mic" in device_name_lower or device_class_major == MAJOR_CLASS_AUDIO_VIDEO:
            threat_level = "HIGH"
            description = f"Audio/Mic device detected within room ({distance:.2f}m). Elevated risk of eavesdropping."
        else:
            threat_level = "LOW"
            description = f"Normal proximity detection ({distance:.2f}m). Generally secure."

    return {
        "status": threat_level,
        "distance_m": round(distance, 2),
        "rssi_dbm": rssi,
        "description": description,
        "device_type_code": device_class_major,
        "device_name": device_name
    }

# --- 3. ACTUAL BLUETOOTH SCANNING (FIXED) ---

# Global dictionary to hold the latest scan results (address -> details)
detected_devices: Dict[str, Dict[str, Any]] = {}

def detection_callback(device: BLEDevice, advertisement_data: AdvertisementData):
    """Callback triggered for every advertisement packet received."""
    global detected_devices

    rssi = advertisement_data.rssi
    
    # --- FIX APPLIED HERE ---
    # Prioritize device.name, then advertisement_data.local_name, 
    # and finally fall back to the unique device.address instead of "Unknown Device".
    name = device.name or advertisement_data.local_name or device.address

    # Only process devices with valid RSSI
    if rssi < 0:
        # Store the latest RSSI and name for this unique device address
        detected_devices[device.address] = {
            "name": name,
            "address": device.address,
            "rssi": rssi,
            "device": device # Store the BLEDevice object if needed later
        }

async def perform_scan_and_assess(scan_duration: float = 2.0) -> List[Dict[str, Any]]:
    """Performs a real BLE scan using a callback and assesses the threat."""
    global detected_devices
    detected_devices = {} # Clear previous scan data

    # Use the BleakScanner context manager to start and stop scanning automatically
    scanner = BleakScanner(detection_callback)
    await scanner.start()
    
    # Wait for the specified duration to collect advertisement packets
    await asyncio.sleep(scan_duration)
    
    await scanner.stop()
    
    # Process the collected devices
    results = []
    for address, data in detected_devices.items():
        # Use the latest RSSI and name from the collected data
        name = data["name"]
        rssi = data["rssi"]

        device_class = get_major_class_from_name(name)
        threat_result = assess_bluetooth_threat(rssi, device_class, name)
        threat_result["address"] = address 
        
        results.append(threat_result)
            
    return results

# --- 4. MAIN EXECUTION LOOP ---
async def main_loop():
    output_filename = "threat_results.json"
    iteration = 0
    
    print("--- REAL-TIME BLUETOOTH MONITORING STARTED ---")
    
    while True:
        iteration += 1
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print("-" * 50)
        print(f"--- Live Scan {iteration} initiated at {current_time} ---")

        # Perform the actual hardware scan (2.0s duration)
        scan_results = await perform_scan_and_assess(scan_duration=2.0)
        
        # Structure the final output
        scan_data = {
            "scan_time": current_time,
            "iteration": iteration,
            "devices_detected": len(scan_results),
            "devices": scan_results
        }
        
        # Write the results to a JSON file
        try:
            with open(output_filename, 'w') as f:
                json.dump(scan_data, f, indent=4)
            print(f"Successfully saved {len(scan_results)} devices to {output_filename}")
        except Exception as e:
            # Note: This file save will only work if running outside the sandbox.
            print(f"Error saving JSON output (expected in this environment): {e}")

        # Wait for the remaining time to achieve a ~3s loop cycle (2.0s scan + 1.0s sleep)
        await asyncio.sleep(1.0) 

if __name__ == '__main__':
    try:
        # Run the asynchronous main loop
        asyncio.run(main_loop())
    except ImportError:
        print("\nERROR: Bleak library not found. Please install it using 'pip install bleak' and run this script locally.")
    except Exception as e:
        # Catch exceptions related to permissions or Bluetooth service availability
        print(f"\nFATAL ERROR: Could not run Bluetooth scanner. Please ensure your Bluetooth adapter is on and permissions are granted for the script/terminal.")
        print(f"Detail: {e}")
