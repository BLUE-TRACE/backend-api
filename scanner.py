import sys
import requests
import time
import bluetooth

# --- CONFIGURATION ---
BACKEND_URL = "http://localhost:5000/api/scan"
SCAN_DURATION = 10
INTERVAL_BETWEEN_SCANS = 8 

def scan_and_send(session_id):
    print(f"\n Scanning room for Classic Bluetooth devices ({SCAN_DURATION} seconds)...")
    
    try:
        nearby_devices = bluetooth.discover_devices(duration=SCAN_DURATION, lookup_names=False, flush_cache=True)
        mac_addresses = [addr for addr in nearby_devices]
        
        print(f" Found {len(mac_addresses)} devices. Sending to backend...")

        if len(mac_addresses) == 0:
            print(" No devices found. Waiting for next cycle.")
            return

        # Prepare the data using the dynamic session_id
        payload = {
            "sessionId": session_id,
            "macAddresses": mac_addresses
        }

        response = requests.post(BACKEND_URL, json=payload)
        
        if response.status_code == 200:
            data = response.json()
            print(f" Backend Success: {data.get('message')} (Newly marked: {data.get('newStudentsMarked', 'N/A')})")
            
        # If the backend says the session is closed, kill the scanner!
        elif response.status_code == 400 and "closed" in response.text.lower():
            print("\n Backend reports this session is now CLOSED. Shutting down scanner automatically.")
            sys.exit(0) # This cleanly exits the invisible Node.js background process
            
        else:
            print(f" Backend Error: {response.text}")
            
    except Exception as e:
        print(f" ERROR during scan or backend connection: {e}")

def main():
    print("BlueTrace Python Scanner Started (PyBluez Edition)!\n")
    
    # --- THE NEW AUTOMATED LOGIC ---
    # 1. Grab the session ID passed by Node.js child_process
    if len(sys.argv) < 2:
        print(" Error: No session ID provided by Node.js!")
        sys.exit(1)

    raw_input = sys.argv[1]
    
    # 2. Safety check: Ensure Node.js passed a valid number
    if not raw_input.isdigit():
        print(f" Invalid session ID provided: '{raw_input}'. Must be a number.")
        sys.exit(1)

    # 3. Convert into an actual integer number
    session_id = int(raw_input)
    
    print(f"\n Scanner automatically locked onto Session {session_id}.")
    print("Running in background... (will auto-close when session ends)")
    
    try:
        while True:
            # 4. Pass the session_id into our scanning function so it knows where to send data
            scan_and_send(session_id)
            
            print(f" Waiting {INTERVAL_BETWEEN_SCANS} seconds before next scan...\n")
            time.sleep(INTERVAL_BETWEEN_SCANS)
            
    except KeyboardInterrupt:
        print("\n Scanner stopped.")

if __name__ == "__main__":
    main()