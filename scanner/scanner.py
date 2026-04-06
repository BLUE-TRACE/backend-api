import bluetooth
import requests
import time
import sys # Added this to allow the script to cleanly shut itself down

# --- CONFIGURATION ---
BACKEND_URL = "http://localhost:5000/api/scan"
SCAN_DURATION = 10
INTERVAL_BETWEEN_SCANS = 8 

# Notice we added 'session_id' inside the parentheses here!
def scan_and_send(session_id):
    print(f"\n🔍 Scanning room for Classic Bluetooth devices ({SCAN_DURATION} seconds)...")
    
    try:
        nearby_devices = bluetooth.discover_devices(duration=SCAN_DURATION, lookup_names=False, flush_cache=True)
        mac_addresses = [addr for addr in nearby_devices]
        
        print(f"📡 Found {len(mac_addresses)} devices. Sending to backend...")

        if len(mac_addresses) == 0:
            print("⚠️ No devices found. Waiting for next cycle.")
            return

        # Prepare the data using the dynamic session_id
        payload = {
            "sessionId": session_id,
            "macAddresses": mac_addresses
        }

        response = requests.post(BACKEND_URL, json=payload)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Backend Success: {data.get('message')} (Newly marked: {data.get('newStudentsMarked', 'N/A')})")
            
        # BONUS FIX: If the backend says the session is closed, kill the scanner!
        elif response.status_code == 400 and "closed" in response.text.lower():
            print("\n🛑 Backend reports this session is now CLOSED. Shutting down scanner automatically.")
            sys.exit(0) # This cleanly exits the program
            
        else:
            print(f"❌ Backend Error: {response.text}")
            
    except Exception as e:
        print(f"🚨 ERROR during scan or backend connection: {e}")

def main():
    print("🚀 BlueTrace Python Scanner Started (PyBluez Edition)!\n")
    
    # --- THE NEW LOGIC ---
    # 1. Pause the script and ask the lecturer to type in the Session ID
    raw_input = input("👉 Enter the Active Session ID from your Web Dashboard: ")
    
    # 2. Safety check: Ensure they actually typed a number and not letters
    if not raw_input.isdigit():
        print("❌ Invalid input. You must enter a number. Please restart the script.")
        return

    # 3. Convert their text input into an actual integer number
    session_id = int(raw_input)
    
    print(f"\n✅ Scanner locked onto Session {session_id}. Press Ctrl+C to stop.")
    
    try:
        while True:
            # 4. Pass the session_id into our scanning function so it knows where to send data
            scan_and_send(session_id)
            
            print(f"⏳ Waiting {INTERVAL_BETWEEN_SCANS} seconds before next scan...\n")
            time.sleep(INTERVAL_BETWEEN_SCANS)
            
    except KeyboardInterrupt:
        print("\n🛑 Scanner stopped by user.")

if __name__ == "__main__":
    main()