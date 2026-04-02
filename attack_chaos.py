import socket
import json
import os
import time
from common.puf import PUF
from client_iot.connection_client import ConnectionClient
from server_hub.server_keys import SERVER_PUBLIC_KEY

# --- Configuration ---
VAULT_PATH = "device_vault.json"
SERVER_ADDR = ("127.0.0.1", 5000)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def run_flood_attack(client_id, puf):
    """Simulates a DDoS/Flood attack by slamming the Hub with CONN1 packets."""
    conn_client = ConnectionClient(puf, client_id, SERVER_PUBLIC_KEY)
    
    print(f"🔥 CHAOS MODE: Starting flood attack from {client_id}")
    print("Press Ctrl+C to stop the attack.")
    
    packet_count = 0
    start_time = time.time()

    try:
        while True:
            # Generate and send CONN1 as fast as possible
            msg1 = conn_client.msg1_connect()
            sock.sendto(msg1, SERVER_ADDR)
            
            packet_count += 1
            if packet_count % 10 == 0:
                elapsed = time.time() - start_time
                pps = packet_count / elapsed
                print(f"🚀 Sent {packet_count} packets... ({pps:.2f} packets/sec)")
            
            # NO time.sleep() here — that's the point!
    except KeyboardInterrupt:
        print(f"\n🛑 Attack stopped. Total packets sent: {packet_count}")

if __name__ == "__main__":
    if not os.path.exists(VAULT_PATH):
        print("❌ Error: No Vault found. Run device.py first to register.")
    else:
        with open(VAULT_PATH, "r") as f:
            vault = json.load(f)
        
        puf = PUF("known_device", seed=bytes.fromhex(vault['puf_seed']))
        client_id = vault['client_id']
        
        run_flood_attack(client_id, puf)