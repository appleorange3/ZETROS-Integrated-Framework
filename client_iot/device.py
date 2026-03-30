import os
import socket
import json
import sys
from common.puf import PUF
from client_iot.register_client import RegistrationClient
from client_iot.connection_client import ConnectionClient
from server_hub.server_keys import SERVER_PUBLIC_KEY
from authority_ca.ca_keys import CA_PUBLIC_KEY

# --- Configuration ---
VAULT_PATH = "device_vault.json"
SERVER_ADDR = ("127.0.0.1", 5000)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def run_connection_phase(client_id, puf):
    """Handles the Phase 2 Authentication handshake."""
    print(f"🚀 [PHASE 2] Starting Connection Handshake for: {client_id}")
    
    conn_client = ConnectionClient(puf, client_id, SERVER_PUBLIC_KEY)

    # ---------------- CONN 1 ----------------
    msg1 = conn_client.msg1_connect()
    sock.sendto(msg1, SERVER_ADDR)
    print("📤 CONN1 sent (Connection Request)")

    # ---------------- CONN 2 ----------------
    msg2_raw, _ = sock.recvfrom(4096)
    if not msg2_raw.startswith(b"CONN2|"):
        print("❌ Unexpected message received instead of CONN2")
        return

    print("📩 CONN2 received (Challenge Index)")
    
    # ---------------- CONN 3 ----------------
    # solve using PUF
    msg3 = conn_client.process_msg2_challenge(msg2_raw[6:]) 
    sock.sendto(msg3, SERVER_ADDR)
    print("📤 CONN3 sent (PUF Hardware Response)")

    # ---------------- CONN 4 ----------------
    msg4_raw, _ = sock.recvfrom(4096)
    if msg4_raw.startswith(b"CONN4|SUCCESS"):
        print("✅ [AUTH SUCCESS] Server verified physical hardware. Connection established.")
    else:
        print("🚫 [AUTH FAILED] Server rejected the hardware fingerprint.")

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    if os.path.exists(VAULT_PATH):
        print("🤖 Known Device detected. Loading Vault...")
        with open(VAULT_PATH, "r") as f:
            vault = json.load(f)
        
        # Initialize PUF with the physical seed from the vault
        puf = PUF("known_device", seed=bytes.fromhex(vault['puf_seed']))
        client_id = vault['client_id']
        
        run_connection_phase(client_id, puf)
        
        # --- THE FIX: Exit after Phase 2 attempt ---
        print("🏁 Phase 2 session complete. Exiting.")
        sys.exit(0)

    else:
        print("🆕 No Vault found. Starting Phase 1 Registration...")
        
        # 1. Initialize for Phase 1
        puf = PUF("sensor_001")
        client = RegistrationClient(puf, SERVER_PUBLIC_KEY, CA_PUBLIC_KEY)

        print("[*] Starting ZETROS registration...")

        # ---------------- MSG1 ----------------
        sock.sendto(client.msg1_hello(), SERVER_ADDR)

        # ---------------- MSG2 ----------------
        msg2, _ = sock.recvfrom(4096)
        cert = client.process_msg2(msg2)

        # ---------------- MSG3 & MSG4 (CA Simulation) ----------------
        msg3 = client.msg3_ca_request(cert)
        from authority_ca.ca_service import handle_verification_request
        msg4 = handle_verification_request(msg3)
        client.process_msg4(msg4)

        # ---------------- MSG5 ----------------
        sock.sendto(client.msg5_key_exchange(), SERVER_ADDR)

        # ---------------- MSG6 ----------------
        msg6, _ = sock.recvfrom(4096)
        C_r = client.process_msg6(msg6)

        # ---------------- MSG7 ----------------
        sock.sendto(client.msg7_response(C_r), SERVER_ADDR)

        # ---------------- MSG8 ----------------
        msg8_raw, _ = sock.recvfrom(4096)
        print("📩 MSG8 received")

        if msg8_raw.startswith(b"MSG8|"):
            r_S1 = client.process_msg8(msg8_raw[5:]) 
            print(f"[✔] Assigned ID: {client.client_id}")

            # ---------------- MSG9 ----------------
            msg9 = client.msg9_finish(r_S1)
            sock.sendto(msg9, SERVER_ADDR)
            print("📤 MSG9 sent")

            # --- SAVE VAULT FOR FUTURE USE ---
            vault_data = {
                "client_id": client.client_id,
                "puf_seed": puf._seed.hex() 
            }
            with open(VAULT_PATH, "w") as f:
                json.dump(vault_data, f, indent=4)

            print("📂 Device Vault created. I now remember my identity for Phase 2!")
        else:
            print("❌ Error: Registration failed at MSG8 stage.")