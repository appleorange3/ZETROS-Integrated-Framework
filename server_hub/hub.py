import socket
import hashlib
import time
import csv
import os
import traceback
from cryptography.hazmat.primitives import serialization

# Handlers
from server_hub.server_keys import SERVER_PRIVATE_KEY, SERVER_CERT
from server_hub.register_handler import RegistrationHandler
from server_hub.connection_handler import ConnectionHandler

# Helpers
from common.crypto import rsa_decrypt, aes_decrypt
from common.encoding import decode_message

# --- ML LOGGING SYSTEM ---
LOG_FILE = "traffic_data.csv"
# We added 'direction' so ML knows if the packet was a Request or a Response
LOG_HEADERS = ["timestamp", "source_ip", "client_id", "packet_size", "msg_type", "direction"]

def log_traffic(addr, client_id, packet_size, msg_type, direction):
    """Logs full-duplex traffic for ML Anomaly Detection."""
    file_exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(LOG_HEADERS)
        
        writer.writerow([
            time.time(),
            addr[0],
            client_id if client_id else "N/A",
            packet_size,
            msg_type,
            direction # 'INBOUND' (to Hub) or 'OUTBOUND' (to Client)
        ])

# --- INITIALIZATION ---
pub_bytes = SERVER_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(f"DEBUG: Hub Public Key Hash: {hashlib.sha256(pub_bytes).hexdigest()}")

MASTER_CHALLENGES = [b"c1", b"c2", b"c3"]
# Legacy DB for testing
PUF_DB = {"sensor_001": {b"c1": b"r1", b"c2": b"r2", b"c3": b"r3"}}

reg_handler = RegistrationHandler(SERVER_PRIVATE_KEY, SERVER_CERT, MASTER_CHALLENGES, PUF_DB)
conn_handler = ConnectionHandler(SERVER_PRIVATE_KEY)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 5000))

print("🚀 ZETROS Hub running. full-duplex ML Logging enabled.")

while True:
    data, addr = sock.recvfrom(4096)
    inbound_size = len(data)
    
    try:
        # ==========================================================
        # PHASE 1: REGISTRATION (MSG 1, 5, 7, 9)
        # ==========================================================
        if data.startswith(b"MSG1|"):
            log_traffic(addr, None, inbound_size, "MSG1", "INBOUND")
            response = reg_handler.handle_msg1(data[5:])
            sock.sendto(response, addr)
            log_traffic(addr, None, len(response), "MSG2", "OUTBOUND")

        elif data.startswith(b"MSG5|"):
            log_traffic(addr, None, inbound_size, "MSG5", "INBOUND")
            response = reg_handler.handle_msg5(data[5:])
            sock.sendto(response, addr)
            log_traffic(addr, None, len(response), "MSG6", "OUTBOUND")

        elif data.startswith(b"MSG7|"):
            log_traffic(addr, None, inbound_size, "MSG7", "INBOUND")
            for ch_S in list(reg_handler.sessions.keys()):
                try:
                    response = reg_handler.handle_msg7(data[5:], ch_S)
                    msg8 = b"MSG8|" + response
                    sock.sendto(msg8, addr)
                    log_traffic(addr, None, len(msg8), "MSG8", "OUTBOUND")
                    break
                except: continue

        elif data.startswith(b"MSG9|"):
            log_traffic(addr, None, inbound_size, "MSG9", "INBOUND")
            for ch_S in list(reg_handler.sessions.keys()):
                try:
                    reg_handler.handle_msg9(data[5:], ch_S)
                    cid = reg_handler.sessions[ch_S].get('client_id')
                    print(f"✅ [REG_SUCCESS] ID: {cid}")
                    break 
                except: continue

        # ==========================================================
        # PHASE 2: CONNECTION / AUTH (CONN 1, 3)
        # ==========================================================
        elif data.startswith(b"CONN1|"):
            # 1. Log Inbound Request
            log_traffic(addr, None, inbound_size, "CONN1", "INBOUND")
            
            # 2. Process
            response = conn_handler.handle_conn1(data[6:])
            msg2 = b"CONN2|" + response
            
            # 3. Log Outbound Challenge
            sock.sendto(msg2, addr)
            log_traffic(addr, None, len(msg2), "CONN2", "OUTBOUND")
            print(f"📤 CONN2 (Challenge) sent to {addr}")

        elif data.startswith(b"CONN3|"):
            # 1. Log Inbound Answer
            log_traffic(addr, None, inbound_size, "CONN3", "INBOUND")
            
            # 2. Verify
            success, client_id = conn_handler.handle_conn3_with_loop(data[6:])
            
            if success:
                msg4 = b"CONN4|SUCCESS"
                sock.sendto(msg4, addr)
                log_traffic(addr, client_id, len(msg4), "CONN4", "OUTBOUND")
                print(f"✅ [AUTH_SUCCESS] Device {client_id}")
            else:
                msg4 = b"CONN4|FAIL"
                sock.sendto(msg4, addr)
                log_traffic(addr, client_id, len(msg4), "CONN4", "OUTBOUND")
                print(f"🚫 [AUTH_FAILED] for {client_id}")

        else:
            print(f"⚠️ Unknown packet from {addr}")

    except Exception as e:
        print(f"❌ Error: {e}")
        # traceback.print_exc()