import socket
import hashlib
import time
import csv
import os
import math
from collections import Counter
from cryptography.hazmat.primitives import serialization

# Handlers
from server_hub.server_keys import SERVER_PRIVATE_KEY, SERVER_CERT
from server_hub.register_handler import RegistrationHandler
from server_hub.connection_handler import ConnectionHandler

# Helpers
from common.crypto import rsa_decrypt, aes_decrypt
from common.encoding import decode_message

# --- ADVANCED ML LOGGING SYSTEM ---
LOG_FILE = "./data_sahil/traffic_data.csv"
LOG_HEADERS = [
    "timestamp", "iat", "source_ip", "client_id", 
    "msg_type", "direction", "packet_size", "entropy", "status"
]

# Track timing for IAT (Inter-Arrival Time)
last_packet_time = {}

def calculate_entropy(data):
    """Calculates Shannon Entropy to detect data randomness/encryption."""
    if not data: return 0
    counts = Counter(data)
    probs = [c / len(data) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

def log_traffic(addr, client_id, packet_size, msg_type, direction, payload=b"", status="PENDING"):
    """Advanced logger with timing, entropy, and security status."""
    global last_packet_time
    now = time.time()
    ip = addr[0]
    
    # Calculate Inter-Arrival Time (IAT)
    iat = now - last_packet_time.get(ip, now)
    last_packet_time[ip] = now
    
    # Calculate Payload Entropy
    entropy = calculate_entropy(payload)
    
    file_exists = os.path.isfile(LOG_FILE)
    # Ensure directory exists
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    with open(LOG_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(LOG_HEADERS)
        
        writer.writerow([
            f"{now:.6f}",    # High-precision timestamp
            f"{iat:.6f}",    # Gap since last packet (detects bots)
            ip, 
            client_id if client_id else "N/A", 
            msg_type, 
            direction, 
            packet_size, 
            f"{entropy:.4f}", # High entropy = Encrypted, Low = Plain/Attack
            status           # SUCCESS, FAIL, or PENDING
        ])

# --- INITIALIZATION ---
pub_bytes = SERVER_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(f"DEBUG: Hub Public Key Hash: {hashlib.sha256(pub_bytes).hexdigest()}")

MASTER_CHALLENGES = [b"c1", b"c2", b"c3"]
PUF_DB = {"sensor_001": {b"c1": b"r1", b"c2": b"r2", b"c3": b"r3"}}

reg_handler = RegistrationHandler(SERVER_PRIVATE_KEY, SERVER_CERT, MASTER_CHALLENGES, PUF_DB)
conn_handler = ConnectionHandler(SERVER_PRIVATE_KEY)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 5000))

print("🚀 ZETROS Hub running. Advanced ML & Blockchain logging active...")

while True:
    data, addr = sock.recvfrom(4096)
    inbound_size = len(data)
    
    try:
        # ==========================================================
        # PHASE 1: REGISTRATION (MSG 1, 5, 7, 9)
        # ==========================================================
        if data.startswith(b"MSG1|"):
            log_traffic(addr, None, inbound_size, "MSG1", "INBOUND", payload=data)
            response = reg_handler.handle_msg1(data[5:])
            sock.sendto(response, addr)
            log_traffic(addr, None, len(response), "MSG2", "OUTBOUND", payload=response)

        elif data.startswith(b"MSG5|"):
            log_traffic(addr, None, inbound_size, "MSG5", "INBOUND", payload=data)
            response = reg_handler.handle_msg5(data[5:])
            sock.sendto(response, addr)
            log_traffic(addr, None, len(response), "MSG6", "OUTBOUND", payload=response)

        elif data.startswith(b"MSG7|"):
            log_traffic(addr, None, inbound_size, "MSG7", "INBOUND", payload=data)
            for ch_S in list(reg_handler.sessions.keys()):
                try:
                    response = reg_handler.handle_msg7(data[5:], ch_S)
                    msg8 = b"MSG8|" + response
                    sock.sendto(msg8, addr)
                    log_traffic(addr, None, len(msg8), "MSG8", "OUTBOUND", payload=msg8)
                    break
                except: continue

        elif data.startswith(b"MSG9|"):
            log_traffic(addr, None, inbound_size, "MSG9", "INBOUND", payload=data)
            for ch_S in list(reg_handler.sessions.keys()):
                try:
                    reg_handler.handle_msg9(data[5:], ch_S)
                    cid = reg_handler.sessions[ch_S].get('client_id')
                    log_traffic(addr, cid, 0, "REG_COMPLETE", "INTERNAL", status="SUCCESS")
                    print(f"✅ [REG_SUCCESS] ID: {cid}")
                    break 
                except: continue

        # ==========================================================
        # PHASE 2: CONNECTION / AUTH (CONN 1, 3)
        # ==========================================================
        elif data.startswith(b"CONN1|"):
            # A. Decrypt first to identify the user for the log
            try:
                decrypted = decode_message(rsa_decrypt(SERVER_PRIVATE_KEY, data[6:]))
                claimed_id = decrypted.get('client_id')
            except: claimed_id = "MALFORMED_ID"

            # B. Log Inbound Request with the ID
            log_traffic(addr, claimed_id, inbound_size, "CONN1", "INBOUND", payload=data)
            
            # C. Process
            response = conn_handler.handle_conn1(data[6:])
            msg2 = b"CONN2|" + response
            
            # D. Send and Log Challenge
            sock.sendto(msg2, addr)
            log_traffic(addr, claimed_id, len(msg2), "CONN2", "OUTBOUND", payload=msg2)
            print(f"📤 CONN2 (Challenge) sent to {addr}")

        elif data.startswith(b"CONN3|"):
            # A. Verify
            success, client_id = conn_handler.handle_conn3_with_loop(data[6:])
            
            # B. Log the Answer
            log_traffic(addr, client_id, inbound_size, "CONN3", "INBOUND", payload=data)
            
            if success:
                msg4 = b"CONN4|SUCCESS"
                sock.sendto(msg4, addr)
                log_traffic(addr, client_id, len(msg4), "CONN4", "OUTBOUND", payload=msg4, status="SUCCESS")
                print(f"✅ [AUTH_SUCCESS] Device {client_id}")
            else:
                msg4 = b"CONN4|FAIL"
                sock.sendto(msg4, addr)
                log_traffic(addr, client_id, len(msg4), "CONN4", "OUTBOUND", payload=msg4, status="FAILED")
                print(f"🚫 [AUTH_FAILED] for {client_id}")

        else:
            print(f"⚠️ Unknown packet from {addr}")

    except Exception as e:
        print(f"❌ Error: {e}")