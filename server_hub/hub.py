import socket
import hashlib
import time
import csv
import os
import math
import pandas as pd
import joblib
from collections import Counter, deque
from cryptography.hazmat.primitives import serialization

# Handlers
from server_hub.server_keys import SERVER_PRIVATE_KEY, SERVER_CERT
from server_hub.register_handler import RegistrationHandler
from server_hub.connection_handler import ConnectionHandler

# Helpers
from common.crypto import rsa_decrypt, aes_decrypt
from common.encoding import decode_message

# --- SAHIL'S ML MODEL INTEGRATION ---
# Ensure Sahil's model.pkl and model.py are in the correct path
try:
    # We import Sahil's logic directly
    from ml_sahil.model import predict as ml_predict
    ML_ACTIVE = True
    print("🧠 ML Model loaded and active.")
except ImportError:
    ML_ACTIVE = False
    print("⚠️ Warning: ml_sahil.model not found. ML detection disabled.")

# Memory for sliding window: { ip_address: deque([(timestamp, size, direction), ...]) }
PACKET_WINDOW = {}
WINDOW_SIZE = 10  # We analyze behavior every 10 packets

# --- ADVANCED ML LOGGING SYSTEM ---
LOG_FILE = "./data_sahil/traffic_data.csv"
LOG_HEADERS = [
    "timestamp", "iat", "source_ip", "client_id", 
    "msg_type", "direction", "packet_size", "entropy", "status"
]

# Track timing for IAT (Inter-Arrival Time)
last_packet_time = {}

# --- REPLAY PROTECTION GATEKEEPER ---
USED_NONCES = {}  # {nonce: expiry_timestamp}
NONCE_TTL = 60    # 60-second window

def calculate_entropy(data):
    """Calculates Shannon Entropy to detect data randomness/encryption."""
    if not data: return 0
    counts = Counter(data)
    probs = [c / len(data) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

def is_replay_attack(nonce, packet_timestamp):
    """Checks if a packet is too old or has been used before."""
    now = time.time()
    
    # Gate 1: Freshness Check
    if now - packet_timestamp > NONCE_TTL:
        return True # Too old
    
    # Gate 2: Uniqueness Check
    if nonce in USED_NONCES:
        return True # Already used
    
    # If passed, record it
    USED_NONCES[nonce] = packet_timestamp + NONCE_TTL
    
    # Simple Cleanup
    if len(USED_NONCES) > 1000:
        expired = [n for n, exp in USED_NONCES.items() if exp < now]
        for n in expired: del USED_NONCES[n]
        
    return False

def log_traffic(addr, client_id, packet_size, msg_type, direction, payload=b"", status="PENDING"):
    """Advanced logger with timing, entropy, and security status."""
    global last_packet_time
    now = time.time()
    ip = addr[0]
    
    iat = now - last_packet_time.get(ip, now)
    last_packet_time[ip] = now
    entropy = calculate_entropy(payload)
    
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    file_exists = os.path.isfile(LOG_FILE)
    
    with open(LOG_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(LOG_HEADERS)
        writer.writerow([
            f"{now:.6f}", f"{iat:.6f}", ip, client_id if client_id else "N/A", 
            msg_type, direction, packet_size, f"{entropy:.4f}", status
        ])

def update_ml_window(ip, size, direction):
    """Updates the sliding window and performs anomaly detection."""
    if not ML_ACTIVE: return False

    if ip not in PACKET_WINDOW:
        PACKET_WINDOW[ip] = deque(maxlen=WINDOW_SIZE)
    
    # Add current packet to history
    PACKET_WINDOW[ip].append({
        "ts": time.time(),
        "size": size,
        "dir": direction
    })

    # Only predict once we have a full window
    if len(PACKET_WINDOW[ip]) == WINDOW_SIZE:
        history = list(PACKET_WINDOW[ip])
        duration = history[-1]['ts'] - history[0]['ts']
        if duration == 0: duration = 0.001 # Prevent div by zero

        total_bytes = sum(p['size'] for p in history)
        inbound_count = len([p for p in history if p['dir'] == "INBOUND"])
        outbound_count = len([p for p in history if p['dir'] == "OUTBOUND"])

        # Calculate Sahil's 5 UNSW-NB15 Features
        features = [
            WINDOW_SIZE / duration,            # requests_per_sec
            duration / WINDOW_SIZE,            # avg_interval
            total_bytes / duration,            # bytes_per_sec
            total_bytes / WINDOW_SIZE,         # avg_packet_size
            inbound_count / (outbound_count + 1) # packet_ratio
        ]

        # Call Sahil's model
        is_attack = ml_predict(features)
        if is_attack:
            print(f"🚨 [ML ALERT] Anomaly detected from {ip}! High probability of attack.")
            return True
    return False

# --- INITIALIZATION ---
pub_bytes = SERVER_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(f"DEBUG: Hub Public Key Hash: {hashlib.sha256(pub_bytes).hexdigest()}")

reg_handler = RegistrationHandler(SERVER_PRIVATE_KEY, SERVER_CERT, [b"c1", b"c2", b"c3"], {"sensor_001": {b"c1": b"r1", b"c2": b"r2", b"c3": b"r3"}})
conn_handler = ConnectionHandler(SERVER_PRIVATE_KEY)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 5000))

print("🚀 ZETROS Hub running. Replay Protection & UNSW-NB15 ML Guard active...")

while True:
    data, addr = sock.recvfrom(4096)
    inbound_size = len(data)
    ip = addr[0]
    
    try:
        # Passive ML Monitoring
        attack_detected = update_ml_window(ip, inbound_size, "INBOUND")

        # ==========================================================
        # PHASE 1: REGISTRATION (MSG 1, 5, 7, 9)
        # ==========================================================
        if data.startswith(b"MSG1|"):
            dec = decode_message(rsa_decrypt(SERVER_PRIVATE_KEY, data[5:]))
            if is_replay_attack(dec.get('r_C'), dec.get('timestamp', 0)):
                print(f"🚫 [REPLAY] MSG1 blocked from {addr}")
                log_traffic(addr, None, inbound_size, "MSG1", "INBOUND", status="REPLAY_ATTACK")
                continue

            log_traffic(addr, None, inbound_size, "MSG1", "INBOUND", payload=data)
            response = reg_handler.handle_msg1(data[5:])
            sock.sendto(response, addr)
            log_traffic(addr, None, len(response), "MSG2", "OUTBOUND", payload=response)
            update_ml_window(ip, len(response), "OUTBOUND")

        elif data.startswith(b"MSG5|"):
            dec = decode_message(rsa_decrypt(SERVER_PRIVATE_KEY, data[5:]))
            if is_replay_attack(dec.get('ch_S'), dec.get('timestamp', 0)):
                print(f"🚫 [REPLAY] MSG5 blocked from {addr}")
                log_traffic(addr, None, inbound_size, "MSG5", "INBOUND", status="REPLAY_ATTACK")
                continue

            log_traffic(addr, None, inbound_size, "MSG5", "INBOUND", payload=data)
            response = reg_handler.handle_msg5(data[5:])
            sock.sendto(response, addr)
            log_traffic(addr, None, len(response), "MSG6", "OUTBOUND", payload=response)
            update_ml_window(ip, len(response), "OUTBOUND")

        elif data.startswith(b"MSG7|"):
            log_traffic(addr, None, inbound_size, "MSG7", "INBOUND", payload=data)
            for ch_S in list(reg_handler.sessions.keys()):
                try:
                    response = reg_handler.handle_msg7(data[5:], ch_S)
                    msg8 = b"MSG8|" + response
                    sock.sendto(msg8, addr)
                    log_traffic(addr, None, len(msg8), "MSG8", "OUTBOUND", payload=msg8)
                    update_ml_window(ip, len(msg8), "OUTBOUND")
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
            try:
                decrypted = decode_message(rsa_decrypt(SERVER_PRIVATE_KEY, data[6:]))
                claimed_id = decrypted.get('client_id')
                if is_replay_attack(f"CONN1_{decrypted.get('nonce')}", decrypted.get('timestamp', 0)):
                    print(f"🚫 [REPLAY] CONN1 blocked for {claimed_id}")
                    log_traffic(addr, claimed_id, inbound_size, "CONN1", "INBOUND", status="REPLAY_ATTACK")
                    continue
            except: claimed_id = "MALFORMED_ID"

            log_traffic(addr, claimed_id, inbound_size, "CONN1", "INBOUND", payload=data)
            response = conn_handler.handle_conn1(data[6:])
            msg2 = b"CONN2|" + response
            sock.sendto(msg2, addr)
            log_traffic(addr, claimed_id, len(msg2), "CONN2", "OUTBOUND", payload=msg2)
            update_ml_window(ip, len(msg2), "OUTBOUND")

        elif data.startswith(b"CONN3|"):
            try:
                dec = decode_message(rsa_decrypt(SERVER_PRIVATE_KEY, data[6:]))
                if is_replay_attack(f"CONN3_{dec.get('nonce')}", dec.get('timestamp', 0)):
                    print(f"🚫 [REPLAY] CONN3 blocked")
                    log_traffic(addr, None, inbound_size, "CONN3", "INBOUND", status="REPLAY_ATTACK")
                    continue
            except: pass

            success, client_id = conn_handler.handle_conn3_with_loop(data[6:])
            log_traffic(addr, client_id, inbound_size, "CONN3", "INBOUND", payload=data)
            
            if success:
                msg4 = b"CONN4|SUCCESS"
                sock.sendto(msg4, addr)
                log_traffic(addr, client_id, len(msg4), "CONN4", "OUTBOUND", payload=msg4, status="SUCCESS")
                update_ml_window(ip, len(msg4), "OUTBOUND")
                print(f"✅ [AUTH_SUCCESS] Device {client_id}")
            else:
                msg4 = b"CONN4|FAIL"
                sock.sendto(msg4, addr)
                log_traffic(addr, client_id, len(msg4), "CONN4", "OUTBOUND", payload=msg4, status="FAILED")
                update_ml_window(ip, len(msg4), "OUTBOUND")
                print(f"🚫 [AUTH_FAILED] for {client_id}")

        else:
            print(f"⚠️ Unknown packet from {addr}")

        # Final Enforcement: If ML flagged an attack, we could drop the connection here
        if attack_detected:
            # log_traffic(addr, "ML_WATCHDOG", 0, "BLOCK", "INTERNAL", status="BLOCK_BY_IDS")
            pass

    except Exception as e:
        print(f"❌ Error: {e}")