import random
import time
from server.auth import generate_hmac
from server.device_manager import register_device, get_device, save_db
from server.detector import detect_attack
from server.blockchain import blockchain, compute_trust

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr}")

    try:
        data = conn.recv(1024).decode()

        # =========================
        # REGISTER
        # =========================
        if data.startswith("REGISTER"):
            _, device_id, device_secret = data.split()

            if register_device(device_id, device_secret):
                conn.send("REGISTERED".encode())
            else:
                conn.send("ALREADY_REGISTERED".encode())

            conn.close()
            return

        # =========================
        # AUTH
        # =========================
        if data.startswith("HELLO"):
            device_id = data.split()[1]

            device = get_device(device_id)
            if not device:
                conn.send("NOT_REGISTERED".encode())
                conn.close()
                return

            # cooldown
            if device["status"] == "blocked":
                if time.time() < device.get("blocked_until", 0):
                    conn.send("BLOCKED".encode())
                    conn.close()
                    return
                else:
                    device["status"] = "active"

            # challenge
            challenge = random.randint(1000, 9999)
            conn.send(f"CHALLENGE {challenge}".encode())

            response = conn.recv(1024).decode()
            expected = generate_hmac(challenge, device["secret"])

            if response != expected:
                conn.send("AUTH_FAILED".encode())
                conn.close()
                return

            conn.send("AUTH_SUCCESS".encode())
            print(f"[AUTH SUCCESS] {device_id}")

            # 🔥 CHECK TRUST IMMEDIATELY
            trust = compute_trust(device_id)
            print(f"[INITIAL TRUST] {trust:.2f}")

            if trust < 0.3:
                conn.send("BLOCKED".encode())
                print(f"[BLOCKED IMMEDIATELY] {device_id}")
                conn.close()
                return

            # =========================
            # LOOP
            # =========================
            while True:
                try:
                    data = conn.recv(1024)

                    if not data:
                        break

                    data_len = len(data)
                    current_time = time.time()

                    # 🔥 RESET WINDOW (NO CONTINUE)
                    if current_time - device["last_time"] > 1:
                        device["last_time"] = current_time
                        device["requests"] = 0
                        device["bytes"] = 0

                    # 🔥 ALWAYS INCREMENT
                    device["requests"] += 1
                    device["bytes"] += data_len

                    attack = detect_attack(device)
                    event = "malicious" if attack else "normal"

                    # 🔥 ALWAYS LOG (no skipping now)
                    blockchain.add_block({
                        "device_id": device_id,
                        "event": event,
                        "time": current_time
                    })

                    # 🔥 COMPUTE TRUST
                    trust = compute_trust(device_id)

                    print(f"[REQ: {device['requests']}] [ATTACK: {attack}] [TRUST: {trust:.2f}]")

                    save_db()

                    # 🔥 BLOCK CONDITION
                    if trust < 0.3:
                        device["status"] = "blocked"
                        device["blocked_until"] = time.time() + 10

                        conn.send("BLOCKED".encode())
                        print(f"[BLOCKED BY TRUST] {device_id}")
                        break

                    # 🔥 ALWAYS RESPOND
                    conn.send("ACK".encode())

                except Exception as e:
                    print("[LOOP ERROR]", e)
                    break

    except Exception as e:
        print("[SERVER ERROR]", e)

    conn.close()