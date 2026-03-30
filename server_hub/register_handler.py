import random
import uuid
import time
import hashlib
import json
from common.crypto import (
    rsa_decrypt, rsa_sign,
    aes_encrypt, aes_decrypt,
    xor_bytes, generate_nonce
)
from common.encoding import encode_message, decode_message


class RegistrationHandler:
    def __init__(self, priv_key, cert, master_challenges, puf_db):
        self.priv_key = priv_key
        self.cert = cert
        self.C = master_challenges
        self.sessions = {}
        self.puf_db = puf_db

    def save_to_disk(self):
        print(f"DEBUG: Attempting to save {len(self.puf_db)} devices to disk...")
        serializable_db = {}
        
        for cid, data in self.puf_db.items():
            try:
                # Check if this is a real registration (has C_r and R_r keys)
                if isinstance(data, dict) and "C_r" in data and "R_r" in data:
                    serializable_db[cid] = {
                        "C_r": [c.hex() if isinstance(c, bytes) else c for c in data["C_r"]],
                        "R_r": [r.hex() if isinstance(r, bytes) else r for r in data["R_r"]]
                    }
                else:
                    # Skip the dummy data or handle it differently
                    print(f"   ℹ️ Skipping legacy/dummy entry: {cid}")
                    continue
            except Exception as e:
                print(f"   ❌ Error processing {cid}: {e}")
                continue

        # ONLY write to file if we have something to save
        if serializable_db:
            with open("puf_database.json", "w") as f:
                json.dump(serializable_db, f, indent=4)
            print("💾 SUCCESS: puf_database.json has been written.")
        else:
            print("⚠️ Warning: No valid registrations found to save.")
    # MSG1 → MSG2
    def handle_msg1(self, msg1):
        print(2.1)
        print(self.priv_key)
        raw = rsa_decrypt(self.priv_key, msg1)
        data = decode_message(raw)
        print(2.5)
        r_C = data['r_C']
        device_id = data['device_id']

        r_S = generate_nonce()
        ch_S = xor_bytes(r_C, r_S)

        sig_data = self.cert + r_S + ch_S
        sig = rsa_sign(self.priv_key, sig_data)

        self.sessions[ch_S] = {
            "r_C": r_C,
            "r_S": r_S,
            "device_id": device_id,
            "timestamp": time.time()
        }

        return encode_message({
            "sig": sig,
            "cert": self.cert,
            "r_S": r_S,
            "ch_S": ch_S
        })

    # MSG5 → MSG6
    def handle_msg5(self, msg5):
        raw = rsa_decrypt(self.priv_key, msg5)
        data = decode_message(raw)

        ch_S = data['ch_S']
        session = self.sessions.get(ch_S)

        if not session:
            raise Exception("Invalid session / replay attack")

        if time.time() - session["timestamp"] > 60:
            raise Exception("Session expired")

        k_session = data['K_session']
        if len(k_session) < 16:
            raise Exception("Weak session key")

        session['K_session'] = k_session

        C_r = self.C.copy()
        random.shuffle(C_r)
        session['C_r'] = C_r

        payload = encode_message({
            "C_r": C_r,
            "ch_S": ch_S
        })

        return aes_encrypt(k_session, payload)

    # PUF VERIFY
    def verify_puf(self, device_id, C_r, R_r):
        expected = self.puf_db.get(device_id)
        if not expected:
            return False

        for c, r in zip(C_r, R_r):
            expected_r = expected.get(c)
            if not expected_r:
                return False

            if hashlib.sha256(expected_r).digest() != hashlib.sha256(r).digest():
                return False

        return True

    # MSG7 → MSG8
    # MSG7 → MSG8
    def handle_msg7(self, msg7, ch_S):
        session = self.sessions.get(ch_S)
        if not session:
            raise Exception("Session not found")

        # Decrypt the responses
        raw = aes_decrypt(session['K_session'], msg7)
        data = decode_message(raw)

        # --- THE FIX: Standardize and Hash the Responses ---
        raw_responses = data['R_r']
        hashed_responses = []
        for r in data['R_r']:
            # If the client sent hex, convert to bytes before hashing
            r_bytes = bytes.fromhex(r) if isinstance(r, str) else r
            # This SHA-256 is the 'Fingerprint' stored in puf_database.json
            hashed_responses.append(hashlib.sha256(r_bytes).hexdigest())

        session['R_r'] = hashed_responses # Save the HASHES
        # --------------------------------------------------

        session['client_id'] = str(uuid.uuid4())
        session['r_S1'] = generate_nonce()

        payload = encode_message({
            "client_id": session['client_id'],
            "r_S1": session['r_S1'],
            "ch_S": ch_S
        })

        return aes_encrypt(session['K_session'], payload) 
    # MSG9 FINAL
    def handle_msg9(self, msg9, ch_S):
        session = self.sessions.get(ch_S)
        if not session:
            raise Exception("Session not found")

        raw = aes_decrypt(session['K_session'], msg9)
        data = decode_message(raw)

        if data['r_S1'] != session['r_S1']:
            raise Exception("Liveness failed")

        # --- THE FIX: PERMANENT STORAGE ---
        client_id = session['client_id']
        device_id = session['device_id'] # From MSG1
        
        # Save the CRPs (Challenge-Response Pairs) for this specific client
        # In a real project, write this to a JSON file!
        self.puf_db[client_id] = {
            "C_r": session["C_r"],
            "R_r": session["R_r"] # From handle_msg7
        }
        
        print(f"[✔] Successfully Registered and Saved: {client_id}")
        # 1. Move from Session to permanent DB
        client_id = session['client_id']
        self.puf_db[client_id] = {
            "C_r": session["C_r"],
            "R_r": session["R_r"]
        }

        # 2. THE FIX: Physically save it!
        self.save_to_disk()
        del self.sessions[ch_S]
        return True