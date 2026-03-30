import json
import hashlib
import random
from common.crypto import rsa_decrypt, generate_nonce
from common.encoding import decode_message, encode_message

class ConnectionHandler:
    def __init__(self, private_key, db_path="puf_database.json"):
        self.private_key = private_key
        self.db_path = db_path
        self.sessions = {} # Short-term memory for active connection attempts

    def _load_db(self):
        """Helper to safely load the database file."""
        try:
            with open(self.db_path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def handle_conn1(self, encrypted_payload):
        """
        Phase 2, Step 1: Processes connection request and sends a random challenge.
        """
        # 1. Decrypt the request
        raw = rsa_decrypt(self.private_key, encrypted_payload)
        data = decode_message(raw)
        client_id = data['client_id']
        r_C2 = data['r_C2']

        # 2. Verify device exists in the "Birth Certificate" file
        db = self._load_db()
        if client_id not in db:
            raise Exception(f"Access Denied: Device {client_id} not recognized.")

        # 3. Pick a RANDOM challenge index from the stored set
        # This prevents 'Replay Attacks' because the question changes every time.
        stored_challenges = db[client_id]["C_r"]
        idx = random.randint(0, len(stored_challenges) - 1)
        selected_challenge = stored_challenges[idx]

        # 4. Save the challenge index to verify the answer later
        r_S2 = generate_nonce()
        self.sessions[client_id] = {
            "expected_idx": idx,
            "r_C2": r_C2,
            "r_S2": r_S2
        }

        # 5. Return CONN2 (The Challenge)
        return encode_message({
            "challenge": selected_challenge,
            "r_S2": r_S2
        })

    def handle_conn3_with_loop(self, encrypted_payload):
        """
        Phase 2, Step 3: Verifies the hardware response against the database.
        """
        # 1. Decrypt the response (RSA encrypted by client)
        raw = rsa_decrypt(self.private_key, encrypted_payload)
        data = decode_message(raw)
        
        received_response_hex = data['response']
        received_r_C2 = data['r_C2']

        # 2. Identify which session this packet belongs to using the nonce r_C2
        target_cid = None 
        for cid, session in self.sessions.items():
            if session['r_C2'] == received_r_C2:
                target_cid = cid
                break
        
        if not target_cid:
            print("⚠️ No active session matches this nonce. Possible timeout or hack attempt.")
            return False, None

        # 3. Retrieve the stored "DNA" (The SHA-256 fingerprint from Phase 1)
        session = self.sessions[target_cid]
        db = self._load_db()
        stored_hash = db[target_cid]["R_r"][session["expected_idx"]]
        
        # 4. VERIFICATION:
        # The client sent a Hex string. We must convert it back to BYTES 
        # so the SHA-256 hash matches the one we saved during registration.
        response_bytes = bytes.fromhex(received_response_hex)
        calculated_hash = hashlib.sha256(response_bytes).hexdigest()

        if calculated_hash == stored_hash:
            print(f"✅ PUF VERIFIED: Device {target_cid} is authentic.")
            # Clear session memory now that they are logged in
            del self.sessions[target_cid] 
            return True, target_cid
        
        print(f"🚫 AUTH FAILED: Physical fingerprint for {target_cid} does not match!")
        return False, target_cid