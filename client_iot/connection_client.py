import time  # 🆕 Needed for the Freshness Seal
from common.crypto import (
    rsa_encrypt, 
    generate_nonce
)
from common.encoding import (
    encode_message, 
    decode_message
)

class ConnectionClient:
    def __init__(self, puf, client_id, server_pub_key):
        self.puf = puf
        self.client_id = client_id
        self.server_pub_key = server_pub_key
        self.r_C2 = None 

    def msg1_connect(self):
        self.r_C2 = generate_nonce()
        # 🔑 THE FIX: Change "r_C2" to "nonce" and add "timestamp"
        payload = encode_message({
            "type": "conn_req",
            "client_id": self.client_id,
            "nonce": self.r_C2,        # Hub is looking for this key name
            "timestamp": time.time()   # Hub uses this to check if packet is < 60s old
        })
        return b"CONN1|" + rsa_encrypt(self.server_pub_key, payload)

    def process_msg2_challenge(self, msg2_raw):
        data = decode_message(msg2_raw)
        challenge_to_solve = data['challenge']
        
        # 1. Get raw bytes from PUF
        response_bytes = self.puf.respond(challenge_to_solve)
        
        # 2. Convert to hex for the network payload
        # 🔑 THE FIX: Again, change "r_C2" to "nonce" and add "timestamp"
        payload = encode_message({
            "response": response_bytes.hex(), 
            "nonce": self.r_C2,        # Hub is looking for this key name
            "timestamp": time.time()   # Freshness seal for CONN3
        })
        return b"CONN3|" + rsa_encrypt(self.server_pub_key, payload)