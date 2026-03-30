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
        self.r_C2 = None # Fresh session key for Phase 2

    def msg1_connect(self):
        self.r_C2 = generate_nonce()
        payload = encode_message({
            "type": "conn_req",
            "client_id": self.client_id,
            "r_C2": self.r_C2
        })
        return b"CONN1|" + rsa_encrypt(self.server_pub_key, payload)

    def process_msg2_challenge(self, msg2_raw):
        data = decode_message(msg2_raw)
        challenge_to_solve = data['challenge']
        
        # 1. Get raw bytes from PUF
        response_bytes = self.puf.respond(challenge_to_solve)
        
        # 2. Convert to hex for the network payload
        payload = encode_message({
            "response": response_bytes.hex(), # Send as hex string
            "r_C2": self.r_C2
        })
        return b"CONN3|" + rsa_encrypt(self.server_pub_key, payload)