import os
import time  # 🆕 Added for timestamps
from common.crypto import (
    rsa_encrypt, rsa_verify,
    aes_encrypt, aes_decrypt,
    xor_bytes, generate_nonce
)
from common.encoding import encode_message, decode_message

class RegistrationClient:
    def __init__(self, puf, server_pub_key, ca_pub_key):
        self.puf = puf
        self.server_pub_key = server_pub_key
        self.ca_pub_key = ca_pub_key

        self.r_C = None
        self.r_S = None
        self.ch_S = None
        self.K_session = None
        self.client_id = None
        self.r_C1 = None

    # MSG1
    def msg1_hello(self):
        self.r_C = generate_nonce()

        payload = encode_message({
            "type": "hello",
            "r_C": self.r_C,
            "timestamp": time.time(),  # 🆕 Freshness Seal
            "device_id": self.puf.device_id
        })

        return b"MSG1|" + rsa_encrypt(self.server_pub_key, payload)

    # MSG2 (No change needed here, it's a server response)
    def process_msg2(self, msg2):
        data = decode_message(msg2)
        required = ['cert', 'r_S', 'ch_S', 'sig']
        if not all(k in data for k in required):
            raise Exception("Invalid MSG2 format")

        verify_data = data['cert'] + data['r_S'] + data['ch_S']
        if not rsa_verify(self.server_pub_key, data['sig'], verify_data):
            raise Exception("MITM detected")

        if data['ch_S'] != xor_bytes(self.r_C, data['r_S']):
            raise Exception("Invalid ch_S")

        self.r_S = data['r_S']
        self.ch_S = data['ch_S']
        return data['cert']

    # MSG3
    def msg3_ca_request(self, cert):
        self.r_C1 = generate_nonce()
        payload = encode_message({
            "cert": cert,
            "nonce": self.r_C1,
            "timestamp": time.time()  # 🆕 CA also needs freshness
        })
        return rsa_encrypt(self.ca_pub_key, payload)

    # MSG4 (Handled by CA)
    def process_msg4(self, msg4):
        data = decode_message(msg4)
        if 'payload' not in data or 'sig' not in data:
            raise Exception("Invalid MSG4")
        payload = data['payload']
        sig = data['sig']
        if not rsa_verify(self.ca_pub_key, sig, payload):
            raise Exception("Invalid CA signature")
        decoded = decode_message(payload)
        if decoded['nonce'] != self.r_C1:
            raise Exception("Replay attack detected")
        if decoded['result'] != "OK":
            raise Exception("Server not trusted")

    # MSG5
    def msg5_key_exchange(self):
        self.K_session = self.puf.generate_session_key(self.ch_S)

        payload = encode_message({
            "type": "key_exchange",
            "K_session": self.K_session,
            "ch_S": self.ch_S,
            "timestamp": time.time()  # 🆕 Added
        })

        return b"MSG5|" + rsa_encrypt(self.server_pub_key, payload)

    # MSG6 (AES Response)
    def process_msg6(self, msg6):
        raw = aes_decrypt(self.K_session, msg6)
        data = decode_message(raw)
        if data.get('ch_S') != self.ch_S:
            raise Exception("Session mismatch")
        if 'C_r' not in data:
            raise Exception("Invalid MSG6")
        return data['C_r']

    # MSG7
    def msg7_response(self, C_r):
        R_r = self.puf.respond_to_set(C_r)

        payload = encode_message({
            "type": "puf_response",
            "R_r": R_r,
            "ch_S": self.ch_S,
            "timestamp": time.time(),  # 🆕 Added
            "device_id": self.puf.device_id
        })

        return b"MSG7|" + aes_encrypt(self.K_session, payload)

    # MSG8
    def process_msg8(self, msg8):
        raw = aes_decrypt(self.K_session, msg8)
        data = decode_message(raw)
        if data.get('ch_S') != self.ch_S:
            raise Exception("Session mismatch")
        if 'client_id' not in data or 'r_S1' not in data:
            raise Exception("Invalid MSG8")
        self.client_id = data['client_id']
        return data['r_S1']

    # MSG9
    def msg9_finish(self, r_S1):
        payload = encode_message({
            "type": "finish",
            "r_S1": r_S1,
            "ch_S": self.ch_S,
            "timestamp": time.time()  # 🆕 Added
        })

        return b"MSG9|" + aes_encrypt(self.K_session, payload)