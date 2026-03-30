# authority_ca/ca_service.py

import json
import hashlib
from common.crypto import rsa_decrypt, rsa_sign
from common.encoding import decode_message, encode_message
from authority_ca.ca_keys import CA_PRIVATE_KEY

REGISTRY_FILE = "authority_ca/trusted_certs.json"


def load_registry():
    try:
        with open(REGISTRY_FILE, "r") as f:
            return json.load(f)
    except:
        return {}


def handle_verification_request(encrypted_msg):
    try:
        # ---------------- STEP 1: Decrypt ----------------
        raw = rsa_decrypt(CA_PRIVATE_KEY, encrypted_msg)
        data = decode_message(raw)

        server_cert = data['cert']
        client_nonce = data['nonce']

        # ---------------- STEP 2: Load Registry ----------------
        registry = load_registry()

        cert_fp = hashlib.sha256(server_cert).hexdigest()

        if cert_fp in registry:
            result = "OK"
            server_name = registry[cert_fp]
        else:
            result = "NOK"
            server_name = "UNKNOWN"

        print(f"[CA] Verification: {server_name} → {result}")

        # ---------------- STEP 3: Sign Response ----------------
        payload = encode_message({
            "result": result,
            "nonce": client_nonce
        })

        signature = rsa_sign(CA_PRIVATE_KEY, payload)

        return encode_message({
            "payload": payload,
            "sig": signature
        })

    except Exception as e:
        print("[CA ERROR]", e)
        return None