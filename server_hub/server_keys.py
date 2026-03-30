# server_hub/server_keys.py
from cryptography.hazmat.primitives import serialization

# 1. Load the exact Private Key for the Hub
with open("server_private.pem", "rb") as f:
    SERVER_PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)

# 2. Load the matching Public Key for the Client
with open("server_public.pem", "rb") as f:
    SERVER_PUBLIC_KEY = serialization.load_pem_public_key(f.read())

# 3. Ensure your certificate is in bytes for the RSA signature [cite: 485-486]
SERVER_CERT = b"ZETROS_HUB_V1_CERT"