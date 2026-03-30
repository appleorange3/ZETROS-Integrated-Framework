import json
import hashlib

REGISTRY_FILE = "authority_ca/trusted_certs.json"

def add_cert(cert_bytes, name):
    cert_hash = hashlib.sha256(cert_bytes).hexdigest()

    try:
        with open(REGISTRY_FILE, "r") as f:
            registry = json.load(f)
    except:
        registry = {}

    registry[cert_hash] = name

    with open(REGISTRY_FILE, "w") as f:
        json.dump(registry, f, indent=4)

    print(f"[CA] Added {name} with hash {cert_hash}")


# Example usage
add_cert(b"server_certificate", "Server_Hub_01")