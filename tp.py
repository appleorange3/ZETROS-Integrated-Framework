import hashlib
cert = b"ZETROS_HUB_V1_CERT"
print(hashlib.sha256(cert).hexdigest())