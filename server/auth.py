import hmac
import hashlib

def generate_hmac(challenge, key):
    return hmac.new(
        key.encode(),
        str(challenge).encode(),
        hashlib.sha256
    ).hexdigest()