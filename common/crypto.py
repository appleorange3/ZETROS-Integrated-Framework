from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
import os
import hashlib
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Combines two nonces to create ch_S[cite: 215, 219]."""
    if len(a) != len(b):
        # Normalize to 32 bytes if lengths mismatch[cite: 224].
        a = hashlib.sha256(a).digest()
        b = hashlib.sha256(b).digest()
    return bytes(x ^ y for x, y in zip(a, b))

def generate_rsa_keypair():
    """Generates a 2048-bit RSA keypair[cite: 241, 260]."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, # Standard fast exponent[cite: 257].
        key_size=2048
    )
    return private_key, private_key.public_key()

def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    """Encrypts data using RSA-OAEP padding[cite: 302, 304]."""
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_sign(private_key, data: bytes) -> bytes:
    """Signs data using RSA-PSS for non-determinism[cite: 317, 318]."""
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypts data via AES-GCM (Confidentiality + Integrity)[cite: 337, 409]."""
    aesgcm = AESGCM(hashlib.sha256(key).digest()) # Normalize key to 32 bytes[cite: 387, 390].
    nonce = os.urandom(12) # 96-bit nonce[cite: 388, 391].
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct # Prepend nonce for the receiver[cite: 394].


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    key = hashlib.sha256(key).digest()

    nonce = data[:12]
    ct = data[12:]

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

def generate_nonce(size: int = 16) -> bytes:
    """
    Generates a cryptographically secure random nonce.
    
    Default: 16 bytes (128-bit) — good for protocol nonces (r_C, r_S, etc.)
    """
    return os.urandom(size)



def rsa_verify(public_key, signature: bytes, data: bytes) -> bool:
    """
    Verifies RSA-PSS signature.
    Returns True if valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False