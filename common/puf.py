import hmac
import hashlib
import os
import json

class PUF:
    def __init__(self, device_id="unnamed_device", seed: bytes = None):
        """
        Initializes the PUF with a unique ID and a secret seed.
        The seed simulates the physical variations of the chip[cite: 119].
        """
        self.device_id = device_id
        # os.urandom(32) provides 256 bits of high-quality entropy[cite: 115, 118].
        self._seed = seed if seed is not None else os.urandom(32)

    def respond(self, challenge):
        # 1. Convert Challenge to Bytes correctly
        if isinstance(challenge, str):
            try:
                # If it's a hex string (like "6331"), turn it back to bytes (b"c1")
                challenge = bytes.fromhex(challenge)
            except ValueError:
                # If it's a normal string, just encode it
                challenge = challenge.encode()
        
        # 2. Calculate HMAC using raw bytes
        import hmac, hashlib
        return hmac.new(self._seed, challenge, hashlib.sha256).digest()
    def generate_session_key(self, challenge: bytes) -> bytes:
        """
        Paper notation: theta(ch_S) = K_session[cite: 125].
        """
        return self.respond(challenge)

    def respond_to_set(self, challenge_set: list) -> list:
        """
        Applies the PUF to a shuffled list of challenges[cite: 129, 130].
        """
        return [self.respond(c) for c in challenge_set]

    def to_dict(self):
        """Converts the PUF state to a dictionary for secure storage."""
        return {
            'device_id': self.device_id,
            'seed': self._seed.hex()
        }