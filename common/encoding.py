import json
import base64

def encode_message(payload: dict) -> bytes:
    """Recursively converts bytes to Base64 strings for JSON transport[cite: 422]."""
    def enc(v):
        if isinstance(v, bytes):
            # Convert raw bytes to a readable Base64 string [cite: 425]
            return {"__bytes__": base64.b64encode(v).decode('utf-8')}
        if isinstance(v, list):
            return [enc(i) for i in v]
        if isinstance(v, dict):
            return {k: enc(val) for k, val in v.items()}
        return v
    
    # Dump the dictionary to a JSON string and encode as UTF-8 bytes [cite: 429]
    return json.dumps({k: enc(v) for k, v in payload.items()}).encode('utf-8')

def decode_message(data: bytes) -> dict:
    """Reverses the encoding to recover raw bytes[cite: 430]."""
    def dec(v):
        if isinstance(v, dict) and "__bytes__" in v:
            # Revert Base64 string back to original raw bytes [cite: 438]
            return base64.b64decode(v["__bytes__"])
        if isinstance(v, list):
            return [dec(i) for i in v]
        if isinstance(v, dict):
            return {k: dec(val) for k, val in v.items()}
        return v
    
    return json.loads(data.decode('utf-8'), object_hook=dec)