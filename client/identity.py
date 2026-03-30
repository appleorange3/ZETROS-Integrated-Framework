import uuid
import platform
import hashlib

def get_device_id():
    return str(uuid.getnode())

def get_device_secret():
    data = str(uuid.getnode()) + platform.node() + platform.processor()
    return hashlib.sha256(data.encode()).hexdigest()