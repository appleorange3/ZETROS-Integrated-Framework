import json
import os
import time

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_FILE = os.path.join(DATA_DIR, "devices.json")

if os.path.exists(DB_FILE):
    try:
        with open(DB_FILE, "r") as f:
            device_db = json.load(f)
    except:
        device_db = {}
else:
    device_db = {}

def save_db():
    with open(DB_FILE, "w") as f:
        json.dump(device_db, f, indent=4)

def register_device(device_id, secret):
    if device_id not in device_db:
        device_db[device_id] = {
            "secret": secret,
            "requests": 0,
            "bytes": 0,
            "last_time": time.time(),
            "status": "active",
            "blocked_until": 0
        }
        save_db()
        print(f"[REGISTERED] {device_id}")
        return True
    return False

def get_device(device_id):
    return device_db.get(device_id)