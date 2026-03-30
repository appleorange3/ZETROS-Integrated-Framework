import hashlib
import json
import time
import os

DB_FILE = "data/blockchain.json"

class Block:
    def __init__(self, index, timestamp, data, prev_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.prev_hash = prev_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "prev_hash": self.prev_hash
        }, sort_keys=True).encode()

        return hashlib.sha256(block_string).hexdigest()


class Blockchain:
    def __init__(self):
        self.chain = self.load_chain()

        if not self.is_valid():
            print("🚨 BLOCKCHAIN TAMPERED!")
            exit()

    def create_genesis_block(self):
        return Block(0, time.time(), {"msg": "genesis"}, "0")

    def load_chain(self):
        if os.path.exists(DB_FILE):
            try:
                with open(DB_FILE, "r") as f:
                    data = json.load(f)

                    chain = []
                    for block_data in data:
                        block = Block(
                            block_data["index"],
                            block_data["timestamp"],
                            block_data["data"],
                            block_data["prev_hash"]
                        )

                        # 🔥 VERIFY HASH
                        if block.hash != block_data["hash"]:
                            raise Exception("Tampered block detected!")

                        chain.append(block)

                    return chain
            except Exception as e:
                print("[BLOCKCHAIN ERROR]", e)
                exit()

        return [self.create_genesis_block()]

    def save_chain(self):
        with open(DB_FILE, "w") as f:
            json.dump([block.__dict__ for block in self.chain], f, indent=4)

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        prev_block = self.get_latest_block()

        new_block = Block(
            index=prev_block.index + 1,
            timestamp=time.time(),
            data=data,
            prev_hash=prev_block.hash
        )

        self.chain.append(new_block)
        self.save_chain()

    def is_valid(self):
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            if curr.hash != curr.calculate_hash():
                return False

            if curr.prev_hash != prev.hash:
                return False

        return True


# 🔥 GLOBAL INSTANCE
blockchain = Blockchain()


# =========================
# 🔥 STRONG TRUST MODEL
# =========================
def compute_trust(device_id):
    trust = 1.0
    current_time = time.time()

    malicious_count = 0

    for block in blockchain.chain:
        data = block.data

        if data.get("device_id") != device_id:
            continue

        event = data["event"]
        event_time = data["time"]

        delta = current_time - event_time
        weight = max(0.2, 1 / (1 + delta / 20))

        if event == "malicious":
            trust -= 0.4 * weight
            malicious_count += 1
        else:
            trust += 0.005 * weight

    # 🔥 CRITICAL: trust floor
    if malicious_count >= 3:
        trust = min(trust, 0.5)   # cannot go above 0.5

    if malicious_count >= 5:
        trust = min(trust, 0.3)   # almost always blocked

    return max(0, min(1, trust))