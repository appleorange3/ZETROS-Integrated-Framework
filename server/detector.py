import time
from ml.model import predict

def detect_attack(device):
    try:
        current_time = time.time()

        interval = current_time - device["last_time"]

        # 🔥 prevent unrealistically small interval (fix spike bug)
        if interval < 0.5:
            interval = 0.5

        total_packets = device["requests"]
        total_bytes = device["bytes"]

        # 🔥 warm-up phase → ignore first few packets
        if total_packets < 5:
            return False

        # features
        requests_per_sec = total_packets / interval
        avg_interval = interval / total_packets
        bytes_per_sec = total_bytes / interval
        avg_packet_size = total_bytes / total_packets
        packet_ratio = 1.0

        features = [
            requests_per_sec,
            avg_interval,
            bytes_per_sec,
            avg_packet_size,
            packet_ratio
        ]

        print("FEATURES:", features)

        prob = predict(features)  # already thresholded OR probability-based

        print("PREDICTION:", prob)

        return prob  # should return True/False

    except Exception as e:
        print("[DETECTOR ERROR]", e)
        return False