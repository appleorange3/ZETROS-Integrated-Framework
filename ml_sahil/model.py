import pandas as pd
import joblib

import os
import joblib

# This finds the actual folder where model.py is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")

model = joblib.load(MODEL_PATH) # ✅ Works regardless of where you run the Hub from

def predict(features):
    columns = [
        "requests_per_sec",
        "avg_interval",
        "bytes_per_sec",
        "avg_packet_size",
        "packet_ratio"
    ]

    df = pd.DataFrame([features], columns=columns)

    prob = model.predict_proba(df)[0][1]  # probability of attack

    print("ATTACK PROB:", prob)

    # 🔥 ADJUST THRESHOLD HERE
    return prob > 0.7   # stricter (reduce false positives)