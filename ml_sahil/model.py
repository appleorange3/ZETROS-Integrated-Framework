import pandas as pd
import joblib

model = joblib.load("ml/model.pkl")

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