import os
import pandas as pd
import numpy as np
import joblib

# These are the imports Pylance was complaining about:
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score

# --- Robust Path Configuration ---
# This ensures it finds the CSVs even if you run it from the root folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRAIN_PATH = os.path.join(BASE_DIR, "UNSW_NB15_training-set.csv")
TEST_PATH = os.path.join(BASE_DIR, "UNSW_NB15_testing-set.csv")
MODEL_SAVE_PATH = os.path.join(BASE_DIR, "model.pkl")

# Load data
print(f"📂 Loading data from {BASE_DIR}...")
try:
    train_df = pd.read_csv(TRAIN_PATH)
    test_df = pd.read_csv(TEST_PATH)
except FileNotFoundError as e:
    print(f"❌ Error: CSV files not found in {BASE_DIR}. Check your file names!")
    raise e

def preprocess(df):
    """
    Standardizes the raw UNSW-NB15 data into the 5 features 
    ZETROS Hub uses for live detection.
    """
    df = df.copy()

    # Avoid division by zero in duration
    df['dur'] = df['dur'].replace(0, 0.0001)

    total_packets = df['spkts'] + df['dpkts']
    total_bytes = df['sbytes'] + df['dbytes']

    df['requests_per_sec'] = total_packets / df['dur']
    df['avg_interval'] = df['dur'] / total_packets.replace(0, 1)
    df['bytes_per_sec'] = total_bytes / df['dur']
    df['avg_packet_size'] = total_bytes / total_packets.replace(0, 1)
    df['packet_ratio'] = df['spkts'] / (df['dpkts'] + 1)

    return df[[
        'requests_per_sec',
        'avg_interval',
        'bytes_per_sec',
        'avg_packet_size',
        'packet_ratio',
        'label'
    ]]

print("🧹 Preprocessing data...")
train_df = preprocess(train_df)
test_df = preprocess(test_df)

X_train = train_df.drop('label', axis=1)
y_train = train_df['label']

X_test = test_df.drop('label', axis=1)
y_test = test_df['label']

# Models to compare
models = {
    "Random Forest": RandomForestClassifier(n_estimators=100),
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "Decision Tree": DecisionTreeClassifier()
}

best_model = None
best_accuracy = 0

print("\n=== MODEL COMPARISON ===\n")

for name, model in models.items():
    print(f"🏋️ Training {name}...")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    print(f"📊 {name} Accuracy: {acc:.4f}")

    if acc > best_accuracy:
        best_accuracy = acc
        best_model = model

print(f"\n✅ Best Model Selected: {type(best_model).__name__} with {best_accuracy:.4f} accuracy")

# Save best model to the ml_sahil folder
print(f"💾 Saving model to {MODEL_SAVE_PATH}...")
joblib.dump(best_model, MODEL_SAVE_PATH)
print("🏁 Done!")