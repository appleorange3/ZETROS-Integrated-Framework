import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Load data
train_df = pd.read_csv("UNSW_NB15_training-set.csv")
test_df = pd.read_csv("UNSW_NB15_testing-set.csv")

def preprocess(df):
    df = df.copy()

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
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    print(f"{name} Accuracy: {acc:.4f}")

    if acc > best_accuracy:
        best_accuracy = acc
        best_model = model

print("\nBest Model Selected ✅")

# Save best model
joblib.dump(best_model, "model.pkl")