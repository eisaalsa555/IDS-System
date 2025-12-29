# src/ml_model.py
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from joblib import dump, load
import os

MODEL_PATH = os.path.join("data", "anomaly_model.joblib")

# 🧠 TRAINING FUNCTION
def train_model(dataset_path):
    """
    Simple anomaly detection model (Isolation Forest).
    dataset_path → CSV file jisme packet stats ka data hai.
    """
    df = pd.read_csv(dataset_path)

    # Example features (aap apne packet stats ke hisab se badal sakte ho)
    features = df[["packet_rate", "unique_ports", "avg_packet_size"]]

    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(features)

    dump(model, MODEL_PATH)
    print(f"✅ Model trained & saved at {MODEL_PATH}")

# 🧪 INFERENCE FUNCTION
def detect_anomaly(packet_stats):
    """
    packet_stats → dict: {"packet_rate": X, "unique_ports": Y, "avg_packet_size": Z}
    return → True (suspicious) / False (normal)
    """
    if not os.path.exists(MODEL_PATH):
        print("⚠️ No model found — returning normal")
        return False

    model = load(MODEL_PATH)
    X = np.array([[packet_stats["packet_rate"],
                   packet_stats["unique_ports"],
                   packet_stats["avg_packet_size"]]])

    prediction = model.predict(X)  # -1 means anomaly
    return prediction[0] == -1
