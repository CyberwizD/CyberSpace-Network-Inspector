import streamlit as st
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.ensemble import IsolationForest

# Assuming data is network metrics (e.g., packet size, frequency)
X = np.array([[50, 1], [100, 2], [150, 1], [6000, 10]])  # Example data
clf = IsolationForest(random_state=0).fit(X)
outliers = clf.predict(X)
st.write(outliers)

# Generate sample network traffic data (replace with real data)
X = np.random.rand(1000, 4)  # Simulated features (e.g., packet size, latency, bandwidth, etc.)
model = IsolationForest(contamination=0.05)  # 5% anomalies
model.fit(X)

# Save the model
joblib.dump(model, r"C:\Users\WISDOM\Documents\Python Codes\StreamLit\CyberSpace Network Inspector\network_anomaly_model.pkl")

# Load the trained model
model = joblib.load(r"C:\Users\WISDOM\Documents\Python Codes\StreamLit\CyberSpace Network Inspector\network_anomaly_model.pkl")

# Function to detect anomalies
@st.cache_data
def detect_anomalies(data):
    predictions = model.predict([data])
    return "Anomaly" if predictions[0] == -1 else "Normal"

# Example usage
sample_data = [0.5, 0.2, 0.8, 0.3]  # Replace with real-time values
st.write(f"Traffic Status: {detect_anomalies(sample_data)}")
