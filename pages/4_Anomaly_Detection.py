import streamlit as st
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# Set the title of the app
st.title("CyberSpace Network Inspector")

# Sidebar for navigation
st.sidebar.header("Navigation")
options = st.sidebar.radio("Select an option:", ["Intrusion Detection", "Malware Analysis", "Vulnerability Scanning"])

# Function to generate synthetic network traffic data
@st.cache_data
def generate_network_data():
    return np.random.rand(1000, 4) * np.array([5000, 10, 100, 100])  # Scale as needed

# Intrusion Detection
if options == "Intrusion Detection":
    st.subheader("Intrusion Detection System")

    # Generate synthetic network data
    X = generate_network_data()
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)

    # Predict anomalies
    outliers = model.predict(X)
    anomaly_df = pd.DataFrame(X, columns=["Packet Size", "Frequency", "Latency", "Bandwidth"])
    anomaly_df['Anomaly'] = outliers

    # Prepare data for scatter chart
    anomaly_df['Anomaly'] = anomaly_df['Anomaly'].replace({1: 'Normal', -1: 'Anomaly'})

    # Display scatter chart
    st.write("Anomaly Detection Results:")
    st.scatter_chart(anomaly_df[['Packet Size', 'Frequency']].rename(columns={"Packet Size": "x", "Frequency": "y"}))
    
    # Show anomalies separately
    anomaly_data = anomaly_df[anomaly_df['Anomaly'] == -1]
    if not anomaly_data.empty:
        st.write("Detected Anomalies:")
        st.dataframe(anomaly_data[['Packet Size', 'Frequency']])

# Malware Analysis
elif options == "Malware Analysis":
    st.subheader("Malware Analysis")

    # Simulated malware traffic indicators
    malware_data = pd.DataFrame({
        "Timestamp": pd.date_range(start="2022-01-01", periods=100, freq="H"),
        "Traffic Volume": np.random.randint(100, 1000, size=100),
        "Malware Indicator": np.random.choice([0, 1], size=100, p=[0.9, 0.1])  # 10% chance of malware
    })

    # Prepare data for line chart
    malware_data.set_index("Timestamp", inplace=True)

    # Display line chart
    st.write("Traffic Volume with Malware Indicators:")
    st.line_chart(malware_data["Traffic Volume"])

    # Highlight malware indicators
    malware_indices = malware_data[malware_data["Malware Indicator"] == 1].index
    st.write("Malware Detected at:")
    st.write(malware_indices)

# Vulnerability Scanning
elif options == "Vulnerability Scanning":
    st.subheader("Vulnerability Scanning")

    # Simulated vulnerability data
    vulnerability_data = pd.DataFrame({
        "Host": ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"],
        "Risk Level": [3, 5, 2, 4]  # 1 (Low) to 5 (Critical)
    })

    # Prepare data for bar chart
    vulnerability_data.set_index("Host", inplace=True)

    # Display bar chart
    st.write("Vulnerability Risk Levels:")
    st.bar_chart(vulnerability_data["Risk Level"])

# Footer
st.sidebar.markdown("### About")
st.sidebar.caption("This application provides insights into network security through anomaly detection, malware analysis, and vulnerability scanning.")