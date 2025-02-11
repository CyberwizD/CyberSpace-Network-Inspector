import streamlit as st
import numpy as np
import pandas as pd
import socket
import nmap
from sklearn.ensemble import IsolationForest

st.logo(image="static/logo.png", size="small", link="https://github.com/CyberwizD")

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
        "Timestamp": pd.date_range(start="2022-01-01", periods=100, freq="h"),
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
    st.line_chart(malware_indices)

# Vulnerability Scanning Tab
elif options == "Vulnerability Scanning":
    st.subheader("Vulnerability Scanning")

    # Retrieve the local host IP address
    host_ip = socket.gethostbyname_ex(socket.gethostname())[-1][-1]
    subnet = '.'.join(host_ip.split('.')[:-1]) + '.0/24'

    # Scan the network for active hosts
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-sn')
    hosts = [host for host in nm.all_hosts() if nm[host].state() == "up"]

    # Check if any hosts are found
    if not hosts:
        st.write("No active hosts found in the network.")
    else:
        # Simulated vulnerability data based on active hosts

        risk_levels = [3, 5, 2, 4]  # Simulated risk levels for illustration
        vulnerability_data = pd.DataFrame({
            "Host": hosts,
            "Risk Level": [risk_levels[i % len(risk_levels)] for i in range(len(hosts))]  # Cycle through risk levels
        })

        # Prepare data for bar chart
        vulnerability_data.set_index("Host", inplace=True)

        # Display bar chart
        st.write("Vulnerability Risk Levels:")
        st.bar_chart(vulnerability_data["Risk Level"])

# Footer
st.sidebar.markdown("### About")
st.sidebar.caption("This application provides insights into network security through anomaly detection, malware analysis, and vulnerability scanning.")