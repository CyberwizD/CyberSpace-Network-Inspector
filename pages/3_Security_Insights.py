import streamlit as st
import nmap
import pandas as pd
import psutil
import socket
import threading
from scapy.all import sniff, IP
import time

st.logo(image="static/logo.png", size="small", link="https://github.com/CyberwizD")

# Initialize global variables
packet_data = []
capture_running = False
vulnerabilities = []
scanning = False

byte_sent = 0
byte_rec = 0

# Initialize Nmap scanner
scanner = nmap.PortScanner()

# Function to scan network segments
def scan_network():
    global vulnerabilities, scanning
    scanning = True
    ip_range = f"{socket.gethostbyname_ex(socket.gethostname())[-1][-1]}"  # Local IP
    scanner.scan(ip_range, arguments='--script vuln')  # Scan for vulnerabilities
    vulnerabilities.clear()
    
    for host in scanner.all_hosts():
        if 'vulns' in scanner[host]:
            vulnerabilities.append((host, scanner[host]['vulns']))
    
    scanning = False

# Function to capture packets
def packet_callback(packet):
    global packet_data
    if IP in packet:
        packet_data.append(packet[IP].src)

# Start packet capture in a thread
def start_capture():
    global capture_running
    capture_running = True
    sniff(prn=packet_callback, store=0)

# Stop packet capture
def stop_capture():
    global capture_running
    capture_running = False

# Streamlit App Title
st.title("Network Security and Performance Analysis")
st.subheader("Network Segmentation Analysis")

st.sidebar.title("Network Metrics")

# Use st.empty() placeholders for network metrics so they can be updated dynamically
bytes_sent_placeholder = st.sidebar.empty()
bytes_received_placeholder = st.sidebar.empty()

# Network Segmentation Button
if st.button("Scan Network"):
    st.write("Scanning network for vulnerabilities...")
    threading.Thread(target=scan_network, daemon=True).start()

    # Add a loading spinner while scanning
    with st.spinner("Scanning..."):
        while scanning:  # Wait for the scan to finish
            time.sleep(1)

    # Display vulnerabilities in a DataFrame
    if vulnerabilities:
        st.write("Vulnerabilities found:")
        vuln_data = [(host, vuln) for host, vulns in vulnerabilities for vuln in vulns.items()]
        vuln_df = pd.DataFrame(vuln_data, columns=["Host", "Vulnerability"])
        st.dataframe(vuln_df)
    else:
        st.write("No vulnerabilities found.")

st.subheader("Packet Capture Analysis")

# Start and Stop Capture Buttons
start_col, stop_col = st.columns(2)

with start_col:
    if st.button("Start Packet Capture"):
        packet_data.clear()  # Clear previous data
        threading.Thread(target=start_capture, daemon=True).start()
        st.success("Packet capture started...")

with stop_col:
    if st.button("Stop Packet Capture"):
        stop_capture()
        st.error("Packet capture stopped.")

# Display Bandwidth Utilization as Bar Chart
st.header("Bandwidth Utilization")

# Reserve space for the bar chart
chart_placeholder = st.empty()

# Continuous update of bytes sent and received
while True:
    net_io = psutil.net_io_counters()
    bytes_sent = net_io.bytes_sent
    bytes_received = net_io.bytes_recv
    
    # Create a DataFrame for the bar chart
    data = pd.DataFrame({
        'Metric': ['Bytes Sent', 'Bytes Received'],
        'Value': [bytes_sent, bytes_received]
    })

    # Display the bar chart
    chart_placeholder.bar_chart(data.set_index('Metric'))

    # Sleep for a short duration before updating
    time.sleep(1)

    # Update the sidebar values
    bytes_sent_placeholder.write(f"Bytes Sent: {bytes_sent}")
    bytes_received_placeholder.write(f"Bytes Received: {bytes_received}")

    # Break the loop if capture is stopped
    if not capture_running:
        break

# Display captured packets after stopping
if not capture_running and packet_data:
    st.header("Captured Packets")
    st.write("Captured IP Addresses:")
    st.write(packet_data)