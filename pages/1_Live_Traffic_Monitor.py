import streamlit as st
import psutil
import time
import threading
import pandas as pd
from scapy.all import sniff, IP

st.logo(image="static/logo.png", size="small", link="https://github.com/CyberwizD")

# Initialize variables
packet_count = 0
packet_loss = 0
latency = 0
bandwidth_utilization = 0
throughput = 0
stop_event = threading.Event()

# Ensure 'chart_data' is initialized in session state
if 'chart_data' not in st.session_state:
    st.session_state.chart_data = pd.DataFrame(columns=["Packet Count"])

# Function to capture packets
def packet_callback(packet):
    global packet_count
    if packet.haslayer(IP):
        packet_count += 1

# Function to calculate network metrics
def calculate_metrics():
    global packet_loss, latency, bandwidth_utilization, throughput
    # Update metrics
    packet_loss = (packet_count / 100).__round__(2) * 100  # Simplified assumption
    if psutil.net_io_counters().packets_sent > 0:
        latency = (psutil.net_io_counters().bytes_sent / (psutil.net_io_counters().packets_sent * 1000)).__round__(2)
    bandwidth_utilization = ((psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv) / \
                            (psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv)).__round__(2) * 100
    throughput = (psutil.net_io_counters().bytes_sent / (psutil.net_io_counters().packets_sent * 1000)).__round__(2)

# Function to capture packets in real-time
def capture_packets():
    sniff(filter="ip", prn=packet_callback, count=100)

# Streamlit App
st.title("Live Traffic Monitor")

# Sidebar for network metrics
st.sidebar.title("Network Metrics")

# Use st.empty() placeholders for network metrics so they can be updated dynamically
packet_count_placeholder = st.sidebar.empty()
packet_loss_placeholder = st.sidebar.empty()
latency_placeholder = st.sidebar.empty()
bandwidth_placeholder = st.sidebar.empty()
throughput_placeholder = st.sidebar.empty()

# Display the real-time line chart
st.subheader("Real-Time Packet Count")

# Use st.empty to create a placeholder for the chart
chart_placeholder = st.empty()

# Function to update the chart in the main thread
def update_chart():
    # Add packet count data to chart
    new_row = pd.DataFrame([[packet_count]], columns=["Packet Count"])
    st.session_state.chart_data = pd.concat([st.session_state.chart_data, new_row], ignore_index=True)
    # Re-render the chart
    chart_placeholder.line_chart(st.session_state.chart_data)

start_btn, stop_btn = st.columns(2, gap="large")

# Create a button to start capturing packets
with start_btn:
    if st.button("Start"):
        st.success("Packet capture started.")
        stop_event.clear()

        # Start packet capture in a thread
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.start()

# Button to stop capturing packets
with stop_btn:
    if st.button("Stop"):
        st.error("Packet capture stopped.")
        stop_event.clear()

# Continuously update the chart and metrics in the main Streamlit loop
while not stop_event.is_set():
    calculate_metrics()
    update_chart()
    
    # Update the sidebar values
    packet_count_placeholder.write(f"Packet Count: {packet_count}")
    packet_loss_placeholder.write(f"Packet Loss: {packet_loss} %")
    latency_placeholder.write(f"Latency: {latency} ms")
    bandwidth_placeholder.write(f"Bandwidth Utilization: {bandwidth_utilization} %")
    throughput_placeholder.write(f"Throughput: {throughput} kbps")
    
    time.sleep(1)  # Adjust sleep time for update frequency


