import streamlit as st
import nmap
import pandas as pd
import matplotlib.pyplot as plt
import psutil
import time
import threading
from scapy.all import sniff, IP

# Initialize nmap scanner
scanner = nmap.PortScanner()

# Function to scan network segments
def scan_network():
    st.subheader("Network Segmentation Analysis")
    st.write("Scanning network for vulnerabilities...")
    scan_results = scanner.all_hosts()
    vulnerabilities = []
    
    for host in scan_results:
        scanner.scan(host, arguments='--script vuln')
        if 'vulns' in scanner[host]:
            vulnerabilities.append((host, scanner[host]['vulns']))
    
    return vulnerabilities

# Function to capture packets and filter
def packet_callback(packet):
    global packet_data
    if packet.haslayer(IP):
        packet_data.append(packet[IP].src)

packet_data = []

# Start packet capture in a thread
def capture_packets():
    sniff(filter="ip", prn=packet_callback, store=0)

# Function to plot bandwidth utilization
def plot_bandwidth_utilization():
    net_io = psutil.net_io_counters()
    bytes_sent = net_io.bytes_sent
    bytes_recv = net_io.bytes_recv
    data = {'Sent (bytes)': bytes_sent, 'Received (bytes)': bytes_recv}
    
    fig, ax = plt.subplots()
    ax.bar(data.keys(), data.values())
    ax.set_ylabel('Bytes')
    ax.set_title('Bandwidth Utilization')
    st.pyplot(fig)

# Function to display performance metrics
def display_performance_metrics():
    st.subheader("Performance Metrics")
    st.write("Monitoring network performance...")
    while True:
        net_io = psutil.net_io_counters()
        st.write(f"Bytes Sent: {net_io.bytes_sent}")
        st.write(f"Bytes Received: {net_io.bytes_recv}")
        time.sleep(2)

# Streamlit App
st.title("Network Security and Performance Analysis")

# Network Segmentation
vulnerabilities = scan_network()
if vulnerabilities:
    st.write("Vulnerabilities found:")
    for host, vuln in vulnerabilities:
        st.write(f"Host: {host}, Vulnerabilities: {vuln}")
else:
    st.write("No vulnerabilities found.")

# Start packet capture
if st.button("Start Packet Capture"):
    packet_data = []
    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.start()
    st.write("Packet capture started...")

# Display captured packets
if st.button("Show Captured Packets"):
    if packet_data:
        st.write("Captured IP Addresses:")
        st.write(packet_data)
    else:
        st.write("No packets captured.")

# Bandwidth Utilization Chart
plot_bandwidth_utilization()

# Display Performance Metrics in a thread
performance_thread = threading.Thread(target=display_performance_metrics)
performance_thread.start()

# Additional analysis and features can be added here