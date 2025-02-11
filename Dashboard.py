import streamlit as st
import pandas as pd
import psutil
import time
import speedtest
import threading
import plotly.express as px
from ping3 import ping
from scapy.all import sniff, IP, TCP, UDP
from analysis import network_analysis, security_analysis

st.set_page_config(
    page_title="CyberSpace Network Inspector", 
    page_icon=":shield:",
    layout="wide"
)

st.logo(image="static/logo.png", size="small", link="https://github.com/CyberwizD")

# Sidebar
st.sidebar.title("Settings")
filter_option = st.sidebar.selectbox("Choose Filter", ["TCP", "UDP"])

# Streamlit UI
st.title("Network Analysis Dashboard")
st.write("Here's a brief overview of your network and security analysis.")

tabs = st.tabs(["📈 Network Analysis", "🛡️ Security Analysis"])

# # Global variable to store captured packets
packet_list = []
stop_event = threading.Event()

# Packet sniffing function (runs in a separate thread)
def packet_callback(packet):
    if IP in packet:
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        packet_data = {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": protocol,
            "size": len(packet),
            "timestamp": pd.to_datetime("now")  # Add timestamp for x-axis
        }
        packet_list.append(packet_data)

# Start packet sniffing in a thread
def start_sniffing():
    sniff(prn=packet_callback, store=False, count=0)

# Real-time network performance metrics
@st.cache_data
def get_network_metrics():
    stats = psutil.net_io_counters()
    try:
        speed = speedtest.Speedtest()
        upload_speed = speed.upload() / 1_000_000  # Convert to Mbps
        download_speed = speed.download() / 1_000_000  # Convert to Mbps
    except Exception as e:
        st.error(f"Speedtest failed: {e}")
        upload_speed = download_speed = None

    return {
        "bytes_sent": stats.bytes_sent,
        "bytes_received": stats.bytes_recv,
        "packets_sent": stats.packets_sent,
        "packets_received": stats.packets_recv,
        "upload_speed": upload_speed,
        "download_speed": download_speed
    }

# Security Analysis Tab
with tabs[1]:
    st.write("This section will run your security analysis.")
    # network_analysis.run_network_analysis()

    security_analysis.run_security_analysis()

# Network Analysis Tab
with tabs[0]:
    left_col, right_col = st.columns(2)

    with left_col:
        st.subheader("Network Performance Metrics")
        metrics = get_network_metrics()
        st.metric("Upload Speed (Mbps)", round(metrics["upload_speed"], 2) if metrics["upload_speed"] else "N/A")
        st.metric("Download Speed (Mbps)", round(metrics["download_speed"], 2) if metrics["download_speed"] else "N/A")
        st.metric("Bytes Sent", metrics["bytes_sent"])
        st.metric("Bytes Received", metrics["bytes_received"])

        sniff(prn=packet_callback, store=False, count=10)  # Capture 10 packets

    df_packets = pd.DataFrame(packet_list)

    with right_col:
        if not df_packets.empty:
            # Visualization of Network Traffic
            st.subheader("Traffic Distribution")
            fig = px.histogram(df_packets, x="protocol", title="Protocol Distribution")
            st.plotly_chart(fig)
        else:
            st.subheader("Traffic Distribution")
            st.write("No data to display yet.")

    st.header("Live Packet Capture")

    start_btn, stop_btn = st.columns(2, gap="small")
    with start_btn:
        if st.button("Start Capture"):
            threading.Thread(target=start_sniffing, daemon=True).start()
            st.success("Packet capture started.")
            
    with stop_btn:
        if st.button("Stop Capture"):
            stop_event.set()
            st.error("Packet capture stopped.")            

    # Reserve space for real-time chart updates
    chart_placeholder = st.empty()

    # Real-time dynamic chart for packet sizes over time
    while True:
        if packet_list:
            df_packets = pd.DataFrame(packet_list)
            fig_line = px.line(
                df_packets,
                x='timestamp',
                y='size',
                title='Packet Size Over Time',
                labels={'timestamp': 'Time', 'size': 'Packet Size (Bytes)'}
            )
            fig_line.update_layout(
                xaxis_title='Time',
                yaxis_title='Packet Size (Bytes)',
                xaxis=dict(showgrid=True),
                yaxis=dict(showgrid=True)
            )
            # Update the chart with a unique key
            chart_placeholder.plotly_chart(fig_line, key=f"live_packet_chart_{int(time.time())}")
        else:
            st.write("No packets captured yet.")
            break

        # Sleep to update chart every second
        time.sleep(1)
