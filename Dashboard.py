import streamlit as st
import pandas as pd
import psutil
import time
import speedtest
import plotly.express as px
from ping3 import ping
from scapy.all import sniff, IP, TCP, UDP
from analysis import network_analysis, security_analysis

# response_time = ping('google.com')
# st.write(f"Ping to Google: {response_time} ms")

st.set_page_config(
    page_title="CyberSpace Network Inspector", 
    page_icon=":Network:",
    layout="wide"
)

st.logo(
    image=r"C:\Users\WISDOM\Documents\Python Codes\StreamLit\CyberSpace Network Inspector\static\google.png",
    size="small",
    link="https://static.streamlit.io/examples/cat.jpg",
)

# Sidebar
st.sidebar.title("Settings")
filter_option = st.sidebar.selectbox("Choose Filter", ["TCP", "UDP"])

# Streamlit UI
st.title("Network Analysis Dashboard")
st.write("Here's a brief overview of your network and security analysis.")

tabs = st.tabs(["📈 Network Analysis", "🛡️ Security Analysis"])

# Network Analysis Tab
with tabs[0]:
    packet_list = []

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

    # Real-time network performance metrics
    @st.cache_data
    def get_network_metrics():
        stats = psutil.net_io_counters()
        try:
            import speedtest
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

    left_col, right_col = st.columns(2)

    with left_col:
        st.header("Network Performance Metrics")
        metrics = get_network_metrics()
        st.metric("Upload Speed (Mbps)", round(metrics["upload_speed"], 2) if metrics["upload_speed"] else "N/A")
        st.metric("Download Speed (Mbps)", round(metrics["download_speed"], 2) if metrics["download_speed"] else "N/A")
        st.metric("Bytes Sent", metrics["bytes_sent"])
        st.metric("Bytes Received", metrics["bytes_received"])

    with right_col:
        st.header("Live Packet Capture")
        sniff(prn=packet_callback, store=False, count=10)  # Capture 10 packets

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
            # Update the chart with a unique key using time or index
            chart_placeholder.plotly_chart(fig_line, key=f"live_packet_chart_{int(time.time())}")
        else:
            st.write("No packets captured yet.")

        # Sleep to update chart every second
        time.sleep(1)

# Security Analysis Tab
with tabs[1]:
    st.header("Security Analysis")
    st.write("This section will run your security analysis.")
    # security_analysis.run_security_analysis()

# Traffic Monitor
st.header("Traffic Monitor")
if st.button("Start Monitoring"):
    # Placeholder for live data
    st.write("Monitoring...")
