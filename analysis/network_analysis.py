import streamlit as st
import scapy.all as scapy
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6

# Define a dictionary to map protocol numbers to their names
PROTOCOL_MAP = {
    1: "ICMP",     # Internet Control Message Protocol
    2: "IGMP",     # Internet Group Management Protocol
    6: "TCP",      # Transmission Control Protocol
    17: "UDP",     # User Datagram Protocol
    47: "GRE",     # Generic Routing Encapsulation
    50: "ESP",     # Encapsulating Security Payload
    51: "AH",      # Authentication Header
}

@st.cache_data
def run_network_analysis():
    # Capture network traffic
    packets = scapy.sniff(count=100)

    # Analyze network protocols
    protocol_analysis = analyze_protocols(packets)

    # Create a DataFrame for the protocol analysis
    protocol_counts = pd.Series(protocol_analysis).value_counts()

    # Pie chart display (Plotly)
    st.subheader("Protocol Distribution (Pie Chart)")
    fig = px.pie(values=protocol_counts.values, names=protocol_counts.index, title="Protocol Distribution")
    st.plotly_chart(fig)

# Analyze protocols and convert protocol numbers to names
def analyze_protocols(packets):
    protocols = []
    
    for packet in packets:
        if IP in packet:
            proto_num = packet[IP].proto  # IPv4 protocol number
            protocol = PROTOCOL_MAP.get(proto_num, f"Unknown ({proto_num})")
            protocols.append(protocol)
        elif IPv6 in packet:
            proto_num = packet[IPv6].nh  # IPv6 next header (protocol number)
            protocol = PROTOCOL_MAP.get(proto_num, f"Unknown ({proto_num})")
            protocols.append(protocol)
        elif TCP in packet:
            protocols.append('TCP')  # If it's explicitly TCP
        elif UDP in packet:
            protocols.append('UDP')  # If it's explicitly UDP
        else:
            protocols.append('Unknown')  # Default for other cases
    
    return protocols
