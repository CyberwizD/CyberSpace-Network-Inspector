import streamlit as st
import scapy.all as scapy
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP

@st.cache_data
def run_network_analysis():
    # Capture network traffic
    packets = scapy.sniff(count=100)

    # Analyze network protocols
    protocol_analysis = analyze_protocols(packets)

    # Visualize network topology
    network_topology = visualize_network_topology(packets)

    # Display results
    st.write("Protocol Analysis:")
    st.write(protocol_analysis)
    st.write("Network Topology:")
    st.pyplot(network_topology)

def analyze_protocols(packets):
    # Analyze network protocols using Scapy
    protocols = []
    for packet in packets:
        protocols.append(packet.proto)
    return protocols

def visualize_network_topology(packets):
    # Create a NetworkX graph
    G = nx.Graph()
    for packet in packets:
        G.add_node(packet.src)
        G.add_node(packet.dst)
        G.add_edge(packet.src, packet.dst)
    # Draw the graph using Matplotlib
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_color='lightblue')
    plt.show()
    return plt

packet_list = []

def packet_callback(packet):
    if IP in packet:
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        packet_data = {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": protocol,
            "size": len(packet)
        }
        packet_list.append(packet_data)

# Capture network packets (Run with sudo if required)
sniff(prn=packet_callback, store=False, count=100)
df = pd.DataFrame(packet_list)
print(df.head())