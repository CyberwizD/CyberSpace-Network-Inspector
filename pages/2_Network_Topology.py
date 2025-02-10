# import nmap
# import networkx as nx
# import streamlit as st

# nm = nmap.PortScanner()
# nm.scan(hosts='192.168.1.0/24', arguments='-sn')
# for host in nm.all_hosts():
#     st.write(f'Host {host} ({nm[host].hostname()}) is up')

# G = nx.Graph()
# G.add_edges_from([(1, 2), (1, 3), (2, 3)])
# nx.draw(G)


import nmap
import networkx as nx
import streamlit as st
import matplotlib.pyplot as plt

# Function to create and draw a graph
@st.cache_data
def draw_graph(G):
    pos = nx.spring_layout(G)  # positions for all nodes
    plt.figure(figsize=(8, 6))
    nx.draw(G, pos, with_labels=True, node_color='skyblue', node_size=2000, font_size=16, font_color='black', edge_color='gray')
    plt.title("Network Topology", fontsize=20)
    st.pyplot(plt)

# Initialize Streamlit app
st.title("Network Topology Analysis")

# Scan the network
nm = nmap.PortScanner()
nm.scan(hosts='192.168.1.0/24', arguments='-sn')
hosts = [host for host in nm.all_hosts() if nm[host].state() == "up"]

# Display active hosts
st.subheader("Active Hosts")
for host in hosts:
    st.write(f'Host {host} ({nm[host].hostname()}) is up')

# Create a graph representation of the network
G = nx.Graph()
for i in range(len(hosts)):
    for j in range(i + 1, len(hosts)):
        G.add_edge(hosts[i], hosts[j])  # Connect all active hosts

# Analyze network topology
if len(hosts) > 0:
    st.subheader("Network Topology Analysis")
    
    # Identify and display network topology type
    num_edges = G.number_of_edges()
    num_nodes = G.number_of_nodes()
    max_edges = num_nodes * (num_nodes - 1) / 2  # Maximum edges in a complete graph

    if num_edges == max_edges:
        topology_type = "Fully Connected"
    else:
        topology_type = "Partial"
    
    st.write(f"Identified Topology Type: {topology_type}")

    # Draw the graph
    draw_graph(G)

    # Additional analysis can be added here (e.g., segmentation, performance)
    st.write("Further analysis on network segmentation and its role in security and performance can be conducted based on the topology.")
else:
    st.write("No active hosts found in the specified range.")