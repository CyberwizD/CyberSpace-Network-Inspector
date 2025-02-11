import nmap
import folium
import requests
import socket
import psutil
import pandas as pd
import networkx as nx
import streamlit as st
import matplotlib.pyplot as plt
from streamlit_folium import st_folium
from scapy.all import sniff, IP, TCP, UDP

st.logo(image="static/logo.png", size="small", link="https://github.com/CyberwizD")

@st.cache_data
def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        public_ip = response.json()['ip']
        return public_ip
    except Exception as e:
        st.error(f"Error retrieving public IP: {e}")
        return None

# Function to check if an IP is public or private
@st.cache_data
def is_public_ip(ip_address):
    blocks = ip_address.split('.')
    first_octet = int(blocks[0])
    
    # Private IP ranges
    if first_octet == 10:
        return False
    if first_octet == 172 and 16 <= int(blocks[1]) <= 31:
        return False
    if first_octet == 192 and blocks[1] == '168':
        return False
    return True

# # Function to get geolocation of an IP using ipinfo.io
@st.cache_data
def get_geolocation(ip_address):
    if not is_public_ip(ip_address):
        st.warning(f"IP {ip_address} is private, geolocating the public IP of the network.")
        public_ip = get_public_ip()
        if public_ip:
            st.write(f"Public IP of the network: {public_ip}")
            return get_geolocation(public_ip)  # Recursively geolocate the public IP
        else:
            return None, None  # No geolocation available
    else:
        try:
            response = requests.get(f'http://ipinfo.io/{ip_address}/json')
            data = response.json()
            location = data['loc'].split(',') if 'loc' in data else None
            return (float(location[0]), float(location[1])) if location else (None, None)
        except Exception as e:
            st.error(f"Error retrieving geolocation for {ip_address}: {e}")
            return None, None

# Function to create the Folium map and add network nodes
@st.cache_data
def create_folium_map(hosts):
    m = folium.Map(location=[45.5236, -122.6750], zoom_start=1)
    
    for host in hosts:
        lat, lon = get_geolocation(host)
        if lat and lon:
            # Add the host as a marker on the map
            folium.Marker([lat, lon], popup=f"Host: {host}").add_to(m)
        else:
            st.warning(f"Could not retrieve geolocation for host {host}")
    
    return m

packet_list = []

def packet_callback(packet):
    if IP in packet:
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        packet_data = {
            "Source IP": packet[IP].src,
            "Destination IP": packet[IP].dst,
            "Protocol": protocol,
            "Size": len(packet)
        }
        packet_list.append(packet_data)

# Function to create and draw a graph
def draw_graph(G):
    pos = nx.spring_layout(G)  # positions for all nodes
    plt.figure(figsize=(8, 6))
    nx.draw(G, pos, with_labels=True, node_color='skyblue', node_size=2000, font_size=16, font_color='black', edge_color='gray')
    plt.title("Network Topology", fontsize=20)
    st.pyplot(plt)

# Initialize Streamlit app
st.title("Geographical Network Topology Analysis")

# Sidebar for Network Configuration
st.sidebar.title("Network Configuration")

# Hostname and Host IP
hostname = socket.gethostname()
host_ip = socket.gethostbyname(hostname)

st.sidebar.write(f"**Host Name:** {hostname}")
st.sidebar.write(f"**Host IP:** {host_ip}")

# Get the local host IP address
host_ip = socket.gethostbyname_ex(socket.gethostname())[-1][-1]

# Extract the network part (first three octets) and append /24
subnet = '.'.join(host_ip.split('.')[:-1]) + '.0/24'

# Scan the network
nm = nmap.PortScanner()
nm.scan(hosts=f"{subnet}", arguments='-sn')
hosts = [host for host in nm.all_hosts() if nm[host].state() == "up"]

# Display active hosts
st.sidebar.title("Active Hosts")
for host in hosts:
    st.sidebar.write(f'Host {host} {nm[host].hostname()} is up')

# Get and display detailed network interfaces information
st.markdown("### Network Interfaces")

# Get network interface information
interfaces = psutil.net_if_addrs()
interface_info = []

for interface, addresses in interfaces.items():
    for address in addresses:
        if address.family == socket.AF_INET:  # IPv4 addresses
            interface_info.append({
                "Interface": interface,
                "Address": address.address,
                "Netmask": address.netmask,
                "Broadcast": address.broadcast
            })

# Create a DataFrame to display the interface information
if interface_info:
    interface_df = pd.DataFrame(interface_info)
    st.dataframe(interface_df, width=700)
else:
    st.write("No network interfaces found.")

# Create a graph representation of the network
G = nx.Graph()
for i in range(len(hosts)):
    for j in range(i + 1, len(hosts)):
        G.add_edge(hosts[i], hosts[j])  # Connect all active hosts

# Analyze network topology
if len(hosts) > 0:
    st.subheader("Network Topology Analysis")
    
    if st.checkbox("View packet data"):
        # Capture network packets (Run with sudo if required)
        sniff(prn=packet_callback, store=False, count=100)
        df = pd.DataFrame(packet_list)
        st.table(df.head())
    
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
    if st.checkbox("View Network Topology"):
        draw_graph(G)

    # Display the map with geolocated network nodes
    folium_map = create_folium_map(hosts)
    st_folium(folium_map, width=700, height=500)

else:
    st.write("No active hosts found in the specified range.")
