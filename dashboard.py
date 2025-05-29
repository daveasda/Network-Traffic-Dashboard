import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
from datetime import datetime
import threading
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PacketProcessor:
    """Process and analyze network packets"""

    def __init__(self):
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        self.packet_data = []
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()

    def get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name"""
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')

    def process_packet(self, packet) -> None:
        """Process a single packet and extract relevant information"""
        try:
            if IP in packet:
                with self.lock:
                    packet_info = {
                        'timestamp': datetime.now(),
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (datetime.now() - self.start_time).total_seconds()
                    }

                    # Add TCP-specific information
                    if TCP in packet:
                        packet_info.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                            'tcp_flags': str(packet[TCP].flags)
                        })

                    # Add UDP-specific information
                    elif UDP in packet:
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport
                        })

                    self.packet_data.append(packet_info)
                    self.packet_count += 1
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def get_dataframe(self) -> pd.DataFrame:
        """Convert packet data to a pandas DataFrame"""
        with self.lock:
            return pd.DataFrame(self.packet_data)

# Initialize PacketProcessor
processor = PacketProcessor()

# Start packet sniffing in a separate thread
def start_sniffing():
    sniff(prn=processor.process_packet, store=False)

sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
sniff_thread.start()

# Streamlit dashboard
st.title("Real-time Network Traffic Dashboard")

# Main loop to update dashboard
while True:
    df = processor.get_dataframe()
    if not df.empty:
        # Protocol distribution
        protocol_counts = df['protocol'].value_counts().reset_index()
        protocol_counts.columns = ['Protocol', 'Count']
        fig_protocol = px.pie(protocol_counts, names='Protocol', values='Count', title='Protocol Distribution')
        st.plotly_chart(fig_protocol)

        # Packets over time
        df['minute'] = df['timestamp'].dt.floor('T')
        packets_per_minute = df.groupby('minute').size().reset_index(name='Packets')
        fig_time = px.line(packets_per_minute, x='minute', y='Packets', title='Packets Over Time')
        st.plotly_chart(fig_time)

        # Top source IPs
        top_sources = df['source'].value_counts().head(10).reset_index()
        top_sources.columns = ['Source IP', 'Count']
        fig_sources = px.bar(top_sources, x='Source IP', y='Count', title='Top Source IPs')
        st.plotly_chart(fig_sources)

        # Display recent packets
        st.subheader("Recent Packets")
        st.dataframe(df.tail(10))
    else:
        st.write("Waiting for packets...")

    time.sleep(5)
