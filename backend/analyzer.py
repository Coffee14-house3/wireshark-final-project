# analyzer.py
from scapy.all import PcapReader
from flask import Blueprint
import matplotlib.pyplot as plt
from collections import defaultdict, Counter
import base64
from io import BytesIO
import logging
import os
import traceback

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def analyze_pcap_for_web(pcap_file):
    """
    Analyzes a PCAP file and generates visualizations for web display.

    Args:
        pcap_file (str): Path to the PCAP file.

    Returns:
        dict: A dictionary containing base64-encoded images of the generated plots.
    """
    try:
        logger.info(f"Starting analysis of PCAP file: {pcap_file}")
        if not os.path.exists(pcap_file):
            raise FileNotFoundError(f"File not found: {pcap_file}")

        # Use Scapy's PcapReader which doesn't require Wireshark/tshark
        logger.info("Successfully created PcapReader object")

        # Initialize data structures
        packet_lengths = []
        protocol_count = defaultdict(int)
        timestamps = []
        packet_count = 0

        # Analyze each packet
        logger.info("Starting packet analysis...")
        try:
            with PcapReader(pcap_file) as pcap_reader:
                for packet in pcap_reader:
                    packet_count += 1
                    packet_lengths.append(len(packet))
                    timestamps.append(float(packet.time))

                    # Count protocols dynamically by iterating through Scapy layers
                    layer = packet
                    while layer:
                        protocol_count[layer.name] += 1
                        layer = layer.payload

                # Progress log for large files
                if packet_count % 1000 == 0:
                    logger.info(f"Processed {packet_count} packets...")

        except Exception as e:
            logger.error(f"Error processing packets: {str(e)}")
            raise

        logger.info(f"Completed processing {packet_count} packets")

        if packet_count == 0:
            logger.error("No packets were processed")
            raise ValueError("No packets found in the PCAP file")

        # Sort timestamps to ensure time-based plots work correctly
        timestamps, packet_lengths = zip(*sorted(zip(timestamps, packet_lengths)))

        # Generate plots and convert to base64
        plots = {}

        logger.info("Generating visualization plots...")

        # Set the style for dark theme compatibility
        plt.style.use('dark_background')

        # 1️⃣ Packet Length Distribution
        plt.figure(figsize=(8, 6))
        plt.hist(packet_lengths, bins=50, color='#5AB0FF', alpha=0.7)
        plt.title('Packet Length Distribution')
        plt.xlabel('Packet Length (bytes)')
        plt.ylabel('Frequency')
        plt.grid(True, alpha=0.3)
        plots['length_dist'] = "data:image/png;base64," + fig_to_base64()
        plt.close()

        # 2️⃣ Protocol Distribution
        plt.figure(figsize=(8, 6))
        plt.bar(protocol_count.keys(), protocol_count.values(), color='#50C878', alpha=0.7)
        plt.title('Protocol Distribution')
        plt.xlabel('Protocol')
        plt.ylabel('Number of Packets')
        plt.xticks(rotation=45)
        plt.grid(True, alpha=0.3)
        plots['protocol_dist'] = "data:image/png;base64," + fig_to_base64()
        plt.close()

        # 3️⃣ Traffic Over Time
        plt.figure(figsize=(8, 6))
        plt.plot(timestamps, packet_lengths, color='#FF6B6B', alpha=0.7)
        plt.title('Traffic Over Time')
        plt.xlabel('Time (seconds)')
        plt.ylabel('Packet Length (bytes)')
        plt.grid(True, alpha=0.3)
        plots['traffic_time'] = "data:image/png;base64," + fig_to_base64()
        plt.close()

        # 4️⃣ Packet Count Over Time
        plt.figure(figsize=(8, 6))
        plt.plot(timestamps, range(1, packet_count + 1), color='#B19CD9', alpha=0.7)
        plt.title('Packet Count Over Time')
        plt.xlabel('Time (seconds)')
        plt.ylabel('Cumulative Packet Count')
        plt.grid(True, alpha=0.3)
        plots['packet_count'] = "data:image/png;base64," + fig_to_base64()
        plt.close()

        logger.info("Successfully generated all plots")
        return plots

    except Exception as e:
        logger.error(f"Error analyzing PCAP file: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise

def fig_to_base64():
    """
    Converts a matplotlib figure to a base64-encoded image.

    Returns:
        str: Base64-encoded image data.
    """
    try:
        buf = BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', facecolor='#2D2D2D')
        buf.seek(0)
        image_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        buf.close()
        return image_base64
    except Exception as e:
        logger.error(f"Error converting figure to base64: {str(e)}")
        raise
