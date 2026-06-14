
# protocol analyzer backend file
from scapy.all import rdpcap, IP, TCP, UDP
import logging

logger = logging.getLogger(__name__)

def analyze_pcap(pcap_file):
    """Analyze PCAP file and extract relevant information."""
    try:
        packets = rdpcap(pcap_file)
        
        analysis = {
            'packet_count': len(packets),
            'byte_count': sum(len(packet) for packet in packets),
            'protocols': {},
            'packets': []
        }
        
        for packet in packets:
            packet_info = {
                'magic_number': hex(0xa1b2c3d4),  # Standard PCAP magic number
                'interface_info': packet.sniffed_on if hasattr(packet, 'sniffed_on') else 'Unknown',
                'link_layer_type': packet.type if hasattr(packet, 'type') else 'Unknown',
                'timestamp': packet.time if hasattr(packet, 'time') else 'Unknown',
                'length': len(packet)
            }
            
            # Extract IP information
            if IP in packet:
                protocol = packet[IP].proto
                if protocol not in analysis['protocols']:
                    analysis['protocols'][protocol] = 0
                analysis['protocols'][protocol] += 1
                
                packet_info.update({
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': protocol,
                    'network_header': packet[IP].summary(),
                    'ttl': packet[IP].ttl,
                    'ip_id': packet[IP].id,
                })
                
                # Extract TCP/UDP information
                if TCP in packet:
                    packet_info.update({
                        'protocol_name': 'TCP',
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'window_length': packet[TCP].window,
                        'seq': packet[TCP].seq,
                        'ack': packet[TCP].ack,
                        'flags': packet[TCP].flags,
                    })
                elif UDP in packet:
                    packet_info.update({
                        'protocol_name': 'UDP',
                        'src_port': packet[UDP].sport,
                        'dst_port': packet[UDP].dport,
                        'length': packet[UDP].len,
                    })
                
                # Extract payload (safely handle binary data)
                if hasattr(packet, 'load'):
                    try:
                        payload = packet.load.hex()
                        packet_info['payload'] = payload[:100] + '...' if len(payload) > 100 else payload
                    except:
                        packet_info['payload'] = 'Binary data'
                else:
                    packet_info['payload'] = 'No payload'
                    
            analysis['packets'].append(packet_info)
        
        return analysis
        
    except Exception as e:
        logger.error(f"Error analyzing PCAP file: {str(e)}")
        raise
