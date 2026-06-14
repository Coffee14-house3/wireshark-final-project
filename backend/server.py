from flask import Flask, render_template, send_file, Blueprint
from flask_socketio import SocketIO
import threading
from scapy.all import sniff, IP, TCP, UDP
import time
from collections import defaultdict, Counter
from datetime import datetime
from fpdf import FPDF
import tempfile
import os
from extensions import socketio

server_api = Blueprint("server_api", __name__)
# socketio = SocketIO(server_api)

# Global variables for packet capture
capturing = False
capture_thread = None
total_packets = 0
packet_count = 0
start_time = 0
bandwidth = 0
connections = defaultdict(set)
protocols = defaultdict(int)
ports = defaultdict(int)
packet_sizes = []

# Store alerts for PDF export
all_alerts = []

# DoS detection thresholds
DOS_PPS_THRESHOLD = 1000  # Packets per second threshold
DOS_BANDWIDTH_THRESHOLD = 10 * 1024 * 1024  # 10 MB/s in bytes
DOS_SYN_THRESHOLD = 100  # Number of SYN packets per second
DOS_CONNECTION_THRESHOLD = 1000  # Number of unique connections

# Brute Force detection thresholds
BRUTE_FORCE_ATTEMPTS_THRESHOLD = 10  # Number of failed attempts
BRUTE_FORCE_TIME_WINDOW = 60  # Time window in seconds
BRUTE_FORCE_PORTS = {22, 23, 3389, 21, 5900}  # Common brute force target ports

# Attack detection state
syn_count = 0
last_syn_check = time.time()
dos_alerts = []
login_attempts = defaultdict(list)  # Format: {(src_ip, dst_ip, port): [timestamp, timestamp, ...]}

class NetworkAnalysisReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Network Analysis Report', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, title, 0, 1, 'L', 1)
        self.ln(4)

    def chapter_body(self, content):
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, content)
        self.ln()

# @server_api.route('')
# def dashboard():
#     return render_template('dashboard.html')

@server_api.route('/server_api/export-pdf')
def export_pdf():
    try:
        # Create PDF with custom class
        pdf = NetworkAnalysisReport()
        pdf.alias_nb_pages()
        pdf.add_page()
        
        # Add timestamp
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 10, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1)
        pdf.ln(5)

        # Summary Section
        pdf.chapter_title('Summary')
        capture_duration = time.time() - start_time if start_time > 0 else 0
        avg_bandwidth = bandwidth / capture_duration if capture_duration > 0 else 0
        
        summary = (
            f'Total Packets: {total_packets}\n'
            f'Active Connections: {len(connections)}\n'
            f'Total Alerts: {len(all_alerts)}\n'
            f'Capture Duration: {capture_duration:.2f} seconds\n'
            f'Average Bandwidth: {avg_bandwidth/1024:.2f} KB/s'
        )
        pdf.chapter_body(summary)

        # Security Alerts Section
        if all_alerts:
            pdf.chapter_title('Security Alerts')
            for alert in all_alerts:
                pdf.chapter_body(alert)
        else:
            pdf.chapter_title('Security Alerts')
            pdf.chapter_body('No security alerts detected during capture.')

        # Protocol Distribution Section
        pdf.chapter_title('Protocol Distribution')
        for proto, count in protocols.items():
            percentage = (count/total_packets*100) if total_packets > 0 else 0
            pdf.chapter_body(f'{proto}: {count} packets ({percentage:.2f}%)')

        # Top Ports Section
        pdf.chapter_title('Top 10 Destination Ports')
        sorted_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]
        for port, count in sorted_ports:
            percentage = (count/total_packets*100) if total_packets > 0 else 0
            pdf.chapter_body(f'Port {port}: {count} packets ({percentage:.2f}%)')

        # Connection Details Section
        pdf.chapter_title('Connection Details')
        for conn, ports_set in connections.items():
            pdf.chapter_body(f'{conn} -> Ports: {", ".join(map(str, ports_set))}')

        # Packet Size Statistics Section
        pdf.chapter_title('Packet Size Statistics')
        if packet_sizes:
            avg_size = sum(packet_sizes)/len(packet_sizes)
            min_size = min(packet_sizes)
            max_size = max(packet_sizes)
            stats = (
                f'Average Size: {avg_size:.2f} bytes\n'
                f'Minimum Size: {min_size} bytes\n'
                f'Maximum Size: {max_size} bytes'
            )
            pdf.chapter_body(stats)
        else:
            pdf.chapter_body('No packet size data available.')

        # Save to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
            pdf.output(tmp_file.name)
            return send_file(
                tmp_file.name,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f'network_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            )

    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        return str(e), 500

def check_brute_force(packet):
    """Check for potential brute force attacks"""
    alerts = []
    current_time = time.time()
    
    if TCP in packet and IP in packet:
        dst_port = packet[TCP].dport
        
        # Check if the destination port is commonly targeted for brute force
        if dst_port in BRUTE_FORCE_PORTS:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            connection_key = (src_ip, dst_ip, dst_port)
            
            # Record the attempt
            login_attempts[connection_key].append(current_time)
            
            # Remove attempts outside the time window
            login_attempts[connection_key] = [
                t for t in login_attempts[connection_key]
                if current_time - t <= BRUTE_FORCE_TIME_WINDOW
            ]
            
            # Check if number of attempts exceeds threshold
            if len(login_attempts[connection_key]) >= BRUTE_FORCE_ATTEMPTS_THRESHOLD:
                alert_msg = (
                    f"Potential brute force attack detected from {src_ip} to {dst_ip}:{dst_port} "
                    f"({len(login_attempts[connection_key])} attempts in {BRUTE_FORCE_TIME_WINDOW}s)"
                )
                alerts.append(alert_msg)
                all_alerts.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {alert_msg}")
                # Reset attempts after alert
                login_attempts[connection_key] = []
    
    return alerts

def check_dos_attacks(pps, current_bandwidth, packet):
    """Check for potential DoS attacks"""
    global syn_count, last_syn_check, dos_alerts
    current_time = time.time()
    alerts = []

    # Check PPS threshold
    if pps > DOS_PPS_THRESHOLD:
        alert_msg = f"High packet rate detected: {pps} PPS"
        alerts.append(alert_msg)
        all_alerts.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {alert_msg}")

    # Check bandwidth threshold
    if current_bandwidth > DOS_BANDWIDTH_THRESHOLD:
        alert_msg = f"High bandwidth usage detected: {current_bandwidth/1024/1024:.2f} MB/s"
        alerts.append(alert_msg)
        all_alerts.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {alert_msg}")

    # Check SYN flood
    if TCP in packet:
        if "S" in packet[TCP].flags:  # SYN flag
            syn_count += 1
            
        # Reset SYN count every second
        if current_time - last_syn_check >= 1:
            if syn_count > DOS_SYN_THRESHOLD:
                alert_msg = f"Possible SYN flood detected: {syn_count} SYN packets/sec"
                alerts.append(alert_msg)
                all_alerts.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {alert_msg}")
            syn_count = 0
            last_syn_check = current_time

    # Check connection count
    if len(connections) > DOS_CONNECTION_THRESHOLD:
        alert_msg = f"High number of unique connections: {len(connections)}"
        alerts.append(alert_msg)
        all_alerts.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {alert_msg}")

    return alerts

def process_packet(packet):
    global capturing, total_packets, packet_count, bandwidth, connections, protocols, ports, packet_sizes
    
    if not capturing:
        return

    try:
        # Update statistics
        total_packets += 1
        packet_count += 1
        length = len(packet)
        bandwidth += length
        
        # Safely get highest layer (prevents silent crashes on malformed packets)
        last_layer = packet.lastlayer()
        highest_layer = getattr(last_layer, 'name', 'Unknown')
        protocols[highest_layer] += 1

        # Handle ports
        if TCP in packet:
            port = packet[TCP].dport
        elif UDP in packet:
            port = packet[UDP].dport
        else:
            port = 'N/A'
        ports[port] += 1

        # Handle IP connections
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            connections[f"{src}->{dst}"].add(port)

        # Packet sizes
        packet_sizes.append(length)

        # Calculate metrics for attack detection
        elapsed = time.time() - start_time
        pps = packet_count / elapsed if elapsed > 0 else 0
        current_bandwidth = bandwidth / elapsed if elapsed > 0 else 0

        # Check for attacks
        alerts = []
        alerts.extend(check_dos_attacks(pps, current_bandwidth, packet))
        alerts.extend(check_brute_force(packet))

        # Send alerts if detected
        if alerts:
            socketio.emit('dos_alert', {
                'alerts': alerts,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            })

        # Real-time updates
        socketio.emit('update_stats', {
            'total_packets': total_packets,
            'pps': f"{pps:.1f}",
            'bandwidth': f"{bandwidth / 1024:.1f} KB/s",
            'connections': len(connections),
            'protocols': dict(protocols),
            'ports': dict(ports),
            'packet_sizes': packet_sizes
        })
    except Exception as e:
        print(f"Error processing packet: {e}")

def capture_packets():
    global capturing
    try:
        # Start sniffing using Scapy (does not require Wireshark)
        sniff(prn=process_packet, store=False, stop_filter=lambda p: not capturing)
    except Exception as e:
        print(f"Packet capture error: {str(e)}")
        capturing = False
        socketio.emit('capture_error', {'message': str(e)})


@socketio.on('start_capture')
def handle_start_capture():
    global capturing, capture_thread, total_packets, packet_count, start_time
    global bandwidth, connections, protocols, ports, packet_sizes, dos_alerts, all_alerts
    
    if not capturing:
        capturing = True
        total_packets = 0
        packet_count = 0
        start_time = time.time()
        bandwidth = 0
        connections.clear()
        protocols.clear()
        ports.clear()
        packet_sizes = []
        dos_alerts = []
        all_alerts = []
        login_attempts.clear()
        
        # Start packet capture in a separate thread
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        
        socketio.emit('capture_started', {'status': 'success'})

@socketio.on('stop_capture')
def handle_stop_capture():
    global capturing
    capturing = False
    socketio.emit('final_report', {  # ✅ Correct
    'total_packets': total_packets,
    'protocols': dict(protocols),
    'ports': dict(ports),
    'connections': len(connections),
    'packet_sizes': packet_sizes
})
    socketio.emit('capture_stopped', {'status': 'success'})


# if _name_ == '_main_':
#     socketio.run(server_api), debug=True)