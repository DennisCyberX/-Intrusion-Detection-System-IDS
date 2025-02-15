import logging
import time
from scapy.all import sniff, IP, TCP

# Configure logging
logging.basicConfig(filename='logs/ids.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Define suspicious activity rules
def detect_suspicious_activity(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Example rule: Detect traffic on port 22 (SSH)
        if dst_port == 22:
            alert_message = f"Suspicious SSH traffic detected from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
            logging.warning(alert_message)
            print(f"🚨 ALERT: {alert_message}")

# Start sniffing network traffic
def start_ids(interface="eth0"):
    print(f"🚀 Starting IDS on interface {interface}...")
    sniff(iface=interface, prn=detect_suspicious_activity, store=False)

if __name__ == "__main__":
    start_ids()
