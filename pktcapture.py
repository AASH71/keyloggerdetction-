from scapy.all import sniff, wrpcap
import logging

from log_handler import log_message

def capture_packets(interface="eth0", filename="captured_traffic.pcap", duration=10):
  """Captures network traffic on the specified interface for a duration."""
  try:
    sniff(iface=interface, count=0, timeout=duration, store=wrpcap(filename))
    log_message(f"Captured packets for {duration} seconds and saved to {filename}")
  except KeyboardInterrupt:
    log_message("Capturing interrupted by user.")

if __name__ == "__main__":
  logging.basicConfig(filename='packet_capture_log.txt', level=logging.WARNING)
  capture_packets()
