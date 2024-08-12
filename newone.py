import psutil
import logging
import time
import argparse
from tqdm import tqdm
import pyshark

def check_running_processes(duration=5, cpu_usage_threshold=80):
    """
    Checks for processes with high CPU usage.

    Args:
        duration (int, optional): The duration in seconds to monitor CPU usage. Defaults to 5.
        cpu_usage_threshold (int, optional): The CPU usage threshold above which a process is considered suspicious. Defaults to 80.

    Logs warnings for processes exceeding the threshold along with basic information.

    Returns:
        None
    """
    logging.basicConfig(filename='process_log.txt', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info('Process check started.')
    print("Process check started...")

    pids = psutil.pids()
    total_processes = len(pids)
    logging.info(f"Total processes to check: {total_processes}")
    print(f"Total processes to check: {total_processes}")

    processed_count = 0
    for pid in tqdm(pids, desc="Processing", unit="process"):
        try:
            proc = psutil.Process(pid)
            cpu_usage = [proc.cpu_percent(interval=1) for _ in range(duration)]
            average_cpu_usage = sum(cpu_usage) / len(cpu_usage)

            if average_cpu_usage > cpu_usage_threshold:
                warning_message = f"Suspicious process: {proc.name()} (PID: {pid}) - Average CPU Usage: {average_cpu_usage:.2f}%"
                logging.warning(warning_message)
                print(f"WARNING: {warning_message}")

        except psutil.NoSuchProcess:
            # Process has terminated or PID is invalid
            logging.error(f"Error accessing process {pid}: process no longer exists.")
            print(f"ERROR: Process {pid} no longer exists.")
            continue
        except psutil.AccessDenied as e:
            # Permission issue accessing process
            logging.error(f"Error accessing process {pid}: {e}")
            print(f"ERROR: Access denied for process {pid}.")
            continue
        except Exception as e:
            # Catch any other unexpected exceptions
            logging.error(f"Unexpected error accessing process {pid}: {e}")
            print(f"ERROR: Unexpected error for process {pid}: {e}")
            continue

        processed_count += 1
        # Print progress update
        print(f"Checked process {pid}: {processed_count}/{total_processes}")

    logging.info('Process check completed.')
    print("Process check completed.")

def monitor_network(interface, duration=10):
    """
    Monitors network traffic for a specified duration.

    Args:
        interface (str): Network interface to capture packets on.
        duration (int, optional): Duration in seconds to capture network packets. Defaults to 10.

    Logs details about captured packets including IP addresses.

    Returns:
        None
    """
    logging.info('Network monitoring started.')
    print(f"Network monitoring started on interface {interface}...")

    capture = pyshark.LiveCapture(interface=interface)
    start_time = time.time()

    packet_count = 0
    for packet in capture.sniff_continuously():
        if time.time() - start_time > duration:
            break

        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            log_message = f"Packet captured: Source IP: {src_ip}, Destination IP: {dst_ip}"
            logging.info(log_message)
            print(log_message)

        packet_count += 1
        # Print progress update
        print(f"Captured packet {packet_count}...")

    logging.info('Network monitoring completed.')
    print("Network monitoring completed.")

def main():
    parser = argparse.ArgumentParser(description="Monitor CPU usage and network traffic.")
    parser.add_argument('--duration', type=int, default=5, help='Duration in seconds to monitor CPU usage. Defaults to 5.')
    parser.add_argument('--threshold', type=int, default=80, help='CPU usage threshold for suspicious processes. Defaults to 80.')
    parser.add_argument('--network-interface', type=str, required=True, help='Network interface to capture packets from.')
    parser.add_argument('--network-duration', type=int, default=10, help='Duration in seconds to capture network packets. Defaults to 10.')

    args = parser.parse_args()

    print(f"Starting process check with duration={args.duration} and threshold={args.threshold}.")
    check_running_processes(duration=args.duration, cpu_usage_threshold=args.threshold)
    
    print(f"Starting network monitoring on interface={args.network_interface} for {args.network_duration} seconds.")
    monitor_network(interface=args.network_interface, duration=args.network_duration)

    print("Finished monitoring.")

if __name__ == "__main__":
    main()
