import psutil
import logging

def check_running_processes(duration=5, cpu_usage_threshold=80):
    """
    Checks for processes with high CPU usage (limited detection).

    Args:
        duration (int, optional): The duration in seconds to monitor CPU usage. Defaults to 5.
        cpu_usage_threshold (int, optional): The CPU usage threshold above which a process is considered suspicious. Defaults to 80.

    Logs warnings for processes exceeding the threshold along with basic information.

    Returns:
        None
    """

    logging.basicConfig(filename='process_log.txt', level=logging.WARNING)
    for process in psutil.process_iter():
        try:
            cpu_usage = []
            for _ in range(duration):
                cpu_usage.append(psutil.cpu_percent(interval=1))

            average_cpu_usage = sum(cpu_usage) / len(cpu_usage)
            if average_cpu_usage > cpu_usage_threshold:
                logging.warning(f"Suspicious process: {process.name()} (PID: {process.pid}) - Average CPU Usage: {average_cpu_usage:.2f}%")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logging.error(f"Error accessing process {process.pid}: {e}")

if __name__ == "__main__":
    check_running_processes()
    print("Finished checking processes.")
