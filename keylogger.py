import psutil
import logging

def check_running_processes(duration=5):  # Track CPU usage for 5 seconds (adjustable)
  """Checks for suspicious processes (limited detection)."""
  for process in psutil.process_iter():
    cpu_usage = []
    for _ in range(duration):  # Capture CPU usage for duration seconds
      cpu_usage.append(psutil.cpu_percent(interval=1))

    # Check for high average CPU usage
    if sum(cpu_usage) / len(cpu_usage) > 80:
      logging.warning(f"Suspicious process: {process.name()} - Average CPU Usage: {sum(cpu_usage) / len(cpu_usage)}%")
      # Add more criteria here (use with caution due to false positives)
      # ...
    # Check for unusual names or other criteria

  return False

if __name__ == "__main__":
  logging.basicConfig(filename='process_log.txt', level=logging.WARNING)
  check_running_processes()
  print("Finished checking processes.")
