import logging

def log_message(message):
  logging.warning(message)

if __name__ == "__main__":
  # Example usage (remove in production)
  log_message("Test message from log_handler.py")
