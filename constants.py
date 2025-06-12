# constants.py

import os

# Define default paths
DEFAULT_PCAP_PATH = os.path.join(os.getcwd(), "data", "in")
DEFAULT_OUT_PATH = os.path.join(os.getcwd(), "data", "out")

# Define flow timeouts in microseconds (matching Java's internal representation)
ACTIVE_TIMEOUT_MICROS = 120_000_000
IDLE_TIMEOUT_MICROS = 5_000_000

# You can add other global constants here if needed.