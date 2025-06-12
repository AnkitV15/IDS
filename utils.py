# utils.py

import logging

logger = logging.getLogger(__name__) # Get logger for this module

# --- Simulate Java's MutableInt for flag counts ---
class MutableInt:
    def __init__(self, value=0):
        self.value = value

    def increment(self):
        self.value += 1

    def get(self):
        return self.value

# You can add other utility functions or classes here.