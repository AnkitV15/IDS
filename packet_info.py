# packet_info.py

import logging
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6 # Import IPv6 layer
from scapy.all import Raw # Import Raw layer for payload
import time # Import time for fallback timestamp

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Set logger level to INFO

# --- Basic Packet Information Extraction (Equivalent to BasicPacketInfo.java) ---
class BasicPacketInfo:
    # Static counter for packet IDs
    _packet_counter = 0

    def __init__(self, packet: Packet):
        # Assign a unique ID to each packet processed
        BasicPacketInfo._packet_counter += 1
        self.id = BasicPacketInfo._packet_counter

        self._packet = packet # Store the original Scapy packet

        # Initialize attributes
        self._src_ip = None
        self._dst_ip = None
        self._src_port = None
        self._dst_port = None
        self._protocol = None
        self._timestamp = None
        self._payload_bytes = 0
        self._header_bytes = 0
        self._tcp_flags = None
        self._tcp_window = None
        self._flow_id = None # Canonical flow ID (src_ip-dst_ip-src_port-dst_port-protocol)

        # Extract information from the packet layers
        self._extract_info()

        # Generate the canonical flow ID after extracting info
        # This is used for the flow dictionary key
        self.generateFlowId()


    def _extract_info(self):
        """Extracts relevant information from the Scapy packet layers."""
        try:
            # Extract timestamp (Scapy packet.time is float seconds since epoch)
            if hasattr(self._packet, 'time'):
                self._timestamp = int(self._packet.time * 1_000_000) # Convert to microseconds
            else:
                 # Handle packets without a timestamp attribute if necessary
                 # For live capture, this is unlikely, but good for robustness
                 logger.warning(f"Packet {self.id} has no timestamp attribute. Using current time.")
                 self._timestamp = int(time.time() * 1_000_000) # Use current time as fallback


            # Check for IP or IPv6 layer
            if IP in self._packet:
                ip_layer = self._packet[IP]
                self._src_ip = ip_layer.src
                self._dst_ip = ip_layer.dst
                self._protocol = ip_layer.proto
                self._header_bytes = len(ip_layer) # IP header length

                # Check for transport layer (TCP or UDP)
                if TCP in self._packet:
                    tcp_layer = self._packet[TCP]
                    self._src_port = tcp_layer.sport
                    self._dst_port = tcp_layer.dport
                    self._tcp_flags = tcp_layer.flags
                    self._tcp_window = tcp_layer.window
                    self._header_bytes += len(tcp_layer) # Add TCP header length

                elif UDP in self._packet:
                    udp_layer = self._packet[UDP]
                    self._src_port = udp_layer.sport
                    self._dst_port = udp_layer.dport
                    # UDP has no flags or window size, these remain None

                    self._header_bytes += len(udp_layer) # Add UDP header length

                # Check for payload (Raw layer usually contains the payload)
                if Raw in self._packet:
                    self._payload_bytes = len(self._packet[Raw].load)

            elif IPv6 in self._packet:
                 ipv6_layer = self._packet[IPv6]
                 self._src_ip = ipv6_layer.src
                 self._dst_ip = ipv6_layer.dst
                 # Note: Getting the next header protocol in IPv6 can be more complex
                 # if there are extension headers. For simplicity, we'll try to get
                 # the protocol from the final layer if it's TCP/UDP.
                 self._header_bytes = len(ipv6_layer) # IPv6 header length

                 # Check for transport layer (TCP or UDP) after IPv6
                 if TCP in self._packet:
                     tcp_layer = self._packet[TCP]
                     self._src_port = tcp_layer.sport
                     self._dst_port = tcp_layer.dport
                     self._protocol = 6 # TCP protocol number
                     self._tcp_flags = tcp_layer.flags
                     self._tcp_window = tcp_layer.window
                     self._header_bytes += len(tcp_layer) # Add TCP header length

                 elif UDP in self._packet:
                     udp_layer = self._packet[UDP]
                     self._src_port = udp_layer.sport
                     self._dst_port = udp_layer.dport
                     self._protocol = 17 # UDP protocol number
                     self._header_bytes += len(udp_layer) # Add UDP header length

                 # Check for payload (Raw layer usually contains the payload)
                 if Raw in self._packet:
                     self._payload_bytes = len(self._packet[Raw].load)

            else:
                # Packet is not IP or IPv6, raise ValueError to be caught by FlowGenerator
                # This will cause FlowGenerator.addPacket to skip this packet.
                raise ValueError(f"Packet {self.id} is not an IP or IPv6 packet.")


        except Exception as e:
            # Catch any other errors during extraction and re-raise
            # This will be caught by the FlowGenerator's addPacket method
            raise Exception(f"Error extracting packet info for packet {self.id}: {e}") from e


    def generateFlowId(self):
        """Generates the canonical flow ID (src_ip-dst_ip-src_port-dst_port-protocol)."""
        # Ensure IP and protocol are available before generating ID
        if self._src_ip is not None and self._dst_ip is not None and self._protocol is not None:
            # Use 0 for ports if they are None (e.g., non-TCP/UDP IP packets)
            src_port = self._src_port if self._src_port is not None else 0
            dst_port = self._dst_port if self._dst_port is not None else 0

            # Determine canonical direction based on the "lower" endpoint
            # This ensures flow ID is consistent regardless of packet direction
            if (self._src_ip, src_port) > (self._dst_ip, dst_port):
                self._flow_id = f"{self._dst_ip}-{self._src_ip}-{dst_port}-{src_port}-{self._protocol}"
            else:
                self._flow_id = f"{self._src_ip}-{self._dst_ip}-{src_port}-{dst_port}-{self._protocol}"
        else:
            # If essential info is missing, the flow ID cannot be generated.
            # This packet should likely be discarded by the FlowGenerator.
            self._flow_id = "UNKNOWN_FLOW"
            # logger.warning(f"Cannot generate flow ID for packet {self.id}: Missing IP or Protocol info.") # Reduced logging


    # --- Getter Methods (Equivalent to BasicPacketInfo.java getters) ---
    def getSourceIP(self) -> str:
        return self._src_ip

    def getDestinationIP(self) -> str:
        return self._dst_ip

    def getSrcPort(self) -> int:
        # Return 0 if port was None (e.g., non-TCP/UDP)
        return self._src_port if self._src_port is not None else 0

    def getDstPort(self) -> int:
        # Return 0 if port was None (e.g., non-TCP/UDP)
        return self._dst_port if self._dst_port is not None else 0

    def getProtocol(self) -> int:
        # Return 0 if protocol was None
        return self._protocol if self._protocol is not None else 0

    def getTimeStamp(self) -> int:
        # Return 0 if timestamp was None
        return self._timestamp if self._timestamp is not None else 0

    def getPayloadBytes(self) -> int:
        return self._payload_bytes

    def getHeaderBytes(self) -> int:
        return self._header_bytes

    def getTCPFlags(self):
        # Returns the flags object (Scapy's Flags field) or None
        return self._tcp_flags

    def getTCPWindow(self) -> int:
        # Return 0 if window was None (e.g., non-TCP packet)
        return self._tcp_window if self._tcp_window is not None else 0

    def getFlowId(self) -> str:
        """Returns the canonical flow ID."""
        return self._flow_id

    # --- Directional Flow ID Methods (NEW) ---
    def fwdFlowId(self) -> str:
        """Generates the flow ID based on the packet's actual source and destination."""
        if self._src_ip is not None and self._dst_ip is not None and self._protocol is not None:
            src_port = self._src_port if self._src_port is not None else 0
            dst_port = self._dst_port if self._dst_port is not None else 0
            return f"{self._src_ip}-{self._dst_ip}-{src_port}-{dst_port}-{self._protocol}"
        return "UNKNOWN_FWD_FLOW" # Return a default if essential info is missing

    def bwdFlowId(self) -> str:
        """Generates the reverse flow ID based on the packet's actual source and destination."""
        if self._src_ip is not None and self._dst_ip is not None and self._protocol is not None:
            src_port = self._src_port if self._src_port is not None else 0
            dst_port = self._dst_port if self._dst_port is not None else 0
            return f"{self._dst_ip}-{self._src_ip}-{dst_port}-{src_port}-{self._protocol}"
        return "UNKNOWN_BWD_FLOW" # Return a default if essential info is missing


    # --- Flag Check Methods (Equivalent to BasicPacketInfo.java flag checks) ---
    # These methods check the presence of specific TCP flags.
    # They should only be called if the protocol is TCP (self.getProtocol() == 6).
    def hasFlagFIN(self) -> bool:
        return self.getProtocol() == 6 and self._tcp_flags is not None and 'F' in self._tcp_flags
    def hasFlagSYN(self) -> bool:
        return self.getProtocol() == 6 and self._tcp_flags is not None and 'S' in self._tcp_flags
    def hasFlagRST(self) -> bool:
        return self.getProtocol() == 6 and self._tcp_flags is not None and 'R' in self._tcp_flags
    def hasFlagPSH(self) -> bool:
        return self.getProtocol() == 6 and self._tcp_flags is not None and 'P' in self._tcp_flags
    def hasFlagACK(self) -> bool:
        return self.getProtocol() == 6 and self._tcp_flags is not None and 'A' in self._tcp_flags
    def hasFlagURG(self) -> bool:
        return self.getProtocol() == 6 and self._tcp_flags is not None and 'U' in self._tcp_flags
    def hasFlagCWR(self) -> bool:
        return self.getProtocol() == 6 and self._tcp_flags is not None and 'C' in self._tcp_flags
    def hasFlagECE(self) -> bool:
        return self.getProtocol() == 6 and self._tcp_flags is not None and 'E' in self._tcp_flags

    # --- Direction Check Method ---
    def isForwardPacket(self, flow_src_ip: str) -> bool:
        """
        Determines if this packet is in the forward direction relative to the flow's source IP.
        Requires the flow's source IP to be established.
        """
        if flow_src_ip is None:
             logger.warning(f"Cannot determine packet direction for packet {self.id}: Flow source IP is None.")
             return False # Cannot determine direction without flow source IP

        return self.getSourceIP() == flow_src_ip

