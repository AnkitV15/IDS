# basic_flow.py

import statistics
from datetime import datetime
import logging
from typing import TYPE_CHECKING # Used for type hinting circular dependencies

# Avoid circular import for type hinting
if TYPE_CHECKING:
    from packet_info import BasicPacketInfo

from utils import MutableInt # Import MutableInt from utils
from flow_feature import FlowFeature # Import FlowFeature enum
from constants import IDLE_TIMEOUT_MICROS # Import default timeout

logger = logging.getLogger(__name__) # Get logger for this module

# --- Basic Flow Representation (Equivalent to BasicFlow.java) ---
class BasicFlow:
    def __init__(self, isBidirectional: bool, packet: 'BasicPacketInfo', flowSrc: str = None, flowDst: str = None, flowSrcPort: int = None, flowDstPort: int = None, activityTimeout: int = IDLE_TIMEOUT_MICROS):
        logger.debug(f"BasicFlow __init__ start for packet id {packet.id}, object id: {id(self)}")
        self.activityTimeout = activityTimeout

        # Initialize identity attributes first (before initParameters)
        self.src = None
        self.dst = None
        self.srcPort = 0
        self.dstPort = 0
        self.protocol = 0
        self.flowId = None

        self.isBidirectional = isBidirectional

        # Determine and set the flow's identity based on constructor arguments or the first packet
        # This block executes for *all* BasicFlow instantiations
        if flowSrc is not None: # Case 1: Flow identity explicitly provided (e.g., after timeout)
            logger.debug("BasicFlow __init__: Using provided identity.")
            self.src = flowSrc
            self.dst = flowDst
            self.srcPort = flowSrcPort
            self.dstPort = flowDstPort
            # Protocol and FlowId are still derived from the first packet below
        else: # Case 2: New flow detection - identity based *solely* on the first packet's direction
            logger.debug("BasicFlow __init__: Determining identity from first packet.")
            # Use the BasicPacketInfo's generateFlowId to get the canonical direction
            packet.generateFlowId() # Ensure the canonical flow ID is determined

            packet_src_ip = packet.getSourceIP()
            packet_dst_ip = packet.getDestinationIP()
            packet_src_port = packet.getSrcPort()
            packet_dst_port = packet.getDstPort()

            logger.debug(f"Packet {packet.id} details: src={packet_src_ip}:{packet_src_port}, dst={packet_dst_ip}:{packet_dst_port}")

            # Determine flow src/dst based on the canonical flow ID direction derived from the first packet
            src_tuple = (packet_src_ip, packet_src_port)
            dst_tuple = (packet_dst_ip, packet_dst_port)

            # Compare tuples to establish canonical flow direction (src is the "lower" endpoint)
            if src_tuple > dst_tuple:
                 logger.debug("Packet source is backward relative to canonical flow ID.")
                 self.src = packet_dst_ip
                 self.dst = packet_src_ip
                 self.srcPort = packet_dst_port
                 self.dstPort = packet_src_port
            else:
                 logger.debug("Packet source is forward relative to canonical flow ID.")
                 self.src = packet_src_ip
                 self.dst = packet_dst_ip
                 self.srcPort = packet_src_port
                 self.dstPort = packet_dst_port

        # Protocol is always taken from the first packet
        self.protocol = packet.getProtocol()
        # Flow ID is always the canonical ID derived from the first packet
        self.flowId = packet.getFlowId()

        logger.debug(f"BasicFlow __init__: Flow identity set. src={self.src}, dst={self.dst}, id={self.flowId}, object id: {id(self)}")

        # Now, call initParameters() to initialize all stats and counters
        # This method will now rely on self.src, self.dst etc. being already set.
        self.initParameters()
        logger.debug(f"BasicFlow __init__ after initParameters. self.src={self.src}, object id: {id(self)}")


        # Finally, process the first packet using the firstPacket method
        # firstPacket will add the packet's data to the lists and update initial stats/times.
        try:
            self.firstPacket(packet)
            logger.debug(f"BasicFlow __init__ finished for packet id {packet.id}, object id: {id(self)})")
        except Exception as e:
             logger.error(f"Error during BasicFlow.firstPacket for packet {packet.id}, object id {id(self)}: {e}", exc_info=True) # Log traceback
             raise # Re-raise the exception to be caught by the caller


    def initParameters(self):
        logger.debug(f"BasicFlow.initParameters called for object {id(self)}. Flow ID: {self.flowId}")
        # Initialize lists and SummaryStatistics equivalents
        self.forward = []
        self.backward = []
        self.flowIAT = []
        self.forwardIAT = []
        self.backwardIAT = []
        self.flowLengthStats = []
        self.flowActive = []
        self.flowIdle = []
        self.fwdPktStats = [] # Stores payload lengths
        self.bwdPktStats = [] # Stores payload lengths

        # Initialize flag counts
        self.flagCounts = {}
        self.initFlags() # Initialize the flagCounts dictionary with MutableInts
        logger.debug(f"BasicFlow.initParameters: initFlags called and finished.")

        # Defensive check: Ensure checkFlags method exists immediately after initFlags
        if not hasattr(self, 'checkFlags') or not callable(getattr(self, 'checkFlags', None)):
             logger.error(f"CRITICAL ERROR: Inside initParameters for object {id(self)}, 'checkFlags' method is missing AFTER initFlags!")
             # Raise a specific exception here if it occurs, which would be a severe issue
             raise AttributeError(f"'BasicFlow' object unexpectedly missing 'checkFlags' method in initParameters for object {id(self)}")

        # Initialize byte and header counts
        self.forwardBytes = 0
        self.backwardBytes = 0
        self.fHeaderBytes = 0
        self.bHeaderBytes = 0

        # Initialize directional flag counters (used for features)
        self.fPSH_cnt = 0
        self.bPSH_cnt = 0
        self.fURG_cnt = 0
        self.bURG_cnt = 0
        self.fFIN_cnt = 0
        self.bFIN_cnt = 0


        # Initialize other specific features/helpers
        self.min_seg_size_forward = float('inf')
        self.Act_data_pkt_forward = 0
        self.Init_Win_bytes_forward = 0
        self.Init_Win_bytes_backward = 0

        # Initialize time tracking variables
        # flowStartTime, flowLastSeen are set in firstPacket
        self.flowStartTime = 0
        self.flowLastSeen = 0
        self.forwardLastSeen = 0
        self.backwardLastSeen = 0

        # Active and Idle Time Tracking
        self.startActiveTime = 0 # These are set in firstPacket initially
        self.endActiveTime = 0
        self._current_activity_start_time = 0 # Helper, also set in firstPacket

        # Bulk related parameters - initialized to 0/None by default
        self.fbulkDuration=0
        self.fbulkPacketCount=0
        self.fbulkSizeTotal=0
        self.fbulkStateCount=0
        self.fbulkPacketCountHelper=0
        self.fbulkStartHelper=0
        self.fbulkSizeHelper=0
        self.flastBulkTS=0
        self.bbulkDuration=0
        self.bbulkPacketCount=0
        self.bbulkSizeTotal=0
        self.bbulkStateCount=0
        self.bbulkPacketCountHelper=0
        self.bbulkStartHelper=0
        self.bbulkSizeHelper=0
        self.blastBulkTS=0

        # Subflow related parameters - initialized to -1/0 by default
        self.sfLastPacketTS = -1
        self.sfCount = 0
        self.sfAcHelper = -1

        logger.debug(f"BasicFlow.initParameters finished for object {id(self)}. Flow ID: {self.flowId}")


    def initFlags(self):
        logger.debug(f"BasicFlow.initFlags called for object {id(self)}")
        # Initialize counts for all TCP flags in the flagCounts dictionary
        self.flagCounts["FIN"] = MutableInt()
        self.flagCounts["SYN"] = MutableInt()
        self.flagCounts["RST"] = MutableInt()
        self.flagCounts["PSH"] = MutableInt()
        self.flagCounts["ACK"] = MutableInt()
        self.flagCounts["URG"] = MutableInt()
        self.flagCounts["CWR"] = MutableInt()
        self.flagCounts["ECE"] = MutableInt()
        logger.debug(f"BasicFlow.initFlags finished for object {id(self)}")

    def checkFlags(self, packet: 'BasicPacketInfo'):
        logger.debug(f"BasicFlow.checkFlags called for object {id(self)}. Packet id: {packet.id}")
        # Increment global flag counts (used for features like FIN Flag Count)
        if packet.hasFlagFIN(): self.flagCounts["FIN"].increment()
        if packet.hasFlagSYN(): self.flagCounts["SYN"].increment()
        if packet.hasFlagRST(): self.flagCounts["RST"].increment()
        if packet.hasFlagPSH(): self.flagCounts["PSH"].increment()
        if packet.hasFlagACK(): self.flagCounts["ACK"].increment()
        if packet.hasFlagURG(): self.flagCounts["URG"].increment()
        if packet.hasFlagCWR(): self.flagCounts["CWR"].increment()
        if packet.hasFlagECE(): self.flagCounts["ECE"].increment()

        # Increment directional PSH/URG flags (used for features Fwd PSH Flags, Bwd PSH Flags, etc.)
        # Note: The Java code also increments these in firstPacket and addPacket directional blocks.
        # It seems checkFlags handles the global counts, while the directional blocks handle directional counts.
        # Let's keep both based on the Java code structure provided.
        # (The directional PSH/URG counts are incremented in firstPacket and addPacket already).
        pass # No need to re-increment directional PSH/URG here if already done in packet processing blocks.
        logger.debug(f"BasicFlow.checkFlags finished for object {id(self)}. Packet id: {packet.id}")


    def firstPacket(self, packet: 'BasicPacketInfo'):
        logger.debug(f"BasicFlow.firstPacket called for object {id(self)}. Packet timestamp: {packet.getTimeStamp()}")

        # Defensive check: Ensure checkFlags method exists before calling it
        if not hasattr(self, 'checkFlags') or not callable(getattr(self, 'checkFlags', None)):
             logger.error(f"CRITICAL ERROR: Inside firstPacket for object {id(self)}, 'checkFlags' method is missing BEFORE calling it!")
             # Raise a specific exception here if it occurs to stop processing and inspect
             raise AttributeError(f"'BasicFlow' object unexpectedly missing 'checkFlags' method in firstPacket for object {id(self)}. State: {getattr(self, '__dict__', 'N/A')}")

        logger.debug(f"BasicFlow.firstPacket about to call checkFlags for object {id(self)}")
        self.checkFlags(packet) # <--- Error occurring here according to logs

        self.updateFlowBulk(packet)
        self.detectUpdateSubflows(packet)


        # Initialize times based on the first packet's timestamp
        self.flowStartTime = packet.getTimeStamp()
        self.flowLastSeen = packet.getTimeStamp()
        self.startActiveTime = packet.getTimeStamp() # Start of first active period
        self.endActiveTime = packet.getTimeStamp() # End of first active period
        self._current_activity_start_time = packet.getTimeStamp() # Initialize helper

        # Add the first packet's payload length to the total flow length stats
        self.flowLengthStats.append(packet.getPayloadBytes())

        # Add the first packet's stats to forward/backward based on the flow direction already determined in __init__
        # Use the isForwardPacket method, which relies on self.src being set.
        if packet.isForwardPacket(self.src):
            logger.debug(f"Packet {packet.id} is FORWARD in flow {self.flowId}")
            # Ensure min_seg_size_forward is only updated if packet has header bytes > 0
            if packet.getHeaderBytes() > 0:
                 self.min_seg_size_forward = min(self.min_seg_size_forward, packet.getHeaderBytes())

            self.Init_Win_bytes_forward = packet.getTCPWindow() # Only set by first forward packet with window > 0
            self.fwdPktStats.append(packet.getPayloadBytes())
            self.fHeaderBytes += packet.getHeaderBytes()
            self.forward.append(packet) # Add packet to forward list
            self.forwardBytes += packet.getPayloadBytes()
            self.forwardLastSeen = packet.getTimeStamp()
            # Directional PSH/URG counts were incremented in checkFlags already based on Java structure

        else: # Backward packet
            logger.debug(f"Packet {packet.id} is BACKWARD in flow {self.flowId}")
            self.bwdPktStats.append(packet.getPayloadBytes())
            # Init_Win_bytes_backward is only set by the *first* backward packet with window > 0.
            # Check again here in case the first backward packet didn't have window > 0.
            if self.Init_Win_bytes_backward == 0 and packet.getTCPWindow() > 0:
                 self.Init_Win_bytes_backward = packet.getTCPWindow()

            self.bHeaderBytes += packet.getHeaderBytes()
            self.backward.append(packet) # Add packet to backward list
            self.backwardBytes += packet.getPayloadBytes()
            if len(self.backward) > 1: # IAT is between this packet and the previous backward packet
                self.backwardIAT.append(currentTimestamp - self.backwardLastSeen)
            self.backwardLastSeen = packet.getTimeStamp() # Update last timestamp in backward direction

        # Add to total flow length stats (payload length) for bidirectional flows
        # Note: For unidirectional, flowLengthStats only gets forward packet lengths,
        # which is handled in firstPacket and the unidirectional block of addPacket.
        if self.isBidirectional and not packet.isForwardPacket(self.src):
             # Only append backward packet payload length to total if bidirectional AND it was a backward packet
             self.flowLengthStats.append(packet.getPayloadBytes())


        logger.debug(f"BasicFlow.firstPacket finished for object {id(self)}")


    def addPacket(self, packet: 'BasicPacketInfo'):
        logger.debug(f"BasicFlow.addPacket called for flow {self.getFlowId()} (object id: {id(self)}). Packet timestamp: {packet.getTimeStamp()}, Packet id: {packet.id}")
        # Process subsequent packets in the flow

        # Defensive check: Ensure this flow object is valid before proceeding
        if not hasattr(self, 'checkFlags') or not callable(getattr(self, 'checkFlags', None)):
             logger.error(f"CRITICAL ERROR: Inside addPacket for object {id(self)}, 'checkFlags' method is missing! Skipping packet {packet.id}")
             # Log the object's state for debugging
             try:
                  logger.error(f"Malformed Flow Object State for ID {id(self)}: {getattr(self, '__dict__', 'N/A')}")
             except Exception:
                  pass
             return # Skip processing this packet for this apparently invalid flow object


        # Update state variables based on the new packet
        self.updateFlowBulk(packet)
        self.detectUpdateSubflows(packet)
        self.checkFlags(packet) # This updates global flag counts and directional PSH/URG counts

        currentTimestamp = packet.getTimeStamp()

        # Update active/idle times based on the arrival of this packet
        self.updateActiveIdleTime(currentTimestamp, self.activityTimeout)

        # Calculate Flow IAT
        if self.flowLastSeen != 0: # Should always be true after the first packet
             self.flowIAT.append(currentTimestamp - self.flowLastSeen)
        self.flowLastSeen = currentTimestamp # Update the timestamp of the last packet seen by the flow


        # Add packet stats to appropriate direction
        # Determine direction based on the flow's established src IP
        if packet.isForwardPacket(self.src):
            logger.debug(f"Packet {packet.id} is FORWARD in flow {self.flowId}")
            if packet.getPayloadBytes() >= 1:
                self.Act_data_pkt_forward += 1 # Count forward packets with payload >= 1
            self.fwdPktStats.append(packet.getPayloadBytes())
            self.fHeaderBytes += packet.getHeaderBytes()
            self.forward.append(packet) # Add packet to forward list
            self.forwardBytes += packet.getPayloadBytes()
            if len(self.forward) > 1: # IAT is between this packet and the previous forward packet
                self.forwardIAT.append(currentTimestamp - self.forwardLastSeen)
            self.forwardLastSeen = currentTimestamp # Update last timestamp in forward direction
            # Ensure min_seg_size_forward is updated only if packet has header bytes > 0
            if packet.getHeaderBytes() > 0:
                 self.min_seg_size_forward = min(self.min_seg_size_forward, packet.getHeaderBytes())

        else: # Backward packet
            logger.debug(f"Packet {packet.id} is BACKWARD in flow {self.flowId}")
            self.bwdPktStats.append(packet.getPayloadBytes())
            # Init_Win_bytes_backward is only set by the *first* backward packet with window > 0.
            # Check again here in case the first backward packet didn't have window > 0.
            if self.Init_Win_bytes_backward == 0 and packet.getTCPWindow() > 0:
                 self.Init_Win_bytes_backward = packet.getTCPWindow()

            self.bHeaderBytes += packet.getHeaderBytes()
            self.backward.append(packet) # Add packet to backward list
            self.backwardBytes += packet.getPayloadBytes()
            if len(self.backward) > 1: # IAT is between this packet and the previous backward packet
                self.backwardIAT.append(currentTimestamp - self.backwardLastSeen)
            self.backwardLastSeen = currentTimestamp # Update last timestamp in backward direction

        # Add to total flow length stats (payload length) for bidirectional flows
        # Note: For unidirectional, flowLengthStats only gets forward packet lengths,
        # which is handled in firstPacket and the unidirectional block of addPacket.
        if self.isBidirectional:
             self.flowLengthStats.append(packet.getPayloadBytes())

        logger.debug(f"BasicFlow.addPacket finished for object {id(self)}. Flow ID: {self.flowId}")


    # --- Bulk and Subflow Calculations (Translating Java Logic) ---
    # These methods are called from addPacket and firstPacket.
    # The getter methods below read the state variables updated by these methods.
    def updateFlowBulk(self, packet: 'BasicPacketInfo'):
        # Direct translation of the Java logic for updating bulk state
        # Determine direction based on the flow's established src IP
        if packet.isForwardPacket(self.src):
            self.updateForwardBulk(packet, self.blastBulkTS)
        else:
            self.updateBackwardBulk(packet, self.flastBulkTS)

    def updateForwardBulk(self, packet: 'BasicPacketInfo', tsOflastBulkInOther: int):
        # Direct translation of the Java logic for updating forward bulk state
        size = packet.getPayloadBytes()
        # If last bulk in OTHER direction is after the start of current potential bulk, reset helper
        if tsOflastBulkInOther > self.fbulkStartHelper: self.fbulkStartHelper = 0
        if size <= 0: return # Only consider packets with payload

        if self.fbulkStartHelper == 0:
            # Start of a potential new bulk
            self.fbulkStartHelper = packet.getTimeStamp()
            self.fbulkPacketCountHelper = 1
            self.fbulkSizeHelper = size
            self.flastBulkTS = packet.getTimeStamp()
        else:
            # Check if the time gap is too large to be part of the same bulk (1 second threshold)
            if ((packet.getTimeStamp() - self.flastBulkTS) / 1_000_000.0) > 1.0:
                # Gap too large, start a new potential bulk
                self.fbulkStartHelper = packet.getTimeStamp()
                self.flastBulkTS = packet.getTimeStamp()
                self.fbulkPacketCountHelper = 1
                self.fbulkSizeHelper = size
            else:
                # Add packet to the current potential bulk
                self.fbulkPacketCountHelper += 1
                self.fbulkSizeHelper += size
                # If helper count reaches 4, a new bulk is confirmed. Add helper stats to total bulk stats.
                if self.fbulkPacketCountHelper == 4:
                    self.fbulkStateCount += 1 # Increment bulk count
                    self.fbulkPacketCount += self.fbulkPacketCountHelper # Add packets from helper
                    self.fbulkSizeTotal += self.fbulkSizeHelper # Add size from helper
                    self.fbulkDuration += packet.getTimeStamp() - self.fbulkStartHelper # Add duration of this bulk
                # If helper count exceeds 4, it's a continuation of an existing bulk. Add this packet's stats directly.
                elif self.fbulkPacketCountHelper > 4:
                    self.fbulkPacketCount += 1 # Just count this packet
                    self.fbulkSizeTotal += size # Add this packet's size
                    self.fbulkDuration += packet.getTimeStamp() - self.flastBulkTS # Add IAT since last packet in bulk
                self.flastBulkTS = packet.getTimeStamp() # Update last timestamp in bulk


    def updateBackwardBulk(self, packet: 'BasicPacketInfo', tsOflastBulkInOther: int):
        # Direct translation of the Java logic for updating backward bulk state
        size = packet.getPayloadBytes()
        # If last bulk in OTHER direction is after the start of current potential bulk, reset helper
        if tsOflastBulkInOther > self.bbulkStartHelper: self.bbulkStartHelper = 0
        if size <= 0: return # Only consider packets with payload

        if self.bbulkStartHelper == 0:
            # Start of a potential new bulk
            self.bbulkStartHelper = packet.getTimeStamp()
            self.bbulkPacketCountHelper = 1
            self.bbulkSizeHelper = size
            self.blastBulkTS = packet.getTimeStamp()
        else:
            # Check if the time gap is too large to be part of the same bulk (1 second threshold)
            if ((packet.getTimeStamp() - self.blastBulkTS) / 1_000_000.0) > 1.0:
                # Gap too large, start a new potential bulk
                self.bbulkStartHelper = packet.getTimeStamp()
                self.blastBulkTS = packet.getTimeStamp()
                self.bbulkPacketCountHelper = 1
                self.bbulkSizeHelper = size
            else:
                # Add packet to the current potential bulk
                self.bbulkPacketCountHelper += 1
                self.bbulkSizeHelper += size
                # If helper count reaches 4, a new bulk is confirmed. Add helper stats to total bulk stats.
                if self.bbulkPacketCountHelper == 4:
                    self.bbulkStateCount += 1 # Increment bulk count
                    self.bbulkPacketCount += self.bbulkPacketCountHelper # Add packets from helper
                    self.bbulkSizeTotal += self.bbulkSizeHelper # Add size from helper
                    self.bbulkDuration += packet.getTimeStamp() - self.bbulkStartHelper # Add duration of this bulk
                # If helper count exceeds 4, it's a continuation of an existing bulk. Add this packet's stats directly.
                elif self.bbulkPacketCountHelper > 4:
                    self.bbulkPacketCount += 1 # Just count this packet
                    self.bbulkSizeTotal += size # Add this packet's size
                    self.bbulkDuration += packet.getTimeStamp() - self.blastBulkTS # Add IAT since last packet in bulk
                self.blastBulkTS = packet.getTimeStamp() # Update last timestamp in bulk


    def detectUpdateSubflows(self, packet: 'BasicPacketInfo'):
        # Direct translation of the Java logic for detecting and updating subflows
        if self.sfLastPacketTS == -1:
            self.sfLastPacketTS = packet.getTimeStamp()
            self.sfAcHelper = packet.getTimeStamp()

        # Subflow is detected if the time gap between the current and last packet is > 1 second
        if ((packet.getTimeStamp() - self.sfLastPacketTS) / 1_000_000.0) > 1.0:
            self.sfCount += 1 # Increment subflow count
            # This call marks the end of the *previous* active period and the start of a new one, based on the subflow boundary (1-second idle time).
            self.updateActiveIdleTime(packet.getTimeStamp(), self.activityTimeout)
            self.sfAcHelper = packet.getTimeStamp() # Reset the subflow active helper timestamp

        self.sfLastPacketTS = packet.getTimeStamp() # Update the timestamp of the last packet seen by subflow detection


    # --- Active and Idle Time Calculations (Translating Java Logic) ---
    def updateActiveIdleTime(self, currentTime: int, threshold: int):
        logger.debug(f"BasicFlow.updateActiveIdleTime called for flow {self.flowId} (object id: {id(self)}). CurrentTime: {currentTime}, Threshold: {threshold}, EndActiveTime: {self.endActiveTime}")
        # Direct translation of the Java logic for updating active/idle time state
        # If the time since the last packet in the flow (endActiveTime) exceeds the activity threshold (IDLE_TIMEOUT_MICROS)
        if (self.endActiveTime > 0) and ((currentTime - self.endActiveTime) > threshold): # Add check for endActiveTime > 0
            logger.debug(f"BasicFlow.updateActiveIdleTime: Idle period detected. Duration: {currentTime - self.endActiveTime}")
            # The previous period was an active period ending at endActiveTime. Record its duration if positive.
            if (self.endActiveTime - self.startActiveTime) > 0:
                self.flowActive.append(self.endActiveTime - self.startActiveTime)

            # The period between endActiveTime and currentTime is an idle period. Record its duration.
            self.flowIdle.append(currentTime - self.endActiveTime)

            # Start a new active period at the current packet's time
            self.startActiveTime = currentTime
            self.endActiveTime = currentTime
            logger.debug(f"BasicFlow.updateActiveIdleTime: New active period started at {self.startActiveTime}")
        else:
            # The current packet arrived within the activity threshold, extend the current active period
            self.endActiveTime = currentTime # Update the end time of the current active period
            # Initialize startActiveTime if it's the first packet (endActiveTime was 0)
            if self.startActiveTime == 0:
                 self.startActiveTime = currentTime
            logger.debug(f"BasicFlow.updateActiveIdleTime: Active period extended to {self.endActiveTime}")


    def endActiveIdleTime(self, currentTime: int, threshold: int, flowTimeOut: int, isFlagEnd: bool):
        logger.debug(f"BasicFlow.endActiveIdleTime called for flow {self.flowId} (object id: {id(self)}). CurrentTime: {currentTime}, IsFlagEnd: {isFlagEnd}")
        # Direct translation of the Java logic for finalizing active/idle times
        # This is called when a flow terminates.

        # Finalize the last active period (if any)
        if (self.endActiveTime - self.startActiveTime) > 0:
            self.flowActive.append(self.endActiveTime - self.startActiveTime)
            logger.debug(f"BasicFlow.endActiveIdleTime: Final active period duration: {self.endActiveTime - self.startActiveTime}")


        # This part of the idle time calculation seems to add remaining flow timeout as idle time if not ended by a flag.
        # Replicating it directly as per the Java code's dump method context.
        # The logic is: if the flow was NOT ended by a FIN/RST flag, AND the duration from the flow start
        # to the end of the *last active period* is less than the overall flow timeout, then
        # the difference between the flow timeout and the duration of the last active period
        # is added as an idle time. This seems intended to account for the final idle period
        # until the flow timeout would have occurred.
        if not isFlagEnd: # If flow was NOT terminated by a flag (i.e., by timeout or end of file)
             duration_until_last_active_end = self.endActiveTime - self.flowStartTime
             # Check if the potential remaining time after the last active period is positive
             potential_remaining_idle = flowTimeOut - duration_until_last_active_end
             logger.debug(f"BasicFlow.endActiveIdleTime: Flow not flag ended. Potential remaining idle: {potential_remaining_idle}")
             # Only add positive idle times and if the last active period didn't cover the entire flow duration
             if potential_remaining_idle > 0 and duration_until_last_active_end < (self.flowLastSeen - self.flowStartTime): # Add extra check
                  self.flowIdle.append(potential_remaining_idle)
                  logger.debug(f"BasicFlow.endActiveIdleTime: Added remaining idle time: {potential_remaining_idle}")

        logger.debug(f"BasicFlow.endActiveIdleTime finished for flow {self.flowId}")


    # --- Feature Calculation Methods (Translating Java Getters and dump method logic) ---

    def packetCount(self) -> int:
        # Total packet count (forward + backward)
        return len(self.forward) + len(self.backward)

    def getFlowStartTime(self) -> int:
        # Flow start timestamp in microseconds
        return self.flowStartTime

    def getSrc(self) -> str:
        # Flow's designated source IP address string
        return self.src

    def getDst(self) -> str:
        # Flow's designated destination IP address string
        return self.dst

    def getSrcPort(self) -> int:
        # Flow's designated source port
        # Return 0 if port was None (e.g., non-TCP/UDP)
        return self.srcPort if self.srcPort is not None else 0

    def getDstPort(self) -> int:
        # Flow's designated destination port
         # Return 0 if port was None (e.g., non-TCP/UDP)
        return self.dstPort if self.dstPort is not None else 0

    def getProtocol(self) -> int:
        # Flow's protocol number
        return self.protocol

    def getProtocolStr(self) -> str:
        # Used for debugging/logging, not in the CSV dump
        if self.protocol == 6: return "TCP"
        if self.protocol == 17: return "UDP"
        return "UNKNOWN"

    def getFlowId(self) -> str:
        # Canonical flow ID string
        return self.flowId

    def getFlowDuration(self) -> int:
        # Flow duration in microseconds
        return self.flowLastSeen - self.flowStartTime

    def getTotalFwdPackets(self) -> int:
        # Total number of forward packets
        return len(self.forward)

    def getTotalBackwardPackets(self) -> int:
        # Total number of backward packets
        return len(self.backward)

    def getTotalLengthofFwdPackets(self) -> int:
        # Total payload bytes in forward packets
        return self.forwardBytes

    def getTotalLengthofBwdPackets(self) -> int:
        # Total payload bytes in backward packets
        return self.backwardBytes

    def getFwdPacketLengthMax(self) -> float:
        return max(self.fwdPktStats) if self.fwdPktStats else 0.0

    def getFwdPacketLengthMin(self) -> float:
        return min(self.fwdPktStats) if self.fwdPktStats else 0.0

    def getFwdPacketLengthMean(self) -> float:
        return statistics.mean(self.fwdPktStats) if self.fwdPktStats else 0.0

    def getFwdPacketLengthStd(self) -> float:
        return statistics.stdev(self.fwdPktStats) if len(self.fwdPktStats) > 1 else 0.0

    def getBwdPacketLengthMax(self) -> float:
        return max(self.bwdPktStats) if self.bwdPktStats else 0.0

    def getBwdPacketLengthMin(self) -> float:
        return min(self.bwdPktStats) if self.bwdPktStats else 0.0

    def getBwdPacketLengthMean(self) -> float:
        return statistics.mean(self.bwdPktStats) if self.bwdPktStats else 0.0

    def getBwdPacketLengthStd(self) -> float:
        return statistics.stdev(self.bwdPktStats) if len(self.bwdPktStats) > 1 else 0.0

    def getFlowBytesPerSec(self) -> float:
        flowDuration = self.getFlowDuration()
        if flowDuration > 0:
            # Java divides by duration in seconds (micros / 1_000_000)
            return (self.forwardBytes + self.backwardBytes) / (flowDuration / 1_000_000.0)
        return 0.0

    def getFlowPacketsPerSec(self) -> float:
        flowDuration = self.getFlowDuration()
        if flowDuration > 0:
            # Java divides by duration in seconds (micros / 1_000_000)
            return self.packetCount() / (flowDuration / 1_000_000.0)
        return 0.0

    def getFlowIATMean(self) -> float:
        return statistics.mean(self.flowIAT) if self.flowIAT else 0.0

    def getFlowIATStd(self) -> float:
        return statistics.stdev(self.flowIAT) if len(self.flowIAT) > 1 else 0.0

    def getFlowIATMax(self) -> float:
        return max(self.flowIAT) if self.flowIAT else 0.0

    def getFlowIATMin(self) -> float:
        return min(self.flowIAT) if self.flowIAT else 0.0

    def getFwdIATTotal(self) -> int:
        # Sum of forward inter-arrival times
        return sum(self.forwardIAT) if self.forwardIAT else 0

    def getFwdIATMean(self) -> float:
        return statistics.mean(self.forwardIAT) if self.forwardIAT else 0.0

    def getFwdIATStd(self) -> float:
        return statistics.stdev(self.forwardIAT) if len(self.forwardIAT) > 1 else 0.0

    def getFwdIATMax(self) -> float:
        return max(self.forwardIAT) if self.forwardIAT else 0.0

    def getFwdIATMin(self) -> float:
        return min(self.forwardIAT) if self.forwardIAT else 0.0

    def getBwdIATTotal(self) -> int:
        # Sum of backward inter-arrival times
        return sum(self.backwardIAT) if self.backwardIAT else 0

    def getBwdIATMean(self) -> float:
        return statistics.mean(self.backwardIAT) if self.backwardIAT else 0.0

    def getBwdIATStd(self) -> float:
        return statistics.stdev(self.backwardIAT) if len(self.backwardIAT) > 1 else 0.0

    def getBwdIATMax(self) -> float:
        return max(self.backwardIAT) if self.backwardIAT else 0.0

    def getBwdIATMin(self) -> float:
        return min(self.backwardIAT) if self.backwardIAT else 0.0

    def getFwdPSHFlags(self) -> int:
        return self.fPSH_cnt

    def getBwdPSHFlags(self) -> int:
        return self.bPSH_cnt

    def getFwdURGFlags(self) -> int:
        return self.fURG_cnt

    def getBwdURGFlags(self) -> int:
        return self.bURG_cnt

    # FIN flag counts used in termination logic, distinct from the global FIN count feature
    def getFwdFINFlags(self) -> int:
        return self.fFIN_cnt

    def getBwdFINFlags(self) -> int:
        return self.bFIN_cnt

    # Methods to increment directional FIN flags (used in FlowGenerator)
    def setFwdFINFlags(self) -> int:
        self.fFIN_cnt += 1
        return self.fFIN_cnt

    def setBwdFINFlags(self) -> int:
        self.bFIN_cnt += 1
        return self.bFIN_cnt

    def getFwdHeaderLength(self) -> int:
        # Total forward header bytes
        return self.fHeaderBytes

    def getBwdHeaderLength(self) -> int:
        # Total backward header bytes
        return self.bHeaderBytes

    def getfPktsPerSecond(self) -> float:
        flowDuration = self.getFlowDuration()
        if flowDuration > 0:
            # Java divides by duration in seconds (micros / 1_000_000)
            return len(self.forward) / (flowDuration / 1_000_000.0)
        return 0.0

    def getbPktsPerSecond(self) -> float:
        flowDuration = self.getFlowDuration()
        if flowDuration > 0:
            # Java divides by duration in seconds (micros / 1_000_000)
            return len(self.backward) / (flowDuration / 1_000_000.0)
        return 0.0

    def getPacketLengthMin(self) -> float:
        # Min payload length across all packets
        all_lengths = self.fwdPktStats + self.bwdPktStats
        return min(all_lengths) if all_lengths else 0.0

    def getPacketLengthMax(self) -> float:
        # Max payload length across all packets
        all_lengths = self.fwdPktStats + self.bwdPktStats
        return max(all_lengths) if all_lengths else 0.0

    def getPacketLengthMean(self) -> float:
        # Mean payload length across all packets
        all_lengths = self.fwdPktStats + self.bwdPktStats
        return statistics.mean(all_lengths) if all_lengths else 0.0

    def getPacketLengthStd(self) -> float:
        # Std Dev of payload length across all packets
        all_lengths = self.fwdPktStats + self.bwdPktStats
        return statistics.stdev(all_lengths) if len(all_lengths) > 1 else 0.0

    def getPacketLengthVariance(self) -> float:
        # Variance of payload length across all packets
        all_lengths = self.fwdPktStats + self.bwdPktStats
        return statistics.variance(all_lengths) if len(all_lengths) > 1 else 0.0

    def getFlagCount(self, key: str) -> int:
        # Get global flag count by key (total occurrences across all packets)
        # Defensive check for flagCounts being initialized
        if not hasattr(self, 'flagCounts') or not isinstance(self.flagCounts, dict):
             logger.error(f"FlagCounts not initialized for flow {self.getFlowId()} (object id: {id(self)})")
             return 0
        return self.flagCounts.get(key, MutableInt()).get()

    # Global Flag Count Getters
    def getFINFlagCount(self) -> int: return self.getFlagCount("FIN")
    def getSYNFlagCount(self) -> int: return self.getFlagCount("SYN")
    def getRSTFlagCount(self) -> int: return self.getFlagCount("RST")
    def getPSHFlagCount(self) -> int: return self.getFlagCount("PSH")
    def getACKFlagCount(self) -> int: return self.getFlagCount("ACK")
    def getURGFlagCount(self) -> int: return self.getFlagCount("URG")
    def getCWRFlagCount(self) -> int: return self.getFlagCount("CWR")
    def getECEFlagCount(self) -> int: return self.getFlagCount("ECE")


    def getDownUpRatio(self) -> float:
        # Ratio of backward packets to forward packets
        if len(self.forward) > 0:
            return len(self.backward) / len(self.forward)
        return 0.0

    def getAveragePacketSize(self) -> float:
        # Average payload size across all packets (sum of payload lengths / total packet count)
        # This is distinct from PacketLengthMean, which is mean of the list of lengths.
        # Following the Java calculation flowLengthStats.getSum() / packetCount()
        total_bytes = sum(self.flowLengthStats) # Sum of payload lengths
        total_packets = self.packetCount()
        return total_bytes / total_packets if total_packets > 0 else 0.0


    def fAvgSegmentSize(self) -> float:
        # Average forward payload size (sum of forward payload lengths / forward packet count)
        if len(self.forward) > 0:
            return sum(self.fwdPktStats) / len(self.forward)
        return 0.0

    def bAvgSegmentSize(self) -> float:
        # Average backward payload size (sum of backward payload lengths / backward packet count)
        if len(self.backward) > 0:
            return sum(self.bwdPktStats) / len(self.backward)
        return 0.0

    # Bulk Feature Getters (read the state variables updated by updateFlowBulk methods)
    def fbulkStateCount_getter(self) -> int: return self.fbulkStateCount # Number of forward bulks detected
    def fbulkSizeTotal_getter(self) -> int: return self.fbulkSizeTotal # Total bytes in forward bulks
    def fbulkPacketCount_getter(self) -> int: return self.fbulkPacketCount # Total packets in forward bulks
    def fbulkDuration_getter(self) -> int: return self.fbulkDuration # Total duration of forward bulks in micros
    def fbulkDurationInSecond(self) -> float:
        return self.fbulkDuration / 1_000_000.0 if self.fbulkDuration > 0 else 0.0 # Avoid division by zero

    def fAvgBytesPerBulk(self) -> float:
        if self.fbulkStateCount_getter() != 0:
            return self.fbulkSizeTotal_getter() / self.fbulkStateCount_getter()
        return 0.0

    def fAvgPacketsPerBulk(self) -> float:
        if self.fbulkStateCount_getter() != 0:
            return self.fbulkPacketCount_getter() / self.fbulkStateCount_getter()
        return 0.0

    # Inside the BasicFlow class

    def fAvgBulkRate(self):
        # Assuming fbulkDurationInSecond() correctly calculates duration in seconds
        duration_seconds = self.fbulkDuration / 1_000_000.0 # Ensure conversion
        if duration_seconds == 0:
            return 0.0 # Return 0 if duration is zero to prevent division by zero
        return self.fbulkSizeTotal / duration_seconds # Use the attribute directly

    # Add a helper method if you don't have fbulkDurationInSecond():
    # def fbulkDurationInSecond(self):
    #     return self.fbulkDuration / 1_000_000.0

    def bbulkPacketCount_getter(self) -> int: return self.bbulkPacketCount
    def bbulkStateCount_getter(self) -> int: return self.bbulkStateCount
    def bbulkSizeTotal_getter(self) -> int: return self.bbulkSizeTotal
    def bbulkDuration_getter(self) -> int: return self.bbulkDuration
    def bbulkDurationInSecond(self) -> float:
        return self.bbulkDuration / 1_000_000.0 if self.bbulkDuration > 0 else 0.0 # Avoid division by zero


    def bAvgBytesPerBulk(self) -> float:
        if self.bbulkStateCount_getter() != 0:
            return self.bbulkSizeTotal_getter() / self.bbulkStateCount_getter()
        return 0.0

    def bAvgPacketsPerBulk(self) -> float:
        if self.bbulkStateCount_getter() != 0:
            return self.bbulkPacketCount_getter() / self.bbulkStateCount_getter()
        return 0.0

    # Inside the BasicFlow class

    def bAvgBulkRate(self):
        # Assuming bbulkDurationInSecond() correctly calculates duration in seconds
        duration_seconds = self.bbulkDuration / 1_000_000.0 # Ensure conversion
        if duration_seconds == 0:
            return 0.0 # Return 0 if duration is zero to prevent division by zero
        return self.bbulkSizeTotal / duration_seconds # Use the attribute directly

    # Add a helper method if you don't have bbulkDurationInSecond():
    # def bbulkDurationInSecond(self):
    #     return self.bbulkDuration / 1_000_000.0


    # Subflow Feature Getters (read the state variables updated by detectUpdateSubflows)
    def getSflow_fpackets(self) -> float:
        # Average forward packets per subflow state count (Java calculates as total fwd packets / sfCount)
        if self.sfCount <= 0: return 0.0
        return len(self.forward) / self.sfCount

    def getSflow_fbytes(self) -> float:
         # Average forward bytes per subflow state count (Java calculates as total fwd bytes / sfCount)
        if self.sfCount <= 0: return 0.0
        return self.forwardBytes / self.sfCount

    def getSflow_bpackets(self) -> float:
        # Average backward packets per subflow state count (Java calculates as total bwd packets / sfCount)
        if self.sfCount <= 0: return 0.0
        return len(self.backward) / self.sfCount

    def getSflow_bbytes(self) -> float:
        # Average backward bytes per subflow state count (Java calculates as total bwd bytes / sfCount)
        if self.sfCount <= 0: return 0.0
        return self.backwardBytes / self.sfCount


    # Initial Window Bytes Getters
    def getInit_Win_bytes_forward(self) -> int:
        return self.Init_Win_bytes_forward

    def getInit_Win_bytes_backward(self) -> int:
        return self.Init_Win_bytes_backward

    # Active Data Packets Forward Getters
    def getAct_data_pkt_forward(self) -> int:
        return self.Act_data_pkt_forward

    # Minimum Segment Size Forward Getters
    def getMin_seg_size_forward(self) -> float:
         # The Java code initializes with float('inf') and takes the min header size.
         # If no forward packets, this would remain the initial infinity value.
         # The dump method output suggests it should be 0 if no forward packets or min is still infinity.
         # Return 0.0 if self.min_seg_size_forward is still the initial infinity value.
        return self.min_seg_size_forward if self.min_seg_size_forward != float('inf') else 0.0


    # Active Time Getters (read the state variables updated by updateActiveIdleTime)
    def getActiveMean(self) -> float:
        return statistics.mean(self.flowActive) if self.flowActive else 0.0
    def getActiveStd(self) -> float:
        return statistics.stdev(self.flowActive) if len(self.flowActive) > 1 else 0.0
    def getActiveMax(self) -> float:
        return max(self.flowActive) if self.flowActive else 0.0
    def getActiveMin(self) -> float:
        return min(self.flowActive) if self.flowActive else 0.0

    # Idle Time Getters (read the state variables updated by updateActiveIdleTime)
    def getIdleMean(self) -> float:
        return statistics.mean(self.flowIdle) if self.flowIdle else 0.0
    def getIdleStd(self) -> float:
        return statistics.stdev(self.flowIdle) if len(self.flowIdle) > 1 else 0.0
    def getIdleMax(self) -> float:
        return max(self.flowIdle) if self.flowIdle else 0.0
    def getIdleMin(self) -> float:
        return min(self.flowIdle) if self.flowIdle else 0.0

    # Label (Placeholder)
    def getLabel(self) -> str:
        # This would typically be determined from the pcap file's context or a separate label file
        # Replicating the commented-out Java logic for demonstration if needed,
        # otherwise returning the default "NeedManualLabel".
        # Example of conditional labeling (replace with your actual labeling logic)
        # if "147.32.84.165" in (self.getSrc(), self.getDst()):
        #      return "BOTNET"
        # else:
        #      return "BENIGN"
        return "NeedManualLabel"


    def dumpFlowBasedFeaturesEx(self) -> str:
        """
        Generates a comma-separated string of all 85 flow features
        in the exact order specified by the Java dumpFlowBasedFeaturesEx method.
        """
        dump = []
        separator = ","

        # Append features in the order of the Java dump method
        # Using str() to ensure all values are converted to strings
        try:
             dump.append(str(self.getFlowId())) # 1
             dump.append(str(self.getSrc())) # 2
             dump.append(str(self.getSrcPort())) # 3
             dump.append(str(self.getDst())) # 4
             dump.append(str(self.getDstPort())) # 5
             dump.append(str(self.getProtocol())) # 6

             # Format timestamp like Java: "dd/MM/yyyy hh:mm:ss a" (AM/PM)
             # Java's timestampInMicros / 1000L gives milliseconds, then formatted
             timestamp_micros = self.getFlowStartTime()
             # Use a default timestamp string if flowStartTime is zero or causes an error
             if timestamp_micros <= 0:
                  formatted_timestamp = "00/00/0000 12:00:00 AM" # Default or error indicator
                  logger.warning(f"Flow {self.getFlowId()} has invalid start timestamp: {timestamp_micros}. Using default string.")
             else:
                  try:
                       timestamp_ms = timestamp_micros // 1000
                       # Convert milliseconds to seconds for Python's fromtimestamp
                       timestamp_sec = timestamp_ms / 1000.0
                       # Format using datetime (%I for 12-hour, %p for AM/PM)
                       formatted_timestamp = datetime.fromtimestamp(timestamp_sec).strftime("%d/%m/%Y %I:%M:%S %p")
                  except (ValueError, OSError) as e:
                       logger.warning(f"Could not format timestamp {timestamp_micros} for flow {self.getFlowId()}: {e}. Using default string.")
                       formatted_timestamp = "00/00/0000 12:00:00 AM" # Default or error indicator


             dump.append(formatted_timestamp) # 7


             dump.append(str(self.getFlowDuration())) # 8

             dump.append(str(self.getTotalFwdPackets())) # 9
             dump.append(str(self.getTotalBackwardPackets())) # 10
             dump.append(str(self.getTotalLengthofFwdPackets())) # 11
             dump.append(str(self.getTotalLengthofBwdPackets())) # 12

             # Fwd Packet Length Stats (Max, Min, Mean, Std Dev) - Features 13-16
             if self.getTotalFwdPackets() > 0:
                 dump.append(str(self.getFwdPacketLengthMax()))
                 dump.append(str(self.getFwdPacketLengthMin()))
                 dump.append(str(self.getFwdPacketLengthMean()))
                 dump.append(str(self.getFwdPacketLengthStd()))
             else:
                 dump.extend(["0.0"] * 4) # Use 0.0 for floating point zeros

             # Bwd Packet Length Stats (Max, Min, Mean, Std Dev) - Features 17-20
             if self.getTotalBackwardPackets() > 0:
                 dump.append(str(self.getBwdPacketLengthMax()))
                 dump.append(str(self.getBwdPacketLengthMin()))
                 dump.append(str(self.getBwdPacketLengthMean()))
                 dump.append(str(self.getBwdPacketLengthStd()))
             else:
                 dump.extend(["0.0"] * 4) # Use 0.0 for floating point zeros


             dump.append(str(self.getFlowBytesPerSec())) # 21
             dump.append(str(self.getFlowPacketsPerSec())) # 22

             dump.append(str(self.getFlowIATMean())) # 23
             dump.append(str(self.getFlowIATStd())) # 24
             dump.append(str(self.getFlowIATMax())) # 25
             dump.append(str(self.getFlowIATMin())) # 26

             # Fwd IAT Stats (Total, Mean, Std Dev, Max, Min) - Features 27-31
             # Note: Java checks forward.size() > 1 for IAT stats
             if len(self.forward) > 1:
                 dump.append(str(self.getFwdIATTotal()))
                 dump.append(str(self.getFwdIATMean()))
                 dump.append(str(self.getFwdIATStd()))
                 dump.append(str(self.getFwdIATMax()))
                 dump.append(str(self.getFwdIATMin()))
             else:
                 dump.extend(["0.0"] * 5) # Use 0.0 for floating point zeros


             # Bwd IAT Stats (Total, Mean, Std Dev, Max, Min) - Features 32-36
             # Note: Java checks backward.size() > 1 for IAT stats
             if len(self.backward) > 1:
                 dump.append(str(self.getBwdIATTotal()))
                 dump.append(str(self.getBwdIATMean()))
                 dump.append(str(self.getBwdIATStd()))
                 dump.append(str(self.getBwdIATMax()))
                 dump.append(str(self.getBwdIATMin()))
             else:
                 dump.extend(["0.0"] * 5) # Use 0.0 for floating point zeros


             dump.append(str(self.getFwdPSHFlags())) # 37
             dump.append(str(self.getBwdPSHFlags())) # 38
             dump.append(str(self.getFwdURGFlags())) # 39
             dump.append(str(self.getBwdURGFlags())) # 40

             dump.append(str(self.getFwdHeaderLength())) # 41
             dump.append(str(self.getBwdHeaderLength())) # 42
             dump.append(str(self.getfPktsPerSecond())) # 43
             dump.append(str(self.getbPktsPerSecond())) # 44

             # Packet Length Stats (Min, Max, Mean, Std Dev, Variance) - Features 45-49
             all_packet_lengths = self.fwdPktStats + self.bwdPktStats
             if all_packet_lengths: # Check if there are any packets with payload
                 dump.append(str(self.getPacketLengthMin()))
                 dump.append(str(self.getPacketLengthMax()))
                 dump.append(str(self.getPacketLengthMean()))
                 dump.append(str(self.getPacketLengthStd()))
                 dump.append(str(self.getPacketLengthVariance()))
             else:
                  dump.extend(["0.0"] * 5) # Use 0.0 for floating point zeros


             # Global Flag Counts (FIN, SYN, RST, PSH, ACK, URG, CWR, ECE) - Features 50-57
             dump.append(str(self.getFINFlagCount())) # 50
             dump.append(str(self.getSYNFlagCount())) # 51
             dump.append(str(self.getRSTFlagCount())) # 52
             dump.append(str(self.getPSHFlagCount())) # 53
             dump.append(str(self.getACKFlagCount())) # 54
             dump.append(str(self.getURGFlagCount())) # 55
             dump.append(str(self.getCWRFlagCount())) # 56
             dump.append(str(self.getECEFlagCount())) # 57

             dump.append(str(self.getDownUpRatio())) # 58
             dump.append(str(self.getAveragePacketSize())) # 59
             dump.append(str(self.fAvgSegmentSize())) # 60
             dump.append(str(self.bAvgSegmentSize())) # 61
             # Feature 62 is a duplicate of 41 (Fwd Header Length) based on the comment in FlowFeature.java,
             # but the dump method explicitly includes it. Replicating the dump order.
             dump.append(str(self.getFwdHeaderLength())) # 62 (Duplicate)


             # Bulk Features (Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate,
             #               Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate) - Features 63-68
             dump.append(str(self.fAvgBytesPerBulk())) # 63
             dump.append(str(self.fAvgPacketsPerBulk())) # 64
             dump.append(str(self.fAvgBulkRate())) # 65
             dump.append(str(self.bAvgBytesPerBulk())) # 66
             dump.append(str(self.bAvgPacketsPerBulk())) # 67
             dump.append(str(self.bAvgBulkRate())) # 68

             # Subflow Features (Fwd Packets, Fwd Bytes, Bwd Packets, Bwd Bytes) - Features 69-72
             # Note: These are average packets/bytes *per subflow state count* based on the Java getters.
             dump.append(str(self.getSflow_fpackets())) # 69
             dump.append(str(self.getSflow_fbytes())) # 70
             dump.append(str(self.getSflow_bpackets())) # 71
             dump.append(str(self.getSflow_bbytes())) # 72

             dump.append(str(self.getInit_Win_bytes_forward())) # 73
             dump.append(str(self.getInit_Win_bytes_backward())) # 74
             dump.append(str(self.getAct_data_pkt_forward())) # 75
             dump.append(str(self.getMin_seg_size_forward())) # 76

             # Active Time Stats (Mean, Std Dev, Max, Min) - Features 77-80
             if self.flowActive: # Check if there are any active periods recorded
                 dump.append(str(statistics.mean(self.flowActive))) # Use statistics directly if getter has issues
                 dump.append(str(statistics.stdev(self.flowActive) if len(self.flowActive) > 1 else 0.0))
                 dump.append(str(max(self.flowActive)))
                 dump.append(str(min(self.flowActive)))
             else:
                 dump.extend(["0.0"] * 4) # Use 0.0 for floating point zeros

             # Idle Time Stats (Mean, Std Dev, Max, Min) - Features 81-84
             if self.flowIdle: # Check if there are any idle periods recorded
                 dump.append(str(statistics.mean(self.flowIdle))) # Use statistics directly if getter has issues
                 dump.append(str(statistics.stdev(self.flowIdle) if len(self.flowIdle) > 1 else 0.0))
                 dump.append(str(max(self.flowIdle)))
                 dump.append(str(min(self.flowIdle)))
             else:
                 dump.extend(["0.0"] * 4) # Use 0.0 for floating point zeros


             dump.append(str(self.getLabel())) # 85 (Last feature)

        except Exception as e:
             # Log error during dump, but try to produce a line with error indicator
             logger.error(f"Error during dumpFlowBasedFeaturesEx for flow {getattr(self, 'flowId', 'UnknownID')} (object id: {id(self)}): {e}", exc_info=True) # Log traceback
             # Fill the rest of the features with "ERROR" to maintain column count
             while len(dump) < 85:
                 dump.append("ERROR")


        return separator.join(dump)