import csv
import time
import os
import logging
from typing import Dict, List, Callable # Import Callable for type hinting
import pandas as pd # Import pandas
import numpy as np # Import numpy
import joblib # Import joblib
import json # Import json for outputting data
import queue # Import queue for thread-safe queue

# Import necessary components from other files
# Ensure these files (packet_info.py, basic_flow.py, constants.py, flow_feature.py)
# exist in the same directory and contain the expected classes/constants.
from scapy.packet import Packet # Keep Packet import for type hinting
from packet_info import BasicPacketInfo # <-- Make sure this import is present and correct
from basic_flow import BasicFlow # <-- Make sure this import is present and correct
from flow_feature import FlowFeature # Needed for header dumping
from constants import ACTIVE_TIMEOUT_MICROS, IDLE_TIMEOUT_MICROS # Import timeouts


logger = logging.getLogger(__name__) # Get logger for this module
logger.setLevel(logging.INFO) # Set logger level to INFO to reduce verbose output


# --- Flow Generator Logic (based on FlowGenerator.java) ---
class FlowGenerator:
    # --- Updated __init__ method to accept model, encoder, features, scaler, and the prediction queue ---
    def __init__(self,
                 bidirectional: bool,
                 flow_timeout_micros: int = ACTIVE_TIMEOUT_MICROS,
                 activity_timeout_micros: int = IDLE_TIMEOUT_MICROS,
                 loaded_model=None, # Accept the loaded model
                 loaded_label_encoder=None, # Accept the loaded label encoder
                 selected_features: List[str] = None, # Accept the list of selected features
                 loaded_scaler=None, # Accept the loaded scaler
                 prediction_queue: queue.Queue = None # Accept the prediction queue
                ):
        self.bidirectional = bidirectional
        self.flow_timeout_micros = flow_timeout_micros
        self.activity_timeout_micros = activity_timeout_micros
        self.current_flows: Dict[str, BasicFlow] = {}  # Dictionary to store active flows: flow_id -> BasicFlow object
        self.finished_flows: list[BasicFlow] = [] # List to store completed flows temporarily
        self.finished_flow_count = 0 # To mimic the Java counter

        # --- Store the loaded objects and the prediction queue as instance attributes ---
        self.loaded_model = loaded_model
        self.loaded_label_encoder = loaded_label_encoder
        self.selected_features = selected_features if selected_features is not None else [] # Store selected features, default to empty list
        self.loaded_scaler = loaded_scaler # Store the loaded scaler
        self.prediction_queue = prediction_queue # Store the prediction queue
        # -------------------------------------------------------------------------

        logger.debug("FlowGenerator initialized with flow_timeout=%d, activity_timeout=%d", flow_timeout_micros, activity_timeout_micros)
        if self.loaded_model is not None:
            logger.info("FlowGenerator initialized with loaded model.") # Changed to INFO
        if self.loaded_label_encoder is not None:
             logger.info("FlowGenerator initialized with loaded label encoder.") # Changed to INFO
        if self.selected_features:
             logger.info(f"FlowGenerator initialized with {len(self.selected_features)} selected features.") # Changed to INFO
        if self.loaded_scaler is not None:
             logger.info("FlowGenerator initialized with loaded scaler.")
        if self.prediction_queue:
             logger.info("FlowGenerator initialized with prediction queue.")


    # --- addPacket method (keep as is from previous versions) ---
    def addPacket(self, packet: Packet):
        """Adds a packet to an existing flow or creates a new one."""
        packet_info = None
        try:
            # The error is happening here: BasicPacketInfo needs to be defined or imported
            packet_info = BasicPacketInfo(packet)
        except ValueError:
             # logger.debug("Skipping non-IP/IPv6 packet") # Too noisy for normal operation
             return # Skip this packet if it's not IP/IPv6
        except Exception as e:
             # This error log will be triggered if BasicPacketInfo is not defined
             logger.error(f"Error creating BasicPacketInfo for packet from scapy: {e}")
             return # Skip this packet if BasicPacketInfo creation failed

        # logger.debug(f"Processing packet id {packet_info.id}, timestamp {packet_info.getTimeStamp()}") # Removed verbose debug
        current_timestamp = packet_info.getTimeStamp()


        # Check for expired flows (active timeout) before processing the new packet
        # Make a copy of keys to avoid modifying the dict during iteration
        keys_to_check = list(self.current_flows.keys())
        # logger.debug(f"Checking {len(keys_to_check)} current flows for timeouts.") # Removed verbose debug
        for flow_id in keys_to_check:
             flow = self.current_flows[flow_id] # Access directly after getting keys
             # Active Timeout: time since the *start* of the flow exceeds the flow timeout
             if (current_timestamp - flow.getFlowStartTime()) > self.flow_timeout_micros:
                  logger.info(f"Flow {flow_id} timed out.") # Changed to INFO
                  # Pass the timestamp that caused the timeout for finalization
                  self._close_flow(flow_id, current_timestamp, "Active Timeout")


        # Determine potential flow IDs for the current packet
        fwd_id = packet_info.fwdFlowId()
        bwd_id = packet_info.bwdFlowId()
        # logger.debug(f"Packet {packet_info.id} has fwd_id: {fwd_id}, bwd_id: {bwd_id}") # Removed verbose debug


        # Check if the packet belongs to an existing flow
        flow_id = None
        if fwd_id in self.current_flows:
             flow_id = fwd_id
             # logger.debug(f"Packet {packet_info.id} belongs to existing flow {flow_id} (via fwd_id).") # Removed verbose debug
        elif bwd_id in self.current_flows:
             flow_id = bwd_id
             # logger.debug(f"Packet {packet_info.id} belongs to existing flow {flow_id} (via bwd_id).") # Removed verbose debug

        if flow_id is not None:
             # Packet belongs to an existing current flow
             flow = self.current_flows.get(flow_id) # Use .get() for safer retrieval, though key should exist


             if flow is None:
                  # This case should ideally not happen if flow_id was found in keys_to_check or dictionary lookups,
                  # but including a check as a safeguard against unexpected state.
                  logger.error(f"Flow {flow_id} unexpectedly not found in current_flows after lookup for packet {packet_info.id}! Skipping packet.")
                  return # Skip processing this packet

             # logger.debug(f"Adding packet {packet_info.id} to existing flow {flow_id} (object id: {id(flow)}).") # Removed verbose debug

             # Check for FIN or RST flags for flow termination (TCP only)
             if packet_info.getProtocol() == 6: # TCP
                  terminate_flow = False
                  if packet_info.hasFlagRST():
                       logger.info(f"Packet {packet_info.id} has RST flag. Terminating flow {flow_id}.") # Changed to INFO
                       terminate_flow = True
                  elif packet_info.hasFlagFIN():
                       # Logic for FIN flags involves counting FINs in both directions
                       # Increment directional FIN counts using the methods in BasicFlow
                       # Ensure flow.getSrc() is valid before calling isForwardPacket
                       if flow.getSrc() is not None:
                            is_forward = packet_info.isForwardPacket(flow.getSrc())
                            if is_forward:
                                 flow.setFwdFINFlags()
                                 # logger.debug(f"Packet {packet_info.id} is FWD FIN. Flow {flow_id} FWD FIN count: {flow.getFwdFINFlags()}") # Removed verbose debug
                            else:
                                 flow.setBwdFINFlags()
                                 # logger.debug(f"Packet {packet_info.id} is BWD FIN. Flow {flow_id} BWD FIN count: {flow.getBwdFINFlags()}") # Removed verbose debug
                       else:
                            logger.warning(f"Flow {flow_id} has None src IP when checking FIN flags for packet {packet_info.id}. Cannot determine direction.")


                       # Terminate if the sum of fwd_fin_flags and bwd_fin_flags is >= 2
                       if (flow.getFwdFINFlags() + flow.getBwdFINFlags()) >= 2:
                            logger.info(f"Flow {flow_id} has >= 2 FIN flags. Terminating flow.") # Changed to INFO
                            terminate_flow = True


                  if terminate_flow:
                       # Add the current packet before closing (Java behavior)
                       try:
                            flow.addPacket(packet_info)
                            # logger.debug(f"Added terminating packet {packet_info.id} to flow {flow_id} before closing.") # Removed verbose debug
                       except Exception as e:
                            logger.error(f"Error adding terminating packet {packet_info.id} to flow {flow_id}: {e}", exc_info=True) # Log traceback
                            # Still attempt to close the flow even if adding the last packet failed
                       self._close_flow(flow_id, current_timestamp, "FIN/RST Flag")
                       return # Flow closed, processing for this packet is done


             # If not terminated by timeouts, FIN, or RST, add the packet to the existing flow
             try:
                  flow.addPacket(packet_info)
                  # logger.debug(f"Successfully added packet {packet_info.id} to existing flow {flow_id}.") # Removed verbose debug
                  # self.current_flows[flow_id] = flow # Ensure the updated flow is in the map (redundant but harmless)
             except Exception as e:
                  logger.error(f"Error adding packet {packet_info.id} to existing flow {flow_id} (object id: {id(flow)}): {e}", exc_info=True) # Log traceback
                  # Do not remove the flow on error, might recover or be closed by timeout later.
                  # Consider incrementing a flow-specific error counter if needed.


        else:
             # New flow detected
             # logger.debug(f"Packet {packet_info.id} is starting a new flow.") # Removed verbose debug
             # Create a new BasicFlow instance
             new_flow = None # Initialize to None
             try:
                  # Use the constructor that takes the first packet.
                  # This constructor is now responsible for setting the flow's identity.
                  # No need to pass flowSrc, flowDst etc. here for NEW flows.
                  # The error might also originate if BasicFlow is not defined
                  new_flow = BasicFlow(self.bidirectional, packet_info, activityTimeout=self.activity_timeout_micros)

                  # Add the new flow to the dictionary using its determined flowId
                  flow_id_for_dict = new_flow.getFlowId()

                  # Safeguard: Should not exist if this path is truly for new flows
                  if flow_id_for_dict in self.current_flows:
                       logger.warning(f"New flow creation for packet {packet_info.id} attempted to overwrite existing flow key {flow_id_for_dict}. This suggests a logic error in flow ID generation or timeout handling.")

                  self.current_flows[flow_id_for_dict] = new_flow
                  logger.info(f"Created new flow {flow_id_for_dict} for packet {packet_info.id}.") # Changed to INFO

             except Exception as e:
                  # This catch block seems to be where the 'checkFlags' error during firstPacket is reported
                  logger.error(f"Error creating new flow for packet {packet_info.id}: {e}", exc_info=True) # Log traceback
                  # The error traceback clearly shows this is happening during the BasicFlow() constructor call,
                  # specifically inside firstPacket() -> checkFlags().
                  # If new flow creation failed, the flow object might be incomplete or not added to current_flows.
                  # The packet is discarded in terms of flow processing.


    # --- _close_flow method ---
    def _close_flow(self, flow_id: str, current_timestamp: int, reason: str):
        """Helper method to finalize and move a flow."""
        flow = self.current_flows.pop(flow_id, None)
        if flow:
            logger.info(f"Closing flow {flow_id}. Reason: {reason}") # Changed to INFO
            # The Java code checks packetCount() > 1 before adding to finishedFlows.
            # This means flows with only one packet are discarded.
            if flow.packetCount() > 1:
                logger.debug(f"Flow {flow_id} has {flow.packetCount()} packets (> 1). Finalizing.") # Keep debug for finalization steps
                try:
                    # Finalize active/idle times with the timestamp that caused the close
                    flow.endActiveIdleTime(current_timestamp, self.activity_timeout_micros, self.flow_timeout_micros, reason in ["FIN/RST Flag"])
                    self.finished_flow_count += 1

                    # --- New: Process and put the flow in the queue if queue is available ---
                    if self.prediction_queue:
                         logger.debug(f"Putting flow {flow_id} in prediction queue immediately upon close.")
                         self._process_and_queue_flow(flow)
                         # We don't add to self.finished_flows if putting in queue immediately
                    else:
                         # If no queue, add to finished_flows list for later batch processing (e.g., file mode without dashboard)
                         self.finished_flows.append(flow)
                         logger.debug(f"Flow {flow_id} finalized and added to finished_flows for batch processing. Total finished: {len(self.finished_flows)}")
                    # ---------------------------------------------------------------------


                except Exception as e:
                     logger.error(f"Error finalizing flow {flow_id} before closing: {e}", exc_info=True) # Log traceback
                     # Even if finalization failed, if we have a queue, try to put partial data
                     if self.prediction_queue:
                          logger.warning(f"Attempting to put flow {flow_id} in queue despite finalization error.")
                          self._process_and_queue_flow(flow)
                     else:
                          # If no queue, still add to finished_flows list
                          self.finished_flows.append(flow)
                          logger.warning(f"Flow {flow_id} added to finished_flows despite finalization error.")


            else:
                logger.debug(f"Discarded flow {flow_id} with only {flow.packetCount()} packet(s). Reason: {reason}") # Keep debug for discarded flows
                pass # Discard flows with 1 packet
        else:
             logger.debug(f"Attempted to close flow {flow_id} but it was not found in current_flows.") # Keep debug for this specific case

    # --- close_all_flows method ---
    def close_all_flows(self, current_timestamp: int):
        """Closes all currently active flows."""
        keys_to_close = list(self.current_flows.keys())
        logger.info(f"Closing all remaining {len(keys_to_close)} active flows.") # Changed to INFO
        for flow_id in keys_to_close:
             flow = self.current_flows.get(flow_id)
             if flow:
                  final_timestamp = flow.flowLastSeen if flow.flowLastSeen > 0 else current_timestamp
                  self._close_flow(flow_id, final_timestamp, "End of Capture/Timeout") # Updated reason
             else:
                  logger.warning(f"Flow {flow_id} was expected in current_flows during close_all_flows but not found.")

    # --- New method to process and put a single flow in the queue ---
    def _process_and_queue_flow(self, flow: BasicFlow):
        """
        Extracts features, makes a prediction, and puts data for a single flow
        into the prediction queue.
        """
        if flow is None:
            logger.warning("Attempted to process a None flow for prediction.")
            return

        # Check if the model, label encoder, scaler were loaded successfully and features are selected
        if self.loaded_model is None or self.loaded_label_encoder is None or not self.selected_features or self.loaded_scaler is None:
            logger.warning(f"Prediction components not fully loaded. Skipping prediction for flow {flow.flowId}.")
            return

        try:
            # Get the full list of 85 features as a string
            full_features_string = flow.dumpFlowBasedFeaturesEx()
            # Split the string into a list of 85 feature values
            full_features_list = full_features_string.split(',')

            # Get the full list of 85 header names
            full_header_string = FlowFeature.get_header()
            full_header_list = full_header_string.split(',')

            if len(full_features_list) == len(full_header_list):
                flow_features_series = pd.Series(full_features_list, index=full_header_list)

                try:
                    features_for_prediction_series = flow_features_series[self.selected_features]
                except KeyError as e:
                    logger.error(f"Error selecting features for flow {flow.flowId}: Missing selected feature {e}. Skipping prediction.")
                    return # Skip prediction for this flow

                # --- Apply Preprocessing (Replicate training preprocessing) ---
                features_for_prediction_numeric = pd.to_numeric(features_for_prediction_series, errors='coerce')
                features_for_prediction_processed = features_for_prediction_numeric.fillna(0)

                # Apply the loaded scaler
                final_features_for_prediction = self.loaded_scaler.transform(features_for_prediction_processed.values.reshape(1, -1))

                # --- Make Prediction ---
                prediction_numeric = self.loaded_model.predict(final_features_for_prediction)
                prediction_proba = self.loaded_model.predict_proba(final_features_for_prediction) # Get probabilities

                # --- Decode Prediction ---
                prediction_label_encoded = int(prediction_numeric[0])
                predicted_label = "Unknown"
                predicted_probability = 0.0

                if prediction_label_encoded < len(self.loaded_label_encoder.classes_):
                     predicted_label = self.loaded_label_encoder.inverse_transform([prediction_label_encoded])[0]
                     predicted_probability = np.max(prediction_proba[0])

                     # --- Prepare Prediction Data ---
                     prediction_data = {
                         "flow_id": flow.flowId,
                         "predicted_label": predicted_label,
                         "probability": float(predicted_probability),
                         "timestamp": int(time.time() * 1000), # Current time in milliseconds
                         "src_ip": flow.getSrc(),
                         "src_port": flow.getSrcPort(),
                         "dst_ip": flow.getDst(),
                         "dst_port": flow.getDstPort(),
                         "protocol": flow.getProtocol(),
                         "packet_count": flow.packetCount()
                     }

                     # --- Put Data into the Queue ---
                     if self.prediction_queue:
                         self.prediction_queue.put(prediction_data)
                         logger.debug(f"Put prediction for flow {flow.flowId} into queue.")
                     else:
                         # Fallback to console print if no queue is available (shouldn't happen if called correctly)
                         logger.warning(f"Prediction queue is None. Cannot queue prediction for flow {flow.flowId}. Printing to console.")
                         print(f"Flow {flow.flowId}: Predicted Label = {predicted_label} (Probability: {predicted_probability:.4f})") # Console fallback

                else:
                     logger.warning(f"Flow {flow.flowId}: Model predicted out-of-range label ({prediction_label_encoded}). Cannot decode.")

            else:
                logger.error(f"Feature count mismatch for flow {flow.flowId}. Expected {len(full_header_list)}, got {len(full_features_list)}. Skipping prediction.")

        except Exception as e:
            logger.error(f"Error during prediction/queueing for flow {getattr(flow, 'flowId', 'UnknownID')}: {e}", exc_info=True)


    # --- dump_labeled_flow_based_features method (Now processes finished_flows batch) ---
    def dump_labeled_flow_based_features(self, output_path: str, filename: str, header: str) -> int:
        """
        Processes completed flows (those in self.finished_flows) by calling
        _process_and_queue_flow for each, and then clears the list.
        This method is primarily used for processing flows that couldn't be sent
        immediately (e.g., in file mode without a dashboard URL or due to errors).
        """
        total_processed_in_batch = 0

        # Process flows that were added to finished_flows
        flows_to_process_batch = list(self.finished_flows) # Get a copy
        self.finished_flows = [] # Clear the list for the next batch

        if flows_to_process_batch:
            logger.info(f"Processing a batch of {len(flows_to_process_batch)} finished flows.")
            for flow in flows_to_process_batch:
                if flow and flow.packetCount() > 1: # Only process flows with more than 1 packet
                    # If a queue is available, this will put it in the queue.
                    # If no queue, it will fall back to console print within _process_and_queue_flow.
                    self._process_and_queue_flow(flow)
                    total_processed_in_batch += 1
                elif flow:
                     logger.debug(f"Discarding finished flow {flow.flowId} with only {flow.packetCount()} packet(s) in batch processing.")

            logger.info(f"Completed processing batch. Total flows processed in this batch: {total_processed_in_batch}.")

        else:
             logger.debug("No finished flows in the batch to process.")


        return total_processed_in_batch # Return the count of flows processed in this batch

    # --- close_all_flows method (keep as is from previous versions) ---
    # This method remains the same. It calls _close_flow for each active flow,
    # and _close_flow now handles the immediate prediction/queueing.
    # def close_all_flows(self, current_timestamp: int):
    #     """Closes all currently active flows."""
    #     keys_to_close = list(self.current_flows.keys())
    #     logger.info(f"Closing all remaining {len(keys_to_close)} active flows.") # Changed to INFO
    #     for flow_id in keys_to_close:
    #          flow = self.current_flows.get(flow_id)
    #          if flow:
    #               final_timestamp = flow.flowLastSeen if flow.flowLastSeen > 0 else current_timestamp
    #               self._close_flow(flow_id, final_timestamp, "End of Capture/Timeout") # Updated reason
    #          else:
    #               logger.warning(f"Flow {flow_id} was expected in current_flows during close_all_flows but not found.")


