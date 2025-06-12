import logging
import sys
import os
import time
import argparse
import joblib # Import joblib to load the model, encoder, and scaler
import pandas as pd # Import pandas for feature selection and preprocessing
import numpy as np # Import numpy for numerical operations
from sklearn.preprocessing import MinMaxScaler # Import the scaler class used in training
import signal # Import signal for graceful termination
import random # Import random for test pcap generation
from datetime import datetime # Import datetime for timestamp handling if needed
import json # Import json for outputting data
import requests # Keep requests for synchronous fallback if needed, but will use aiohttp
import asyncio # Import asyncio for asynchronous operations
import aiohttp # Import aiohttp for asynchronous HTTP requests
import queue # Import queue for thread-safe queue
import threading # Import threading to run the async loop in a separate thread

# Assuming these components are in their respective files
# Make sure flow_generator.py, constants.py, flow_feature.py, packet_info.py, basic_flow.py exist
from flow_generator import FlowGenerator
from constants import DEFAULT_PCAP_PATH, DEFAULT_OUT_PATH, ACTIVE_TIMEOUT_MICROS, IDLE_TIMEOUT_MICROS
from flow_feature import FlowFeature
from scapy.all import rdpcap, wrpcap, Ether, IP, IPv6, TCP, UDP, Raw, sniff, get_if_list


# --- Logging Configuration ---
# Configure logging to only output to console (stdout)
# Setting level to INFO for less console spam during sniffing, but __main__ logger is DEBUG
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

# Get the root logger
root_logger = logging.getLogger()

# Ensure only the console handler is present if basicConfig was called before
if root_logger.hasHandlers():
    root_logger.handlers = [h for h in root_logger.handlers if isinstance(h, logging.StreamHandler)]
    if not root_logger.handlers: # Add console handler if none exist after cleaning
         console_handler = logging.StreamHandler(sys.stdout)
         console_handler.setLevel(logging.INFO) # Console handler INFO
         console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
         root_logger.addHandler(console_handler)


# Set the logger for this module (__main__) to DEBUG for detailed script flow
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# --- Global flag for graceful shutdown ---
# This flag will be set by the signal handler
stop_sniffing_flag = False

# --- Signal Handler ---
def signal_handler(signum, frame):
    """
    Handles termination signals (like Ctrl+C) to stop sniffing gracefully.
    """
    global stop_sniffing_flag
    stop_sniffing_flag = True
    logger.info("Termination signal received (Ctrl+C). Initiating graceful shutdown...")
    # Note: In this version, the signal handler sets the flag, and the packet callback
    # checks the flag and raises StopIteration to stop sniff().


# --- Dashboard URL (Update this with your Flask app's address and port) ---
DASHBOARD_URL = "http://127.0.0.1:5000/predict" # Default Flask address and route
# ------------------------------------------------------------------------

# --- Thread-safe Queue for Predictions ---
# This queue will hold prediction data dictionaries to be sent asynchronously
prediction_queue = queue.Queue()

# --- Asynchronous Sender Function ---
async def async_send_prediction(session, url, prediction_data):
    """
    Sends prediction data asynchronously using aiohttp.
    """
    try:
        async with session.post(url, json=prediction_data) as response:
            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
            logger.debug(f"Sent prediction for flow {prediction_data.get('flow_id', 'N/A')} to dashboard. Status Code: {response.status}")
    except aiohttp.ClientConnectorError:
        logger.warning(f"Could not connect to dashboard at {url}. Is the Flask app running?")
    except aiohttp.ClientResponseError as e:
        logger.error(f"HTTP error sending prediction to dashboard: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while sending prediction to dashboard: {e}", exc_info=True)

# --- Asynchronous Sender Worker ---
async def async_sender_worker(q: queue.Queue, url: str):
    """
    Worker function that runs in a separate thread to process the prediction queue
    and send data asynchronously.
    """
    # Create a single aiohttp ClientSession for efficiency
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                # Get prediction data from the queue (blocks until data is available)
                # Use a small timeout to allow checking the stop flag eventually,
                # or rely on the main thread to put a sentinel value.
                # A better approach for graceful shutdown is to put a sentinel None value.
                prediction_data = q.get(timeout=1) # Get with a timeout

                if prediction_data is None: # Check for sentinel value
                    logger.info("Async sender received stop signal (None). Exiting loop.")
                    q.task_done() # Mark the sentinel task as done
                    break # Exit the loop

                logger.debug(f"Async sender got data from queue for flow: {prediction_data.get('flow_id', 'N/A')}")
                # Schedule the asynchronous sending task
                await async_send_prediction(session, url, prediction_data)

                # Mark the task as done so q.join() knows when the queue is empty
                q.task_done()

            except queue.Empty:
                # Queue is empty, continue looping and waiting for items
                # This allows the thread to periodically check for the stop flag
                pass
            except Exception as e:
                logger.error(f"An error occurred in the async sender worker: {e}", exc_info=True)
                # Even on error, mark the task as done to prevent q.join() from hanging
                if 'prediction_data' in locals() and prediction_data is not None:
                     q.task_done()


# --- Function to put prediction data into the queue ---
def put_prediction_in_queue(prediction_data: dict):
    """
    Puts prediction data into the thread-safe queue to be sent asynchronously.
    """
    # Check if DASHBOARD_URL is set before putting in queue
    # This check is now also done in the async_send_prediction function,
    # but putting it here prevents unnecessary queue operations.
    global DASHBOARD_URL
    if DASHBOARD_URL:
        try:
            prediction_queue.put(prediction_data)
            logger.debug(f"Put prediction for flow {prediction_data.get('flow_id', 'N/A')} into queue.")
        except Exception as e:
            logger.error(f"Error putting prediction data into queue: {e}", exc_info=True)
    else:
        logger.debug("Dashboard URL not set. Skipping putting prediction data in queue.")


# --- Load Trained Model, Label Encoder, Selected Features, and Scaler ---
# Define the paths to your saved files
# Assuming the files are in a 'models' subdirectory relative to where flowmeter.py is run
MODEL_FILENAME = 'models/xgboost_model.pkl' # Corrected filename based on user output
SCALER_MODEL_FILENAME = 'models/scaler.joblib' # Corrected filename based on user output
LABEL_ENCODER_FILENAME = 'models/label_encoder.joblib' # Make sure this matches your filename
SELECTED_FEATURES_FILENAME = 'models/selected_features.csv' # Make sure this matches your filename

# Variables to hold the loaded model and encoder
loaded_model = None
loaded_label_encoder = None
loaded_scaler = None
selected_features = []

# Attempt to load the model
try:
    loaded_model = joblib.load(MODEL_FILENAME)
    logger.info(f"Successfully loaded model from {MODEL_FILENAME}")
except FileNotFoundError:
    logger.error(f"Error: Model file not found at {MODEL_FILENAME}. Please ensure the file exists in the 'models' directory.")
except Exception as e:
    logger.error(f"An error occurred while loading the model: {e}")

# Attempt to load the scaler
try:
    loaded_scaler = joblib.load(SCALER_MODEL_FILENAME) # Correctly loading the scaler file into loaded_scaler
    logger.info(f"Successfully loaded scaler from {SCALER_MODEL_FILENAME}")
except FileNotFoundError:
    logger.error(f"Error: Scaler file not found at {SCALER_MODEL_FILENAME}. Please ensure the file exists in the 'models' directory.")
except Exception as e:
    logger.error(f"An error occurred while loading the scaler: {e}")

# Attempt to load the label encoder
try:
    loaded_label_encoder = joblib.load(LABEL_ENCODER_FILENAME)
    logger.info(f"Successfully loaded label encoder from {LABEL_ENCODER_FILENAME}")
except FileNotFoundError:
    logger.error(f"Error: Label encoder file not found at {LABEL_ENCODER_FILENAME}. Please ensure the file exists in the 'models' directory.")
except Exception as e:
    logger.error(f"An error occurred while loading the label encoder: {e}")

# Attempt to load the selected features list
try:
    # Load the selected features list from the CSV
    features_df = pd.read_csv(SELECTED_FEATURES_FILENAME)
    selected_features = features_df['Features'].tolist()
    logger.info(f"Successfully loaded {len(selected_features)} selected features from {SELECTED_FEATURES_FILENAME}")
except FileNotFoundError:
    logger.error(f"Error: Selected features file not found at {SELECTED_FEATURES_FILENAME}. Please ensure the file exists in the 'models' directory and has a 'Features' column.")
except Exception as e:
    logger.error(f"An error occurred while loading the selected features: {e}")


# --- Simple PCAP Generation Function (Keep this for file mode or testing) ---
def generate_simple_test_pcap(output_dir, filename="simple_test_flow.pcap", num_packets=10):
    """
    Generates a simple test PCAP file with a single TCP flow.
    This is for demonstration of the pipeline; generating realistic traffic is complex.
    """
    filepath = os.path.join(output_dir, filename)
    packets = []

    # Define source and destination IP and ports
    src_ip = "192.168.1.100"
    dst_ip = "8.8.8.8"
    src_port = random.randint(1024, 65535)
    dst_port = 80 # HTTP example

    logger.info(f"Generating simple test PCAP: {filename}")

    for i in range(num_packets):
        # Create a simple Ethernet -> IP -> TCP packet
        ether_layer = Ether()
        ip_layer = IP(src=src_ip, dst=dst_ip)
        # Use empty string for flags when not SYN or ACK
        tcp_flags = "S" if i == 0 else ("A" if i == 1 else "")
        tcp_layer = TCP(sport=src_port, dport=dst_port, flags=tcp_flags, seq=i*100, ack=i*100 + 1) # Simulate some sequence/ack
        # Add a small payload
        payload = f"Packet {i}".encode()
        packet = ether_layer / ip_layer / tcp_layer / payload
        # Adjust timestamp (Scapy uses floating point seconds since epoch)
        packet.time = time.time() + i * 0.01 # Add a small delay between packets

        packets.append(packet)

    try:
        wrpcap(filepath, packets)
        logger.info(f"Generated {len(packets)} packets in {filepath}")
        return filepath # Return the path of the generated file
    except Exception as e:
        logger.error(f"Error generating PCAP file {filepath}: {e}")
        return None

# --- Packet Processing Function for Live Capture ---
# This function will be called by Scapy's sniff() for each captured packet
def process_live_packet(packet, flow_generator):
    """
    Processes a single packet captured live and adds it to the flow generator.
    """
    # FlowGenerator will handle internal state updates and prediction.
    try:
        flow_generator.addPacket(packet)
    except Exception as e:
        # Log any errors during packet processing but don't stop sniffing
        logger.error(f"Error processing live packet: {e}", exc_info=True)


# --- Main Function with Live Capture Mode ---
def main():
    # --- CORRECTED: Move global declaration to the top of the function ---
    global DASHBOARD_URL
    # -------------------------------------------------------------------

    parser = argparse.ArgumentParser(description="Python version of CICFlowMeter.")
    parser.add_argument("--pcap-path", default=DEFAULT_PCAP_PATH,
                        help=f"Path to directory containing .pcap files (default: {DEFAULT_PCAP_PATH})")
    parser.add_argument("--out-path", default=DEFAULT_OUT_PATH,
                        help=f"Path to output directory for .csv files (default: {DEFAULT_OUT_PATH})")
    parser.add_argument("--skip-generate", action="store_true",
                        help="Skip generating the simple test PCAP (only applicable in file mode).")
    parser.add_argument("--interface", help="Network interface to sniff on for live capture.")
    # Set a default sniff-count for live capture for easier testing
    parser.add_argument("--sniff-count", type=int, default=0, # User changed default to 0
                        help="Number of packets to sniff for live capture (0 means indefinite).")
    parser.add_argument("--sniff-timeout", type=int, default=0,
                        help="Timeout for live sniffing in seconds (0 means indefinite).")
    # --- Added dashboard-url argument ---
    parser.add_argument("--dashboard-url", default="", # Changed default to empty string
                        help=f"URL of the dashboard endpoint to send predictions (e.g., http://127.0.0.1:5000/predict). Leave empty to print to console.")
    # ------------------------------------
    # --- Added dump-interval argument for periodic updates in file mode ---
    parser.add_argument("--dump-interval", type=int, default=1000,
                        help="Number of packets to process before dumping/sending completed flows in file mode (default: 1000). Set to 0 to only dump at the end.")
    # -------------------------------------------------------------------


    args = parser.parse_args()

    pcap_path = args.pcap_path
    out_path = args.out_path
    dump_interval = args.dump_interval # Get the dump interval

    # --- CORRECTED: Assignment after global declaration ---
    # Only update the global URL if the argument is provided and not empty
    if args.dashboard_url:
        DASHBOARD_URL = args.dashboard_url
        logger.info(f"Dashboard URL set to: {DASHBOARD_URL}")
    else:
        logger.info("No dashboard URL provided. Prediction results will be printed to console.")
        # Set DASHBOARD_URL to None or empty string to indicate no dashboard output
        DASHBOARD_URL = "" # Using empty string to check later


    os.makedirs(out_path, exist_ok=True)

    # --- Start the Asynchronous Sender Thread ---
    # Create and start the thread that runs the async event loop and sends data
    # Pass the prediction_queue and the DASHBOARD_URL to the worker
    sender_thread = threading.Thread(target=lambda: asyncio.run(async_sender_worker(prediction_queue, DASHBOARD_URL)))
    sender_thread.daemon = True # Allow the main thread to exit even if the sender thread is running
    sender_thread.start()
    logger.info("Asynchronous sender thread started.")
    # --------------------------------------------


    # --- Pass loaded model, encoder, features, scaler, and the queue to FlowGenerator ---
    # Initialize the FlowGenerator
    # The FlowGenerator needs access to the loaded model, encoder, and selected features
    # Pass them during initialization
    flow_gen = FlowGenerator(
        bidirectional=True,
        flow_timeout_micros=ACTIVE_TIMEOUT_MICROS,
        activity_timeout_micros=IDLE_TIMEOUT_MICROS,
        loaded_model=loaded_model, # Pass the loaded model
        loaded_label_encoder=loaded_label_encoder, # Pass the loaded label encoder
        selected_features=selected_features, # Pass the selected features list
        loaded_scaler=loaded_scaler, # Pass the loaded scaler
        prediction_queue=prediction_queue # Pass the prediction queue
    )
    logger.debug("FlowGenerator initialized with loaded components and prediction queue.")
    # -----------------------------------------------------------------------------------------


    if args.interface:
        # --- Live Capture Mode ---
        interface = args.interface
        logger.info(f"Starting live capture on interface: {interface}")
        # Only report timeout/count if they are non-zero
        if args.sniff_timeout > 0 or args.sniff_count > 0:
             logger.info(f"Sniffing timeout: {args.sniff_timeout}s, Packet count limit: {args.sniff_count}")
        else:
             logger.info("Sniffing indefinitely. Press Ctrl+C to stop.") # Updated message

        # --- Register the signal handler for graceful termination ---
        # This allows stopping the sniff with Ctrl+C
        signal.signal(signal.SIGINT, signal_handler)
        # -----------------------------------------------------------

        try:
            # Define the packet callback for live capture
            def packet_callback_wrapper(packet):
                 # Check the global flag before processing the packet
                 if stop_sniffing_flag:
                     # If the flag is set, raise StopIteration to stop the sniff loop
                     logger.debug("stop_sniffing_flag is set. Raising StopIteration to stop sniffing.")
                     raise StopIteration
                 else:
                    # Otherwise, process the packet
                    process_live_packet(packet, flow_gen) # Call process_live_packet


            logger.debug("Calling scapy.sniff()...")
            start_time_sniff = time.time() # Record sniff start time
            # Start sniffing live traffic

            # --- Modified sniff call logic (removed stop_sniffing, rely on StopIteration) ---
            sniff_kwargs = {
                'iface': interface,
                'prn': packet_callback_wrapper,
                'store': 0
                # Removed 'stop_sniffing': should_stop_sniffing
            }

            # Add timeout and count only if they are specified (non-zero)
            if args.sniff_timeout > 0:
                sniff_kwargs['timeout'] = args.sniff_timeout
            if args.sniff_count > 0:
                sniff_kwargs['count'] = args.sniff_count

            sniff(**sniff_kwargs) # Use the dictionary to pass arguments
            # -------------------------------------------------------------

            end_time_sniff = time.time() # Record sniff end time
            logger.debug(f"scapy.sniff() returned after {end_time_sniff - start_time_sniff:.2f} seconds.")


        except KeyboardInterrupt:
             # Catch KeyboardInterrupt specifically for Ctrl+C.
             # This might still be reached in some cases, but StopIteration is the primary stop mechanism now.
             logger.info("Sniffing interrupted by user (Ctrl+C).")
        except StopIteration: # Catch the StopIteration raised by the callback
            logger.info("Sniffing stopped by StopIteration from packet callback.")
        except Exception as e:
            # This will catch other exceptions during sniff or if sniff raises on failure
            logger.error(f"An error occurred during live sniffing: {e}", exc_info=True)
            logger.info("Troubleshooting live capture:")
            logger.info("1. Ensure you have administrator or root privileges.")
            try:
                logger.info(f"2. Verify interface name. Available interfaces: {get_if_list()}")
            except Exception as if_e:
                 logger.error(f"Could not list interfaces: {if_e}")


        # Processing logic after sniff returns (either by timeout, count, or signal/StopIteration)
        logger.info("Sniffing stopped. Processing remaining flows...")
        # Use the timestamp of when the sniff stopped for final flow closing
        final_process_timestamp = int(time.time() * 1_000_000)
        flow_gen.close_all_flows(final_process_timestamp) # Close any remaining active flows

        # --- Call the modified dump function to process remaining finished flows ---
        # The dump_labeled_flow_based_features method in flow_generator.py will now
        # process any flows that were added to its internal finished_flows list.
        # In live capture with immediate sending, this list should ideally be empty
        # unless there were errors during immediate processing.
        total_flows_processed_for_prediction = flow_gen.dump_labeled_flow_based_features(
            out_path, # Output path (might not be used for file writing in this version)
            "live_capture_predictions.json", # Filename (might not be used for file writing)
            FlowFeature.get_header() # Header (might not be used for file writing)
            # Removed send_to_dashboard_func here, it's handled by the FlowGenerator instance
        )
        print(f"Completed processing {total_flows_processed_for_prediction} flows from live capture (batch).")


    else:
        # --- PCAP File Processing Mode (Existing Logic with Periodic Dump) ---

        # Pipeline Step 1: Generate PCAPs (simple test PCAP) - Only in file mode
        if not args.skip_generate:
            os.makedirs(pcap_path, exist_ok=True)
            generate_simple_test_pcap(pcap_path)
        else:
            logger.info("Skipping simple test PCAP generation as --skip-generate flag is set.")

        # Pipeline Step 2: Process PCAP files
        if not os.path.isdir(pcap_path):
            logger.error("Input directory not found: %s", pcap_path)
            sys.exit(1)

        try:
            pcap_files = [f for f in os.listdir(pcap_path) if f.lower().endswith(".pcap")]
            pcap_files.sort()
        except OSError as e:
            logger.error(f"Error listing files in directory {pcap_path}: {e}")
            sys.exit(1)

        if not pcap_files:
            logger.info(f"Sorry, no pcap files can be found under: {pcap_path}")
            if args.skip_generate:
                 logger.info("Note: No PCAP files found and generation was skipped. Please ensure PCAP files are in the input directory or remove --skip-generate.")
            return

        logger.info("")
        logger.info("PythonFlowMeter found: %d Files.", len(pcap_files))

        total_flows_processed_for_prediction_all_files = 0 # Track total across files

        for file in pcap_files:
            filepath = os.path.join(pcap_path, file)
            logger.info("")
            logger.info("")
            logger.info("Working on... %s", file)

            # Re-initialize FlowGenerator for each file in file mode (matching Java's behavior)
            # This ensures flow IDs are unique per file processed in a single run.
            # If you wanted continuous flows across files, the flow_gen should be initialized once before the loop.
            # Sticking to per-file initialization for closer Java behavior translation.
            # --- Pass loaded model, encoder, features, scaler, and the queue to FlowGenerator for each file ---
            flow_gen = FlowGenerator(
                bidirectional=True,
                flow_timeout_micros=ACTIVE_TIMEOUT_MICROS,
                activity_timeout_micros=IDLE_TIMEOUT_MICROS,
                loaded_model=loaded_model, # Pass the loaded model
                loaded_label_encoder=loaded_label_encoder, # Pass the loaded label encoder
                selected_features=selected_features,
                loaded_scaler=loaded_scaler, # Pass the loaded scaler
                prediction_queue=prediction_queue # Pass the prediction queue
            )
            logger.debug("FlowGenerator initialized for file processing...")
            # -------------------------------------------------------------------------


            first_packet_timestamp_micros = None
            last_packet_timestamp_micros = None
            discarded_packet_count = 0
            packet_counter_this_file = 0 # Counter for packets processed in this file

            start_time_script_sec = time.time()

            packets = []
            total_scapy_packets = 0

            try:
                try:
                    packets = rdpcap(filepath)
                    total_scapy_packets = len(packets)
                    logger.info(f"Read {total_scapy_packets} packets from {file}")
                except Exception as e:
                     logger.error(f"Error reading PCAP file {filepath}: {e}")
                     continue

                for i, packet in enumerate(packets):
                    try:
                        flow_gen.addPacket(packet)
                        packet_counter_this_file += 1 # Increment packet counter

                        if hasattr(packet, 'time'):
                             packet_timestamp_micros = int(packet.time * 1_000_000)
                             if first_packet_timestamp_micros is None or packet_timestamp_micros < first_packet_timestamp_micros:
                                 first_packet_timestamp_micros = packet_timestamp_micros
                             if last_packet_timestamp_micros is None or packet_timestamp_micros > last_packet_timestamp_micros:
                                 last_packet_timestamp_micros = packet_timestamp_micros
                        else:
                             logger.warning(f"Packet {i+1} in {file} has no timestamp attribute. Skipping time tracking for this packet.")

                        # --- Periodic Dump and Send ---
                        # Check if it's time to dump/send based on the interval
                        # Only dump/send if a dashboard URL is provided
                        if DASHBOARD_URL and dump_interval > 0 and packet_counter_this_file % dump_interval == 0:
                            logger.debug(f"Processed {packet_counter_this_file} packets. Performing periodic dump/send.")
                            # Use the timestamp of the current packet for closing flows
                            current_dump_timestamp = packet_timestamp_micros if packet_timestamp_micros is not None else int(time.time() * 1_000_000)
                            # Close flows that have timed out based on the current timestamp
                            flow_gen.close_all_flows(current_dump_timestamp) # This will move timed-out flows to finished_flows
                            # The flows moved to finished_flows will be processed and put into the queue
                            # by _close_flow and _process_and_send_flow methods within FlowGenerator.
                            # We don't need to call dump_labeled_flow_based_features here anymore
                            # for sending, as it's handled on flow close.
                            # We can still call it to process any flows that might have ended
                            # but weren't sent immediately due to errors, or for console output
                            # if no dashboard URL is set (though that case is handled by the sender check).
                            # Let's remove the explicit call here to avoid confusion, as _close_flow
                            # is now the primary trigger for sending.
                            pass # Remove the explicit call to dump_labeled_flow_based_features here
                        # -----------------------------


                    except Exception as e:
                         logger.error(f"Unhandled error processing packet {i+1}/{total_scapy_packets} in PCAP loop: {e}", exc_info=True)
                         discarded_packet_count += 1

                # --- Final Dump and Send after processing all packets in the file ---
                logger.info("Finished processing all packets in file. Performing final dump/send.")
                final_closing_timestamp = last_packet_timestamp_micros if last_packet_timestamp_micros is not None else int(time.time() * 1_000_000)
                flow_gen.close_all_flows(final_closing_timestamp) # Close any remaining active flows

                # --- Call dump_labeled_flow_based_features to process any remaining finished flows ---
                # This will process any flows that were added to finished_flows but not sent
                # immediately (e.g., if DASHBOARD_URL was empty or errors occurred).
                # If DASHBOARD_URL is set and immediate sending worked, this list should be empty.
                total_flows_processed_for_prediction_this_file = flow_gen.dump_labeled_flow_based_features(
                    out_path,
                    file.replace(".pcap", "") + "_PythonFeatures.json", # Use a final filename
                    FlowFeature.get_header()
                )
                total_flows_processed_for_prediction_all_files += total_flows_processed_for_prediction_this_file
                print(f"Completed prediction for {total_flows_processed_for_prediction_this_file} flows for file {file} (final batch).")


            except Exception as e:
                logger.error(f"An unhandled error occurred during processing of file {file}", exc_info=True)

            end_time_script_sec = time.time()
            logger.info("Done! processing file %s in %.2f seconds", file, (end_time_script_sec - start_time_script_sec))
            logger.info("\t Total packets read by scapy: %d", total_scapy_packets)
            logger.info("\t Packets causing errors or filtered by addPacket: %d", discarded_packet_count)

            if first_packet_timestamp_micros is not None and last_packet_timestamp_micros is not None:
                 pcap_duration_micros = last_packet_timestamp_micros - first_packet_timestamp_micros
                 if pcap_duration_micros >= 0:
                      logger.info("PCAP duration %.6f seconds", pcap_duration_micros / 1_000_000.0)
                 else:
                      logger.warning("Calculated negative PCAP duration. Timestamps might be inconsistent.")
                      logger.info("PCAP duration: N/A")
            else:
                 logger.info("PCAP duration: N/A (no packets read or processed)")

            logger.info("----------------------------------------------------------------------------")


        print("\n\n----------------------------------------------------------------------------")
        print(f"TOTAL FLOWS PROCESSED FOR PREDICTION ACROSS ALL FILES (packet count > 1): {total_flows_processed_for_prediction_all_files}")
        print("----------------------------------------------------------------------------\n")


    # --- Graceful Shutdown for the Sender Thread ---
    # Put a sentinel value (None) into the queue to signal the worker to stop
    if DASHBOARD_URL: # Only put sentinel if sender thread was started
        logger.info("Putting sentinel value in prediction queue.")
        prediction_queue.put(None)
        # Wait for the sender thread to finish processing remaining items and the sentinel
        logger.info("Waiting for asynchronous sender thread to finish...")
        sender_thread.join()
        logger.info("Asynchronous sender thread finished.")
    # ---------------------------------------------


if __name__ == "__main__":
    main()
