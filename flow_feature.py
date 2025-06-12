# flow_feature.py

import logging
# Removed the import for 'enum' as the class will no longer inherit from it.
# import enum

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Set logger level to INFO

# This class is primarily used to define the header for the flow features.
# In Java, this might be an enum or a class with static methods.
# We'll use a class with a static method to get the header string.

# Removed (enum.Enum) inheritance
class FlowFeature:
    # Define the header string for the 85 features.
    # This must exactly match the order and names used in BasicFlow.dumpFlowBasedFeaturesEx
    # and the features expected by your trained model (after selecting the 36).
    # Removed spaces after commas to fix the KeyError during feature selection.
    _header = (
        "Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol,Timestamp,"
        "Flow Duration,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,"
        "Total Length of Bwd Packets,Fwd Packet Length Max,Fwd Packet Length Min,"
        "Fwd Packet Length Mean,Fwd Packet Length Std,Bwd Packet Length Max,Bwd Packet Length Min,"
        "Bwd Packet Length Mean,Bwd Packet Length Std,Flow Bytes/s,Flow Packets/s,Flow IAT Mean,"
        "Flow IAT Std,Flow IAT Max,Flow IAT Min,Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std,"
        "Fwd IAT Max,Fwd IAT Min,Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,"
        "Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,Fwd Header Length,"
        "Bwd Header Length,Fwd Packets/s,Bwd Packets/s,Min Packet Length,Max Packet Length,"
        "Packet Length Mean,Packet Length Std,Packet Length Variance,FIN Flag Count,SYN Flag Count,"
        "RST Flag Count,PSH Flag Count,ACK Flag Count,URG Flag Count,CWR Flag Count,ECE Flag Count,"
        "Down/Up Ratio,Average Packet Size,Avg Fwd Segment Size,Avg Bwd Segment Size,"
        "Fwd Header Length.1,Fwd Avg Bytes/Bulk,Fwd Avg Packets/Bulk,Fwd Avg Bulk Rate," # Note: Fwd Header Length.1 is a duplicate in the original CICFlowMeter features
        "Bwd Avg Bytes/Bulk,Bwd Avg Packets/Bulk,Bwd Avg Bulk Rate,Subflow Fwd Packets,"
        "Subflow Fwd Bytes,Subflow Bwd Packets,Subflow Bwd Bytes,Init_Win_bytes_forward,"
        "Init_Win_bytes_backward,act_data_pkt_fwd,min_seg_size_forward,Active Mean,Active Std,"
        "Active Max,Active Min,Idle Mean,Idle Std,Idle Max,Idle Min,Label" # Added 'Label'
    )

    @staticmethod
    def get_header() -> str:
        """Returns the comma-separated string of all 85 feature headers."""
        # Log the header length for debugging
        header_list = FlowFeature._header.split(',')
        logger.debug(f"FlowFeature.get_header() returning {len(header_list)} headers.")
        return FlowFeature._header

    # You could potentially add methods here to get subsets of features
    # or other feature-related utility functions if needed in the future.

