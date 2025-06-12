from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import time
from collections import defaultdict # Import defaultdict for easy counting

app = Flask(__name__)
# Allow CORS for all origins, useful for development.
# In production, you might want to restrict this to specific origins.
CORS(app)

# In-memory storage for received predictions
# We'll keep this simple for now. For a production system, consider a database.
# Store predictions with a timestamp for potential time-based visualizations later
# Structure: [{"flow_id": "...", "predicted_label": "...", "probability": ..., "timestamp": ..., "src_ip": "...", "src_port": ..., "dst_ip": "...", "dst_port": ..., "protocol": ..., "packet_count": ...}, ...]
predictions = []

# --- Store aggregated data for visualizations ---
# Using defaultdict makes it easy to increment counts
label_counts = defaultdict(int)
protocol_counts = defaultdict(int) # Still store by number internally
total_flows_predicted = 0
# --------------------------------------------------

# --- New: Mapping for protocol numbers to names ---
PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    # Add other common protocols if needed
    # You might need to capture more protocols or check your dataset for others
}
# -------------------------------------------------


@app.route('/')
def index():
    """Renders the main dashboard HTML page."""
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def receive_prediction():
    """Receives prediction data from flowmeter.py."""
    if request.is_json:
        prediction_data = request.get_json()
        # Add a server-side timestamp for consistency, or use the one from flowmeter.py
        # prediction_data['server_timestamp'] = int(time.time() * 1000) # Milliseconds

        # Append the received data to our in-memory list
        # We are storing the full prediction_data dictionary now
        predictions.append(prediction_data)

        # --- Update aggregated counts ---
        global total_flows_predicted
        total_flows_predicted += 1
        label = prediction_data.get('predicted_label', 'Unknown')
        # Store protocol count by number first, then map for visualization
        protocol_num = prediction_data.get('protocol', 'Unknown')

        label_counts[label] += 1
        protocol_counts[protocol_num] += 1 # Store count by number
        # -----------------------------------

        print(f"Received prediction: {prediction_data}") # Log received data
        return jsonify({"status": "success", "message": "Prediction received"}), 200
    else:
        return jsonify({"status": "error", "message": "Request must be JSON"}), 415 # Unsupported Media Type

@app.route('/data', methods=['GET'])
def get_predictions():
    """Returns the list of received predictions."""
    # For simplicity, return all predictions.
    # In a real app, you might want to return only the latest N predictions or filter by time.
    return jsonify(predictions), 200

# --- Endpoint to provide data for visualizations ---
@app.route('/viz_data', methods=['GET'])
def get_viz_data():
    """
    Returns aggregated data for dashboard visualizations, with protocol names mapped.
    """
    # --- New: Map protocol numbers to names for the counts ---
    protocol_counts_mapped = {
        PROTOCOL_NAMES.get(num, f"Protocol {num}"): count # Use name if in map, else use "Protocol X"
        for num, count in protocol_counts.items()
    }
    # ------------------------------------------------------

    # Convert defaultdicts to regular dicts for JSON serialization
    viz_data = {
        "label_counts": dict(label_counts),
        "protocol_counts": protocol_counts_mapped, # Use the mapped counts
        "total_flows": total_flows_predicted
        # Add other aggregated data here as needed for future visualizations
    }
    return jsonify(viz_data), 200

# --- New: Endpoint to get details for a specific flow ---
@app.route('/flow_details/<flow_id>', methods=['GET'])
def get_flow_details(flow_id):
    """
    Returns the prediction data for a specific flow ID.
    """
    # Find the prediction with the matching flow_id
    # Iterate through the predictions list to find the flow
    # Note: For large numbers of flows, a dictionary lookup would be faster
    # if predictions were stored in a dict keyed by flow_id.
    found_flow = None
    for pred in predictions:
        if pred.get('flow_id') == flow_id:
            found_flow = pred
            break # Found the flow, exit loop

    if found_flow:
        # Map protocol number to name for the details view as well
        protocol_num = found_flow.get('protocol', 'Unknown')
        found_flow['protocol_name'] = PROTOCOL_NAMES.get(protocol_num, f"Protocol {protocol_num}")

        return jsonify(found_flow), 200
    else:
        return jsonify({"status": "error", "message": f"Flow with ID {flow_id} not found."}), 404 # Not Found
# -----------------------------------------------------


if __name__ == '__main__':
    # Use debug=True for development. Disable in production.
    # host='0.0.0.0' makes the server accessible externally (use with caution)
    # port=5000 is the default Flask port
    app.run(debug=True, host='127.0.0.1', port=5000)
