
# 🔐 Real-Time Intrusion Detection System (IDS)

This project is a real-time **Intrusion Detection System** (IDS) that captures and analyzes live network traffic to detect suspicious activity using machine learning. It is built on top of a custom Python-based implementation of **CICFlowMeter**, and integrates a web-based dashboard to display detection results in real time.

## 🚀 Features

- ✅ Real-time network traffic monitoring
- 📦 Flow-based feature extraction (CICFlowMeter-style)
- 🤖 Machine learning model for intrusion detection
- 🌐 Web dashboard for visualization and alerts
- 🖥️ Supports live capture or PCAP file analysis

## 📁 Project Structure

```bash
├── flowmeter.py            # Core traffic sniffer and feature extractor
├── flow_feature.py         # Flow Feature for prediction
├── flow_generator.py       # Packet Flow generator
├── basic_flow.py           # Basic Data Flow Packet
├── constants.py            # Constants.py
├── app.py                  # Web dashboard for real-time predictions
├── generate_pcaps.py       # Simulated traffic generator (for testing)
├── list_interfaces.py      # Lists available network interfaces
├── packet_info.py          # Core packet information
├── utils.py                # Common Utils
├── data/
│   ├── in/                 # Input PCAP files for analysis
│   └── out/                # Extracted flow CSVs
├── models/                 # Saved ML models
├── static/                 # Static web assets
├── templates/              # HTML templates for dashboard
├── requirements.txt
└── README.md
```

## ⚙️ Installation

1. **Clone the repository:**

```bash
git clone https://github.com/AnkitV15/Python-CICFlowmeter.git
cd Intrusion-Detection-System
```

2.**Install dependencies:**

```bash
pip install -r requirements.txt
```

3.**Run with administrator privileges (for packet capture):**

```bash
sudo python flowmeter.py --interface INTERFACE
```

> 🔧 Replace `INTERFACE` with your actual network interface name. Use `python list_interfaces.py` to list available interfaces.

## 📡 Live Traffic Monitoring

To start real-time monitoring and feature extraction:

```bash
sudo python flowmeter.py --interface INTERFACE
```

This will capture live packets and save flow-based features to `data/out/`.

## 📂 Analyze PCAP Files

You can also analyze offline traffic using `.pcap` files:

```bash
sudo python flowmeter.py --pcap-path /path/to/pcaps
```

Output CSVs will be saved to `data/out/` (or use `--out-path` to change it).

## 🧠 Machine Learning IDS + Dashboard

The IDS uses a trained ML model to predict attacks based on extracted features. To launch the real-time prediction dashboard:

```bash
python app.py
```

Open your browser and go to:

```bash
http://localhost:5000
```

You’ll see:

- 📈 Live prediction updates
- 🛡️ Classification results (e.g., DoS, PortScan, Benign, etc.)
- 🔔 Alert system for threats

## 🧪 Simulate Traffic (Optional)

You can generate dummy `.pcap` files for testing:

```bash
python generate_pcaps.py
```

## 🛑 Stopping the System

Use `Ctrl + C` to safely stop any running script, especially during live sniffing.

## 💡 Notes

- Make sure you run the `flowmeter.py` script **before** launching `app.py`.
- Your ML model and scaler should be pre-trained and saved in the `models/` directory.
- Tested on Python 3.10+

## 📜 License

This project is open-source and licensed under the MIT License.

## 👤 Author

Developed by **[Ankit Vishwakarma](https://github.com/AnkitV15)**  
GitHub: [github.com/AnkitV15](https://github.com/AnkitV15)
