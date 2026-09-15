# Local Network Scanner (Multi-Threaded)

A fast, concurrent local network scanner written in Python using the Scapy library. It sends ARP (Address Resolution Protocol) requests to a targeted subnet range to discover active hosts and map out IP and MAC address pairings on a local area network.

## Prerequisites
Because this tool builds custom raw network packets, it requires administrative/root privileges to run.

## Setup and Installation

1. Make sure Python is installed on your machine.
2. Install the necessary dependencies using the project requirements file:
   ```bash
   pip install -r requirements.txt
   ```

## How to Use

Run the script from your terminal using administrator privileges, and specify your target subnet using the `-t` or `--target` flag.

### Windows (Run Command Prompt / VS Code as Administrator)
```cmd
python scanner.py -t 192.168.1.1/24
```

### Linux / macOS
```bash
sudo python scanner.py -t 192.168.1.1/24
```

