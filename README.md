# Network Security Monitor
**Source:** https://www.linkedin.com/in/mr-lopeza/

## 1. Overview

This Python script implements a multi-threaded network security monitoring system. It is designed to continuously monitor a specified network for potential security threats and vulnerabilities by integrating several key security tools:

* **Nmap:** Used for discovering new devices, performing port scans, and identifying operating systems on detected hosts.
* **Nessus:** Leveraged for running comprehensive vulnerability scans across the network.
* **Tshark (Wireshark):** Employed to capture network traffic for analysis.
* **Snort:** Utilized for intrusion detection by analyzing network traffic against a defined ruleset.
* **psutil & scapy:** Used for monitoring network bandwidth usage and detecting unusual traffic spikes.

The system aims to provide real-time monitoring by running these tasks concurrently and generates daily reports summarizing findings.

## 2. File Structure


.
├── network_security_monitor.py   # The main Python script
└── security_reports/             # (Auto-created) Directory for storing scan results, traffic captures, and reports


## 3. Modules Used

The script relies on the following standard and third-party Python modules:

* `os`: Operating system interactions (directory/file handling).
* `subprocess`: Running external command-line tools (Nmap, Nessus CLI, Tshark, Snort).
* `json`: Parsing JSON data (potentially from Nessus reports).
* `time`: Time-related functions (sleeping, scheduling).
* `threading`: Enabling concurrent execution of monitoring tasks.
* `psutil`: Accessing system details and process utilities (for network usage).
* `scapy.all`: Powerful packet manipulation library (for traffic sniffing).

## 4. Configuration

Key operational parameters are set via variables within the `network_security_monitor.py` script:

* `TARGET_IP` (str): The network range to monitor (e.g., `"192.168.1.1/24"`).
* `NESSUS_URL` (str): URL of the Nessus server (e.g., `"https://<nessus_server_ip>:8834"`).
* `NESSUS_API_KEY` (str): API credentials for Nessus authentication. **(See Security Considerations)**.
* `SNORT_RULES_PATH` (str): Filesystem path to the Snort rules file.
* `OUTPUT_DIR` (str): Directory path for saving reports and captures (default: `"./security_reports/"`).
* `NMAP_SCAN_INTERVAL` (int): Frequency (in seconds) for scanning newly detected IPs.
* `NESSUS_SCAN_INTERVAL` (int): Frequency (in seconds) for periodic Nessus scans (e.g., `86400` for daily).
* `TRAFFIC_SPIKE_THRESHOLD` (int): Network usage threshold (bytes/sec) that triggers traffic capture.

**Note:** You must edit these variables directly in the script before execution.

## 5. Core Functions

* `run_nmap_scan(target_ip)`: Executes an Nmap scan against a specific IP.
* `run_nessus_scan()`: Initiates a Nessus vulnerability scan.
* `capture_traffic(interface="eth0")`: Captures network packets using Tshark on the specified interface.
* `analyze_with_snort()`: Runs Snort to analyze previously captured traffic files.
* `monitor_connections()`: Uses `arp -a` to find new IPs on the network and triggers Nmap scans for them.
* `monitor_network_usage(interface="eth0")`: Tracks network bandwidth and triggers `capture_traffic` if `TRAFFIC_SPIKE_THRESHOLD` is exceeded.
* `monitor_snort_alerts()`: Monitors traffic in real-time and analyzes it with Snort.
* `run_nessus_periodically()`: Schedules and runs `run_nessus_scan` at the configured interval.
* `generate_daily_report()`: Consolidates outputs from various tools into a daily summary report.
* `main()`: Initializes the system, creates the output directory, starts all monitoring threads, and keeps the script running.

## 6. Security Considerations

**Please review these carefully before deploying:**

* **Nessus API Key Security:** The script stores the Nessus API key directly in the code (plain text). This is **highly insecure**. Use environment variables, a secure configuration file with restricted permissions, or a dedicated secrets management solution.
* **Root Privileges:** Running Nmap, Tshark, and Snort typically requires root/administrator privileges. Executing the entire script as root increases the security risk if the script itself is compromised. Evaluate if specific components can run with lower privileges.
* **Snort Ruleset:** The effectiveness of the intrusion detection component (Snort) is directly tied to the quality, relevance, and timeliness of the `SNORT_RULES_PATH`. Ensure rules are appropriate for your environment and regularly updated.
* **Error Handling:** The script relies on `subprocess.run(..., check=True)`, which halts the specific subprocess on failure. Implement more granular error handling, logging, and potentially alerting mechanisms for production use.
* **Resource Consumption:** Continuous scanning (Nmap, Nessus) and traffic capture (Tshark) can consume significant CPU, memory, disk I/O, and storage space. Monitor system resources and adjust `NMAP_SCAN_INTERVAL`, `NESSUS_SCAN_INTERVAL`, capture durations, and potentially Tshark filters to manage load.

## 7. Dependencies

Ensure the following are installed and accessible on the system where the script runs:

* **Python:** Version 3.x
* **Python Packages:**
    * `psutil`
    * `scapy`
    * Install via pip: `pip install psutil scapy`
* **External Tools:**
    * Nmap
    * Nessus (Scanner/Server accessible via `NESSUS_URL`)
    * Snort
    * Tshark (Command-line component of Wireshark)

Refer to the official documentation for each tool for installation and setup instructions.

## 8. Usage

1.  **Configure:** Modify the configuration variables at the top of `network_security_monitor.py` to match your environment and credentials. Pay special attention to securing the `NESSUS_API_KEY`.
2.  **Install Dependencies:** Ensure Python, required packages, and all external tools are installed.
3.  **Run:** Execute the script with sufficient privileges (likely root/sudo due to tool requirements):
    ```bash
    sudo python network_security_monitor.py
    ```
4.  **Monitor:** The script will start its monitoring threads and run continuously. Check the `OUTPUT_DIR` for reports and captured data. Stop the script with `Ctrl+C`.

## 9. Limitations

* **Detection Risk:** Active scanning techniques used by Nmap and Nessus can be detected by Intrusion Detection Systems (IDS) or Intrusion Prevention Systems (IPS) on the network, potentially triggering alerts.
* **Data Volume:** Capturing all network traffic without filters can rapidly consume large amounts of disk space. Consider implementing specific Tshark capture filters (`-f`) to target only relevant traffic.
* **Network Complexity:** The script's design may assume a simpler network structure. Adjustments might be necessary for environments with VLANs, complex routing, or multiple network segments.
* **Tool Dependency:** The script's functionality is entirely dependent on the correct installation, configuration, and availability of the external tools (Nmap, Nessus, Snort, Tshark). Errors in these tools will impact the monitor's operation.
