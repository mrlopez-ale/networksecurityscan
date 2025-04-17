import os
import subprocess
import json
import time
import threading

# CONFIGURATION
TARGET_IP = "192.168.1.1/24"  # Change to the appropriate network range
NESSUS_URL = "https://localhost:8834"  # Nessus API URL
NESSUS_API_KEY = "your_api_key_here"  # Replace with your API key
SNORT_RULES_PATH = "/etc/snort/rules"  # Adjust Snort rules path if needed
OUTPUT_DIR = "./security_reports"
NMAP_SCAN_INTERVAL = 10  # Seconds to check for new connections
NESSUS_SCAN_INTERVAL = 3600  # Run Nessus every hour
TRAFFIC_SPIKE_THRESHOLD = 1.2  # 20% increase in network usage triggers Tshark

def run_nmap_scan(target_ip):
    print("[+] Running Nmap scan...")
    nmap_output_file = os.path.join(OUTPUT_DIR, "nmap_scan.txt")
    command = f"nmap -O -sV -Pn -p- {target_ip} -oN {nmap_output_file}"
    subprocess.run(command, shell=True, check=True)
    print(f"[+] Nmap scan complete. Results saved in {nmap_output_file}")

def run_nessus_scan():
    print("[+] Running Nessus vulnerability scan...")
    nessus_report = os.path.join(OUTPUT_DIR, "nessus_report.json")
    command = f"curl -k -H 'X-ApiKeys: accessKey={NESSUS_API_KEY}' {NESSUS_URL}/scans > {nessus_report}"
    subprocess.run(command, shell=True, check=True)
    print(f"[+] Nessus scan results saved in {nessus_report}")

def capture_traffic(interface="eth0"):
    print("[+] Capturing network traffic with Tshark...")
    pcap_file = os.path.join(OUTPUT_DIR, "network_traffic.pcap")
    command = f"tshark -i {interface} -a duration:60 -w {pcap_file}"
    subprocess.run(command, shell=True, check=True)
    print(f"[+] Network traffic capture complete. File saved as {pcap_file}")

def analyze_with_snort():
    print("[+] Running Snort for intrusion detection...")
    pcap_file = os.path.join(OUTPUT_DIR, "network_traffic.pcap")
    snort_output_file = os.path.join(OUTPUT_DIR, "snort_alerts.txt")
    command = f"snort -r {pcap_file} -c {SNORT_RULES_PATH}/snort.conf -A full > {snort_output_file}"
    subprocess.run(command, shell=True, check=True)
    print(f"[+] Snort analysis complete. Alerts saved in {snort_output_file}")

def monitor_connections():
    seen_ips = set()
    while True:
        active_ips = subprocess.getoutput("arp -a | awk '{print $2}' | tr -d '()'").split('\n')
        for ip in active_ips:
            if ip not in seen_ips:
                seen_ips.add(ip)
                run_nmap_scan(ip)
        time.sleep(NMAP_SCAN_INTERVAL)

def monitor_network_usage(interface="eth0"):
    baseline_usage = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
    while True:
        time.sleep(10)
        current_usage = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
        if current_usage > baseline_usage * TRAFFIC_SPIKE_THRESHOLD:
            print("[!] Network usage spike detected, capturing traffic...")
            capture_traffic(interface)
            baseline_usage = current_usage

def monitor_snort_alerts():
    def snort_callback(pkt):
        print("[!] Potential attack detected, running Snort...")
        analyze_with_snort()
    sniff(filter="tcp", prn=snort_callback, store=0)

def run_nessus_periodically():
    while True:
        run_nessus_scan()
        time.sleep(NESSUS_SCAN_INTERVAL)

def generate_daily_report():
    while True:
        time.sleep(86400)  # Run once per day
        report_file = os.path.join(OUTPUT_DIR, "daily_report.txt")
        with open(report_file, "w") as f:
            f.write("Daily Security Report\n")
            f.write("=======================\n\n")
            for filename in os.listdir(OUTPUT_DIR):
                if filename.endswith(".txt") or filename.endswith(".json"):
                    with open(os.path.join(OUTPUT_DIR, filename), "r") as report:
                        f.write(f"Report: {filename}\n")
                        f.write(report.read() + "\n\n")
        print(f"[+] Daily report generated at {report_file}")

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    threading.Thread(target=monitor_connections, daemon=True).start()
    threading.Thread(target=monitor_network_usage, daemon=True).start()
    threading.Thread(target=monitor_snort_alerts, daemon=True).start()
    threading.Thread(target=run_nessus_periodically, daemon=True).start()
    threading.Thread(target=generate_daily_report, daemon=True).start()
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
