#Network Security Scan

#Nmap on every new connection: It scans new devices joining the network.
#Nessus every hour: A separate thread runs Nessus scans hourly.
#Tshark on network spikes: It captures traffic when network usage spikes above 20% of the baseline.
#Snort on attack attempts: A Snort callback listens for suspicious packets.
#Daily reports: A thread compiles all findings into a daily report.
