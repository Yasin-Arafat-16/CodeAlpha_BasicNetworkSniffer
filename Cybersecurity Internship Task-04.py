import os
os.environ["SCAPY_CACHE"] = "0"
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
from collections import defaultdict

# ------------------------------
# ১. কনফিগারেশন এবং সেটিংস
# ------------------------------
PORT_SCAN_THRESHOLD = 15
SYN_FLOOD_THRESHOLD = 20
TIME_WINDOW = 10
LOG_FILE = "nids_alerts.log"

# ট্র্যাকিং ভেরিয়েবল
ip_activity = defaultdict(list)
syn_activity = defaultdict(int)

# ------------------------------
# ২. ডিসপ্লে এবং লগিং ফাংশন
# ------------------------------
def print_header():
    print("-" * 135)
    print(f"{'Time':<10} | {'Protocol':<8} | {'Source IP':<18} | {'Type':<20} | {'Severity':<10} | {'Detailed Message'}")
    print("-" * 135)

def log_alert(ip, attack_type, severity, message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # কনসোলে সুন্দরভাবে দেখানো (Color coding manually simulated)
    print(f"{timestamp:<10} | {'ALERT':<8} | {ip:<18} | {attack_type:<20} | {severity:<10} | {message}")
    
    # ফাইলে সেভ করা
    with open(LOG_FILE, "a") as f:
        f.write(f"[{log_time}] SEVERITY:{severity} | TYPE:{attack_type} | SRC:{ip} | MSG:{message}\n")

# ------------------------------
# ৩. ডিটেকশন লজিক (Detection Rules)
# ------------------------------
def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        current_time = datetime.now().timestamp()

        # ক. SYN Flood Detection
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            syn_activity[src_ip] += 1
            if syn_activity[src_ip] >= SYN_FLOOD_THRESHOLD:
                log_alert(src_ip, "SYN Flood Attack", "HIGH", "Excessive SYN packets detected (Potential DoS)")
                syn_activity[src_ip] = 0

        # খ. Port Scanning Detection
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            ip_activity[src_ip].append((dst_port, current_time))
            # টাইম উইন্ডো ফিল্টার
            ip_activity[src_ip] = [(p, t) for p, t in ip_activity[src_ip] if current_time - t <= TIME_WINDOW]
            
            unique_ports = set(p for p, t in ip_activity[src_ip])
            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                log_alert(src_ip, "Port Scanning", "MEDIUM", f"Scanned {len(unique_ports)} unique ports in {TIME_WINDOW}s")
                ip_activity[src_ip].clear()

        # গ. Malicious Payload Detection
        if packet.haslayer(Raw):
            try:
                payload = str(packet[Raw].load).lower()
                malicious_keywords = ["admin", "passwd", "sql", "select", "drop", "eval"]
                for key in malicious_keywords:
                    if key in payload:
                        log_alert(src_ip, "Malicious Payload", "CRITICAL", f"Found suspicious keyword: '{key}'")
            except:
                pass

# ------------------------------
# ৪. মেইন ফাংশন
# ------------------------------
def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\n" + "="*50)
    print("      CODEALPHA PROFESSIONAL NIDS v3.0      ")
    print("="*50)
    print(f"[*] Monitoring Active... Logs saving to: {LOG_FILE}")
    print_header()

    try:
        # sniffing শুরু
        sniff(prn=analyze_packet, store=False, filter="ip")
    except KeyboardInterrupt:
        print("\n" + "="*50)
        print("  IDS STOPPED BY USER - CHECK LOG FILE FOR DETAILS  ")
        print("="*50)

if __name__ == "__main__":
    main()