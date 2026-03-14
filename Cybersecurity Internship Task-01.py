from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

# ১. টেবিলের হেডার প্রিন্ট করা
def print_header():
    print("-" * 125)
    print(f"{'Time':<10} | {'Protocol':<8} | {'Source IP':<18} | {'Destination IP':<18} | {'Port':<15} | {'Payload Summary'}")
    print("-" * 125)

# ২. ক্রেডেনশিয়াল ফিল্টার করার লজিক
def extract_credentials(payload):
    decoded_payload = str(payload).lower()
    patterns = ['user', 'uid', 'username', 'email', 'pass', 'pw', 'pwd']
    
    if any(p in decoded_payload for p in patterns) and "post" in decoded_payload:
        parts = decoded_payload.split('&')
        found = [part for part in parts if any(p in part for p in patterns)]
        if found:
            return " | ".join(found)
    return None

# ৩. মূল অ্যানালাইসিস ফাংশন (TCP, UDP ও অন্যান্য প্রোটোকলসহ)
def analyze_packet(packet):
    if IP in packet:
        timestamp = datetime.now().strftime('%H:%M:%S')
        ip_layer = packet[IP]
        
        # প্রোটোকল ও পোর্ট শনাক্তকরণ
        protocol = "Other"
        ports = "N/A"
        
        if packet.haslayer(TCP):
            protocol = "TCP"
            ports = f"{packet[TCP].sport} -> {packet[TCP].dport}"
        elif packet.haslayer(UDP):
            protocol = "UDP"
            ports = f"{packet[UDP].sport} -> {packet[UDP].dport}"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            ports = "Echo Req/Rep"

        payload_summary = ""
        if packet.haslayer(Raw):
            raw_payload = packet[Raw].load
            creds = extract_credentials(raw_payload)
            
            if creds:
                # হাইলাইট করা ক্রেডেনশিয়াল আউটপুট
                print(f"\n{'!'*125}")
                print(f"[!] {timestamp} - CRITICAL: LOGIN DATA DETECTED!")
                print(f"[!] CREDENTIALS: {creds}")
                print(f"{'!'*125}\n")
                payload_summary = f"*** LOGIN DATA FOUND ***"
            else:
                payload_summary = str(raw_payload)[:40].replace('\n', '') + "..."
        
        # টেবিল আকারে রো প্রিন্ট করা
        print(f"{timestamp:<10} | {protocol:<8} | {ip_layer.src:<18} | {ip_layer.dst:<18} | {ports:<15} | {payload_summary}")

def start_sniffing():
    print("\n" + "="*45 + " MULTI-PROTOCOL NETWORK SNIFFER " + "="*45)
    print_header()
    
    try:
        # ফিল্টার সরিয়ে দেওয়া হয়েছে যাতে সব প্রোটোকল দেখা যায়
        sniff(prn=analyze_packet, store=False)
    except KeyboardInterrupt:
        print("\n" + "-" * 125)
        print("Sniffing stopped by user.")

if __name__ == "__main__":
    start_sniffing()
