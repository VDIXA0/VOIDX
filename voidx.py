import socket
import threading
import requests
import whois
import platform
import scapy.all as scapy
import sys
import json
import time

# Tool Banner
def print_banner():
    banner = """
██    ██  ██████  ██████ ██████   ██   ██
██    ██ ██    ██   ██   ██   ██   ██ ██
 ██  ██  ██    ██   ██   ██   ██    ███
  ████   ██    ██   ██   ██   ██   ██ ██
   ██     ██████  ██████ ██████   ██   ██
        VOIDX - OSINT & Scanner
-----------------------------------------
    """
    print(banner)

# Function to get MAC Address (Requires sudo/root permissions)
def get_mac(ip):
    packet = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    final_packet = broadcast / packet
    result = scapy.srp(final_packet, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc if result else "Unknown"

# Function to identify possible attacks on open ports
def get_attack_vector(port):
    attack_vectors = {
        21: "FTP Bruteforce, Anonymous Login",
        22: "SSH Bruteforce, Credential Stuffing",
        23: "Telnet Bruteforce, Sniffing",
        25: "SMTP Enumeration, Email Spoofing",
        53: "DNS Cache Poisoning, Amplification Attack",
        80: "XSS, SQL Injection, Directory Traversal",
        443: "MITM Attack, SSL Strip",
        3306: "MySQL Bruteforce, SQL Injection",
        3389: "RDP Bruteforce, BlueKeep Exploit"
    }
    return attack_vectors.get(port, "Unknown attack vector")

# OSINT Information Gathering
def gather_osint(target):
    print("\n[1] WHOIS Lookup:")
    try:
        domain_info = whois.whois(target)
        print(json.dumps({
            "Domain Name": domain_info.domain_name,
            "Registrar": domain_info.registrar,
            "Creation Year": domain_info.creation_date.year if domain_info.creation_date else "Unknown",
            "Expiration Date": domain_info.expiration_date,
            "Name Servers": domain_info.name_servers,
            "Status": domain_info.status,
            "Emails": domain_info.emails,
            "Organization": domain_info.org,
            "Country": domain_info.country
        }, indent=2, default=str))
    except:
        print("WHOIS information not found.")

    print("\n[2] DNS Lookup:")
    try:
        ip = socket.gethostbyname(target)
        print(f"IP Address: {ip}")
    except:
        print("Failed to retrieve IP.")
        return
    
    print("\n[3] Geolocation Lookup:")
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data.get("status") == "success":
            print(json.dumps(data, indent=2))
        else:
            print("Private IP detected. Geolocation data not available.")
    except:
        print("Failed to retrieve geolocation data.")

    print("\n[4] Device Information:")
    print(f"System: {platform.system()} {platform.release()}")
    print(f"Machine: {platform.machine()}")
    print(f"Processor: {platform.processor()}")
    
    if sys.platform.startswith("linux") and sys.argv[0].startswith("sudo"):
        print(f"MAC Address: {get_mac(ip)}")
    else:
        print("[!] Run the script with sudo to get MAC Address!")
    
    print("\nOSINT Information Gathering Completed!\n")

# Function to grab HTTP headers
def http_scan(target):
    print("\n[5] HTTP Headers:")
    try:
        response = requests.get(f"http://{target}", timeout=5)
        print(json.dumps(dict(response.headers), indent=2))
    except:
        print("Failed to retrieve HTTP headers.")

# Function to scan a port
def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            attack = get_attack_vector(port)
            print(f"[+] Port {port} is OPEN - Possible Attack: {attack}")
        else:
            print(f"[-] Port {port} is CLOSED or FILTERED")
        sock.close()
    except Exception as e:
        print(f"Error: {e}")

# User Input for IP or URL
def main():
    print_banner()

    while True:
        choice = input("\nEnter (1) for IP, (2) for URL, (3) Coming Soon, or (4) to Exit: ")

        if choice == "1":
            target = input("Enter IP Address: ")
        elif choice == "2":
            domain = input("Enter Domain (with or without https://): ").strip().replace("https://", "").replace("http://", "").split("/")[0]
            if "." not in domain:
                print("Invalid input! Enter only the domain name.")
                continue
            try:
                target = socket.gethostbyname(domain)
                print(f"Resolved {domain} to {target}")
            except:
                print("Invalid domain!")
                continue
        elif choice == "3":
            print("We will update this soon. We are working on Social Engineering & Brute Force features. Have fun with this code! See ya! 🚀")
            continue
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice!")
            continue

        gather_osint(target)
        http_scan(target)

        start_port = int(input("Enter starting port: "))
        end_port = int(input("Enter ending port: "))

        print("\nStarting Port Scan...\n")
        threads = [threading.Thread(target=scan_port, args=(target, port)) for port in range(start_port, end_port + 1)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        print("\nPort Scanning Completed!")

if __name__ == "__main__":
    main()
