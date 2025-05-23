import socket
import sys

# Weak cipher indicators (esempi comuni)
weak_kex = ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1']
weak_ciphers = ['3des-cbc', 'aes128-cbc', 'aes256-cbc', 'arcfour']
weak_macs = ['hmac-md5', 'hmac-sha1']

def analyze_banner(banner):
    print(f"\n[+] Banner: {banner.strip()}")
    if b"OpenSSH" in banner:
        version = banner.decode(errors="ignore").split("-")[-1]
        print(f"[*] Detected OpenSSH version: {version}")
        major = version.split("p")[0]
        if float(major) < 8.2:
            print("[!] Vulnerable version: consider CVEs for OpenSSH < 8.2")
    else:
        print("[!] Non-OpenSSH server or malformed banner")

def scan_ssh(ip, port):
    try:
        sock = socket.create_connection((ip, int(port)), timeout=5)
        banner = sock.recv(1024)
        analyze_banner(banner)
        sock.close()
    except Exception as e:
        print(f"[x] {ip}:{port} - Connection failed: {e}")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} targets.txt")
        return

    with open(sys.argv[1], "r") as f:
        for line in f:
            if ":" in line:
                ip, port = line.strip().split(":")
                print(f"\n== Scanning {ip}:{port} ==")
                scan_ssh(ip, port)

if __name__ == "__main__":
    main()
