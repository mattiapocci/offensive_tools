import os
import csv
import re

RESULTS_DIR = "results"
CSV_FILE = "sslscan_summary.csv"

def parse_sslscan_output(filepath):
    info = {
        "Weak_RSA_Key": "No",
        "Weak_TLS_Key_Exchange": "No",
        "SSLv3": "No",
        "TLSv1.0": "No",
        "TLSv1.1": "No",
        "TLSv1.2": "No",
        "TLSv1.3": "No"
    }

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[!] Errore leggendo {filepath}: {e}")
        return info

    for line in lines:
        line = line.strip()

        # Protocol versions enabled
        if line.startswith("Accepted"):
            if "SSLv3" in line:
                info["SSLv3"] = "Yes"
            elif "TLSv1.0" in line:
                info["TLSv1.0"] = "Yes"
            elif "TLSv1.1" in line:
                info["TLSv1.1"] = "Yes"
            elif "TLSv1.2" in line:
                info["TLSv1.2"] = "Yes"
            elif "TLSv1.3" in line:
                info["TLSv1.3"] = "Yes"

        # Weak RSA Key Strength from certificate
        if "RSA Key Strength:" in line:
            match = re.search(r'RSA Key Strength:\s+(\d+)', line)
            if match and int(match.group(1)) < 2048:
                info["Weak_RSA_Key"] = "Yes"

        # Backup: also detect weak RSA keys from keySize=
        if "keySize" in line and "RSA" in line:
            match = re.search(r'keySize=(\d+)', line)
            if match and int(match.group(1)) < 2048:
                info["Weak_RSA_Key"] = "Yes"

        # Weak key exchange: RSA or DHE
        if "TLS_DHE" in line or "TLS_RSA" in line:
            if any(x in line for x in ["Accepted", "keySize=1024", "keySize=768"]):
                info["Weak_TLS_Key_Exchange"] = "Yes"

        # Weak elliptic curves (ECC) < 256 bits
        ecc_match = re.search(r'TLSv\d\.\d\s+(\d+)\s+bits', line)
        if ecc_match:
            bits = int(ecc_match.group(1))
            if bits < 256:
                info["Weak_TLS_Key_Exchange"] = "Yes"

    return info

def generate_csv():
    rows = []

    for ip in os.listdir(RESULTS_DIR):
        ip_path = os.path.join(RESULTS_DIR, ip)
        scans_path = os.path.join(ip_path, "scans")

        if not os.path.isdir(scans_path):
            continue

        for port_dir in os.listdir(scans_path):
            full_port_path = os.path.join(scans_path, port_dir)
            if not os.path.isdir(full_port_path) or not port_dir.startswith("tcp"):
                continue

            port = port_dir.replace("tcp", "")
            expected_filename = f"tcp_{port}_sslscan.html"
            sslscan_path = os.path.join(full_port_path, expected_filename)

            if os.path.exists(sslscan_path):
                info = parse_sslscan_output(sslscan_path)
                row = {
                    "IP": ip,
                    "Port": port,
                    **info
                }
                rows.append(row)

    with open(CSV_FILE, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["IP", "Port", "Weak_RSA_Key", "Weak_TLS_Key_Exchange",
                      "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Report salvato in {CSV_FILE}")

if __name__ == "__main__":
    generate_csv()
