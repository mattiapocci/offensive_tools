import os
import csv
import re

LOG_DIR = "sslscan_logs"
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
            content = f.readlines()
    except Exception as e:
        print(f"[!] Errore leggendo {filepath}: {e}")
        return info

    for line in content:
        line = line.strip()

        # Protocols enabled
        if "Accepted" in line:
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

        # Weak RSA Key Strength from certificate block
        if "RSA Key Strength:" in line:
            match = re.search(r'RSA Key Strength:\s+(\d+)', line)
            if match and int(match.group(1)) < 2048:
                info["Weak_RSA_Key"] = "Yes"

        # Backup: check for RSA keySize= pattern
        if "keySize" in line and "RSA" in line:
            match = re.search(r'keySize=(\d+)', line)
            if match and int(match.group(1)) < 2048:
                info["Weak_RSA_Key"] = "Yes"

        # Weak key exchange with DHE/RSA and low key sizes
        if "TLS_DHE" in line or "TLS_RSA" in line:
            if any(x in line for x in ["Accepted", "keySize=1024", "keySize=768"]):
                info["Weak_TLS_Key_Exchange"] = "Yes"

        # Weak elliptic curves key exchange (<256 bits)
        ecc_match = re.search(r'TLSv\d\.\d\s+(\d+)\s+bits', line)
        if ecc_match:
            bits = int(ecc_match.group(1))
            if bits < 256:
                info["Weak_TLS_Key_Exchange"] = "Yes"

    return info

def generate_csv():
    rows = []

    for filename in os.listdir(LOG_DIR):
        if filename.endswith(".txt"):
            try:
                parts = filename.replace(".txt", "").split("_")
                ip = ".".join(parts[:4])
                port = parts[4]
            except IndexError:
                print(f"[!] Nome file non conforme: {filename}")
                continue

            filepath = os.path.join(LOG_DIR, filename)
            info = parse_sslscan_output(filepath)
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

    print(f"[+] Report saved to {CSV_FILE}")

if __name__ == "__main__":
    generate_csv()
