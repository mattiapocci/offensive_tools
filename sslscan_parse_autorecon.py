import os
import csv
import re

# Cartella principale dove si trovano i risultati generati da AutoRecon
RESULTS_DIR = "results"

# Nome del file CSV che verrà generato in output
CSV_FILE = "sslscan_summary.csv"

# Funzione che analizza il contenuto di un file di output di sslscan
def parse_sslscan_output(filepath):
    # Valori iniziali: tutto disabilitato o considerato sicuro
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

    # Parsing riga per riga del contenuto del file sslscan
    for line in lines:
        line = line.strip()

        # Se una riga contiene un protocollo accettato, lo segniamo come abilitato
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

        # Se è presente una chiave RSA debole (es. <2048 bit)
        if "keySize" in line and "RSA" in line:
            match = re.search(r'keySize=(\d+)', line)
            if match and int(match.group(1)) < 2048:
                info["Weak_RSA_Key"] = "Yes"

        # Se c'è un key exchange debole (es. DHE o RSA con keySize basso)
        if "TLS_DHE" in line or "TLS_RSA" in line:
            if any(x in line for x in ["Accepted", "keySize=1024", "keySize=768"]):
                info["Weak_TLS_Key_Exchange"] = "Yes"

    return info

# Funzione principale che scorre la struttura dei risultati e genera il CSV
def generate_csv():
    rows = []

    # Scorri ogni IP target nella cartella dei risultati
    for ip in os.listdir(RESULTS_DIR):
        ip_path = os.path.join(RESULTS_DIR, ip)
        scans_path = os.path.join(ip_path, "scans")

        if not os.path.isdir(scans_path):
            continue  # Salta se non esiste la cartella scans

        # Scorri ogni cartella "tcpPORT" (es. tcp443)
        for port_dir in os.listdir(scans_path):
            full_port_path = os.path.join(scans_path, port_dir)
            if not os.path.isdir(full_port_path) or not port_dir.startswith("tcp"):
                continue  # Salta se non è una cartella valida

            # Estrai la porta dal nome (es. tcp443 → 443)
            port = port_dir.replace("tcp", "")

            # Costruisci il nome atteso del file di output sslscan
            expected_filename = f"tcp_{port}_sslscan.html"
            sslscan_path = os.path.join(full_port_path, expected_filename)

            # Se il file esiste, analizzalo
            if os.path.exists(sslscan_path):
                info = parse_sslscan_output(sslscan_path)
                row = {
                    "IP": ip,
                    "Port": port,
                    **info  # Espande il dizionario info come colonne CSV
                }
                rows.append(row)

    # Scrivi tutti i risultati in un file CSV
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["IP", "Port", "Weak_RSA_Key", "Weak_TLS_Key_Exchange",
                      "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Report salvato in {CSV_FILE}")

# Avvia lo script
if __name__ == "__main__":
    generate_csv()
