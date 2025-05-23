import subprocess
import os
from datetime import datetime

INPUT_FILE = "targets.txt"
OUTPUT_DIR = "sslscan_logs"

def run_sslscan(target, output_file):
    try:
        print(f"[+] Scanning {target} ...")
        result = subprocess.run(
            ["sslscan", "--no-colour", target],
            capture_output=True,
            text=True,
            timeout=30
        )
        with open(output_file, "w") as f:
            f.write(result.stdout)
        print(f"[+] Output saved to {output_file}")
    except Exception as e:
        print(f"[!] Error scanning {target}: {e}")

def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    with open(INPUT_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            ip, port = line.split(":")
            target = f"{ip}:{port}"
            safe_name = f"{ip.replace('.', '_')}_{port}.txt"
            output_file = os.path.join(OUTPUT_DIR, safe_name)
            run_sslscan(target, output_file)

if __name__ == "__main__":
    main()
