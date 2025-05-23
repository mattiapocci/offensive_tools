import socket
import sys

def ping_rmi(ip, port):
    try:
        s = socket.create_connection((ip, port), timeout=5)
        print(f"[+] Connessione RMI aperta su {ip}:{port}")
        s.send(b'\x4a\x52\x4d\x49\x00\x01\x00\x00')  # JRMI protocol header
        resp = s.recv(4)
        if resp.startswith(b'\x4e\x00'):
            print("[+] RMI response valida.")
        else:
            print(f"[-] Risposta RMI inattesa: {resp}")
        s.close()
    except Exception as e:
        print(f"[-] Errore su {ip}:{port} - {e}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <IP> <PORT>")
        sys.exit(1)
    ping_rmi(sys.argv[1], int(sys.argv[2]))
