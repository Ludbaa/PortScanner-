import socket
import termcolor
import sys
import time


def scan(target, ports):
    print(f"[*] Memindai target: {target}")
    for port in range(1, ports + 1):
        scan_port(target, port)
        time.sleep(0.1)


def scan_port(ipaddress, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ipaddress, port))
            if result == 0:
                print(termcolor.colored(f"[+] Port {port} TERBUKA", "green"))
            else:
                print(termcolor.colored(f"[-] Port {port} TERTUTUP", "red"))
    except socket.error as e:
        print(termcolor.colored(f"[!] Kesalahan socket: {e}", "yellow"))


def main():
    targets = input("[*] Masukkan IP target (pisahkan dengan koma): ").strip()
    if not targets:
        print("[!] Tidak ada target yang diberikan.")
        sys.exit(1)

    try:
        ports = int(input("[*] Masukkan jumlah port yang ingin dipindai: ").strip())
        if ports <= 0:
            raise ValueError("Jumlah port harus lebih dari 0.")
    except ValueError as ve:
        print(f"[!] Input tidak valid untuk jumlah port: {ve}")
        sys.exit(1)

    if "," in targets:
        print("[*] Memindai beberapa target.")
        for ip_addr in targets.split(","):
            ip_addr = ip_addr.strip()
            if ip_addr:
                scan(ip_addr, ports)
    else:
        scan(targets, ports)


if __name__ == "__main__":
    main()
