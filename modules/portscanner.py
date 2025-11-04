import tkinter as tk
from tkinter import ttk
import threading
import time
import concurrent.futures
import socket

class PortScanner(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.pack(fill="both", expand=True)
        ttk.Label(self, text="Host/IP:").pack(anchor="w")
        self.host = ttk.Entry(self)
        self.host.pack(fill="x", pady=(0, 10))
        ttk.Label(self, text="Ports (e.g. 22,80,8000-8010):").pack(anchor="w")
        self.ports = ttk.Entry(self)
        self.ports.pack(fill="x", pady=(0, 10))
        btn = ttk.Button(self, text="Start Scan",
                         command=self.run_scan).pack(pady=5)
        btn = ttk.Button(self, text="Start popular ports",
                         command=self.run_popular_scan).pack(pady=5)
        self.output = tk.Text(self, bg="#252526", fg="white", height=15)
        self.output.pack(fill="both", expand=True, pady=10)

    def log(self, msg):
        self.output.insert("end", msg + "\n")
        self.output.see("end")

    def run_popular_scan(self):
        ports = [20,21,22,23,25,53,67,68,69,80,110,123,137,139,143,161,162,389,443,445,465,514,587,636,873,993,995,1080,1194,1433,1521,1701,2049,2082,2083,2375,2376,2379,2380,3306,3389,3478,3690,5000,5001,5432,5900,5984,6379,6667,8000,8080,8443,8888,9000,9200,9300,11211,27017,28017,3000,3306,4444,50000,50010]
        self._run_scan(ports)

    def run_scan(self):
        ports = parse_ports(self.ports.get())
        self._run_scan(ports)

    def _run_scan(self, ports):
        host = self.host.get().strip()
        if not host or not ports:
            self.log("[!] Invalid input.")
            return
        self.log(f"Scanning {host} ({len(ports)} ports)...")
        threading.Thread(target=self._scan_thread, args=(
            host, ports), daemon=True).start()

    def _scan_thread(self, host, ports):
        open_ports = []
        start = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(scan_tcp, host, p, 1.0): p for p in ports}
            for fut in concurrent.futures.as_completed(futures):
                port, state = fut.result()
                if state == "open":
                    open_ports.append(port)
                    self.log(f"{host}:{port} open")
        elapsed = time.time() - start
        self.log(f"\nScan complete in {elapsed:.2f}s")
        self.log(f"Open ports: {open_ports if open_ports else 'None'}")

def parse_ports(ports_str):
    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-')
            a, b = int(a), int(b)
            for p in range(min(a, b), max(a, b) + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def scan_tcp(host, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return (port, 'open')
    except:
        s.close()
        return (port, 'closed')
