"""
modules/verbose_error.py


"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import requests
import time


ERROR_PAYLOADS = [
    "'", "\"", "%'", "' OR", "' AND", "' UNION", "')", "\" )"
]


class VerboseErrorScanner:
    def __init__(self, log_callback):
        self.log = log_callback
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "AttackGUI-VerboseErrorScanner"
        })
        self.vulnerable = False

    def scan(self, base_url: str):
        target = base_url.rstrip("/") + "/search"
        self.log(f"[*] Target endpoint: {target}")

        for payload in ERROR_PAYLOADS:
            self.log(f"[*] Testing payload: {payload}")

            try:
                response = self.session.post(
                    target,
                    data={"searched": payload},
                    timeout=10
                )

                text = response.text.lower()

                if self._is_error_leaked(text):
                    self.vulnerable = True
                    self.log("[!] VULNERABLE – SQL error disclosed")
                    self.log(f"[!] Payload: {payload}")
                    self.log("[!] Server response contains SQL error")
                    return

                self.log("[+] No SQL error detected")

            except requests.RequestException as e:
                self.log(f"[-] Request failed: {str(e)}")

            time.sleep(0.2)

        self.log("[+] Scan finished – No verbose SQL errors detected")

    def _is_error_leaked(self, text: str) -> bool:
        keywords = [
            "sql error",
            "syntax error",
            "sqlite",
            "mysql",
            "psql",
            "near",
            "unterminated",
            "odbc",
            "query failed"
        ]
        return any(k in text for k in keywords)


class VerboseErrorModule(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.pack(fill="both", expand=True)

        self.scanner = None
        self.scan_thread = None

        self.build_ui()

    def build_ui(self):
        title = tk.Label(
            self,
            text="Verbose Error Disclosure Scanner – OWASP A05",
            bg="#1e1e1e",
            fg="white",
            font=("Arial", 14, "bold")
        )
        title.pack(anchor="w", pady=5)

        desc = tk.Label(
            self,
            text=(
                "Scans a web application for SQL error leakage.\n"
                "Target must be the base URL of the vulnerable site (example: http://127.0.0.1:3000)"
            ),
            bg="#1e1e1e",
            fg="white",
            justify="left"
        )
        desc.pack(anchor="w", pady=5)

        config = tk.Frame(self, bg="#1e1e1e")
        config.pack(fill="x", pady=5)

        ttk.Label(config, text="Target URL:").pack(side="left", padx=5)
        self.url_entry = ttk.Entry(config, width=50)
        self.url_entry.insert(0, "http://127.0.0.1:3000")
        self.url_entry.pack(side="left", padx=5)

        ttk.Button(config, text="Start Scan", command=self.start_scan).pack(side="left", padx=10)

        self.output = scrolledtext.ScrolledText(
            self,
            height=20,
            bg="#121212",
            fg="white"
        )
        self.output.pack(fill="both", expand=True, pady=10)

    def log(self, msg):
        self.output.insert(tk.END, msg + "\n")
        self.output.see(tk.END)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            self.log("[!] Please enter a target URL")
            return

        if not url.startswith("http"):
            url = "http://" + url

        self.output.delete(1.0, tk.END)
        self.log("[+] Starting Verbose Error scan")
        self.log(f"[*] Target: {url}")
        self.log("=" * 60)

        self.scanner = VerboseErrorScanner(self.log)
        self.scan_thread = threading.Thread(
            target=self.scanner.scan,
            args=(url,),
            daemon=True
        )
        self.scan_thread.start()
