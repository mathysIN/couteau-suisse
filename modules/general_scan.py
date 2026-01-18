"""
modules/general_scan.py
General Scan Module - Orchestrates all attack modules sequentially

This module executes all available attacks in a predefined order,
displaying logs in its own terminal area without switching pages.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import socket
import concurrent.futures
from urllib.parse import urlparse

# Import backend classes from modules
from modules.xss_injection import XSSScanner, XSSPayloads
from modules.buffer_overflow import BoFScanner, BoFPayloads
from modules.path_traversal import PathTraversalScanner, PathTraversalPayloads
from modules.verbose_error import VerboseErrorScanner
from modules.scan_supply_chain import SupplyChainScanner
from modules.portscanner import scan_tcp, parse_ports
import requests


class GeneralScanModule(tk.Frame):
    """Module GUI for General Scan - orchestrates all attacks sequentially"""

    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.pack(fill="both", expand=True)

        self.scan_thread = None
        self.is_scanning = False
        self.stop_event = threading.Event()

        # UI Configuration
        config_frame = tk.Frame(self, bg="#1e1e1e")
        config_frame.pack(fill="x", pady=5)

        ttk.Label(config_frame, text="Target URL/Host:").grid(
            row=0, column=0, sticky="w", padx=5, pady=5)
        self.target_entry = ttk.Entry(config_frame, width=60)
        self.target_entry.insert(0, "http://localhost:3000")
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        config_frame.columnconfigure(1, weight=1)

        # Buttons
        button_frame = tk.Frame(self, bg="#1e1e1e")
        button_frame.pack(fill="x", pady=5)

        self.start_btn = ttk.Button(
            button_frame, text="Start General Scan", command=self.start_scan)
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = ttk.Button(
            button_frame, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        ttk.Button(button_frame, text="Clear Logs",
                   command=self.clear_output).pack(side="left", padx=5)

        # Output terminal area
        output_label = ttk.Label(self, text="Scan Log:")
        output_label.pack(anchor="w", pady=(10, 0))

        self.output = scrolledtext.ScrolledText(
            self, bg="#252526", fg="white", height=25, wrap=tk.WORD, font=("Courier", 9)
        )
        self.output.pack(fill="both", expand=True, pady=5)

        # Configure text tags for colored output
        self.output.tag_config("success", foreground="#51cf66")
        self.output.tag_config("error", foreground="#ff6b6b")
        self.output.tag_config("info", foreground="#4dabf7")
        self.output.tag_config("warning", foreground="#ffd43b")
        self.output.tag_config("vulnerable", foreground="#ff6b6b")

        self.log("=" * 70, "info")
        self.log("General Scan Module Ready", "info")
        self.log("This module will execute all attacks sequentially", "info")
        self.log("=" * 70, "info")

    def log(self, msg: str, tag: str = None) -> None:
        """Thread-safe logging to the output area"""
        def _log():
            self.output.insert("end", msg + "\n", tag)
            self.output.see("end")

        if threading.current_thread() != threading.main_thread():
            self.after(0, _log)
        else:
            _log()

    def clear_output(self) -> None:
        """Clear the output area"""
        self.output.delete(1.0, "end")

    def start_scan(self) -> None:
        """Start the general scan"""
        if self.is_scanning:
            return

        target = self.target_entry.get().strip()
        if not target:
            self.log("[!] Please enter a target URL or host", "error")
            return

        self.is_scanning = True
        self.stop_event.clear()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

        self.clear_output()
        self.log("=" * 70, "info")
        self.log("GENERAL SCAN INITIATED", "info")
        self.log("=" * 70, "info")
        self.log(f"Target: {target}", "info")
        self.log(f"Start Time: {time.strftime('%Y-%m-%d %H:%M:%S')}", "info")
        self.log("=" * 70, "info")
        self.log("", "info")

        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self._run_all_attacks,
            args=(target,),
            daemon=True
        )
        self.scan_thread.start()

    def stop_scan(self) -> None:
        """Stop the current scan"""
        self.stop_event.set()
        self.is_scanning = False
        self.log("\n[!] Scan stopped by user", "warning")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def _run_all_attacks(self, target: str) -> None:
        """Execute all attacks sequentially"""
        try:
            # Parse target to extract host and URL
            parsed = urlparse(target if target.startswith(('http://', 'https://')) else f"http://{target}")
            host = parsed.netloc.split(':')[0] if parsed.netloc else target.split(':')[0]
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else f"http://{target}"

            # Attack execution order (strict)
            attacks = [
                ("Port Scanner", self._run_port_scanner, host),
                ("Proxy Interception", self._run_proxy_interception, base_url),
                ("XSS Injection", self._run_xss_injection, base_url),
                ("HTTP Flood", self._run_http_flood, base_url),
                ("Buffer Overflow", self._run_buffer_overflow, base_url),
                ("Brute Force", self._run_brute_force, base_url),
                ("Directory Scanner", self._run_directory_scanner, base_url),
                ("Path Traversal", self._run_path_traversal, base_url),
                ("Verbose Error Disclosure", self._run_verbose_error, base_url),
                ("SQL Injection", self._run_sql_injection, base_url),
                ("Supply Chain Scan", self._run_supply_chain, base_url),
            ]

            total_attacks = len(attacks)
            for idx, (attack_name, attack_func, attack_target) in enumerate(attacks, 1):
                if self.stop_event.is_set():
                    break

                self.log("", "info")
                self.log("=" * 70, "info")
                self.log(f"[{idx}/{total_attacks}] {attack_name}", "info")
                self.log("=" * 70, "info")

                try:
                    attack_func(attack_target)
                    self.log(f"[+] {attack_name} completed", "success")
                except Exception as e:
                    self.log(f"[-] {attack_name} failed: {str(e)}", "error")
                    # Continue to next attack despite errors

                if idx < total_attacks:
                    self.log("", "info")
                    time.sleep(1)  # Brief pause between attacks

            # Final summary
            self.log("", "info")
            self.log("=" * 70, "info")
            if self.stop_event.is_set():
                self.log("GENERAL SCAN STOPPED", "warning")
            else:
                self.log("GENERAL SCAN COMPLETE", "success")
            self.log("=" * 70, "info")
            self.log(f"End Time: {time.strftime('%Y-%m-%d %H:%M:%S')}", "info")

        except Exception as e:
            self.log(f"[-] Critical error in general scan: {str(e)}", "error")
        finally:
            self.is_scanning = False
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")

    # ========================================================================
    # Individual Attack Implementations
    # ========================================================================

    def _run_port_scanner(self, host: str) -> None:
        """Execute Port Scanner attack"""
        try:
            self.log(f"[*] Scanning host: {host}", "info")
            # Popular ports to scan
            popular_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080]
            self.log(f"[*] Testing {len(popular_ports)} popular ports...", "info")

            open_ports = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(scan_tcp, host, port, 1.0): port for port in popular_ports}
                for future in concurrent.futures.as_completed(futures):
                    if self.stop_event.is_set():
                        break
                    port, state = future.result()
                    if state == "open":
                        open_ports.append(port)
                        self.log(f"[+] Port {port} is OPEN", "success")

            if open_ports:
                self.log(f"[+] Found {len(open_ports)} open ports: {open_ports}", "success")
            else:
                self.log("[*] No open ports found", "info")
        except Exception as e:
            self.log(f"[-] Port scanner error: {str(e)}", "error")

    def _run_proxy_interception(self, url: str) -> None:
        """Execute Proxy Interception (log-only mode)"""
        try:
            self.log("[*] Proxy Interception - Log-only mode", "info")
            self.log("[*] This attack requires mitmproxy and manual configuration", "info")
            self.log("[*] Executed in demonstration mode", "warning")
            self.log("[*] To use proxy interception:", "info")
            self.log("    1. Install mitmproxy: pip install mitmproxy", "info")
            self.log("    2. Configure browser to use proxy", "info")
            self.log("    3. Use the Proxy Interception module directly", "info")
        except Exception as e:
            self.log(f"[-] Proxy interception error: {str(e)}", "error")

    def _run_xss_injection(self, url: str) -> None:
        """Execute XSS Injection attack"""
        try:
            self.log(f"[*] Starting XSS scan on: {url}", "info")
            scanner = XSSScanner(self.log)
            payloads = XSSPayloads.get_basic_payloads()  # Use basic payloads for speed
            scanner.scan_url(url, payloads, test_forms=True)
            results = scanner.get_results()
            if results:
                self.log(f"[!] Found {len(results)} XSS vulnerabilities", "vulnerable")
            else:
                self.log("[+] No XSS vulnerabilities detected", "success")
        except Exception as e:
            self.log(f"[-] XSS injection error: {str(e)}", "error")

    def _run_http_flood(self, url: str) -> None:
        """Execute HTTP Flood attack"""
        try:
            self.log(f"[*] Starting HTTP Flood on: {url}", "info")
            self.log("[*] Sending limited requests (10 requests, 1 thread for demo)", "info")

            session = requests.Session()
            session.headers.update({'User-Agent': 'GeneralScan-HTTPFlood/1.0'})

            sent = 0
            success = 0
            failed = 0

            for i in range(10):  # Limited requests for general scan
                if self.stop_event.is_set():
                    break

                try:
                    response = session.get(url, timeout=5)
                    sent += 1
                    if response.status_code == 200:
                        success += 1
                    else:
                        failed += 1
                    if (i + 1) % 5 == 0:
                        self.log(f"[*] Sent {i+1}/10 requests...", "info")
                except requests.exceptions.RequestException:
                    sent += 1
                    failed += 1

            self.log(f"[+] HTTP Flood complete: {sent} sent, {success} success, {failed} failed", "info")
        except Exception as e:
            self.log(f"[-] HTTP Flood error: {str(e)}", "error")

    def _run_buffer_overflow(self, url: str) -> None:
        """Execute Buffer Overflow attack"""
        try:
            self.log(f"[*] Starting Buffer Overflow test on: {url}", "info")
            # Try to find a parameter to test
            test_url = url if '?' in url else f"{url}?param=test"
            scanner = BoFScanner(self.log)
            scanner.attack_url(test_url, "param")
        except Exception as e:
            self.log(f"[-] Buffer Overflow error: {str(e)}", "error")

    def _run_brute_force(self, url: str) -> None:
        """Execute Brute Force attack"""
        try:
            self.log(f"[*] Starting Brute Force on: {url}", "info")
            login_url = f"{url.rstrip('/')}/login" if not url.endswith('/login') else url

            # Common passwords (limited set for general scan)
            common_passwords = ["admin", "password", "123456", "root", "test", "admin123"]

            self.log(f"[*] Testing {len(common_passwords)} common passwords...", "info")

            session = requests.Session()
            found = False

            for password in common_passwords:
                if self.stop_event.is_set():
                    break

                try:
                    response = session.post(
                        login_url,
                        data={"username": "admin", "password": password},
                        timeout=5
                    )

                    # Simple check for successful login
                    if response.status_code == 200 and ("success" in response.text.lower() or "welcome" in response.text.lower()):
                        self.log(f"[!] PASSWORD FOUND: {password}", "vulnerable")
                        found = True
                        break
                except requests.exceptions.RequestException:
                    pass

            if not found:
                self.log("[+] No password found in common dictionary", "info")
        except Exception as e:
            self.log(f"[-] Brute Force error: {str(e)}", "error")

    def _run_directory_scanner(self, url: str) -> None:
        """Execute Directory Scanner attack"""
        try:
            self.log(f"[*] Starting Directory Scanner on: {url}", "info")
            # Limited directory list for general scan
            common_dirs = ["admin", "login", "api", "backup", "test", "config", "assets", "static"]

            self.log(f"[*] Testing {len(common_dirs)} common directories...", "info")

            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })

            found_dirs = []
            base_url = url.rstrip('/')

            for directory in common_dirs:
                if self.stop_event.is_set():
                    break

                try:
                    test_url = f"{base_url}/{directory}"
                    response = session.get(test_url, timeout=5, allow_redirects=False)
                    if response.status_code in [200, 301, 302, 403]:
                        found_dirs.append((directory, response.status_code))
                        self.log(f"[+] Found: /{directory} ({response.status_code})", "success")
                except requests.exceptions.RequestException:
                    pass

            if found_dirs:
                self.log(f"[+] Found {len(found_dirs)} accessible directories", "success")
            else:
                self.log("[+] No common directories found", "info")
        except Exception as e:
            self.log(f"[-] Directory Scanner error: {str(e)}", "error")

    def _run_path_traversal(self, url: str) -> None:
        """Execute Path Traversal attack"""
        try:
            self.log(f"[*] Starting Path Traversal test on: {url}", "info")
            # Ensure URL has a parameter
            test_url = url if '?' in url else f"{url}?file=test"
            scanner = PathTraversalScanner(self.log)
            scanner.scan_url(test_url)
        except Exception as e:
            self.log(f"[-] Path Traversal error: {str(e)}", "error")

    def _run_verbose_error(self, url: str) -> None:
        """Execute Verbose Error Disclosure attack"""
        try:
            self.log(f"[*] Starting Verbose Error scan on: {url}", "info")
            scanner = VerboseErrorScanner(self.log)
            scanner.scan(url)
            if scanner.vulnerable:
                self.log("[!] Verbose error disclosure vulnerability found", "vulnerable")
            else:
                self.log("[+] No verbose errors detected", "success")
        except Exception as e:
            self.log(f"[-] Verbose Error error: {str(e)}", "error")

    def _run_sql_injection(self, url: str) -> None:
        """Execute SQL Injection attack"""
        try:
            self.log(f"[*] Starting SQL Injection test on: {url}", "info")
            self.log("[*] SQL Injection requires specific endpoint (POST /search)", "info")
            self.log("[*] Executed in demonstration mode", "warning")
            self.log("[*] To test SQL Injection:", "info")
            self.log("    1. Ensure target has /search endpoint", "info")
            self.log("    2. Use the SQL Injection module directly", "info")
            # Try to test if endpoint exists
            search_url = f"{url.rstrip('/')}/search"
            try:
                response = requests.get(search_url, timeout=5)
                self.log(f"[*] Endpoint {search_url} exists (status: {response.status_code})", "info")
            except:
                self.log(f"[*] Endpoint {search_url} not accessible", "info")
        except Exception as e:
            self.log(f"[-] SQL Injection error: {str(e)}", "error")

    def _run_supply_chain(self, url: str) -> None:
        """Execute Supply Chain Scan attack"""
        try:
            self.log(f"[*] Starting Supply Chain scan on: {url}", "info")
            scanner = SupplyChainScanner(self.log)
            scanner.scan_url(url)
            findings = scanner.get_results()
            if findings:
                self.log(f"[!] Found {len(findings)} supply chain issues", "vulnerable")
            else:
                self.log("[+] No supply chain vulnerabilities detected", "success")
        except Exception as e:
            self.log(f"[-] Supply Chain scan error: {str(e)}", "error")


if __name__ == "__main__":
    # Test standalone
    root = tk.Tk()
    root.title("General Scan Module")
    root.geometry("900x700")
    root.configure(bg="#1e1e1e")

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TButton", background="#3c3c3c", foreground="white", padding=6)
    style.configure("TLabel", background="#1e1e1e", foreground="white")

    GeneralScanModule(root)
    root.mainloop()
