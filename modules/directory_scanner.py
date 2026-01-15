"""
modules/directory_scanner.py
Module pour Directory/Path Enumeration (OWASP Reconnaissance)

Red Team Context: Découvre les répertoires et fichiers cachés d'un site web
en testant une wordlist de chemins courants.

Auteur : Étudiant en cybersécurité
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import requests
import time
import csv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple


class DirectoryScannerModule(tk.Frame):
    """Module GUI pour le scan de répertoires"""

    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.pack(fill="both", expand=True)

        self.scan_thread = None
        self.is_scanning = False
        self.found_count = 0
        self.tested_count = 0
        self.total_paths = 0
        self.start_time = None
        self.directories = []

        # Load wordlist
        self._load_wordlist()

        # Configuration frame
        config_frame = tk.Frame(self, bg="#1e1e1e")
        config_frame.pack(fill="x", pady=5)

        # Target URL
        ttk.Label(config_frame, text="Target URL:").grid(
            row=0, column=0, sticky="w", padx=5, pady=5)
        self.url_entry = ttk.Entry(config_frame, width=50)
        self.url_entry.insert(0, "http://localhost:3000")
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        config_frame.columnconfigure(1, weight=1)

        # Options frame
        options_frame = tk.Frame(self, bg="#1e1e1e")
        options_frame.pack(fill="x", pady=5)

        # Threads
        ttk.Label(options_frame, text="Threads:").pack(side="left", padx=5)
        self.threads_var = tk.StringVar(value="10")
        threads_spinbox = ttk.Spinbox(options_frame, from_=1, to=50, width=8,
                                       textvariable=self.threads_var)
        threads_spinbox.pack(side="left", padx=5)

        # Timeout
        ttk.Label(options_frame, text="Timeout (s):").pack(side="left", padx=5)
        self.timeout_var = tk.StringVar(value="5")
        timeout_spinbox = ttk.Spinbox(options_frame, from_=1, to=30, width=8,
                                       textvariable=self.timeout_var)
        timeout_spinbox.pack(side="left", padx=5)

        # Status code filter
        ttk.Label(options_frame, text="Show codes:").pack(side="left", padx=5)
        self.codes_var = tk.StringVar(value="200,301,302,403")
        codes_entry = ttk.Entry(options_frame, width=20, textvariable=self.codes_var)
        codes_entry.pack(side="left", padx=5)

        # Warning label
        warning_frame = tk.Frame(self, bg="#1e1e1e")
        warning_frame.pack(fill="x", pady=5)
        warning_label = ttk.Label(warning_frame,
                                  text="⚠️ Educational purpose only - Test only on authorized targets!",
                                  foreground="#ff6b6b")
        warning_label.pack(side="left", padx=5)

        # Buttons
        button_frame = tk.Frame(self, bg="#1e1e1e")
        button_frame.pack(fill="x", pady=5)

        self.start_btn = ttk.Button(button_frame, text="Start Scan",
                                     command=self.start_scan)
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = ttk.Button(button_frame, text="Stop Scan",
                                    command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        ttk.Button(button_frame, text="Clear Output",
                   command=self.clear_output).pack(side="left", padx=5)

        ttk.Button(button_frame, text="Reload Wordlist",
                   command=self._load_wordlist).pack(side="left", padx=5)

        # Stats frame
        stats_frame = tk.Frame(self, bg="#252526")
        stats_frame.pack(fill="x", pady=5, padx=5)

        self.stats_label = ttk.Label(stats_frame,
                                     text="Tested: 0/0 | Found: 0 | Time: 0s | Status: Ready",
                                     foreground="#4dabf7")
        self.stats_label.pack(side="left", padx=10, pady=5)

        # Output
        output_frame = tk.Frame(self, bg="#1e1e1e")
        output_frame.pack(fill="both", expand=True, pady=5)

        self.output = scrolledtext.ScrolledText(output_frame,
                                               wrap=tk.WORD,
                                               bg="#0d1117",
                                               fg="#58a6ff",
                                               font=("Consolas", 10),
                                               insertbackground="white")
        self.output.pack(fill="both", expand=True, padx=5, pady=5)

        # Configure tags for colored output
        self.output.tag_configure("success", foreground="#40c057")
        self.output.tag_configure("redirect", foreground="#fab005")
        self.output.tag_configure("forbidden", foreground="#ff6b6b")
        self.output.tag_configure("info", foreground="#4dabf7")

        self.log("📁 Directory Scanner Module loaded", "info")
        self.log(f"📋 Wordlist size: {len(self.directories)} paths", "info")
        self.log("=" * 60, "info")

    def _load_wordlist(self):
        """Load directories from CSV file"""
        self.directories = []
        csv_path = os.path.join(os.path.dirname(__file__), "..", "data", "directories.csv")
        csv_path = os.path.normpath(csv_path)
        
        try:
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                for row in reader:
                    if row and row[0].strip():
                        self.directories.append(row[0].strip())
            self.total_paths = len(self.directories)
            if hasattr(self, 'output'):
                self.log(f"✅ Loaded {self.total_paths} paths from wordlist", "success")
        except FileNotFoundError:
            if hasattr(self, 'output'):
                self.log(f"❌ Wordlist not found: {csv_path}", "forbidden")
            self.directories = ["admin", "login", "backup", "test", "api"]
            self.total_paths = len(self.directories)
        except Exception as e:
            if hasattr(self, 'output'):
                self.log(f"❌ Error loading wordlist: {str(e)}", "forbidden")

    def log(self, message: str, tag: str = None):
        """Add a message to the log"""
        self.output.insert(tk.END, message + "\n", tag)
        self.output.see(tk.END)
        self.output.update()

    def update_stats(self, status: str = "Scanning"):
        """Update statistics display"""
        elapsed = time.time() - self.start_time if self.start_time else 0
        self.stats_label.config(
            text=f"Tested: {self.tested_count}/{self.total_paths} | Found: {self.found_count} | Time: {elapsed:.1f}s | Status: {status}"
        )

    def start_scan(self):
        """Start the directory scan"""
        if self.is_scanning:
            return

        target_url = self.url_entry.get().strip().rstrip("/")

        if not target_url:
            self.log("❌ Please provide a target URL", "forbidden")
            return

        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, target_url)

        self.is_scanning = True
        self.found_count = 0
        self.tested_count = 0
        self.start_time = time.time()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

        # Parse status codes to show
        try:
            self.show_codes = [int(c.strip()) for c in self.codes_var.get().split(",")]
        except ValueError:
            self.show_codes = [200, 301, 302, 403]

        self.log("\n" + "=" * 60, "info")
        self.log("🔍 DIRECTORY SCAN INITIATED", "info")
        self.log("=" * 60, "info")
        self.log(f"Target: {target_url}", "info")
        self.log(f"Wordlist size: {self.total_paths}", "info")
        self.log(f"Threads: {self.threads_var.get()}", "info")
        self.log(f"Timeout: {self.timeout_var.get()}s", "info")
        self.log(f"Show codes: {self.show_codes}", "info")
        self.log("=" * 60 + "\n", "info")

        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(target_url,),
            daemon=True
        )
        self.scan_thread.start()

    def run_scan(self, target_url: str):
        """Run the scan in a separate thread"""
        threads = int(self.threads_var.get())
        timeout = float(self.timeout_var.get())
        found_paths = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self.check_path, target_url, path, timeout): path
                for path in self.directories
            }

            for future in as_completed(futures):
                if not self.is_scanning:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                path = futures[future]
                self.tested_count += 1

                try:
                    result = future.result()
                    if result:
                        status_code, url, size = result
                        if status_code in self.show_codes:
                            self.found_count += 1
                            found_paths.append((url, status_code, size))
                            
                            # Color based on status code
                            if status_code == 200:
                                tag = "success"
                                icon = "✅"
                            elif status_code in (301, 302):
                                tag = "redirect"
                                icon = "↪️"
                            elif status_code == 403:
                                tag = "forbidden"
                                icon = "🔒"
                            else:
                                tag = "info"
                                icon = "📄"
                            
                            self.log(f"{icon} [{status_code}] {url} ({size} bytes)", tag)
                
                except Exception as e:
                    pass  # Silently ignore errors for cleaner output

                # Update stats every 10 requests
                if self.tested_count % 10 == 0:
                    self.update_stats()

        # Final summary
        elapsed = time.time() - self.start_time
        self.log("\n" + "=" * 60, "info")
        
        if self.is_scanning:
            self.log("✅ SCAN COMPLETE", "success")
        else:
            self.log("⏸️ SCAN STOPPED", "redirect")
        
        self.log("=" * 60, "info")
        self.log(f"Paths tested: {self.tested_count}/{self.total_paths}", "info")
        self.log(f"Paths found: {self.found_count}", "info")
        self.log(f"Time elapsed: {elapsed:.2f}s", "info")
        
        if found_paths:
            self.log("\n📋 SUMMARY OF FOUND PATHS:", "info")
            for url, code, size in found_paths:
                self.log(f"  [{code}] {url}", "success" if code == 200 else "redirect")
        
        self.log("=" * 60, "info")
        self.update_stats("Complete" if self.is_scanning else "Stopped")

        self.is_scanning = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def check_path(self, base_url: str, path: str, timeout: float) -> Tuple[int, str, int]:
        """Check if a path exists on the target"""
        url = f"{base_url}/{path}"
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
            )
            return (response.status_code, url, len(response.content))
        except requests.exceptions.RequestException:
            return None

    def stop_scan(self):
        """Stop the current scan"""
        self.is_scanning = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def clear_output(self):
        """Clear the output"""
        self.output.delete(1.0, tk.END)
        self.found_count = 0
        self.tested_count = 0
        self.start_time = None
        self.update_stats("Ready")
