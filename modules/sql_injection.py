"""
modules/sql_injection.py

SCÉNARIO OWASP A03 – SQL INJECTION (Web Application Simulation)

Objectif pédagogique :
- Simuler une attaque SQL Injection sur une application WEB
- L’attaque passe par des paramètres HTTP (GET /login)
- Backend vulnérable qui construit une requête SQL dangereuse
- Démontrer : Authentication Bypass, Union-based Injection, etc.

⚠️ Usage pédagogique uniquement
"""

import sqlite3
import tkinter as tk
from tkinter import ttk, scrolledtext

# =========================
# BASE DE DONNÉES (DEMO)
# =========================
DB_PATH = "data/webapp_demo.sqlite"


def init_demo_db():
    """Initialise une base simulant une base de site web"""
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
def vulnerable_web_login(http_request: dict):
    """
    Simule un backend WEB vulnérable à la SQL Injection
    """
    username = http_request["params"]["username"]
    password = http_request["params"]["password"]

    # ❌ VULNÉRABILITÉ INTENTIONNELLE
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
    Module GUI compatible avec main.py
    """

    def __init__(self, parent):
        self.parent = parent
        self.build_ui()

    def build_ui(self):
        frame = tk.Frame(self.parent, bg="#1e1e1e")
        frame.pack(fill="both", expand=True)

        title = tk.Label(
            frame,
            text="SQL Injection – OWASP A03 (Web Application)",
            bg="#1e1e1e",
            fg="white",
            font=("Arial", 14, "bold")
        )
        title.pack(anchor="w", pady=5)

        description = tk.Label(
            frame,
            text=(
                "Simulation d’une attaque SQL Injection sur une application WEB.\n"
                "Les données injectées transitent via une requête HTTP (login)."
            ),
            bg="#1e1e1e",
            fg="white",
            justify="left"
        )
        description.pack(anchor="w", pady=5)

        controls = tk.Frame(frame, bg="#1e1e1e")
        controls.pack(fill="x", pady=5)

        ttk.Button(
            controls,
            text="Init DB Web",
            command=self.init_db
        ).pack(side="left", padx=5)

        self.payload_entry = ttk.Entry(controls, width=60)
        self.payload_entry.insert(0, "' OR '1'='1' --")
        self.payload_entry.pack(side="left", padx=5)

        ttk.Button(
            controls,
            text="Send HTTP Request",
            command=self.send_request
        ).pack(side="left", padx=5)

        self.output = scrolledtext.ScrolledText(
            frame,
            height=18,
            bg="#121212",
            fg="white"
        )
        self.output.pack(fill="both", expand=True, pady=5)

        self.log("[INFO] Module SQL Injection prêt.")

    def log(self, text):
        self.output.insert(tk.END, text + "\n\n")
        self.output.see(tk.END)

    def init_db(self):
        init_demo_db()
        self.log("[DB] Base de données Web initialisée.")

    def send_request(self):
        payload = self.payload_entry.get()

        http_request = {
            "method": "GET",
            "path": "/login",
            "params": {
                "username": payload,
                "password": "test"
            }
        }

        self.log("[HTTP REQUEST]")
        self.log(f"GET /login?username={payload}&password=test")

        sql, result, error = vulnerable_web_login(http_request)

        self.log("[SQL GENERATED]")
        self.log(sql)

        if error:
            self.log("[ERROR]")
            self.log(error)
        else:
            self.log("[DB RESPONSE]")
            self.log(str(result))

            if result:
                self.log("[IMPACT]")
                self.log("Authentication bypass detected (OWASP A03: Injection)")
            else:
                self.log("[RESULT]")
                self.log("Login failed (no injection success)")
