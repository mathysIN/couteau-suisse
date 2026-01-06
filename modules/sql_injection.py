"""
modules/sql_injection.py

SCÉNARIO OWASP A03 – SQL INJECTION
Adapté au site web de test (endpoint POST /search)

Objectif pédagogique :
- Scanner SQL Injection sur un formulaire réel
- Injection via paramètre POST "searched"
- Simulation fidèle du backend Node.js vulnérable

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
DB_PATH = "data/products.db"

SQLI_PAYLOADS = [
    "banana",
    "' OR '1'='1",
    "%' OR '1'='1",
    "' UNION SELECT 1,2,3,4,5--",
    "' UNION SELECT id,name,color,price,stock FROM products--",
    "' AND 1=0 UNION SELECT id,name,color,price,stock FROM products--"
]

# =========================
# BASE DE DONNÉES (SIMULATION)
# =========================
def init_demo_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS products")
    cur.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            color TEXT,
            price REAL,
            stock INTEGER
        )
    """)

    products = [
        ("Apple", "Red", 0.99, 120),
        ("Banana", "Yellow", 0.59, 200),
        ("Orange", "Orange", 1.29, 150),
        ("Kiwi", "Brown", 1.49, 80),
        ("Strawberry", "Red", 2.99, 60),
    ]

    cur.executemany(
        "INSERT INTO products (name, color, price, stock) VALUES (?, ?, ?, ?)",
        products
    )

    conn.commit()
    conn.close()

# =========================
# BACKEND WEB VULNÉRABLE (POST /search)
# =========================
def vulnerable_search_endpoint(searched: str):
    sql = f"SELECT * FROM products WHERE name LIKE '%{searched}%'"

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
    SQL Injection Scanner – adapté au site web de test
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
            text="SQL Injection Scanner – OWASP A03 (POST /search)",
            bg="#1e1e1e",
            fg="white",
            font=("Arial", 14, "bold")
        ).pack(anchor="w", pady=5)

        tk.Label(
            frame,
            text=(
                "Scan SQL Injection sur le formulaire de recherche du site web.\n"
                "Endpoint ciblé : POST /search | Paramètre : searched"
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
        self.url_entry.insert(0, "http://127.0.0.1/search")
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
        self.log("[INFO] Database initialized from website schema.")

    def log(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def run_scan(self):
        self.log("\n[SCAN] Starting SQL Injection scan on /search...\n")

        for payload in SQLI_PAYLOADS:
            self.log(f"[TARGET] POST /search")
            self.log(f"[PAYLOAD] searched={payload}")

            sql, result, error = vulnerable_search_endpoint(payload)

            self.log(f"[SQL] {sql}")

            if error:
                self.log(f"[ERROR] {error}")
            elif result:
                self.log("[RESULT] VULNERABLE ✔")
                self.log("         → SQL Injection successful (data returned)")
            else:
                self.log("[RESULT] No data returned")

            self.log("-" * 70)

        self.log("[SCAN] Finished.")
