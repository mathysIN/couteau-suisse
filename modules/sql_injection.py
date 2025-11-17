"""
modules/sql_injection.py

Module pédagogique pour le scénario "SQL Injection".
Expose :
  - fonctions utilitaires : setup_db, vulnerable_query, safe_query, run_simulation
  - classe UI : SQLInjectionModule(parent_frame) -> intègre l'interface
Usage :
  from modules.sql_injection import SQLInjectionModule, setup_db, run_simulation
  SQLInjectionModule(parent_frame)  # pour l'UI dans le conteneur principal
"""

import sqlite3
import tkinter as tk
from tkinter import ttk, scrolledtext
from typing import List, Dict, Any, Optional


# --------------------------
# Backend : simulation DB
# --------------------------
DEFAULT_DB = "data/demo_sql_injection.sqlite"


def setup_db(db_path: str = DEFAULT_DB) -> None:
    """
    Crée / ré-initialise une DB SQLite d'exemple et la peuple avec des utilisateurs.
    Écrase la DB si elle existe.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users;")
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT
        );
    """)
    users = [
        ("alice", "alicepass", "alice@example.com"),
        ("bob", "bobpass", "bob@example.com"),
        ("charlie", "charliepass", "charlie@example.com")
    ]
    cur.executemany("INSERT INTO users (username, password, email) VALUES (?, ?, ?);", users)
    conn.commit()
    conn.close()


def _execute_raw(db_path: str, raw_sql: str) -> (Optional[List[Dict[str, Any]]], Optional[str]):
    """
    Exécute une requête SQL brute et retourne (rows-as-dicts, error_message).
    On garde la fonction factice simple : retourne une erreur en cas d'exception.
    """
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(raw_sql)
        cols = [c[0] for c in cur.description] if cur.description else []
        rows = cur.fetchall()
        result = [dict(zip(cols, row)) for row in rows]
        conn.commit()
        conn.close()
        return result, None
    except Exception as e:
        return None, str(e)


def vulnerable_query(db_path: str, user_input: str) -> Dict[str, Any]:
    """
    Construite volontairement de façon vulnérable : concaténation directe.
    Retourne dict contenant raw_sql, result (ou error).
    """
    raw_sql = f"SELECT id, username, email FROM users WHERE username = '{user_input}';"
    result, error = _execute_raw(db_path, raw_sql)
    return {"raw_sql": raw_sql, "result": result, "error": error}


def safe_query(db_path: str, username: str) -> Dict[str, Any]:
    """
    Version sécurisée (paramétrée) pour comparaison pédagogique.
    """
    raw_sql = "SELECT id, username, email FROM users WHERE username = ?;"
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(raw_sql, (username,))
        cols = [c[0] for c in cur.description] if cur.description else []
        rows = cur.fetchall()
        result = [dict(zip(cols, row)) for row in rows]
        conn.close()
        return {"raw_sql": raw_sql, "result": result, "error": None}
    except Exception as e:
        return {"raw_sql": raw_sql, "result": None, "error": str(e)}


def detect_payload_type(payload: str, result: Optional[List[Dict[str, Any]]]) -> str:
    """
    Heuristique simple pour annoter le type de payload.
    """
    pl = (payload or "").lower()
    if "drop table" in pl or "delete" in pl or "truncate" in pl:
        return "destructive"
    if "union" in pl:
        return "union"
    if "or '1'='1" in pl or 'or 1=1' in pl or "or '1' = '1" in pl:
        return "tautology"
    if "--" in pl or "#" in pl:
        return "comment"
    if result and len(result) > 0:
        # si la requête renvoie des lignes qui ne contiennent pas le payload as-is
        usernames = {r.get("username") for r in result if r.get("username")}
        if payload not in usernames:
            return "bypass / abnormal result"
    return "no obvious pattern"


def run_simulation(db_path: str = DEFAULT_DB, extra_payloads: List[str] = None) -> Dict[str, Any]:
    """
    Lance une batterie de payloads classiques et renvoie un rapport structuré.
    ATTENTION : les payloads potentiellement destructeurs ne sont pas réellement exécutés
    (on les détecte et les "simule" pour éviter de supprimer la DB d'exemple).
    """
    payloads = [
        "alice",
        "bob' --",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "'; DROP TABLE users; --",  # destructive -> simulation only
        "' UNION SELECT null, sql, sql FROM sqlite_master --",
        "nonexistent' OR username = 'bob"
    ]
    if extra_payloads:
        payloads.extend(extra_payloads)

    report = []
    for p in payloads:
        ptype = detect_payload_type(p, None)
        raw_sql = f"SELECT id, username, email FROM users WHERE username = '{p}';"
        if ptype == "destructive":
            # Ne pas exécuter la requête destructive : simuler l'effet
            note = "destructive (simulated - blocked)"
            result = [{"__simulated__": "DROP/TRUNCATE detected, execution blocked"}]
            report.append({"payload": p, "raw_sql": raw_sql, "result": result, "note": note})
            continue

        result, error = _execute_raw(db_path, raw_sql)
        note = detect_payload_type(p, result)
        if error:
            report.append({"payload": p, "raw_sql": raw_sql, "result": None, "note": "error", "error": error})
        else:
            report.append({"payload": p, "raw_sql": raw_sql, "result": result, "note": note})

    return {"db_path": db_path, "report": report}


# --------------------------
# Frontend : classe UI
# --------------------------
class SQLInjectionModule:
    """
    UI module compatible avec la structure du projet.
    Utilisation : SQLInjectionModule(parent_frame)
    L'instance ajoute ses widgets dans parent_frame (pack/grid selon style projet).
    """

    def __init__(self, parent, db_path: str = DEFAULT_DB):
        self.parent = parent
        self.db_path = db_path
        self._build_ui()

    def _build_ui(self):
        # wrapper frame
        self.frame = tk.Frame(self.parent, bg="#1e1e1e")
        self.frame.pack(fill="both", expand=True)

        # Titre / description courte
        header = tk.Label(self.frame, text="SQL Injection — Simulation pédagogique",
                          bg="#1e1e1e", fg="white", font=("Helvetica", 14, "bold"))
        header.pack(anchor="w", pady=(6, 2))

        desc_text = (
            "Cet écran permet d'initialiser une DB de démonstration, tester un payload "
            "et lancer une simulation de payloads classiques.\n\n"
            "⚠️ Usage pédagogique seulement — les payloads destructeurs sont bloqués."
        )
        desc = tk.Label(self.frame, text=desc_text, bg="#1e1e1e", fg="white", justify="left", wraplength=760)
        desc.pack(anchor="w", pady=(0, 8))

        # Contrôles (buttons + entry)
        ctrl_frame = tk.Frame(self.frame, bg="#1e1e1e")
        ctrl_frame.pack(fill="x", pady=(0, 8))

        self.init_btn = ttk.Button(ctrl_frame, text="Init DB (reset demo)", command=self._on_init_db)
        self.init_btn.pack(side="left", padx=(0, 6))

        self.payload_entry = ttk.Entry(ctrl_frame, width=60)
        self.payload_entry.pack(side="left", padx=(0, 6))
        self.payload_entry.insert(0, "alice' OR '1'='1")

        self.test_btn = ttk.Button(ctrl_frame, text="Tester payload", command=self._on_test_payload)
        self.test_btn.pack(side="left", padx=(0, 6))

        self.sim_btn = ttk.Button(ctrl_frame, text="Lancer simulation", command=self._on_run_simulation)
        self.sim_btn.pack(side="left", padx=(0, 6))

        # Zone de résultat / log
        results_label = tk.Label(self.frame, text="Résultats / Logs :", bg="#1e1e1e", fg="white")
        results_label.pack(anchor="w")

        self.output = scrolledtext.ScrolledText(self.frame, height=18, wrap=tk.WORD, bg="#121212", fg="white")
        self.output.pack(fill="both", expand=True, pady=(4, 0))

        # Footer rapide : hints pédagogiques
        footer = tk.Label(self.frame, text="Comparaison : utilisez safe_query() pour voir l'approche paramétrée.",
                          bg="#1e1e1e", fg="#cccccc", font=("Helvetica", 9))
        footer.pack(anchor="w", pady=(6, 0))

        # initial state
        self._append_log(f"Module SQL Injection initialisé. DB path = {self.db_path}")

    # --- UI helpers ---
    def _append_log(self, text: str):
        self.output.insert(tk.END, text + "\n\n")
        self.output.see(tk.END)

    # --- Button callbacks ---
    def _on_init_db(self):
        try:
            setup_db(self.db_path)
            self._append_log(f"[Init DB] Base de démonstration initialisée : {self.db_path}")
        except Exception as e:
            self._append_log(f"[Init DB] Erreur lors de l'initialisation : {e}")

    def _on_test_payload(self):
        payload = self.payload_entry.get()
        if not payload:
            self._append_log("[Test payload] Aucun payload fourni.")
            return

        self._append_log(f"[Test payload] Payload: {payload}")
        res = vulnerable_query(self.db_path, payload)
        self._append_log(f"SQL construit : {res.get('raw_sql')}")
        if res.get("error"):
            self._append_log(f"Erreur : {res.get('error')}")
        else:
            self._append_log(f"Résultat ({len(res.get('result', []))} lignes) : {res.get('result')}")
        # Afficher aussi la version paramétrée pour comparaison
        safe = safe_query(self.db_path, payload)
        self._append_log(f"[Safe query] SQL paramétré : {safe.get('raw_sql')}")
        if safe.get("error"):
            self._append_log(f"[Safe query] Erreur : {safe.get('error')}")
        else:
            self._append_log(f"[Safe query] Résultat ({len(safe.get('result', []))} lignes) : {safe.get('result')}")

    def _on_run_simulation(self):
        self._append_log("[Run simulation] Lancement de la batterie de payloads...")
        report = run_simulation(self.db_path)
        for item in report["report"]:
            payload = item.get("payload")
            note = item.get("note")
            raw_sql = item.get("raw_sql")
            result = item.get("result")
            error = item.get("error")
            self._append_log(f"Payload: {payload}  —  Note: {note}")
            self._append_log(f"SQL: {raw_sql}")
            if error:
                self._append_log(f"Erreur: {error}")
            else:
                self._append_log(f"Résultat: {result}")

        self._append_log("[Run simulation] Terminé.")


# Si on exécute le module directement, faire une petite démo rapide (utile pour dev)
if __name__ == "__main__":
    root = tk.Tk()
    root.title("SQL Injection Module - DEV")
    frame = tk.Frame(root, bg="#1e1e1e")
    frame.pack(fill="both", expand=True)
    SQLInjectionModule(frame)
    root.geometry("800x600")
    root.mainloop()
