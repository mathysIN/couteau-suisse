#!/usr/bin/env python3
"""
modules/scan_supply_chain.py
Module de scan pour OWASP A03:2025 Software Supply Chain Failures

Red Team Context: Analyse d'une application web via URL pour détecter :
- Bibliothèques JavaScript exposées et leurs versions
- Frameworks et CDN vulnérables
- Fichiers de configuration exposés (package.json, composer.json, etc.)
- Headers révélant des versions de serveur/framework
- Scripts et dépendances obsolètes

Auteur : Étudiant en cybersécurité
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
from typing import List, Dict, Set, Optional
import json

import json


# Known vulnerable library versions (simplified database)
KNOWN_VULNERABILITIES = {
    'jquery': {
        '1.6.0': 'CVE-2011-4969 (XSS)',
        '1.7.2': 'CVE-2012-6708 (XSS)',
        '1.12.3': 'CVE-2015-9251 (XSS)',
        '2.2.3': 'CVE-2015-9251 (XSS)',
        '3.3.1': 'CVE-2019-11358 (Prototype Pollution)',
    },
    'bootstrap': {
        '3.3.7': 'CVE-2018-14040 (XSS)',
        '3.4.0': 'CVE-2019-8331 (XSS)',
    },
    'angular': {
        '1.5.0': 'CVE-2019-10768 (Prototype Pollution)',
    },
    'lodash': {
        '4.17.11': 'CVE-2019-10744 (Prototype Pollution)',
    },
    'moment': {
        '2.29.1': 'CVE-2022-31129 (ReDoS)',
    }
}


class SupplyChainScanner:
    """Scanner pour détecter les vulnérabilités de supply chain dans une web app"""

    def __init__(self, log_callback):
        self.log = log_callback
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.findings: List[Dict] = []
        self.detected_libraries: Set[str] = set()

    def scan_url(self, url: str) -> None:
        """Lance le scan complet sur l'URL cible"""
        self.log(f"[*] Starting supply chain scan on: {url}")
        self.findings.clear()
        self.detected_libraries.clear()

        # 1. Récupérer la page principale
        try:
            response = self.session.get(url, timeout=10, verify=False)
            self.log(f"[+] Target responded with status: {response.status_code}")
        except requests.RequestException as e:
            self.log(f"[-] Error accessing target: {str(e)}")
            return

        # 2. Analyser les headers pour version disclosure
        self._check_server_headers(response)

        # 3. Extraire et analyser les scripts JavaScript
        self._analyze_javascript_libraries(response, url)

        # 4. Chercher des fichiers de configuration exposés
        self._check_exposed_config_files(url)

        # 5. Résumé des findings
        self._print_summary()

    def _check_server_headers(self, response) -> None:
        """Analyse les headers HTTP pour version disclosure"""
        self.log("\n[*] Analyzing HTTP headers...")
        
        sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 
                            'X-AspNetMvc-Version', 'X-Generator']
        
        for header in sensitive_headers:
            if header in response.headers:
                value = response.headers[header]
                self.log(f"[!] Version disclosure in header: {header}: {value}")
                self.findings.append({
                    'type': 'Version Disclosure',
                    'location': 'HTTP Header',
                    'detail': f"{header}: {value}",
                    'severity': 'Low'
                })

    def _analyze_javascript_libraries(self, response, base_url: str) -> None:
        """Extrait et analyse les bibliothèques JavaScript"""
        self.log("\n[*] Analyzing JavaScript libraries...")
        
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        
        self.log(f"[*] Found {len(scripts)} script tags")
        
        for script in scripts:
            src = script.get('src', '')
            full_url = urljoin(base_url, src)
            
            # Détecter les bibliothèques connues
            lib_info = self._identify_library(src, full_url)
            if lib_info:
                lib_name, version = lib_info
                self.detected_libraries.add(f"{lib_name}@{version}")
                self.log(f"[+] Detected: {lib_name} v{version}")
                
                # Vérifier si version vulnérable
                if lib_name in KNOWN_VULNERABILITIES:
                    if version in KNOWN_VULNERABILITIES[lib_name]:
                        vuln = KNOWN_VULNERABILITIES[lib_name][version]
                        self.log(f"[!] VULNERABLE: {lib_name} v{version} - {vuln}")
                        self.findings.append({
                            'type': 'Vulnerable Library',
                            'library': lib_name,
                            'version': version,
                            'vulnerability': vuln,
                            'severity': 'High'
                        })

    def _identify_library(self, src: str, full_url: str) -> Optional[tuple]:
        """Identifie une bibliothèque et sa version depuis l'URL du script"""
        
        # Patterns pour détecter les bibliothèques populaires
        patterns = {
            'jquery': r'jquery[.-](\d+\.\d+\.\d+)',
            'bootstrap': r'bootstrap[.-](\d+\.\d+\.\d+)',
            'angular': r'angular[.-](\d+\.\d+\.\d+)',
            'react': r'react[.-](\d+\.\d+\.\d+)',
            'vue': r'vue[.-](\d+\.\d+\.\d+)',
            'lodash': r'lodash[.-](\d+\.\d+\.\d+)',
            'moment': r'moment[.-](\d+\.\d+\.\d+)',
        }
        
        src_lower = src.lower()
        
        for lib_name, pattern in patterns.items():
            match = re.search(pattern, src_lower)
            if match:
                version = match.group(1)
                return (lib_name, version)
        
        # Tentative de récupération depuis les commentaires du fichier JS
        if not src.startswith('http'):
            return None
            
        try:
            js_response = self.session.get(full_url, timeout=5)
            first_lines = '\n'.join(js_response.text.split('\n')[:10])
            
            # Chercher version dans les commentaires
            version_match = re.search(r'v?(\d+\.\d+\.\d+)', first_lines)
            if version_match:
                for lib in patterns.keys():
                    if lib in src_lower:
                        return (lib, version_match.group(1))
        except:
            pass
        
        return None

    def _check_exposed_config_files(self, base_url: str) -> None:
        """Vérifie si des fichiers de configuration sont exposés"""
        self.log("\n[*] Checking for exposed configuration files...")
        
        config_files = [
            'package.json',
            'package-lock.json',
            'composer.json',
            'composer.lock',
            'bower.json',
            'yarn.lock',
            '.env',
            'webpack.config.js',
            '.git/config',
        ]
        
        for filename in config_files:
            test_url = urljoin(base_url, filename)
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    
                    # Vérifier si c'est vraiment du JSON/texte
                    if 'json' in content_type or 'text' in content_type or len(response.text) < 1000000:
                        self.log(f"[!] EXPOSED: {filename} ({response.status_code})")
                        self.findings.append({
                            'type': 'Exposed Config File',
                            'file': filename,
                            'url': test_url,
                            'severity': 'Medium' if filename != '.env' else 'Critical'
                        })
                        
                        # Analyser package.json si trouvé
                        if filename == 'package.json':
                            self._analyze_package_json(response.text)
            except:
                pass

    def _analyze_package_json(self, content: str) -> None:
        """Analyse le contenu d'un package.json exposé"""
        try:
            data = json.loads(content)
            dependencies = data.get('dependencies', {})
            
            self.log(f"[*] Found {len(dependencies)} dependencies in package.json")
            
            for dep, version in dependencies.items():
                clean_version = version.lstrip('^~>=<')
                self.log(f"    - {dep}: {clean_version}")
                
                # Vérifier vulnérabilités connues
                if dep in KNOWN_VULNERABILITIES:
                    if clean_version in KNOWN_VULNERABILITIES[dep]:
                        vuln = KNOWN_VULNERABILITIES[dep][clean_version]
                        self.log(f"[!] VULNERABLE: {dep} v{clean_version} - {vuln}")
        except:
            pass

    def _print_summary(self) -> None:
        """Affiche le résumé des findings"""
        self.log("\n" + "="*60)
        self.log("SCAN SUMMARY")
        self.log("="*60)
        
        if not self.findings:
            self.log("[+] No supply chain vulnerabilities detected")
            return
        
        # Grouper par sévérité
        by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
        for finding in self.findings:
            severity = finding.get('severity', 'Low')
            by_severity[severity].append(finding)
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            count = len(by_severity[severity])
            if count > 0:
                self.log(f"\n[!] {severity}: {count} finding(s)")
                for f in by_severity[severity]:
                    self.log(f"    - {f.get('type')}: {f}")
        
        self.log(f"\n[*] Total libraries detected: {len(self.detected_libraries)}")
        for lib in sorted(self.detected_libraries):
            self.log(f"    - {lib}")

    def get_results(self) -> List[Dict]:
        """Retourne les résultats du scan"""
        return self.findings


class SupplyChainModule(tk.Frame):
    """Module GUI pour le scan de supply chain"""

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
        self.url_entry.insert(0, "http://testphp.vulnweb.com/")
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        config_frame.columnconfigure(1, weight=1)

        # Info label
        info_frame = tk.Frame(self, bg="#1e1e1e")
        info_frame.pack(fill="x", pady=5)
        
        info_text = "OWASP A03:2025 - Scans for exposed dependencies, vulnerable libraries, and configuration files"
        ttk.Label(info_frame, text=info_text, foreground="#888").pack(side="left", padx=5)

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
            self, bg="#252526", fg="white", height=20, wrap=tk.WORD, font=("Courier", 9)
        )
        self.output.pack(fill="both", expand=True, pady=5)

        # Configuration des tags pour coloration
        self.output.tag_config("vulnerable", foreground="#ff6b6b")
        self.output.tag_config("info", foreground="#4dabf7")
        self.output.tag_config("success", foreground="#51cf66")
        self.output.tag_config("warning", foreground="#ffd43b")

    def log(self, msg: str) -> None:
        """Log un message dans l'interface"""
        def _log():
            # Détection du type de message pour coloration
            if "[!]" in msg and "VULNERABLE" in msg:
                tag = "vulnerable"
            elif "[!]" in msg:
                tag = "warning"
            elif "[+]" in msg:
                tag = "success"
            elif "[*]" in msg:
                tag = "info"
            else:
                tag = None
            
            self.output.insert("end", msg + "\n", tag)
            self.output.see("end")
        
        if threading.current_thread() != threading.main_thread():
            self.after(0, _log)
        else:
            _log()

    def clear_output(self) -> None:
        """Efface les résultats"""
        self.output.delete(1.0, "end")

    def start_scan(self) -> None:
        """Démarre le scan dans un thread séparé"""
        url = self.url_entry.get().strip()
        
        if not url:
            self.log("[!] Please enter a target URL")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            self.url_entry.delete(0, "end")
            self.url_entry.insert(0, url)
        
        self.clear_output()
        self.log("[*] Initializing supply chain scanner...")
        
        self.scanner = SupplyChainScanner(self.log)
        self.scan_thread = threading.Thread(
            target=self.scanner.scan_url,
            args=(url,),
            daemon=True
        )
        self.scan_thread.start()


# Pour compatibilité avec l'ancien système
def main():
    """Point d'entrée pour l'exécution standalone (mode CLI)"""
    print("This module is designed to be used within the GUI.")
    print("Run main.py instead.")


if __name__ == "__main__":
    main()
