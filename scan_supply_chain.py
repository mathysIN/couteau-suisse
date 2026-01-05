#!/usr/bin/env python3
"""
scan_supply_chain.py
Module de scan pour OWASP A03:2025 Software Supply Chain Failures

Ce script analyse les dépendances Python et Node.js pour détecter :
- Les bibliothèques obsolètes (outdated)
- Les vulnérabilités connues (via pip-audit et npm audit)
- Les dépendances non maintenues

Auteur : Étudiant en cybersécurité
"""

import subprocess
import sys
import os
import json
import datetime
import shutil

SBOM_FILE = "sbom.txt"

def run_command(cmd, cwd=None):
    """Exécute une commande et affiche le résultat"""
    try:
        result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True, timeout=60)
        print(f"\n$ {cmd}")
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
        return result.stdout, result.returncode
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout pour la commande : {cmd}")
        return "", -1
    except Exception as e:
        print(f"[!] Erreur lors de l'exécution de '{cmd}': {e}")
        return "", -1

def get_pip_freeze():
    """Récupère la liste des dépendances Python installées"""
    try:
        result = subprocess.run([sys.executable, "-m", "pip", "freeze"], capture_output=True, text=True, timeout=30)
        return result.stdout.splitlines()
    except Exception as e:
        print(f"[!] Erreur lors de pip freeze: {e}")
        return []

def get_npm_list(website_dir):
    """Récupère la liste des dépendances Node.js (avec gestion d'erreur si npm absent)"""
    if not shutil.which("npm"):
        print("[!] npm n'est pas installé ou n'est pas dans le PATH")
        print("    Téléchargez Node.js depuis https://nodejs.org/")
        return []
    
    try:
        result = subprocess.run(
            ["npm", "list", "--json", "--depth=0"], 
            cwd=website_dir, 
            capture_output=True, 
            text=True, 
            timeout=30
        )
        data = json.loads(result.stdout)
        deps = data.get("dependencies", {})
        return [f"{k}@{v.get('version', 'unknown')}" for k, v in deps.items()]
    except FileNotFoundError:
        print("[!] npm n'a pas été trouvé. Installez Node.js depuis https://nodejs.org/")
        return []
    except Exception as e:
        print(f"[!] Erreur lors de la récupération des dépendances npm: {e}")
        return []

def write_sbom(pip_deps, npm_deps):
    """Génère un fichier SBOM (Software Bill of Materials)"""
    try:
        with open(SBOM_FILE, "w", encoding="utf-8") as f:
            f.write("# Software Bill of Materials (SBOM)\n")
            f.write(f"# Generated: {datetime.datetime.now()}\n")
            f.write("# OWASP A03:2025 Software Supply Chain Failures\n\n")
            
            f.write("## Python dependencies\n")
            if pip_deps:
                for dep in pip_deps:
                    f.write(f"  - {dep}\n")
            else:
                f.write("  (aucune dépendance trouvée)\n")
            
            f.write("\n## Node.js dependencies\n")
            if npm_deps:
                for dep in npm_deps:
                    f.write(f"  - {dep}\n")
            else:
                f.write("  (aucune dépendance trouvée ou npm non installé)\n")
        
        print(f"\n[+] SBOM généré avec succès : {SBOM_FILE}")
    except Exception as e:
        print(f"[!] Erreur lors de la génération du SBOM: {e}")

def scan_python():
    """Scan des dépendances Python"""
    print("\n" + "="*60)
    print("PYTHON SUPPLY CHAIN SCAN")
    print("="*60)
    
    # 1. Lister les paquets obsolètes
    print("\n[1] Recherche de paquets obsolètes...")
    run_command(f'"{sys.executable}" -m pip list --outdated')
    
    # 2. Vérifier l'intégrité des dépendances
    print("\n[2] Vérification de l'intégrité des dépendances...")
    run_command(f'"{sys.executable}" -m pip check')
    
    # 3. Scan de vulnérabilités avec pip-audit
    print("\n[3] Scan de vulnérabilités (pip-audit)...")
    try:
        import pip_audit
        run_command(f'"{sys.executable}" -m pip_audit')
    except ImportError:
        print("[!] pip-audit n'est pas installé.")
        print("    Pour l'installer : pip install pip-audit")
        print("    pip-audit détecte les vulnérabilités connues (CVE) dans vos dépendances.")
    
    # 4. Compter les dépendances obsolètes
    print("\n[4] Analyse des dépendances...")
    pip_list_output, _ = run_command(f'"{sys.executable}" -m pip list --outdated --format=json')
    try:
        outdated = json.loads(pip_list_output)
        if outdated:
            print(f"[!] {len(outdated)} paquet(s) obsolète(s) détecté(s)")
            print("    Recommandation : mettez à jour régulièrement vos dépendances")
        else:
            print("[+] Toutes les dépendances Python sont à jour")
    except:
        pass

def scan_node():
    """Scan des dépendances Node.js"""
    print("\n" + "="*60)
    print("NODE.JS SUPPLY CHAIN SCAN")
    print("="*60)
    
    website_dir = os.path.join(os.path.dirname(__file__), "website")
    
    if not os.path.exists(website_dir):
        print(f"[!] Le dossier {website_dir} n'existe pas")
        return
    
    if not shutil.which("npm"):
        print("[!] npm n'est pas installé ou n'est pas dans le PATH")
        print("    Téléchargez Node.js depuis https://nodejs.org/")
        print("    npm permet de scanner les vulnérabilités avec 'npm audit'")
        return
    
    # 1. Lister les paquets obsolètes
    print("\n[1] Recherche de paquets obsolètes...")
    run_command("npm outdated", cwd=website_dir)
    
    # 2. Audit de sécurité
    print("\n[2] Audit de sécurité npm...")
    audit_output, return_code = run_command("npm audit --json", cwd=website_dir)
    
    try:
        audit_data = json.loads(audit_output)
        vulnerabilities = audit_data.get("metadata", {}).get("vulnerabilities", {})
        total = sum(vulnerabilities.values()) if vulnerabilities else 0
        
        if total > 0:
            print(f"\n[!] {total} vulnérabilité(s) détectée(s) :")
            for severity, count in vulnerabilities.items():
                if count > 0:
                    print(f"    - {severity}: {count}")
            print("\n    Recommandation : exécutez 'npm audit fix' pour corriger automatiquement")
        else:
            print("[+] Aucune vulnérabilité détectée dans les dépendances Node.js")
    except Exception as e:
        print(f"[!] Impossible d'analyser les résultats de npm audit: {e}")
    
    # 3. Vérifier la date du package-lock.json
    print("\n[3] Vérification de la fraîcheur des dépendances...")
    lock_path = os.path.join(website_dir, "package-lock.json")
    if os.path.exists(lock_path):
        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(lock_path))
        age_days = (datetime.datetime.now() - mtime).days
        
        if age_days > 365:
            print(f"[!] package-lock.json n'a pas été mis à jour depuis {age_days} jours")
            print("    Recommandation : revoyez et mettez à jour vos dépendances régulièrement")
        else:
            print(f"[+] package-lock.json à jour (dernière modification : il y a {age_days} jours)")
    else:
        print("[!] package-lock.json introuvable")

def print_header():
    """Affiche l'en-tête pédagogique"""
    print("""
================================================================
   OWASP A03:2025 - Software Supply Chain Failures
   Scan de securite des dependances
================================================================

[Ce que ce scan detecte]
   - Bibliotheques obsoletes (outdated)
   - Vulnerabilites connues (CVE)
   - Dependances non maintenues

[Bonnes pratiques OWASP]
   - Maintenir un SBOM (Software Bill of Materials)
   - Scanner regulierement les dependances
   - Mettre a jour les bibliotheques vulnerables
   - Utiliser des outils automatises (pip-audit, npm audit)
   - Documenter les changements de dependances

[Ressources]
   - pip-audit : https://pypi.org/project/pip-audit/
   - npm audit : https://docs.npmjs.com/cli/audit
   - OWASP Dependency Check : https://owasp.org/www-project-dependency-check/
""")

def print_footer():
    """Affiche le résumé final"""
    print("\n" + "="*60)
    print("SCAN TERMINE")
    print("="*60)
    print(f"\n[OK] SBOM genere : {SBOM_FILE}")
    print("\n[Actions recommandees]")
    print("   1. Verifier le SBOM pour la liste complete des dependances")
    print("   2. Corriger les vulnerabilites critiques en priorite")
    print("   3. Mettre a jour les packages obsoletes")
    print("   4. Reexecuter ce scan regulierement\n")

def main():
    """Fonction principale"""
    print_header()
    
    # Scan Python
    scan_python()
    
    # Scan Node.js
    scan_node()
    
    # Génération du SBOM
    print("\n" + "="*60)
    print("GÉNÉRATION DU SBOM")
    print("="*60)
    
    website_dir = os.path.join(os.path.dirname(__file__), "website")
    pip_deps = get_pip_freeze()
    npm_deps = get_npm_list(website_dir)
    write_sbom(pip_deps, npm_deps)
    
    # Résumé final
    print_footer()

if __name__ == "__main__":
    main()
