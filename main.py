import tkinter as tk
from tkinter import ttk
# ensure ngrok header patch is applied before importing other modules
import modules.ngrok_patch
from modules.portscanner import PortScannerModule
from modules.proxy_interception import ProxyInterceptionModule
from modules.xss_injection import XSSModule
from modules.sql_injection import SQLInjectionModule
from modules.scan_supply_chain import SupplyChainModule
from modules.http_flood import HTTPFloodModule
from modules.buffer_overflow import BufferOverflowModule
from modules.bruteforce import BruteForceModule
from modules.directory_scanner import DirectoryScannerModule
from modules.verbose_error import VerboseErrorModule
from modules.path_traversal import PathTraversalModule
from modules.general_scan import GeneralScanModule


class ThinkerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Attack GUI Tool")
        self.geometry("900x600")
        self.configure(bg="#1e1e1e")
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("TButton", background="#3c3c3c",
                             foreground="white", padding=6)
        self.style.configure(
            "TLabel", background="#1e1e1e", foreground="white")

        self.module_frame = tk.Frame(self, bg="#1e1e1e")
        self.module_frame.pack(side="top", fill="x", pady=20)


        modules = [
            ("General Scan", self.show_general_scan),
            ("Port Scanner", self.show_port_scanner),
            ("Proxy Interception", self.show_proxy_interception),
            ("XSS Injection", self.show_xss),
            ("SQL Injection", self.show_sql_injection),
            ("Supply Chain Scan", self.run_supply_chain_scan),
            ("HTTP Flood", self.show_http_flood),
            ("Buffer Overflow", self.show_bof),
            ("Brute Force", self.show_bruteforce),
            ("Dir Scanner", self.show_dir_scanner),
            ("Verbose Errors", self.show_verbose_errors),
            ("Path Traversal", self.show_path_traversal)
        ]

        for i, (label, action) in enumerate(modules):
            frame = tk.Frame(self.module_frame, bg="#1e1e1e")
            frame.grid(row=0, column=i, padx=20)
            btn = ttk.Button(frame, text=label, command=action)
            btn.pack()

        # Initialisation correcte du container principal
        self.container = tk.Frame(self, bg="#1e1e1e")
        self.container.pack(fill="both", expand=True, padx=20, pady=10)
        
    def run_supply_chain_scan(self):
        self.clear_container()
        SupplyChainModule(self.container)

    def clear_container(self):
        for w in self.container.winfo_children():
            w.destroy()

    def show_port_scanner(self):
        self.clear_container()
        PortScannerModule(self.container)

    def show_proxy_interception(self):
        self.clear_container()
        ProxyInterceptionModule(self.container)

    def show_xss(self):
        self.clear_container()
        XSSModule(self.container)
        
    def show_sql_injection(self):
        self.clear_container()
        SQLInjectionModule(self.container)
        
    def show_http_flood(self):
        self.clear_container()
        HTTPFloodModule(self.container)
        
    def show_bruteforce(self):
        self.clear_container()
        BruteForceModule(self.container)

    def show_bof(self):
        self.clear_container()
        BufferOverflowModule(self.container)

    def show_dir_scanner(self):
        self.clear_container()
        DirectoryScannerModule(self.container)

    def show_verbose_errors(self):
        self.clear_container()
        VerboseErrorModule(self.container)

    def show_path_traversal(self):
        self.clear_container()
        PathTraversalModule(self.container)

    def show_general_scan(self):
        self.clear_container()
        GeneralScanModule(self.container)


if __name__ == "__main__":
    ThinkerApp().mainloop()