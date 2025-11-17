import tkinter as tk
from tkinter import ttk
from modules.portscanner import PortScannerModule
from modules.crsf import CRSFModule
from modules.xss_injection import XSSModule
from modules.sql_injection import SQLInjectionModule


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
            ("Port Scanner", self.show_port_scanner),
            ("CSRF", self.show_crsf),
            ("XSS Injection", self.show_xss)
            ("SQL Injection", self.show_sql_injection)
        ]

        for i, (label, action) in enumerate(modules):
            frame = tk.Frame(self.module_frame, bg="#1e1e1e")
            frame.grid(row=0, column=i, padx=20)
            btn = ttk.Button(frame, text=label, command=action)
            btn.pack()

        self.container = tk.Frame(self, bg="#1e1e1e")
        self.container.pack(fill="both", expand=True, padx=20, pady=10)

    def clear_container(self):
        for w in self.container.winfo_children():
            w.destroy()

    def show_port_scanner(self):
        self.clear_container()
        PortScannerModule(self.container)

    def show_crsf(self):
        self.clear_container()
        CRSFModule(self.container)

    def show_xss(self):
        self.clear_container()
        XSSModule(self.container)
    def show_sql_injection(self):
        self.clear_container()
        SQLInjectionModule(self.container)


if __name__ == "__main__":
    ThinkerApp().mainloop()