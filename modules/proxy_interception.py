import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import os
import json
import re
from typing import Callable, Dict, Optional
import subprocess
import tempfile

try:
    from mitmproxy import http
    from mitmproxy.tools.dump import DumpMaster
    MITMPROXY_AVAILABLE = True
except Exception:
    MITMPROXY_AVAILABLE = False


class ProxyInterceptionAddon:
    def __init__(self, log_fn: Callable[[str], None], scope_pattern: Optional[str] = None,
                 probe_mode: bool = False, intercept_mode: bool = False,
                 state_file: Optional[str] = None) -> None:
        self.log_fn = log_fn
        self.intercept_mode = intercept_mode
        self.scope_re = re.compile(scope_pattern) if scope_pattern else None
        self.state_file = state_file
        self.intercepted_flows: Dict[str, "http.HTTPFlow"] = {}

    def _in_scope(self, flow: "http.HTTPFlow") -> bool:
        if not self.scope_re:
            return True
        host = flow.request.host
        url = flow.request.pretty_url
        return bool(self.scope_re.search(host) or self.scope_re.search(url))

    def request(self, flow: "http.HTTPFlow") -> None:
        if self.intercept_mode:
            self._check_commands()
        
        if not self._in_scope(flow):
            return
        
        if self.intercept_mode:
            method = flow.request.method.upper()
            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                flow_id = flow.id
                self.intercepted_flows[flow_id] = flow
                target = f"{flow.request.method} {flow.request.pretty_url}"
                self.log_fn(f"[*] Intercepted request: {target} (ID: {flow_id})")
                
                if self.state_file:
                    self._save_intercepted_flow(flow_id, flow)
                else:
                    self.log_fn(f"[!] No state file set!")
                
                flow.intercept()
                return
    
    def _save_intercepted_flow(self, flow_id: str, flow: "http.HTTPFlow") -> None:
        try:
            flow_data = {
                "flow_id": flow_id,
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": dict(flow.request.headers),
                "body": flow.request.get_text(strict=False) or "",
            }
            with open(self.state_file, "w") as f:
                json.dump(flow_data, f)
        except Exception as e:
            self.log_fn(f"[!] Failed to save flow: {e}")
    
    def _check_commands(self) -> None:
        if not self.state_file:
            return
        
        cmd_file = self.state_file + ".cmd"
        if not os.path.exists(cmd_file):
            return
        
        try:
            with open(cmd_file, "r") as f:
                cmd = json.load(f)
            os.unlink(cmd_file)
            
            flow_id = cmd.get("flow_id")
            action = cmd.get("action")
            
            if flow_id not in self.intercepted_flows:
                return
            
            flow = self.intercepted_flows[flow_id]
            
            if action == "resume":
                if "headers" in cmd:
                    flow.request.headers.clear()
                    for k, v in cmd["headers"].items():
                        flow.request.headers[k] = v
                if "body" in cmd:
                    flow.request.set_content(cmd["body"].encode("utf-8"))
                flow.resume()
                del self.intercepted_flows[flow_id]
                self.log_fn(f"[*] Resumed flow {flow_id}")
            elif action == "drop":
                flow.kill()
                del self.intercepted_flows[flow_id]
                self.log_fn(f"[*] Dropped flow {flow_id}")
        except Exception as e:
            self.log_fn(f"[!] Command error: {e}")
    
    def running(self) -> None:
        if self.intercept_mode:
            self._check_commands()


class MitmProxyRunner:
    def __init__(self, log_fn: Callable[[str], None], intercept_callback: Optional[Callable] = None) -> None:
        self.log_fn = log_fn
        self.intercept_callback = intercept_callback
        self.master: Optional[DumpMaster] = None
        self.thread: Optional[threading.Thread] = None
        self.proc: Optional[subprocess.Popen] = None
        self.proc_reader_thread: Optional[threading.Thread] = None
        self.temp_script_path: Optional[str] = None
        self.state_file: Optional[str] = None

    def start(self, listen_host: str, listen_port: int, upstream: Optional[str],
              scope_pattern: Optional[str], probe_mode: bool, intercept_mode: bool = False) -> None:
        if self.proc is not None or self.master is not None:
            self.log_fn("[!] Proxy already running")
            return
        
        if intercept_mode:
            self.state_file = os.path.join(tempfile.gettempdir(), f"proxy_interception_state_{os.getpid()}.json")
        
        self._start_mitmdump_subprocess(
            listen_host, listen_port, upstream, scope_pattern, probe_mode, intercept_mode)

    def stop(self) -> None:
        if self.proc is not None:
            try:
                self.log_fn("[*] Stopping mitmdump...")
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except Exception:
                    self.proc.kill()
            finally:
                self.proc = None
            if self.proc_reader_thread is not None:
                self.proc_reader_thread.join(timeout=1)
                self.proc_reader_thread = None
            if self.temp_script_path and os.path.exists(self.temp_script_path):
                try:
                    os.unlink(self.temp_script_path)
                except Exception:
                    pass
            if self.state_file and os.path.exists(self.state_file):
                try:
                    os.unlink(self.state_file)
                    if os.path.exists(self.state_file + ".cmd"):
                        os.unlink(self.state_file + ".cmd")
                except Exception:
                    pass
            self.log_fn("[*] Proxy stopped")
            return
        if self.master is not None:
            try:
                self.master.shutdown()
            except Exception:
                pass
            self.master = None
            self.log_fn("[*] Proxy stopped")

    def _start_mitmdump_subprocess(self, listen_host: str, listen_port: int, upstream: Optional[str],
                                   scope_pattern: Optional[str], probe_mode: bool, intercept_mode: bool = False) -> None:
        try:
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            script_code = self._generate_addon_script(scope_pattern, probe_mode, intercept_mode)
            fd, path = tempfile.mkstemp(prefix="proxy_interception_addon_", suffix=".py")
            with os.fdopen(fd, "w") as f:
                f.write(script_code)
            self.temp_script_path = path

            cmd = [
                "mitmdump",
                "--listen-host", str(listen_host),
                "--listen-port", str(int(listen_port)),
                "-s", self.temp_script_path
            ]
            if upstream:
                up = upstream.strip()
                if "://" not in up:
                    up = f"http://{up}"
                cmd += ["--mode", f"upstream:{up}"]

            env = os.environ.copy()
            env["PYTHONPATH"] = project_root + os.pathsep + env.get("PYTHONPATH", "")
            if intercept_mode and self.state_file:
                env["PROXY_INTERCEPTION_STATE_FILE"] = self.state_file

            self.log_fn(f"[*] Starting mitmproxy on {listen_host}:{listen_port}" +
                        (f" via upstream {upstream}" if upstream else ""))
            self.log_fn("[*] To intercept HTTPS, trust mitmproxy CA (run 'mitmproxy' once to install)")

            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env
            )

            def _read_stdout():
                assert self.proc and self.proc.stdout
                for line in self.proc.stdout:
                    self.log_fn(line.rstrip("\n"))
                self.log_fn("[*] Subprocess output closed")

            self.proc_reader_thread = threading.Thread(target=_read_stdout, daemon=True)
            self.proc_reader_thread.start()
        except FileNotFoundError:
            self.log_fn("[!] 'mitmdump' not found. Install mitmproxy or ensure it's on PATH.")
        except Exception as e:
            self.log_fn(f"[!] Failed to start mitmdump: {e}")

    def _generate_addon_script(self, scope_pattern: Optional[str], probe_mode: bool, intercept_mode: bool = False) -> str:
        sp = (scope_pattern or "")
        pm = "True" if probe_mode else "False"
        im = "True" if intercept_mode else "False"
        state_file_str = "os.environ.get('PROXY_INTERCEPTION_STATE_FILE')" if intercept_mode else "None"
        scope_repr = repr(sp) if sp else "None"
        scope_bool = "True" if sp else "False"
        return (
            "import os\n"
            "from modules.proxy_interception import ProxyInterceptionAddon\n"
            "def _log(msg: str):\n"
            "    print(msg, flush=True)\n"
            "state_file = {}\n".format(state_file_str) +
            "_log('[PROXY INTERCEPTION] Starting with scope=' + {} + ', probe={}, intercept={}, state_file=' + str(state_file))\n".format(scope_repr, pm, im) +
            "addons = [ProxyInterceptionAddon(_log, scope_pattern={} if {} else None, probe_mode={}, intercept_mode={}, state_file=state_file)]\n".format(scope_repr, scope_bool, pm, im) +
            "_log('[PROXY INTERCEPTION] Addon loaded successfully')\n"
        )
    
    def resume_flow(self, flow_id: str, headers: Dict[str, str], body: str) -> bool:
        if not self.state_file:
            return False
        try:
            cmd_file = self.state_file + ".cmd"
            cmd = {
                "action": "resume",
                "flow_id": flow_id,
                "headers": headers,
                "body": body
            }
            with open(cmd_file, "w") as f:
                json.dump(cmd, f)
            return True
        except Exception as e:
            self.log_fn(f"[!] Failed to resume flow: {e}")
            return False
    
    def drop_flow(self, flow_id: str) -> bool:
        if not self.state_file:
            return False
        try:
            cmd_file = self.state_file + ".cmd"
            cmd = {"action": "drop", "flow_id": flow_id}
            with open(cmd_file, "w") as f:
                json.dump(cmd, f)
            return True
        except Exception as e:
            self.log_fn(f"[!] Failed to drop flow: {e}")
            return False


class ProxyInterceptionModule(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.pack(fill="both", expand=True)

        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self.runner = MitmProxyRunner(self._enqueue_log, self._on_intercepted_flow)
        self.intercept_dialogs: Dict[str, tk.Toplevel] = {}

        row = tk.Frame(self, bg="#1e1e1e")
        row.pack(fill="x")
        ttk.Label(row, text="Listen host:").pack(side="left")
        self.listen_host = ttk.Entry(row, width=14)
        self.listen_host.insert(0, "127.0.0.1")
        self.listen_host.pack(side="left", padx=(5, 15))

        ttk.Label(row, text="Listen port:").pack(side="left")
        self.listen_port = ttk.Entry(row, width=7)
        self.listen_port.insert(0, "8081")
        self.listen_port.pack(side="left", padx=(5, 15))

        row2 = tk.Frame(self, bg="#1e1e1e")
        row2.pack(fill="x", pady=(8, 0))
        ttk.Label(row2, text="Scope (regex):").pack(side="left")
        self.scope = ttk.Entry(row2)
        self.scope.insert(0, "")
        self.scope.pack(side="left", fill="x", expand=True, padx=(5, 15))

        row3 = tk.Frame(self, bg="#1e1e1e")
        row3.pack(fill="x", pady=(8, 0))
        ttk.Button(row3, text="Start Proxy", command=self._on_start).pack(side="left")
        ttk.Button(row3, text="Stop Proxy", command=self._on_stop).pack(side="left", padx=(8, 0))

        self.output = tk.Text(self, bg="#252526", fg="white", height=18)
        self.output.pack(fill="both", expand=True, pady=10)

        self.after(150, self._flush_logs)

        if not MITMPROXY_AVAILABLE:
            self._enqueue_log("[!] mitmproxy is not installed. Install with: pip install mitmproxy")

    def _enqueue_log(self, msg: str) -> None:
        self.log_queue.put(msg)

    def _flush_logs(self) -> None:
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.output.insert("end", msg + "\n")
                self.output.see("end")
        except queue.Empty:
            pass
        self.after(200, self._flush_logs)
    
    def _check_intercepted_flows(self) -> None:
        if not self.runner.state_file:
            self.after(200, self._check_intercepted_flows)
            return
        
        if os.path.exists(self.runner.state_file):
            try:
                with open(self.runner.state_file, "r") as f:
                    flow_data = json.load(f)
                os.unlink(self.runner.state_file)
                self._on_intercepted_flow(flow_data)
            except (json.JSONDecodeError, FileNotFoundError):
                pass
            except Exception as e:
                self._enqueue_log(f"[!] Error checking flows: {e}")
        
        self.after(200, self._check_intercepted_flows)

    def _on_start(self) -> None:
        listen_host = self.listen_host.get().strip() or "127.0.0.1"
        try:
            listen_port = int(self.listen_port.get().strip() or "8081")
        except Exception:
            self._enqueue_log("[!] Invalid listen port")
            return
        scope_pattern = self.scope.get().strip() or None
        if not scope_pattern:
            self._enqueue_log("[!] Scope pattern is required")
            return
        self.runner.start(listen_host, listen_port, None, scope_pattern, False, True)
        self.after(200, self._check_intercepted_flows)

    def _on_stop(self) -> None:
        self.runner.stop()
        for dialog in list(self.intercept_dialogs.values()):
            try:
                dialog.destroy()
            except Exception:
                pass
        self.intercept_dialogs.clear()
    
    def _on_intercepted_flow(self, flow_data: Dict) -> None:
        flow_id = flow_data.get("flow_id")
        if not flow_id:
            return
        self.after(0, lambda: self._show_intercept_dialog(flow_data))
    
    def _show_intercept_dialog(self, flow_data: Dict) -> None:
        flow_id = flow_data.get("flow_id")
        if flow_id in self.intercept_dialogs:
            try:
                self.intercept_dialogs[flow_id].lift()
                return
            except Exception:
                pass
        
        dialog = tk.Toplevel(self)
        dialog.title(f"Edit Request - {flow_data.get('method')} {flow_data.get('url', '')[:50]}")
        dialog.configure(bg="#1e1e1e")
        dialog.geometry("800x700")
        
        self.intercept_dialogs[flow_id] = dialog
        
        def on_close():
            if flow_id in self.intercept_dialogs:
                del self.intercept_dialogs[flow_id]
            dialog.destroy()
        
        dialog.protocol("WM_DELETE_WINDOW", on_close)
        
        info_frame = tk.Frame(dialog, bg="#1e1e1e")
        info_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(info_frame, text="Method:", background="#1e1e1e", foreground="white").pack(side="left")
        ttk.Label(info_frame, text=flow_data.get("method", ""), background="#1e1e1e", foreground="white").pack(side="left", padx=5)
        ttk.Label(info_frame, text="URL:", background="#1e1e1e", foreground="white").pack(side="left", padx=(20, 0))
        ttk.Label(info_frame, text=flow_data.get("url", ""), background="#1e1e1e", foreground="white").pack(side="left", padx=5)
        
        headers_frame = tk.LabelFrame(dialog, text="Headers", bg="#1e1e1e", fg="white")
        headers_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        headers_text = scrolledtext.ScrolledText(headers_frame, bg="#252526", fg="white", height=12, font=("Courier", 10))
        headers_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        headers = flow_data.get("headers", {})
        for key, value in headers.items():
            headers_text.insert("end", f"{key}: {value}\n")
        
        body_frame = tk.LabelFrame(dialog, text="Request Body", bg="#1e1e1e", fg="white")
        body_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        body_text = scrolledtext.ScrolledText(body_frame, bg="#252526", fg="white", height=15, font=("Courier", 10))
        body_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        body = flow_data.get("body", "")
        body_text.insert("1.0", body)
        
        button_frame = tk.Frame(dialog, bg="#1e1e1e")
        button_frame.pack(fill="x", padx=10, pady=10)
        
        def send_request():
            headers_content = headers_text.get("1.0", "end-1c")
            new_headers = {}
            for line in headers_content.split("\n"):
                line = line.strip()
                if ":" in line:
                    key, value = line.split(":", 1)
                    new_headers[key.strip()] = value.strip()
            
            new_body = body_text.get("1.0", "end-1c")
            
            if self.runner.resume_flow(flow_id, new_headers, new_body):
                self._enqueue_log(f"[*] Sent modified request for flow {flow_id}")
                on_close()
            else:
                messagebox.showerror("Error", "Failed to send request")
        
        def drop_request():
            if self.runner.drop_flow(flow_id):
                self._enqueue_log(f"[*] Dropped request for flow {flow_id}")
                on_close()
            else:
                messagebox.showerror("Error", "Failed to drop request")
        
        ttk.Button(button_frame, text="Send Request", command=send_request).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Drop Request", command=drop_request).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel", command=on_close).pack(side="right", padx=5)
