import tkinter as tk
from tkinter import ttk
import threading
import asyncio
import queue
import os
import json
import re
from typing import Callable, Dict, Optional, Set, Tuple
import subprocess
import tempfile
import sys

try:
    from mitmproxy import http
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster
    MITMPROXY_AVAILABLE = True
except Exception:
    MITMPROXY_AVAILABLE = False


TOKEN_NAME_CANDIDATES = [
    "csrf", "_csrf", "xsrf", "_xsrf",
    "csrf_token", "xsrf_token", "x_csrf_token", "x_xsrf_token",
    "authenticity_token", "__RequestVerificationToken",
    "anti_csrf", "anti_forgery", "anti_forger"
]

TOKEN_HEADER_CANDIDATES = [
    "x-csrf-token", "x-xsrf-token", "x-request-verification-token"
]


class CsrfAddon:
    def __init__(self, log_fn: Callable[[str], None], scope_pattern: Optional[str] = None,
                 probe_mode: bool = False) -> None:
        self.log_fn = log_fn
        self.probe_mode = probe_mode
        self.scope_re = re.compile(scope_pattern) if scope_pattern else None

        self.host_to_token_names: Dict[str, Set[str]] = {}
        self.probed_flow_ids: Dict[str, Tuple[str, str]] = {}

        token_name_regex = r"|".join([re.escape(n) for n in TOKEN_NAME_CANDIDATES])
        self.hidden_input_re = re.compile(
            rf"<input[^>]*type=['\"]hidden['\"][^>]*name=['\"]([^'\"]*?(?:{token_name_regex})[^'\"]*)['\"][^>]*value=['\"]([^'\"]*)['\"][^>]*>",
            re.IGNORECASE
        )
        self.meta_token_re = re.compile(
            r"<meta[^>]*name=['\"]csrf-token['\"][^>]*content=['\"]([^'\"]*)['\"][^>]*>",
            re.IGNORECASE
        )

    def _in_scope(self, flow: "http.HTTPFlow") -> bool:
        if not self.scope_re:
            return True
        host = flow.request.host
        url = flow.request.pretty_url
        return bool(self.scope_re.search(host) or self.scope_re.search(url))

    def _record_token_name(self, host: str, name: str) -> None:
        if not name:
            return
        names = self.host_to_token_names.setdefault(host, set())
        if name not in names:
            names.add(name)
            self.log_fn(f"[+] Learned CSRF token field '{name}' for host {host}")

    def _discover_tokens_from_html(self, host: str, content: bytes) -> None:
        try:
            text = content.decode("utf-8", errors="ignore")
        except Exception:
            return
        for m in self.hidden_input_re.finditer(text):
            name = m.group(1)
            self._record_token_name(host, name)
        for m in self.meta_token_re.finditer(text):
            self._record_token_name(host, "header:x-csrf-token")

    def _extract_params(self, flow: "http.HTTPFlow") -> Dict[str, str]:
        params: Dict[str, str] = {}
        try:
            for k, v in flow.request.query.items(multi=True):
                params[k] = v
        except Exception:
            pass
        ctype = flow.request.headers.get("content-type", "").lower()
        body_bytes = flow.request.raw_content or b""
        if "application/x-www-form-urlencoded" in ctype:
            try:
                for k, v in flow.request.urlencoded_form.items(multi=True):
                    params[k] = v
            except Exception:
                try:
                    from urllib.parse import parse_qsl
                    for k, v in parse_qsl(body_bytes.decode("utf-8", errors="ignore")):
                        params[k] = v
                except Exception:
                    pass
        elif "multipart/form-data" in ctype:
            try:
                if flow.request.multipart_form:
                    for k, v in flow.request.multipart_form.items(multi=True):
                        if isinstance(v, bytes):
                            try:
                                params[k] = v.decode("utf-8", errors="ignore")
                            except Exception:
                                params[k] = "[bytes]"
                        else:
                            params[k] = v
            except Exception:
                pass
        elif "application/json" in ctype:
            try:
                obj = json.loads(body_bytes.decode("utf-8", errors="ignore"))
                def flatten(prefix: str, value):
                    if isinstance(value, dict):
                        for kk, vv in value.items():
                            flatten(f"{prefix}.{kk}" if prefix else kk, vv)
                    else:
                        params[prefix] = str(value)
                flatten("", obj)
            except Exception:
                pass
        return params

    def _has_csrf_signal(self, flow: "http.HTTPFlow", params: Dict[str, str]) -> bool:
        headers = {k.lower(): v for k, v in flow.request.headers.items()}
        for h in TOKEN_HEADER_CANDIDATES:
            if h in headers and headers[h]:
                return True
        host = flow.request.host
        names_for_host = set(self.host_to_token_names.get(host, set()))
        lower_to_original = {k.lower(): k for k in params.keys()}
        for candidate in TOKEN_NAME_CANDIDATES:
            if candidate in lower_to_original:
                return True
        for learned in names_for_host:
            key_lower = learned.lower()
            if key_lower.startswith("header:"):
                continue
            if key_lower in lower_to_original:
                return True
        return False

    def request(self, flow: "http.HTTPFlow") -> None:
        if not self._in_scope(flow):
            return
        method = flow.request.method.upper()
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return
        params = self._extract_params(flow)
        has_token = self._has_csrf_signal(flow, params)
        target = f"{flow.request.method} {flow.request.pretty_url}"
        if not has_token:
            self.log_fn(f"[!] Potential CSRF: no token in {target}")
        elif self.probe_mode:
            removed_any = False
            for h in list(flow.request.headers.keys()):
                if h.lower() in TOKEN_HEADER_CANDIDATES:
                    removed_any = True
                    del flow.request.headers[h]
            body_was_modified = False
            ctype = flow.request.headers.get("content-type", "").lower()
            if "application/x-www-form-urlencoded" in ctype:
                try:
                    q = flow.request.urlencoded_form
                    keys_to_remove = []
                    for k in q.keys():
                        if any(t in k.lower() for t in TOKEN_NAME_CANDIDATES):
                            keys_to_remove.append(k)
                    for k in keys_to_remove:
                        removed_any = True
                        del q[k]
                    flow.request.urlencoded_form = q
                    body_was_modified = True
                except Exception:
                    pass
            elif "application/json" in ctype:
                try:
                    obj = json.loads(flow.request.get_text(strict=False) or "{}")
                    def strip_tokens(o):
                        if isinstance(o, dict):
                            for k in list(o.keys()):
                                if any(t in k.lower() for t in TOKEN_NAME_CANDIDATES):
                                    del o[k]
                                else:
                                    strip_tokens(o[k])
                        elif isinstance(o, list):
                            for it in o:
                                strip_tokens(it)
                    strip_tokens(obj)
                    flow.request.set_text(json.dumps(obj))
                    body_was_modified = True
                except Exception:
                    pass
            if removed_any or body_was_modified:
                self.probed_flow_ids[flow.id] = (flow.request.method, flow.request.path)
                self.log_fn(f"[*] Probe: removed CSRF token(s) from {target}")

    def response(self, flow: "http.HTTPFlow") -> None:
        if not self._in_scope(flow):
            return
        host = flow.request.host
        ctype = (flow.response.headers.get("content-type", "").split(";")[0]).lower()
        if "text/html" in ctype or "application/xhtml" in ctype:
            self._discover_tokens_from_html(host, flow.response.raw_content or b"")
        if flow.id in self.probed_flow_ids:
            method, path = self.probed_flow_ids.pop(flow.id, (flow.request.method, flow.request.path))
            status = flow.response.status_code
            if 200 <= status < 300:
                self.log_fn(f"[!] Probe result: {method} {path} accepted WITHOUT CSRF token (HTTP {status})")
            elif status in {400, 401, 403}:
                self.log_fn(f"[+] Probe result: {method} {path} rejected as expected (HTTP {status})")
            else:
                self.log_fn(f"[-] Probe result: {method} {path} returned HTTP {status} (inconclusive)")


class MitmProxyRunner:
    def __init__(self, log_fn: Callable[[str], None]) -> None:
        self.log_fn = log_fn
        self.master: Optional[DumpMaster] = None
        self.thread: Optional[threading.Thread] = None
        self.proc: Optional[subprocess.Popen] = None
        self.proc_reader_thread: Optional[threading.Thread] = None
        self.temp_script_path: Optional[str] = None

    def start(self, listen_host: str, listen_port: int, upstream: Optional[str],
              scope_pattern: Optional[str], probe_mode: bool) -> None:
        if self.proc is not None or self.master is not None:
            self.log_fn("[!] Proxy already running")
            return
        self._start_mitmdump_subprocess(listen_host, listen_port, upstream, scope_pattern, probe_mode)

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
                                   scope_pattern: Optional[str], probe_mode: bool) -> None:
        try:
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            script_code = self._generate_addon_script(scope_pattern, probe_mode)
            fd, path = tempfile.mkstemp(prefix="csrf_addon_", suffix=".py")
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

    def _generate_addon_script(self, scope_pattern: Optional[str], probe_mode: bool) -> str:
        sp = (scope_pattern or "")
        pm = "True" if probe_mode else "False"
        return (
            "from modules.crsf import CsrfAddon\n"
            "def _log(msg: str):\n"
            "    print(msg, flush=True)\n"
            f"addons = [CsrfAddon(_log, scope_pattern={sp!r} if {bool(sp)!r} else None, probe_mode={pm})]\n"
        )


class CRSFModule(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.pack(fill="both", expand=True)

        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self.runner = MitmProxyRunner(self._enqueue_log)

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

        ttk.Label(row, text="Upstream proxy (host:port or scheme://host:port):").pack(side="left")
        self.upstream = ttk.Entry(row, width=28)
        default_upstream = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or ""
        if default_upstream:
            self.upstream.insert(0, default_upstream)
        self.upstream.pack(side="left", padx=(5, 15))

        row2 = tk.Frame(self, bg="#1e1e1e")
        row2.pack(fill="x", pady=(8, 0))
        ttk.Label(row2, text="Scope (regex, optional):").pack(side="left")
        self.scope = ttk.Entry(row2)
        self.scope.insert(0, "")
        self.scope.pack(side="left", fill="x", expand=True, padx=(5, 15))

        self.probe_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="Active probe (strip tokens)", variable=self.probe_var).pack(side="left")

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

    def _on_start(self) -> None:
        listen_host = self.listen_host.get().strip() or "127.0.0.1"
        try:
            listen_port = int(self.listen_port.get().strip() or "8081")
        except Exception:
            self._enqueue_log("[!] Invalid listen port")
            return
        upstream = self.upstream.get().strip() or None
        scope_pattern = self.scope.get().strip() or None
        probe_mode = bool(self.probe_var.get())
        self.runner.start(listen_host, listen_port, upstream, scope_pattern, probe_mode)

    def _on_stop(self) -> None:
        self.runner.stop()
