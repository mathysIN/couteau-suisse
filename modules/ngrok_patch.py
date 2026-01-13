"""Patch common HTTP clients to add ngrok-skip-browser-warning: 1 on HTTPS calls."""
from urllib.parse import urlparse

NGROK_HDR = "ngrok-skip-browser-warning"
NGROK_VAL = "1"


def _is_https(url) -> bool:
    try:
        return urlparse(str(url)).scheme.lower() == "https"
    except Exception:
        return False


# requests: patch Session.request and Session.send
try:
    import requests

    _orig_requests_session_request = requests.Session.request
    _orig_requests_session_send = requests.Session.send

    def _patched_requests_session_request(self, method, url, *args, **kwargs):
        try:
            headers = kwargs.get("headers")
            if headers is None:
                headers = {}
            elif not isinstance(headers, dict):
                try:
                    headers = dict(headers)
                except Exception:
                    headers = {}
            if _is_https(url) and not any(k.lower() == NGROK_HDR.lower() for k in headers.keys()):
                headers.setdefault(NGROK_HDR, NGROK_VAL)
            kwargs["headers"] = headers
        except Exception:
            pass
        return _orig_requests_session_request(self, method, url, *args, **kwargs)

    def _patched_requests_session_send(self, request, *args, **kwargs):
        try:
            if _is_https(getattr(request, "url", None)):
                existing = {k.lower() for k in request.headers.keys()}
                if NGROK_HDR.lower() not in existing:
                    request.headers.setdefault(NGROK_HDR, NGROK_VAL)
        except Exception:
            pass
        return _orig_requests_session_send(self, request, *args, **kwargs)

    requests.Session.request = _patched_requests_session_request
    requests.Session.send = _patched_requests_session_send
except Exception:
    pass


# urllib.request.urlopen
try:
    import urllib.request as _urllib_request

    _orig_urlopen = _urllib_request.urlopen

    def _patched_urlopen(req, *args, **kwargs):
        try:
            if isinstance(req, str):
                if _is_https(req):
                    headers = kwargs.get("headers") or {}
                    if not isinstance(headers, dict):
                        try:
                            headers = dict(headers)
                        except Exception:
                            headers = {}
                    headers.setdefault(NGROK_HDR, NGROK_VAL)
                    kwargs["headers"] = headers
            else:
                try:
                    existing = {k.lower() for k, v in req.header_items()}
                except Exception:
                    existing = set()
                if _is_https(getattr(req, "full_url", None)) and NGROK_HDR.lower() not in existing:
                    req.add_header(NGROK_HDR, NGROK_VAL)
        except Exception:
            pass
        return _orig_urlopen(req, *args, **kwargs)

    _urllib_request.urlopen = _patched_urlopen
except Exception:
    pass


# urllib3 PoolManager.request
try:
    import urllib3

    _orig_poolmanager_request = urllib3.poolmanager.PoolManager.request

    def _patched_poolmanager_request(self, method, url, *args, **kwargs):
        try:
            headers = kwargs.get("headers") or {}
            if not isinstance(headers, dict):
                try:
                    headers = dict(headers)
                except Exception:
                    headers = {}
            if _is_https(url) and not any(k.lower() == NGROK_HDR.lower() for k in headers.keys()):
                headers.setdefault(NGROK_HDR, NGROK_VAL)
            kwargs["headers"] = headers
        except Exception:
            pass
        return _orig_poolmanager_request(self, method, url, *args, **kwargs)

    urllib3.poolmanager.PoolManager.request = _patched_poolmanager_request
except Exception:
    pass


# httpx.Client.request
try:
    import httpx

    _orig_httpx_client_request = httpx.Client.request

    def _patched_httpx_request(self, method, url, *args, **kwargs):
        try:
            headers = kwargs.get("headers") or {}
            if not isinstance(headers, dict):
                try:
                    headers = dict(headers)
                except Exception:
                    headers = {}
            if _is_https(url) and not any(k.lower() == NGROK_HDR.lower() for k in headers.keys()):
                headers.setdefault(NGROK_HDR, NGROK_VAL)
            kwargs["headers"] = headers
        except Exception:
            pass
        return _orig_httpx_client_request(self, method, url, *args, **kwargs)

    httpx.Client.request = _patched_httpx_request
except Exception:
    pass


# aiohttp ClientSession._request (async)
try:
    import aiohttp

    _orig_aiohttp_request = aiohttp.ClientSession._request

    async def _patched_aiohttp_request(self, method, url, *args, **kwargs):
        try:
            headers = kwargs.get("headers") or {}
            if not isinstance(headers, dict):
                try:
                    headers = dict(headers)
                except Exception:
                    headers = {}
            if _is_https(url) and not any(k.lower() == NGROK_HDR.lower() for k in headers.keys()):
                headers.setdefault(NGROK_HDR, NGROK_VAL)
            kwargs["headers"] = headers
        except Exception:
            pass
        return await _orig_aiohttp_request(self, method, url, *args, **kwargs)

    aiohttp.ClientSession._request = _patched_aiohttp_request
except Exception:
    pass
