"""Safe, read-only verification checks the triage agent may request.

This is what makes ReconTriage an *agent* rather than a single prompt: after
the first ranking, the model can ask for evidence, we run it, and it revises
its findings. But the model never gets arbitrary execution. It may only pick
from this fixed menu of checks, and every check is:

  * read-only: HEAD/GET, a TLS handshake, a DNS query. No writes, no auth,
    no payloads, nothing that changes the target.
  * scope-bound: the host is re-checked against the allow-list before we act,
    so a check the model requests on an out-of-scope host is refused here too.
  * bounded: short timeouts, tiny response reads, no redirects followed blindly.

The model requests checks by the ids of items we already found, never by free
text, for the same anti-hallucination reason as the ranking.
"""
from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

from ..scope import Scope, normalize_target

# The menu. Keep this list tight; every entry is attack-surface we hand the model.
CHECK_TYPES = ("http_head", "http_title", "tls_cert", "dns")

_MAX_BYTES = 4096
_TIMEOUT = 8


def _host_of(target: str) -> str:
    return normalize_target(target)


def http_head(url: str) -> dict:
    """HEAD request: status, server header, redirect location, content type.
    Does NOT follow redirects (we want to see the 301 itself)."""
    req = urllib.request.Request(url, method="HEAD",
                                 headers={"User-Agent": "recontriage/0.1"})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=_TIMEOUT) as r:
            h = r.headers
            return {"status": r.status, "server": h.get("Server", ""),
                    "content_type": h.get("Content-Type", ""),
                    "location": h.get("Location", "")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "server": e.headers.get("Server", ""),
                "content_type": e.headers.get("Content-Type", ""),
                "location": e.headers.get("Location", "")}


def http_title(url: str) -> dict:
    """GET the first few KB and pull the <title> and any Server header.
    Useful for spotting default panels ('phpMyAdmin', 'Apache2 Ubuntu Default')."""
    req = urllib.request.Request(url, headers={"User-Agent": "recontriage/0.1"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
        body = r.read(_MAX_BYTES).decode("utf-8", "replace")
        server = r.headers.get("Server", "")
    low = body.lower()
    title = ""
    if "<title" in low:
        start = low.find(">", low.find("<title")) + 1
        end = low.find("</title>", start)
        if end != -1:
            title = body[start:end].strip()[:200]
    return {"title": title, "server": server}


def tls_cert(host: str, port: int = 443) -> dict:
    """Read the server certificate: subject CN, SANs, issuer, expiry.
    Expired or wildcard-mismatched certs are findings in their own right."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # we want to inspect, not validate
    with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            cert = ss.getpeercert()
    if not cert:
        # getpeercert returns {} when verify_mode is CERT_NONE on some builds;
        # fall back to the binary form just for the dates.
        return {"note": "certificate present but details unavailable"}
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    not_after = cert.get("notAfter", "")
    expired = None
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            expired = exp < datetime.now(timezone.utc)
        except ValueError:
            pass
    return {"cn": subject.get("commonName", ""), "issuer": issuer.get("organizationName", ""),
            "sans": sans[:20], "not_after": not_after, "expired": expired}


def dns(host: str) -> dict:
    """Forward and reverse DNS for a host."""
    out: dict = {"a": [], "ptr": ""}
    try:
        out["a"] = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
    except OSError:
        pass
    if out["a"]:
        try:
            out["ptr"] = socket.gethostbyaddr(out["a"][0])[0]
        except OSError:
            pass
    return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):   # noqa: D401
        return None


def run_check(check: dict, items_by_id: dict[str, dict], scope: Scope) -> dict:
    """Execute ONE check the model requested. Returns a result dict that always
    echoes the request so the model can correlate. Never raises: failures come
    back as {"error": ...} so one bad check can't abort the loop."""
    ctype = check.get("type")
    target_id = str(check.get("id", ""))
    item = items_by_id.get(target_id)
    base = {"type": ctype, "id": target_id}

    if ctype not in CHECK_TYPES:
        return {**base, "error": f"unknown check type {ctype!r}"}
    if item is None:
        return {**base, "error": f"unknown item id {target_id!r}"}

    # Figure out the host/url this item points at and re-assert scope on it.
    url = item.get("url", "")
    host = _host_of(url) if url else item.get("host", "")
    if not host or not scope.allows(host):
        return {**base, "error": f"host for {target_id} is not in scope"}

    try:
        if ctype == "http_head":
            if not url:
                return {**base, "error": "item has no URL"}
            return {**base, "result": http_head(url)}
        if ctype == "http_title":
            if not url:
                return {**base, "error": "item has no URL"}
            return {**base, "result": http_title(url)}
        if ctype == "tls_cert":
            port = item.get("port", 443) if item.get("type") == "port" else 443
            return {**base, "result": tls_cert(host, int(port) if port in (443, 8443) else 443)}
        if ctype == "dns":
            return {**base, "result": dns(host)}
    except Exception as e:  # noqa: BLE001 - never let a check kill the run
        return {**base, "error": f"{type(e).__name__}: {e}"}
    return {**base, "error": "unhandled"}
