"""Subdomain discovery via Certificate Transparency logs (crt.sh).

Why CT logs and not brute-force or subfinder?
  * Passive: we never send a packet to the target. We ask crt.sh, a public
    database of every TLS certificate ever issued. Any cert for
    "api.example.com" means that name exists (or existed).
  * Zero dependencies: a single HTTPS GET with the standard library.
  * Good enough for v1. Real tools like subfinder combine ~30 sources; we can
    add more later if there's time.

After discovery we resolve each name with DNS so the triage layer knows
which ones are actually live, and so the port scanner has IPs to work with.

Output shape:
    {"type": "subdomain", "host": "api.example.com", "ip": "93.184.216.34", "source": "crt.sh"}
    ("ip" is "" when the name no longer resolves; those are still worth
     reporting - dangling names are a classic takeover finding.)
"""
from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

CRTSH_URL = "https://crt.sh/?q={query}&output=json"


def fetch_crtsh(domain: str, timeout: int = 60) -> list[dict]:
    """GET the raw JSON from crt.sh for `*.domain` plus the domain itself.

    crt.sh is a free community service and is sometimes slow or returns 502.
    We retry a couple of times and otherwise raise, so the caller can decide
    to continue without subdomains rather than crash the whole run.
    """
    # "%.example.com" is SQL LIKE syntax: crt.sh is literally a Postgres
    # front end. URL-encoding turns % into %25.
    url = CRTSH_URL.format(query=urllib.parse.quote(f"%.{domain}"))
    req = urllib.request.Request(url, headers={"User-Agent": "recontriage/0.1"})
    last_err: Exception | None = None
    for _attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:  # noqa: BLE001 - we really do want to retry anything here
            last_err = e
    raise RuntimeError(f"crt.sh lookup failed for {domain}: {last_err}")


def parse_crtsh(entries: list[dict], domain: str) -> list[str]:
    """Extract a sorted, de-duplicated list of hostnames from crt.sh JSON.

    Each entry has "name_value", which can hold SEVERAL names separated by
    newlines (one cert covering many hosts). Names may be wildcards like
    "*.example.com" which are not real hosts, so we drop the "*." prefix.
    We also keep only names that end in the domain we asked about; crt.sh's
    LIKE query can occasionally match more than intended.
    """
    found: set[str] = set()
    suffix = "." + domain.lower()
    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name == domain.lower() or name.endswith(suffix):
                found.add(name)
    return sorted(found)


def resolve(host: str) -> str:
    """Return the first IPv4 for host, or "" if it doesn't resolve."""
    try:
        return socket.gethostbyname(host)
    except OSError:
        return ""


def discover_subdomains(domain: str, resolve_dns: bool = True, workers: int = 20) -> list[dict]:
    """Full module entry point: crt.sh -> parse -> (optionally) DNS-resolve.

    DNS resolution is done in a thread pool because each lookup is a slow
    network round-trip and they're independent of each other. 20 workers
    turns 200 lookups from ~minutes into a few seconds.
    """
    names = parse_crtsh(fetch_crtsh(domain), domain)
    if resolve_dns and names:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            ips = list(pool.map(resolve, names))
    else:
        ips = [""] * len(names)

    return [
        {"type": "subdomain", "host": name, "ip": ip, "source": "crt.sh"}
        for name, ip in zip(names, ips)
    ]
