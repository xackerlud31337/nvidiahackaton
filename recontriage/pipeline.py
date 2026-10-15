"""End-to-end orchestration: scope check -> recon -> triage -> note.

This is the only place that knows about *all* the modules. The CLI just
parses flags, calls run(), and prints. Keeping the pipeline free of
printing/argparse means it can be reused by a web UI or tests later.

Order of operations and the safety rule:
    1. Load scope, assert the user's target is in it. Nothing runs before this.
    2. Subdomain discovery (domains only; passive, crt.sh).
    3. For each host we will actively scan: assert_in_scope AGAIN. A subdomain
       from crt.sh is only scanned if the scope file covers it.
    4. nmap on each unique host, ffuf on each web port found.
    5. Nemotron triage (Nano enrich + Ultra rank), then Ultra drafts the note.
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Callable

from .recon.dirs import DEFAULT_WORDLIST, brute_force_dirs
from .recon.ports import scan_ports
from .recon.subdomains import discover_subdomains, resolve
from .scope import Scope, assert_in_scope, load_scope, normalize_target
from .triage.client import NemotronClient
from .triage.note import draft_note
from .triage.rank import triage

WEB_SERVICES = {"http", "https", "http-proxy", "http-alt", "ssl/http", "upnp", "tomcat"}
WEB_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888}


@dataclass
class Options:
    scope_path: str = "scope.txt"
    skip_subdomains: bool = False
    skip_dirs: bool = False
    no_llm: bool = False
    top_ports: int = 1000
    max_hosts: int = 5           # cap on hosts we actively scan per run
    top_n: int = 10              # findings to ask Ultra for
    wordlist: str = str(DEFAULT_WORDLIST)
    log: Callable[[str], None] = field(default=print)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _web_url(host: str, port: dict) -> str | None:
    """Decide whether an open port is a web server and build its base URL."""
    svc = port["service"]
    if svc not in WEB_SERVICES and port["port"] not in WEB_PORTS:
        return None
    https = port["tunnel"] == "ssl" or svc == "https" or port["port"] in (443, 8443)
    scheme = "https" if https else "http"
    default = (scheme == "http" and port["port"] == 80) or (scheme == "https" and port["port"] == 443)
    return f"{scheme}://{host}" if default else f"{scheme}://{host}:{port['port']}"


def run(target: str, opts: Options | None = None) -> dict:
    opts = opts or Options()
    log = opts.log
    started = time.time()

    # ---- 1. scope guard --------------------------------------------------
    scope: Scope = load_scope(opts.scope_path)
    target = normalize_target(target)
    assert_in_scope(target, scope)
    log(f"[scope] {target} is in scope ({opts.scope_path})")

    items: list[dict] = []
    hosts: list[str] = [target]

    # ---- 2. subdomains (passive) ----------------------------------------
    if not _is_ip(target) and not opts.skip_subdomains:
        log(f"[subdomains] querying crt.sh for *.{target}")
        try:
            subs = discover_subdomains(target)
        except RuntimeError as e:
            log(f"[subdomains] skipped: {e}")
            subs = []
        items.extend(subs)
        live = [s for s in subs if s["ip"]]
        log(f"[subdomains] {len(subs)} names, {len(live)} resolve")
        for s in live:
            if s["host"] not in hosts and scope.allows(s["host"]):
                hosts.append(s["host"])

    # ---- 3+4. active recon per host --------------------------------------
    seen_ips: set[str] = set()
    scanned = 0
    for host in hosts:
        if scanned >= opts.max_hosts:
            log(f"[ports] host cap ({opts.max_hosts}) reached; skipping the rest")
            break
        assert_in_scope(host, scope)                 # belt and braces
        ip = host if _is_ip(host) else resolve(host)
        if ip in seen_ips:
            log(f"[ports] {host} shares IP {ip} with a scanned host; skipping nmap")
            continue
        seen_ips.add(ip)
        scanned += 1

        log(f"[ports] nmap -sV --top-ports {opts.top_ports} {host}")
        try:
            ports = scan_ports(host, top_ports=opts.top_ports)
        except RuntimeError as e:
            log(f"[ports] failed on {host}: {e}")
            continue
        items.extend(ports)
        log(f"[ports] {len(ports)} open on {host}: " + ", ".join(f"{p['port']}/{p['service'] or '?'}" for p in ports))

        if opts.skip_dirs:
            continue
        for p in ports:
            url = _web_url(host, p)
            if not url:
                continue
            log(f"[dirs] ffuf {url}/FUZZ")
            try:
                hits = brute_force_dirs(url, wordlist=opts.wordlist)
            except RuntimeError as e:
                log(f"[dirs] failed on {url}: {e}")
                continue
            items.extend(hits)
            log(f"[dirs] {len(hits)} hits on {url}")

    result = {
        "target": target,
        "started": started,
        "items": items,
        "findings": [],
        "notes": {},
        "note": "",
        "usage": "",
    }

    # ---- 5. triage -------------------------------------------------------
    if opts.no_llm:
        log("[triage] skipped (--no-llm)")
        return result
    if not items:
        log("[triage] nothing to triage")
        return result

    client = NemotronClient()
    log(f"[triage] Nemotron Nano enriching {len(items)} items")
    tri = triage(client, target, items, top_n=opts.top_n)
    log(f"[triage] Nemotron Ultra ranked {len(tri['findings'])} findings")
    result["items"] = tri["items"]
    result["notes"] = tri["notes"]
    result["findings"] = tri["findings"]

    if tri["findings"]:
        log("[note] Nemotron Ultra drafting note for #1")
        result["note"] = draft_note(client, target, tri["findings"][0], tri["items"])

    result["usage"] = client.usage.summary()
    result["elapsed"] = round(time.time() - started, 1)
    return result
