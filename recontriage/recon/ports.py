"""Port / service fingerprinting via nmap.

We don't reimplement port scanning. nmap is the industry tool, it's installed,
and it can emit XML, which is far easier to parse reliably than its human
output. So this module is just: run nmap, parse XML, return our common dict
shape.

Output shape (one dict per OPEN port):
    {
        "type": "port",
        "host": "45.33.32.156",
        "port": 22,
        "proto": "tcp",
        "service": "ssh",
        "product": "OpenSSH",
        "version": "6.6.1p1 Ubuntu 2ubuntu2.13",
        "extra": "Ubuntu Linux; protocol 2.0",
        "tunnel": "",
        "source": "nmap",
    }

The parsing is split from the scanning so the parser can be tested against a
saved XML file without touching the network.
"""
from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Turn nmap's -oX output into a list of open-port dicts.

    nmap XML looks like this (trimmed):

        <nmaprun>
          <host>
            <address addr="45.33.32.156" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="22">
                <state state="open" .../>
                <service name="ssh" product="OpenSSH" version="6.6.1p1" extrainfo="..."/>
              </port>
            </ports>
          </host>
        </nmaprun>

    Note that product/version/extrainfo are ATTRIBUTES of <service>, not child
    elements, and any of them (including <service> itself) can be absent.
    """
    root = ET.fromstring(xml_text)
    results: list[dict] = []

    for host in root.iter("host"):
        # Prefer the IPv4 address; fall back to whatever address is there.
        # (ElementTree elements must be compared with "is None", never used
        # as booleans: an element with no children is falsy, which is a trap.)
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        host_addr = addr_el.get("addr", "") if addr_el is not None else ""

        for port in host.iter("port"):
            state = port.find("state")
            # Closed and filtered ports also appear in the XML. We only care
            # about open ones; the rest are noise for triage.
            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            # .get(name, "") means "missing attribute -> empty string" instead
            # of a crash. Services nmap couldn't identify have no <service>.
            get = service.get if service is not None else (lambda _k, d="": d)

            results.append({
                "type": "port",
                "host": host_addr,
                "port": int(port.get("portid", 0)),
                "proto": port.get("protocol", "tcp"),
                "service": get("name", ""),
                "product": get("product", ""),
                "version": get("version", ""),
                "extra": get("extrainfo", ""),
                # "ssl" when nmap saw TLS on the port (e.g. https). The
                # pipeline uses this to pick http:// vs https:// for ffuf.
                "tunnel": get("tunnel", ""),
                "source": "nmap",
            })
    return results


def scan_ports(target: str, top_ports: int = 1000, timeout: int = 600) -> list[dict]:
    """Run nmap against ONE target and return the parsed open ports.

    Flags:
        -sV           probe open ports to identify service/version (the
                      fingerprint the triage model needs)
        -T4           faster timing; fine for authorized targets
        --top-ports N scan nmap's N most common ports instead of all 65535.
                      1000 is nmap's default and a good speed/coverage tradeoff.
        -oX -         write XML to stdout ("-") so we never touch a temp file

    The command is a LIST, not a string. That means the target is passed as a
    single argument and can never be interpreted as extra shell commands,
    even if someone types something weird. Never build shell strings from
    user input.
    """
    cmd = ["nmap", "-sV", "-T4", "--top-ports", str(top_ports), "-oX", "-", target]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        raise RuntimeError("nmap is not installed or not on PATH") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"nmap timed out after {timeout}s on {target}") from None

    if result.returncode != 0:
        raise RuntimeError(f"nmap failed (exit {result.returncode}): {result.stderr.strip()}")

    return parse_nmap_xml(result.stdout)
