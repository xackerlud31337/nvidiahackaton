"""Allow-list guard.

This runs BEFORE any scanning. If the target is not listed in the scope file,
nothing else in the pipeline is allowed to touch it.

Scope file format: one entry per line, '#' starts a comment.
    example.com          exact hostname
    *.example.com        any subdomain of example.com (not example.com itself)
    10.10.11.0/24        network in CIDR notation
    192.168.1.50         single IP (treated as a /32 network)
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

# Either IPv4 or IPv6 network; ipaddress picks the right class for us.
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class OutOfScopeError(Exception):
    """Raised when a target is not covered by the scope file."""

    def __init__(self, target: str) -> None:
        super().__init__(
            f"'{target}' is not in the authorized scope. "
            "Add it to the scope file only if you are allowed to test it."
        )
        self.target = target


@dataclass
class Scope:
    hosts: set[str] = field(default_factory=set)        # "example.com"
    wildcards: set[str] = field(default_factory=set)    # "example.com" from "*.example.com"
    networks: list[Network] = field(default_factory=list)

    def allows(self, target: str) -> bool:
        host = normalize_target(target)
        if not host:
            return False

        # 1. IP address?  Check it against the networks.
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            addr = None
        if addr is not None:
            return any(addr in net for net in self.networks)

        # 2. Exact hostname match.
        if host in self.hosts:
            return True

        # 3. Wildcard match. We require the DOT before the suffix so that
        #    "evil-example.com" does not match "*.example.com".
        #    Decision: "*.example.com" does NOT match bare "example.com".
        #    If you want the apex too, list it as its own line. Explicit > clever.
        return any(host.endswith("." + suffix) for suffix in self.wildcards)


def normalize_target(target: str) -> str:
    """Turn whatever the user typed into a bare lowercase hostname or IP.

    'HTTPS://Api.Example.com:8080/login'  ->  'api.example.com'
    'example.com.'                        ->  'example.com'
    """
    t = target.strip().lower()
    if "://" in t:
        # urlsplit gives us .hostname with port and path already stripped
        t = urlsplit(t).hostname or ""
    elif ":" in t and t.count(":") == 1:
        # "host:8080" without a scheme. IPv6 has many colons, so only strip
        # the port when there is exactly one.
        t = t.split(":", 1)[0]
    return t.rstrip(".")


def load_scope(path: str | Path) -> Scope:
    scope = Scope()
    for raw in Path(path).read_text().splitlines():
        line = raw.split("#", 1)[0].strip().lower()   # drop comments and whitespace
        if not line:
            continue
        if line.startswith("*."):
            scope.wildcards.add(line[2:])
            continue
        try:
            # strict=False lets "10.10.11.5/24" through instead of complaining
            # that host bits are set. A bare IP becomes a /32 (or /128).
            scope.networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            scope.hosts.add(line.rstrip("."))
    return scope


def assert_in_scope(target: str, scope: Scope) -> None:
    """The one function the CLI calls. Raises instead of returning False so the
    caller can't forget to check the result."""
    if not scope.allows(target):
        raise OutOfScopeError(target)
