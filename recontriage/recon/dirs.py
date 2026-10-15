"""Directory / file brute-force via ffuf.

ffuf is fast and already installed; we drive it the same way we drive nmap:
run it with machine-readable output, parse, return our common dict shape.

Output shape (one dict per hit):
    {"type": "path", "url": "http://host/admin", "status": 200, "size": 1234,
     "words": 80, "redirect": "", "source": "ffuf"}

Unlike nmap, ffuf can't write JSON to stdout, only to a file, so we give it a
temporary file and read it back.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

DEFAULT_WORDLIST = Path(__file__).resolve().parents[2] / "wordlists" / "common-small.txt"


def parse_ffuf_json(text: str) -> list[dict]:
    """Parse ffuf's `-of json` output.

    The file looks like:
        {"commandline": "...", "time": "...", "results": [
            {"input": {"FUZZ": "admin"}, "status": 301, "length": 312,
             "words": 20, "lines": 10, "url": "http://host/admin",
             "redirectlocation": "http://host/admin/", ...}, ...
        ], "config": {...}}
    """
    data = json.loads(text)
    hits = []
    for r in data.get("results", []):
        hits.append({
            "type": "path",
            "url": r.get("url", ""),
            "status": int(r.get("status", 0)),
            "size": int(r.get("length", 0)),
            "words": int(r.get("words", 0)),
            "redirect": r.get("redirectlocation", "") or "",
            "source": "ffuf",
        })
    # Sort so the output is stable: interesting codes first, then by URL.
    hits.sort(key=lambda h: (h["status"], h["url"]))
    return hits


def brute_force_dirs(
    base_url: str,
    wordlist: str | Path = DEFAULT_WORDLIST,
    rate: int = 50,
    timeout: int = 600,
) -> list[dict]:
    """Run ffuf against base_url (e.g. "http://10.10.11.5") and return hits.

    Flags:
        -u URL/FUZZ    FUZZ is the placeholder ffuf replaces with each word
        -w wordlist    the words to try
        -ac            auto-calibrate: learn what a "not found" page looks like
                       on this host and drop those, so a site that returns 200
                       for everything doesn't produce 500 fake hits
        -rate N        requests per second. 50 is polite; this is recon, not a
                       stress test, and a hammered target is a bad demo
        -of json -o f  machine-readable output to file f
        -s             silent; no progress bar in our stdout
    """
    base_url = base_url.rstrip("/")
    wordlist = Path(wordlist)
    if not wordlist.exists():
        raise RuntimeError(f"wordlist not found: {wordlist}")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = Path(tmp.name)
    try:
        cmd = [
            "ffuf", "-u", f"{base_url}/FUZZ", "-w", str(wordlist),
            "-ac", "-rate", str(rate), "-of", "json", "-o", str(out_path), "-s",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        except FileNotFoundError:
            raise RuntimeError("ffuf is not installed or not on PATH") from None
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"ffuf timed out after {timeout}s on {base_url}") from None

        # ffuf exits non-zero when the target is unreachable; surface that.
        if result.returncode != 0 and not out_path.exists():
            raise RuntimeError(f"ffuf failed (exit {result.returncode}): {result.stderr.strip()}")

        return parse_ffuf_json(out_path.read_text()) if out_path.stat().st_size else []
    finally:
        out_path.unlink(missing_ok=True)
