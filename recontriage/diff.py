"""Compare a run against the previous run of the same target.

For a real operator, 'what changed since last time' is often more useful than
the full list: a newly opened port or a path that appeared yesterday is a
signal. This is pure set math over the saved recon.json files; no scanning,
no API.
"""
from __future__ import annotations

import json
from pathlib import Path


def _key(item: dict) -> str:
    """A stable identity for a recon item, independent of triage ids."""
    t = item.get("type")
    if t == "port":
        return f"port {item['host']}:{item['port']}/{item.get('proto','tcp')}"
    if t == "subdomain":
        return f"subdomain {item['host']}"
    if t == "path":
        return f"path {item['url']}"
    return json.dumps(item, sort_keys=True)


def diff_items(old: list[dict], new: list[dict]) -> dict:
    """Return {"added": [...], "removed": [...], "same": n}."""
    old_map = {_key(i): i for i in old}
    new_map = {_key(i): i for i in new}
    added = [new_map[k] for k in new_map if k not in old_map]
    removed = [old_map[k] for k in old_map if k not in new_map]
    same = sum(1 for k in new_map if k in old_map)
    return {"added": added, "removed": removed, "same": same}


def two_latest_recons(target: str, runs_dir: str = "runs") -> tuple[Path, Path] | None:
    """The two most recent runs/<target>_*/recon.json, (previous, latest)."""
    recons = sorted(
        (f for folder in Path(runs_dir).glob(f"{target}_*")
         if (f := folder / "recon.json").exists()),
        key=lambda f: f.parent.name,
    )
    if len(recons) < 2:
        return None
    return recons[-2], recons[-1]


def diff_latest(target: str, runs_dir: str = "runs") -> dict | None:
    pair = two_latest_recons(target, runs_dir)
    if not pair:
        return None
    prev, latest = pair
    d = diff_items(json.loads(prev.read_text()), json.loads(latest.read_text()))
    d["previous"] = prev.parent.name
    d["latest"] = latest.parent.name
    return d
