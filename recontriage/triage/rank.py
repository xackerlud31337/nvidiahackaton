"""Turn raw recon items into a ranked list of findings using two Nemotron tiers.

Pipeline inside this module:

    items (from recon) --label_items--> items with ids (P1, S2, D3 ...)
        --enrich_with_nano--> one-line technical note per item   (cheap, Nano)
        --rank_with_ultra--> ranked findings with rationale      (Ultra, once)

Why two models?
  * Nano (30B) is ~15x cheaper than Ultra and is plenty for "what is OpenSSH
    6.6.1 and is it old?". We can run it over every item.
  * Ultra (550B) is the one we want *reasoning* across all items at once:
    "a dangling subdomain plus an exposed .svn is more interesting than ssh".
    One call per run keeps credits safe.

Why ids like "P1"?
  LLMs hallucinate hostnames and ports if you let them write free text. By
  giving every item a short id and telling the model to reference ids only,
  we can (a) verify every finding points at something real and (b) drop any
  that don't. That check is in rank_with_ultra.
"""
from __future__ import annotations

import json

from .client import NANO, ULTRA, NemotronClient

SEVERITIES = ("critical", "high", "medium", "low", "info")

_PREFIX = {"port": "P", "subdomain": "S", "path": "D"}

SYSTEM_PROMPT = """You are a senior penetration tester triaging reconnaissance output.
The engagement is AUTHORIZED and scoped. Your job is detection and prioritisation only:
never suggest exploitation steps, only what to look at and why.
Be concrete and terse. Prefer evidence from the data over speculation.
Reply with JSON only. No markdown fences, no prose before or after."""


def label_items(items: list[dict]) -> list[dict]:
    """Give every item a stable short id: P1, P2 for ports, S1.. subdomains,
    D1.. directories. Returns new dicts; input is not mutated."""
    counters: dict[str, int] = {}
    out = []
    for it in items:
        prefix = _PREFIX.get(it.get("type", ""), "X")
        counters[prefix] = counters.get(prefix, 0) + 1
        out.append({"id": f"{prefix}{counters[prefix]}", **it})
    return out


def _compact(item: dict) -> str:
    """One line per item for the prompt. Shorter prompts = fewer tokens = cheaper,
    and the model doesn't need the 'type'/'source' boilerplate spelled out."""
    t = item["type"]
    if t == "port":
        svc = " ".join(x for x in (item["service"], item["product"], item["version"], item["extra"]) if x)
        return f'{item["id"]} port {item["host"]}:{item["port"]}/{item["proto"]} {svc}'.rstrip()
    if t == "subdomain":
        ip = item["ip"] or "DOES-NOT-RESOLVE"
        return f'{item["id"]} subdomain {item["host"]} -> {ip}'
    if t == "path":
        extra = f' -> {item["redirect"]}' if item.get("redirect") else ""
        return f'{item["id"]} path {item["url"]} status={item["status"]} size={item["size"]}{extra}'
    return f'{item["id"]} {json.dumps(item)}'


def enrich_with_nano(client: NemotronClient, items: list[dict], chunk: int = 40) -> dict[str, str]:
    """Ask Nano for one short technical note per item.

    Batched `chunk` items per call: one call for 40 items is far cheaper than
    40 calls, and Nano handles this size fine. Returns {id: note}. Any item
    Nano skipped simply has no note; ranking still works without it.
    """
    notes: dict[str, str] = {}
    for i in range(0, len(items), chunk):
        batch = items[i:i + chunk]
        user = (
            "For each recon item below, write ONE short technical note (max 20 words): "
            "what the software/asset is, whether the version is old or end-of-life, "
            "and any well-known misconfiguration or exposure it typically indicates. "
            "If nothing notable, say 'nothing notable'.\n\n"
            + "\n".join(_compact(it) for it in batch)
            + '\n\nReply as JSON: {"notes": {"<id>": "<note>", ...}}'
        )
        try:
            data = client.chat_json(NANO, SYSTEM_PROMPT, user, max_tokens=3000)
            got = data.get("notes", {}) if isinstance(data, dict) else {}
            notes.update({k: str(v) for k, v in got.items() if isinstance(k, str)})
        except Exception as e:  # noqa: BLE001
            # Enrichment is nice-to-have. Never let it kill the run.
            print(f"[warn] Nano enrichment failed for batch {i // chunk}: {e}")
    return notes


def rank_with_ultra(
    client: NemotronClient,
    target: str,
    items: list[dict],
    notes: dict[str, str],
    top_n: int = 10,
) -> list[dict]:
    """One Ultra call that ranks everything. Returns validated findings.

    Each finding: {"rank", "id", "severity", "title", "rationale", "next_step", "item"}
    where "item" is the original recon dict the id refers to.
    """
    lines = []
    for it in items:
        note = notes.get(it["id"])
        lines.append(_compact(it) + (f"   # {note}" if note else ""))

    user = (
        f"Target: {target}\n"
        f"Recon items ({len(items)}), one per line, with analyst notes after '#':\n\n"
        + "\n".join(lines)
        + f"\n\nRank the {min(top_n, len(items))} items most worth a human's attention, best first. "
        "Consider: exposure of sensitive files/panels, outdated software, dangling DNS, "
        "unusual services, and how items combine. Reference items ONLY by their id.\n"
        'Reply as JSON: {"findings": [{"rank": 1, "id": "P1", "severity": "high|medium|low|info", '
        '"title": "<8 words max>", "rationale": "<one sentence, cite evidence>", '
        '"next_step": "<one non-exploitative verification step>"}]}'
    )
    data = client.chat_json(ULTRA, SYSTEM_PROMPT, user, max_tokens=8000)

    by_id = {it["id"]: it for it in items}
    findings: list[dict] = []
    raw = data.get("findings", []) if isinstance(data, dict) else data
    for f in raw if isinstance(raw, list) else []:
        fid = str(f.get("id", "")).strip()
        if fid not in by_id:
            # Hallucination guard: a finding about an item we never gave it.
            print(f"[warn] Ultra referenced unknown id {fid!r}; dropped")
            continue
        sev = str(f.get("severity", "info")).lower()
        findings.append({
            "rank": int(f.get("rank", len(findings) + 1)),
            "id": fid,
            "severity": sev if sev in SEVERITIES else "info",
            "title": str(f.get("title", "")).strip(),
            "rationale": str(f.get("rationale", "")).strip(),
            "next_step": str(f.get("next_step", "")).strip(),
            "item": by_id[fid],
        })
    findings.sort(key=lambda f: f["rank"])
    for i, f in enumerate(findings, 1):   # normalise ranks to 1..n
        f["rank"] = i
    return findings[:top_n]


def triage(client: NemotronClient, target: str, items: list[dict], top_n: int = 10) -> dict:
    """Module entry point. Returns {"items": [...labelled...], "notes": {...}, "findings": [...]}."""
    labelled = label_items(items)
    if not labelled:
        return {"items": [], "notes": {}, "findings": []}
    notes = enrich_with_nano(client, labelled)
    findings = rank_with_ultra(client, target, labelled, notes, top_n=top_n)
    return {"items": labelled, "notes": notes, "findings": findings}
