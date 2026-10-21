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

from ..scope import Scope
from . import verify
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


def _clamp_conf(v) -> float:
    try:
        c = float(v)
    except (TypeError, ValueError):
        return 0.5
    return max(0.0, min(1.0, c))


def _validate_findings(raw, by_id: list[str] | dict, top_n: int, log=print) -> list[dict]:
    """Shared validator. Keeps only findings that reference known ids, clamps
    severity/confidence, resolves related_ids, normalises ranks."""
    ids = set(by_id)
    findings: list[dict] = []
    for f in raw if isinstance(raw, list) else []:
        fid = str(f.get("id", "")).strip()
        if fid not in ids:
            log(f"[warn] Ultra referenced unknown id {fid!r}; dropped")
            continue
        sev = str(f.get("severity", "info")).lower()
        related = [r for r in (str(x).strip() for x in f.get("related_ids", []) or [])
                   if r in ids and r != fid]
        findings.append({
            "rank": int(f.get("rank", len(findings) + 1)),
            "id": fid,
            "severity": sev if sev in SEVERITIES else "info",
            "title": str(f.get("title", "")).strip(),
            "rationale": str(f.get("rationale", "")).strip(),
            "next_step": str(f.get("next_step", "")).strip(),
            "confidence": _clamp_conf(f.get("confidence", 0.5)),
            "related_ids": related[:5],
        })
    findings.sort(key=lambda f: f["rank"])
    for i, f in enumerate(findings, 1):
        f["rank"] = i
    return findings[:top_n]


def rank_with_ultra(
    client: NemotronClient,
    target: str,
    items: list[dict],
    notes: dict[str, str],
    top_n: int = 10,
    log=print,
) -> dict:
    """One Ultra call that ranks everything with cross-item reasoning.

    Returns {"attack_surface": "<short paragraph>", "findings": [...]}.
    Each finding has: rank, id, severity, title, rationale, next_step,
    confidence (0-1), related_ids (other item ids that combine with this one),
    and item (the original recon dict).

    The attack_surface summary and related_ids are the reason a 550B model is
    here: they require reasoning ACROSS items, not item-by-item.
    """
    lines = []
    for it in items:
        note = notes.get(it["id"])
        lines.append(_compact(it) + (f"   # {note}" if note else ""))

    user = (
        f"Target: {target}\n"
        f"Recon items ({len(items)}), one per line, with analyst notes after '#':\n\n"
        + "\n".join(lines)
        + f"\n\nFirst, in one short paragraph, describe the overall attack surface: "
        "what kind of host(s) this looks like and the 2-3 themes that stand out.\n"
        f"Then rank the {min(top_n, len(items))} items most worth a human's attention, best first. "
        "Weigh how items COMBINE (e.g. a dangling subdomain plus an exposed VCS directory "
        "is worse than either alone). Reference items ONLY by their id.\n"
        'Reply as JSON: {"attack_surface": "<paragraph>", "findings": [{"rank": 1, '
        '"id": "P1", "severity": "critical|high|medium|low|info", "title": "<8 words max>", '
        '"rationale": "<one sentence citing evidence>", "confidence": 0.0-1.0, '
        '"related_ids": ["S2"], "next_step": "<one non-exploitative verification step>"}]}'
    )
    data = client.chat_json(ULTRA, SYSTEM_PROMPT, user, max_tokens=8000)

    by_id = {it["id"]: it for it in items}
    raw = data.get("findings", []) if isinstance(data, dict) else data
    findings = _validate_findings(raw, by_id, top_n, log=log)
    for f in findings:                       # attach the source recon dict
        f["item"] = by_id[f["id"]]
    summary = str(data.get("attack_surface", "")).strip() if isinstance(data, dict) else ""
    return {"attack_surface": summary, "findings": findings}


def verify_findings(
    client: NemotronClient,
    target: str,
    items: list[dict],
    findings: list[dict],
    scope: Scope,
    max_checks: int = 6,
    log=print,
) -> list[dict]:
    """The agent loop. Ultra proposes read-only checks on the top findings; we
    run them (scope-enforced, in verify.py); Ultra revises confidence/severity
    given the evidence. One propose call + one revise call, bounded checks.

    Returns the (possibly re-ordered) findings with an added "evidence" list
    per finding and updated confidence.
    """
    by_id = {it["id"]: it for it in items}
    top = findings[:max_checks]
    if not top:
        return findings

    # 1. propose checks
    menu = ", ".join(verify.CHECK_TYPES)
    lines = [f'{f["id"]} {f["title"]} (sev={f["severity"]}, conf={f["confidence"]}) '
             f'-- {_compact(f["item"]).split(" ", 1)[1]}' for f in top]
    propose = (
        f"Target: {target}\nTop findings:\n" + "\n".join(lines) +
        f"\n\nYou may request up to {max_checks} READ-ONLY checks to raise or lower your "
        f"confidence. Available check types: {menu}. http_* needs a path item; "
        "tls_cert/dns work on any host item. Request checks ONLY for the ids above.\n"
        'Reply as JSON: {"checks": [{"type": "http_title", "id": "D1"}]}'
    )
    try:
        data = client.chat_json(ULTRA, SYSTEM_PROMPT, propose, max_tokens=2000, log=log)
        requested = data.get("checks", []) if isinstance(data, dict) else []
    except Exception as e:  # noqa: BLE001
        log(f"[verify] propose step failed, skipping verification: {e}")
        return findings

    # 2. run checks (scope-enforced inside run_check)
    results = []
    for chk in requested[:max_checks]:
        res = verify.run_check(chk, by_id, scope)
        results.append(res)
        tag = "ok" if "result" in res else res.get("error", "?")
        log(f"[verify] {chk.get('type')} {chk.get('id')}: {tag}")

    # attach evidence to findings
    ev_by_id: dict[str, list] = {}
    for r in results:
        ev_by_id.setdefault(r.get("id", ""), []).append(r)
    for f in findings:
        f["evidence"] = ev_by_id.get(f["id"], [])

    if not results:
        return findings

    # 3. revise
    revise = (
        f"Target: {target}\nHere are the check results (JSON):\n{json.dumps(results)[:4000]}\n\n"
        "Given this evidence, re-rank and adjust severity/confidence for these findings. "
        "If a check confirmed a default/unauthenticated panel or an expired cert, raise "
        "confidence; if a path 404s or redirects to login, lower it.\n"
        'Reply as JSON: {"findings": [{"rank": 1, "id": "D1", "severity": "...", '
        '"title": "...", "rationale": "...", "confidence": 0.0-1.0, "related_ids": [], '
        '"next_step": "..."}]}'
    )
    try:
        data = client.chat_json(ULTRA, SYSTEM_PROMPT, revise, max_tokens=6000, log=log)
        raw = data.get("findings", []) if isinstance(data, dict) else data
        revised = _validate_findings(raw, by_id, len(findings), log=log)
    except Exception as e:  # noqa: BLE001
        log(f"[verify] revise step failed, keeping original ranking: {e}")
        return findings

    if not revised:
        return findings
    for f in revised:
        f["item"] = by_id[f["id"]]
        f["evidence"] = ev_by_id.get(f["id"], [])
    return revised


def triage(
    client: NemotronClient,
    target: str,
    items: list[dict],
    top_n: int = 10,
    scope: Scope | None = None,
    verify_loop: bool = True,
    log=print,
) -> dict:
    """Module entry point.

    Returns {"items", "notes", "attack_surface", "findings"}. When verify_loop
    is on and a scope is given, runs the read-only agent loop to gather
    evidence and revise the ranking.
    """
    labelled = label_items(items)
    if not labelled:
        return {"items": [], "notes": {}, "attack_surface": "", "findings": []}
    notes = enrich_with_nano(client, labelled)
    ranked = rank_with_ultra(client, target, labelled, notes, top_n=top_n, log=log)
    findings = ranked["findings"]
    if verify_loop and scope is not None and findings:
        log(f"[verify] Nemotron Ultra proposing read-only checks")
        findings = verify_findings(client, target, labelled, findings, scope, log=log)
    return {
        "items": labelled,
        "notes": notes,
        "attack_surface": ranked["attack_surface"],
        "findings": findings,
    }
