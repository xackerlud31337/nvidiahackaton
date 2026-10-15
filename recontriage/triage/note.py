"""Draft a first-pass finding note for the top-ranked finding.

A pentester's deliverable is a written finding, not a port list. This takes
the #1 finding (plus the full context, so Ultra can mention related items)
and drafts the note a human would then verify and polish. Plain markdown,
rendered by the CLI and saved to the run folder.

One Ultra call per run. Uses chat() not chat_json() because we want prose.
"""
from __future__ import annotations

from .client import ULTRA, NemotronClient
from .rank import SYSTEM_PROMPT, _compact

NOTE_SYSTEM = SYSTEM_PROMPT.replace(
    "Reply with JSON only. No markdown fences, no prose before or after.",
    "Reply in Markdown. Be factual; mark anything unverified as 'to confirm'.",
)


def draft_note(client: NemotronClient, target: str, finding: dict, all_items: list[dict]) -> str:
    related = "\n".join(_compact(it) for it in all_items)
    user = f"""Target: {target}

Top finding selected by triage:
  id: {finding['id']}
  title: {finding['title']}
  severity: {finding['severity']}
  evidence: {_compact(finding['item'])}
  rationale: {finding['rationale']}

All recon items for context:
{related}

Write a draft finding note with exactly these sections:
## Title
## Affected asset
## Evidence  (quote the recon data; do not invent details)
## Why it matters  (impact in 2-3 sentences, for a non-specialist reader)
## Suggested verification  (safe, non-exploitative steps a human should do next)
## References  (relevant CWE/CVE ids or vendor docs if you are confident; otherwise say none)
Keep it under 250 words."""
    return client.chat(ULTRA, NOTE_SYSTEM, user, max_tokens=4000, temperature=0.3)
