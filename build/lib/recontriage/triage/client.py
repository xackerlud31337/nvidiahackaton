"""Thin wrapper around the Nebius Token Factory API for Nemotron models.

Token Factory speaks the OpenAI protocol, so we use the stock `openai` SDK and
only change base_url + api_key. Everything specific to *our* use lives here:

  * the two model ids we use and why (see MODELS)
  * handling of the reasoning-model quirk: the answer arrives in
    message.content and the chain-of-thought in message.reasoning. We only
    want content, and it can be empty if max_tokens was eaten by reasoning.
  * robust JSON extraction: we ask for JSON but the model may wrap it in
    ```json fences or a sentence. We don't use tool-calling (flaky on this
    endpoint, per the build plan); we parse text ourselves.
  * a running token/cost tally so a run can print what it cost.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from openai import OpenAI

BASE_URL = "https://api.tokenfactory.nebius.com/v1/"

# Cheap and fast; used for per-item enrichment where volume is high.
NANO = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
# Strongest reasoning; used once per run for the ranking and the note.
ULTRA = "nvidia/Nemotron-3-Ultra-550b-a55b"

# USD per 1M tokens (input, output). Approximate, Oct 2026 Token Factory list
# prices; only used for the cost estimate printed at the end of a run.
PRICES = {
    NANO: (0.06, 0.24),
    ULTRA: (1.00, 3.00),
}


class EmptyResponseError(RuntimeError):
    """The model returned no content (usually: max_tokens too small for a
    reasoning model, which spends tokens thinking before it answers)."""


@dataclass
class Usage:
    """Accumulates token counts per model across a run."""
    prompt: dict[str, int] = field(default_factory=dict)
    completion: dict[str, int] = field(default_factory=dict)

    def add(self, model: str, prompt_tokens: int, completion_tokens: int) -> None:
        self.prompt[model] = self.prompt.get(model, 0) + prompt_tokens
        self.completion[model] = self.completion.get(model, 0) + completion_tokens

    def cost_usd(self) -> float:
        total = 0.0
        for model in set(self.prompt) | set(self.completion):
            pin, pout = PRICES.get(model, (0.0, 0.0))
            total += self.prompt.get(model, 0) / 1e6 * pin
            total += self.completion.get(model, 0) / 1e6 * pout
        return total

    def summary(self) -> str:
        lines = []
        for model in sorted(set(self.prompt) | set(self.completion)):
            short = model.split("/")[-1]
            lines.append(f"{short}: {self.prompt.get(model, 0)} in / {self.completion.get(model, 0)} out")
        lines.append(f"estimated cost: ${self.cost_usd():.4f}")
        return "\n".join(lines)


class NemotronClient:
    def __init__(self, api_key: str | None = None) -> None:
        key = api_key or os.environ.get("NEBIUS_API_KEY")
        if not key:
            raise RuntimeError("NEBIUS_API_KEY is not set (export it or put it in .env)")
        self._client = OpenAI(base_url=BASE_URL, api_key=key)
        self.usage = Usage()

    def chat(
        self,
        model: str,
        system: str,
        user: str,
        *,
        max_tokens: int = 4000,
        temperature: float = 0.2,
    ) -> str:
        """One chat call. Returns the stripped content string.

        Low temperature because triage should be consistent run to run, not
        creative. max_tokens defaults high because the reasoning tokens count
        against it; too low and content comes back empty.
        """
        resp = self._client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if resp.usage:
            self.usage.add(model, resp.usage.prompt_tokens, resp.usage.completion_tokens)

        content = (resp.choices[0].message.content or "").strip()
        if not content:
            raise EmptyResponseError(
                f"{model} returned empty content (finish_reason="
                f"{resp.choices[0].finish_reason}). Try a larger max_tokens."
            )
        return content

    def chat_json(self, model: str, system: str, user: str, *, retries: int = 1, **kw) -> dict | list:
        """chat() + extract_json(), with self-repair.

        If the reply doesn't contain parseable JSON we send it back ONCE with
        the parser's complaint and ask for JSON only. Models fix their own
        formatting mistakes reliably; this turns a rare crash into a rare
        extra call. Separate from chat() so prose callers (the finding note)
        aren't affected.
        """
        text = self.chat(model, system, user, **kw)
        for attempt in range(retries + 1):
            try:
                return extract_json(text)
            except ValueError as e:
                if attempt == retries:
                    raise
                repair = (
                    "Your previous reply could not be parsed as JSON.\n"
                    f"Parser error: {str(e).splitlines()[0]}\n\n"
                    "Previous reply:\n" + text[:4000] +
                    "\n\nReply again with ONLY the JSON, no fences, no prose."
                )
                text = self.chat(model, system, repair, **kw)
        raise AssertionError("unreachable")


_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def extract_json(text: str) -> dict | list:
    """Pull a JSON object/array out of model output that may have junk around it.

    Strategy, in order:
      1. If there's a ```json ... ``` fence, use what's inside it.
      2. Otherwise, take the substring from the first '{' or '[' to the last
         matching '}' or ']' and parse that. This survives "Here is the
         ranking:\n{...}\nLet me know if..." style replies.
    Raises ValueError with the raw text attached if nothing parses, so the
    caller can save it for debugging instead of silently losing it.
    """
    candidates = [m.group(1) for m in _FENCE.finditer(text)]
    # Also try the whole text and the bracket-delimited slice.
    first = min((i for i in (text.find("{"), text.find("[")) if i != -1), default=-1)
    if first != -1:
        opener = text[first]
        closer = "}" if opener == "{" else "]"
        last = text.rfind(closer)
        if last > first:
            candidates.append(text[first:last + 1])
    candidates.append(text)

    for cand in candidates:
        try:
            return json.loads(cand.strip())
        except json.JSONDecodeError:
            continue
    raise ValueError(f"no JSON found in model output:\n{text[:500]}")
