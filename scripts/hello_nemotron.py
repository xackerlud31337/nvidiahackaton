"""Smoke test: prove the Token Factory key works and see how Nemotron answers.

Usage:
    export NEBIUS_API_KEY="v1.CmQKHHN0YXRpY2tleS1lMDBjZ2piZ3Q5NTBrZDBtcWQSIXNlcnZpY2VhY2NvdW50LWUwMHgxMHR3NGRxZndlZzVoZzIMCN-NxdYGEJq20JcDOgwI25DdoQcQgITKzQNAAloDZTAw.AAAAAAAAAAGcdGmLKsM5nLeXA4iycxau_G6j5ax9bAHkz8zi-eSsReND09PPkXcAW96AqyHGqFSA-w2TZJI6SGN5n1T2_7YB"
    python scripts/hello_nemotron.py              # uses DEFAULT_MODEL
    python scripts/hello_nemotron.py <model-id>   # try another id from the list
"""
import os
import sys

from openai import OpenAI

BASE_URL = "https://api.tokenfactory.nebius.com/v1/"
NANO_MODEL = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
ULTRA_MODEL = "nvidia/Nemotron-3-Ultra-550b-a55b"
DEFAULT_MODEL = NANO_MODEL 


def main() -> None:
    key = os.environ.get("NEBIUS_API_KEY")
    if not key:
        sys.exit("NEBIUS_API_KEY is not set. Run: export NEBIUS_API_KEY=...")

    client = OpenAI(base_url=BASE_URL, api_key=key)

    # 1. which Nemotron models does the API actually expose right now?
    print("== Nemotron models available ==")
    for m in client.models.list():
        if "nemotron" in m.id.lower():
            print("  ", m.id)

    # 2. one small call
    model = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MODEL
    print(f"\n== calling {model} ==")
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You triage recon output for a pentester."},
            {"role": "user", "content": "Reply with one sentence confirming you are ready."},
        ],
        temperature=0.2,
        max_tokens=200,
    )

    msg = resp.choices[0].message
    # Reasoning models may split the answer: look at the whole message, not just .content
    print("\n-- content --")
    print(repr(msg.content))
    reasoning = getattr(msg, "reasoning_content", None) or getattr(msg, "reasoning", None)
    print("\n-- reasoning field --")
    print(repr(reasoning))
    print("\n-- usage --")
    print(resp.usage)

    if not msg.content:
        print("\nWARNING: content is empty. This is the gotcha from the plan.")


if __name__ == "__main__":
    main()
