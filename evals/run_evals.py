"""Measure triage quality on synthetic recon fixtures with a known best finding.

Each fixture declares the item that SHOULD rank #1 (expect_top_type +
expect_top_match substring). We run the real triage pipeline N times per
fixture and report:

  * top1   : fraction of runs where the expected item ranked #1
  * top3   : fraction where it landed in the top 3
  * cost   : total estimated API cost

Why N runs? These are reasoning models at temperature 0.2, so output varies.
A single run tells you nothing about reliability; the spread does. This is the
difference between "the prompt works" and "the prompt works 9 times in 10".

Usage:
    export NEBIUS_API_KEY=...
    python evals/run_evals.py            # 3 runs each (default)
    python evals/run_evals.py --runs 5
    python evals/run_evals.py --no-verify   # skip the agent loop (cheaper)

No network scanning happens; fixtures are static. Only the model is called.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from dotenv import load_dotenv

from recontriage.triage.client import NemotronClient
from recontriage.triage.rank import triage

FIXTURES = Path(__file__).parent / "fixtures"


def _matches(finding: dict, exp_type: str, exp_match: str) -> bool:
    item = finding["item"]
    if item.get("type") != exp_type:
        return False
    blob = json.dumps(item).lower()
    # the subdomain case marks the expectation with a sentinel, not real data
    if exp_match == "DOES-NOT-RESOLVE":
        return item.get("type") == "subdomain" and not item.get("ip")
    return exp_match.lower() in blob


def run_fixture(fx: dict, runs: int, verify: bool) -> dict:
    client = NemotronClient()
    top1 = top3 = 0
    for _ in range(runs):
        res = triage(client, fx["name"], fx["items"], top_n=5,
                     scope=None, verify_loop=False, log=lambda *_: None)
        # verify_loop needs a scope; evals run without network so default off
        findings = res["findings"]
        if findings and _matches(findings[0], fx["expect_top_type"], fx["expect_top_match"]):
            top1 += 1
        if any(_matches(f, fx["expect_top_type"], fx["expect_top_match"]) for f in findings[:3]):
            top3 += 1
    return {"name": fx["name"], "runs": runs, "top1": top1 / runs, "top3": top3 / runs,
            "cost": client.usage.cost_usd()}


def main() -> None:
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--no-verify", action="store_true")
    a = ap.parse_args()

    rows = []
    for path in sorted(FIXTURES.glob("*.json")):
        fx = json.loads(path.read_text())
        print(f"running {fx['name']} x{a.runs} ...")
        rows.append(run_fixture(fx, a.runs, not a.no_verify))

    print(f"\n{'fixture':<22} {'top1':>6} {'top3':>6} {'cost':>8}")
    print("-" * 44)
    for r in rows:
        print(f"{r['name']:<22} {r['top1']:>6.0%} {r['top3']:>6.0%} ${r['cost']:>6.4f}")
    agg1 = sum(r["top1"] for r in rows) / len(rows)
    agg3 = sum(r["top3"] for r in rows) / len(rows)
    total = sum(r["cost"] for r in rows)
    print("-" * 44)
    print(f"{'AVERAGE':<22} {agg1:>6.0%} {agg3:>6.0%} ${total:>6.4f}")


if __name__ == "__main__":
    main()
