# ReconTriage

**License: MIT** · Built for the Nebius x NVIDIA Global AI Hackathon (track: Best Apps & Agents)

A CLI agent that runs the reconnaissance a pentester does by hand against an
**authorized** target, then uses **NVIDIA Nemotron models on Nebius Token
Factory** to rank the output by what is worth a human look and draft a
first-pass finding note.

Offensive-security triage is drowning in noise: a single scan produces
hundreds of lines, most of them irrelevant. ReconTriage keeps the scanning
tools you already trust (nmap, ffuf, certificate-transparency logs) and puts a
reasoning model on top to do the sifting. Detection and prioritisation only:
no exploitation, no auth bypass, no automated attacks.

```
$ recontriage scanme.nmap.org
[scope] scanme.nmap.org is in scope (scope.txt)
[subdomains] querying crt.sh for *.scanme.nmap.org
[ports] nmap -sV --top-ports 1000 scanme.nmap.org
[ports] 2 open on scanme.nmap.org: 22/ssh, 80/http
[dirs] ffuf http://scanme.nmap.org/FUZZ
[dirs] 2 hits on http://scanme.nmap.org
[triage] Nemotron Nano enriching 5 items
[triage] Nemotron Ultra ranked 5 findings
[note] Nemotron Ultra drafting note for #1

┌───┬────────┬──────────────────────────────────┬─────────────────────────────────┐
│ # │ Sev    │ Item                             │ Why it matters                  │
├───┼────────┼──────────────────────────────────┼─────────────────────────────────┤
│ 1 │ medium │ Exposed .svn directory           │ Version-control metadata can…   │
│ … │        │                                  │                                 │
└───┴────────┴──────────────────────────────────┴─────────────────────────────────┘
╭─ Draft finding note (top item) ───────────────────────────────────────────────╮
│ ## Title …                                                                    │
╰───────────────────────────────────────────────────────────────────────────────╯
```

## How Nemotron is used

Two model sizes, chosen deliberately so credits stretch and reasoning goes
where it matters (`recontriage/triage/`):

| Step | Model | Why |
|---|---|---|
| Enrich every recon item with a one-line technical note | `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` | cheap and fast; runs over all items in batches |
| Rank everything and give a rationale + safe next step per item | `nvidia/Nemotron-3-Ultra-550b-a55b` | one call per run; needs reasoning *across* items |
| Draft the finding note for the #1 item | `nvidia/Nemotron-3-Ultra-550b-a55b` | writing quality matters here |

The API is Nebius Token Factory (`https://api.tokenfactory.nebius.com/v1/`),
OpenAI-compatible, accessed through the stock `openai` SDK. A typical run
costs about **$0.02**; the CLI prints the exact token usage and estimate.

Design notes you can read in the code:

* Nemotron models are **reasoning models**. The answer comes back in
  `message.content`, the chain-of-thought in `message.reasoning`, and
  reasoning tokens count against `max_tokens`. The client guards against
  empty content and budgets tokens accordingly (`triage/client.py`).
* We do **not** use tool-calling. The model returns JSON as text and we parse
  it ourselves with a tolerant extractor (code fences, prose around it).
* Every recon item gets a short id (`P1`, `S2`, `D3`). The model may only
  reference ids. Findings that point at ids we never sent are dropped, which
  stops hallucinated hosts and ports reaching the report (`triage/rank.py`).

## Architecture

```
recontriage <target>
     │
     ▼
 scope.py ── allow-list guard. Refuses anything not in scope.txt. Runs first, always.
     │
     ▼
 recon/subdomains.py   crt.sh certificate-transparency lookup + DNS resolve  (passive)
 recon/ports.py        nmap -sV, XML parsed                                   (active)
 recon/dirs.py         ffuf against every web port, JSON parsed               (active)
     │   all three emit the same list[dict] shape → one recon.json
     ▼
 triage/rank.py        Nano enriches → Ultra ranks (validated JSON)
 triage/note.py        Ultra drafts the finding note (markdown)
     │
     ▼
 cli.py                rich table + note + cost; saved to runs/<target>_<time>/
```

`pipeline.py` wires these together and is the only module that knows about
all of them, so a web UI could reuse it unchanged.

## Setup

Requirements: Python 3.11+, `nmap`, `ffuf` on your PATH
(`brew install nmap ffuf` on macOS, `apt install nmap ffuf` on Debian/Ubuntu),
and a Nebius Token Factory API key.

```bash
git clone https://github.com/xackerlud31337/nvidiahackaton.git
cd nvidiahackaton
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# API key: either export it or put it in .env (gitignored)
cp .env.example .env            # then edit NEBIUS_API_KEY=...

# Scope: list ONLY targets you are authorized to scan
cp scope.example.txt scope.txt  # then edit
```

Smoke-test the API before anything else:

```bash
python scripts/hello_nemotron.py
```

## Run

```bash
recontriage scanme.nmap.org                 # full pipeline
recontriage 10.10.11.5 --top-ports 100      # quicker port scan
recontriage example.com --skip-dirs         # no ffuf
recontriage example.com --no-llm            # recon only, zero API calls
recontriage --help
```

Output goes to the terminal and to `runs/<target>_<timestamp>/`:
`recon.json` (raw items), `triage.json` (ranked findings + notes + usage),
`finding.md` (the draft note).

`scanme.nmap.org` is run by the nmap project specifically so people can test
scanners against it. It is the default target in `scope.example.txt`.

## Authorization and safety

* **Only scan what you are allowed to scan.** Your own machines, a Hack The
  Box / TryHackMe box, or a target with a published bug-bounty or VDP scope.
  Scanning anything else is illegal.
* `scope.txt` is an allow-list and the guard runs before any traffic. Hosts
  discovered via crt.sh are only actively scanned if they are *also* covered
  by the scope file (for example by a `*.example.com` line). An out-of-scope
  target exits with code 3 and a clear message.
* ffuf runs rate-limited (50 req/s) with auto-calibration; nmap uses the
  default top-1000 ports. This is recon, not load testing.
* The model is instructed to suggest only non-exploitative verification steps.

## Tests

```bash
pytest -q
```

Tests cover the scope guard (including the `evil-example.com` wildcard trap),
the nmap / ffuf / crt.sh parsers against saved fixtures, the JSON extractor,
and the ranking validator with a fake client. No network or API key needed.

## Troubleshooting

* **`No module named 'recontriage'` after `pip install -e .` on macOS with
  Python 3.13+**: macOS sometimes sets the "hidden" file flag on the install
  hook and newer Pythons skip hidden `.pth` files. Fix with
  `chflags nohidden .venv/lib/python3.*/site-packages/__editable__*.pth`,
  or just use `pip install .` (non-editable).
* **`EmptyResponseError`**: the model spent its whole token budget reasoning.
  The defaults are generous; if you lowered `max_tokens`, raise it.
* **crt.sh timeouts**: it is a free community service and is sometimes slow.
  The pipeline retries three times, then continues without subdomains.

## Roadmap (post-hackathon)

More passive sources for subdomains, screenshotting web services, a thin web
UI on top of `pipeline.run()`, and per-item Nano "is this interesting?"
pre-filtering for very large scopes.
