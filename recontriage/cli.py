"""Command-line entry point.  `recontriage <target>`

Responsibilities: parse flags, load .env, call pipeline.run(), print a
readable report, save everything under runs/<target>_<timestamp>/.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from . import pipeline
from .scope import OutOfScopeError

console = Console()

SEV_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recontriage",
        description="Run recon against an AUTHORIZED target and let Nemotron rank what's worth a look.",
    )
    p.add_argument("target", help="domain or IP; must be listed in the scope file")
    p.add_argument("--scope", default="scope.txt", help="allow-list file (default: scope.txt)")
    p.add_argument("--skip-subdomains", action="store_true", help="don't query crt.sh")
    p.add_argument("--skip-dirs", action="store_true", help="don't run ffuf")
    p.add_argument("--no-llm", action="store_true", help="recon only, no Nemotron calls")
    p.add_argument("--top-ports", type=int, default=1000, help="nmap --top-ports N (default 1000)")
    p.add_argument("--max-hosts", type=int, default=5, help="max hosts to actively scan (default 5)")
    p.add_argument("--top-n", type=int, default=10, help="findings to rank (default 10)")
    p.add_argument("--wordlist", default=str(pipeline.DEFAULT_WORDLIST), help="ffuf wordlist")
    p.add_argument("--out", default="runs", help="output directory (default runs/)")
    return p


def print_report(result: dict) -> None:
    findings = result["findings"]
    if not findings:
        console.print("[yellow]No findings ranked.[/yellow]")
    else:
        table = Table(title=f"ReconTriage: {result['target']}", show_lines=True)
        table.add_column("#", justify="right", width=3)
        table.add_column("Sev", width=8)
        table.add_column("Item", width=34)
        table.add_column("Why it matters")
        for f in findings:
            sev = f["severity"]
            evidence = _evidence(f["item"])
            table.add_row(
                str(f["rank"]),
                f"[{SEV_STYLE[sev]}]{sev}[/]",
                f"[bold]{f['title']}[/bold]\n[dim]{f['id']}: {evidence}[/dim]",
                f"{f['rationale']}\n[dim]next: {f['next_step']}[/dim]",
            )
        console.print(table)

    if result.get("note"):
        console.print(Panel(Markdown(result["note"]), title="Draft finding note (top item)", border_style="green"))
    if result.get("usage"):
        console.print(Panel(result["usage"], title="Nemotron usage", border_style="dim"))


def _evidence(item: dict) -> str:
    from .triage.rank import _compact
    return _compact(item).split(" ", 2)[-1]   # drop the id and type words


def save_run(result: dict, out_dir: str) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(result["started"]))
    folder = Path(out_dir) / f"{result['target']}_{stamp}"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "recon.json").write_text(json.dumps(result["items"], indent=2))
    (folder / "triage.json").write_text(json.dumps(
        {"findings": result["findings"], "notes": result["notes"], "usage": result["usage"]}, indent=2))
    if result.get("note"):
        (folder / "finding.md").write_text(result["note"])
    return folder


def main(argv: list[str] | None = None) -> int:
    load_dotenv()                     # picks up NEBIUS_API_KEY from .env if present
    args = build_parser().parse_args(argv)

    if not Path(args.scope).exists():
        console.print(f"[red]scope file '{args.scope}' not found.[/red] "
                      "Copy scope.example.txt to scope.txt and list only targets you are authorized to scan.")
        return 2

    opts = pipeline.Options(
        scope_path=args.scope,
        skip_subdomains=args.skip_subdomains,
        skip_dirs=args.skip_dirs,
        no_llm=args.no_llm,
        top_ports=args.top_ports,
        max_hosts=args.max_hosts,
        top_n=args.top_n,
        wordlist=args.wordlist,
        # escape() so "[scope]" in a log line is not eaten as rich markup
        log=lambda m: console.print(f"[dim]{escape(m)}[/dim]"),
    )
    try:
        result = pipeline.run(args.target, opts)
    except OutOfScopeError as e:
        console.print(f"[bold red]REFUSED:[/bold red] {e}")
        return 3
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/yellow]")
        return 130

    print_report(result)
    folder = save_run(result, args.out)
    console.print(f"[dim]saved to {folder}/[/dim]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
