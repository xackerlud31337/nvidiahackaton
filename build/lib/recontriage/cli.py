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
    p.add_argument("--reuse", action="store_true",
                   help="reuse the last saved recon for this target instead of rescanning")
    p.add_argument("--no-verify", action="store_true",
                   help="skip the read-only verification loop (faster, fewer API calls)")
    p.add_argument("--diff", action="store_true",
                   help="after the run, show what changed vs the previous run of this target")
    p.add_argument("--out", default="runs", help="output directory (default runs/)")
    return p


def print_report(result: dict, console: Console = console) -> None:
    """Render the report. `console` is injectable so the web UI can render the
    exact same output to HTML via a recording Console."""
    findings = result["findings"]
    if result.get("attack_surface"):
        console.print(Panel(result["attack_surface"],
                            title="Attack surface (Nemotron Ultra)", border_style="cyan"))
    if not findings:
        console.print("[yellow]No findings ranked.[/yellow]")
    else:
        table = Table(title=f"ReconTriage: {result['target']}", show_lines=True)
        table.add_column("#", justify="right", width=3)
        table.add_column("Sev", width=8)
        table.add_column("Conf", width=5)
        table.add_column("Item", width=32)
        table.add_column("Why it matters")
        for f in findings:
            sev = f["severity"]
            evidence = _evidence(f["item"])
            related = f.get("related_ids") or []
            rel = f"\n[dim]+ {', '.join(related)}[/dim]" if related else ""
            checks = f.get("evidence") or []
            ok = sum(1 for c in checks if "result" in c)
            ev = f"\n[green]✓ {ok} check(s) run[/green]" if checks else ""
            table.add_row(
                str(f["rank"]),
                f"[{SEV_STYLE[sev]}]{sev}[/]",
                _conf_bar(f.get("confidence", 0.5)),
                f"[bold]{f['title']}[/bold]\n[dim]{f['id']}: {evidence}[/dim]{rel}",
                f"{f['rationale']}\n[dim]next: {f['next_step']}[/dim]{ev}",
            )
        console.print(table)

    if result.get("note"):
        console.print(Panel(Markdown(result["note"]), title="Draft finding note (top item)", border_style="green"))
    if result.get("usage"):
        console.print(Panel(result["usage"], title="Nemotron usage", border_style="dim"))


def _conf_bar(c: float) -> str:
    """Tiny text confidence meter, e.g. 0.8 -> '████·'."""
    filled = round(max(0.0, min(1.0, c)) * 5)
    style = "green" if c >= 0.66 else "yellow" if c >= 0.33 else "red"
    return f"[{style}]{'█' * filled}{'·' * (5 - filled)}[/]"


def _evidence(item: dict) -> str:
    from .triage.rank import _compact
    return _compact(item).split(" ", 2)[-1]   # drop the id and type words


def save_run(result: dict, out_dir: str) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(result["started"]))
    folder = Path(out_dir) / f"{result['target']}_{stamp}"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "recon.json").write_text(json.dumps(result["items"], indent=2))
    (folder / "triage.json").write_text(json.dumps(
        {"attack_surface": result.get("attack_surface", ""),
         "findings": result["findings"], "notes": result["notes"],
         "usage": result["usage"]}, indent=2, default=str))
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
        reuse=args.reuse,
        verify=not args.no_verify,
        runs_dir=args.out,
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
    if args.diff:
        from .diff import diff_latest
        d = diff_latest(result["target"], args.out)
        if not d:
            console.print("[dim]diff: no previous run to compare against[/dim]")
        else:
            from .triage.rank import _compact
            console.print(f"\n[bold]Changes vs {d['previous']}:[/bold] "
                          f"[green]+{len(d['added'])}[/green] [red]-{len(d['removed'])}[/red] "
                          f"[dim]({d['same']} unchanged)[/dim]")
            for i in d["added"]:
                console.print(f"  [green]+ {_compact({'id': '', **i}).strip()}[/green]")
            for i in d["removed"]:
                console.print(f"  [red]- {_compact({'id': '', **i}).strip()}[/red]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
