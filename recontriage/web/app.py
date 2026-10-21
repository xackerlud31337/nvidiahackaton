"""Thin web front end: a browser page that looks like a terminal.

How it works
------------
* The page POSTs {"target": ..., options} to /api/scan.
* The server runs pipeline.run() in a background thread and streams events
  back as newline-delimited JSON (NDJSON) over the same HTTP response:
      {"type": "log",    "line": "[ports] nmap ..."}      one per log line
      {"type": "report", "html": "<pre>...</pre>"}        the rich table + note
      {"type": "error",  "message": "..."}
      {"type": "done"}
  The browser reads the stream with fetch() and appends lines as they come,
  which is what makes it feel like a live terminal.
* The report is rendered by the SAME print_report() the CLI uses, into a
  recording rich Console, then exported as HTML. So the web view is pixel-
  for-pixel what the terminal shows, colours included. No second renderer.
* The scope guard is unchanged: the server refuses out-of-scope targets with
  the same OutOfScopeError, which arrives in the browser as an error event.

This is a demo UI, bound to localhost. It is not hardened for the internet.
"""
from __future__ import annotations

import io
import json
import queue
import threading
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from rich.console import Console

from .. import pipeline
from ..cli import print_report
from ..scope import OutOfScopeError

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="ReconTriage")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class ScanRequest(BaseModel):
    target: str
    skip_subdomains: bool = False
    skip_dirs: bool = False
    no_llm: bool = False
    top_ports: int = 1000
    scope: str = "scope.txt"


_DONE = object()   # sentinel the worker puts on the queue when finished


def _render_report_html(result: dict) -> str:
    """Run the CLI's print_report into a recording console, export as HTML."""
    console = Console(record=True, file=io.StringIO(), width=110,
                      force_terminal=True, color_system="truecolor")
    print_report(result, console)
    # code_format gives us just the <pre>, not a full <html> document.
    return console.export_html(inline_styles=True, code_format="<pre class=\"rich\">{code}</pre>")


def _worker(req: ScanRequest, q: "queue.Queue[dict | object]") -> None:
    """Runs in a thread. Everything it wants the browser to see goes on q."""
    opts = pipeline.Options(
        scope_path=req.scope,
        skip_subdomains=req.skip_subdomains,
        skip_dirs=req.skip_dirs,
        no_llm=req.no_llm,
        top_ports=req.top_ports,
        log=lambda line: q.put({"type": "log", "line": line}),
    )
    try:
        result = pipeline.run(req.target, opts)
        from ..cli import save_run
        folder = save_run(result, "runs")
        q.put({"type": "report", "html": _render_report_html(result)})
        q.put({"type": "log", "line": f"saved to {folder}/"})
    except OutOfScopeError as e:
        q.put({"type": "error", "message": f"REFUSED: {e}"})
    except Exception as e:  # noqa: BLE001 - surface anything to the UI
        q.put({"type": "error", "message": f"{type(e).__name__}: {e}"})
    finally:
        q.put(_DONE)


@app.post("/api/scan")
def scan(req: ScanRequest):
    q: "queue.Queue[dict | object]" = queue.Queue()
    threading.Thread(target=_worker, args=(req, q), daemon=True).start()

    def events():
        while True:
            item = q.get()
            if item is _DONE:
                yield json.dumps({"type": "done"}) + "\n"
                return
            yield json.dumps(item) + "\n"

    return StreamingResponse(events(), media_type="application/x-ndjson")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


def main() -> None:
    """`recontriage-web [--port N]`. Default 8765 because 8000 is often busy."""
    import argparse
    import uvicorn
    load_dotenv()
    ap = argparse.ArgumentParser(prog="recontriage-web")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1", help="keep this localhost; the UI is not hardened")
    a = ap.parse_args()
    print(f"ReconTriage web UI on http://{a.host}:{a.port}  (Ctrl+C to stop)")
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
