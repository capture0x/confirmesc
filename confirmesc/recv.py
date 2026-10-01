"""confirmesc-recv: a tiny listener for `confirmesc --send`.

Runs on YOUR machine. Receives the JSON report that a `confirmesc --send URL`
run POSTs to it, renders it exactly like a local run would, and saves a
timestamped copy. The scan itself runs on the target with the same local
check code that's already tested here; only the finished report travels back.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .report import render_html, render_text, result_from_payload


def _make_handler(save_dir: Path, save_format: str):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw)
                result = result_from_payload(payload)
            except Exception as exc:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(f"bad payload: {exc}".encode())
                return

            meta = payload.get("meta", {})
            duration = payload.get("duration")
            host = meta.get("hostname", "unknown")
            text = render_text(result, use_color=False, duration=duration, meta=meta)

            print("\n" + "=" * 72)
            print(f"[*] Report received from {self.client_address[0]} (host={host})")
            print("=" * 72)
            print(text)

            stamp = time.strftime("%Y%m%d-%H%M%S")
            if save_format == "html":
                out = save_dir / f"confirmesc-{host}-{stamp}.html"
                out.write_text(render_html(result, duration=duration, meta=meta))
            elif save_format == "json":
                out = save_dir / f"confirmesc-{host}-{stamp}.json"
                out.write_text(json.dumps(payload, indent=2, default=str))
            else:
                out = save_dir / f"confirmesc-{host}-{stamp}.txt"
                out.write_text(text)
            print(f"[*] Saved to {out}", file=sys.stderr)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args) -> None:  # silence default access logging
            pass

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="confirmesc-recv",
        description="Listen for reports pushed by `confirmesc --send`.",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: all interfaces).")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000).")
    parser.add_argument("--save-dir", default=".", help="Where to save received reports (default: cwd).")
    parser.add_argument("--save-format", choices=["text", "json", "html"], default="text")
    args = parser.parse_args(argv)

    save_dir = Path(args.save_dir)
    save_dir.mkdir(parents=True, exist_ok=True)
    server = HTTPServer((args.host, args.port), _make_handler(save_dir, args.save_format))
    print(
        f"[*] confirmesc-recv listening on http://{args.host}:{args.port}\n"
        f"    on the target run:  confirmesc --send http://<YOUR-IP>:{args.port}",
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] bye", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
