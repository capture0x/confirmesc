"""confirmesc CLI entry point."""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .checks import ALL_CHECKS
from .core.base import Confidence
from .core.runner import run_checks
from .report import render_html, render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="confirmesc",
        description=(
            "Linux privilege escalation enumerator that CONFIRMS findings against "
            "the real system state instead of just listing suspicious-looking things."
        ),
    )
    parser.add_argument(
        "--active",
        action="store_true",
        help=(
            "Allow non-destructive active confirmation probes (e.g. running a "
            "suspected GTFOBins binary with --version to prove it's live). "
            "Never writes to disk or spawns exploits. Default: off (fully passive)."
        ),
    )
    parser.add_argument(
        "--poc",
        action="store_true",
        help=(
            "DANGEROUS/INVASIVE: actually execute the real GTFOBins escalation "
            "payload for every SUID/sudo/capability vector we have a curated "
            "recipe for, and verify the resulting process really has euid 0. "
            "This is live exploitation, not just a condition check. Payloads "
            "are read-only ('id -u') - no shell, no file writes, no persistence "
            "- but only run this against systems you are explicitly authorized "
            "to test (your own box, a CTF, or a signed engagement)."
        ),
    )
    parser.add_argument("--format", choices=["text", "json", "html"], default="text", help="Output format (default: text).")
    parser.add_argument("--quiet", action="store_true", help="Suppress the per-check progress lines on stderr.")
    parser.add_argument("-o", "--output", metavar="FILE", help="Write report to FILE instead of stdout.")
    parser.add_argument(
        "--category",
        action="append",
        dest="categories",
        metavar="NAME",
        help="Only run checks whose category matches NAME. Repeatable.",
    )
    parser.add_argument(
        "--min-confidence",
        choices=[c.value for c in Confidence],
        default=None,
        help="Only show findings at or above this confidence (CONFIRMED > LIKELY > INFO > ERROR).",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in text output.")
    parser.add_argument("--version", action="version", version=f"confirmesc {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.poc:
        print(
            "[!] --poc: actually running real escalation payloads against this "
            "system to prove root access. Only continue if you are authorized "
            "to test this system.",
            file=sys.stderr,
        )

    checks = [
        cls(active=args.active, poc=args.poc)
        for cls in ALL_CHECKS
        if not args.categories or cls.category in args.categories
    ]
    if not checks:
        print("No checks matched the given --category filter(s).", file=sys.stderr)
        return 2

    def on_check_done(check_id: str, duration: float) -> None:
        if not args.quiet:
            print(f"[*] {check_id} done ({duration:.1f}s)", file=sys.stderr)

    result = run_checks(checks, on_check_done=on_check_done)

    if args.min_confidence:
        order = {c.value: i for i, c in enumerate([Confidence.CONFIRMED, Confidence.LIKELY, Confidence.INFO, Confidence.ERROR])}
        threshold = order[args.min_confidence]
        result.findings = [f for f in result.findings if order[f.confidence.value] <= threshold]

    if args.format == "json":
        output = render_json(result)
    elif args.format == "html":
        output = render_html(result)
    else:
        use_color = not args.no_color and sys.stdout.isatty() and not args.output
        output = render_text(result, use_color=use_color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
        print(f"Report written to {args.output}")
    else:
        print(output)

    if os.geteuid() == 0:
        print("\n[!] Running as root - most findings are irrelevant. Run as the target unprivileged user instead.", file=sys.stderr)

    has_confirmed = any(f.confidence == Confidence.CONFIRMED for f in result.findings)
    return 1 if has_confirmed else 0


if __name__ == "__main__":
    sys.exit(main())
