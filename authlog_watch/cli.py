"""Command line entry point for authlog-watch."""

from __future__ import annotations

import argparse
import os
import sys

from authlog_watch import __version__
from authlog_watch.detectors import DetectorConfig, run_detectors
from authlog_watch.models import ScanResult, Severity
from authlog_watch.parser import parse_lines
from authlog_watch.report import render_json, render_text

_DEFAULTS = DetectorConfig()
_SEVERITY_CHOICES = ["info", "low", "medium", "high", "critical"]


def build_parser() -> argparse.ArgumentParser:
    """Build the ``argparse`` parser for the authlog-watch command line."""
    parser = argparse.ArgumentParser(
        prog="authlog-watch",
        description=(
            "Scan a Linux SSH auth log for brute force activity and report "
            "the source IPs involved, classified by severity."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="/var/log/auth.log",
        help='Path to the log file, or "-" to read stdin. Default: /var/log/auth.log',
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of the text report",
    )
    parser.add_argument(
        "--min-severity",
        choices=_SEVERITY_CHOICES,
        default="low",
        help=(
            "Findings below this level are dropped from output and ignored "
            "when computing the exit code. Default: low"
        ),
    )
    parser.add_argument(
        "--volume-threshold",
        type=int,
        default=_DEFAULTS.volume_threshold,
        help=f"Total failures from one IP to flag as high volume. Default: {_DEFAULTS.volume_threshold}",
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=_DEFAULTS.window_seconds,
        help=f"Length of the burst detection window, in seconds. Default: {_DEFAULTS.window_seconds}",
    )
    parser.add_argument(
        "--window-threshold",
        type=int,
        default=_DEFAULTS.window_threshold,
        help=f"Failures inside the window to flag a burst. Default: {_DEFAULTS.window_threshold}",
    )
    parser.add_argument(
        "--spray-threshold",
        type=int,
        default=_DEFAULTS.spray_threshold,
        help=f"Distinct usernames from one IP to flag username spray. Default: {_DEFAULTS.spray_threshold}",
    )
    parser.add_argument(
        "--success-after-failures",
        type=int,
        default=_DEFAULTS.success_after_failures,
        help=(
            "Failures preceding a success, from the same IP, to flag it as "
            f"critical. Default: {_DEFAULTS.success_after_failures}"
        ),
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year to assume for syslog timestamps that omit it. Default: current year",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"authlog-watch {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the authlog-watch CLI and return a process exit code.

    Exit codes: 0 when no findings meet ``--min-severity``, 1 when at least
    one does, 2 for usage errors, a missing file, or a permission error.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.path == "-":
            lines = sys.stdin.readlines()
        else:
            with open(args.path, "r", encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()
    except FileNotFoundError:
        print(f"authlog-watch: error: log file not found: {args.path}", file=sys.stderr)
        return 2
    except PermissionError:
        print(
            f"authlog-watch: error: permission denied reading {args.path} "
            "(try running with sudo)",
            file=sys.stderr,
        )
        return 2

    events, lines_read, lines_unparsed = parse_lines(lines, default_year=args.year)

    config = DetectorConfig(
        volume_threshold=args.volume_threshold,
        window_seconds=args.window_seconds,
        window_threshold=args.window_threshold,
        spray_threshold=args.spray_threshold,
        success_after_failures=args.success_after_failures,
    )
    findings = run_detectors(events, config)

    min_severity = Severity[args.min_severity.upper()]
    findings = [finding for finding in findings if finding.severity >= min_severity]

    result = ScanResult(
        findings=findings,
        events_parsed=len(events),
        lines_read=lines_read,
        lines_unparsed=lines_unparsed,
    )

    use_color = (
        not args.no_color
        and sys.stdout.isatty()
        and not os.environ.get("NO_COLOR")
    )

    if args.json:
        print(render_json(result))
    else:
        print(render_text(result, use_color=use_color))

    return 1 if findings else 0
