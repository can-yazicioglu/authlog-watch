"""Render a :class:`~authlog_watch.models.ScanResult` as text or JSON."""

from __future__ import annotations

import json

from authlog_watch.models import Finding, ScanResult, Severity

_RESET = "\033[0m"
_COLOR_BY_SEVERITY = {
    Severity.CRITICAL: "\033[31m",  # red
    Severity.HIGH: "\033[31m",  # red
    Severity.MEDIUM: "\033[33m",  # yellow
    Severity.LOW: "\033[34m",  # blue
}

_SEVERITY_LABEL_WIDTH = 8
_IP_COLUMN_WIDTH = 15
_DETAIL_INDENT = " " * 12


def _format_span(seconds: float) -> str:
    """Format a duration in seconds as ``HH:MM:SS``."""
    total = int(seconds)
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"

def _evidence_line(finding: Finding) -> str | None:
    """Build the one-line evidence detail shown under a finding's summary.

    Formatting is chosen per rule so the most relevant fields for that rule
    read naturally; unrecognised rules fall back to a plain key=value dump.
    """
    evidence = finding.evidence
    if finding.rule == "success_after_failures":
        return (
            f"method={evidence['method']}  "
            f"succeeded={evidence['succeeded_at']}  "
            f"prior_failures={evidence['prior_failures']}"
        )
    if finding.rule == "username_spray":
        sample = evidence["usernames_sample"]
        extra = evidence["distinct_usernames"] - len(sample)
        tried = ", ".join(sample)
        if extra > 0:
            tried += f" (+{extra} more)"
        return f"tried={tried}"
    if finding.rule == "high_volume":
        return f"span={_format_span(evidence['span_seconds'])}"
    if finding.rule == "burst":
        return (
            f"peak={evidence['peak_count']} attempts in {evidence['window_seconds']}s "
            f"({evidence['attempts_per_minute']}/min)"
        )
    return "  ".join(f"{key}={value}" for key, value in evidence.items())


def render_text(result: ScanResult, use_color: bool) -> str:
    """Render a scan result as aligned, human-readable terminal output."""
    if not result.findings:
        return (
            f"authlog-watch  scanned {result.lines_read:,} lines, "
            f"parsed {result.events_parsed:,} events, nothing suspicious found"
        )

    lines: list[str] = [
        f"authlog-watch  scanned {result.lines_read:,} lines, "
        f"parsed {result.events_parsed:,} events",
        "",
    ]

    for finding in result.findings:
        label = finding.severity.name
        padded_label = label.ljust(_SEVERITY_LABEL_WIDTH)
        if use_color:
            color = _COLOR_BY_SEVERITY.get(finding.severity, "")
            padded_label = f"{color}{padded_label}{_RESET}" if color else padded_label
        ip_column = finding.source_ip.ljust(_IP_COLUMN_WIDTH)
        lines.append(f"  {padded_label}  {ip_column} {finding.summary}")
        detail = _evidence_line(finding)
        if detail:
            lines.append(f"{_DETAIL_INDENT}{detail}")
        lines.append("")

    counts: dict[Severity, int] = {}
    for finding in result.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    ordered = sorted(counts.items(), key=lambda item: -int(item[0]))
    counts_text = ", ".join(f"{count} {severity.name.lower()}" for severity, count in ordered)
    lines.append(f"{len(result.findings)} findings  ({counts_text})")

    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    """Render a scan result as indented JSON. Never contains ANSI codes."""
    return json.dumps(result.to_dict(), indent=2)
