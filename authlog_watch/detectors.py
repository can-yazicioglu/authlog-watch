"""Brute force detection rules that turn parsed events into findings.

Each detector is a pure function of ``(events, config)``. None of them touch
the network or mutate shared state, so they can be run in any order and
tested in isolation from the parser.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from authlog_watch.models import EventType, Finding, LogEvent, Severity


@dataclass(frozen=True)
class DetectorConfig:
    """Tunable thresholds shared by all detectors."""

    volume_threshold: int = 10
    window_seconds: int = 60
    window_threshold: int = 5
    spray_threshold: int = 5
    success_after_failures: int = 3


def _failures_by_ip(events: list[LogEvent]) -> dict[str, list[LogEvent]]:
    """Group failed-authentication events by source IP, each list time-sorted."""
    grouped: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.is_failure:
            grouped[event.source_ip].append(event)
    for failures in grouped.values():
        failures.sort(key=lambda event: event.timestamp)
    return grouped


def detect_high_volume(events: list[LogEvent], config: DetectorConfig) -> list[Finding]:
    """Flag an IP with at least ``volume_threshold`` total failed attempts.

    Severity is HIGH when the failure count exceeds three times the
    threshold, MEDIUM otherwise.
    """
    findings: list[Finding] = []
    for ip, failures in _failures_by_ip(events).items():
        count = len(failures)
        if count < config.volume_threshold:
            continue

        usernames = sorted({event.username for event in failures})
        first_seen = failures[0].timestamp
        last_seen = failures[-1].timestamp
        span_seconds = (last_seen - first_seen).total_seconds()

        severity = Severity.HIGH if count > config.volume_threshold * 3 else Severity.MEDIUM
        if len(usernames) == 1:
            summary = f"{count} failed attempts as {usernames[0]}"
        else:
            summary = f"{count} failed attempts across {len(usernames)} usernames"

        findings.append(
            Finding(
                rule="high_volume",
                severity=severity,
                source_ip=ip,
                summary=summary,
                evidence={
                    "failure_count": count,
                    "distinct_usernames": len(usernames),
                    "usernames_sample": usernames[:10],
                    "span_seconds": span_seconds,
                },
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )
    return findings


def detect_burst(events: list[LogEvent], config: DetectorConfig) -> list[Finding]:
    """Flag an IP with ``window_threshold`` failures inside any sliding window.

    Uses a real sliding window over the sorted failure timestamps rather
    than fixed-size buckets, so a burst that straddles a bucket boundary is
    still caught.
    """
    findings: list[Finding] = []
    window = timedelta(seconds=config.window_seconds)

    for ip, failures in _failures_by_ip(events).items():
        timestamps = [event.timestamp for event in failures]
        peak_count = 0
        peak_start: datetime | None = None
        peak_end: datetime | None = None

        left = 0
        for right, right_ts in enumerate(timestamps):
            while right_ts - timestamps[left] > window:
                left += 1
            count = right - left + 1
            if count > peak_count:
                peak_count = count
                peak_start = timestamps[left]
                peak_end = right_ts

        if peak_count < config.window_threshold or peak_start is None or peak_end is None:
            continue

        attempts_per_minute = round(peak_count / (config.window_seconds / 60), 1)
        findings.append(
            Finding(
                rule="burst",
                severity=Severity.MEDIUM,
                source_ip=ip,
                summary=(
                    f"{peak_count} failed attempts within a {config.window_seconds}s window"
                ),
                evidence={
                    "peak_count": peak_count,
                    "window_start": peak_start.isoformat(),
                    "window_end": peak_end.isoformat(),
                    "window_seconds": config.window_seconds,
                    "attempts_per_minute": attempts_per_minute,
                },
                first_seen=timestamps[0],
                last_seen=timestamps[-1],
            )
        )
    return findings


def detect_username_spray(events: list[LogEvent], config: DetectorConfig) -> list[Finding]:
    """Flag an IP that tried at least ``spray_threshold`` distinct usernames.

    This is the strongest signal in the tool: a legitimate user mistyping a
    password only ever tries one account, so username spread all but rules
    out an innocent explanation.
    """
    findings: list[Finding] = []
    for ip, failures in _failures_by_ip(events).items():
        usernames = sorted({event.username for event in failures})
        if len(usernames) < config.spray_threshold:
            continue

        first_seen = failures[0].timestamp
        last_seen = failures[-1].timestamp
        findings.append(
            Finding(
                rule="username_spray",
                severity=Severity.HIGH,
                source_ip=ip,
                summary=f"tried {len(usernames)} distinct usernames",
                evidence={
                    "distinct_usernames": len(usernames),
                    "usernames_sample": usernames[:20],
                },
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )
    return findings


_METHOD_BY_EVENT_TYPE = {
    EventType.ACCEPTED_PASSWORD: "password",
    EventType.ACCEPTED_PUBLICKEY: "publickey",
}


def detect_success_after_failures(
    events: list[LogEvent], config: DetectorConfig
) -> list[Finding]:
    """Flag a successful login preceded by a run of failures from the same IP.

    This is the highest-value finding the tool produces: it means the brute
    force may have worked. Only failures strictly before the success, in
    time order, count towards the threshold.
    """
    findings: list[Finding] = []
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.source_ip].append(event)

    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda event: event.timestamp)
        failures_so_far = 0
        for event in ip_events:
            if event.is_failure:
                failures_so_far += 1
                continue
            if event.is_success and failures_so_far >= config.success_after_failures:
                findings.append(
                    Finding(
                        rule="success_after_failures",
                        severity=Severity.CRITICAL,
                        source_ip=ip,
                        summary=(
                            f"successful login as {event.username} after "
                            f"{failures_so_far} failed attempts"
                        ),
                        evidence={
                            "account": event.username,
                            "prior_failures": failures_so_far,
                            "succeeded_at": event.timestamp.isoformat(),
                            "method": _METHOD_BY_EVENT_TYPE.get(event.event_type, "unknown"),
                        },
                        first_seen=ip_events[0].timestamp,
                        last_seen=event.timestamp,
                    )
                )
            # A success (of any prior-failure count) resets the run, matching
            # how a fresh attempt sequence starts after any login outcome.
            failures_so_far = 0
    return findings


ALL_DETECTORS: list[Callable[[list[LogEvent], DetectorConfig], list[Finding]]] = [
    detect_high_volume,
    detect_burst,
    detect_username_spray,
    detect_success_after_failures,
]


def run_detectors(events: list[LogEvent], config: DetectorConfig) -> list[Finding]:
    """Run every detector and return findings sorted by severity, then IP."""
    findings: list[Finding] = []
    for detector in ALL_DETECTORS:
        findings.extend(detector(events, config))
    findings.sort(key=lambda finding: (-int(finding.severity), finding.source_ip))
    return findings
