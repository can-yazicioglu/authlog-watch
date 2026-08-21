"""Tests for authlog_watch.detectors.

Event lists are built directly here rather than parsed from text, so these
tests exercise detector logic independently of the parser.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from authlog_watch.detectors import (
    DetectorConfig,
    detect_burst,
    detect_high_volume,
    detect_success_after_failures,
    detect_username_spray,
    run_detectors,
)
from authlog_watch.models import EventType, LogEvent, Severity

BASE_TIME = datetime(2026, 1, 12, 3, 0, 0)


def make_event(
    offset_seconds: float,
    event_type: EventType,
    username: str = "root",
    source_ip: str = "203.0.113.44",
    port: int = 51234,
) -> LogEvent:
    """Build a LogEvent offset by some number of seconds from BASE_TIME."""
    return LogEvent(
        timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        port=port,
        raw_line="<test>",
    )


def failure(offset_seconds: float, username: str = "root", source_ip: str = "203.0.113.44") -> LogEvent:
    """Shorthand for a FAILED_PASSWORD event."""
    return make_event(offset_seconds, EventType.FAILED_PASSWORD, username=username, source_ip=source_ip)


def success(
    offset_seconds: float,
    username: str = "root",
    source_ip: str = "203.0.113.44",
    event_type: EventType = EventType.ACCEPTED_PASSWORD,
) -> LogEvent:
    """Shorthand for a successful authentication event."""
    return make_event(offset_seconds, event_type, username=username, source_ip=source_ip)


# --- detect_high_volume -----------------------------------------------------


def test_high_volume_fires_at_threshold() -> None:
    """An IP with exactly volume_threshold failures fires (MEDIUM)."""
    config = DetectorConfig(volume_threshold=10)
    events = [failure(i * 10, username="root") for i in range(10)]
    findings = detect_high_volume(events, config)
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].source_ip == "203.0.113.44"
    assert findings[0].evidence["failure_count"] == 10


def test_high_volume_does_not_fire_one_below_threshold() -> None:
    """An IP with volume_threshold - 1 failures must not fire."""
    config = DetectorConfig(volume_threshold=10)
    events = [failure(i * 10, username="root") for i in range(9)]
    findings = detect_high_volume(events, config)
    assert findings == []


def test_high_volume_escalates_to_high_over_three_times_threshold() -> None:
    """More than 3x the threshold escalates severity to HIGH."""
    config = DetectorConfig(volume_threshold=10)
    events = [failure(i * 5, username=f"user{i}") for i in range(31)]
    findings = detect_high_volume(events, config)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


def test_high_volume_empty_events() -> None:
    """An empty event list produces no findings."""
    assert detect_high_volume([], DetectorConfig()) == []


# --- detect_burst ------------------------------------------------------------


def test_burst_fires_within_sliding_window() -> None:
    """window_threshold failures inside window_seconds fires, even when the
    burst straddles what would be a fixed-bucket boundary.
    """
    config = DetectorConfig(window_seconds=60, window_threshold=5)
    # Five failures within a 50-second span, starting mid-way through a
    # hypothetical fixed 60s bucket, so only a true sliding window catches it.
    events = [failure(45 + i * 10) for i in range(5)]
    findings = detect_burst(events, config)
    assert len(findings) == 1
    assert findings[0].evidence["peak_count"] == 5


def test_burst_does_not_fire_one_below_threshold() -> None:
    """window_threshold - 1 failures inside the window must not fire."""
    config = DetectorConfig(window_seconds=60, window_threshold=5)
    events = [failure(i * 10) for i in range(4)]
    findings = detect_burst(events, config)
    assert findings == []


def test_burst_does_not_fire_when_spread_out() -> None:
    """Failures spread far beyond the window never accumulate a peak."""
    config = DetectorConfig(window_seconds=60, window_threshold=5)
    events = [failure(i * 3600) for i in range(11)]  # one per hour
    findings = detect_burst(events, config)
    assert findings == []


def test_burst_empty_events() -> None:
    """An empty event list produces no findings."""
    assert detect_burst([], DetectorConfig()) == []


# --- detect_username_spray ---------------------------------------------------


def test_username_spray_fires_at_threshold() -> None:
    """An IP trying exactly spray_threshold distinct usernames fires."""
    config = DetectorConfig(spray_threshold=5)
    events = [failure(i * 5, username=f"user{i}") for i in range(5)]
    findings = detect_username_spray(events, config)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].evidence["distinct_usernames"] == 5


def test_username_spray_does_not_fire_one_below_threshold() -> None:
    """spray_threshold - 1 distinct usernames must not fire."""
    config = DetectorConfig(spray_threshold=5)
    events = [failure(i * 5, username=f"user{i}") for i in range(4)]
    findings = detect_username_spray(events, config)
    assert findings == []


def test_username_spray_ignores_repeated_single_username() -> None:
    """Many failures against a single account is not a spray."""
    config = DetectorConfig(spray_threshold=5)
    events = [failure(i * 5, username="root") for i in range(20)]
    findings = detect_username_spray(events, config)
    assert findings == []


def test_username_spray_empty_events() -> None:
    """An empty event list produces no findings."""
    assert detect_username_spray([], DetectorConfig()) == []


# --- detect_success_after_failures -------------------------------------------


def test_success_after_failures_fires() -> None:
    """A success preceded by at least success_after_failures failures fires
    CRITICAL.
    """
    config = DetectorConfig(success_after_failures=3)
    events = [failure(i * 10, username="deploy") for i in range(4)]
    events.append(success(50, username="deploy"))
    findings = detect_success_after_failures(events, config)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].evidence["account"] == "deploy"
    assert findings[0].evidence["prior_failures"] == 4
    assert findings[0].evidence["method"] == "password"


def test_success_after_failures_does_not_fire_below_threshold() -> None:
    """A success preceded by success_after_failures - 1 failures must not fire."""
    config = DetectorConfig(success_after_failures=3)
    events = [failure(i * 10, username="deploy") for i in range(2)]
    events.append(success(50, username="deploy"))
    findings = detect_success_after_failures(events, config)
    assert findings == []


def test_success_with_zero_preceding_failures_does_not_fire() -> None:
    """A clean success with no prior failures must not fire."""
    config = DetectorConfig(success_after_failures=3)
    events = [success(0, username="can", source_ip="192.168.1.30")]
    findings = detect_success_after_failures(events, config)
    assert findings == []


def test_legitimate_mistype_then_success_does_not_fire() -> None:
    """One mistyped password followed by success is normal user behaviour,
    not a brute force finding.
    """
    config = DetectorConfig(success_after_failures=3)
    events = [
        failure(0, username="can", source_ip="192.168.1.30"),
        success(5, username="can", source_ip="192.168.1.30"),
    ]
    findings = detect_success_after_failures(events, config)
    assert findings == []


def test_success_after_failures_publickey_method() -> None:
    """The evidence records publickey as the method when that's how the
    success happened.
    """
    config = DetectorConfig(success_after_failures=3)
    events = [failure(i * 10, username="root") for i in range(5)]
    events.append(success(60, username="root", event_type=EventType.ACCEPTED_PUBLICKEY))
    findings = detect_success_after_failures(events, config)
    assert len(findings) == 1
    assert findings[0].evidence["method"] == "publickey"


def test_success_after_failures_empty_events() -> None:
    """An empty event list produces no findings."""
    assert detect_success_after_failures([], DetectorConfig()) == []


# --- run_detectors ------------------------------------------------------------


def test_run_detectors_sorts_by_severity_then_ip() -> None:
    """Findings come back sorted by severity descending, then by IP."""
    config = DetectorConfig(
        volume_threshold=10, spray_threshold=5, success_after_failures=3
    )
    events = []
    # High volume + spray on .44 (MEDIUM + HIGH)
    events += [failure(i * 5, username=f"user{i}", source_ip="203.0.113.44") for i in range(12)]
    # Critical success-after-failures on .23
    events += [failure(i * 10, username="deploy", source_ip="198.51.100.23") for i in range(4)]
    events.append(success(50, username="deploy", source_ip="198.51.100.23"))

    findings = run_detectors(events, config)
    assert [f.severity for f in findings] == sorted(
        (f.severity for f in findings), reverse=True
    )
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].source_ip == "198.51.100.23"


def test_run_detectors_empty_events() -> None:
    """No events means no findings, from any detector."""
    assert run_detectors([], DetectorConfig()) == []
