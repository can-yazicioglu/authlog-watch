"""Tests for authlog_watch.parser."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from authlog_watch.models import EventType
from authlog_watch.parser import parse_line, parse_lines

DATA_DIR = Path(__file__).parent / "data"


def test_failed_password_for_invalid_user() -> None:
    """'Failed password for invalid user X' is parsed as FAILED_PASSWORD."""
    line = (
        "Jan 12 03:14:02 host sshd[2211]: Failed password for invalid user "
        "admin from 203.0.113.44 port 51234 ssh2"
    )
    event = parse_line(line, default_year=2026)
    assert event is not None
    assert event.event_type is EventType.FAILED_PASSWORD
    assert event.username == "admin"
    assert event.source_ip == "203.0.113.44"
    assert event.port == 51234
    assert event.is_failure is True
    assert event.is_success is False


def test_failed_password_for_known_user() -> None:
    """'Failed password for X' (no 'invalid user') is also FAILED_PASSWORD."""
    line = (
        "Jan 12 03:14:03 host sshd[2211]: Failed password for root "
        "from 203.0.113.44 port 51234 ssh2"
    )
    event = parse_line(line, default_year=2026)
    assert event is not None
    assert event.event_type is EventType.FAILED_PASSWORD
    assert event.username == "root"


def test_accepted_password() -> None:
    """'Accepted password for X' is parsed as ACCEPTED_PASSWORD."""
    line = (
        "Jan 12 03:14:04 host sshd[2212]: Accepted password for can "
        "from 192.168.1.30 port 44122 ssh2"
    )
    event = parse_line(line, default_year=2026)
    assert event is not None
    assert event.event_type is EventType.ACCEPTED_PASSWORD
    assert event.username == "can"
    assert event.is_success is True
    assert event.is_failure is False


def test_accepted_publickey() -> None:
    """'Accepted publickey for X ...: RSA ...' is parsed as ACCEPTED_PUBLICKEY."""
    line = (
        "Jan 12 03:14:05 host sshd[2213]: Accepted publickey for can "
        "from 192.168.1.30 port 44130 ssh2: RSA SHA256:abc123"
    )
    event = parse_line(line, default_year=2026)
    assert event is not None
    assert event.event_type is EventType.ACCEPTED_PUBLICKEY
    assert event.username == "can"
    assert event.port == 44130
    assert event.is_success is True


def test_invalid_user() -> None:
    """'Invalid user X from IP port P' (no 'from' before IP is still present,
    but there is no 'Failed password' and no 'ssh2') is parsed as INVALID_USER.
    """
    line = "Jan 12 03:14:06 host sshd[2214]: Invalid user oracle from 203.0.113.44 port 51260"
    event = parse_line(line, default_year=2026)
    assert event is not None
    assert event.event_type is EventType.INVALID_USER
    assert event.username == "oracle"
    assert event.is_failure is True


def test_connection_closed_preauth() -> None:
    """'Connection closed by authenticating user X IP port P [preauth]' has
    no 'from' keyword before the IP, and must still parse correctly.
    """
    line = (
        "Jan 12 03:14:07 host sshd[2215]: Connection closed by authenticating "
        "user root 203.0.113.44 port 51262 [preauth]"
    )
    event = parse_line(line, default_year=2026)
    assert event is not None
    assert event.event_type is EventType.CONNECTION_CLOSED_PREAUTH
    assert event.username == "root"
    assert event.source_ip == "203.0.113.44"
    assert event.port == 51262
    assert event.is_failure is True


def test_sudo_line_is_ignored() -> None:
    """Lines from processes other than sshd (e.g. sudo) return None."""
    line = (
        "Jan 12 03:14:08 host sudo: can : TTY=pts/0 ; PWD=/home/can ; "
        "USER=root ; COMMAND=/usr/bin/whoami"
    )
    assert parse_line(line, default_year=2026) is None


def test_garbage_returns_none() -> None:
    """Lines that are not recognisable log lines at all return None."""
    assert parse_line("this is not a log line", default_year=2026) is None
    assert parse_line("", default_year=2026) is None


def test_sshd_line_with_unrecognised_message_returns_none() -> None:
    """An sshd line whose message body doesn't match any known shape is
    ignored rather than raising.
    """
    line = "Jan 12 03:14:09 host sshd[2216]: some brand new message format"
    assert parse_line(line, default_year=2026) is None


def test_truncated_sshd_line_does_not_crash() -> None:
    """A truncated message body must not raise, only return None."""
    line = "Jan 12 03:14:10 host sshd[2217]: Failed password for"
    assert parse_line(line, default_year=2026) is None


def test_rfc3339_timestamp_format() -> None:
    """RFC 3339 timestamps, as written by rsyslog/systemd, are parsed."""
    line = (
        "2026-01-12T03:14:02.123456+00:00 host sshd[2211]: Failed password "
        "for root from 203.0.113.44 port 51234 ssh2"
    )
    event = parse_line(line)
    assert event is not None
    assert event.timestamp == datetime(2026, 1, 12, 3, 14, 2, 123456)


def test_rfc3339_timestamp_with_z_suffix() -> None:
    """RFC 3339 timestamps may use a bare 'Z' instead of '+00:00'."""
    line = (
        "2026-01-12T03:14:02Z host sshd[2211]: Accepted password "
        "for can from 192.168.1.30 port 44122 ssh2"
    )
    event = parse_line(line)
    assert event is not None
    assert event.timestamp == datetime(2026, 1, 12, 3, 14, 2)


def test_syslog_timestamp_uses_default_year() -> None:
    """A traditional syslog timestamp with no year uses default_year."""
    line = (
        "Jan 12 03:14:02 host sshd[2211]: Failed password for root "
        "from 203.0.113.44 port 51234 ssh2"
    )
    event = parse_line(line, default_year=2025)
    assert event is not None
    assert event.timestamp == datetime(2025, 1, 12, 3, 14, 2)


def test_year_rollover_forward_crossing() -> None:
    """A December event immediately followed, in file order, by a January
    event must resolve the January event to the following year, even though
    both lines omit the year.
    """
    december = parse_line(
        "Dec 31 23:58:00 host sshd[1]: Failed password for root from 192.0.2.50 port 41000 ssh2",
        default_year=2025,
    )
    assert december is not None
    assert december.timestamp == datetime(2025, 12, 31, 23, 58, 0)

    january = parse_line(
        "Jan 1 00:00:45 host sshd[2]: Failed password for root from 192.0.2.50 port 41001 ssh2",
        default_year=2025,
        previous=december.timestamp,
    )
    assert january is not None
    assert january.timestamp == datetime(2026, 1, 1, 0, 0, 45)


def test_year_rollover_out_of_order_december() -> None:
    """A stray December line that appears after a January reference point,
    and would naively look like it jumped ~11 months into the future, is
    pulled back a year instead.
    """
    january = parse_line(
        "Jan 5 09:00:00 host sshd[1]: Failed password for root from 192.0.2.50 port 41000 ssh2",
        default_year=2026,
    )
    assert january is not None

    december = parse_line(
        "Dec 31 23:58:00 host sshd[2]: Failed password for root from 192.0.2.50 port 41001 ssh2",
        default_year=2026,
        previous=january.timestamp,
    )
    assert december is not None
    assert december.timestamp == datetime(2025, 12, 31, 23, 58, 0)


def test_parse_lines_counts_and_rollover_fixture() -> None:
    """parse_lines reports correct read/unparsed counts against a fixture
    that mixes both timestamp formats and crosses a year boundary.
    """
    with open(DATA_DIR / "mixed_auth.log", encoding="utf-8") as handle:
        raw_lines = handle.readlines()

    events, lines_read, lines_unparsed = parse_lines(raw_lines, default_year=2026)

    assert lines_read == len(raw_lines)
    assert lines_unparsed == 4
    assert len(events) == lines_read - lines_unparsed

    december_test_events = [event for event in events if event.username == "test"]
    assert any(event.timestamp.year == 2025 and event.timestamp.month == 12 for event in december_test_events)
    assert any(event.timestamp.year == 2026 and event.timestamp.month == 1 for event in december_test_events)
