"""Parser turning raw auth.log lines into :class:`~authlog_watch.models.LogEvent`.

Only lines produced by ``sshd`` are recognised. Everything else, including
lines from ``sudo``, ``cron`` or ``systemd-logind``, and any line whose shape
does not match a known OpenSSH message, is ignored. A line is never fatal:
callers get ``None`` back instead of an exception.
"""

from __future__ import annotations

import calendar
import re
from datetime import datetime, timedelta
from typing import Iterable

from authlog_watch.models import EventType, LogEvent

_MONTH_NUMBERS: dict[str, int] = {
    abbr: index for index, abbr in enumerate(calendar.month_abbr) if abbr
}

# A traditional syslog line: "Jan 12 03:14:02 host sshd[2211]: <message>"
_SYSLOG_LINE_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

# An RFC 3339 line as written by modern rsyslog/systemd:
# "2026-01-12T03:14:02.123456+00:00 host sshd[2211]: <message>"
_RFC3339_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

_RFC3339_TS_RE = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<tz>Z|[+-]\d{2}:\d{2})$"
)

_IP_PATTERN = r"\d{1,3}(?:\.\d{1,3}){3}"

_FAILED_PASSWORD_RE = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) from "
    rf"(?P<ip>{_IP_PATTERN}) port (?P<port>\d+) ssh2$"
)
_ACCEPTED_PASSWORD_RE = re.compile(
    rf"^Accepted password for (?P<user>\S+) from (?P<ip>{_IP_PATTERN}) "
    r"port (?P<port>\d+) ssh2$"
)
_ACCEPTED_PUBLICKEY_RE = re.compile(
    rf"^Accepted publickey for (?P<user>\S+) from (?P<ip>{_IP_PATTERN}) "
    r"port (?P<port>\d+) ssh2(?::.*)?$"
)
_INVALID_USER_RE = re.compile(
    rf"^Invalid user (?P<user>\S+) from (?P<ip>{_IP_PATTERN}) port (?P<port>\d+)$"
)
_CONNECTION_CLOSED_RE = re.compile(
    r"^Connection closed by authenticating user (?P<user>\S+) "
    rf"(?P<ip>{_IP_PATTERN}) port (?P<port>\d+) \[preauth\]$"
)

_MESSAGE_PATTERNS: list[tuple[re.Pattern[str], EventType]] = [
    (_FAILED_PASSWORD_RE, EventType.FAILED_PASSWORD),
    (_ACCEPTED_PASSWORD_RE, EventType.ACCEPTED_PASSWORD),
    (_ACCEPTED_PUBLICKEY_RE, EventType.ACCEPTED_PUBLICKEY),
    (_INVALID_USER_RE, EventType.INVALID_USER),
    (_CONNECTION_CLOSED_RE, EventType.CONNECTION_CLOSED_PREAUTH),
]

_ROLLOVER_WINDOW = timedelta(hours=24)


def _parse_rfc3339(value: str) -> datetime | None:
    """Parse an RFC 3339 timestamp string into a naive ``datetime``.

    The UTC offset is validated for well-formedness but then discarded: all
    timestamps in this tool, whether parsed from RFC 3339 or from year-less
    syslog lines, are kept as naive wall-clock values so the two formats can
    be compared and sorted directly. Detectors only need the relative order
    and spacing of events within a single log, not an absolute UTC instant.
    Returns ``None`` instead of raising if the string is malformed, so a
    corrupt timestamp degrades to an unparsed line rather than a crash.
    """
    match = _RFC3339_TS_RE.match(value)
    if match is None:
        return None
    frac = match.group("frac") or ""
    microsecond = int((frac + "000000")[:6]) if frac else 0
    try:
        return datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            microsecond,
        )
    except ValueError:
        return None


def _resolve_syslog_timestamp(
    month_abbr: str,
    day: str,
    time_str: str,
    default_year: int,
    previous: datetime | None,
) -> datetime | None:
    """Resolve a year-less syslog timestamp to a full ``datetime``.

    The year is assumed to be ``default_year`` for the first event seen, and
    the previous event's year thereafter. Because that assumption breaks at
    a year boundary, the result is nudged by one year whenever it would
    otherwise land more than 24 hours away from ``previous``: more than 24
    hours in the future rolls it back a year (the classic case of an older,
    out-of-order December line following a January one), and more than 24
    hours in the past rolls it forward a year (a December line immediately
    followed, in file order, by the January of the next year).
    """
    month = _MONTH_NUMBERS.get(month_abbr)
    if month is None:
        return None
    try:
        hour, minute, second = (int(part) for part in time_str.split(":"))
        year = previous.year if previous is not None else default_year
        candidate = datetime(year, month, int(day), hour, minute, second)
    except ValueError:
        return None

    if previous is not None:
        try:
            if candidate > previous + _ROLLOVER_WINDOW:
                candidate = candidate.replace(year=candidate.year - 1)
            elif candidate < previous - _ROLLOVER_WINDOW:
                candidate = candidate.replace(year=candidate.year + 1)
        except ValueError:
            pass  # Feb 29 landing on a non-leap year after the shift: leave as-is.

    return candidate


def parse_line(
    line: str,
    default_year: int | None = None,
    previous: datetime | None = None,
) -> LogEvent | None:
    """Parse one raw auth.log line into a :class:`LogEvent`.

    Only lines emitted by ``sshd`` matching a recognised OpenSSH message are
    turned into events; anything else, including malformed or truncated
    lines, yields ``None``. ``default_year`` supplies the year for syslog
    timestamps (which omit one) when there is no ``previous`` event to infer
    it from; it defaults to the current calendar year. ``previous`` is the
    timestamp of the last successfully parsed event and is used to resolve
    year rollover, see :func:`_resolve_syslog_timestamp`.
    """
    text = line.rstrip("\n")
    if not text.strip():
        return None

    year = default_year if default_year is not None else datetime.now().year

    rfc_match = _RFC3339_LINE_RE.match(text)
    syslog_match = None if rfc_match is not None else _SYSLOG_LINE_RE.match(text)
    match = rfc_match or syslog_match
    if match is None:
        return None

    if match.group("proc") != "sshd":
        return None

    message = match.group("message")
    event_type = None
    event_match = None
    for pattern, candidate_type in _MESSAGE_PATTERNS:
        event_match = pattern.match(message)
        if event_match is not None:
            event_type = candidate_type
            break
    if event_type is None or event_match is None:
        return None

    if rfc_match is not None:
        timestamp = _parse_rfc3339(rfc_match.group("ts"))
    else:
        assert syslog_match is not None
        timestamp = _resolve_syslog_timestamp(
            syslog_match.group("month"),
            syslog_match.group("day"),
            syslog_match.group("time"),
            year,
            previous,
        )
    if timestamp is None:
        return None

    return LogEvent(
        timestamp=timestamp,
        event_type=event_type,
        username=event_match.group("user"),
        source_ip=event_match.group("ip"),
        port=int(event_match.group("port")),
        raw_line=text,
    )


def parse_lines(
    lines: Iterable[str],
    default_year: int | None = None,
) -> tuple[list[LogEvent], int, int]:
    """Parse many lines, returning ``(events, lines_read, lines_unparsed)``.

    The previous event's timestamp is threaded through each call to
    :func:`parse_line` so that syslog-format year rollover can be detected
    across the whole stream.
    """
    year = default_year if default_year is not None else datetime.now().year
    events: list[LogEvent] = []
    lines_read = 0
    lines_unparsed = 0
    previous: datetime | None = None

    for line in lines:
        lines_read += 1
        event = parse_line(line, default_year=year, previous=previous)
        if event is None:
            lines_unparsed += 1
            continue
        events.append(event)
        previous = event.timestamp

    return events, lines_read, lines_unparsed
