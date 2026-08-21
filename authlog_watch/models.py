"""Data model for authlog-watch: parsed events, findings, and scan results."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class Severity(enum.IntEnum):
    """Ordered severity levels for findings, from least to most urgent."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        """Return the severity name in title case, e.g. 'Critical'."""
        return self.name.title()


class EventType(enum.Enum):
    """Kinds of sshd authentication events this tool recognises."""

    FAILED_PASSWORD = "failed_password"
    ACCEPTED_PASSWORD = "accepted_password"
    ACCEPTED_PUBLICKEY = "accepted_publickey"
    INVALID_USER = "invalid_user"
    CONNECTION_CLOSED_PREAUTH = "connection_closed_preauth"


_FAILURE_TYPES = frozenset(
    {
        EventType.FAILED_PASSWORD,
        EventType.INVALID_USER,
        EventType.CONNECTION_CLOSED_PREAUTH,
    }
)

_SUCCESS_TYPES = frozenset(
    {
        EventType.ACCEPTED_PASSWORD,
        EventType.ACCEPTED_PUBLICKEY,
    }
)


@dataclass(frozen=True)
class LogEvent:
    """A single parsed sshd authentication event from an auth log line."""

    timestamp: datetime
    event_type: EventType
    username: str
    source_ip: str
    port: int | None
    raw_line: str

    @property
    def is_failure(self) -> bool:
        """Return True if this event represents a failed authentication attempt."""
        return self.event_type in _FAILURE_TYPES

    @property
    def is_success(self) -> bool:
        """Return True if this event represents a successful authentication."""
        return self.event_type in _SUCCESS_TYPES


@dataclass(frozen=True)
class Finding:
    """A single detection result produced by one of the brute force rules."""

    rule: str
    severity: Severity
    source_ip: str
    summary: str
    evidence: dict[str, Any]
    first_seen: datetime
    last_seen: datetime

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dict representation of this finding."""
        return {
            "rule": self.rule,
            "severity": self.severity.label,
            "source_ip": self.source_ip,
            "summary": self.summary,
            "evidence": self.evidence,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }


@dataclass
class ScanResult:
    """The outcome of scanning an auth log: findings plus parse statistics."""

    findings: list[Finding] = field(default_factory=list)
    events_parsed: int = 0
    lines_read: int = 0
    lines_unparsed: int = 0

    @property
    def max_severity(self) -> Severity:
        """Return the highest severity among findings, or INFO if there are none."""
        if not self.findings:
            return Severity.INFO
        return max(finding.severity for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dict representation of this scan result."""
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "events_parsed": self.events_parsed,
            "lines_read": self.lines_read,
            "lines_unparsed": self.lines_unparsed,
            "max_severity": self.max_severity.label,
        }
