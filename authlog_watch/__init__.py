"""authlog-watch: detect SSH brute force activity in Linux auth logs."""

from authlog_watch.models import (
    EventType,
    Finding,
    LogEvent,
    ScanResult,
    Severity,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "EventType",
    "Finding",
    "LogEvent",
    "ScanResult",
    "Severity",
]
