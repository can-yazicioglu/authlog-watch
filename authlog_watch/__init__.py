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

from authlog_watch.parser import parse_line, parse_lines  # noqa: E402
from authlog_watch.detectors import (  # noqa: E402
    ALL_DETECTORS,
    DetectorConfig,
    run_detectors,
)
from authlog_watch.report import render_json, render_text  # noqa: E402

__all__ += [
    "parse_line",
    "parse_lines",
    "ALL_DETECTORS",
    "DetectorConfig",
    "run_detectors",
    "render_json",
    "render_text",
]
