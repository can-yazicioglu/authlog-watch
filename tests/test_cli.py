"""Tests for authlog_watch.cli."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from authlog_watch.cli import main

SAMPLE_LOG = str(Path(__file__).parent.parent / "samples" / "auth.log")


def test_main_against_sample_exits_one(capsys: pytest.CaptureFixture[str]) -> None:
    """Scanning the bundled sample log finds brute force activity: exit 1."""
    exit_code = main([SAMPLE_LOG, "--no-color"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "CRITICAL" in captured.out


def test_main_json_output_contains_critical_finding(capsys: pytest.CaptureFixture[str]) -> None:
    """--json emits valid JSON with a critical finding for the sample log."""
    exit_code = main([SAMPLE_LOG, "--json"])
    captured = capsys.readouterr()
    assert exit_code == 1

    payload = json.loads(captured.out)
    assert payload["events_parsed"] > 0
    severities = {finding["severity"] for finding in payload["findings"]}
    assert "Critical" in severities


def test_main_min_severity_critical_shows_only_critical(capsys: pytest.CaptureFixture[str]) -> None:
    """--min-severity critical drops every finding below CRITICAL."""
    exit_code = main([SAMPLE_LOG, "--json", "--min-severity", "critical"])
    captured = capsys.readouterr()
    assert exit_code == 1

    payload = json.loads(captured.out)
    assert len(payload["findings"]) >= 1
    assert all(finding["severity"] == "Critical" for finding in payload["findings"])


def test_main_missing_file_exits_two(capsys: pytest.CaptureFixture[str]) -> None:
    """A nonexistent path exits 2 with a clear stderr message."""
    exit_code = main(["/nonexistent/path/auth.log"])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "error" in captured.err.lower()


def test_legitimate_user_produces_no_finding(capsys: pytest.CaptureFixture[str]) -> None:
    """The legitimate user 192.168.1.30, who mistypes once then succeeds,
    must not appear in any finding.
    """
    exit_code = main([SAMPLE_LOG, "--json"])
    captured = capsys.readouterr()
    assert exit_code == 1

    payload = json.loads(captured.out)
    for finding in payload["findings"]:
        assert finding["source_ip"] != "192.168.1.30"


def test_no_color_output_has_no_escape_codes(capsys: pytest.CaptureFixture[str]) -> None:
    """--no-color must never emit ANSI escape sequences."""
    main([SAMPLE_LOG, "--no-color"])
    captured = capsys.readouterr()
    assert "\033[" not in captured.out


def test_version_flag_exits_zero() -> None:
    """--version exits 0 via argparse's built-in version action."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
