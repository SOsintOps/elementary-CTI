import json
import logging

from pestilentia.logging import JSONFormatter, setup_logging


def test_json_formatter_basic():
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    output = formatter.format(record)
    data = json.loads(output)
    assert data["message"] == "Test message"
    assert data["level"] == "INFO"
    assert data["logger"] == "test"
    assert "timestamp" in data


def test_json_formatter_with_extra():
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Fetched data",
        args=(),
        exc_info=None,
    )
    record.source = "ransomware.live"
    record.record_count = 42
    record.duration_s = 1.5
    output = formatter.format(record)
    data = json.loads(output)
    assert data["source"] == "ransomware.live"
    assert data["record_count"] == 42
    assert data["duration_s"] == 1.5


def test_json_formatter_with_exception():
    formatter = JSONFormatter()
    try:
        raise ValueError("Test error")
    except ValueError:
        import sys

        exc_info = sys.exc_info()
    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname="test.py",
        lineno=1,
        msg="Error occurred",
        args=(),
        exc_info=exc_info,
    )
    output = formatter.format(record)
    data = json.loads(output)
    assert "traceback" in data
    assert any("ValueError" in line for line in data["traceback"])


def test_setup_logging_configures_root():
    setup_logging("WARNING")
    root = logging.getLogger()
    assert root.level == logging.WARNING
    assert len(root.handlers) >= 1
    assert isinstance(root.handlers[0].formatter, JSONFormatter)
