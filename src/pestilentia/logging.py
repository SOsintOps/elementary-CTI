# "Every puzzle has an answer." — Sherlock Holmes, Elementary
from __future__ import annotations

import json
import logging
import traceback
from datetime import UTC, datetime


# "You see but you do not observe." — Sherlock Holmes, Elementary
class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        for key in ("source", "endpoint", "record_count", "duration_s", "error_type"):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val

        if record.exc_info and record.exc_info[1]:
            exc = record.exc_info[1]
            entry["error_type"] = type(exc).__name__
            entry["error_message"] = str(exc)
            entry["traceback"] = traceback.format_exception(*record.exc_info)

        return json.dumps(entry, default=str)


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
