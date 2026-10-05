"""Local-only event exports; no network forwarding is performed here."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from . import __version__


def _clean(value: Any) -> str:
    # Prevent line and field injection from router/device-controlled strings.
    return re.sub(r"[\r\n\x00-\x1f\x7f]+", " ", str(value)).strip()


def _cef(value: Any) -> str:
    return _clean(value).replace("\\", "\\\\").replace("=", "\\=").replace("|", "\\|")


def render_events(events: list[dict[str, Any]], output_format: str) -> str:
    lines: list[str] = []
    for event in events:
        if output_format == "jsonl":
            lines.append(json.dumps({"source": "LANwatch", **event}, ensure_ascii=False, separators=(",", ":")))
        elif output_format == "syslog":
            severity = event.get("severity", "INFO")
            pri = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "INFO": 6}.get(severity, 5)
            timestamp = datetime.fromtimestamp(int(event.get("captured_at", 0)), tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            lines.append(f"<{pri}>1 {timestamp} LANwatch - {event.get('kind', 'event')} - - {_clean(event.get('title', ''))}: {_clean(event.get('details', ''))}")
        elif output_format == "cef":
            severity = {"INFO": 3, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}.get(event.get("severity"), 5)
            lines.append("CEF:0|LANwatch|LANwatch|{}|{}|{}|{}|rt={} cs1={} cs1Label=kind msg={}".format(__version__,
                _cef(event.get("kind", "event")), _cef(event.get("title", "Event")), severity,
                _cef(event.get("captured_at", "")), _cef(event.get("kind", "")), _cef(event.get("details", ""))))
        else:
            raise ValueError("unsupported export format")
    return "\n".join(lines) + ("\n" if lines else "")
