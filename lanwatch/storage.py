from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class Storage:
    """Private local state with JSON compatibility and SQLite event history."""

    def __init__(self, directory: str = ".lanwatch") -> None:
        self.directory = Path(directory)
        legacy = self.directory.parent / ".miwifi-sentinel"
        if self.directory == Path(".lanwatch") and not self.directory.exists() and legacy.is_dir():
            self.directory.mkdir(parents=True, exist_ok=True)
            for name in ("baseline.json", "last_snapshot.json", "events.json"):
                old = legacy / name
                if old.is_file():
                    shutil.copy2(old, self.directory / name)
        self.directory.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.directory.chmod(0o700)
        self.db_path = self.directory / "lanwatch.sqlite3"
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    @contextmanager
    def _database(self):
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        # Pre-create with owner-only permissions before SQLite writes data.
        descriptor = os.open(self.db_path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        if os.name != "nt":
            self.db_path.chmod(0o600)
        with self._database() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS snapshots (
                    captured_at INTEGER PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    captured_at INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    title TEXT NOT NULL,
                    details TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_recent ON events(captured_at DESC);
                CREATE INDEX IF NOT EXISTS events_identity ON events(kind, title, details, captured_at DESC);
            """)
            marker = db.execute("SELECT value FROM metadata WHERE key='json_events_migrated'").fetchone()
            if not marker:
                old = self._read("events.json") or {}
                for row in old.get("items", []):
                    try:
                        db.execute(
                            "INSERT INTO events(captured_at,severity,kind,title,details) VALUES(?,?,?,?,?)",
                            (int(row.get("captured_at", 0)), str(row.get("severity", "INFO")), str(row.get("kind", "legacy")), str(row.get("title", "")), str(row.get("details", ""))),
                        )
                    except (TypeError, ValueError):
                        continue
                db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('json_events_migrated','1')")
            count = db.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
            if not count:
                old_snapshot = self._read("last_snapshot.json")
                if old_snapshot:
                    stamp = int(old_snapshot.get("captured_at") or time.time())
                    db.execute("INSERT OR IGNORE INTO snapshots(captured_at,payload) VALUES(?,?)", (stamp, json.dumps(old_snapshot, ensure_ascii=False)))

    def _read(self, name: str) -> dict[str, Any] | None:
        path = self.directory / name
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def _write(self, name: str, data: dict[str, Any]) -> None:
        path = self.directory / name
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        if os.name != "nt":
            temp.chmod(0o600)
        temp.replace(path)

    def baseline(self) -> dict[str, Any] | None:
        return self._read("baseline.json")

    def save_baseline(self, data: dict[str, Any]) -> None:
        self._write("baseline.json", data)

    def last_snapshot(self) -> dict[str, Any] | None:
        with self._database() as db:
            row = db.execute("SELECT payload FROM snapshots ORDER BY captured_at DESC LIMIT 1").fetchone()
        if row:
            return json.loads(row["payload"])
        # Compatibility in case older software wrote only the JSON file.
        return self._read("last_snapshot.json")

    def save_snapshot(self, data: dict[str, Any]) -> None:
        self._write("last_snapshot.json", data)
        stamp = int(data.get("captured_at") or time.time())
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        with self._database() as db:
            db.execute("INSERT OR REPLACE INTO snapshots(captured_at,payload) VALUES(?,?)", (stamp, payload))
            db.execute("DELETE FROM snapshots WHERE captured_at NOT IN (SELECT captured_at FROM snapshots ORDER BY captured_at DESC LIMIT 10000)")

    def history(self, limit: int = 360) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 10000))
        with self._database() as db:
            rows = db.execute("SELECT payload FROM (SELECT captured_at,payload FROM snapshots ORDER BY captured_at DESC LIMIT ?) ORDER BY captured_at ASC", (limit,)).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def events(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(0, min(int(limit), 10000))
        with self._database() as db:
            rows = db.execute("SELECT captured_at,severity,kind,title,details FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def record_events(self, events: list[Any], captured_at: int | None = None, jsonl_path: str | None = None) -> None:
        if not events:
            return
        timestamp = int(captured_at or time.time())
        emitted: list[dict[str, Any]] = []
        with self._database() as db:
            for event in events:
                row = event.to_dict()
                previous = db.execute(
                    "SELECT id,captured_at FROM events WHERE kind=? AND title=? AND details=? ORDER BY id DESC LIMIT 1",
                    (row["kind"], row["title"], row["details"]),
                ).fetchone()
                if previous and timestamp - int(previous["captured_at"]) < 600:
                    db.execute("UPDATE events SET captured_at=?,severity=? WHERE id=?", (timestamp, row["severity"], previous["id"]))
                else:
                    db.execute(
                        "INSERT INTO events(captured_at,severity,kind,title,details) VALUES(?,?,?,?,?)",
                        (timestamp, row["severity"], row["kind"], row["title"], row["details"]),
                    )
                    emitted.append({"source": "LANwatch", **row, "captured_at": timestamp})
            db.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 10000)")
        if jsonl_path and emitted:
            path = Path(jsonl_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags, 0o600)
            with os.fdopen(descriptor, "a", encoding="utf-8", newline="\n") as stream:
                for row in emitted:
                    stream.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            if os.name != "nt":
                path.chmod(0o600)

    def trust_device(self, mac: str, snapshot: dict[str, Any]) -> str:
        if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
            raise ValueError("Некорректный MAC-адрес")
        baseline = self.baseline()
        if baseline is None:
            raise ValueError("Сначала создайте доверенную базу устройств")
        device = snapshot.get("devices", {}).get(mac)
        if not device or not device.get("online"):
            raise ValueError("Подтвердить можно только устройство, которое сейчас онлайн")
        known = baseline.setdefault("known_devices", {})
        if mac in known:
            return str(known[mac].get("name", device.get("name", mac)))
        name = str(device.get("name") or "Неизвестное устройство")
        known[mac] = {"name": name}
        self.save_baseline(baseline)
        return name
