from __future__ import annotations

import html
import hmac
import ipaddress
import re
import secrets
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

from . import __version__
from .client import RouterError
from .adapters import create_adapter
from .detectors import Event, detect
from .storage import Storage
from .security_audit import audit_snapshot
from .notifications import send_webhook, send_telegram
from .local_discovery import collect_snapshot


MAC_RE = re.compile(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\Z")


def _line_chart(title: str, values: list[float], color: str, suffix: str = "") -> str:
    if len(values) < 2:
        return f"<section><h2>{html.escape(title)}</h2><p class=\"sub\">Нужно минимум две сохранённые проверки.</p></section>"
    width, height = 720, 150
    max_value = max(max(values), 1)
    min_value = min(values)
    spread = max(max_value - min_value, 1)
    coords = []
    for index, value in enumerate(values):
        x = 12 + index * (width - 24) / (len(values) - 1)
        y = height - 16 - ((value - min_value) / spread) * (height - 32)
        coords.append(f"{x:.1f},{y:.1f}")
    latest = values[-1]
    display = f"{latest:.0f}{suffix}" if suffix else f"{latest:.0f}"
    svg = f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title, quote=True)}" style="width:100%;max-height:180px"><line x1="12" y1="{height-16}" x2="{width-12}" y2="{height-16}" stroke="#26364b"/><polyline fill="none" stroke="{color}" stroke-width="3" points="{" ".join(coords)}"/><text x="12" y="14" fill="#9bacc1" font-size="12">последнее: {display}</text></svg>'
    return f"<section><h2>{html.escape(title)}</h2>{svg}</section>"


class DashboardState:
    def __init__(self, args: Any, storage: Storage, baseline: dict[str, Any], login: tuple[str, ...]) -> None:
        self.args = args
        self.storage = storage
        self.baseline = baseline
        self.login = login
        self.adapter = create_adapter(args.router, args._resolved_adapter, args.allow_insecure_http)
        self.previous = storage.last_snapshot()
        self.error = ""
        self.notice = ""
        self.active_event_fingerprints: set[str] = set()
        self.csrf_token = secrets.token_urlsafe(32)
        self.lock = threading.RLock()

    def snapshot(self) -> dict[str, Any] | None:
        with self.lock:
            return self.storage.last_snapshot()

    def scan(self) -> tuple[list[Event], str]:
        with self.lock:
            try:
                current = collect_snapshot(self.adapter, self.login, self.storage.directory, getattr(self.args, "arp_neighbors", True))
                events = detect(self.baseline, self.previous, current, self.args.upload_threshold)
                self.storage.record_events(events, current.get("captured_at"), getattr(self.args, "wazuh_jsonl", None))
                self.storage.save_snapshot(current)
                self.previous = current
                self.error = ""
                fresh = [event for event in events if event.fingerprint not in self.active_event_fingerprints]
                self.active_event_fingerprints = {event.fingerprint for event in events}
                try:
                    send_webhook(getattr(self.args, "webhook_url", None), fresh)
                    send_telegram(getattr(self.args, "telegram_notifications", False), fresh)
                except ValueError as exc:
                    self.error = f"Уведомление: {exc}"
                return events, ""
            except RouterError as exc:
                self.error = str(exc)
                return [], self.error

    def approve(self, mac: str) -> str:
        with self.lock:
            snapshot = self.storage.last_snapshot() or {}
            name = self.storage.trust_device(mac, snapshot)
            self.baseline = self.storage.baseline() or self.baseline
            return name


def valid_loopback_host(host: str, port: int) -> bool:
    """Only bind to the IPv4 loopback address; never to LAN or wildcard interfaces."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.version == 4 and address.is_loopback and str(address) == "127.0.0.1"


def valid_host_header(value: str, port: int) -> bool:
    expected = "127.0.0.1" if port == 80 else f"127.0.0.1:{port}"
    return value == expected


def valid_post_host(host_header: str, port: int) -> bool:
    # The anti-CSRF token is authoritative. Browsers differ in whether they
    # send Origin for a loopback form (some send no value or "null"). Host is
    # still checked exactly to prevent DNS-rebinding access to the panel.
    return valid_host_header(host_header, port)


def valid_csrf_token(received: str, expected: str) -> bool:
    return bool(received) and hmac.compare_digest(received, expected)


def render_page(state: DashboardState, title_message: str = "") -> bytes:
    snapshot = state.snapshot() or {}
    baseline = state.storage.baseline() or {}
    known = baseline.get("known_devices", {})
    devices = snapshot.get("devices", {})
    source_comparison = snapshot.get("source_comparison", {})
    router = snapshot.get("router", {})
    wan = snapshot.get("wan", {})
    audit = audit_snapshot(snapshot)
    errors = state.error
    notice = title_message or state.notice or errors
    notice_html = f'<p class="notice">{html.escape(notice)}</p>' if notice else ""
    csrf = html.escape(state.csrf_token, quote=True)

    device_rows: list[str] = []
    for mac, device in sorted(devices.items(), key=lambda pair: (not pair[1].get("online"), pair[1].get("name", "").casefold())):
        online = bool(device.get("online"))
        is_known = mac in known
        sources = device.get("sources", ["router_api"])
        state_label = "В сети" if online else ("В ARP-кэше · статус не подтверждён" if "arp_cache" in sources and "router_api" not in sources else "Не в сети")
        source_label = "API роутера + ARP-кэш" if set(sources) >= {"router_api", "arp_cache"} else ("ARP-кэш ОС" if "arp_cache" in sources else "API роутера")
        vendor = device.get("vendor") or "Не определён"
        trust = "Доверенное" if is_known else "Новое"
        button = ""
        if online and not is_known:
            button = (
                '<form method="post" action="/action">'
                '<input type="hidden" name="action" value="trust">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<input type="hidden" name="mac" value="{html.escape(mac, quote=True)}">'
                '<button type="submit">Доверять этому устройству</button></form>'
            )
        device_rows.append(
            "<tr>"
            f"<td>{html.escape(str(device.get('name') or 'Без имени'))}</td>"
            f"<td><code>{html.escape(mac)}</code></td>"
            f"<td>{html.escape(', '.join(device.get('ips', [])) or '—')}</td>"
            f"<td>{html.escape(vendor)}</td><td>{html.escape(source_label)}</td><td>{html.escape(state_label)}</td><td>{trust}</td><td>{button}</td>"
            "</tr>"
        )
    if not device_rows:
        device_rows.append('<tr><td colspan="8">Снимка устройств пока нет. Нажмите «Проверить сейчас».</td></tr>')

    event_rows: list[str] = []
    for event in state.storage.events(50):
        timestamp = time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(event.get("captured_at", 0)))
        event_rows.append(
            "<tr>"
            f"<td>{html.escape(timestamp)}</td>"
            f'<td><span class="severity {html.escape(str(event.get("severity", "INFO")))}">{html.escape(str(event.get("severity", "INFO")))}</span></td>'
            f"<td>{html.escape(str(event.get('title', '')))}</td>"
            f"<td>{html.escape(str(event.get('details', '')))}</td>"
            "</tr>"
        )
    if not event_rows:
        event_rows.append('<tr><td colspan="4">Событий пока нет.</td></tr>')
    audit_rows = []
    for finding in audit:
        audit_rows.append(
            "<tr>"
            f"<td>{html.escape(finding['label'])}</td>"
            f"<td><span class=\"severity {html.escape(finding['severity'])}\">{html.escape(finding['status'].upper())}</span></td>"
            f"<td>{html.escape(finding['summary'])}</td>"
            f"<td>{html.escape(finding['recommendation'])}</td></tr>"
        )

    captured = snapshot.get("captured_at")
    last_seen = time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(captured)) if captured else "ещё не проверялся"
    wan_label = "Доступен" if wan.get("online") else ("Нет связи" if snapshot else "Нет данных")
    history = state.storage.history(48)
    online_history = [sum(bool(d.get("online")) for d in entry.get("devices", {}).values()) for entry in history]
    wan_history = [1 if entry.get("wan", {}).get("online") else 0 for entry in history]
    comparison_html = ""
    if source_comparison:
        comparison_html = (f"<p class=\"sub\">Источники: API — {len(source_comparison.get('router_api_only', [])) + len(source_comparison.get('both', []))}; ARP-кэш — {source_comparison.get('arp_cache_count', 0)}; совпали — {len(source_comparison.get('both', []))}; только ARP — {len(source_comparison.get('arp_cache_only', []))}.</p>")
    body = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LANwatch — локальная панель</title>
<style>
:root{{color-scheme:dark;--bg:#0b1220;--card:#121d2e;--line:#26364b;--text:#edf3fb;--muted:#9bacc1;--accent:#5eead4;}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1180px;margin:36px auto;padding:0 20px}}h1{{margin:0;font-size:30px}}h2{{font-size:18px;margin:0 0 14px}}.sub{{color:var(--muted);margin:4px 0 24px}}.grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:20px 0}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:17px}}.value{{font-size:22px;font-weight:650;margin-top:5px}}.label{{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em}}h1 small{{font-size:13px;color:var(--muted);font-weight:500}}
section{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin:14px 0;overflow:auto}}table{{width:100%;border-collapse:collapse;min-width:680px}}th,td{{padding:11px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{color:var(--muted);font-size:12px;text-transform:uppercase}}td form{{margin:0}}button{{border:0;border-radius:8px;padding:8px 11px;background:var(--accent);color:#06211e;font-weight:650;cursor:pointer;white-space:nowrap}}.toolbar{{display:flex;align-items:center;gap:12px;flex-wrap:wrap}}.notice{{background:#442b16;border:1px solid #956018;border-radius:10px;padding:12px}}.severity{{font-weight:700}}.CRITICAL,.HIGH{{color:#ff7979}}.MEDIUM{{color:#ffd166}}.INFO{{color:#7dd3fc}}code{{color:#b7c9df}}footer{{color:var(--muted);font-size:12px;margin:20px 0}}@media(max-width:740px){{main{{margin:20px auto}}.grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}h1{{font-size:25px}}}}
</style></head><body><main>
<h1>LANwatch <small>v{html.escape(__version__)}</small></h1><p class="sub">Локальный монитор безопасности сети · панель доступна только на этом компьютере</p>
{notice_html}
<div class="toolbar"><form method="post" action="/action"><input type="hidden" name="action" value="check"><input type="hidden" name="csrf" value="{csrf}"><button type="submit">Проверить сейчас</button></form><span class="sub">Последняя проверка: {html.escape(last_seen)} · обновление раз в {state.args.interval} сек.</span></div>
<div class="grid"><div class="card"><div class="label">Интернет</div><div class="value">{html.escape(wan_label)}</div></div>
<div class="card"><div class="label">Устройства</div><div class="value">{sum(bool(d.get('online')) for d in devices.values())} онлайн / {len(devices)} всего</div></div>
<div class="card"><div class="label">DNS</div><div class="value">{html.escape(', '.join(wan.get('dns', [])) or '—')}</div></div>
<div class="card"><div class="label">Роутер / прошивка</div><div class="value">{html.escape(str(router.get('model') or 'Неизвестно'))}</div><div class="sub">{html.escape(str(router.get('firmware') or ''))}</div></div></div>
<section><h2>Устройства</h2>{comparison_html}<table><thead><tr><th>Имя</th><th>MAC</th><th>IP</th><th>Производитель</th><th>Источник</th><th>Статус</th><th>Доверие</th><th>Действие</th></tr></thead><tbody>{''.join(device_rows)}</tbody></table></section>
{_line_chart("Устройства онлайн по данным роутера", [float(value) for value in online_history], "#5eead4")}
{_line_chart("Доступность WAN", [float(value) for value in wan_history], "#7dd3fc", " · 1=доступен")}
<section><h2>Аудит настроек роутера</h2><p class="sub">Только read-only поля API. «UNKNOWN» означает, что LANwatch не может подтвердить настройку.</p><table><thead><tr><th>Проверка</th><th>Статус</th><th>Результат</th><th>Что сделать</th></tr></thead><tbody>{''.join(audit_rows)}</tbody></table></section>
<section><h2>История событий</h2><table><thead><tr><th>Время</th><th>Уровень</th><th>Событие</th><th>Детали</th></tr></thead><tbody>{''.join(event_rows)}</tbody></table></section>
<footer>Работает локально. Сетевые данные хранятся на этом компьютере; внешние уведомления отправляются только при явном включении. Наблюдение ограничено данными API и локальной таблицей ARP.</footer>
</main></body></html>"""
    return body.encode("utf-8")


def serve(args: Any, storage: Storage, baseline: dict[str, Any], login: tuple[str, ...]) -> None:
    if not valid_loopback_host(args.host, args.port):
        raise RouterError("Веб-панель разрешено запускать только на 127.0.0.1")
    state = DashboardState(args, storage, baseline, login)
    state.scan()
    stop = threading.Event()

    def monitor() -> None:
        while not stop.wait(args.interval):
            state.scan()

    monitor_thread = threading.Thread(target=monitor, name="lanwatch-monitor", daemon=True)
    monitor_thread.start()

    class Handler(BaseHTTPRequestHandler):
        server_version = "LANwatch"
        sys_version = ""

        def log_message(self, _format: str, *args: Any) -> None:
            # Avoid writing device IPs, MACs, or submitted data to terminal logs.
            return

        def _security_headers(self, content_type: str) -> None:
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")

        def _host_is_valid(self) -> bool:
            return valid_host_header(self.headers.get("Host", ""), args.port)

        def _send_page(self, notice: str = "") -> None:
            page = render_page(state, notice)
            self.send_response(HTTPStatus.OK)
            self._security_headers("text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.send_header("Refresh", str(args.interval))
            self.end_headers()
            self.wfile.write(page)
            state.notice = ""

        def do_GET(self) -> None:
            if not self._host_is_valid() or self.path != "/":
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            self._send_page()

        def do_POST(self) -> None:
            if not valid_post_host(self.headers.get("Host", ""), args.port) or self.path != "/action":
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/x-www-form-urlencoded":
                self.send_error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
                return
            if self.headers.get("Transfer-Encoding"):
                self.send_error(HTTPStatus.BAD_REQUEST)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if not 0 < length <= 2048:
                self.send_error(HTTPStatus.BAD_REQUEST)
                return
            form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"), max_num_fields=5)
            if not valid_csrf_token(form.get("csrf", [""])[0], state.csrf_token):
                body = "Защитный токен устарел. Обновите страницу LANwatch и повторите действие.".encode("utf-8")
                self.send_response(HTTPStatus.FORBIDDEN)
                self._security_headers("text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            action = form.get("action", [""])[0]
            if action == "check":
                _, error = state.scan()
                state.notice = error or "Проверка завершена."
            elif action == "trust":
                mac = form.get("mac", [""])[0].upper()
                if not MAC_RE.fullmatch(mac):
                    state.notice = "Некорректный MAC-адрес."
                else:
                    try:
                        state.approve(mac)
                        state.notice = "Устройство добавлено в доверенную базу."
                    except ValueError as exc:
                        state.notice = str(exc)
            else:
                self.send_error(HTTPStatus.BAD_REQUEST)
                return
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()

    class LocalOnlyServer(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = False
        request_queue_size = 8

    server = LocalOnlyServer(("127.0.0.1", args.port), Handler)
    print(f"LANwatch запущен: http://127.0.0.1:{args.port}")
    print("Доступ только с этого компьютера. Ctrl+C — остановить.")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nПанель остановлена.")
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
