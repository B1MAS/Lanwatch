from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from .client import RouterError
from .adapters import adapter_name, create_adapter
from .adapters.miwifi import MiWiFiAdapter
from .adapters.openwrt import OpenWrtAdapter
from .detectors import Event, detect
from .models import make_baseline
from .probe import diagnostic_report, write_report
from .storage import Storage
from .web import serve, valid_loopback_host
from .security_audit import audit_snapshot
from .exports import render_events
from .notifications import send_webhook, send_telegram
from .local_discovery import collect_snapshot, update_oui_database


COLORS = {"CRITICAL": "\033[91m", "HIGH": "\033[31m", "MEDIUM": "\033[33m", "INFO": "\033[36m"}
RESET = "\033[0m"


def print_events(events: list[Event]) -> None:
    if not events:
        print("[OK] Опасных изменений не обнаружено")
        return
    use_color = sys.stdout.isatty()
    for event in events:
        color = COLORS.get(event.severity, "") if use_color else ""
        reset = RESET if use_color else ""
        print(f"{color}[{event.severity}] {event.title}{reset}\n  {event.details}")


def password() -> str:
    value = os.environ.get("MIWIFI_PASSWORD")
    return value if value is not None else getpass.getpass("Пароль панели роутера: ")


def credentials(adapter: str) -> tuple[str, ...]:
    if adapter == "openwrt":
        username = os.environ.get("OPENWRT_USERNAME") or input("Пользователь OpenWrt (рекомендуется отдельная read-only учётная запись): ")
        secret = os.environ.get("OPENWRT_PASSWORD")
        if secret is None:
            secret = getpass.getpass("Пароль OpenWrt: ")
        return username, secret
    return (password(),)


def capture(router: str, adapter: str, login: tuple[str, ...], allow_insecure_http: bool = False, data_dir: str = ".lanwatch", include_arp: bool = True) -> dict[str, Any]:
    client = create_adapter(router, adapter, allow_insecure_http)
    return collect_snapshot(client, login, Path(data_dir), include_arp)


def resolve(args: argparse.Namespace) -> str:
    adapter = adapter_name(args.adapter, args.router)
    args._resolved_adapter = adapter
    return adapter


def prepare_for_auth(args: argparse.Namespace) -> str:
    adapter = resolve(args)
    # Reject insecure OpenWrt transport before asking the user for any secret.
    if adapter == "openwrt":
        OpenWrtAdapter(args.router, allow_insecure_http=args.allow_insecure_http)
    else:
        MiWiFiAdapter(args.router)
    return adapter


def cmd_probe(args: argparse.Namespace) -> int:
    detected = False
    adapter = "unknown"
    try:
        adapter = resolve(args)
        if args.adapter == "auto":
            detected = True
        elif adapter == "miwifi":
            detected = MiWiFiAdapter(args.router).probe()
        else:
            detected = OpenWrtAdapter(args.router, allow_insecure_http=True).probe()
        if not detected:
            adapter = "unknown"
    except RouterError:
        if args.adapter != "auto":
            raise
    report = diagnostic_report(adapter, detected)
    try:
        path = write_report(report, args.output)
    except FileExistsError as exc:
        raise RouterError("Диагностический файл уже существует; задайте другой путь через --output") from exc
    except OSError as exc:
        raise RouterError("Не удалось сохранить диагностический файл в указанное место") from exc
    print(f"Создан безопасный диагностический файл: {path}")
    print("Перед отправкой в issue всё равно откройте JSON и проверьте его содержимое.")
    if not detected:
        print("Поддерживаемый API не обнаружен; приложите файл и укажите модель роутера вручную.")
    return 0


def require_baseline(storage: Storage) -> dict[str, Any]:
    baseline = storage.baseline()
    if not baseline:
        raise RouterError("Сначала выполните: python -m lanwatch enroll")
    return baseline


def cmd_enroll(args: argparse.Namespace) -> int:
    adapter = prepare_for_auth(args)
    snapshot = capture(args.router, adapter, credentials(adapter), args.allow_insecure_http, args.data_dir, args.arp_neighbors)
    storage = Storage(args.data_dir)
    storage.save_baseline(make_baseline(snapshot))
    storage.save_snapshot(snapshot)
    print(f"Доверенная база создана: {len(snapshot['devices'])} устройств")
    print(f"DNS: {', '.join(snapshot['wan']['dns']) or 'не определён'}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    storage = Storage(args.data_dir)
    baseline = require_baseline(storage)
    previous = storage.last_snapshot()
    adapter = prepare_for_auth(args)
    current = capture(args.router, adapter, credentials(adapter), args.allow_insecure_http, args.data_dir, args.arp_neighbors)
    events = detect(baseline, previous, current, args.upload_threshold)
    storage.record_events(events, current.get("captured_at"), args.wazuh_jsonl)
    try:
        send_webhook(args.webhook_url, events)
        send_telegram(args.telegram_notifications, events)
    except ValueError as exc:
        print(f"[NOTIFICATION] {exc}", file=sys.stderr)
    print_events(events)
    storage.save_snapshot(current)
    return 2 if any(event.severity in {"CRITICAL", "HIGH"} for event in events) else 0


def cmd_monitor(args: argparse.Namespace) -> int:
    storage = Storage(args.data_dir)
    baseline = require_baseline(storage)
    adapter = prepare_for_auth(args)
    login = credentials(adapter)
    client = create_adapter(args.router, adapter, args.allow_insecure_http)
    previous = storage.last_snapshot()
    active: set[str] = set()
    print(f"Мониторинг запущен, интервал {args.interval} сек. Ctrl+C — остановить.")
    while True:
        try:
            current = collect_snapshot(client, login, storage.directory, args.arp_neighbors)
            events = detect(baseline, previous, current, args.upload_threshold)
            storage.record_events(events, current.get("captured_at"), args.wazuh_jsonl)
            fresh = [event for event in events if event.fingerprint not in active]
            try:
                send_webhook(args.webhook_url, fresh)
                send_telegram(args.telegram_notifications, fresh)
            except ValueError as exc:
                print(f"[NOTIFICATION] {exc}", file=sys.stderr)
            if fresh:
                print(time.strftime("\n%Y-%m-%d %H:%M:%S"))
                print_events(fresh)
            active = {event.fingerprint for event in events}
            previous = current
            storage.save_snapshot(current)
        except RouterError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            pass
        time.sleep(args.interval)


def cmd_demo(_: argparse.Namespace) -> int:
    root = Path(__file__).resolve().parent / "demo"
    baseline = json.loads((root / "baseline.json").read_text(encoding="utf-8"))
    previous = json.loads((root / "normal_snapshot.json").read_text(encoding="utf-8"))
    current = json.loads((root / "incident_snapshot.json").read_text(encoding="utf-8"))
    print_events(detect(baseline, previous, current))
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    adapter = prepare_for_auth(args)
    current = capture(args.router, adapter, credentials(adapter), args.allow_insecure_http)
    findings = audit_snapshot(current)
    for item in findings:
        print(f"[{item['severity']}/{item['status'].upper()}] {item['label']}: {item['summary']}\n  Рекомендация: {item['recommendation']}")
    print("\nАудит read-only и ограничен данными API; UNKNOWN не означает безопасно.")
    return 2 if any(item["severity"] in {"CRITICAL", "HIGH"} for item in findings) else 0


def cmd_export(args: argparse.Namespace) -> int:
    storage = Storage(args.data_dir)
    content = render_events(storage.events(1000), args.format)
    path = Path(args.output)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
    except FileExistsError as exc:
        raise RouterError("Файл уже существует; задайте другой --output, чтобы ничего не перезаписать") from exc
    except OSError as exc:
        raise RouterError("Не удалось сохранить экспорт в указанное место") from exc
    if os.name != "nt":
        path.chmod(0o600)
    print(f"Экспортировано событий: {path}")
    print("Файл может содержать имена устройств, MAC- и IP-адреса; проверьте его перед отправкой.")
    return 0


def cmd_oui_update(args: argparse.Namespace) -> int:
    count, path = update_oui_database(Path(args.data_dir))
    print(f"Загружено IEEE OUI записей: {count}")
    print(f"Локальная база: {path}")
    print("Поиск производителей далее работает локально; MAC-адреса не отправляются.")
    return 0


def cmd_trust(args: argparse.Namespace) -> int:
    mac = args.mac.upper()
    if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
        raise RouterError("MAC-адрес должен быть в формате AA:BB:CC:DD:EE:FF")
    storage = Storage(args.data_dir)
    snapshot = storage.last_snapshot() or {}
    try:
        name = storage.trust_device(mac, snapshot)
    except ValueError as exc:
        raise RouterError(str(exc)) from exc
    print(f"Устройство добавлено в доверенную базу: {name} ({mac})")
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    storage = Storage(args.data_dir)
    baseline = require_baseline(storage)
    if not valid_loopback_host(args.host, args.port):
        raise RouterError("Веб-панель разрешено запускать только на 127.0.0.1")
    adapter = resolve(args)
    # Validate the local target before prompting for credentials.
    if adapter == "openwrt":
        OpenWrtAdapter(args.router, allow_insecure_http=args.allow_insecure_http)
    else:
        MiWiFiAdapter(args.router)
    args._resolved_adapter = adapter
    serve(args, storage, baseline, credentials(adapter))
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="LANwatch — локальный монитор безопасности сети")
    result.add_argument("command", choices=["demo", "probe", "enroll", "check", "monitor", "trust", "web", "audit", "export", "oui-update"])
    result.add_argument("--router", default="http://192.168.31.1")
    result.add_argument("--adapter", choices=["auto", "miwifi", "openwrt"], default="auto")
    result.add_argument("--allow-insecure-http", action="store_true", help="разрешить отправку пароля OpenWrt открытым текстом в доверенной изолированной LAN")
    result.add_argument("--output", default="lanwatch-probe.json", help="путь для безопасного файла команды probe")
    result.add_argument("--data-dir", default=".lanwatch")
    result.add_argument("--interval", type=max_one, default=30)
    result.add_argument("--upload-threshold", type=float, default=5_000_000, help="байт/с")
    result.add_argument("--host", default="127.0.0.1", help="веб-панель: принимается только 127.0.0.1")
    result.add_argument("--port", type=valid_port, default=8080)
    result.add_argument("--format", choices=["jsonl", "syslog", "cef"], default="jsonl", help="формат команды export")
    result.add_argument("--webhook-url", default=None, help="необязательный opt-in HTTPS webhook; отправляет только severity/kind/title")
    result.add_argument("--telegram-notifications", action="store_true", help="включить Telegram; токен и chat ID берутся из env")
    result.add_argument("--arp-neighbors", action=argparse.BooleanOptionalAction, default=True, help="обогащать снимок записями из локального ARP-кэша ОС (можно отключить --no-arp-neighbors)")
    result.add_argument("--wazuh-jsonl", default=None, help="локальный JSONL журнал новых событий, который можно собирать агентом Wazuh")
    return result


def max_one(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("значение должно быть больше нуля")
    return parsed


def valid_port(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("порт должен быть от 1 до 65535")
    return parsed


def main() -> int:
    args = parser().parse_args()
    try:
        return globals()[f"cmd_{args.command}"](args)
    except RouterError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nМониторинг остановлен")
        return 130
