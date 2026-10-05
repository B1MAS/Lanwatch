import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from lanwatch.client import MiWiFiClient, RouterError
from lanwatch.adapters.openwrt import OpenWrtClient, normalize_openwrt
from lanwatch.adapters import detect_adapter
from lanwatch.detectors import Event
from lanwatch.probe import diagnostic_report, write_report
from lanwatch.storage import Storage
from lanwatch.web import (
    DashboardState,
    render_page,
    valid_csrf_token,
    valid_host_header,
    valid_loopback_host,
    valid_post_host,
)


class StorageAndSecurityTests(unittest.TestCase):
    def test_only_literal_local_router_addresses_are_accepted(self):
        self.assertEqual(MiWiFiClient("http://192.168.31.1").base_url, "http://192.168.31.1")
        for address in (
            "http://example.com",
            "http://8.8.8.8",
            "http://0.0.0.0",
            "http://192.168.1.1/redirect",
            "http://user:pass@192.168.1.1",
            "ftp://192.168.1.1",
        ):
            with self.subTest(address=address), self.assertRaises(RouterError):
                MiWiFiClient(address)

    def test_openwrt_requires_https_before_any_credentials_are_sent(self):
        with self.assertRaisesRegex(RouterError, "нужен HTTPS"):
            OpenWrtClient("http://192.168.1.1")
        self.assertEqual(OpenWrtClient("https://192.168.1.1").base_url, "https://192.168.1.1")
        self.assertEqual(OpenWrtClient("http://192.168.1.1", allow_insecure_http=True).base_url, "http://192.168.1.1")

    def test_openwrt_rpc_blocks_non_read_calls(self):
        client = OpenWrtClient("https://192.168.1.1")
        with self.assertRaisesRegex(RouterError, "заблокировал"):
            client._call("system", "reboot")

    def test_auto_detection_uses_known_api_probes_without_credentials(self):
        with patch("lanwatch.adapters.MiWiFiAdapter") as miwifi, patch("lanwatch.adapters.OpenWrtAdapter") as openwrt:
            miwifi.return_value.probe.return_value = False
            openwrt.return_value.probe.return_value = True
            self.assertEqual(detect_adapter("https://192.168.1.1"), "openwrt")
            miwifi.return_value.probe.assert_called_once_with()
            openwrt.return_value.probe.assert_called_once_with()

    def test_openwrt_lease_snapshot_normalizes_to_common_schema(self):
        snapshot = normalize_openwrt({
            "captured_at": 10,
            "board": {"model": "Example Router", "release": {"version": "SNAPSHOT"}},
            "info": {"uptime": 99},
            "wan": {"up": True, "dns-server": ["1.1.1.1"]},
            "leases": [{"interface": "lan", "leases": [
                {"macaddr": "aa:bb:cc:dd:ee:ff", "hostname": "laptop", "ipaddr": "192.168.1.9"},
                {"macaddr": "not-a-mac", "hostname": "bad"},
            ]}],
        })
        self.assertEqual(snapshot["router"]["model"], "Example Router")
        self.assertEqual(snapshot["wan"]["dns"], ["1.1.1.1"])
        self.assertEqual(list(snapshot["devices"]), ["AA:BB:CC:DD:EE:FF"])
        self.assertEqual(snapshot["devices"]["AA:BB:CC:DD:EE:FF"]["ips"], ["192.168.1.9"])
        single_group = normalize_openwrt({"leases": {
            "device": "br-lan",
            "leases": [{"macaddr": "11:22:33:44:55:66", "hostname": "desktop", "ipaddr": "192.168.1.10"}],
        }})
        self.assertIn("11:22:33:44:55:66", single_group["devices"])

    def test_probe_contains_only_safe_allowlisted_metadata(self):
        report = diagnostic_report("openwrt", True)
        rendered = str(report)
        for private in ("AA:BB:CC:DD:EE:FF", "192.168.1.1", "admin", "stok", "password", "hostname"):
            self.assertNotIn(private, rendered)
        with tempfile.TemporaryDirectory() as temp:
            path = f"{temp}/lanwatch-probe.json"
            write_report(report, path)
            with self.assertRaises(FileExistsError):
                write_report(report, path)

    def test_dashboard_host_is_loopback_only(self):
        self.assertTrue(valid_loopback_host("127.0.0.1", 8080))
        self.assertFalse(valid_loopback_host("0.0.0.0", 8080))
        self.assertFalse(valid_loopback_host("192.168.31.10", 8080))
        self.assertFalse(valid_loopback_host("localhost", 8080))
        self.assertTrue(valid_host_header("127.0.0.1:8080", 8080))
        self.assertFalse(valid_host_header("attacker.example:8080", 8080))

    def test_post_requires_exact_local_host(self):
        self.assertTrue(valid_post_host("127.0.0.1:8080", 8080))
        self.assertFalse(valid_post_host("192.168.31.2:8080", 8080))

    def test_post_requires_unpredictable_csrf_token(self):
        self.assertTrue(valid_csrf_token("secret-value", "secret-value"))
        self.assertFalse(valid_csrf_token("", "secret-value"))
        self.assertFalse(valid_csrf_token("wrong", "secret-value"))

    def test_trust_only_accepts_current_online_device(self):
        with tempfile.TemporaryDirectory() as temp:
            storage = Storage(temp)
            storage.save_baseline({"known_devices": {}})
            snapshot = {"devices": {"AA:BB:CC:DD:EE:01": {"name": "Phone", "online": True}}}
            self.assertEqual(storage.trust_device("AA:BB:CC:DD:EE:01", snapshot), "Phone")
            self.assertIn("AA:BB:CC:DD:EE:01", storage.baseline()["known_devices"])
            with self.assertRaises(ValueError):
                storage.trust_device("AA:BB:CC:DD:EE:02", snapshot)

    def test_event_history_persists_and_coalesces_repeated_alerts(self):
        with tempfile.TemporaryDirectory() as temp:
            storage = Storage(temp)
            event = Event("HIGH", "unknown_device", "Новое устройство", "Phone (AA:BB:CC:DD:EE:01)")
            storage.record_events([event], 1000)
            storage.record_events([event], 1030)
            rows = storage.events()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["captured_at"], 1030)

    def test_wazuh_jsonl_stream_appends_only_new_alerts(self):
        import json
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            storage = Storage(temp)
            stream = Path(temp) / "events.jsonl"
            event = Event("HIGH", "dns_changed", "DNS changed", "new resolver")
            storage.record_events([event], 100, str(stream))
            storage.record_events([event], 130, str(stream))
            rows = [json.loads(line) for line in stream.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source"], "LANwatch")
            self.assertEqual(rows[0]["kind"], "dns_changed")

    def test_sqlite_history_keeps_snapshots_and_migrates_json_events_once(self):
        import json
        with tempfile.TemporaryDirectory() as temp:
            old = __import__("pathlib").Path(temp)
            (old / "events.json").write_text(json.dumps({"items": [{"captured_at": 4, "severity": "INFO", "kind": "old", "title": "legacy", "details": "imported"}]}), encoding="utf-8")
            storage = Storage(temp)
            self.assertEqual(storage.events()[0]["title"], "legacy")
            Storage(temp)
            self.assertEqual(len(storage.events()), 1)
            storage.save_snapshot({"captured_at": 10, "devices": {}, "wan": {"online": True}})
            storage.save_snapshot({"captured_at": 20, "devices": {}, "wan": {"online": False}})
            self.assertEqual([row["captured_at"] for row in storage.history(10)], [10, 20])

    def test_dashboard_escapes_router_controlled_device_names(self):
        with tempfile.TemporaryDirectory() as temp:
            storage = Storage(temp)
            storage.save_snapshot({
                "captured_at": 1,
                "router": {},
                "wan": {},
                "devices": {
                    "AA:BB:CC:DD:EE:01": {
                        "name": "<img src=x onerror=alert(1)>",
                        "ips": [],
                        "online": True,
                    }
                },
            })
            state = DashboardState(SimpleNamespace(
                interval=30, router="http://192.168.1.1", _resolved_adapter="miwifi",
                allow_insecure_http=False,
            ), storage, {"known_devices": {}}, ("",))
            page = render_page(state).decode("utf-8")
            self.assertIn("&lt;img src=x onerror=alert(1)&gt;", page)
            self.assertNotIn("<img src=x onerror=alert(1)>", page)
            self.assertIn(f'name="csrf" value="{state.csrf_token}"', page)

    def test_dashboard_renders_sqlite_history_charts_and_source_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            storage = Storage(temp)
            for stamp, online in ((100, True), (200, False)):
                storage.save_snapshot({
                    "captured_at": stamp,
                    "router": {}, "wan": {"online": online},
                    "devices": {"AA:BB:CC:DD:EE:01": {
                        "name": "Phone", "ips": ["192.168.1.9"], "online": online,
                        "sources": ["router_api", "arp_cache"], "vendor": "Example Inc.",
                    }},
                    "source_comparison": {"router_api_only": [], "both": ["AA:BB:CC:DD:EE:01"], "arp_cache_only": [], "arp_cache_count": 1},
                })
            state = DashboardState(SimpleNamespace(
                interval=30, router="http://192.168.1.1", _resolved_adapter="miwifi", allow_insecure_http=False,
            ), storage, {"known_devices": {}}, ("",))
            page = render_page(state).decode("utf-8")
            self.assertIn("<svg", page)
            self.assertIn("API роутера + ARP-кэш", page)
            self.assertIn("Example Inc.", page)


if __name__ == "__main__":
    unittest.main()
