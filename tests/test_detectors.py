import unittest

from lanwatch.detectors import detect


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.baseline = {
            "expected_dns": ["1.1.1.1"],
            "known_devices": {"AA": {"name": "Laptop"}},
        }
        self.previous = {
            "router": {"uptime": 1000, "firmware": "1.0"},
            "wan": {"online": True, "dns": ["1.1.1.1"]},
            "devices": {"AA": {"name": "Laptop", "online": True}},
        }

    def current(self):
        return {
            "router": {"uptime": 1100, "firmware": "1.0"},
            "wan": {"online": True, "dns": ["1.1.1.1"]},
            "devices": {"AA": {"name": "Laptop", "online": True, "wan_access": True, "up_bps": 0, "ips": []}},
        }

    def test_clean_snapshot_has_no_events(self):
        self.assertEqual(detect(self.baseline, self.previous, self.current()), [])

    def test_unknown_device(self):
        current = self.current()
        current["devices"]["BB"] = {"name": "Phone", "online": True, "wan_access": True, "up_bps": 0, "ips": ["192.0.2.1"]}
        kinds = {event.kind for event in detect(self.baseline, self.previous, current)}
        self.assertIn("unknown_device", kinds)

    def test_dns_change_and_reboot(self):
        current = self.current()
        current["wan"]["dns"] = ["9.9.9.9"]
        current["router"]["uptime"] = 10
        kinds = {event.kind for event in detect(self.baseline, self.previous, current)}
        self.assertEqual(kinds, {"dns_changed", "router_reboot"})

    def test_wan_down(self):
        current = self.current()
        current["wan"]["online"] = False
        kinds = {event.kind for event in detect(self.baseline, self.previous, current)}
        self.assertIn("wan_down", kinds)


if __name__ == "__main__":
    unittest.main()
