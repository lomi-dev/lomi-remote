"""Pure tests for account-bound boot-service journal evidence."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).with_name("boot_service_lifecycle.py")
SPEC = importlib.util.spec_from_file_location("boot_service_lifecycle_tested", SCRIPT)
boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boot)


BOOT_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


class QualifyTimestampsTests(unittest.TestCase):
    def setUp(self):
        self.units = {
            "user-runtime-dir@1001.service": "100",
            "user@1001.service": "200",
            "product": "800",
        }

    def event(self, account="alice", boot_id=BOOT_ID, timestamp="900"):
        return {
            "_BOOT_ID": boot_id,
            "MESSAGE": "Accepted publickey for %s from 127.0.0.1" % account,
            "__MONOTONIC_TIMESTAMP": timestamp,
        }

    def qualify(self, events, units=None, account="alice"):
        return boot.qualify_timestamps(BOOT_ID, units or self.units, events, 1001, account)

    def test_accepts_exact_resolved_account(self):
        result = self.qualify([self.event(account="resolved-user")], account="resolved-user")
        self.assertEqual(result["firstObservedSshLoginMonotonic"], 900)

    def test_rejects_another_account(self):
        with self.assertRaises(RuntimeError):
            self.qualify([self.event(account="another-user")], account="resolved-user")

    def test_ignores_events_from_different_boot_ids(self):
        with self.assertRaises(RuntimeError):
            self.qualify([self.event(boot_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")])

    def test_requires_every_service_timestamp_before_first_ssh_login(self):
        for key in self.units:
            units = dict(self.units, **{key: "900"})
            with self.subTest(unit=key), self.assertRaises(RuntimeError):
                self.qualify([self.event(timestamp="900")], units=units)

    def test_rejects_unsafe_account_name(self):
        with self.assertRaises(RuntimeError):
            self.qualify([self.event()], account="alice|root")


if __name__ == "__main__":
    unittest.main()
