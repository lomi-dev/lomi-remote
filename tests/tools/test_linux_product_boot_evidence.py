"""Fail-closed tests for monotonic boot-service qualification evidence."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "linux_product_boot_under_test", ROOT / "tests/product-linux/boot_service_lifecycle.py")
boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boot)


class BootEvidenceTests(unittest.TestCase):
    def evidence(self):
        uid = 501
        events = [{"_BOOT_ID": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "MESSAGE": "Accepted publickey for lomi-e0 from 127.0.0.1",
                   "__MONOTONIC_TIMESTAMP": "900", "_UID": "0"},
                  {"_BOOT_ID": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "MESSAGE": "Accepted password for lomi-e0 from 127.0.0.1",
                   "__MONOTONIC_TIMESTAMP": "1200", "_UID": "0"}]
        units = {"user-runtime-dir@501.service": "100", "user@501.service": "200",
                 "product": "800"}
        return uid, units, events

    def test_accepts_only_same_boot_earlier_service_activation(self):
        uid, units, events = self.evidence()
        result = boot.qualify_timestamps("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", units, events, uid, "lomi-e0")
        self.assertEqual(result["firstObservedSshLoginMonotonic"], 900)
        self.assertEqual(result["claim"], "service active before first observed SSH login")

    def test_missing_zero_equal_late_or_truncated_evidence_fails_closed(self):
        uid, units, events = self.evidence()
        cases = []
        cases.append((dict(units, product=""), events))
        cases.append((dict(units, product="0"), events))
        cases.append((dict(units, product="900"), events))
        cases.append((dict(units, product="901"), events))
        cases.append((units, [{"_BOOT_ID": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "MESSAGE": "Accepted publickey for lomi-e0",
                              "__MONOTONIC_TIMESTAMP": ""}]))
        cases.append((units, [{"_BOOT_ID": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "MESSAGE": "Accepted publickey for lomi-e0",
                              "__MONOTONIC_TIMESTAMP": "900"}]))
        for bad_units, bad_events in cases:
            with self.subTest(units=bad_units, events=bad_events):
                with self.assertRaises(RuntimeError):
                    boot.qualify_timestamps("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", bad_units, bad_events, uid, "lomi-e0")

    def test_rejects_invalid_boot_identity(self):
        uid, units, events = self.evidence()
        for value in ("malformed", "aaaaaaaa-aaaaaaaaaaaaaaaaaaaaaaaa",
                      "aaaaaaaa--aaaa-aaaa-aaaa-aaaaaaaaaaaa"):
            with self.subTest(boot_id=value), self.assertRaises(RuntimeError):
                boot.qualify_timestamps(value, units, events, uid, "lomi-e0")

    def test_each_manager_timestamp_is_required(self):
        uid, units, events = self.evidence()
        for key in ("user-runtime-dir@501.service", "user@501.service"):
            bad = dict(units)
            del bad[key]
            with self.subTest(unit=key), self.assertRaises(RuntimeError):
                boot.qualify_timestamps("boot-a", bad, events, uid, "lomi-e0")

    def test_cold_boot_requires_valid_changed_id(self):
        for before, current in (("boot-a", "boot-b"), ("00000000-0000-0000-0000-000000000000",
                                                               "11111111-1111-1111-1111-111111111111")):
            if before == "boot-a":
                before = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
                current = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
            boot.require_changed_boot_id(before, current)
        for before, current in (("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                                ("malformed", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
                                ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bad")):
            with self.subTest(before=before, current=current), self.assertRaises(RuntimeError):
                boot.require_changed_boot_id(before, current)

    def test_unit_name_is_deterministic_and_bounded_to_profile(self):
        self.assertEqual(boot.expected_unit("/home/test/s $%"), boot.expected_unit("/home/test/s $%"))
        self.assertNotEqual(boot.expected_unit("/home/test/a"), boot.expected_unit("/home/test/b"))

    def test_absent_unit_requires_complete_manager_and_filesystem_evidence(self):
        valid = {"LoadState": "not-found", "ActiveState": "inactive", "MainPID": "0",
                 "FragmentPath": "", "DropInPaths": ""}
        self.assertTrue(boot.absent_unit_confirmed(False, False, valid))
        invalid = [
            dict(valid, ActiveState="active"),
            dict(valid, MainPID="41"),
            {key: value for key, value in valid.items() if key != "MainPID"},
            dict(valid, FragmentPath="/tmp/lomiremote.service"),
            dict(valid, DropInPaths="/etc/systemd/user/override.conf"),
        ]
        for properties in invalid:
            with self.subTest(properties=properties):
                self.assertFalse(boot.absent_unit_confirmed(False, False, properties))
        self.assertFalse(boot.absent_unit_confirmed(True, False, valid))
        self.assertFalse(boot.absent_unit_confirmed(False, True, valid))

    def test_linger_mutations_use_noninteractive_sudo_for_exact_uid(self):
        self.assertEqual(boot.linger_mutation_command("enable-linger", 1001),
                         ["/usr/bin/sudo", "-n", "/usr/bin/loginctl", "enable-linger", "1001"])
        self.assertEqual(boot.linger_mutation_command("disable-linger", 1001),
                         ["/usr/bin/sudo", "-n", "/usr/bin/loginctl", "disable-linger", "1001"])
        for action, uid in (("show-user", 1001), ("enable-linger", "1001"), ("disable-linger", -1)):
            with self.subTest(action=action, uid=uid), self.assertRaises(RuntimeError):
                boot.linger_mutation_command(action, uid)

    def test_registration_requires_exact_os_account_and_other_owned_fields(self):
        registration = {"profile": "/home/lomi-e0/profile", "executable": "/home/lomi-e0/bin/lomiremote",
                        "account": "lomi-e0", "mode": "boot", "unit": "lomiremote-owned.service"}
        self.assertTrue(boot.registration_matches(registration, "/home/lomi-e0/profile",
                                                 "/home/lomi-e0/bin/lomiremote", "lomi-e0", "boot",
                                                 "lomiremote-owned.service"))
        for key, value in (("account", "1001"), ("profile", "/other/profile"),
                           ("executable", "/other/lomiremote"), ("mode", "login"),
                           ("unit", "lomiremote-other.service")):
            changed = dict(registration, **{key: value})
            with self.subTest(key=key):
                self.assertFalse(boot.registration_matches(
                    changed, "/home/lomi-e0/profile", "/home/lomi-e0/bin/lomiremote",
                    "lomi-e0", "boot", "lomiremote-owned.service"))

    def test_ssh_journal_query_uses_fixed_privileged_argv_and_narrow_filter(self):
        self.assertEqual(boot.ssh_journal_command(),
                         ["/usr/bin/sudo", "-n", "/usr/bin/journalctl", "--boot", "--no-pager",
                          "--output=json", "_COMM=sshd"])

    def test_already_absent_registration_requires_unit_reconciliation_before_restore(self):
        actions = []
        boot.cleanup_owned_service(
            "lomiremote-fixture.service", lambda: self.fail("must not uninstall absent registration"),
            lambda: (actions.append("registration-check") or False),
            lambda unit: (actions.append("reconcile:" + unit) or True),
            lambda: actions.append("restore-linger"))
        self.assertEqual(actions, ["registration-check", "reconcile:lomiremote-fixture.service",
                                   "restore-linger"])

    def test_registered_unit_cleanup_uses_uninstall_then_reconciles(self):
        actions = []
        registration_checks = iter((True, False))
        boot.cleanup_owned_service(
            "lomiremote-fixture.service",
            lambda: actions.append("uninstall"), lambda: next(registration_checks),
            lambda unit: (actions.append("reconcile:" + unit) or True),
            lambda: actions.append("restore-linger"))
        self.assertEqual(actions, ["uninstall", "reconcile:lomiremote-fixture.service", "restore-linger"])

    def test_partial_install_cleanup_resumes_uninstall_when_unit_is_missing(self):
        actions = []
        registration_checks = iter((True, False))
        boot.cleanup_owned_service(
            "lomiremote-fixture.service", lambda: actions.append("resume-uninstall"),
            lambda: next(registration_checks),
            lambda unit: (actions.append("reconcile:" + unit) or True),
            lambda: actions.append("restore-linger"))
        self.assertEqual(actions, ["resume-uninstall", "reconcile:lomiremote-fixture.service",
                                   "restore-linger"])

    def test_absent_registration_requires_reconciliation_before_linger_restore(self):
        actions = []
        with self.assertRaises(RuntimeError):
            boot.cleanup_owned_service(
                "lomiremote-fixture.service", lambda: self.fail("must not stop without registration"),
                lambda: False, lambda unit: (actions.append("reconcile:" + unit) or False),
                lambda: actions.append("restore-linger"))
        self.assertEqual(actions, ["reconcile:lomiremote-fixture.service"])

    def test_uncertain_stop_or_uninstall_never_restores_linger(self):
        for fail_at in ("uninstall", "reconcile"):
            actions = []
            registration_checks = iter((True, False))
            def uninstall():
                actions.append("uninstall")
                if fail_at == "uninstall":
                    raise RuntimeError("uninstall uncertain")
            def reconcile(_unit):
                actions.append("reconcile")
                return fail_at != "reconcile"
            with self.subTest(fail_at=fail_at), self.assertRaises(RuntimeError):
                boot.cleanup_owned_service(
                    "lomiremote-fixture.service", uninstall, lambda: next(registration_checks),
                    reconcile, lambda: actions.append("restore-linger"))
            self.assertNotIn("restore-linger", actions)


if __name__ == "__main__":
    unittest.main()
