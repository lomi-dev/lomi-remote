import unittest
from run_native import require_native_pass


def receipt():
    return dict(passed=True, actualHostDbDigestPreserved=True, workspacePreserved=True,
                manualLocalServiceOnly=True, servicesAbsent=True, rootAbsent=True,
                registrationAbsent=True, sameAccountCleanup=True,
                ownedProcessesRemaining=0, publicBootCredentialsQualified=False,
                checks=[dict(name=str(i), passed=True) for i in range(20)])


class Acceptance(unittest.TestCase):
    def test_complete_fixture(self):
        require_native_pass(receipt())

    def test_claimed_pass_cannot_hide_incomplete_cleanup(self):
        for key in ('servicesAbsent','rootAbsent','registrationAbsent','sameAccountCleanup',
                    'actualHostDbDigestPreserved','workspacePreserved'):
            value=receipt();value[key]=False
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                require_native_pass(value)

    def test_missing_checks_or_live_processes_are_rejected(self):
        for key,value in [('checks',[]),('ownedProcessesRemaining',1),
                          ('publicBootCredentialsQualified',True)]:
            row=receipt();row[key]=value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                require_native_pass(row)


if __name__=='__main__':unittest.main()
