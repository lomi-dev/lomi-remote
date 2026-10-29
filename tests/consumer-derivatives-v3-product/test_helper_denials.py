"""Pure plan and evidence-validator tests; no PostgreSQL tools are invoked."""
from pathlib import Path
import json
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import helper_denials


RUN_UUID = "7e1c2b9f-9b28-4b52-a345-12dfcb08a012"


def capture(signature, *, definition="CREATE FUNCTION helper() RETURNS void\nBEGIN\n RETURN;\nEND\n",
            owner=helper_denials.BODY_OWNER, acl=None, config=None, security_definer=False,
            encoded=None, missing=()):
    raw_definition = definition.encode("utf-8")
    row = {
        "kind": "function",
        "signature": signature,
        "owner": owner,
        "securityDefiner": security_definer,
        "config": ["search_path=pg_catalog, public, pg_temp"] if config is None else config,
        "definition": definition,
        "definitionUtf8Hex": raw_definition.hex() if encoded is None else encoded,
        # Deliberately unrelated to the body: this validator must compare raw
        # catalog fields and must not depend on source or supplied catalog hashes.
        "catalogSha256": "0" * 64,
        "acl": [{
            "grantor": helper_denials.BODY_OWNER,
            "grantee": "lomi_remote_inventory_owner",
            "privilege": "EXECUTE",
            "grantable": False,
        }] if acl is None else acl,
    }
    for field in missing:
        row.pop(field, None)
    return json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


def transcript(attempt, *, sqlstate="42501", session_user=None, current_user=None,
               role=None, rolsuper="false", rolcreaterole="false", is_superuser="false",
               run_uuid=None, attempt_id=None, include_ack=True):
    run_uuid = attempt["runUuid"] if run_uuid is None else run_uuid
    attempt_id = attempt["attemptId"] if attempt_id is None else attempt_id
    role = attempt["role"] if role is None else role
    session_user = role if session_user is None else session_user
    current_user = role if current_user is None else current_user
    result = (
        "NOTICE: CONSUMER_DENIAL_RESULT"
        f"|run={run_uuid}|attempt={attempt_id}|role={role}"
        f"|session_user={session_user}|current_user={current_user}"
        f"|rolsuper={rolsuper}|rolcreaterole={rolcreaterole}"
        f"|is_superuser={is_superuser}|sqlstate={sqlstate}\n"
    )
    if include_ack:
        result += (
            "CONSUMER_DENIAL_ROLLBACK_ACK"
            f"|run={run_uuid}|attempt={attempt_id}|role={role}\n"
        )
    return result.encode("ascii")


class DenialPlanTests(unittest.TestCase):
    def test_fixed_matrix_uses_role_bound_connections_and_all_operations(self):
        attempts = helper_denials.build_attempts(RUN_UUID)
        self.assertEqual(len(attempts), 2 * 4 * 10)
        self.assertEqual(len({item["attemptId"] for item in attempts}), 80)
        self.assertEqual({item["role"] for item in attempts}, set(helper_denials.ROLES))
        self.assertEqual({item["signature"] for item in attempts}, {
            item["signature"] for item in helper_denials.HELPERS
        })
        self.assertEqual({item["operation"] for item in attempts}, set(helper_denials.OPERATIONS))

        for item in attempts:
            self.assertIn("BEGIN;\nDO $consumer_denial_connection$", item["sql"])
            self.assertIn("SET LOCAL SESSION AUTHORIZATION '" + item["role"] + "';", item["sql"])
            self.assertIn("current_user IS DISTINCT FROM '" + item["role"] + "'", item["sql"])
            self.assertIn("current_setting('is_superuser')::boolean", item["sql"])
            self.assertIn("rolsuper, r.rolcreaterole INTO STRICT", item["sql"])
            self.assertIn("CONSUMER_DENIAL_RESULT", item["sql"])
            self.assertIn("ROLLBACK;\nSELECT 'CONSUMER_DENIAL_ROLLBACK_ACK", item["sql"])
            self.assertEqual(item["connectionRole"], helper_denials.CONNECTION_ROLE_BY_ACTOR[item["role"]])

        migrator = attempts[0]
        self.assertEqual(migrator["connectionRole"], "lomi_migrator")
        self.assertIn("session_user IS DISTINCT FROM 'lomi_migrator'", migrator["sql"])
        self.assertIn("current_setting('is_superuser')::boolean IS DISTINCT FROM false::boolean", migrator["sql"])
        for actor in helper_denials.APP_ROLES:
            role_attempt = next(item for item in attempts if item["role"] == actor)
            self.assertEqual(role_attempt["connectionRole"], actor)
            self.assertIn("session_user IS DISTINCT FROM '" + actor + "'", role_attempt["sql"])

        principal = next(item for item in attempts if item["operation"] == "replace_noop"
                         and item["signature"] == helper_denials.HELPERS[0]["signature"])
        scalar = next(item for item in attempts if item["operation"] == "replace_noop"
                      and item["signature"] == helper_denials.HELPERS[1]["signature"])
        self.assertIn("(c public.consumer_authorization)", principal["statement"])
        self.assertIn("p_expiry_ms bigint,p_manage boolean,p_hash bytea", scalar["statement"])
        self.assertIn("RETURNS void", principal["statement"])
        self.assertIn("BEGIN RETURN; END", principal["statement"])

    def test_rename_names_are_unique_valid_and_below_postgres_identifier_limit(self):
        attempts = [item for item in helper_denials.build_attempts(RUN_UUID)
                    if item["operation"] == "rename"]
        names = [item["statement"].rsplit(" ", 1)[-1] for item in attempts]
        self.assertEqual(len(names), 8)
        self.assertEqual(len(names), len(set(names)))
        for name in names:
            self.assertRegex(name, r"^lomi_helper_denial_[0-9]+_[0-9a-f]{32}$")
            self.assertLessEqual(len(name.encode("ascii")), 63)

    def test_builder_and_validator_reject_noncanonical_identifiers_and_forged_plans(self):
        for unsafe in ("../bad", RUN_UUID.upper(), RUN_UUID + "x", "not-a-uuid"):
            with self.subTest(unsafe=unsafe), self.assertRaises(helper_denials.Rejected):
                helper_denials.build_attempts(unsafe)
        attempt = helper_denials.build_attempts(RUN_UUID)[0]
        baseline = capture(attempt["signature"])
        for field, value in (
            ("role", "lomi_migrator; DROP ROLE lomi_runtime"),
            ("connectionRole", "e2_owner; SET ROLE lomi_runtime"),
            ("signature", "public.other(uuid)"),
            ("statement", "DROP FUNCTION public.other()"),
        ):
            forged = dict(attempt)
            forged[field] = value
            with self.subTest(field=field), self.assertRaises(helper_denials.Rejected):
                helper_denials.validate_attempt_result(
                    forged, process_return_code=0, output=transcript(attempt),
                    before_capture=baseline, after_capture=baseline,
                )


class DenialEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.attempt = helper_denials.build_attempts(RUN_UUID)[0]
        self.signature = self.attempt["signature"]
        self.before = capture(self.signature)

    def validate(self, *, output=None, process_return_code=0, before=None, after=None):
        return helper_denials.validate_attempt_result(
            self.attempt,
            process_return_code=process_return_code,
            output=transcript(self.attempt) if output is None else output,
            before_capture=self.before if before is None else before,
            after_capture=self.before if after is None else after,
        )

    def test_accepts_only_attempt_bound_42501_after_rollback_and_exact_snapshot(self):
        # The deliberately stale catalogSha256 is ignored; UTF-8 bytes, owner,
        # expanded ACL, config, and invoker state are compared directly.
        report = self.validate()
        self.assertEqual(report["sqlstate"], "42501")
        self.assertTrue(report["catalogUnchanged"])
        self.assertTrue(report["rollbackAcknowledged"])

    def test_borrowed_attempt_transcript_cannot_validate_another_matrix_row(self):
        second = helper_denials.build_attempts(RUN_UUID)[1]
        with self.assertRaisesRegex(helper_denials.Rejected, "another run, role, or attempt"):
            helper_denials.validate_attempt_result(
                second, process_return_code=0, output=transcript(self.attempt),
                before_capture=capture(second["signature"]),
                after_capture=capture(second["signature"]),
            )

    def test_rejects_wrong_identity_role_attributes_process_failure_and_missing_ack(self):
        valid = transcript(self.attempt)
        result_line, ack_line = valid.splitlines()
        bad_transcripts = (
            transcript(self.attempt, session_user="e2_owner"),
            transcript(self.attempt, current_user="lomi_consumer_auth_body_owner"),
            transcript(self.attempt, role="lomi_remote_api"),
            transcript(self.attempt, rolsuper="true"),
            transcript(self.attempt, rolcreaterole="true"),
            transcript(self.attempt, is_superuser="true"),
            transcript(self.attempt, include_ack=False),
            ack_line + b"\n" + result_line + b"\n",
            b"ERROR: permission denied for role lomi_migrator\n",
        )
        for output in bad_transcripts:
            with self.subTest(output=output), self.assertRaises(helper_denials.Rejected):
                self.validate(output=output)
        with self.assertRaisesRegex(helper_denials.Rejected, "process did not succeed"):
            self.validate(process_return_code=1)
        with self.assertRaisesRegex(helper_denials.Rejected, "process did not succeed"):
            self.validate(process_return_code=True)

    def test_rejects_wrong_sqlstate_and_each_material_catalog_drift(self):
        for code in ("00000", "42601", "2BP01", "42502"):
            with self.subTest(sqlstate=code), self.assertRaisesRegex(helper_denials.Rejected, "SQLSTATE"):
                self.validate(output=transcript(self.attempt, sqlstate=code))
        changed_acl = [{
            "grantor": helper_denials.BODY_OWNER,
            "grantee": "lomi_runtime",
            "privilege": "EXECUTE",
            "grantable": False,
        }]
        drifted = (
            capture(self.signature, definition="CREATE FUNCTION bypass() RETURNS void\n"),
            capture(self.signature, owner="lomi_migrator"),
            capture(self.signature, acl=changed_acl),
            capture(self.signature, config=["search_path=public"]),
            capture(self.signature, security_definer=True),
        )
        for after in drifted:
            with self.subTest(after=after), self.assertRaises(helper_denials.Rejected):
                self.validate(after=after)

    def test_rejects_missing_duplicate_malformed_and_bad_utf8_captures(self):
        with self.assertRaisesRegex(helper_denials.Rejected, "exactly one"):
            self.validate(before=b"")
        with self.assertRaisesRegex(helper_denials.Rejected, "exactly one"):
            self.validate(before=self.before + self.before)
        for malformed in (
            b"{not json}\n",
            capture(self.signature, encoded="00"),
            capture(self.signature, missing=("config",)),
            capture(self.signature, config="search_path=public"),
            capture(self.signature, acl=[{"grantee": "PUBLIC"}]),
        ):
            with self.subTest(malformed=malformed), self.assertRaises(helper_denials.Rejected):
                self.validate(before=malformed)

    def test_complete_matrix_rejects_replay_and_validates_80_unique_transcripts(self):
        attempts = helper_denials.build_attempts(RUN_UUID)
        outcomes = [{
            "attemptId": item["attemptId"],
            "processReturnCode": 0,
            "output": transcript(item),
            "beforeCapture": capture(item["signature"]),
            "afterCapture": capture(item["signature"]),
        } for item in attempts]
        report = helper_denials.validate_complete_matrix(RUN_UUID, outcomes)
        self.assertEqual(report["attemptCount"], 80)
        self.assertEqual(report["deniedCount"], 80)
        self.assertEqual(len(report["results"]), 80)
        with self.assertRaisesRegex(helper_denials.Rejected, "complete"):
            helper_denials.validate_complete_matrix(RUN_UUID, outcomes[:-1])
        duplicate = list(outcomes)
        duplicate[-1] = dict(duplicate[0])
        with self.assertRaisesRegex(helper_denials.Rejected, "duplicate"):
            helper_denials.validate_complete_matrix(RUN_UUID, duplicate)

        replayed = [dict(item, output=transcript(attempts[0])) for item in outcomes]
        with self.assertRaisesRegex(helper_denials.Rejected, "another run, role, or attempt"):
            helper_denials.validate_complete_matrix(RUN_UUID, replayed)


if __name__ == "__main__":
    unittest.main()
