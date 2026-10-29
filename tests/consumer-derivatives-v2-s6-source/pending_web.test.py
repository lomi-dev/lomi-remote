import importlib.util
from pathlib import Path
import re
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("pending_web", HERE / "pending_web.py")
pending_web = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pending_web)


class PendingWebSourceTests(unittest.TestCase):
    def test_builder_escapes_synthetic_literals_and_is_strict(self):
        self.assertEqual(pending_web._literal("s6-client'quoted"), "'s6-client''quoted'")
        sql = pending_web.build_pending_web_sql(pending_web.DEFAULT_SEED)
        self.assertIn("BEGIN;", sql)
        self.assertTrue(sql.rstrip().endswith("COMMIT;"))
        with self.assertRaises(ValueError):
            pending_web.build_pending_web_sql({**pending_web.DEFAULT_SEED, "surprise": "value"})
        with self.assertRaises(ValueError):
            pending_web.build_pending_web_sql({**pending_web.DEFAULT_SEED, "user_id": "real-user"})
        with self.assertRaises(ValueError):
            pending_web.build_pending_web_sql({**pending_web.DEFAULT_SEED, "state": "x'; DROP TABLE public.user; --"})

    def test_real_client_and_credential_shaped_values_are_rejected(self):
        for field, value in (
            ("client_id", "production-oauth-client-id"),
            ("cookie_hash", "A" * 43),
            ("state", "B" * 43),
            ("verifier", "D" * 43),
            ("code_hash", "E" * 43),
            ("session_id", "s6-session-real-looking-value"),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                pending_web.build_pending_web_sql({**pending_web.DEFAULT_SEED, field: value})

    def test_exact_pending_source_binding_and_absence_assertions(self):
        sql = pending_web.build_pending_web_sql(pending_web.DEFAULT_SEED)
        for fragment in (
            'a."consumerV3Requested" IS TRUE',
            'c."userId"=\'s6-user\'', 'c."sourceSessionId"=\'s6-session-fixture\'',
            'a."clientId"', 'a."redirectUri"', 'a.state', 'a."cookieHash"',
            'c."codeHash"', 'c."codeChallenge"', 'a."expiresAt"', 'c."expiresAt"',
            'a.id,c.id',
            'SET CONSTRAINTS approval_intent_complete_v2 IMMEDIATE',
            'consumer_approval_consumed_proof', 'remote_service_authorization',
            'remote_web_session', 'consumer_derivative_consent',
            '"consumedAt" IS NULL',
            "request_exp := (stamp + interval '5 minutes')",
            "code_exp := (stamp + interval '30 seconds')",
            "SET LOCAL ROLE e2_owner;",
            "SET LOCAL ROLE lomi_runtime;",
            "SET CONSTRAINTS approval_intent_complete_v2 IMMEDIATE",
            "COMMIT;",
        ):
            self.assertIn(fragment, sql)
        self.assertLess(sql.index("SET LOCAL ROLE e2_owner;"), sql.index("SET LOCAL ROLE lomi_runtime;"))
        self.assertLess(sql.index("SET LOCAL ROLE lomi_runtime;"), sql.index("INSERT INTO public.consumer_approval_intent"))
        self.assertLess(sql.index("SET LOCAL ROLE lomi_runtime;"), sql.index("SET CONSTRAINTS approval_intent_complete_v2 IMMEDIATE"))
        self.assertNotIn("consumer_authorization", sql)
        self.assertIn("code_exp := (stamp + interval '30 seconds')", sql)
        self.assertIn("request_exp := (stamp + interval '5 minutes')", sql)
        self.assertRegex(sql, re.compile(r"INSERT INTO public\.remote_login_attempt[\s\S]+?true\);"))

    def test_negative_source_binding_changes_client_snapshot(self):
        sql = pending_web.build_pending_web_sql(pending_web.DEFAULT_SEED, mismatch=True)
        self.assertIn("'s6-mismatched-client'", sql)
        self.assertIn("EXCEPTION WHEN SQLSTATE '23514' THEN", sql)
        self.assertIn("IF NOT rejected THEN RAISE EXCEPTION 'S6 mismatched binding was accepted'; END IF;", sql)
        self.assertIn("SET LOCAL ROLE lomi_runtime;", sql)
        self.assertIn("SET LOCAL ROLE e2_owner;", sql)
        self.assertIn("S6 mismatch rollback assertion failed", sql)
        self.assertIn("ROLLBACK;", sql)
        self.assertNotIn("SET CONSTRAINTS approval_intent_complete_v2 IMMEDIATE", sql)
        self.assertNotIn("consumer_authorization", sql)
        self.assertNotIn("INSERT INTO public.remote_service_authorization", sql)
        self.assertNotIn("INSERT INTO public.remote_web_session", sql)
        self.assertNotIn("INSERT INTO public.consumer_derivative_consent", sql)

    def test_partial_source_consumption_is_rejected_and_rolled_back(self):
        sql = pending_web.build_pending_web_sql(
            pending_web.DEFAULT_SEED, consume_sources_without_proof=True,
        )
        for fragment in (
            'UPDATE public.remote_login_attempt SET "consumedAt"=consumed_at',
            'UPDATE public.remote_identity_code SET "consumedAt"=consumed_at',
            'SET CONSTRAINTS approval_web_attempt_complete_v2 IMMEDIATE',
            "EXCEPTION WHEN SQLSTATE '23514' THEN",
            "web approval/code consumption mismatch",
            '"consumedAt" IS NULL',
            "consumer_approval_consumed_proof",
            "remote_service_authorization",
            "remote_web_session",
            "consumer_derivative_consent",
            "S6 partial-consumption rollback assertion failed",
            "ROLLBACK;",
        ):
            self.assertIn(fragment, sql)
        runtime_role = sql.index("SET LOCAL ROLE lomi_runtime;")
        partial_block = sql.index("DO $s6_partial$")
        attempt_update = sql.index('UPDATE public.remote_login_attempt SET "consumedAt"=consumed_at')
        code_update = sql.index('UPDATE public.remote_identity_code SET "consumedAt"=consumed_at')
        constraint_flush = sql.index("SET CONSTRAINTS approval_web_attempt_complete_v2 IMMEDIATE")
        expected_diagnostic = sql.index("web approval/code consumption mismatch")
        rollback = sql.rindex("ROLLBACK;")
        self.assertLess(runtime_role, partial_block)
        self.assertLess(partial_block, attempt_update)
        self.assertLess(attempt_update, code_update)
        self.assertLess(code_update, constraint_flush)
        self.assertLess(constraint_flush, expected_diagnostic)
        self.assertLess(expected_diagnostic, rollback)
        self.assertNotIn("UPDATE public.consumer_approval_intent", sql)
        self.assertNotIn("INSERT INTO public.consumer_approval_consumed_proof", sql)
        with self.assertRaises(ValueError):
            pending_web.build_pending_web_sql(
                pending_web.DEFAULT_SEED,
                mismatch=True,
                consume_sources_without_proof=True,
            )
        with self.assertRaises(ValueError):
            pending_web.build_pending_web_sql(
                pending_web.DEFAULT_SEED,
                consume_sources_without_proof=1,
            )

    def test_legacy_request_cannot_be_upgraded_or_reminted(self):
        sql = pending_web.build_pending_web_sql(
            pending_web.DEFAULT_SEED, legacy_upgrade=True,
        )
        for fragment in (
            '"consumerV3Requested" IS FALSE',
            'SET "consumerV3Requested"=true',
            "fresh request intent cannot be upgraded in place",
            "exact real Remote web source and PKCE required",
            "S6 legacy request upgrade was accepted",
            "S6 legacy request remint was accepted",
            '"consumerV3Requested" IS FALSE)',
            "S6 legacy upgrade/remint assertion failed",
            "consumer_approval_consumed_proof",
            "remote_service_authorization",
            "remote_web_session",
            "consumer_derivative_consent",
            "ROLLBACK;",
        ):
            self.assertIn(fragment, sql)
        self.assertRegex(sql, re.compile(
            r'INSERT INTO public\.remote_login_attempt[\s\S]+?NULL,false\);'
        ))
        self.assertIn("EXCEPTION WHEN SQLSTATE '23514' THEN", sql)
        intent_block = sql.split("DO $s6_intent$", 1)[1].split("END $s6_intent$;", 1)[0]
        self.assertEqual(intent_block.count("DECLARE"), 1)
        self.assertIn("diagnostic text;", intent_block)
        self.assertIn("BEGIN\n  BEGIN\n    UPDATE public.remote_login_attempt", intent_block)
        self.assertEqual(intent_block.count("EXCEPTION WHEN SQLSTATE '23514' THEN"), 2)
        self.assertEqual(intent_block.count("GET STACKED DIAGNOSTICS diagnostic = MESSAGE_TEXT;"), 2)
        self.assertLess(
            sql.index("SET LOCAL ROLE lomi_runtime;"),
            sql.index('UPDATE public.remote_login_attempt SET "consumerV3Requested"=true'),
        )
        self.assertLess(
            sql.index('UPDATE public.remote_login_attempt SET "consumerV3Requested"=true'),
            sql.index("exact real Remote web source and PKCE required"),
        )
        self.assertNotIn("COMMIT;", sql)
        for invalid in (
            {"mismatch": True},
            {"consume_sources_without_proof": True},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                pending_web.build_pending_web_sql(
                    pending_web.DEFAULT_SEED, legacy_upgrade=True, **invalid,
                )

    def test_pending_approval_snapshot_fields_are_immutable(self):
        sql = pending_web.build_pending_web_sql(
            pending_web.DEFAULT_SEED, immutable_snapshots=True,
        )
        expected_updates = {
            'id=gen_random_uuid()',
            '"accountId"=\'00000000-0000-4000-8000-000000000001\'::uuid',
            '"userId"=\'s6-other-user\'',
            '"accountSessionId"=\'s6-other-session\'',
            '"actualKind"=\'mobile\'',
            '"actualId"=\'s6-other-actual\'',
            '"webActualId"=\'s6-other-web\'',
            '"mobileActualId"=\'s6-other-mobile\'',
            '"serviceAuthorizationId"=\'s6-other-service\'',
            '"clientId"=\'s6-other-client\'',
            '"approvalOrigin"=\'https://other.s6.invalid\'',
            '"targetOrigin"=\'https://other.s6.invalid\'',
            '"redirectUri"=\'https://other.s6.invalid/auth/callback\'',
            "state='T'",
            "scope='remote:account:read'",
            '"serviceVersion"="serviceVersion"+1',
            '"consentVersion"="consentVersion"+1',
            '"authorizationEpoch"="authorizationEpoch"+1',
            '"webAttemptId"=\'s6-other-attempt\'',
            '"webCodeId"=\'s6-other-code\'',
            '"mobileLoginId"=\'s6-other-mobile-login\'',
            '"cookieHash"=repeat(\'D\',43)',
            '"codeHash"=repeat(\'E\',43)',
            '"codeChallenge"=repeat(\'F\',43)',
            '"requestExpiresAt"="requestExpiresAt"+interval \'1 second\'',
            '"codeExpiresAt"="codeExpiresAt"+interval \'1 second\'',
            '"approvedAt"="approvedAt"+interval \'1 second\'',
            '"approvalXid"="approvalXid"+1',
            '"parentDeadline"="parentDeadline"+interval \'1 second\'',
            '"serviceDeadline"="serviceDeadline"+interval \'1 second\'',
            '"actualDeadline"="actualDeadline"+interval \'1 second\'',
            '"actualIdleDeadline"="actualIdleDeadline"+interval \'1 second\'',
            '"expiresAt"="expiresAt"+interval \'1 second\'',
        }
        immutable_block = sql.split("DO $s6_immutable$", 1)[1].split(
            "END $s6_immutable$;", 1,
        )[0]
        updates = re.findall(
            r"^\s*UPDATE public\.consumer_approval_intent SET (.+)$",
            immutable_block, re.MULTILINE,
        )
        self.assertEqual(len(updates), 33)
        self.assertEqual(set(updates), expected_updates)
        self.assertEqual(immutable_block.count("EXCEPTION WHEN SQLSTATE '23514' THEN"), 33)
        self.assertEqual(
            immutable_block.count("immutable approval or terminal consumption"), 33,
        )
        self.assertEqual(
            immutable_block.count("GET STACKED DIAGNOSTICS diagnostic = MESSAGE_TEXT;"),
            33,
        )
        for fragment in (
            "SET CONSTRAINTS approval_intent_complete_v2 IMMEDIATE",
            "(to_jsonb(current_row)-ARRAY['consumedAt','consumedXid']) IS DISTINCT FROM",
            "current_row.\"consumedAt\" IS NOT NULL",
            "S6 immutable snapshot rollback assertion failed",
            "consumer_approval_consumed_proof",
            "remote_service_authorization",
            "remote_web_session",
            "consumer_derivative_consent",
            "ROLLBACK;",
        ):
            self.assertIn(fragment, sql)
        self.assertNotIn("COMMIT;", sql)
        self.assertLess(sql.index("SET LOCAL ROLE lomi_runtime;"), sql.index("INSERT INTO public.consumer_approval_intent"))
        self.assertLess(sql.index("SET LOCAL ROLE e2_owner;\nSET CONSTRAINTS approval_intent_complete_v2 IMMEDIATE"), sql.index("DO $s6_immutable$"))
        self.assertLess(sql.index("DO $s6_immutable$"), sql.index("UPDATE public.consumer_approval_intent SET id="))
        for invalid in (
            {"mismatch": True},
            {"consume_sources_without_proof": True},
            {"legacy_upgrade": True},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                pending_web.build_pending_web_sql(
                    pending_web.DEFAULT_SEED, immutable_snapshots=True, **invalid,
                )
        with self.assertRaises(ValueError):
            pending_web.build_pending_web_sql(
                pending_web.DEFAULT_SEED, immutable_snapshots=1,
            )

    def test_candidate_source_is_pinned(self):
        self.assertEqual(pending_web.CANDIDATE_SHA256, pending_web.candidate_source_hash())


if __name__ == "__main__":
    unittest.main()
