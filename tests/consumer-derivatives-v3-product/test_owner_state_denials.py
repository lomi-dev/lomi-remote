"""Pure source and mutation tests for owner_state_denials; no SQL is run."""
from pathlib import Path
import hashlib
import json
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import owner_state_denials


RUN_UUID = "7e1c2b9f-9b28-4b52-a345-12dfcb08a012"
FROZEN = HERE.parents[1] / "staging/consumer-derivatives-v3-product-successor/inputs/frozen-v3-successor"
PACKAGE = HERE.parents[1] / "staging/consumer-derivatives-v3-product-successor"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fill_json_block(raw, marker, fill):
    tag = marker.encode("ascii")
    if raw.count(tag) != 2:
        raise AssertionError("source test fixture delimiter drift")
    start = raw.index(tag) + len(tag)
    end = raw.index(tag, start)
    value = json.loads(raw[start:end])
    fill(value)
    replacement = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return raw[:start] + replacement + raw[end:]


def measured_sources():
    helper = (PACKAGE / "operator-seal-auth-helpers.candidate.sql").read_bytes()
    helper = fill_json_block(helper, "$helper_pins$", lambda rows: [
        row.update({
            "old_catalog_sha256": "1" * 64,
            "new_catalog_sha256": "2" * 64,
            "old_acl": [],
            "new_acl": [],
        }) for row in rows
    ])
    roots = (FROZEN / "operator-three-roots.candidate.sql").read_bytes()
    roots = fill_json_block(roots, "$pins$", lambda rows: [
        row.update({
            "old_catalog_sha256": "3" * 64,
            "new_catalog_sha256": "4" * 64,
            "old_acl": [],
            "new_acl": [],
        }) for row in rows
    ])
    roots = fill_json_block(roots, "$deps$", lambda rows: [
        row.update({"catalog_sha256": "5" * 64, "acl": []}) for row in rows
    ])
    return {"helperSeal": helper, "threeRoots": roots}


def setup_plan():
    sources = measured_sources()
    source_hashes = {name: digest(raw) for name, raw in sources.items()}
    controls = {
        name: {
            "operatorSha256": source_hashes[name],
            "allOldTransition": 0,
            "allNewIdempotent": 0,
        }
        for name in owner_state_denials.OPERATORS
    }
    attempts = owner_state_denials.build_attempts(
        RUN_UUID, operator_sources=sources,
        expected_operator_sha256=source_hashes,
        positive_controls=controls,
    )
    return sources, source_hashes, controls, attempts


def selected_controls(controls, operator_ids):
    return {operator_id: controls[operator_id] for operator_id in operator_ids}


def transcript(attempt, *, sqlstate=None, reason_code=None, run_uuid=None,
               attempt_id=None, operator=None, source_sha256=None, case=None,
               session_user="e2_owner", current_user="e2_owner",
               is_superuser="true", include_ack=True):
    sqlstate = attempt["expectedSqlstate"] if sqlstate is None else sqlstate
    reason_code = attempt["expectedReasonCode"] if reason_code is None else reason_code
    run_uuid = attempt["runUuid"] if run_uuid is None else run_uuid
    attempt_id = attempt["attemptId"] if attempt_id is None else attempt_id
    operator = attempt["operator"] if operator is None else operator
    source_sha256 = attempt["operatorSha256"] if source_sha256 is None else source_sha256
    case = attempt["case"] if case is None else case
    result = (
        "NOTICE: OWNER_STATE_DENIAL_RESULT"
        f"|run={run_uuid}|attempt={attempt_id}|operator={operator}"
        f"|source_sha256={source_sha256}|case={case}"
        f"|session_user={session_user}|current_user={current_user}"
        f"|is_superuser={is_superuser}|sqlstate={sqlstate}|reason={reason_code}\n"
    )
    if include_ack:
        result += (
            "OWNER_STATE_DENIAL_ROLLBACK_ACK"
            f"|run={run_uuid}|attempt={attempt_id}|operator={operator}"
            f"|source_sha256={source_sha256}|case={case}\n"
        )
    return result.encode("ascii")


def outcome(attempt, *, output=None, before=b'{"kind":"roles-and-catalog"}\n',
            after=None, return_code=0):
    return {
        "attemptId": attempt["attemptId"],
        "processReturnCode": return_code,
        "output": transcript(attempt) if output is None else output,
        "beforeCapture": before,
        "afterCapture": before if after is None else after,
    }


def validate(attempt, sources, source_hashes, controls,
             operator_ids=owner_state_denials.OPERATORS, **kwargs):
    defaults = {
        "process_return_code": 0,
        "output": transcript(attempt),
        "before_capture": b'{"kind":"roles-and-catalog"}\n',
        "after_capture": b'{"kind":"roles-and-catalog"}\n',
    }
    defaults.update(kwargs)
    return owner_state_denials.validate_attempt_result(
        attempt, operator_sources=sources,
        expected_operator_sha256=source_hashes,
        positive_controls=controls, operator_ids=operator_ids, **defaults,
    )


class OwnerStateDenialPlanTests(unittest.TestCase):
    def setUp(self):
        self.sources, self.source_hashes, self.controls, self.attempts = setup_plan()

    def test_builds_two_source_bound_operators_across_the_fixed_owner_matrix(self):
        self.assertEqual(len(self.attempts), 2 * len(owner_state_denials.CASES))
        self.assertEqual(len({item["attemptId"] for item in self.attempts}), 28)
        self.assertEqual({item["operator"] for item in self.attempts},
                         set(owner_state_denials.OPERATORS))
        self.assertEqual({item["case"] for item in self.attempts},
                         set(owner_state_denials.CASES))
        for attempt in self.attempts:
            with self.subTest(operator=attempt["operator"], case=attempt["case"]):
                self.assertEqual(attempt["operatorSha256"], self.source_hashes[attempt["operator"]])
                self.assertEqual(attempt["expectedSqlstate"], "P0001")
                self.assertIn(attempt["expectedRejectionReason"], attempt["sql"])
                self.assertIn(owner_state_denials._sql_literal(attempt["mutation"]), attempt["sql"])
                self.assertIn("EXECUTE '", attempt["sql"])
                self.assertEqual(attempt["sql"].count("ROLLBACK;"), 1)
                self.assertNotIn("COMMIT;", attempt["sql"])
                self.assertIn("GET STACKED DIAGNOSTICS", attempt["sql"])
                self.assertIn("reason_code := 'unexpected_rejection'", attempt["sql"])
                self.assertIn("OWNER_STATE_DENIAL_RESULT", attempt["sql"])
                self.assertIn("OWNER_STATE_DENIAL_ROLLBACK_ACK", attempt["sql"])
                self.assertEqual(attempt["case"], owner_state_denials.CASES[
                    int(attempt["attemptId"].rsplit(":", 1)[1]) % len(owner_state_denials.CASES)
                ])

    def test_matrix_covers_exact_role_attributes_config_schema_and_membership_directions(self):
        mutations = {
            attempt["case"]: attempt["mutation"] for attempt in self.attempts[:14]
        }
        self.assertIn("RENAME TO lomi_owner_state_missing_000_", mutations["missing_owner_name"])
        self.assertIn(" LOGIN;", mutations["login"])
        self.assertIn(" INHERIT;", mutations["inherit"])
        self.assertIn(" SUPERUSER;", mutations["superuser"])
        self.assertIn(" CREATEDB;", mutations["createdb"])
        self.assertIn(" CREATEROLE;", mutations["createrole"])
        self.assertIn(" REPLICATION;", mutations["replication"])
        self.assertIn(" BYPASSRLS;", mutations["bypassrls"])
        self.assertIn("SET statement_timeout", mutations["role_config"])
        self.assertIn("GRANT CREATE ON SCHEMA public", mutations["public_schema_create"])
        self.assertEqual(mutations["owner_granted_to_operator"],
                         "GRANT lomi_consumer_auth_body_owner TO e2_owner;")
        self.assertEqual(mutations["operator_granted_to_owner"],
                         "GRANT e2_owner TO lomi_consumer_auth_body_owner;")
        self.assertIn("WITH ADMIN OPTION", mutations["owner_granted_to_operator_admin"])
        self.assertIn("WITH ADMIN OPTION", mutations["operator_granted_to_owner_admin"])
        self.assertEqual(
            {attempt["expectedRejectionReason"] for attempt in self.attempts[:14]},
            {
                "unexpected helper definition/owner/ACL: " + owner_state_denials._FIRST_HELPER_SIGNATURE,
                "body owner must be unreachable and retain no broad capability",
            },
        )
        self.assertEqual(
            {attempt["expectedRejectionReason"] for attempt in self.attempts[14:]},
            {
                "missing execution owner",
                "execution owner retains excessive authority: lomi_consumer_auth_body_owner",
            },
        )

    def test_requires_measured_pins_positive_controls_and_supported_operator_ids(self):
        null_source = (PACKAGE / "operator-seal-auth-helpers.candidate.sql").read_bytes()
        sources = dict(self.sources)
        sources["helperSeal"] = null_source
        hashes = dict(self.source_hashes)
        hashes["helperSeal"] = digest(null_source)
        controls = dict(self.controls)
        controls["helperSeal"] = dict(controls["helperSeal"], operatorSha256=hashes["helperSeal"])
        with self.assertRaisesRegex(owner_state_denials.Rejected, "not measured"):
            owner_state_denials.build_attempts(
                RUN_UUID, operator_sources=sources,
                expected_operator_sha256=hashes, positive_controls=controls,
            )

        bad_controls = dict(self.controls)
        bad_controls["threeRoots"] = dict(bad_controls["threeRoots"], allNewIdempotent=1)
        with self.assertRaisesRegex(owner_state_denials.Rejected, "positive operator control"):
            owner_state_denials.build_attempts(
                RUN_UUID, operator_sources=self.sources,
                expected_operator_sha256=self.source_hashes, positive_controls=bad_controls,
            )

        unsupported = dict(self.sources)
        unsupported["channelRoots"] = unsupported["threeRoots"]
        with self.assertRaisesRegex(owner_state_denials.Rejected, "supported operator source IDs"):
            owner_state_denials.build_attempts(
                RUN_UUID, operator_sources=unsupported,
                expected_operator_sha256=self.source_hashes, positive_controls=self.controls,
            )

    def test_rejects_source_digest_drift_and_operator_wrapper_mutation(self):
        bad_hashes = dict(self.source_hashes)
        bad_hashes["helperSeal"] = "0" * 64
        with self.assertRaisesRegex(owner_state_denials.Rejected, "source digest mismatch"):
            owner_state_denials.build_attempts(
                RUN_UUID, operator_sources=self.sources,
                expected_operator_sha256=bad_hashes, positive_controls=self.controls,
            )

        changed = dict(self.sources)
        changed["threeRoots"] = changed["threeRoots"].replace(b"COMMIT;", b"COMMIT;\nSELECT 1;", 1)
        changed_hashes = {name: digest(raw) for name, raw in changed.items()}
        controls = {
            name: dict(self.controls[name], operatorSha256=changed_hashes[name])
            for name in owner_state_denials.OPERATORS
        }
        with self.assertRaisesRegex(owner_state_denials.Rejected, "wrapper shape drift"):
            owner_state_denials.build_attempts(
                RUN_UUID, operator_sources=changed,
                expected_operator_sha256=changed_hashes, positive_controls=controls,
            )

    def test_operator_subsets_keep_global_ids_and_validate_both_source_digests(self):
        helper_ids = ("helperSeal",)
        root_ids = ("threeRoots",)
        helper_attempts = owner_state_denials.build_attempts(
            RUN_UUID, operator_sources=self.sources,
            expected_operator_sha256=self.source_hashes,
            positive_controls=selected_controls(self.controls, helper_ids),
            operator_ids=helper_ids,
        )
        root_attempts = owner_state_denials.build_attempts(
            RUN_UUID, operator_sources=self.sources,
            expected_operator_sha256=self.source_hashes,
            positive_controls=selected_controls(self.controls, root_ids),
            operator_ids=root_ids,
        )
        self.assertEqual(len(helper_attempts), 14)
        self.assertEqual([item["attemptId"] for item in helper_attempts],
                         [f"{RUN_UUID}:{index:03d}" for index in range(14)])
        self.assertEqual(len(root_attempts), 14)
        self.assertEqual([item["attemptId"] for item in root_attempts],
                         [f"{RUN_UUID}:{index:03d}" for index in range(14, 28)])

        with self.assertRaisesRegex(owner_state_denials.Rejected, "exact supported operator source IDs"):
            owner_state_denials.build_attempts(
                RUN_UUID, operator_sources={"helperSeal": self.sources["helperSeal"]},
                expected_operator_sha256=self.source_hashes,
                positive_controls=selected_controls(self.controls, helper_ids),
                operator_ids=helper_ids,
            )
        wrong_unselected_digest = dict(self.source_hashes, threeRoots="0" * 64)
        with self.assertRaisesRegex(owner_state_denials.Rejected, "source digest mismatch"):
            owner_state_denials.build_attempts(
                RUN_UUID, operator_sources=self.sources,
                expected_operator_sha256=wrong_unselected_digest,
                positive_controls=selected_controls(self.controls, helper_ids),
                operator_ids=helper_ids,
            )
        with self.assertRaisesRegex(owner_state_denials.Rejected, "canonical nonempty operator tuple"):
            owner_state_denials.build_attempts(
                RUN_UUID, operator_sources=self.sources,
                expected_operator_sha256=self.source_hashes,
                positive_controls=selected_controls(self.controls, helper_ids),
                operator_ids=["helperSeal"],
            )
        for invalid in ((), ("threeRoots", "helperSeal"), ("helperSeal", "helperSeal"),
                        ("channelRoots",)):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                    owner_state_denials.Rejected, "canonical nonempty operator tuple"):
                owner_state_denials.build_attempts(
                    RUN_UUID, operator_sources=self.sources,
                    expected_operator_sha256=self.source_hashes,
                    positive_controls=selected_controls(self.controls, helper_ids),
                    operator_ids=invalid,
                )

        missing_future_control = selected_controls(self.controls, helper_ids)
        missing_future_control.pop("helperSeal")
        with self.assertRaisesRegex(owner_state_denials.Rejected, "positive controls"):
            owner_state_denials.build_attempts(
                RUN_UUID, operator_sources=self.sources,
                expected_operator_sha256=self.source_hashes,
                positive_controls=missing_future_control, operator_ids=helper_ids,
            )
        with self.assertRaisesRegex(owner_state_denials.Rejected, "positive controls"):
            owner_state_denials.build_attempts(
                RUN_UUID, operator_sources=self.sources,
                expected_operator_sha256=self.source_hashes,
                positive_controls=self.controls, operator_ids=helper_ids,
            )
        wrong_selected_control = selected_controls(self.controls, helper_ids)
        wrong_selected_control["helperSeal"] = dict(
            wrong_selected_control["helperSeal"], operatorSha256="0" * 64,
        )
        with self.assertRaisesRegex(owner_state_denials.Rejected, "source-mismatched"):
            owner_state_denials.build_attempts(
                RUN_UUID, operator_sources=self.sources,
                expected_operator_sha256=self.source_hashes,
                positive_controls=wrong_selected_control, operator_ids=helper_ids,
            )

    def test_rename_case_records_the_actual_reachable_source_guard(self):
        helper = self.attempts[0]
        roots = self.attempts[14]
        self.assertEqual(helper["case"], "missing_owner_name")
        self.assertEqual(roots["case"], "missing_owner_name")
        self.assertEqual(helper["expectedReasonCode"], "helper_owner_name_mismatch")
        self.assertEqual(roots["expectedReasonCode"], "three_roots_missing_execution_owner")
        self.assertIn("unexpected helper definition/owner/ACL", helper["expectedRejectionReason"])
        self.assertEqual(roots["expectedRejectionReason"], "missing execution owner")


class OwnerStateDenialEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.sources, self.source_hashes, self.controls, self.attempts = setup_plan()
        self.attempt = self.attempts[0]
        self.capture = b'{"kind":"full-catalog-and-role-state","rows":[]}\n'

    def test_accepts_bound_known_rejection_and_exact_post_rollback_capture(self):
        result = validate(
            self.attempt, self.sources, self.source_hashes, self.controls,
            before_capture=self.capture, after_capture=self.capture,
        )
        self.assertEqual(result["sqlstate"], "P0001")
        self.assertEqual(result["reasonCode"], self.attempt["expectedReasonCode"])
        self.assertTrue(result["catalogAndRolesUnchanged"])
        self.assertTrue(result["rollbackAcknowledged"])
        self.assertEqual(result["beforeCaptureSha256"], digest(self.capture))

    def test_rejects_other_run_attempt_operator_source_case_and_reason(self):
        good = transcript(self.attempt)
        output_mutations = (
            transcript(self.attempt, run_uuid="5cfe1ed0-744f-4fe5-a514-5b47cd7e7311"),
            transcript(self.attempt, attempt_id=f"{RUN_UUID}:027"),
            transcript(self.attempt, operator="threeRoots"),
            transcript(self.attempt, source_sha256="0" * 64),
            transcript(self.attempt, case="role_config"),
            transcript(self.attempt, reason_code="unexpected_rejection"),
            transcript(self.attempt, sqlstate="42601"),
            transcript(self.attempt, session_user="postgres"),
            transcript(self.attempt, current_user="lomi_migrator"),
            transcript(self.attempt, is_superuser="false"),
            good + b"ERROR: private database error text\n",
        )
        for altered in output_mutations:
            with self.subTest(output=altered[-90:]), self.assertRaises(owner_state_denials.Rejected):
                validate(self.attempt, self.sources, self.source_hashes, self.controls,
                         output=altered)

    def test_rejects_missing_ack_process_failure_and_replayed_transcript(self):
        second = self.attempts[1]
        with self.assertRaisesRegex(owner_state_denials.Rejected, "acknowledgement"):
            validate(self.attempt, self.sources, self.source_hashes, self.controls,
                     output=transcript(self.attempt, include_ack=False))
        with self.assertRaisesRegex(owner_state_denials.Rejected, "process did not succeed"):
            validate(self.attempt, self.sources, self.source_hashes, self.controls,
                     process_return_code=1)
        with self.assertRaisesRegex(owner_state_denials.Rejected, "another run, attempt"):
            validate(second, self.sources, self.source_hashes, self.controls,
                     output=transcript(self.attempt))

    def test_rejects_forged_plan_mismatched_digest_and_capture_drift(self):
        forged = dict(self.attempt, expectedRejectionReason="anything")
        with self.assertRaisesRegex(owner_state_denials.Rejected, "fixed owner-state plan"):
            validate(forged, self.sources, self.source_hashes, self.controls)

        wrong_digest = dict(self.source_hashes, helperSeal="0" * 64)
        with self.assertRaisesRegex(owner_state_denials.Rejected, "source digest mismatch"):
            validate(self.attempt, self.sources, wrong_digest, self.controls)

        with self.assertRaisesRegex(owner_state_denials.Rejected, "capture changed"):
            validate(self.attempt, self.sources, self.source_hashes, self.controls,
                     after_capture=self.capture + b'{"kind":"role","name":"drift"}\n')

    def test_complete_matrix_rejects_duplicate_replayed_and_incomplete_outcomes(self):
        outcomes = [outcome(attempt, before=self.capture) for attempt in self.attempts]
        report = owner_state_denials.validate_complete_matrix(
            RUN_UUID, outcomes, operator_sources=self.sources,
            expected_operator_sha256=self.source_hashes,
            positive_controls=self.controls,
        )
        self.assertEqual(report["attemptCount"], 28)
        self.assertEqual(report["deniedCount"], 28)
        self.assertEqual(report["cases"], list(owner_state_denials.CASES))
        self.assertTrue(report["entireCatalogAndRoleCaptureEqualAfterEveryRollback"])
        self.assertTrue(report["fullOwnerStateDenialMatrixValidated"])
        self.assertFalse(report["fullS5Qualified"])

        duplicate = list(outcomes)
        duplicate[-1] = dict(duplicate[0])
        with self.assertRaisesRegex(owner_state_denials.Rejected, "duplicate attempt"):
            owner_state_denials.validate_complete_matrix(
                RUN_UUID, duplicate, operator_sources=self.sources,
                expected_operator_sha256=self.source_hashes,
                positive_controls=self.controls,
            )
        with self.assertRaisesRegex(owner_state_denials.Rejected, "complete owner-state"):
            owner_state_denials.validate_complete_matrix(
                RUN_UUID, outcomes[:-1], operator_sources=self.sources,
                expected_operator_sha256=self.source_hashes,
                positive_controls=self.controls,
            )

    def test_phase_subsets_merge_to_28_and_reject_duplicate_or_cross_operator_evidence(self):
        helper_ids = ("helperSeal",)
        root_ids = ("threeRoots",)
        helper_controls = selected_controls(self.controls, helper_ids)
        root_controls = selected_controls(self.controls, root_ids)
        helper_attempts = owner_state_denials.build_attempts(
            RUN_UUID, operator_sources=self.sources,
            expected_operator_sha256=self.source_hashes,
            positive_controls=helper_controls, operator_ids=helper_ids,
        )
        root_attempts = owner_state_denials.build_attempts(
            RUN_UUID, operator_sources=self.sources,
            expected_operator_sha256=self.source_hashes,
            positive_controls=root_controls, operator_ids=root_ids,
        )
        helper_outcomes = [outcome(attempt, before=self.capture) for attempt in helper_attempts]
        root_outcomes = [outcome(attempt, before=self.capture + b"phase=three-roots\n")
                         for attempt in root_attempts]

        helper_report = owner_state_denials.validate_complete_matrix(
            RUN_UUID, helper_outcomes, operator_sources=self.sources,
            expected_operator_sha256=self.source_hashes,
            positive_controls=helper_controls, operator_ids=helper_ids,
        )
        self.assertEqual(helper_report["attemptCount"], 14)
        self.assertEqual(helper_report["operatorIds"], ["helperSeal"])
        self.assertEqual(helper_report["casesByOperator"], {"helperSeal": list(owner_state_denials.CASES)})
        self.assertEqual(helper_report["matrixScope"], "OPERATOR_SUBSET")
        self.assertFalse(helper_report["fullOwnerStateDenialMatrixValidated"])
        self.assertFalse(helper_report["fullS5Qualified"])
        self.assertEqual({row["operator"] for row in helper_report["results"]}, {"helperSeal"})

        root_report = owner_state_denials.validate_complete_matrix(
            RUN_UUID, root_outcomes, operator_sources=self.sources,
            expected_operator_sha256=self.source_hashes,
            positive_controls=root_controls, operator_ids=root_ids,
        )
        self.assertEqual(root_report["attemptCount"], 14)
        self.assertEqual(root_report["operatorIds"], ["threeRoots"])
        self.assertEqual(root_report["casesByOperator"], {"threeRoots": list(owner_state_denials.CASES)})
        self.assertFalse(root_report["fullOwnerStateDenialMatrixValidated"])

        merged = helper_outcomes + root_outcomes
        merged_report = owner_state_denials.validate_complete_matrix(
            RUN_UUID, merged, operator_sources=self.sources,
            expected_operator_sha256=self.source_hashes,
            positive_controls=self.controls,
        )
        self.assertEqual(merged_report["attemptCount"], 28)
        self.assertEqual(merged_report["operatorIds"], list(owner_state_denials.OPERATORS))
        self.assertTrue(merged_report["fullOwnerStateDenialMatrixValidated"])

        duplicate = list(merged)
        duplicate[-1] = dict(duplicate[0])
        with self.assertRaisesRegex(owner_state_denials.Rejected, "duplicate attempt"):
            owner_state_denials.validate_complete_matrix(
                RUN_UUID, duplicate, operator_sources=self.sources,
                expected_operator_sha256=self.source_hashes,
                positive_controls=self.controls,
            )

        cross_phase = list(merged)
        cross_phase[14] = dict(cross_phase[14], output=transcript(helper_attempts[0]))
        with self.assertRaisesRegex(owner_state_denials.Rejected, "another run, attempt, operator, or source"):
            owner_state_denials.validate_complete_matrix(
                RUN_UUID, cross_phase, operator_sources=self.sources,
                expected_operator_sha256=self.source_hashes,
                positive_controls=self.controls,
            )

        replayed = list(merged)
        replayed[1] = dict(replayed[1], output=transcript(helper_attempts[0]))
        with self.assertRaisesRegex(owner_state_denials.Rejected, "another run, attempt, operator, or source"):
            owner_state_denials.validate_complete_matrix(
                RUN_UUID, replayed, operator_sources=self.sources,
                expected_operator_sha256=self.source_hashes,
                positive_controls=self.controls,
            )


if __name__ == "__main__":
    unittest.main()
