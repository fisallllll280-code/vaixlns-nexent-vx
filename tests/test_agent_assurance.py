"""Security invariants for the VX agent-action assurance gate (stdlib only)."""
import random
import unittest

from vaixlns.vx.agent_assurance import (
    STATES, AssuranceSession, EvidenceReceipt, EvidenceSigner, EvidenceVerifier,
    IdempotencyRegistry, InvalidTransition, PermitAuthority, PermitVerifier,
    TaskContract, digest,
)

NOW = 1_000
PERMIT_KEY = b"test-permit-signing-key-32-bytes-long!!"
PLAN_KEY = b"independent-plan-verifier-key-32-bytes!!"
AUDIT_KEY = b"target-side-audit-signing-key-32-bytes!!"
READBACK_KEY = b"independent-readback-key-32-bytes-long!!"
TRIPWIRE_KEY = b"independent-tripwire-key-32-bytes-long!!"


class AssuranceFixture(unittest.TestCase):
    def setUp(self):
        self.contract = TaskContract(
            contract_id="CONTRACT-001",
            operation_id="OPERATION-001",
            principal_id="agent-build-07",
            resource_id="repo:owner/project",
            expected_resource_version="v7",
            requested_actions=("write", "compensate"),
            allowed_diff_paths=("reports/output.json",),
        )
        self.permit_authority = PermitAuthority("permit-key", PERMIT_KEY)
        self.permit_verifier = PermitVerifier({"permit-key": PERMIT_KEY})
        self.plan_signer = EvidenceSigner("plan-key", "independent-plan-verifier", PLAN_KEY)
        self.audit_signer = EvidenceSigner("audit-key", "target-audit-log", AUDIT_KEY)
        self.readback_signer = EvidenceSigner("readback-key", "readback-monitor", READBACK_KEY)
        self.tripwire_signer = EvidenceSigner("tripwire-key", "tripwire-monitor", TRIPWIRE_KEY)
        self.evidence_verifier = EvidenceVerifier({
            "plan-key": (PLAN_KEY, "independent-plan-verifier"),
            "audit-key": (AUDIT_KEY, "target-audit-log"),
            "readback-key": (READBACK_KEY, "readback-monitor"),
            "tripwire-key": (TRIPWIRE_KEY, "tripwire-monitor"),
        })
        self.registry = IdempotencyRegistry()
        self.session = self.new_session(self.contract)

    def new_session(self, contract):
        return AssuranceSession(
            contract, self.permit_verifier, self.evidence_verifier,
            connector_source_id="agent-connector",
            connector_key_id="agent-connector-key",
            idempotency_registry=self.registry,
        )

    def permit(self, issued=900, expires=1200, actions=None, version=None, permit_id="PERMIT-001"):
        return self.permit_authority.issue(
            self.contract, issued, expires, allowed_actions=actions,
            resource_version=version, permit_id=permit_id,
        )

    def plan_receipt(self, contract=None, timestamp=NOW):
        c = contract or self.contract
        return self.plan_signer.issue("PLAN_VERIFICATION", {
            "contract_id": c.contract_id,
            "operation_id": c.operation_id,
            "resource_id": c.resource_id,
            "verdict": "PASS",
            "plan_hash": "a" * 64,
            "actions": list(c.requested_actions),
        }, timestamp)

    def audit(self, effect_state="COMPLETE", before="v7", after="v8",
              diff_paths=("reports/output.json",), sequence=23, state_hash="b" * 64,
              log_complete=True, source_signer=None, contract=None, timestamp=NOW):
        c = contract or self.contract
        signer = source_signer or self.audit_signer
        return signer.issue("TARGET_AUDIT", {
            "contract_id": c.contract_id,
            "operation_id": c.operation_id,
            "resource_id": c.resource_id,
            "effect_state": effect_state,
            "resource_version_before": before,
            "resource_version_after": after,
            "diff_paths": list(diff_paths),
            "state_hash": state_hash,
            "log_complete": log_complete,
            "sequence": sequence,
        }, timestamp)

    def readback(self, version="v8", state_hash="b" * 64, residual=0,
                 source_signer=None, contract=None, timestamp=NOW):
        c = contract or self.contract
        signer = source_signer or self.readback_signer
        return signer.issue("READBACK", {
            "contract_id": c.contract_id,
            "operation_id": c.operation_id,
            "resource_id": c.resource_id,
            "verdict": "PASS",
            "resource_version": version,
            "observed_state_hash": state_hash,
            "residual_effects": residual,
        }, timestamp)

    def tripwire(self, clean=True, coverage=True, unexpected=(),
                 source_signer=None, contract=None, timestamp=NOW):
        c = contract or self.contract
        signer = source_signer or self.tripwire_signer
        return signer.issue("TRIPWIRE", {
            "contract_id": c.contract_id,
            "operation_id": c.operation_id,
            "resource_id": c.resource_id,
            "clean": clean,
            "coverage_complete": coverage,
            "unexpected_events": list(unexpected),
        }, timestamp)

    def reach_executing(self):
        permit = self.permit()
        self.assertTrue(self.session.authorize(permit, NOW, "v7"))
        self.assertTrue(self.session.verify_plan(self.plan_receipt(), NOW + 1))
        ticket = self.session.begin_execution(permit, NOW + 2, "v7")
        self.assertIsNotNone(ticket)
        return permit, ticket

    def valid_bundle(self, state="COMPLETE", before="v7", after="v8", hash_value="b" * 64):
        return (
            self.audit(effect_state=state, before=before, after=after, state_hash=hash_value),
            self.readback(version=after, state_hash=hash_value, residual=0),
            self.tripwire(),
        )


class AgentAssuranceTests(AssuranceFixture):
    def test_complete_happy_path_is_evidence_gated(self):
        self.reach_executing()
        bundle = self.valid_bundle()
        self.assertTrue(self.session.verify_effect(*bundle, "v8", NOW + 3))
        self.assertEqual(self.session.state, "EFFECT_VERIFIED")
        self.assertTrue(self.session.close_verified(NOW + 4))
        self.assertEqual(self.session.state, "CLOSED_VERIFIED")
        transitions = [item["to_state"] for item in self.session.history]
        self.assertLess(transitions.index("EFFECT_VERIFIED"), transitions.index("CLOSED_VERIFIED"))

    def test_expired_permit_rejected(self):
        self.assertFalse(self.session.authorize(self.permit(issued=900, expires=999), 1000, "v7"))
        self.assertEqual(self.session.state, "EXPIRED")

    def test_scope_escalation_rejected(self):
        narrow = self.permit(actions=("write",), permit_id="NARROW")
        self.assertFalse(self.session.authorize(narrow, NOW, "v7"))
        self.assertEqual(self.session.state, "REJECTED")

    def test_time_of_check_time_of_use_resource_change_rejected(self):
        permit = self.permit()
        self.assertTrue(self.session.authorize(permit, NOW, "v7"))
        self.assertTrue(self.session.verify_plan(self.plan_receipt(), NOW + 1))
        self.assertIsNone(self.session.begin_execution(permit, NOW + 2, "v8"))
        self.assertEqual(self.session.state, "CONFLICT")

    def test_fake_readback_signature_forces_recovery(self):
        self.reach_executing()
        audit, readback, tripwire = self.valid_bundle()
        tampered_payload = dict(readback.payload)
        tampered_payload["observed_state_hash"] = "c" * 64
        fake = EvidenceReceipt(
            kind=readback.kind, source_id=readback.source_id, key_id=readback.key_id,
            timestamp=readback.timestamp, payload=tampered_payload, signature=readback.signature,
        )
        self.assertFalse(self.session.verify_effect(audit, fake, tripwire, "v8", NOW + 3))
        self.assertEqual(self.session.state, "RECOVERY_REQUIRED")
        with self.assertRaises(InvalidTransition):
            self.session.close_verified(NOW + 4)

    def test_tripwire_detection_blocks_verified_close(self):
        self.reach_executing()
        audit, readback, _ = self.valid_bundle()
        dirty_tripwire = self.tripwire(clean=False, unexpected=("protected-path-write",))
        self.assertFalse(self.session.verify_effect(audit, readback, dirty_tripwire, "v8", NOW + 3))
        self.assertEqual(self.session.state, "RECOVERY_REQUIRED")

    def test_partial_effect_requires_compensation_and_failed_close(self):
        permit, _ = self.reach_executing()
        partial = self.audit(effect_state="PARTIAL", before="v7", after="v8", state_hash="d" * 64)
        self.assertTrue(self.session.observe_partial_effect(partial, NOW + 3))
        self.assertEqual(self.session.state, "PARTIAL_EFFECT")
        with self.assertRaises(InvalidTransition):
            self.session.close_verified(NOW + 4)

        compensation = self.permit_authority.issue(
            self.contract, issued_at=NOW + 4, expires_at=NOW + 100,
            allowed_actions=("compensate",), resource_version="v8", permit_id="COMPENSATION-001",
        )
        self.assertTrue(self.session.begin_compensation(compensation, NOW + 5, "v8"))
        self.assertEqual(self.session.state, "COMPENSATING")
        bundle = self.valid_bundle(state="COMPENSATED", before="v8", after="v9", hash_value="e" * 64)
        self.assertTrue(self.session.close_failed(*bundle, "v9", NOW + 6))
        self.assertEqual(self.session.state, "CLOSED_FAILED")

    def test_incomplete_target_log_cannot_prove_success(self):
        self.reach_executing()
        audit, readback, tripwire = self.valid_bundle()
        incomplete = self.audit(log_complete=False)
        self.assertFalse(self.session.verify_effect(incomplete, readback, tripwire, "v8", NOW + 3))
        self.assertEqual(self.session.state, "RECOVERY_REQUIRED")

    def test_evidence_channels_must_be_independent(self):
        self.reach_executing()
        shared_signer = EvidenceSigner("audit-key", "target-audit-log", AUDIT_KEY)
        audit = self.audit(source_signer=shared_signer)
        readback = self.readback(source_signer=shared_signer)
        tripwire = self.tripwire()
        self.assertFalse(self.session.verify_effect(audit, readback, tripwire, "v8", NOW + 3))
        self.assertEqual(self.session.state, "RECOVERY_REQUIRED")

    def test_idempotency_key_is_stable_and_contract_bound(self):
        permit, ticket = self.reach_executing()
        again = self.session.begin_execution(permit, NOW + 3, "v7")
        self.assertEqual(ticket, again)
        self.assertEqual(ticket.idempotency_key, self.contract.idempotency_key)
        changed = TaskContract(
            contract_id=self.contract.contract_id,
            operation_id=self.contract.operation_id,
            principal_id=self.contract.principal_id,
            resource_id=self.contract.resource_id,
            expected_resource_version=self.contract.expected_resource_version,
            requested_actions=("write",),
            allowed_diff_paths=self.contract.allowed_diff_paths,
        )
        other_session = self.new_session(changed)
        self.assertTrue(other_session.authorize(
            self.permit_authority.issue(changed, NOW, NOW + 100), NOW, "v7"
        ))
        self.assertTrue(other_session.verify_plan(self.plan_receipt(changed), NOW + 1))
        self.assertIsNone(other_session.begin_execution(
            self.permit_authority.issue(changed, NOW, NOW + 100), NOW + 2, "v7"
        ))
        self.assertEqual(other_session.state, "CONFLICT")

    def test_no_public_unconditional_transition_api(self):
        self.assertFalse(hasattr(self.session, "transition"))
        self.assertFalse(hasattr(self.session, "force_transition"))

    def test_revoked_permit_rejected(self):
        verifier = PermitVerifier({"permit-key": PERMIT_KEY}, revoked_permit_ids={"REVOKED"})
        session = AssuranceSession(self.contract, verifier, self.evidence_verifier)
        revoked = self.permit(permit_id="REVOKED")
        self.assertFalse(session.authorize(revoked, NOW, "v7"))
        self.assertEqual(session.state, "REJECTED")

    def test_hash_chained_transition_receipts(self):
        self.session.authorize(self.permit(), NOW, "v7")
        previous = "0" * 64
        for event in self.session.history:
            self.assertEqual(event["previous_digest"], previous)
            body = {key: value for key, value in event.items() if key != "digest"}
            self.assertEqual(event["digest"], digest(body))
            previous = event["digest"]


class RandomizedInvariantTests(AssuranceFixture):
    def test_5000_random_transition_sequences_preserve_invariants(self):
        rng = random.Random(271828)
        operations = (
            "authorize", "authorize_expired", "plan", "begin", "partial",
            "verify_effect", "verify_fake_readback", "compensate",
            "close_verified", "close_failed", "abort",
        )
        for sequence in range(5000):
            contract = TaskContract(
                contract_id=f"PROPERTY-{sequence:05d}",
                operation_id=f"OP-{sequence:05d}",
                principal_id="agent-under-test",
                resource_id="repo:test",
                expected_resource_version="v7",
                requested_actions=("write", "compensate"),
                allowed_diff_paths=("out.json",),
            )
            session = self.new_session(contract)
            permit = self.permit_authority.issue(contract, 900, 1200)
            for step in range(8):
                now = rng.randint(950, 1250)
                action = rng.choice(operations)
                try:
                    if action == "authorize":
                        session.authorize(permit, now, rng.choice(("v7", "v7", "v8")))
                    elif action == "authorize_expired":
                        session.authorize(self.permit_authority.issue(contract, 900, 999), now, "v7")
                    elif action == "plan":
                        session.verify_plan(self.plan_receipt(contract, now), now)
                    elif action == "begin":
                        session.begin_execution(permit, now, rng.choice(("v7", "v8")))
                    elif action == "partial":
                        partial = self.audit(
                            effect_state="PARTIAL", before="v7", after="v8",
                            diff_paths=("out.json",), contract=contract, timestamp=now,
                        )
                        session.observe_partial_effect(partial, now)
                    elif action in ("verify_effect", "verify_fake_readback"):
                        audit = self.audit(before="v7", after="v8", diff_paths=("out.json",),
                                           contract=contract, timestamp=now)
                        readback = self.readback(version="v8", state_hash="b" * 64,
                                                contract=contract, timestamp=now)
                        tripwire = self.tripwire(contract=contract, timestamp=now)
                        if action == "verify_fake_readback":
                            altered = dict(readback.payload)
                            altered["observed_state_hash"] = "f" * 64
                            readback = EvidenceReceipt(
                                readback.kind, readback.source_id, readback.key_id,
                                readback.timestamp, altered, readback.signature,
                            )
                        session.verify_effect(audit, readback, tripwire, "v8", now)
                    elif action == "compensate":
                        version = rng.choice(("v7", "v8"))
                        cp = self.permit_authority.issue(
                            contract, now, now + 50, allowed_actions=("compensate",),
                            resource_version=version, permit_id=f"CP-{sequence}-{step}",
                        )
                        session.begin_compensation(cp, now, version)
                    elif action == "close_verified":
                        session.close_verified(now)
                    elif action == "close_failed":
                        audit, readback, tripwire = (
                            self.audit(effect_state="NONE", before="v7", after="v7",
                                       diff_paths=(), state_hash="0" * 64, contract=contract, timestamp=now),
                            self.readback(version="v7", state_hash="0" * 64, residual=0,
                                          contract=contract, timestamp=now),
                            self.tripwire(contract=contract, timestamp=now),
                        )
                        session.close_failed(audit, readback, tripwire, "v7", now)
                    elif action == "abort":
                        session.abort(now)
                except (InvalidTransition, ValueError):
                    pass

                self.assertIn(session.state, STATES)
                # A verified close must have passed the explicit effect-verification state.
                if session.state == "CLOSED_VERIFIED":
                    states = [entry["to_state"] for entry in session.history]
                    self.assertIn("EFFECT_VERIFIED", states)
                    self.assertTrue(session._effect_evidence)
                # Every accepted execution-start event must bind the immutable contract version.
                starts = [entry for entry in session.history
                          if entry["event"] == "EXECUTION_STARTED" and entry["accepted"]]
                if starts:
                    self.assertIsNotNone(session.ticket)
                    self.assertEqual(session.ticket.resource_version, contract.expected_resource_version)
                    self.assertEqual(session.ticket.contract_digest, contract.contract_digest)
                # Receipt chain must remain tamper-evident after arbitrary invalid calls.
                previous = "0" * 64
                for event in session.history:
                    self.assertEqual(event["previous_digest"], previous)
                    body = {key: value for key, value in event.items() if key != "digest"}
                    self.assertEqual(event["digest"], digest(body))
                    previous = event["digest"]


if __name__ == "__main__":
    unittest.main()
