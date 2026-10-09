"""Reference implementation of a fail-closed agent action-assurance gate.

This is a deterministic control model. Production deployments must keep signing keys
and target-side evidence sources outside the agent process and integrate an actuator
that enforces the supplied idempotency key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from typing import Any, Iterable


STATES = {
    "SPECIFIED", "AUTHORIZED", "VERIFIED_PLAN", "EXECUTING",
    "PARTIAL_EFFECT", "COMPENSATING", "EFFECT_VERIFIED",
    "CLOSED_VERIFIED", "CLOSED_FAILED", "CONFLICT", "REJECTED",
    "EXPIRED", "ABORTED", "RECOVERY_REQUIRED",
}

_ALLOWED_TRANSITIONS = {
    "SPECIFIED": {"AUTHORIZED", "REJECTED", "EXPIRED", "CONFLICT", "ABORTED", "RECOVERY_REQUIRED"},
    "AUTHORIZED": {"VERIFIED_PLAN", "REJECTED", "ABORTED", "RECOVERY_REQUIRED"},
    "VERIFIED_PLAN": {"EXECUTING", "REJECTED", "EXPIRED", "CONFLICT", "ABORTED", "RECOVERY_REQUIRED"},
    "EXECUTING": {"PARTIAL_EFFECT", "EFFECT_VERIFIED", "RECOVERY_REQUIRED"},
    "PARTIAL_EFFECT": {"COMPENSATING", "RECOVERY_REQUIRED"},
    "COMPENSATING": {"CLOSED_FAILED", "RECOVERY_REQUIRED"},
    "EFFECT_VERIFIED": {"CLOSED_VERIFIED", "RECOVERY_REQUIRED"},
    "REJECTED": {"CLOSED_FAILED", "RECOVERY_REQUIRED"},
    "EXPIRED": {"CLOSED_FAILED", "RECOVERY_REQUIRED"},
    "CONFLICT": {"CLOSED_FAILED", "RECOVERY_REQUIRED"},
    "ABORTED": {"CLOSED_FAILED", "RECOVERY_REQUIRED"},
    "RECOVERY_REQUIRED": {"COMPENSATING", "CLOSED_FAILED", "RECOVERY_REQUIRED"},
    "CLOSED_VERIFIED": set(),
    "CLOSED_FAILED": set(),
}


class AssuranceError(RuntimeError):
    """Base class for fail-closed assurance errors."""


class InvalidTransition(AssuranceError):
    """Raised when an API call is invalid for the current lifecycle state."""


class EvidenceError(AssuranceError):
    """Raised when an evidence or authorization check fails."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _hmac_hex(payload: Any, key: bytes) -> str:
    return hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class TaskContract:
    contract_id: str
    operation_id: str
    principal_id: str
    resource_id: str
    expected_resource_version: str
    requested_actions: tuple[str, ...]
    allowed_diff_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("contract_id", "operation_id", "principal_id", "resource_id", "expected_resource_version"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must not be empty")
        if not self.requested_actions or any(not item.strip() for item in self.requested_actions):
            raise ValueError("requested_actions must contain non-empty action names")
        if len(set(self.requested_actions)) != len(self.requested_actions):
            raise ValueError("requested_actions must be unique")
        for path in self.allowed_diff_paths:
            if not path or path.startswith("/") or ".." in path.split("/"):
                raise ValueError(f"unsafe allowlist path: {path}")

    def as_payload(self) -> dict[str, Any]:
        value = asdict(self)
        value["requested_actions"] = list(self.requested_actions)
        value["allowed_diff_paths"] = list(self.allowed_diff_paths)
        return value

    @property
    def contract_digest(self) -> str:
        return digest(self.as_payload())

    @property
    def idempotency_key(self) -> str:
        # Stable across retries for one operation. A separate contract digest detects
        # attempts to reuse the same IDs with a changed contract.
        return hashlib.sha256(f"{self.contract_id}:{self.operation_id}".encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Permit:
    permit_id: str
    contract_id: str
    operation_id: str
    principal_id: str
    resource_id: str
    resource_version: str
    allowed_actions: tuple[str, ...]
    issued_at: int
    expires_at: int
    key_id: str
    signature: str

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "permit_id": self.permit_id,
            "contract_id": self.contract_id,
            "operation_id": self.operation_id,
            "principal_id": self.principal_id,
            "resource_id": self.resource_id,
            "resource_version": self.resource_version,
            "allowed_actions": list(self.allowed_actions),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "key_id": self.key_id,
        }


class PermitAuthority:
    """Signing-side helper; in production this must live outside the agent process."""

    def __init__(self, key_id: str, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("HMAC keys must be at least 32 bytes")
        self.key_id = key_id
        self._key = key

    def issue(
        self,
        contract: TaskContract,
        issued_at: int,
        expires_at: int,
        allowed_actions: Iterable[str] | None = None,
        resource_version: str | None = None,
        permit_id: str = "PERMIT-001",
    ) -> Permit:
        actions = tuple(allowed_actions if allowed_actions is not None else contract.requested_actions)
        payload = {
            "permit_id": permit_id,
            "contract_id": contract.contract_id,
            "operation_id": contract.operation_id,
            "principal_id": contract.principal_id,
            "resource_id": contract.resource_id,
            "resource_version": resource_version or contract.expected_resource_version,
            "allowed_actions": list(actions),
            "issued_at": issued_at,
            "expires_at": expires_at,
            "key_id": self.key_id,
        }
        return Permit(**payload, signature=_hmac_hex(payload, self._key))


class PermitVerifier:
    """Verifier containing trusted keys, never a caller-provided approval Boolean."""

    def __init__(self, trusted_keys: dict[str, bytes], revoked_permit_ids: set[str] | None = None) -> None:
        self._keys = dict(trusted_keys)
        self._revoked = set(revoked_permit_ids or set())

    def evaluate(
        self,
        contract: TaskContract,
        permit: Permit,
        now: int,
        current_resource_version: str,
        actions: Iterable[str] | None = None,
        expected_resource_version: str | None = None,
    ) -> str | None:
        key = self._keys.get(permit.key_id)
        if key is None:
            return "untrusted_permit_key"
        if permit.permit_id in self._revoked:
            return "permit_revoked"
        if not hmac.compare_digest(_hmac_hex(permit.unsigned_payload(), key), permit.signature):
            return "permit_signature_invalid"
        if (
            permit.contract_id != contract.contract_id
            or permit.operation_id != contract.operation_id
            or permit.principal_id != contract.principal_id
            or permit.resource_id != contract.resource_id
        ):
            return "permit_contract_binding_mismatch"
        if permit.expires_at <= permit.issued_at:
            return "permit_lifetime_invalid"
        if now < permit.issued_at:
            return "permit_not_yet_valid"
        if now >= permit.expires_at:
            return "permit_expired"
        expected = expected_resource_version or contract.expected_resource_version
        if permit.resource_version != expected or current_resource_version != expected:
            return "resource_version_conflict"
        requested = set(actions if actions is not None else contract.requested_actions)
        if not requested.issubset(set(permit.allowed_actions)):
            return "action_scope_exceeded"
        return None


@dataclass(frozen=True)
class EvidenceReceipt:
    kind: str
    source_id: str
    key_id: str
    timestamp: int
    payload: dict[str, Any]
    signature: str

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "source_id": self.source_id,
            "key_id": self.key_id,
            "timestamp": self.timestamp,
            "payload": self.payload,
        }

    @property
    def receipt_digest(self) -> str:
        return digest({**self.unsigned_payload(), "signature": self.signature})


class EvidenceSigner:
    """Test/adapter-side signer. Keep the corresponding key out of the agent process."""

    def __init__(self, key_id: str, source_id: str, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("HMAC keys must be at least 32 bytes")
        self.key_id = key_id
        self.source_id = source_id
        self._key = key

    def issue(self, kind: str, payload: dict[str, Any], timestamp: int) -> EvidenceReceipt:
        unsigned = {
            "kind": kind,
            "source_id": self.source_id,
            "key_id": self.key_id,
            "timestamp": timestamp,
            "payload": payload,
        }
        return EvidenceReceipt(**unsigned, signature=_hmac_hex(unsigned, self._key))


class EvidenceVerifier:
    """Maps each trusted signing key to one expected independent source."""

    def __init__(self, trusted_sources: dict[str, tuple[bytes, str]]) -> None:
        self._trusted = dict(trusted_sources)

    def verify(self, receipt: EvidenceReceipt) -> bool:
        trusted = self._trusted.get(receipt.key_id)
        if trusted is None:
            return False
        key, expected_source = trusted
        if receipt.source_id != expected_source:
            return False
        return hmac.compare_digest(_hmac_hex(receipt.unsigned_payload(), key), receipt.signature)


@dataclass(frozen=True)
class ExecutionTicket:
    contract_id: str
    operation_id: str
    resource_id: str
    resource_version: str
    idempotency_key: str
    contract_digest: str
    permit_id: str


class IdempotencyRegistry:
    """Small in-memory reference registry; production requires durable atomic storage."""

    def __init__(self) -> None:
        self._records: dict[str, tuple[str, ExecutionTicket]] = {}

    def reserve(self, contract: TaskContract, ticket: ExecutionTicket) -> ExecutionTicket:
        existing = self._records.get(contract.idempotency_key)
        if existing is not None:
            existing_digest, existing_ticket = existing
            if existing_digest != contract.contract_digest:
                raise EvidenceError("idempotency_key_reused_with_changed_contract")
            return existing_ticket
        self._records[contract.idempotency_key] = (contract.contract_digest, ticket)
        return ticket


class AssuranceSession:
    """Only guarded methods can advance state; no external transition flag is accepted."""

    def __init__(
        self,
        contract: TaskContract,
        permit_verifier: PermitVerifier,
        evidence_verifier: EvidenceVerifier,
        connector_source_id: str = "agent-connector",
        connector_key_id: str = "agent-connector-key",
        idempotency_registry: IdempotencyRegistry | None = None,
    ) -> None:
        self.contract = contract
        self._permit_verifier = permit_verifier
        self._evidence_verifier = evidence_verifier
        self._connector_source_id = connector_source_id
        self._connector_key_id = connector_key_id
        self._idempotency = idempotency_registry or IdempotencyRegistry()
        self._state = "SPECIFIED"
        self._history: list[dict[str, Any]] = []
        self._permit: Permit | None = None
        self._ticket: ExecutionTicket | None = None
        self._plan_digest: str | None = None
        self._effect_evidence: tuple[str, ...] = ()
        self._partial_audit: EvidenceReceipt | None = None

    @property
    def state(self) -> str:
        return self._state

    @property
    def history(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._history)

    @property
    def ticket(self) -> ExecutionTicket | None:
        return self._ticket

    def _record(self, event: str, next_state: str, now: int, accepted: bool, reason: str | None = None,
                evidence_refs: Iterable[str] = ()) -> None:
        if next_state not in STATES:
            raise ValueError("unknown state")
        if next_state != self._state and next_state not in _ALLOWED_TRANSITIONS[self._state]:
            raise InvalidTransition(f"{self._state} -> {next_state} is forbidden")
        body = {
            "sequence": len(self._history) + 1,
            "event": event,
            "from_state": self._state,
            "to_state": next_state,
            "timestamp": now,
            "accepted": accepted,
            "reason": reason,
            "evidence_refs": sorted(set(evidence_refs)),
            "previous_digest": self._history[-1]["digest"] if self._history else "0" * 64,
        }
        body["digest"] = digest(body)
        self._history.append(body)
        self._state = next_state

    def _permit_failure_state(self, reason: str) -> str:
        if reason == "permit_expired" or reason == "permit_not_yet_valid":
            return "EXPIRED"
        if reason == "resource_version_conflict":
            return "CONFLICT"
        if self._state in {"EXECUTING", "PARTIAL_EFFECT", "RECOVERY_REQUIRED", "COMPENSATING"}:
            return "RECOVERY_REQUIRED"
        return "REJECTED"

    def _check_evidence(self, receipt: EvidenceReceipt, expected_kind: str) -> None:
        if receipt.kind != expected_kind:
            raise EvidenceError(f"wrong_evidence_kind:{receipt.kind}")
        if receipt.key_id == self._connector_key_id or receipt.source_id == self._connector_source_id:
            raise EvidenceError("evidence_not_independent_of_connector")
        if not self._evidence_verifier.verify(receipt):
            raise EvidenceError("evidence_signature_or_source_invalid")
        p = receipt.payload
        if p.get("contract_id") != self.contract.contract_id or p.get("operation_id") != self.contract.operation_id:
            raise EvidenceError("evidence_contract_binding_mismatch")
        if p.get("resource_id") not in (None, self.contract.resource_id):
            raise EvidenceError("evidence_resource_binding_mismatch")

    def _check_independence(self, receipts: tuple[EvidenceReceipt, ...]) -> None:
        key_ids = [item.key_id for item in receipts]
        sources = [item.source_id for item in receipts]
        if len(set(key_ids)) != len(key_ids) or len(set(sources)) != len(sources):
            raise EvidenceError("evidence_channels_not_independent")
        if self._connector_key_id in key_ids or self._connector_source_id in sources:
            raise EvidenceError("evidence_channel_reuses_connector_identity")

    def authorize(self, permit: Permit, now: int, current_resource_version: str) -> bool:
        if self._state != "SPECIFIED":
            raise InvalidTransition("authorize requires SPECIFIED")
        reason = self._permit_verifier.evaluate(self.contract, permit, now, current_resource_version)
        if reason:
            self._record("AUTHORIZATION_DENIED", self._permit_failure_state(reason), now, False, reason)
            return False
        self._permit = permit
        self._record("AUTHORIZATION_GRANTED", "AUTHORIZED", now, True, evidence_refs=[digest(permit.unsigned_payload())])
        return True

    def verify_plan(self, receipt: EvidenceReceipt, now: int) -> bool:
        if self._state != "AUTHORIZED":
            raise InvalidTransition("verify_plan requires AUTHORIZED")
        try:
            self._check_evidence(receipt, "PLAN_VERIFICATION")
            p = receipt.payload
            if p.get("verdict") != "PASS" or not p.get("plan_hash"):
                raise EvidenceError("plan_not_verified")
            if not set(self.contract.requested_actions).issubset(set(p.get("actions", []))):
                raise EvidenceError("verified_plan_scope_incomplete")
        except EvidenceError as exc:
            self._record("PLAN_REJECTED", "REJECTED", now, False, str(exc), [receipt.receipt_digest])
            return False
        self._plan_digest = str(receipt.payload["plan_hash"])
        self._record("PLAN_VERIFIED", "VERIFIED_PLAN", now, True, evidence_refs=[receipt.receipt_digest])
        return True

    def begin_execution(self, permit: Permit, now: int, current_resource_version: str) -> ExecutionTicket | None:
        if self._state == "EXECUTING" and self._ticket is not None:
            # A retry returns the same ticket/key. The downstream actuator must also
            # enforce that key atomically to prevent duplicate side effects.
            return self._ticket
        if self._state != "VERIFIED_PLAN":
            raise InvalidTransition("begin_execution requires VERIFIED_PLAN")
        reason = self._permit_verifier.evaluate(self.contract, permit, now, current_resource_version)
        if reason:
            self._record("EXECUTION_DENIED", self._permit_failure_state(reason), now, False, reason)
            return None
        if self._plan_digest is None:
            self._record("EXECUTION_DENIED", "REJECTED", now, False, "missing_plan_digest")
            return None
        candidate = ExecutionTicket(
            contract_id=self.contract.contract_id,
            operation_id=self.contract.operation_id,
            resource_id=self.contract.resource_id,
            resource_version=current_resource_version,
            idempotency_key=self.contract.idempotency_key,
            contract_digest=self.contract.contract_digest,
            permit_id=permit.permit_id,
        )
        try:
            ticket = self._idempotency.reserve(self.contract, candidate)
        except EvidenceError as exc:
            self._record("IDEMPOTENCY_CONFLICT", "CONFLICT", now, False, str(exc))
            return None
        self._ticket = ticket
        self._record("EXECUTION_STARTED", "EXECUTING", now, True, evidence_refs=[self.contract.contract_digest, ticket.idempotency_key])
        return ticket

    def observe_partial_effect(self, audit: EvidenceReceipt, now: int) -> bool:
        if self._state != "EXECUTING":
            raise InvalidTransition("observe_partial_effect requires EXECUTING")
        try:
            self._check_evidence(audit, "TARGET_AUDIT")
            p = audit.payload
            if p.get("effect_state") != "PARTIAL" or p.get("log_complete") is not True:
                raise EvidenceError("partial_effect_not_proven_by_complete_target_audit")
            if p.get("resource_version_before") != self.contract.expected_resource_version:
                raise EvidenceError("partial_effect_precondition_version_mismatch")
            if not set(p.get("diff_paths", [])).issubset(set(self.contract.allowed_diff_paths)):
                raise EvidenceError("partial_effect_outside_allowlist")
            if not p.get("state_hash") or not isinstance(p.get("sequence"), int) or not p.get("resource_version_after"):
                raise EvidenceError("partial_effect_audit_incomplete")
        except EvidenceError as exc:
            self._record("PARTIAL_EFFECT_EVIDENCE_REJECTED", "RECOVERY_REQUIRED", now, False, str(exc), [audit.receipt_digest])
            return False
        self._partial_audit = audit
        self._record("PARTIAL_EFFECT_OBSERVED", "PARTIAL_EFFECT", now, True, evidence_refs=[audit.receipt_digest])
        return True

    def _verify_bundle(
        self,
        audit: EvidenceReceipt,
        readback: EvidenceReceipt,
        tripwire: EvidenceReceipt,
        current_resource_version: str,
        accepted_effect_states: set[str],
        expected_version_before: str | None,
    ) -> tuple[bool, str | None]:
        receipts = (audit, readback, tripwire)
        try:
            self._check_independence(receipts)
            self._check_evidence(audit, "TARGET_AUDIT")
            self._check_evidence(readback, "READBACK")
            self._check_evidence(tripwire, "TRIPWIRE")
            a, r, t = audit.payload, readback.payload, tripwire.payload
            if a.get("effect_state") not in accepted_effect_states:
                raise EvidenceError("target_audit_effect_state_mismatch")
            if a.get("log_complete") is not True or not isinstance(a.get("sequence"), int):
                raise EvidenceError("target_audit_completeness_not_proven")
            if expected_version_before is not None and a.get("resource_version_before") != expected_version_before:
                raise EvidenceError("target_audit_precondition_version_mismatch")
            if a.get("resource_version_after") != current_resource_version:
                raise EvidenceError("target_audit_current_version_mismatch")
            if not a.get("state_hash"):
                raise EvidenceError("target_audit_state_hash_missing")
            if not set(a.get("diff_paths", [])).issubset(set(self.contract.allowed_diff_paths)):
                raise EvidenceError("target_diff_outside_allowlist")
            if r.get("verdict") != "PASS":
                raise EvidenceError("readback_verdict_not_pass")
            if r.get("observed_state_hash") != a.get("state_hash"):
                raise EvidenceError("readback_hash_does_not_match_target_audit")
            if r.get("resource_version") != current_resource_version:
                raise EvidenceError("readback_resource_version_mismatch")
            if t.get("clean") is not True or t.get("coverage_complete") is not True:
                raise EvidenceError("tripwire_not_clean_or_coverage_incomplete")
            if t.get("unexpected_events") != []:
                raise EvidenceError("tripwire_observed_unexpected_event")
            if a.get("resource_id") != self.contract.resource_id:
                raise EvidenceError("target_audit_resource_mismatch")
            if r.get("residual_effects", 0) != 0 and "COMPENSATED" in accepted_effect_states:
                raise EvidenceError("compensation_left_residual_effects")
            return True, None
        except EvidenceError as exc:
            return False, str(exc)

    def verify_effect(
        self,
        audit: EvidenceReceipt,
        readback: EvidenceReceipt,
        tripwire: EvidenceReceipt,
        current_resource_version: str,
        now: int,
    ) -> bool:
        if self._state != "EXECUTING":
            raise InvalidTransition("verify_effect requires EXECUTING")
        ok, reason = self._verify_bundle(
            audit, readback, tripwire, current_resource_version,
            accepted_effect_states={"COMPLETE"},
            expected_version_before=self.contract.expected_resource_version,
        )
        refs = [audit.receipt_digest, readback.receipt_digest, tripwire.receipt_digest]
        if not ok:
            self._record("EFFECT_VERIFICATION_FAILED", "RECOVERY_REQUIRED", now, False, reason, refs)
            return False
        self._effect_evidence = tuple(refs)
        self._record("EFFECT_VERIFIED", "EFFECT_VERIFIED", now, True, evidence_refs=refs)
        return True

    def begin_compensation(self, permit: Permit, now: int, current_resource_version: str) -> bool:
        if self._state not in {"PARTIAL_EFFECT", "RECOVERY_REQUIRED"}:
            raise InvalidTransition("begin_compensation requires PARTIAL_EFFECT or RECOVERY_REQUIRED")
        reason = self._permit_verifier.evaluate(
            self.contract, permit, now, current_resource_version,
            actions=("compensate",), expected_resource_version=current_resource_version,
        )
        if reason:
            self._record("COMPENSATION_DENIED", "RECOVERY_REQUIRED", now, False, reason)
            return False
        self._permit = permit
        self._record("COMPENSATION_STARTED", "COMPENSATING", now, True, evidence_refs=[digest(permit.unsigned_payload())])
        return True

    def abort(self, now: int) -> None:
        if self._state not in {"SPECIFIED", "AUTHORIZED", "VERIFIED_PLAN"}:
            raise InvalidTransition("abort is allowed only before execution starts")
        self._record("ABORT_REQUESTED", "ABORTED", now, True)

    def close_verified(self, now: int) -> bool:
        if self._state != "EFFECT_VERIFIED" or not self._effect_evidence:
            raise InvalidTransition("CLOSED_VERIFIED requires EFFECT_VERIFIED and evidence")
        self._record("CLOSE_VERIFIED", "CLOSED_VERIFIED", now, True, evidence_refs=self._effect_evidence)
        return True

    def close_failed(
        self,
        audit: EvidenceReceipt,
        readback: EvidenceReceipt,
        tripwire: EvidenceReceipt,
        current_resource_version: str,
        now: int,
    ) -> bool:
        if self._state not in {"COMPENSATING", "ABORTED", "REJECTED", "EXPIRED", "CONFLICT", "RECOVERY_REQUIRED"}:
            raise InvalidTransition("CLOSED_FAILED requires a failed/compensating/recovery state")
        before = None
        if self._state == "COMPENSATING" and self._partial_audit is not None:
            before = self._partial_audit.payload.get("resource_version_after")
        ok, reason = self._verify_bundle(
            audit, readback, tripwire, current_resource_version,
            accepted_effect_states={"NONE", "COMPENSATED", "FAILED_NO_CHANGE"},
            expected_version_before=before,
        )
        refs = [audit.receipt_digest, readback.receipt_digest, tripwire.receipt_digest]
        if not ok:
            self._record("FAILED_CLOSURE_UNPROVEN", "RECOVERY_REQUIRED", now, False, reason, refs)
            return False
        self._record("CLOSE_FAILED", "CLOSED_FAILED", now, True, evidence_refs=refs)
        return True
