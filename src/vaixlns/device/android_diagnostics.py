"""Fail-closed, read-only Android diagnostics over a locally installed ADB client.

This module never executes repair commands. It gathers bounded diagnostics and
creates repair proposals for a human approval workflow.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import shutil
import subprocess
from typing import Callable, Sequence


@dataclass(frozen=True)
class DiagnosticResult:
    check: str
    status: str
    output: str = ""
    error: str = ""


@dataclass(frozen=True)
class RepairProposal:
    proposal_id: str
    device_serial: str
    summary: str
    proposed_action: str
    requires_user_approval: bool = True
    execution_status: str = "NOT_EXECUTED"


class AndroidDiagnosticBridge:
    """Read-only ADB bridge. No shell=True and no arbitrary command interface."""

    CHECKS: dict[str, tuple[str, ...]] = {
        "device_state": ("get-state",),
        "device_properties": ("shell", "getprop"),
        "storage": ("shell", "df", "-h", "/data"),
        "battery": ("shell", "dumpsys", "battery"),
        "memory": ("shell", "dumpsys", "meminfo"),
        "third_party_packages": ("shell", "pm", "list", "packages", "-3"),
    }

    def __init__(
        self,
        adb_path: str = "adb",
        device_serial: str | None = None,
        timeout_seconds: int = 12,
        runner: Callable = subprocess.run,
        which: Callable = shutil.which,
    ) -> None:
        if timeout_seconds < 1 or timeout_seconds > 60:
            raise ValueError("timeout_seconds must be between 1 and 60")
        self.adb_path = adb_path
        self.device_serial = device_serial
        self.timeout_seconds = timeout_seconds
        self._runner = runner
        self._which = which

    def _base(self) -> list[str]:
        if not self._which(self.adb_path):
            raise RuntimeError("ADB_NOT_INSTALLED")
        args = [self.adb_path]
        if self.device_serial:
            args.extend(["-s", self.device_serial])
        return args

    def run_check(self, check: str) -> DiagnosticResult:
        if check not in self.CHECKS:
            return DiagnosticResult(check, "BLOCKED", error="CHECK_NOT_ALLOWLISTED")
        try:
            command = self._base() + list(self.CHECKS[check])
            completed = self._runner(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
            )
            if completed.returncode != 0:
                return DiagnosticResult(check, "ERROR", error=(completed.stderr or "ADB_COMMAND_FAILED")[:1000])
            return DiagnosticResult(check, "PASS", output=(completed.stdout or "")[:12000])
        except subprocess.TimeoutExpired:
            return DiagnosticResult(check, "TIMEOUT", error="DIAGNOSTIC_TIMEOUT")
        except RuntimeError as exc:
            return DiagnosticResult(check, "BLOCKED", error=str(exc))

    def run_all(self) -> list[DiagnosticResult]:
        return [self.run_check(name) for name in self.CHECKS]

    def propose_repair(self, summary: str, proposed_action: str) -> RepairProposal:
        """Record a proposal only; this method cannot mutate the device."""
        if not summary.strip() or not proposed_action.strip():
            raise ValueError("summary and proposed_action are required")
        serial = self.device_serial or "UNSPECIFIED_DEVICE"
        material = json.dumps(
            [serial, summary.strip(), proposed_action.strip()],
            ensure_ascii=False,
            separators=(",", ":"),
        )
        proposal_id = hashlib.sha256(material.encode("utf-8")).hexdigest()
        return RepairProposal(
            proposal_id=proposal_id,
            device_serial=serial,
            summary=summary.strip(),
            proposed_action=proposed_action.strip(),
        )

    @staticmethod
    def evidence_manifest(results: Sequence[DiagnosticResult]) -> dict:
        payload = [asdict(item) for item in results]
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return {
            "schema": "VX-ANDROID-DIAGNOSTICS-0.1",
            "checks_total": len(payload),
            "checks_passed": sum(item["status"] == "PASS" for item in payload),
            "checks_failed_or_blocked": sum(item["status"] != "PASS" for item in payload),
            "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            "results": payload,
            "device_mutations_performed": 0,
        }
