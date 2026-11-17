"""Safety and determinism tests for the Android diagnostic bridge."""
import subprocess

from vaixlns.device.android_diagnostics import AndroidDiagnosticBridge


def fake_runner_ok(command, **kwargs):
    assert kwargs["shell"] is False
    assert kwargs["timeout"] <= 60
    return subprocess.CompletedProcess(command, 0, stdout="diagnostic-ok", stderr="")


def test_allowlisted_check_runs_without_shell():
    bridge = AndroidDiagnosticBridge(runner=fake_runner_ok, which=lambda _: "/usr/bin/adb")
    result = bridge.run_check("battery")
    assert result.status == "PASS"
    assert result.output == "diagnostic-ok"


def test_arbitrary_command_is_blocked():
    bridge = AndroidDiagnosticBridge(runner=fake_runner_ok, which=lambda _: "/usr/bin/adb")
    result = bridge.run_check("shell rm -rf /")
    assert result.status == "BLOCKED"
    assert result.error == "CHECK_NOT_ALLOWLISTED"


def test_missing_adb_fails_closed():
    bridge = AndroidDiagnosticBridge(which=lambda _: None)
    result = bridge.run_check("storage")
    assert result.status == "BLOCKED"
    assert result.error == "ADB_NOT_INSTALLED"


def test_timeout_is_reported():
    def timeout_runner(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
    bridge = AndroidDiagnosticBridge(runner=timeout_runner, which=lambda _: "/usr/bin/adb")
    assert bridge.run_check("memory").status == "TIMEOUT"


def test_repair_is_proposal_only_and_deterministic():
    bridge = AndroidDiagnosticBridge(device_serial="DEVICE-1")
    first = bridge.propose_repair("Storage pressure", "Review large cached files")
    second = bridge.propose_repair("Storage pressure", "Review large cached files")
    assert first == second
    assert first.requires_user_approval is True
    assert first.execution_status == "NOT_EXECUTED"


def test_evidence_manifest_is_hashed_and_non_mutating():
    bridge = AndroidDiagnosticBridge(runner=fake_runner_ok, which=lambda _: "/usr/bin/adb")
    manifest = bridge.evidence_manifest(bridge.run_all())
    assert len(manifest["sha256"]) == 64
    assert manifest["device_mutations_performed"] == 0
    assert manifest["checks_total"] == len(bridge.CHECKS)
