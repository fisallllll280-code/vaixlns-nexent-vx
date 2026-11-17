# VX Android Diagnostic Bridge v0.1

## Scope and operating mode

This isolated module implements **read-only diagnostics** over an ADB executable
available on a trusted host. It does not provide remote access to this ChatGPT
session or direct control of the user's handset.

The first milestone is diagnostic-only:
- fixed allowlist of read-only ADB checks;
- no arbitrary command execution;
- no `shell=True`;
- bounded command timeout and output size;
- optional explicit device serial;
- deterministic SHA-256 evidence manifest;
- repair proposals are records only and always remain `NOT_EXECUTED`.

## Checks

1. `adb get-state`
2. `adb shell getprop`
3. `adb shell df -h /data`
4. `adb shell dumpsys battery`
5. `adb shell dumpsys meminfo`
6. `adb shell pm list packages -3`

These checks require a separately configured ADB host and an Android device
with USB debugging enabled and explicitly authorized by its owner. This
repository module does not enable debugging, bypass Android permissions, or
silently pair with a device.

## Approval boundary

The module cannot apply repairs. It can create a proposal with a stable ID,
but there is no repair executor in v0.1. Any future repair capability must be
implemented as narrowly scoped handlers, show the exact target and rollback
plan, obtain a fresh explicit user approval, and emit before/after evidence.
Factory reset, bootloader changes, security-setting changes, app-data deletion,
and broad file deletion must remain out of scope unless separately designed
and explicitly approved.

## Evidence and verification

`AndroidDiagnosticBridge.evidence_manifest()` returns per-check status,
bounded output, a SHA-256 digest, and `device_mutations_performed: 0`.
The tests use a mocked ADB runner; they do not claim a physical Android
handset was connected or tested.

## Known limitations

- ADB must be installed on a trusted host; this is not an Android on-device
  service or accessibility controller.
- A real device session, Android version, OEM behavior, and permissions have
  not been verified.
- Test execution is not asserted by this commit; CI or a local Python
  environment must run `pytest -q` before any VERIFIED status is assigned.
- This branch is isolated; no merge, deployment, or changes to
  `project.genome` or `Ω.000` are part of this milestone.
