#!/usr/bin/env python3
"""Run three targeted mutation canaries against the assurance safety tests.

Each mutant intentionally disables one guard. A mutant is considered killed only when
its corresponding invariant test fails. This is a small curated mutation runner, not
a replacement for a general mutation-testing framework.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/vaixlns/vx/agent_assurance.py"
TEST = ROOT / "tests/test_agent_assurance.py"

MUTANTS = [
    (
        "permit-expiry",
        "if now >= permit.expires_at:",
        "if False and now >= permit.expires_at:",
        "test_agent_assurance.AgentAssuranceTests.test_expired_permit_rejected",
    ),
    (
        "action-scope",
        "if not requested.issubset(set(permit.allowed_actions)):",
        "if requested.issubset(set(permit.allowed_actions)):",
        "test_agent_assurance.AgentAssuranceTests.test_scope_escalation_rejected",
    ),
    (
        "resource-version-toctou",
        "if permit.resource_version != expected or current_resource_version != expected:",
        "if permit.resource_version != expected or False:",
        "test_agent_assurance.AgentAssuranceTests.test_time_of_check_time_of_use_resource_change_rejected",
    ),
]


def run_one(name: str, before: str, after: str, test_name: str) -> bool:
    original = SOURCE.read_text(encoding="utf-8")
    if original.count(before) != 1:
        print(f"MUTATION_ERROR {name}: expected exactly one mutation site")
        return False

    with tempfile.TemporaryDirectory(prefix=f"vaixlns-mutant-{name}-") as temp:
        root = Path(temp)
        src = root / "src/vaixlns/vx"
        tests = root / "tests"
        src.mkdir(parents=True)
        tests.mkdir(parents=True)
        mutant_source = original.replace(before, after, 1)
        (src / "agent_assurance.py").write_text(mutant_source, encoding="utf-8")
        (src / "__init__.py").write_text("", encoding="utf-8")
        (src.parent / "__init__.py").write_text("", encoding="utf-8")
        (src.parent.parent / "__init__.py").write_text("", encoding="utf-8")
        shutil.copy2(TEST, tests / "test_agent_assurance.py")

        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        run = subprocess.run(
            [sys.executable, "-m", "unittest", test_name, "-v"],
            cwd=tests,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if run.returncode == 0:
            print(f"MUTATION_SURVIVED {name}")
            print(run.stdout)
            print(run.stderr)
            return False
        print(f"MUTATION_KILLED {name}")
        return True


def main() -> int:
    results = [run_one(*mutant) for mutant in MUTANTS]
    killed = sum(results)
    print(f"MUTATION_SUMMARY killed={killed} total={len(MUTANTS)}")
    return 0 if killed == len(MUTANTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
