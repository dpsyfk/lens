#!/usr/bin/env python3
"""Regression tests for the fail-closed release evidence gate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import release_gate


class ReleaseGateTests(unittest.TestCase):
    version = "0.1.0"

    def report(self, target: str, tester: str) -> dict[str, object]:
        checks = {name: True for name in release_gate.COMMON_CHECKS}
        checks["ebpf" if target == "x86_64-unknown-linux-gnu" else "native_signature"] = True
        return {
            "schema_version": 1,
            "release": f"v{self.version}",
            "target": target,
            "artifact": release_gate.archive_name(self.version, target),
            "tester": tester,
            "environment": "clean test machine",
            "checks": checks,
            "blocking_issues": [],
        }

    def write_reports(self, directory: Path) -> None:
        for index, target in enumerate(release_gate.TARGETS):
            report = self.report(target, f"tester-{index}")
            (directory / f"{target}.json").write_text(json.dumps(report), encoding="utf-8")

    def test_accepts_complete_independent_quorum(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            self.write_reports(directory)
            reports = release_gate.read_reports(directory, self.version)
            self.assertEqual(set(reports), set(release_gate.TARGETS))

    def test_rejects_duplicate_tester_and_failed_gate(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            self.write_reports(directory)
            paths = sorted(directory.glob("*.json"))
            first = json.loads(paths[0].read_text(encoding="utf-8"))
            second = json.loads(paths[1].read_text(encoding="utf-8"))
            second["tester"] = first["tester"]
            paths[1].write_text(json.dumps(second), encoding="utf-8")
            with self.assertRaises(release_gate.GateError):
                release_gate.read_reports(directory, self.version)

            second["tester"] = "independent"
            second["checks"]["https"] = False
            paths[1].write_text(json.dumps(second), encoding="utf-8")
            with self.assertRaises(release_gate.GateError):
                release_gate.read_reports(directory, self.version)

    def test_checksums_require_exact_complete_artifact_set(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            lines = []
            for target in release_gate.TARGETS:
                name = release_gate.archive_name(self.version, target)
                payload = target.encode("utf-8")
                (directory / name).write_bytes(payload)
                (directory / f"{name}.sigstore.json").write_text("{}", encoding="utf-8")
                lines.append(f"{hashlib.sha256(payload).hexdigest()}  {name}")
            (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
            (directory / "SHA256SUMS.sigstore.json").write_text("{}", encoding="utf-8")
            release_gate.validate_artifacts(directory, self.version)

            first = release_gate.archive_name(self.version, next(iter(release_gate.TARGETS)))
            (directory / first).write_bytes(b"tampered")
            with self.assertRaises(release_gate.GateError):
                release_gate.validate_artifacts(directory, self.version)

    def test_lockfile_rejects_unapproved_sources_and_missing_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            path = Path(value) / "Cargo.lock"
            checksum = "a" * 64
            path.write_text(
                'version = 4\n[[package]]\nname = "safe"\nversion = "1.0.0"\n'
                f'source = "{release_gate.CRATES_IO}"\nchecksum = "{checksum}"\n',
                encoding="utf-8",
            )
            release_gate.validate_lockfile(path)

            path.write_text(
                'version = 4\n[[package]]\nname = "unsafe"\nversion = "1.0.0"\n'
                'source = "git+https://example.invalid/repo"\n',
                encoding="utf-8",
            )
            with self.assertRaises(release_gate.GateError):
                release_gate.validate_lockfile(path)


if __name__ == "__main__":
    unittest.main()
