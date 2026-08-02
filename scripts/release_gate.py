#!/usr/bin/env python3
"""Fail closed unless a Lens release candidate has complete evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import tomllib


TARGETS = {
    "x86_64-unknown-linux-gnu": "tar.gz",
    "x86_64-pc-windows-msvc": "zip",
    "x86_64-apple-darwin": "zip",
    "aarch64-apple-darwin": "zip",
}
COMMON_CHECKS = {
    "artifact_verification",
    "first_run",
    "tui_restoration",
    "http",
    "https",
    "postgres",
    "redis",
    "http2_grpc",
    "plugins",
    "default_redaction",
    "fault_overload",
    "upgrade_rollback",
}
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


class GateError(ValueError):
    """Release evidence is missing, inconsistent, or unsafe."""


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--reports",
        type=Path,
        help="directory containing four independent dogfood JSON reports",
    )
    parser.add_argument(
        "--artifacts",
        type=Path,
        help="directory containing archives, checksums, and Sigstore bundles",
    )
    return parser.parse_args()


def workspace_version(root: Path) -> str:
    versions: dict[str, str] = {}
    for manifest in sorted((root / "crates").glob("*/Cargo.toml")):
        with manifest.open("rb") as file:
            package = tomllib.load(file)["package"]
        versions[package["name"]] = package["version"]
    unique = set(versions.values())
    if len(unique) != 1:
        detail = ", ".join(f"{name}={value}" for name, value in versions.items())
        raise GateError(f"workspace crate versions differ: {detail}")
    return unique.pop()


def archive_name(version: str, target: str) -> str:
    return f"lens-{version}-{target}.{TARGETS[target]}"


def validate_source(root: Path, version: str) -> None:
    required = (
        "README.md",
        "SECURITY.md",
        "SECURITY_REVIEW.md",
        "docs/INSTALL.md",
        "docs/UPGRADING.md",
        "docs/RELEASING.md",
        "docs/DOGFOODING.md",
        ".github/workflows/release.yml",
        ".github/ISSUE_TEMPLATE/dogfood_report.yml",
    )
    missing = [name for name in required if not (root / name).is_file()]
    if missing:
        raise GateError(f"release source is missing: {', '.join(missing)}")

    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    if not re.search(rf"^## \[{re.escape(version)}\](?:\s|$)", changelog, re.MULTILINE):
        raise GateError(f"CHANGELOG.md has no finalized {version} section")

    workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
    for target in TARGETS:
        if target not in workflow:
            raise GateError(f"release workflow does not build {target}")
    for control in ("actions/attest@", "cosign sign-blob", "draft: true"):
        if control not in workflow:
            raise GateError(f"release workflow is missing control: {control}")

    template = (root / ".github/ISSUE_TEMPLATE/dogfood_report.yml").read_text(
        encoding="utf-8"
    )
    for check in sorted(COMMON_CHECKS | {"native_signature", "ebpf"}):
        if f"[{check}]" not in template:
            raise GateError(f"dogfood issue template is missing check id: {check}")

    validate_lockfile(root / "Cargo.lock")


def validate_lockfile(path: Path) -> None:
    with path.open("rb") as file:
        lockfile = tomllib.load(file)
    if lockfile.get("version") != 4:
        raise GateError("Cargo.lock must use lockfile version 4")
    seen: set[tuple[str, str, str | None]] = set()
    for package in lockfile.get("package", []):
        identity = (package["name"], package["version"], package.get("source"))
        if identity in seen:
            raise GateError(f"duplicate locked package identity: {identity}")
        seen.add(identity)
        source = package.get("source")
        if source is None:
            continue
        if source != CRATES_IO:
            raise GateError(f"unapproved dependency source for {package['name']}: {source}")
        checksum = package.get("checksum", "")
        if not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise GateError(f"missing or invalid checksum for {package['name']}")


def read_reports(directory: Path, version: str) -> dict[str, dict[str, object]]:
    if not directory.is_dir():
        raise GateError(f"dogfood report directory does not exist: {directory}")
    reports: dict[str, dict[str, object]] = {}
    testers: set[str] = set()
    for path in sorted(directory.glob("*.json")):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise GateError(f"invalid dogfood report {path}: {error}") from error
        if report.get("schema_version") != 1:
            raise GateError(f"{path} does not use dogfood schema version 1")
        target = report.get("target")
        if target not in TARGETS:
            raise GateError(f"{path} has unsupported target {target!r}")
        if target in reports:
            raise GateError(f"duplicate dogfood report for {target}")
        if report.get("release") != f"v{version}":
            raise GateError(f"{path} does not match release v{version}")
        if report.get("artifact") != archive_name(version, target):
            raise GateError(f"{path} names the wrong artifact for {target}")
        tester = report.get("tester")
        environment = report.get("environment")
        if not isinstance(tester, str) or not tester.strip():
            raise GateError(f"{path} has no tester")
        if not isinstance(environment, str) or not environment.strip():
            raise GateError(f"{path} has no environment description")
        if tester in testers:
            raise GateError(f"tester {tester!r} submitted more than one target report")
        testers.add(tester)
        blockers = report.get("blocking_issues")
        if blockers != []:
            raise GateError(f"{path} has unresolved blocking issues")
        checks = report.get("checks")
        if not isinstance(checks, dict):
            raise GateError(f"{path} has no checks object")
        required = set(COMMON_CHECKS)
        required.add("ebpf" if target == "x86_64-unknown-linux-gnu" else "native_signature")
        failed = sorted(name for name in required if checks.get(name) is not True)
        if failed:
            raise GateError(f"{path} has incomplete checks: {', '.join(failed)}")
        reports[target] = report

    missing = sorted(set(TARGETS) - set(reports))
    if missing:
        raise GateError(f"dogfood reports are missing targets: {', '.join(missing)}")
    return reports


def checksum_entries(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        parts = line.split()
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            raise GateError(f"invalid SHA256SUMS line {number}")
        name = parts[1].removeprefix("*")
        if Path(name).name != name or name in entries:
            raise GateError(f"unsafe or duplicate SHA256SUMS entry: {name}")
        entries[name] = parts[0].lower()
    return entries


def validate_artifacts(directory: Path, version: str) -> None:
    if not directory.is_dir():
        raise GateError(f"artifact directory does not exist: {directory}")
    expected = {archive_name(version, target) for target in TARGETS}
    actual = {
        path.name
        for pattern in ("*.tar.gz", "*.zip")
        for path in directory.glob(pattern)
    }
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise GateError(f"release archive set mismatch; missing={missing}, extra={extra}")
    sums_path = directory / "SHA256SUMS"
    sums_bundle = directory / "SHA256SUMS.sigstore.json"
    if not sums_path.is_file() or not sums_bundle.is_file():
        raise GateError("SHA256SUMS and its Sigstore bundle are required")
    entries = checksum_entries(sums_path)
    if set(entries) != expected:
        missing = sorted(expected - set(entries))
        extra = sorted(set(entries) - expected)
        raise GateError(f"checksum manifest mismatch; missing={missing}, extra={extra}")
    for name in sorted(expected):
        artifact = directory / name
        bundle = directory / f"{name}.sigstore.json"
        if not artifact.is_file() or not bundle.is_file():
            raise GateError(f"artifact or Sigstore bundle is missing for {name}")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if digest != entries[name]:
            raise GateError(f"checksum mismatch for {name}")


def main() -> None:
    options = arguments()
    root = Path(__file__).resolve().parent.parent
    version = workspace_version(root)
    validate_source(root, version)
    print(f"source release gate passed for v{version}")
    if options.reports:
        read_reports(options.reports, version)
        print("four-platform dogfood quorum passed")
    if options.artifacts:
        validate_artifacts(options.artifacts, version)
        print("release artifact set passed")


if __name__ == "__main__":
    try:
        main()
    except GateError as error:
        raise SystemExit(f"release gate failed: {error}") from error
