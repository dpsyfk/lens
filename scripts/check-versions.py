#!/usr/bin/env python3
"""Require every workspace crate to use one release version."""

from __future__ import annotations

from pathlib import Path
import sys
import tomllib


versions: dict[str, str] = {}
for manifest in sorted(Path("crates").glob("*/Cargo.toml")):
    with manifest.open("rb") as file:
        package = tomllib.load(file)["package"]
    versions[package["name"]] = package["version"]

unique = set(versions.values())
if len(unique) != 1:
    details = ", ".join(f"{name}={version}" for name, version in versions.items())
    raise SystemExit(f"workspace crate versions differ: {details}")

version = unique.pop()
if len(sys.argv) == 2 and sys.argv[1] != version:
    raise SystemExit(f"expected workspace version {sys.argv[1]}, found {version}")
print(version)
