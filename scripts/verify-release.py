#!/usr/bin/env python3
"""Verify the expected contents of one Lens release archive."""

from __future__ import annotations

import argparse
from pathlib import Path
import tarfile
import zipfile


parser = argparse.ArgumentParser()
parser.add_argument("archive", type=Path)
options = parser.parse_args()

if options.archive.suffix == ".zip":
    with zipfile.ZipFile(options.archive) as archive:
        names = archive.namelist()
else:
    with tarfile.open(options.archive, "r:gz") as archive:
        names = archive.getnames()

basenames = {Path(name).name for name in names}
binary_names = {"lens", "lens.exe"}
required = {
    "README.md",
    "LICENSE",
    "INSTALL.md",
    "UPGRADING.md",
    "QUICKSTART.md",
    "REPLAY.md",
    "TROUBLESHOOTING.md",
}
if not basenames.intersection(binary_names):
    raise SystemExit("release archive does not contain the Lens binary")
missing = required - basenames
if missing:
    raise SystemExit(f"release archive is missing: {', '.join(sorted(missing))}")
print(f"verified {options.archive}")
