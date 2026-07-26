#!/usr/bin/env python3
"""Fail when a local Markdown link points at a missing path."""

from __future__ import annotations

import re
from pathlib import Path
import sys


LINK = re.compile(r"!?\[[^]]*\]\(([^)]+)\)")


def markdown_files(argument: str) -> list[Path]:
    path = Path(argument)
    return sorted(path.rglob("*.md")) if path.is_dir() else [path]


failures: list[str] = []
for argument in sys.argv[1:]:
    for document in markdown_files(argument):
        for line_number, line in enumerate(document.read_text(encoding="utf-8").splitlines(), 1):
            for raw_target in LINK.findall(line):
                target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
                if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                    continue
                target = target.split("#", 1)[0].split("?", 1)[0]
                if target and not (document.parent / target).exists():
                    failures.append(f"{document}:{line_number}: missing local link {target}")

if failures:
    raise SystemExit("\n".join(failures))
print("local Markdown links are valid")
