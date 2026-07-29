#!/usr/bin/env python3
"""Reject drift between Lens's Rust and C WFP control records."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "crates" / "lens-platform" / "src" / "transparent.rs"
HEADER = (
    ROOT
    / "drivers"
    / "windows"
    / "lens-wfp"
    / "include"
    / "lens_wfp_shared.h"
)


def require(pattern: str, text: str, source: Path) -> re.Match[str]:
    match = re.search(pattern, text, re.MULTILINE)
    if match is None:
        raise SystemExit(f"missing ABI declaration in {source}: {pattern}")
    return match


def main() -> None:
    rust = RUST.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")

    rust_version = int(
        require(r"pub const LENS_WFP_ABI_VERSION: u16 = (\d+);", rust, RUST).group(1)
    )
    c_version = int(
        require(r"#define LENS_WFP_ABI_VERSION \(\(uint16_t\)(\d+)\)", header, HEADER).group(1)
    )
    if rust_version != c_version:
        raise SystemExit(
            f"WFP ABI version drift: Rust={rust_version}, C={c_version}"
        )

    expected_sizes = {
        "CONFIG": int(require(r"const CONFIG_SIZE: u16 = (\d+);", rust, RUST).group(1)),
        "STATUS": int(require(r"const STATUS_SIZE: u16 = (\d+);", rust, RUST).group(1)),
        "REDIRECT_CONTEXT": int(
            require(r"const REDIRECT_CONTEXT_SIZE: u16 = (\d+);", rust, RUST).group(1)
        ),
    }
    for name, rust_size in expected_sizes.items():
        c_size = int(
            require(
                rf"sizeof\(LENS_WFP_{name}\) == (\d+)", header, HEADER
            ).group(1)
        )
        if rust_size != c_size:
            raise SystemExit(
                f"WFP {name} size drift: Rust={rust_size}, C={c_size}"
            )

    for name in ("CONFIG", "STATUS", "REDIRECT_CONTEXT"):
        body = require(
            rf"(?s)typedef struct LENS_WFP_{name} \{{(.*?)\}} LENS_WFP_{name};",
            header,
            HEADER,
        ).group(1)
        if "*" in body:
            raise SystemExit(f"WFP {name} must remain pointer-free")

    print(f"Lens WFP ABI {rust_version}: fixed-width records verified")


if __name__ == "__main__":
    main()
