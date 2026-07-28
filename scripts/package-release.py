#!/usr/bin/env python3
"""Create a deterministic Lens release archive."""

from __future__ import annotations

import argparse
import gzip
import os
from pathlib import Path
import tarfile
import time
import zipfile


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--format", choices=("tar.gz", "zip"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def normalized_epoch() -> int:
    value = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    return max(value, 315_532_800)  # ZIP timestamps cannot predate 1980.


def inputs(binary: Path) -> list[tuple[Path, str, int]]:
    executable = 0o755
    regular = 0o644
    return [
        (binary, binary.name, executable),
        (Path("README.md"), "README.md", regular),
        (Path("LICENSE"), "LICENSE", regular),
        (Path("docs/INSTALL.md"), "INSTALL.md", regular),
        (Path("docs/UPGRADING.md"), "UPGRADING.md", regular),
        (Path("docs/src/quickstart.md"), "QUICKSTART.md", regular),
        (Path("docs/src/troubleshooting.md"), "TROUBLESHOOTING.md", regular),
    ]


def write_zip(output: Path, root: str, files: list[tuple[Path, str, int]], epoch: int) -> None:
    timestamp = time.gmtime(epoch)[:6]
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for source, name, mode in files:
            info = zipfile.ZipInfo(f"{root}/{name}", timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = mode << 16
            archive.writestr(info, source.read_bytes())


def write_tar(output: Path, root: str, files: list[tuple[Path, str, int]], epoch: int) -> None:
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for source, name, mode in files:
                    data = source.read_bytes()
                    info = tarfile.TarInfo(f"{root}/{name}")
                    info.size = len(data)
                    info.mode = mode
                    info.mtime = epoch
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    from io import BytesIO

                    archive.addfile(info, BytesIO(data))


def main() -> None:
    options = arguments()
    if not options.binary.is_file():
        raise SystemExit(f"binary does not exist: {options.binary}")
    if any(character in options.version for character in "/\\"):
        raise SystemExit("version may not contain path separators")

    options.output.mkdir(parents=True, exist_ok=True)
    root = f"lens-{options.version}-{options.target}"
    suffix = ".tar.gz" if options.format == "tar.gz" else ".zip"
    destination = options.output / f"{root}{suffix}"
    epoch = normalized_epoch()
    archive_inputs = inputs(options.binary)
    if options.format == "zip":
        write_zip(destination, root, archive_inputs, epoch)
    else:
        write_tar(destination, root, archive_inputs, epoch)
    print(destination)


if __name__ == "__main__":
    main()
