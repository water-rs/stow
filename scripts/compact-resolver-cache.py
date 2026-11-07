#!/usr/bin/env python3
"""Reclaim completed resolver scratch before Actions cache packs downloads."""

import argparse
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import shutil
import stat
import tempfile


def allocated_bytes(root: Path) -> int:
    """Count each inode once, including hardlinked crate archives."""
    seen = set()
    total = 0
    for directory, _, files in os.walk(root):
        for name in files:
            metadata = (Path(directory) / name).lstat()
            identity = (metadata.st_dev, metadata.st_ino)
            if identity not in seen:
                seen.add(identity)
                # POSIX st_blocks is measured in 512-byte units.
                total += metadata.st_blocks * 512
    return total


def compact(root: Path) -> dict:
    """Workers must have exited; mutable index and Git DB files stay private."""
    before = allocated_bytes(root)
    homes = [
        home
        for lane in sorted(root.iterdir()) if lane.is_dir()
        for home in sorted(lane.iterdir()) if home.is_dir()
    ]
    if not homes:
        raise ValueError(f"no resolver homes beneath {root}")

    removed = 0
    for home in homes:
        for relative in ("registry/src", "git/checkouts"):
            scratch = home / relative
            if scratch.exists():
                shutil.rmtree(scratch)
                removed += 1

    archives = 0
    linked = 0
    unique = {}
    for home in homes:
        for archive in sorted(home.glob("registry/cache/*/*.crate")):
            metadata = archive.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"crate archive is not a regular file: {archive}")
            with archive.open("rb") as contents:
                hasher = hashlib.sha256()
                for chunk in iter(lambda: contents.read(io.DEFAULT_BUFFER_SIZE), b""):
                    hasher.update(chunk)
                digest = hasher.hexdigest()
            identity = (metadata.st_size, digest)
            archives += 1
            canonical = unique.get(identity)
            if canonical is None:
                unique[identity] = archive
                continue
            if archive.samefile(canonical):
                continue
            # Create the replacement first: a failed link preserves the
            # original archive. GNU tar records these as hardlinks, so
            # the native Actions cache packs each body only once.
            with tempfile.TemporaryDirectory(prefix=".stow-link-", dir=archive.parent) as scratch:
                replacement = Path(scratch) / "archive"
                os.link(canonical, replacement)
                replacement.replace(archive)
            linked += 1

    return {
        "allocated_bytes_before": before,
        "allocated_bytes_after": allocated_bytes(root),
        "removed_scratch_directories": removed,
        "crate_archives": archives,
        "unique_crate_archives": len(unique),
        "hardlinked_archives": linked,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    report = compact(args.root)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    logging.basicConfig(level=logging.INFO)
    logging.getLogger(__name__).info("resolver cache compaction: %s", report)


if __name__ == "__main__":
    main()
