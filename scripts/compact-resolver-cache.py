#!/usr/bin/env python3
"""Compact offline resolver caches and restore private mutable worker files."""

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


def resolver_homes(root: Path) -> list[Path]:
    return [
        home
        for lane in sorted(root.iterdir()) if lane.is_dir()
        for home in sorted(lane.iterdir()) if home.is_dir()
    ]


def mutable_files(homes: list[Path]):
    for home in homes:
        for relative in ("registry/index", "git/db"):
            for directory, _, names in os.walk(home / relative):
                for name in sorted(names):
                    yield Path(directory) / name


def hardlink_identical(files) -> tuple[int, int, int]:
    """Only called after all workers exit; tar stores each inode once."""
    count = 0
    linked = 0
    unique = {}
    digests = {}
    for path in files:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"cache entry is not a regular file: {path}")
        inode = (metadata.st_dev, metadata.st_ino)
        digest = digests.get(inode)
        if digest is None:
            with path.open("rb") as contents:
                hasher = hashlib.sha256()
                for chunk in iter(lambda: contents.read(io.DEFAULT_BUFFER_SIZE), b""):
                    hasher.update(chunk)
            digest = hasher.digest()
            digests[inode] = digest
        identity = (metadata.st_size, stat.S_IMODE(metadata.st_mode), digest)
        count += 1
        canonical = unique.get(identity)
        if canonical is None:
            unique[identity] = path
            continue
        if path.samefile(canonical):
            continue
        with tempfile.TemporaryDirectory(prefix=".stow-link-", dir=path.parent) as scratch:
            replacement = Path(scratch) / "entry"
            os.link(canonical, replacement)
            replacement.replace(path)
        linked += 1
    return count, len(unique), linked


def materialize(root: Path) -> int:
    """Detach restored mutable files before any resolver worker starts."""
    detached = 0
    for path in mutable_files(resolver_homes(root)):
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"cache entry is not a regular file: {path}")
        if metadata.st_nlink == 1:
            continue
        # Copy before replacing the alias: failure leaves the cached
        # data intact, and no mutable inode is shared when this returns.
        with tempfile.TemporaryDirectory(prefix=".stow-copy-", dir=path.parent) as scratch:
            replacement = Path(scratch) / "entry"
            shutil.copy2(path, replacement)
            replacement.replace(path)
        detached += 1
    return detached


def compact(root: Path) -> dict:
    """Pack repeated bytes once; materialize must precede future workers."""
    before = allocated_bytes(root)
    homes = resolver_homes(root)
    if not homes:
        raise ValueError(f"no resolver homes beneath {root}")

    removed = 0
    for home in homes:
        for relative in ("registry/src", "git/checkouts"):
            scratch = home / relative
            if scratch.exists():
                shutil.rmtree(scratch)
                removed += 1

    archives, unique_archives, linked_archives = hardlink_identical(
        archive
        for home in homes
        for archive in sorted(home.glob("registry/cache/*/*.crate"))
    )
    mutable, unique_mutable, linked_mutable = hardlink_identical(mutable_files(homes))
    return {
        "allocated_bytes_before": before,
        "allocated_bytes_after": allocated_bytes(root),
        "removed_scratch_directories": removed,
        "crate_archives": archives,
        "unique_crate_archives": unique_archives,
        "hardlinked_archives": linked_archives,
        "mutable_cache_files": mutable,
        "unique_mutable_cache_files": unique_mutable,
        "hardlinked_mutable_files": linked_mutable,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("compact")
    pack.add_argument("root", type=Path)
    pack.add_argument("report", type=Path)
    restore = commands.add_parser("materialize")
    restore.add_argument("root", type=Path)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    if args.command == "materialize":
        logger.info("resolver cache materialization: %s files detached", materialize(args.root))
    else:
        report = compact(args.root)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        logger.info("resolver cache compaction: %s", report)


if __name__ == "__main__":
    main()
