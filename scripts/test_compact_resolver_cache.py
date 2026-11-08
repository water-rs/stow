"""Correctness checks for post-resolution cache compaction."""

from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest


class CacheCompaction(unittest.TestCase):
    def test_compaction_preserves_archives_and_mutable_worker_isolation(self):
        compact = runpy.run_path(str(Path(__file__).with_name("compact-resolver-cache.py")))["compact"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "homes"
            archives = []
            indexes = []
            databases = []
            for worker in ("worker-0", "worker-1"):
                home = root / "01-projects" / worker
                archive = home / "registry/cache/crates-io/example-1.0.0.crate"
                archive.parent.mkdir(parents=True)
                archive.write_bytes(b"same immutable crate body")
                archives.append(archive)
                index = home / "registry/index/crates-io/.cache/ex/am/example"
                index.parent.mkdir(parents=True)
                index.write_bytes(worker.encode())
                indexes.append(index)
                database = home / "git/db/example/objects/pack/example.pack"
                database.parent.mkdir(parents=True)
                database.write_bytes(worker.encode())
                databases.append(database)
                for relative in ("registry/src/crates-io/example/src", "git/checkouts/example/revision"):
                    scratch = home / relative
                    scratch.mkdir(parents=True)
                    (scratch / "source.rs").write_text("pub fn example() {}")
            different = archives[1].with_name("different-1.0.0.crate")
            different.write_bytes(b"another immutable crate body")

            report = compact(root)
            self.assertEqual(report["hardlinked_archives"], 1)
            self.assertEqual(report["unique_crate_archives"], 2)
            self.assertEqual(report["removed_scratch_directories"], 4)
            self.assertLess(report["allocated_bytes_after"], report["allocated_bytes_before"])
            self.assertTrue(archives[0].samefile(archives[1]))
            self.assertFalse(archives[0].samefile(different))
            self.assertFalse(indexes[0].samefile(indexes[1]))
            self.assertEqual(indexes[0].read_bytes(), b"worker-0")
            self.assertEqual(indexes[1].read_bytes(), b"worker-1")
            self.assertFalse(databases[0].samefile(databases[1]))
            self.assertEqual(databases[0].read_bytes(), b"worker-0")
            self.assertEqual(databases[1].read_bytes(), b"worker-1")
            self.assertEqual(compact(root)["hardlinked_archives"], 0)

            # The same native tar mechanism Actions cache uses must
            # restore both names without storing the body twice.
            packed = Path(temporary) / "cache.tar"
            subprocess.run(["tar", "-cf", str(packed), "-C", str(root), "."], check=True, timeout=10)
            restored = Path(temporary) / "restored"
            restored.mkdir()
            subprocess.run(["tar", "-xf", str(packed), "-C", str(restored)], check=True, timeout=10)
            restored_archives = [restored / archive.relative_to(root) for archive in archives]
            self.assertTrue(restored_archives[0].samefile(restored_archives[1]))
            self.assertEqual(restored_archives[1].read_bytes(), b"same immutable crate body")

    def test_restored_mutable_files_are_private_before_workers_start(self):
        module = runpy.run_path(str(Path(__file__).with_name("compact-resolver-cache.py")))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "homes"
            mutable = []
            archives = []
            for worker in ("worker-0", "worker-1", "worker-2"):
                home = root / "01-projects" / worker
                for relative in (
                    "registry/index/crates-io/.cache/ex/am/example",
                    "git/db/example/objects/pack/example.pack",
                ):
                    path = home / relative
                    path.parent.mkdir(parents=True)
                    path.write_bytes(b"identical cache data")
                    mutable.append(path.relative_to(root))
                archive = home / "registry/cache/crates-io/example.crate"
                archive.parent.mkdir(parents=True)
                archive.write_bytes(b"immutable archive")
                archives.append(archive.relative_to(root))

            report = module["compact"](root)
            self.assertEqual(report["hardlinked_mutable_files"], len(mutable) - 1)
            self.assertEqual(report["unique_mutable_cache_files"], 1)
            packed = Path(temporary) / "cache.tar"
            subprocess.run(["tar", "-cf", str(packed), "-C", str(root), "."], check=True, timeout=10)
            restored = Path(temporary) / "restored"
            restored.mkdir()
            subprocess.run(["tar", "-xf", str(packed), "-C", str(restored)], check=True, timeout=10)
            self.assertTrue((restored / mutable[0]).samefile(restored / mutable[-1]))
            self.assertEqual(module["materialize"](restored), len(mutable) - 1)
            self.assertEqual(module["materialize"](restored), 0)
            self.assertEqual(len({(restored / path).stat().st_ino for path in mutable}), len(mutable))
            for path in mutable:
                self.assertEqual((restored / path).read_bytes(), b"identical cache data")
            # Write through the inode rather than replacing the path:
            # this would corrupt other workers if a hardlink remained.
            (restored / mutable[0]).write_bytes(b"worker-local update")
            for path in mutable[1:]:
                self.assertEqual((restored / path).read_bytes(), b"identical cache data")
            self.assertTrue((restored / archives[0]).samefile(restored / archives[-1]))

    def test_cold_cache_needs_no_materialization(self):
        module = runpy.run_path(str(Path(__file__).with_name("compact-resolver-cache.py")))
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(module["materialize"](Path(temporary)), 0)

    def test_empty_resolver_root_is_an_error(self):
        compact = runpy.run_path(str(Path(__file__).with_name("compact-resolver-cache.py")))["compact"]
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "no resolver homes"):
                compact(Path(temporary))


if __name__ == "__main__":
    unittest.main()
