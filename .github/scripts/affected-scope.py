#!/usr/bin/env python3
"""Derive per-job scope outputs from a lexoliu/affected-crates JSON report.

Reads the JSON report emitted by `affected-crates` and writes `GITHUB_OUTPUT`
variables for `test.yml` and `release-gate.yml`, filtering doc-test targets to
packages that actually declare a library target and resolving each
`release-gate` leg's precise dependency boundary.

Any missing or malformed report fails loudly rather than silently narrowing.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
from pathlib import Path

LIB_KINDS = {"lib", "rlib", "proc-macro"}

TRAFFIC_COST_PACKAGES = {
    "stow-edge",
    "stow-admin",
    "stow-mock-registry",
    "stow-types",
    "stow-oci",
    "stow-shim",
}

PREHEAT_COST_PACKAGES = TRAFFIC_COST_PACKAGES | {"stow-resolver"}

MOCK_E2E_PACKAGES = PREHEAT_COST_PACKAGES | {"stow-cli", "stow-build"}

MOCK_E2E_EXTRA_GLOBS = (
    "scripts/mock-e2e.sh",
    "scripts/gate-tools.sh",
    ".github/actions/gate-tools/**",
    ".github/actions/install-skyzen-cli/**",
    ".github/actions/link-with-mold/**",
    ".github/workflows/release-gate.yml",
    "edge/Skyzen.mock.toml",
    "ci/glibc-sysroot-debs.txt",
)

TRAFFIC_COST_EXTRA_GLOBS = (
    "launch-model.toml",
    "scripts/traffic-cost.sh",
    "scripts/traffic-cost/**",
    "scripts/gate-tools.sh",
    ".github/actions/gate-tools/**",
    ".github/actions/install-skyzen-cli/**",
    ".github/actions/link-with-mold/**",
    ".github/workflows/release-gate.yml",
    "edge/Skyzen*.toml",
)

PREHEAT_COST_EXTRA_GLOBS = (
    "preheat/**",
    "launch-model.toml",
    "scripts/preheat-cost.sh",
    "scripts/production-wave.sh",
    "scripts/gate-tools.sh",
    ".github/actions/gate-tools/**",
    ".github/actions/install-skyzen-cli/**",
    ".github/actions/link-with-mold/**",
    ".github/workflows/release-gate.yml",
    "edge/Skyzen*.toml",
)

RELEASE_FLOW_EXTRA_GLOBS = (
    "scripts/release-*",
    "scripts/gate-tools.sh",
    ".github/actions/gate-tools/**",
    "release-plz.toml",
    "dist-workspace.toml",
    ".github/workflows/release.yml",
    ".github/workflows/release-plz.yml",
    ".github/workflows/release-gate.yml",
)


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout


def changed_files(base: str, head: str) -> list[str]:
    if not base:
        return []
    merge_base = git("merge-base", base, head).strip()
    out = git("diff", "--no-renames", "--name-only", "-z", merge_base, head)
    return [p for p in out.split("\0") if p]


def library_packages(manifest_path: str) -> set[str]:
    raw = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--manifest-path", manifest_path],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    meta = json.loads(raw)
    member_ids = set(meta["workspace_members"])
    libs: set[str] = set()
    for pkg in meta["packages"]:
        if pkg["id"] not in member_ids:
            continue
        for target in pkg.get("targets", []):
            if any(kind in LIB_KINDS for kind in target.get("kind", [])):
                libs.add(pkg["name"])
                break
    return libs


def matches_any(paths: list[str], globs: tuple[str, ...]) -> bool:
    for path in paths:
        for pattern in globs:
            if pattern.endswith("/**"):
                prefix = pattern[:-3]
                if path == prefix or path.startswith(prefix + "/"):
                    return True
            elif fnmatch.fnmatch(path, pattern):
                return True
    return False


def has_admin_code_or_manifest_change(paths: list[str]) -> bool:
    return any(
        path.startswith("admin/src/")
        or path in ("admin/Cargo.toml", "admin/build.rs", "Cargo.toml", "Cargo.lock")
        for path in paths
    )


def bool_str(value: bool) -> str:
    return "true" if value else "false"


def emit(outputs: dict[str, str]) -> None:
    github_output = os.environ.get("GITHUB_OUTPUT")
    lines = [f"{k}={v}" for k, v in outputs.items()]
    if github_output:
        with open(github_output, "a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
    else:
        for line in lines:
            print(line)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-file", required=True)
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--manifest-path", default="Cargo.toml")
    parser.add_argument("--version-only", default="false")
    args = parser.parse_args()

    if args.version_only == "true":
        emit(
            {
                "packages": "",
                "package-args": "",
                "doc-package-args": "",
                "workspace": "false",
                "has-scope": "false",
                "wasm-edge": "false",
                "edge-idle": "false",
                "release-mock-e2e": "false",
                "release-traffic-cost": "false",
                "release-preheat-cost": "false",
                "release-flow": "false",
                "tools-variants": "[]",
                "has-tools": "false",
            }
        )
        return

    report_text = Path(args.report_file).read_text(encoding="utf-8").strip()
    if not report_text:
        sys.exit("empty affected-crates report")
    report = json.loads(report_text)

    workspace = bool(report["workspace"])
    affected = list(report.get("affected", []))
    affected_set = set(affected)
    packages = str(report.get("packages", ""))
    package_args = str(report.get("package_args", ""))

    if workspace:
        doc_package_args = ""
    else:
        libs = library_packages(args.manifest_path)
        doc_pkgs = [pkg for pkg in affected if pkg in libs]
        doc_package_args = " ".join(f"-p {pkg}" for pkg in doc_pkgs)

    has_scope = workspace or bool(affected)
    wasm_edge = workspace or ("stow-edge" in affected_set)
    edge_idle = wasm_edge

    paths = changed_files(args.base, args.head)
    ci_direct = any(p == "ci" or p.startswith("ci/") for p in paths)
    admin_direct = has_admin_code_or_manifest_change(paths)

    # `stow-admin` is added by affected-rules.toml whenever workflow YAML files
    # change so test.yml runs admin's workflow validation tests; in release-gate
    # only actual `admin/` / `Cargo.*` changes or the leg's own files require
    # running the slow mock-stack lanes.
    effective_cost_pkgs = {
        pkg
        for pkg in affected_set
        if pkg != "stow-admin" or admin_direct
    }

    if workspace:
        release_mock_e2e = True
        release_traffic_cost = True
        release_preheat_cost = True
        release_flow = True
    else:
        release_mock_e2e = bool(
            (effective_cost_pkgs & MOCK_E2E_PACKAGES)
            or matches_any(paths, MOCK_E2E_EXTRA_GLOBS)
        )
        release_traffic_cost = bool(
            (effective_cost_pkgs & TRAFFIC_COST_PACKAGES)
            or ci_direct
            or matches_any(paths, TRAFFIC_COST_EXTRA_GLOBS)
        )
        release_preheat_cost = bool(
            (effective_cost_pkgs & PREHEAT_COST_PACKAGES)
            or ci_direct
            or matches_any(paths, PREHEAT_COST_EXTRA_GLOBS)
        )
        release_flow = bool(
            ci_direct
            or ("stow-types" in affected_set)
            or matches_any(paths, RELEASE_FLOW_EXTRA_GLOBS)
        )

    variants: list[str] = []
    if release_traffic_cost or release_flow:
        variants.append("production")
    if release_preheat_cost:
        variants.append("preheat")
    if release_mock_e2e:
        variants.append("mock")

    emit(
        {
            "packages": packages,
            "package-args": package_args,
            "doc-package-args": doc_package_args,
            "workspace": bool_str(workspace),
            "has-scope": bool_str(has_scope),
            "wasm-edge": bool_str(wasm_edge),
            "edge-idle": bool_str(edge_idle),
            "release-mock-e2e": bool_str(release_mock_e2e),
            "release-traffic-cost": bool_str(release_traffic_cost),
            "release-preheat-cost": bool_str(release_preheat_cost),
            "release-flow": bool_str(release_flow),
            "tools-variants": json.dumps(variants),
            "has-tools": bool_str(bool(variants)),
        }
    )


if __name__ == "__main__":
    main()
