#!/usr/bin/env python3
"""Reject inference dependencies and unexpected public release assets."""

import argparse
from pathlib import Path
import tomllib


def check_dependencies(lockfile):
    packages = tomllib.loads(Path(lockfile).read_text())["package"]
    for package in packages:
        name = package["name"]
        source = package.get("source", "").lower()
        if name == "biometric-engines-protocol":
            continue
        if (
            "biometric-engines" in source
            or name.startswith(("biometric-engine", "face-engine", "onnxruntime"))
            or name in {"flamingo-verifier-worker", "ort", "ort-sys", "hf-hub"}
        ):
            raise ValueError(f"private inference dependency in public build: {name}")


def release_assets(workload):
    if workload not in {"verifier", "di"}:
        raise ValueError(f"unknown workload: {workload}")
    return {
        f"{workload}-enclave.eif",
        f"{workload}-oci.tar.gz",
        f"{workload}-pcr.json",
        "manifest.json",
    }


def check_assets(directory, workload):
    directory = Path(directory)
    expected = release_assets(workload)
    actual = {path.name for path in directory.iterdir()}
    if actual != expected:
        raise ValueError(
            f"unexpected release contents: extra={sorted(actual - expected)}, "
            f"missing={sorted(expected - actual)}"
        )
    for name in expected:
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"release asset must be a nonempty regular file: {name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lockfile", type=Path, default=Path("Cargo.lock"))
    parser.add_argument("--assets", type=Path)
    parser.add_argument("--workload", choices=("verifier", "di"))
    args = parser.parse_args()
    if args.assets and not args.workload:
        parser.error("--assets requires --workload")
    try:
        check_dependencies(args.lockfile)
        if args.assets:
            check_assets(args.assets, args.workload)
    except (ValueError, OSError, KeyError) as error:
        raise SystemExit(str(error)) from error
