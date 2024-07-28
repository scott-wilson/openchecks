#!/usr/bin/env python3

from __future__ import annotations

import argparse
import enum
import os
import platform
import pathlib
import shutil
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    pass


class ReleaseMode(enum.Enum):
    DEBUG = "debug"
    RELEASE = "release"


def _build(
    cargo_path: pathlib.Path,
    release_mode: ReleaseMode,
    manifest_path: pathlib.Path,
    project_build_root: pathlib.Path,
    current_build_dir: pathlib.Path,
) -> None:
    cargo_target_dir = pathlib.Path(project_build_root) / "target"
    compiled_target_dir = cargo_target_dir / release_mode.value

    args = [
        cargo_path.resolve().as_posix(),
        "build",
        "--manifest-path",
        manifest_path.resolve().as_posix(),
        "--target-dir",
        cargo_target_dir.resolve().as_posix(),
    ]

    if release_mode == ReleaseMode.RELEASE:
        args.append("--release")

    subprocess.run(args, check=True)

    for extension in [".so", ".a", ".dll", ".lib", ".dylib"]:
        for input_path in compiled_target_dir.glob(f"*{extension}"):
            output_path = current_build_dir / input_path.name
            shutil.copy(input_path, output_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("cargo_path", type=pathlib.Path)
    build_parser.add_argument("--manifest-path", type=pathlib.Path, required=True)
    build_parser.add_argument("--project-build-root", type=pathlib.Path, required=True)
    build_parser.add_argument("--current-build-dir", type=pathlib.Path, required=True)
    build_parser.add_argument(
        "--release-mode",
        choices=["debug", "release"],
        default="debug",
    )

    args = parser.parse_args()

    if args.command == "build":
        _build(
            args.cargo_path,
            release_mode=ReleaseMode(args.release_mode),
            manifest_path=args.manifest_path,
            project_build_root=args.project_build_root,
            current_build_dir=args.current_build_dir,
        )
