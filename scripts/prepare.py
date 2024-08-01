from __future__ import annotations

import dataclasses
import pathlib
import argparse
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    pass


def main(version: str) -> None:
    version_obj = _parse_version(version)
    project_dir = pathlib.Path(__file__).parent.parent
    cargo_files = [
        project_dir / "bindings" / "c" / "Cargo.toml",
        project_dir / "bindings" / "python" / "Cargo.toml",
        project_dir / "Cargo.toml",
    ]
    meson_files = [
        project_dir / "bindings" / "c" / "meson.build",
        project_dir / "bindings" / "cpp" / "meson.build",
    ]
    pyproject_files = [
        project_dir / "bindings" / "c" / "pyproject.toml",
    ]

    for cargo_file in cargo_files:
        _prepare_cargo_file(version_obj, cargo_file)

    for meson_file in meson_files:
        _prepare_meson_file(version_obj, meson_file)

    for pyproject_file in pyproject_files:
        _prepare_pyproject_file(version_obj, pyproject_file)


@dataclasses.dataclass
class Version:
    major: int
    minor: int
    patch: int
    prerelease: str | None = None

    def __str__(self) -> str:
        version = f"{self.major}.{self.minor}.{self.patch}"

        if self.prerelease:
            version = f"{version}-{self.prerelease}"

        return version

    def to_pyversion(self) -> str:
        version = f"{self.major}.{self.minor}.{self.patch}"
        prerelease = self.prerelease

        if prerelease:
            split = prerelease.split(".", maxsplit=1)
            pre = split[0]

            if pre == "alpha":
                pre = "a"
            elif pre == "beta":
                pre = "b"
            elif pre == "rc":
                pre = "rc"
            else:
                raise NotImplementedError(f"Prerelease {prerelease!r} not implemented.")

            split[0] = pre
            prerelease = "".join(split)
            version = f"{version}.{prerelease}"

        return version


def _parse_version(version: str) -> Version:
    result = re.search(
        r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:alpha|beta|rc)(?:\.(?:0|[1-9]\d*))?))?$",
        version,
    )

    if not result:
        raise ValueError(f"Invalid version: {version}")

    return Version(
        major=int(result.group("major")),
        minor=int(result.group("minor")),
        patch=int(result.group("patch")),
        prerelease=result.group("prerelease"),
    )


def _prepare_pyproject_file(version: Version, pyproject_path: pathlib.Path) -> None:
    with pyproject_path.open(mode="r") as f_in:
        data = f_in.read()

    data = re.sub(
        r"version = .*", f'version = "{version.to_pyversion()}"', data, count=1
    )

    with pyproject_path.open(mode="w") as f_out:
        f_out.write(data)


def _prepare_cargo_file(version: Version, cargo_path: pathlib.Path) -> None:
    with cargo_path.open(mode="r") as f_in:
        data = f_in.read()

    data = re.sub(r"version = .*", f'version = "{version}"', data, count=1)

    with cargo_path.open(mode="w") as f_out:
        f_out.write(data)


def _prepare_meson_file(version: Version, meson_path: pathlib.Path) -> None:
    with meson_path.open(mode="r") as f_in:
        data = f_in.read()

    data = re.sub(r"version: '.*',", f"version: '{version}',", data, count=1)

    with meson_path.open(mode="w") as f_out:
        f_out.write(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    args = parser.parse_args()

    main(args.version)
