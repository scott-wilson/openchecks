from __future__ import annotations

import pathlib
import argparse
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    pass

_CARGO_PATH = (
    pathlib.Path(__file__).parent.parent.parent / "bindings" / "python" / "Cargo.toml"
)


def main() -> None:
    result = subprocess.run(["git", "rev-parse", "HEAD"], shell=True, check=True)
    git_commit_id = result.stdout.decode().strip()

    with _CARGO_PATH.open(mode="r") as f_in:
        data = f_in.read()

    data = data.replace(
        'base_openchecks = { path = "../../", package = "openchecks" }',
        f'base_openchecks = {{ git = "https://github.com/scott-wilson/openchecks.git", package = "openchecks", rev="{git_commit_id}" }}',
        1,
    )

    with _CARGO_PATH.open(mode="w") as f_out:
        f_out.write(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    args = parser.parse_args()

    main()
