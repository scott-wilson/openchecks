from __future__ import annotations

import pathlib
import tarfile
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    pass


def main() -> None:
    paths: list[pathlib.Path] = []
    glob_patterns = [
        "wheels-*/*.whl",
        "wheels-*/*.tar.gz",
        "wheels-*/*.whl.sigstore",
        "wheels-*/*.tar.gz.sigstore",
        "wheels-*/*.whl.sigstore.json",
        "wheels-*/*.tar.gz.sigstore.json",
    ]

    for glob_pattern in glob_patterns:
        paths.extend(pathlib.Path().glob(glob_pattern))

    if not paths:
        logging.info("No paths found. Exiting.")
        return

    with tarfile.open("python-wheels.tar.gz", mode="w:gz") as f_out:
        for path in paths:
            f_out.add(path)

    logging.info("Saved archives to tar")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    main()
