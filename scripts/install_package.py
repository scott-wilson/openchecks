import argparse
import subprocess
import shlex
import sys

_PACKAGE_NAME_OVERRIDE = {"ninja": {"linux": "ninja-build"}}


def main(package: str):
    package = _PACKAGE_NAME_OVERRIDE.get(package, {}).get(sys.platform, package)

    if sys.platform == "linux":
        cmd = ["apt-get", "install", package]
        subprocess.run(["sudo", "bash", "-c", shlex.join(cmd)], check=True)
    elif sys.platform == "win32":
        subprocess.run(["choco", "install", package], shell=True, check=True)
    elif sys.platform == "darwin":
        subprocess.run(["brew", "install", package], shell=True, check=True)
    else:
        raise NotImplementedError(f"{sys.platform!r} is not supported")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("package")
    args = parser.parse_args()

    main(args.package)
