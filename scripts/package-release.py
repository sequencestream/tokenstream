#!/usr/bin/env python3
"""Assemble one platform archive for a GitHub Release."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def main() -> None:
    version = require("VERSION")
    target = require("TARGET")
    asset = require("ASSET")
    archive = require("ARCHIVE")
    binary_name = "tokenstream.exe" if "windows" in target else "tokenstream"
    binary = Path("target") / target / "release" / binary_name
    if not binary.is_file():
        raise SystemExit(f"missing release binary at {binary}")
    page = Path("web/dist")
    if not (page / "index.html").is_file():
        raise SystemExit("missing compiled administration page at web/dist/index.html")

    staging_root = Path("staging")
    bundle = staging_root / f"tokenstream-{version}-{asset}"
    if staging_root.exists():
        shutil.rmtree(staging_root)
    bundle.mkdir(parents=True)
    shutil.copy2(binary, bundle / binary_name)
    shutil.copytree(page, bundle / "admin")

    dist = Path("dist")
    dist.mkdir(exist_ok=True)
    archive_base = dist / f"tokenstream-{version}-{asset}"
    if archive == "zip":
        shutil.make_archive(str(archive_base), "zip", root_dir=staging_root, base_dir=bundle.name)
    elif archive == "tar.gz":
        shutil.make_archive(str(archive_base), "gztar", root_dir=staging_root, base_dir=bundle.name)
    else:
        raise SystemExit(f"unsupported archive type {archive}")


if __name__ == "__main__":
    main()
