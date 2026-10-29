#!/usr/bin/env python3
"""UI/package contracts retained from the former WP10 merge coverage."""

from __future__ import annotations

import hashlib
import io
import plistlib
import subprocess
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
SETTINGS = ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m"
BOOTSTRAPPER = ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m"
PROJECT = ROOT / "Application/Dopamine.xcodeproj/project.pbxproj"
INFO = ROOT / "Application/Dopamine/Info.plist"
SILEO_DEB = ROOT / "Application/Dopamine/Resources/sileo.deb"
ROOTHIDE_DEB = ROOT / "Application/Dopamine/Resources/roothide.deb"
BOOTSTRAP = ROOT / "Application/Dopamine/Resources/bootstrap_1900.tar.zst"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def field(package: Path, name: str) -> str:
    return subprocess.check_output(["dpkg-deb", "-f", str(package), name], text=True).strip()


def member(package: Path, member_name: str) -> bytes:
    contents = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)])
    with tarfile.open(fileobj=io.BytesIO(contents)) as archive:
        entry = archive.extractfile(member_name)
        require(entry is not None, f"package member missing: {member_name}")
        return entry.read()


def bootstrap_member(member_name: str) -> bytes:
    contents = subprocess.check_output(["zstd", "-dc", str(BOOTSTRAP)])
    with tarfile.open(fileobj=io.BytesIO(contents)) as archive:
        entry = archive.extractfile(member_name)
        require(entry is not None, f"bootstrap member missing: {member_name}")
        return entry.read()


def main() -> None:
    settings = SETTINGS.read_text(encoding="utf-8")
    bootstrapper = BOOTSTRAPPER.read_text(encoding="utf-8")
    project = PROJECT.read_text(encoding="utf-8")
    info = plistlib.loads(INFO.read_bytes())

    require("PRODUCT_BUNDLE_IDENTIFIER = com.m1337v.Opamine;" in project,
            "Opamine app bundle identity changed")
    require("selectCustomBootlogoPressed" in settings and "UIImagePickerController" in settings,
            "boot-logo photo picker was removed without an intentional replacement")
    require(bool(info.get("NSPhotoLibraryUsageDescription")),
            "boot-logo photo picker must retain its TCC usage string")

    require(SILEO_DEB.is_file() and ROOTHIDE_DEB.is_file(), "bundled fork package missing")
    require(field(SILEO_DEB, "Package") == "org.coolstar.sileo", "Sileo package identity changed")
    require(field(SILEO_DEB, "Version") == "2.5.1-14+opamine1", "Sileo fork version changed")
    require(field(ROOTHIDE_DEB, "Package") == "roothide", "RootHide core package identity changed")
    require(field(ROOTHIDE_DEB, "Version") == "0.1.0-0+opamine1", "RootHide core fork guard changed")

    sileo_plist = plistlib.loads(member(SILEO_DEB, "./Applications/Sileo.app/Info.plist"))
    require("CFBundleURLTypes" not in sileo_plist and "CFBundleURLSchemes" not in sileo_plist,
            "Sileo URL registration returned")
    require("filza" in sileo_plist.get("LSApplicationQueriesSchemes", []),
            "Sileo Filza query permission was removed")

    old_core = member(ROOTHIDE_DEB, "./usr/lib/libroothide.dylib")
    bootstrap_core = bootstrap_member("./usr/lib/libroothide.dylib")
    require(hashlib.sha256(old_core).digest() == hashlib.sha256(bootstrap_core).digest(),
            "fork core payload does not match the bootstrap baseline")
    status = bootstrap_member("./Library/dpkg/status").decode("utf-8")
    require("Package: roothide\n" in status and "Version: 0.1.0\n" in status,
            "expected upstream RootHide bootstrap baseline changed")
    for invariant in (
        'ROOTHIDE_CORE_BUNDLED_VERSION @"0.1.0-0+opamine1"',
        '@"roothide" : ROOTHIDE_CORE_BUNDLED_VERSION',
        'shouldInstallPackage:@"roothide"',
        'stringByAppendingPathComponent:@"roothide.deb"',
        "Failed to install RootHide Core",
    ):
        require(invariant in bootstrapper, f"fork RootHide package update guard missing: {invariant}")

    print("UI and fork package contracts: PASS")


if __name__ == "__main__":
    main()
