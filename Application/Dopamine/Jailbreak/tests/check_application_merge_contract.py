#!/usr/bin/env python3
"""Static contracts for the Opamine-specific portions of the 3.x app port."""

from __future__ import annotations

import io
import plistlib
import subprocess
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
MAKEFILE = ROOT / "Application/Makefile"
PROJECT = ROOT / "Application/Dopamine.xcodeproj/project.pbxproj"
ENVIRONMENT = ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m"
SETTINGS = ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m"
INFO_PLIST = ROOT / "Application/Dopamine/Info.plist"
SILEO_DEB = ROOT / "Application/Dopamine/Resources/sileo.deb"
BASEBIN_VERSION = ROOT / "BaseBin/_external/basebin/.version"
ROOTHIDE_VERSION = ROOT / "BaseBin/_external/basebin/.version-roothide"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def package_field(package: Path, field: str) -> str:
    return subprocess.check_output(["dpkg-deb", "-f", str(package), field], text=True).strip()


def sileo_info_plist(package: Path) -> dict:
    payload = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)])
    with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
        member = next(
            item
            for item in archive.getmembers()
            if item.name.lstrip("./") == "Applications/Sileo.app/Info.plist"
        )
        source = archive.extractfile(member)
        require(source is not None, "Sileo Info.plist cannot be read")
        return plistlib.loads(source.read())


def main() -> None:
    makefile = MAKEFILE.read_text(encoding="utf-8")
    project = PROJECT.read_text(encoding="utf-8")
    environment = ENVIRONMENT.read_text(encoding="utf-8")
    settings = SETTINGS.read_text(encoding="utf-8")
    info_plist = plistlib.loads(INFO_PLIST.read_bytes())

    require(
        'plutil -replace CFBundleIdentifier -string "com.m1337v.Opamine"' in makefile,
        "package step must retain the Opamine bundle identity",
    )
    require(
        project.count("PRODUCT_BUNDLE_IDENTIFIER = com.m1337v.Opamine;") == 2,
        "both Dopamine app configurations must retain the Opamine bundle identity",
    )
    require("libroothider.dylib" in makefile, "app packaging must include libroothider")
    require(".version-roothide" in makefile, "app version must include the RootHide revision")
    require(BASEBIN_VERSION.read_text(encoding="utf-8").strip() == "3.0.12", "unexpected basebin version")
    require(ROOTHIDE_VERSION.read_text(encoding="utf-8").strip() == "28+opamine1", "unexpected RootHide fork revision")

    for mode in ("stock", "blacklist", "whitelist", "hiddenwhitelist", "blacklistallowlist"):
        require(f'@"{mode}"' in environment, f"missing RootHide injection mode: {mode}")
    for path in (
        "pro.m1337.inject.mode.plist",
        "pro.m1337.inject.plist",
        "pro.m1337.inject.system.plist",
        "pro.m1337.inject.wantsblacklist.plist",
        "pro.m1337.jetsam.addend.plist",
        "pro.m1337.uninject.plist",
    ):
        require(path in environment, f"missing exact RootHide settings path: {path}")
    require(
        "NSString *path = JBROOT_PATH(relativePath);" in environment
        and "NSString *rootHidePath = JBROOT_PATH(DORootHideDirectoryRelativePath);" in environment,
        "RootHide settings must resolve inside the active randomized root",
    )
    require(
        "ensureRootHideDictionaryExistsAtPath" in environment,
        "per-app RootHide settings must be initialized without replacing existing dictionaries",
    )
    require(
        "DORootHideInjectionModeHiddenWhitelist" in settings
        and "DORootHideInjectionModeBlacklistAllowlist" in settings,
        "settings UI must expose the two fork-specific injection modes",
    )
    if "PHPhotoLibrary" in settings or "UIImagePickerController" in settings:
        require(
            bool(info_plist.get("NSPhotoLibraryUsageDescription")),
            "the retained boot-logo photo picker requires NSPhotoLibraryUsageDescription",
        )

    require(SILEO_DEB.is_file(), "embedded Sileo fork is missing")
    require(package_field(SILEO_DEB, "Package") == "org.coolstar.sileo", "Sileo package identity changed")
    require(package_field(SILEO_DEB, "Version") == "2.5.1-13+opamine1", "Sileo fork version changed")
    require(package_field(SILEO_DEB, "Architecture") == "iphoneos-arm64e", "Sileo package architecture changed")
    plist = sileo_info_plist(SILEO_DEB)
    require("CFBundleURLTypes" not in plist and "CFBundleURLSchemes" not in plist, "Sileo URL registration returned")
    require("filza" in plist.get("LSApplicationQueriesSchemes", []), "Sileo Filza query permission was removed")

    print("application merge contracts: PASS")


if __name__ == "__main__":
    main()
