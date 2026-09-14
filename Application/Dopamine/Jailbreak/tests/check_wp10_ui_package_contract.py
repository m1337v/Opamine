#!/usr/bin/env python3
"""Host contracts for the bounded WP10 UI and package finalization work."""

from __future__ import annotations

import plistlib
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
SETTINGS = ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m"
ENVIRONMENT = ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m"
PROJECT = ROOT / "Application/Dopamine.xcodeproj/project.pbxproj"
PACKAGE_SCRIPT = ROOT / "Scripts/build-fork-packages.sh"
VERSION_FILE = ROOT / "BaseBin/_external/basebin/.version"
SILEO_DEB = ROOT / "Application/Dopamine/Resources/sileo.deb"
ROOT_HIDE_DEB = ROOT / "Application/Dopamine/Resources/roothide.deb"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def package_field(deb: Path, field: str) -> str:
    return subprocess.check_output(
        ["dpkg-deb", "-f", str(deb), field], text=True
    ).strip()


def semver(value: str) -> tuple[int, ...]:
    match = re.fullmatch(r"(\d+(?:\.\d+)*)", value.strip())
    require(match is not None, f"invalid basebin version: {value!r}")
    return tuple(int(part) for part in match.group(1).split("."))


def main() -> None:
    settings = SETTINGS.read_text(encoding="utf-8")
    environment = ENVIRONMENT.read_text(encoding="utf-8")
    project = PROJECT.read_text(encoding="utf-8")
    package_script = PACKAGE_SCRIPT.read_text(encoding="utf-8")

    # D3's removal-button fix is safe to carry into RootHide: direct deletion
    # is exposed only for an inactive TrollStore environment.  A live
    # randomized root must use the reboot/rejailbreak removal flow.
    require(
        "if (!envManager.isJailbroken && envManager.isInstalledThroughTrollStore && envManager.isBootstrapped) {"
        in settings,
        "remove-jailbreak action is not limited to inactive TrollStore installs",
    )
    require(
        "if (envManager.isBootstrapped) {" in settings,
        "actions section must not appear for an unbootstrapped environment",
    )
    require(
        "if ((envManager.isJailbroken || envManager.isInstalledThroughTrollStore) && envManager.isBootstrapped) {"
        not in settings,
        "unsafe live-jailbreak remove-button condition remains active",
    )
    require(
        "deleteBootstrap" in settings and "locateJailbreakRoot" in settings,
        "RootHide remove action no longer refreshes its randomized-root state",
    )
    require("/var/jb" not in settings, "WP10 UI must not use /var/jb as an internal path")

    # Keep the current Opamine product identity and advertised matrix until
    # device gates prove a capability change.  These strings are intentionally
    # source contracts rather than claims inferred from official Dopamine.
    require(
        "PRODUCT_BUNDLE_IDENTIFIER = com.opa334.Dopamine-roothide;" in project,
        "Opamine bundle identity changed",
    )
    require(
        "iOS 15.0 - 16.5.1 (arm64e)" in environment
        and "iOS 15.0 - 16.7.16 (arm64)" in environment,
        "current Opamine support matrix changed without a device-gated update",
    )

    # The package builder owns the custom versions and source checksums.  Keep
    # the RootHide Core and Sileo pins above their repository source versions.
    package_pins = (
        'sileo_source_version="2.5.1-13"',
        'sileo_fork_version="2.5.1-13+opamine1"',
        'roothide_source_version="0.1.0"',
        'roothide_fork_version="0.1.0-0+opamine1"',
        'sileo_sha256="b23e51371938bb6257ba82abdcdae9a6519755556b874b06672868c64843a0f6"',
        'roothide_sha256="06adc371ec37e7356762c875ca682bfb2f9b33a1100fb14168653b7e571ca670"',
    )
    for pin in package_pins:
        require(pin in package_script, f"package pin disappeared: {pin}")

    require(SILEO_DEB.is_file(), "embedded Sileo package is missing")
    require(
        package_field(SILEO_DEB, "Package") == "org.coolstar.sileo",
        "embedded Sileo package identity changed",
    )
    require(
        package_field(SILEO_DEB, "Version") == "2.5.1-13+opamine1",
        "embedded Sileo fork version changed",
    )
    require(
        package_field(SILEO_DEB, "Architecture") == "iphoneos-arm64e",
        "embedded Sileo architecture changed",
    )
    require(ROOT_HIDE_DEB.is_file(), "embedded RootHide Core package is missing")
    require(
        package_field(ROOT_HIDE_DEB, "Package") == "roothide"
        and package_field(ROOT_HIDE_DEB, "Version") == "0.1.0-0+opamine1"
        and package_field(ROOT_HIDE_DEB, "Architecture") == "iphoneos-arm64e",
        "embedded RootHide Core package pin changed",
    )

    # URL registration is deliberately stripped from Sileo.  Query permission
    # for Filza is retained and is not equivalent to registering a URL scheme.
    with tempfile.TemporaryDirectory(prefix="opamine-wp10-sileo-") as directory:
        subprocess.run(["dpkg-deb", "-x", str(SILEO_DEB), directory], check=True)
        plist_path = Path(directory) / "Applications/Sileo.app/Info.plist"
        require(plist_path.is_file(), "Sileo Info.plist is missing from package")
        plist = plistlib.loads(plist_path.read_bytes())
        require("CFBundleURLTypes" not in plist, "Sileo URL registration keys returned")
        require("CFBundleURLSchemes" not in plist, "Sileo URL scheme registration returned")
        require(
            "filza" in plist.get("LSApplicationQueriesSchemes", []),
            "Sileo Filza query permission was removed",
        )

    # The D3 2.x -> 3.x update guard keys off the basebin version.  A release
    # artifact must therefore sort strictly after official 3.0.9; 3.0.9.1 is
    # the planned Opamine value.  This test intentionally fails until the
    # release owner updates the separately-owned .version file.
    basebin_version = VERSION_FILE.read_text(encoding="utf-8").strip()
    require(
        semver(basebin_version) > semver("3.0.9"),
        f"basebin version {basebin_version} must be above official 3.0.9 before packaging (target 3.0.9.1)",
    )

    print("WP10 UI/package contracts: PASS")


if __name__ == "__main__":
    main()
