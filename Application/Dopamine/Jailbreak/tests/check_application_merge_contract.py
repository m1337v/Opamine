#!/usr/bin/env python3
"""Static contracts for the Opamine-specific portions of the 3.x app port."""

from __future__ import annotations

import io
import json
import plistlib
import re
import subprocess
import sys
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
MAKEFILE = ROOT / "Application/Makefile"
PROJECT = ROOT / "Application/Dopamine.xcodeproj/project.pbxproj"
ENVIRONMENT = ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m"
SETTINGS = ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m"
INFO_PLIST = ROOT / "Application/Dopamine/Info.plist"
SILEO_DEB = ROOT / "Application/Dopamine/Resources/sileo.deb"
SILEO_LOCK = ROOT / "Vendor/sileo.lock.json"
SILEO_SOURCE = ROOT / "Vendor/Sileo"
SILEO_BUILDER = ROOT / "Scripts/build_vendored_sileo.py"
LEGACY_PACKAGE_BUILDER = ROOT / "Scripts/build-fork-packages.sh"
SILEO_RESOURCE_REPO_PATH = "Application/Dopamine/Resources/sileo.deb"
BASEBIN_VERSION = ROOT / "BaseBin/_external/basebin/.version"
ROOTHIDE_VERSION = ROOT / "BaseBin/_external/basebin/.version-roothide"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def package_field(package: Path, field: str) -> str:
    return subprocess.check_output(["dpkg-deb", "-f", str(package), field], text=True).strip()


def check_category_header_registration(project_path: Path) -> None:
    project = plistlib.loads(subprocess.check_output([
        "plutil", "-convert", "xml1", "-o", "-", str(project_path)
    ]))
    objects = project["objects"]
    groups = [item for item in objects.values()
              if item.get("isa") == "PBXGroup" and item.get("path") == "Jailbreak"]
    require(len(groups) == 1, "expected one Jailbreak project group")
    for header in ("DOBootstrapper+RootHide.h", "DOEnvironmentManager+RootHide.h"):
        references = [(key, item) for key, item in objects.items()
                      if item.get("isa") == "PBXFileReference" and item.get("path") == header]
        require(len(references) == 1, f"Xcode must register {header} exactly once")
        reference, item = references[0]
        require(item.get("sourceTree") == "<group>" and
                item.get("lastKnownFileType") == "sourcecode.c.h",
                f"invalid Xcode header reference for {header}")
        require(groups[0].get("children", []).count(reference) == 1,
                f"{header} must belong to the Jailbreak group for header-map resolution")
        require((project_path.parent.parent / "Dopamine/Jailbreak" / header).is_file(),
                f"registered header is absent: {header}")


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


def run_sileo_verifier(mode: str, package: Path | None = None) -> None:
    command = [sys.executable, str(SILEO_BUILDER), mode]
    if package is not None:
        command.append(str(package))
    result = subprocess.run(command, text=True, capture_output=True)
    require(
        result.returncode == 0,
        f"vendored Sileo verification failed ({mode}): {(result.stdout + result.stderr).strip()}",
    )


def check_vendored_sileo_source(lock: dict[str, str], makefile: str) -> None:
    gitmodules = ROOT / ".gitmodules"
    module_path = subprocess.run(
        ["git", "config", "--file", str(gitmodules), "--get-regexp", r"^submodule\..*\.path$"],
        text=True,
        capture_output=True,
    )
    module_url = subprocess.run(
        ["git", "config", "--file", str(gitmodules), "--get-regexp", r"^submodule\..*\.url$"],
        text=True,
        capture_output=True,
    )
    require(module_path.returncode == 0 and "Vendor/Sileo" in module_path.stdout,
            "Sileo source must be registered as the Vendor/Sileo submodule")
    require(module_url.returncode == 0 and lock["fork_repository"] in module_url.stdout,
            "Vendor/Sileo submodule URL must match the pinned fork repository")

    gitlink = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--stage", "--", "Vendor/Sileo"],
        text=True,
        capture_output=True,
    )
    gitlink_fields = gitlink.stdout.split()
    require(gitlink.returncode == 0 and len(gitlink_fields) >= 3 and gitlink_fields[0] == "160000",
            "Vendor/Sileo must be recorded as a git submodule link")
    require(gitlink_fields[1].lower() == lock["fork_revision"].lower(),
            "Vendor/Sileo gitlink must match the pinned fork revision")
    source_head = subprocess.run(
        ["git", "-C", str(SILEO_SOURCE), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
    )
    require(source_head.returncode == 0 and source_head.stdout.strip().lower() == lock["fork_revision"].lower(),
            "checked-out Vendor/Sileo source must match the pinned fork revision")

    sileo_target = "Dopamine/Resources/sileo.deb"
    app_targets = re.findall(
        r"(?m)^build/Build/Products/Debug-iphoneos/Dopamine\.app:\s*(.*)$",
        makefile,
    )
    require(app_targets and all(sileo_target in prerequisites for prerequisites in app_targets),
            "every Dopamine Xcode build path must depend on generated Sileo first")
    require("Dopamine/Resources/sileo.deb: FORCE" in makefile and
            "python3 ../Scripts/build_vendored_sileo.py" in makefile,
            "Application/Makefile must generate Sileo from the pinned vendor source")

    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--error-unmatch", "--", SILEO_RESOURCE_REPO_PATH],
        text=True,
        capture_output=True,
    )
    require(tracked.returncode != 0, "generated sileo.deb must remain untracked source output")
    ignored = subprocess.run(
        ["git", "-C", str(ROOT), "check-ignore", "--no-index", "-q", "--", SILEO_RESOURCE_REPO_PATH],
        text=True,
        capture_output=True,
    )
    require(ignored.returncode == 0, "generated sileo.deb must be ignored by Git")

    legacy_script = LEGACY_PACKAGE_BUILDER.read_text(encoding="utf-8")
    downloaded_sileo_lines = [
        line for line in legacy_script.splitlines()
        if re.search(r"\b(?:curl|wget)\b", line) and re.search(r"sileo", line, flags=re.IGNORECASE)
    ]
    require(not downloaded_sileo_lines, "legacy fork-package script must not download a Sileo binary")
    require("python3 \"$repo_root/Scripts/build_vendored_sileo.py\"" in legacy_script,
            "legacy fork-package script must delegate Sileo to the pinned source builder")
    require('roothide_sha256="06adc371ec37e7356762c875ca682bfb2f9b33a1100fb14168653b7e571ca670"' in legacy_script,
            "legacy fork-package script must retain RootHide Core source pinning")

    run_sileo_verifier("--verify-source")


def main() -> None:
    makefile = MAKEFILE.read_text(encoding="utf-8")
    project = PROJECT.read_text(encoding="utf-8")
    environment = ENVIRONMENT.read_text(encoding="utf-8")
    settings = SETTINGS.read_text(encoding="utf-8")
    info_plist = plistlib.loads(INFO_PLIST.read_bytes())
    lock = json.loads(SILEO_LOCK.read_text(encoding="utf-8"))
    check_category_header_registration(PROJECT)

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
    require(ROOTHIDE_VERSION.read_text(encoding="utf-8").strip() == "29+opamine1", "unexpected RootHide fork revision")
    macro = re.search(r'(?m)^#define SILEO_BUNDLED_VERSION @"([^\"]+)"',
                      (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text(encoding="utf-8"))
    require(macro is not None and macro.group(1) == lock["package_version"],
            "Sileo bundled-version macro must match the pinned vendor manifest")
    check_vendored_sileo_source(lock, makefile)

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
    run_sileo_verifier("--verify-package", SILEO_DEB)
    require(package_field(SILEO_DEB, "Package") == lock["package_id"], "Sileo package identity changed")
    require(package_field(SILEO_DEB, "Version") == lock["package_version"], "Sileo fork version changed")
    require(package_field(SILEO_DEB, "Architecture") == lock["architecture"], "Sileo package architecture changed")
    plist = sileo_info_plist(SILEO_DEB)
    require("CFBundleURLTypes" not in plist and "CFBundleURLSchemes" not in plist, "Sileo URL registration returned")
    require("filza" in plist.get("LSApplicationQueriesSchemes", []), "Sileo Filza query permission was removed")

    print("application merge contracts: PASS")


if __name__ == "__main__":
    main()
