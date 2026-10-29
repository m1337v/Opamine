#!/usr/bin/env python3
"""Host contract checks for Scripts/build_vendored_sileo.py."""

from __future__ import annotations

import importlib.util
import json
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
BUILDER_PATH = ROOT / "Scripts/build_vendored_sileo.py"
SPEC = importlib.util.spec_from_file_location("sileo_vendor_builder_test", BUILDER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load production builder: {BUILDER_PATH}")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)
CHECKS = 0


def require(condition: bool, message: str) -> None:
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError(message)


def rejects(operation, message: str) -> None:
    try:
        operation()
    except BUILDER.BuildError as error:
        require(message in str(error), f"expected {message!r}, got {error!r}")
    else:
        raise AssertionError(f"expected BuildError containing {message!r}")


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_source_pin(lock: dict[str, str], temp: Path) -> dict:
    source_bytes = BUILDER.SOURCE_INFO.read_bytes()
    head = BUILDER.run_git("rev-parse", "HEAD")
    source_info = BUILDER.verify_source(lock)
    require(bool(source_info), "valid locked Sileo source should verify")

    payload = json.loads(BUILDER.MANIFEST_PATH.read_text(encoding="utf-8"))
    payload["fork_revision"] = "not-a-full-commit"
    bad_manifest = temp / "bad-lock.json"
    write_json(bad_manifest, payload)
    original_manifest = BUILDER.MANIFEST_PATH
    try:
        BUILDER.MANIFEST_PATH = bad_manifest
        rejects(BUILDER.load_lock, "must be a full Git commit ID")
    finally:
        BUILDER.MANIFEST_PATH = original_manifest

    wrong_pin = dict(lock, fork_revision="0" * len(lock["fork_revision"]))
    rejects(lambda: BUILDER.verify_source(wrong_pin), "does not match the lock manifest")
    require(BUILDER.SOURCE_INFO.read_bytes() == source_bytes, "bad lock mutated vendored source")
    require(BUILDER.run_git("rev-parse", "HEAD") == head, "bad lock changed vendored HEAD")
    return source_info


def test_resolved_pins(temp: Path) -> None:
    revisions = {"alpha": "a" * 40, "beta": "b" * 40}
    schema1_pins = [
        {"package": name, "repositoryURL": f"https://example.test/{name}.git",
         "state": {"revision": revision}}
        for name, revision in revisions.items()
    ]
    schema3_pins = [
        {"identity": name.upper(), "location": f"https://example.test/{name}/",
         "state": {"revision": revision}}
        for name, revision in reversed(list(revisions.items()))
    ]
    schema1, schema3 = temp / "resolved-v1.json", temp / "resolved-v3.json"
    write_json(schema1, {"version": 1, "object": {"pins": schema1_pins}})
    write_json(schema3, {"version": 3, "pins": schema3_pins})
    BUILDER.compare_resolved_pins(schema1, schema3)
    require(True, "SwiftPM schema 1 and 3 semantic pin sequences should match")

    schema3_pins[0]["state"]["revision"] = "c" * 40
    write_json(schema3, {"version": 3, "pins": schema3_pins})
    rejects(lambda: BUILDER.compare_resolved_pins(schema1, schema3), "changed the pinned dependency")


def macho(platform: int) -> bytes:
    # Synthetic header only: the fixture is parsed as data and never executed.
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
    build_version = struct.pack("<IIIIII", 0x32, 24, platform, 0, 0, 0)
    return header + build_version


def test_macho_platforms() -> None:
    BUILDER.verify_ios_executable(macho(2), "synthetic iOS executable")
    require(True, "Mach-O platform 2 should pass")
    rejects(lambda: BUILDER.verify_ios_executable(macho(6), "synthetic Catalyst executable"),
            "must target iOS")


def test_ios_adapter(temp: Path) -> None:
    original = (
        "IOS = xcodebuild -arch $(ARCH) -sdk $(PLATFORM) -derivedDataPath $(SILEOTMP)\n"
        "MAC = xcodebuild -arch $(ARCH) -sdk macosx -derivedDataPath $(SILEOTMP)\n"
    )
    source, exported = temp / "source", temp / "exported"
    source.mkdir()
    exported.mkdir()
    (source / "Makefile").write_text(original, encoding="utf-8")
    makefile = exported / "Makefile"
    makefile.write_text(original, encoding="utf-8")
    BUILDER.apply_ios_destination_build_adapter(exported)
    lines = makefile.read_text(encoding="utf-8").splitlines()
    require("-destination 'generic/platform=iOS'" in lines[0] and "ARCHS=$(ARCH)" in lines[0],
            "iOS export must use destination and ARCHS")
    require("-arch $(ARCH)" not in lines[0] and lines[1] == original.splitlines()[1],
            "adapter should remove -arch only from the iOS stage")
    require((source / "Makefile").read_text(encoding="utf-8") == original,
            "export adapter mutated its source Makefile")


def build_deb(temp: Path, name: str, lock: dict[str, str], source_info: dict,
              *, platform: int = 2, info: dict | None = None,
              version: str | None = None, marketing_version: str | None = None,
              bundle_identifier: str | None = None) -> Path:
    dpkg_deb = shutil.which("dpkg-deb")
    if dpkg_deb is None:
        raise AssertionError("dpkg-deb is required for Debian package fixtures")
    root = temp / f"{name}-root"
    app = root / "Applications/Sileo.app"
    (root / "DEBIAN").mkdir(parents=True)
    app.mkdir(parents=True)
    control = (
        f"Package: {lock['package_id']}\n"
        f"Version: {version or lock['package_version']}\n"
        f"Architecture: {lock['architecture']}\n"
        "Description: temporary Sileo validation fixture\n"
    )
    (root / "DEBIAN/control").write_text(control, encoding="utf-8")
    packaged_info = dict(source_info if info is None else info)
    packaged_info["CFBundleIdentifier"] = bundle_identifier or lock["bundle_identifier"]
    packaged_info["CFBundleShortVersionString"] = marketing_version or lock["marketing_version"]
    (app / "Info.plist").write_bytes(plistlib.dumps(packaged_info))
    executable = app / "Sileo"
    executable.write_bytes(macho(platform))
    executable.chmod(0o755)
    root_helper = app / "giveMeRoot"
    root_helper.write_bytes(b"synthetic helper fixture")
    root_helper.chmod(0o4755)
    package = temp / f"{name}.deb"
    subprocess.run([dpkg_deb, "--build", str(root), str(package)],
                   check=True, capture_output=True, text=True)
    return package


def test_packages(temp: Path, lock: dict[str, str], source_info: dict) -> None:
    valid = build_deb(temp, "valid", lock, source_info)
    BUILDER.verify_package(valid, lock, source_info)
    require(True, "synthetic package fixture with locked metadata and iOS header should pass")

    with_url = dict(source_info)
    with_url["CFBundleURLTypes"] = [{"CFBundleURLSchemes": ["sileo"]}]
    with_url["CFBundleURLSchemes"] = ["sileo"]
    rejects(lambda: BUILDER.verify_package(build_deb(temp, "url", lock, source_info, info=with_url), lock, source_info),
            "still declares URL registration")
    changed_queries = dict(source_info)
    changed_queries[BUILDER.QUERY_SCHEMES_KEY] = ["changed-scheme"]
    rejects(lambda: BUILDER.verify_package(build_deb(temp, "queries", lock, source_info, info=changed_queries), lock, source_info),
            "does not exactly match vendored source")
    rejects(lambda: BUILDER.verify_package(build_deb(temp, "version", lock, source_info, version="0.0"), lock, source_info),
            "Version mismatch")
    rejects(lambda: BUILDER.verify_package(build_deb(temp, "marketing", lock, source_info, marketing_version="0.0"), lock, source_info),
            "CFBundleShortVersionString mismatch")
    rejects(lambda: BUILDER.verify_package(build_deb(temp, "bundle", lock, source_info, bundle_identifier="invalid.bundle"), lock, source_info),
            "CFBundleIdentifier mismatch")
    rejects(lambda: BUILDER.verify_package(build_deb(temp, "catalyst", lock, source_info, platform=6), lock, source_info),
            "must target iOS")

    destination = temp / "existing.deb"
    destination.write_bytes(b"known-good-old-package")
    rejects(lambda: BUILDER.atomic_copy_verified(temp / "version.deb", destination, lock, source_info),
            "Version mismatch")
    require(destination.read_bytes() == b"known-good-old-package",
            "invalid package replaced the existing temporary destination")
    require(not list(temp.glob(".existing.deb.*.tmp")),
            "failed atomic verification left a staged package behind")
    BUILDER.atomic_copy_verified(valid, temp / "accepted.deb", lock, source_info)
    require((temp / "accepted.deb").read_bytes() == valid.read_bytes(),
            "verified synthetic package was not atomically copied")


def test_cli_failure(temp: Path) -> None:
    destination = temp / "existing.deb"
    original = b"old temporary destination bytes"
    destination.write_bytes(original)
    child = r'''import importlib.util, sys
from pathlib import Path
builder_path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("sileo_cli_child", builder_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.BUILD_ROOT = Path(sys.argv[2]) / "build"
module.BUILD_TMP = module.BUILD_ROOT / "sileo"
sys.argv = [str(builder_path), "--destination", sys.argv[3]]
raise SystemExit(module.main())
'''
    env = dict(os.environ, MAKE="/usr/bin/false", PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [sys.executable, "-c", child, str(BUILDER_PATH), str(temp / "cli-work"), str(destination)],
        env=env, capture_output=True, text=True,
    )
    require(result.returncode == 1 and "command failed with exit status 1" in result.stderr,
            f"builder child should fail at MAKE=false, got {result.returncode}: {result.stderr}")
    require(destination.read_bytes() == original,
            "failed CLI build replaced the existing temporary destination")


def test_comparator_link_compatibility(temp: Path) -> None:
    sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
    output = temp / "dpkgversion.o"
    source = BUILDER.SOURCE_ROOT / "Sileo/Backend/C Contrib/dpkgversion.c"
    subprocess.run([
        "xcrun", "--sdk", "iphoneos", "clang", "-O3", "-fno-builtin-strrchr",
        "-arch", "arm64", "-target", "arm64-apple-ios15.0", "-isysroot", sdk,
        "-c", str(source), "-o", str(output),
    ], check=True)
    symbols = subprocess.check_output(["nm", "-u", str(output)], text=True).split()
    require("_memrchr" not in symbols and "_strrchr" in symbols,
            "the optimized comparator must use the available strrchr function")


def test_parent_build_flavor(temp: Path, lock: dict[str, str]) -> None:
    command = []
    original_run, original_tmp = BUILDER.run_checked, BUILDER.BUILD_TMP
    def capture(arguments, **options):
        command.extend(arguments)
        return subprocess.CompletedProcess(arguments, 0)
    try:
        BUILDER.run_checked = capture
        BUILDER.BUILD_TMP = temp / "flavor-cache"
        BUILDER.build_package(lock, BUILDER.SOURCE_ROOT)
    finally:
        BUILDER.run_checked, BUILDER.BUILD_TMP = original_run, original_tmp
    overrides = [argument for argument in command if "=" in argument]
    goal = 'print-vendor-config: ; @printf "%s\\n" "$(SILEO_ID)|$(SILEO_APP)|$(BUILD_CONFIG)|$(PREFIX)|$(ARCH)"'
    actual = subprocess.check_output(
        ["make", "-s", "--no-print-directory", "-C", str(BUILDER.SOURCE_ROOT),
         "--eval", goal, "print-vendor-config", *overrides],
        env=dict(os.environ, NIGHTLY="1", BETA="1", DEBUG="1"), text=True,
    ).strip()
    require(actual == "org.coolstar.sileo|Sileo.app|Release||arm64",
            f"parent build flavor changed the stable Sileo configuration: {actual}")


def main() -> int:
    lock = BUILDER.load_lock()
    with tempfile.TemporaryDirectory(prefix="sileo-vendor-contract-") as directory:
        temp = Path(directory)
        source_info = test_source_pin(lock, temp)
        test_resolved_pins(temp)
        test_macho_platforms()
        test_ios_adapter(temp)
        test_packages(temp, lock, source_info)
        test_comparator_link_compatibility(temp)
        test_parent_build_flavor(temp, lock)
        with tempfile.TemporaryDirectory(prefix="sileo-vendor-cli-") as cli_directory:
            test_cli_failure(Path(cli_directory))
    print(f"PASS: Sileo vendor builder contract ({CHECKS} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
