#!/usr/bin/env python3
"""Build and verify the vendored Sileo package before embedding it in Opamine."""

from __future__ import annotations

import argparse
import collections
import io
import json
import os
import plistlib
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPO_ROOT / "Vendor/Sileo"
MANIFEST_PATH = REPO_ROOT / "Vendor/sileo.lock.json"
SOURCE_INFO_PATH = Path("Sileo/Info.plist")
SOURCE_INFO = SOURCE_ROOT / SOURCE_INFO_PATH
SOURCE_PROJECT_PATH = Path("Sileo.xcodeproj/project.pbxproj")
DESTINATION = REPO_ROOT / "Application/Dopamine/Resources/sileo.deb"
BUILD_ROOT = REPO_ROOT / ".build"
BUILD_TMP = BUILD_ROOT / "sileo"
RESOLVED_PATH = Path("Sileo.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved")
URL_REGISTRATION_KEYS = ("CFBundleURLTypes", "CFBundleURLSchemes")
QUERY_SCHEMES_KEY = "LSApplicationQueriesSchemes"


class BuildError(Exception):
    """A validation or build step failed with an actionable message."""


def fail(message: str) -> BuildError:
    return BuildError(message)


def run_checked(
    command: list[str], *, cwd: Path | None = None, capture: bool = True
) -> subprocess.CompletedProcess[str]:
    """Run a text command and turn OS/process failures into a clear build error."""
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=True,
            text=True,
            capture_output=capture,
        )
    except FileNotFoundError as error:
        raise fail(f"required command is unavailable: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise fail(f"command failed with exit status {error.returncode}: {shlex.join(command)}{suffix}") from error


def run_git(*arguments: str) -> str:
    result = run_checked(["git", "-C", str(SOURCE_ROOT), *arguments])
    return result.stdout.strip()


def load_lock() -> dict[str, str]:
    if not MANIFEST_PATH.is_file():
        raise fail(f"missing Sileo lock manifest: {MANIFEST_PATH}")
    try:
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise fail(f"cannot read Sileo lock manifest {MANIFEST_PATH}: {error}") from error
    if not isinstance(payload, dict):
        raise fail("Sileo lock manifest must be a JSON object")

    required = (
        "fork_revision",
        "upstream_revision",
        "package_version",
        "marketing_version",
        "bundle_identifier",
        "package_id",
        "architecture",
    )
    values: dict[str, str] = {}
    for key in required:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise fail(f"Sileo lock manifest requires a non-empty string: {key}")
        values[key] = value

    for key in ("fork_revision", "upstream_revision"):
        if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", values[key]):
            raise fail(f"Sileo lock manifest {key} must be a full Git commit ID")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.+-]*", values["package_id"]):
        raise fail("Sileo lock manifest package_id contains invalid characters")
    if not re.fullmatch(r"[A-Za-z0-9.+:~\-]+", values["package_version"]):
        raise fail("Sileo lock manifest package_version contains invalid characters")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", values["architecture"]):
        raise fail("Sileo lock manifest architecture contains invalid characters")
    return values


def read_plist(data: bytes, description: str) -> dict[str, Any]:
    try:
        value = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise fail(f"cannot parse {description}: {error}") from error
    if not isinstance(value, dict):
        raise fail(f"{description} is not a property-list dictionary")
    return value


def verify_source(lock: dict[str, str]) -> dict[str, Any]:
    if not SOURCE_ROOT.is_dir():
        raise fail(f"vendored Sileo checkout is missing: {SOURCE_ROOT}")

    head = run_git("rev-parse", "HEAD")
    if head.lower() != lock["fork_revision"].lower():
        raise fail(
            "vendored Sileo HEAD does not match the lock manifest: "
            f"expected {lock['fork_revision']}, got {head}"
        )

    source_delta = run_git(
        "diff",
        "--name-only",
        lock["upstream_revision"],
        lock["fork_revision"],
        "--",
        ".",
        ":(exclude).github",
    ).splitlines()
    if set(source_delta) != {SOURCE_INFO_PATH.as_posix(), SOURCE_PROJECT_PATH.as_posix()}:
        raise fail(
            "pinned Sileo fork has unexpected source changes outside .github; "
            f"expected only its Info.plist and checked compiler compatibility flag, got {source_delta}"
        )

    upstream_project = run_checked_bytes(
        ["git", "-C", str(SOURCE_ROOT), "show", f"{lock['upstream_revision']}:{SOURCE_PROJECT_PATH.as_posix()}"]
    )
    # Preserve the upstream comparator's C behavior. Clang otherwise optimizes
    # its strrchr call into an unavailable memrchr symbol for iOS. Permit only
    # this exact per-file compiler setting, never arbitrary project changes.
    pattern = rb"(?m)^(\s*[A-F0-9]{24} /\* dpkgversion\.c in Sources \*/ = \{isa = PBXBuildFile; fileRef = [A-F0-9]{24} /\* dpkgversion\.c \*/; )\};$"
    expected_project, count = re.subn(
        pattern, rb'\1settings = {COMPILER_FLAGS = "-fno-builtin-strrchr"; }; };', upstream_project
    )
    if count != 3 or (SOURCE_ROOT / SOURCE_PROJECT_PATH).read_bytes() != expected_project:
        raise fail("Sileo Xcode project differs beyond the checked dpkgversion.c compiler flag")

    status = run_git("status", "--porcelain", "--untracked-files=no")
    if status:
        raise fail("vendored Sileo has tracked worktree changes; commit or discard them before building:\n" + status)

    # Confirm both pins name commits in this checkout before checking ancestry.
    for key in ("fork_revision", "upstream_revision"):
        run_git("cat-file", "-e", f"{lock[key]}^{{commit}}")
    ancestry = subprocess.run(
        [
            "git",
            "-C",
            str(SOURCE_ROOT),
            "merge-base",
            "--is-ancestor",
            lock["upstream_revision"],
            lock["fork_revision"],
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if ancestry.returncode == 1:
        raise fail("locked upstream Sileo revision is not an ancestor of the locked fork revision")
    if ancestry.returncode != 0:
        detail = (ancestry.stderr or ancestry.stdout or "").strip()
        raise fail(f"could not verify Sileo upstream ancestry: {detail or ancestry.returncode}")

    try:
        fork_info = read_plist(SOURCE_INFO.read_bytes(), str(SOURCE_INFO))
    except OSError as error:
        raise fail(f"cannot read vendored Sileo Info.plist: {error}") from error
    upstream_bytes = run_checked_bytes(
        ["git", "-C", str(SOURCE_ROOT), "show", f"{lock['upstream_revision']}:{SOURCE_INFO_PATH.as_posix()}"]
    )
    upstream_info = read_plist(upstream_bytes, "pinned upstream Sileo Info.plist")

    # The fork is allowed to remove only these registration keys. In particular,
    # query schemes, document types, bundle identity, and runtime version remain
    # structurally identical to the pinned upstream source.
    expected_info = dict(upstream_info)
    for key in URL_REGISTRATION_KEYS:
        expected_info.pop(key, None)
    if fork_info != expected_info:
        keys = sorted(key for key in set(fork_info) | set(expected_info) if fork_info.get(key) != expected_info.get(key))
        missing_or_added = [key for key in keys if (key in fork_info) != (key in expected_info)]
        details = ", ".join(keys) if keys else "nested plist value"
        if missing_or_added:
            details += f" (added/removed: {', '.join(missing_or_added)})"
        raise fail(
            "vendored Sileo Info.plist differs from pinned upstream beyond removal of "
            f"{', '.join(URL_REGISTRATION_KEYS)}; differing keys: {details}"
        )
    return fork_info


def normalize_resolved_location(value: Any, description: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise fail(f"Swift package resolved pin has no {description}")
    location = value.strip().rstrip("/")
    if location.lower().endswith(".git"):
        location = location[:-4]
    return location.casefold()


def resolved_pin_set(path: Path) -> collections.Counter[tuple[str, str, str]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise fail(f"cannot read Swift package resolved pins at {path}: {error}") from error
    if not isinstance(payload, dict):
        raise fail(f"Swift package resolved file is not a JSON object: {path}")
    schema = payload.get("version")
    if type(schema) is not int or schema not in (1, 2, 3):
        raise fail(f"unsupported Swift package resolved schema at {path}: {schema!r}")
    if schema == 1:
        object_value = payload.get("object")
        pins = object_value.get("pins") if isinstance(object_value, dict) else None
    else:
        pins = payload.get("pins")
    if not isinstance(pins, list):
        raise fail(f"Swift package resolved file has no pins list: {path}")

    result: collections.Counter[tuple[str, str, str]] = collections.Counter()
    for index, pin in enumerate(pins):
        if not isinstance(pin, dict):
            raise fail(f"invalid Swift package pin {index} in {path}")
        identity = pin.get("package", pin.get("identity"))
        if not isinstance(identity, str) or not identity.strip():
            raise fail(f"Swift package pin {index} in {path} has no package identity")
        location = normalize_resolved_location(
            pin.get("repositoryURL", pin.get("location")), "repositoryURL/location"
        )
        state = pin.get("state")
        revision = state.get("revision") if isinstance(state, dict) else None
        if not isinstance(revision, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", revision):
            raise fail(f"Swift package pin {index} in {path} has no full pinned revision")
        result[(identity.strip().casefold(), location, revision.casefold())] += 1
    return result


def compare_resolved_pins(expected_path: Path, actual_path: Path) -> None:
    expected = resolved_pin_set(expected_path)
    actual = resolved_pin_set(actual_path)
    if actual != expected:
        expected_only = sorted((entry, count) for entry, count in (expected - actual).items())
        actual_only = sorted((entry, count) for entry, count in (actual - expected).items())
        details = []
        if expected_only:
            details.append(f"missing/changed pins: {expected_only}")
        if actual_only:
            details.append(f"added/changed pins: {actual_only}")
        raise fail(
            "SwiftPM changed the pinned dependency revision set in the isolated Sileo build "
            f"({'; '.join(details)})"
        )


def safe_extract_git_archive(archive: tarfile.TarFile, destination: Path) -> None:
    """Extract a pinned git archive while rejecting path escapes and special files."""
    members = archive.getmembers()
    seen: set[str] = set()

    def normalized_parts(parts: tuple[str, ...], *, allow_parent: bool) -> tuple[str, ...]:
        normalized: list[str] = []
        for part in parts:
            if part in ("", "."):
                continue
            if part == "..":
                if not allow_parent or not normalized:
                    raise fail("git archive contains a path escaping the isolated build directory")
                normalized.pop()
            else:
                normalized.append(part)
        return tuple(normalized)

    for member in members:
        member_path = PurePosixPath(member.name)
        if member_path.is_absolute() or ".." in member_path.parts:
            raise fail(f"git archive contains an unsafe path: {member.name}")
        normalized_name = "/".join(normalized_parts(member_path.parts, allow_parent=False))
        if not normalized_name or normalized_name in seen:
            raise fail(f"git archive contains an empty or duplicate path: {member.name}")
        seen.add(normalized_name)
        if member.issym() or member.islnk():
            link_path = PurePosixPath(member.linkname)
            if link_path.is_absolute():
                raise fail(f"git archive contains an absolute link: {member.name}")
            base = () if member.islnk() else tuple(PurePosixPath(normalized_name).parent.parts)
            normalized_parts((*base, *link_path.parts), allow_parent=True)
        elif not (member.isdir() or member.isfile()):
            raise fail(f"git archive contains an unsupported special file: {member.name}")

    destination.mkdir(parents=True, exist_ok=True)
    try:
        if hasattr(tarfile, "data_filter"):
            archive.extractall(destination, members=members, filter="data")
        else:
            archive.extractall(destination, members=members)
    except (OSError, tarfile.TarError, ValueError) as error:
        raise fail(f"cannot extract pinned Sileo git archive: {error}") from error


def export_pinned_source(lock: dict[str, str], destination: Path) -> Path:
    archive_path = destination.parent / "sileo-source.tar"
    command = ["git", "-C", str(SOURCE_ROOT), "archive", "--format=tar", lock["fork_revision"]]
    try:
        with archive_path.open("wb") as output:
            subprocess.run(command, check=True, stdout=output, stderr=subprocess.PIPE)
    except FileNotFoundError as error:
        raise fail("required command is unavailable: git") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode("utf-8", errors="replace").strip() if error.stderr else ""
        suffix = f": {detail}" if detail else ""
        raise fail(f"command failed with exit status {error.returncode}: {shlex.join(command)}{suffix}") from error
    except OSError as error:
        raise fail(f"cannot create pinned Sileo source archive: {error}") from error

    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            safe_extract_git_archive(archive, destination)
    except (tarfile.TarError, OSError) as error:
        raise fail(f"cannot read pinned Sileo source archive: {error}") from error
    return destination


def apply_ios_destination_build_adapter(source_root: Path) -> None:
    makefile = source_root / "Makefile"
    anchor = "-arch $(ARCH) -sdk $(PLATFORM) -derivedDataPath $(SILEOTMP)"
    # Xcode rejects a destination combined with its -arch option. ARCHS is a
    # build setting and retains the upstream arm64 choice without that conflict.
    replacement = "-sdk $(PLATFORM) -destination 'generic/platform=iOS' ARCHS=$(ARCH) -derivedDataPath $(SILEOTMP)"
    try:
        contents = makefile.read_text(encoding="utf-8")
    except OSError as error:
        raise fail(f"cannot read exported Sileo Makefile: {error}") from error
    count = contents.count(anchor)
    if count != 1:
        raise fail(f"expected exactly one iOS xcodebuild adapter anchor in exported Makefile, found {count}")
    try:
        makefile.write_text(contents.replace(anchor, replacement, 1), encoding="utf-8")
    except OSError as error:
        raise fail(f"cannot apply isolated iOS destination adapter: {error}") from error


def macho_platforms(data: bytes) -> set[int]:
    """Read platform IDs from thin or universal Mach-O load commands."""
    if len(data) < 4:
        raise fail("Sileo executable is too short to be a Mach-O binary")
    magic = data[:4]
    fat_magics = {
        b"\xca\xfe\xba\xbe": (">", False),
        b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True),
        b"\xbf\xba\xfe\xca": ("<", True),
    }
    if magic in fat_magics:
        endian, fat64 = fat_magics[magic]
        if len(data) < 8:
            raise fail("Sileo universal Mach-O header is truncated")
        count = struct.unpack_from(endian + "I", data, 4)[0]
        record_size = 32 if fat64 else 20
        if count == 0 or 8 + count * record_size > len(data):
            raise fail("Sileo universal Mach-O architecture table is invalid")
        platforms: set[int] = set()
        for index in range(count):
            offset = 8 + index * record_size
            if fat64:
                _, _, slice_offset, slice_size, _, _ = struct.unpack_from(endian + "iiQQII", data, offset)
            else:
                _, _, slice_offset, slice_size, _ = struct.unpack_from(endian + "iiIII", data, offset)
            end = slice_offset + slice_size
            if slice_size == 0 or end > len(data):
                raise fail("Sileo universal Mach-O slice is out of bounds")
            platforms.update(macho_platforms(data[slice_offset:end]))
        return platforms

    thin_magics = {
        b"\xce\xfa\xed\xfe": ("<", 28),
        b"\xfe\xed\xfa\xce": (">", 28),
        b"\xcf\xfa\xed\xfe": ("<", 32),
        b"\xfe\xed\xfa\xcf": (">", 32),
    }
    if magic not in thin_magics:
        raise fail("Sileo executable is not a recognized Mach-O binary")
    endian, header_size = thin_magics[magic]
    if len(data) < header_size:
        raise fail("Sileo Mach-O header is truncated")
    command_count = struct.unpack_from(endian + "I", data, 16)[0]
    command_offset = header_size
    platforms: set[int] = set()
    for _ in range(command_count):
        if command_offset + 8 > len(data):
            raise fail("Sileo Mach-O load command is truncated")
        command, command_size = struct.unpack_from(endian + "II", data, command_offset)
        if command_size < 8 or command_offset + command_size > len(data):
            raise fail("Sileo Mach-O load command has an invalid size")
        if command == 0x32:  # LC_BUILD_VERSION
            if command_size < 24:
                raise fail("Sileo LC_BUILD_VERSION command is truncated")
            platforms.add(struct.unpack_from(endian + "I", data, command_offset + 8)[0])
        elif command == 0x25:  # LC_VERSION_MIN_IPHONEOS
            platforms.add(2)
        command_offset += command_size
    return platforms


def verify_ios_executable(data: bytes, description: str) -> None:
    platforms = macho_platforms(data)
    if platforms != {2}:
        names = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "Mac Catalyst"}
        found = sorted(names.get(platform, f"platform {platform}") for platform in platforms)
        raise fail(f"{description} must target iOS (platform 2), got {found or 'no platform load command'}")


def deb_field(package: Path, field: str) -> str:
    result = run_checked(["dpkg-deb", "-f", str(package), field])
    return result.stdout.strip()


def normalize_member_name(name: str) -> str:
    path = PurePosixPath(name)
    if path.is_absolute():
        return ""
    return "/".join(part for part in path.parts if part not in ("", "."))


def find_member(archive: tarfile.TarFile, path: str) -> tarfile.TarInfo:
    found = [member for member in archive.getmembers() if normalize_member_name(member.name) == path]
    if len(found) != 1:
        raise fail(f"Sileo Debian data archive must contain exactly one {path}; found {len(found)}")
    return found[0]


def read_member(archive: tarfile.TarFile, member: tarfile.TarInfo, description: str) -> bytes:
    if not member.isfile():
        raise fail(f"Sileo package member is not a regular file: {description}")
    stream = archive.extractfile(member)
    if stream is None:
        raise fail(f"cannot read Sileo package member: {description}")
    with stream:
        return stream.read()


def verify_package(package: Path, lock: dict[str, str], source_info: dict[str, Any]) -> None:
    if not package.is_file():
        raise fail(f"Sileo Debian package is missing: {package}")
    for field, key in (("Package", "package_id"), ("Version", "package_version"), ("Architecture", "architecture")):
        actual = deb_field(package, field)
        expected = lock[key]
        if actual != expected:
            raise fail(f"Sileo package {field} mismatch: expected {expected}, got {actual or 'missing'}")

    result = run_checked_bytes(["dpkg-deb", "--fsys-tarfile", str(package)])
    try:
        with tarfile.open(fileobj=io.BytesIO(result), mode="r:*") as archive:
            info_member = find_member(archive, "Applications/Sileo.app/Info.plist")
            executable_member = find_member(archive, "Applications/Sileo.app/Sileo")
            root_member = find_member(archive, "Applications/Sileo.app/giveMeRoot")
            packaged_info = read_plist(
                read_member(archive, info_member, info_member.name),
                "Sileo package Applications/Sileo.app/Info.plist",
            )
            if not executable_member.isfile() or executable_member.mode & 0o111 == 0:
                raise fail("Sileo package executable is missing or not executable")
            verify_ios_executable(
                read_member(archive, executable_member, executable_member.name),
                "Sileo package executable",
            )
            if not root_member.isfile() or root_member.mode & 0o7777 != 0o4755:
                raise fail("Sileo package giveMeRoot must be a regular file with mode 4755")
    except (tarfile.TarError, OSError) as error:
        raise fail(f"cannot read Sileo package data archive: {error}") from error

    remaining_url_keys = [key for key in URL_REGISTRATION_KEYS if key in packaged_info]
    for key, expected in (("CFBundleIdentifier", lock["bundle_identifier"]),
                          ("CFBundleShortVersionString", lock["marketing_version"])):
        if packaged_info.get(key) != expected:
            raise fail(f"Sileo package {key} mismatch: expected {expected}, got {packaged_info.get(key)!r}")
    if remaining_url_keys:
        raise fail("Sileo package Info.plist still declares URL registration: " + ", ".join(remaining_url_keys))

    source_has_queries = QUERY_SCHEMES_KEY in source_info
    package_has_queries = QUERY_SCHEMES_KEY in packaged_info
    if source_has_queries != package_has_queries or packaged_info.get(QUERY_SCHEMES_KEY) != source_info.get(QUERY_SCHEMES_KEY):
        raise fail("Sileo package LSApplicationQueriesSchemes does not exactly match vendored source")


def run_checked_bytes(command: list[str]) -> bytes:
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError as error:
        raise fail(f"required command is unavailable: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode("utf-8", errors="replace").strip() if error.stderr else ""
        suffix = f": {detail}" if detail else ""
        raise fail(f"command failed with exit status {error.returncode}: {shlex.join(command)}{suffix}") from error
    return result.stdout


def build_package(lock: dict[str, str], source_root: Path) -> Path:
    try:
        make_command = shlex.split(os.environ.get("MAKE", "make"))
    except ValueError as error:
        raise fail(f"invalid MAKE environment value: {error}") from error
    if not make_command:
        raise fail("MAKE environment value is empty")

    BUILD_TMP.mkdir(parents=True, exist_ok=True)
    command = [
        *make_command,
        "package",
        "SILEO_PLATFORM=iphoneos-arm64e",
        f"SILEO_VERSION={lock['package_version']}",
        f"SILEOTMP={BUILD_TMP}",
    ]
    # Always invoke the source builder. An existing package is never a fallback
    # for a failed build, and the app resource is replaced only after validation.
    run_checked(command, cwd=source_root, capture=False)
    filename = f"{lock['package_id']}_{lock['package_version']}_{lock['architecture']}.deb"
    return source_root / "packages" / filename


def atomic_copy_verified(package: Path, destination: Path, lock: dict[str, str], source_info: dict[str, Any]) -> None:
    temporary_path: Path | None = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            with package.open("rb") as source:
                shutil.copyfileobj(source, temporary)
            temporary.flush()
            os.fsync(temporary.fileno())
        shutil.copymode(package, temporary_path)
        # Verify the staged bytes themselves before replacing the known-good
        # destination, so a copy error cannot publish an unverified archive.
        verify_package(temporary_path, lock, source_info)
        os.replace(temporary_path, destination)
        temporary_path = None
    except OSError as error:
        raise fail(f"cannot atomically install verified Sileo package at {destination}: {error}") from error
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify-source", action="store_true", help="validate the pinned fork source only")
    mode.add_argument("--verify-package", metavar="PATH", type=Path, help="validate an existing Sileo .deb only")
    parser.add_argument(
        "--destination",
        type=Path,
        default=DESTINATION,
        help=f"generated app resource destination (default: {DESTINATION})",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        lock = load_lock()
        source_info = verify_source(lock)
        if arguments.verify_source:
            print(f"Sileo source verified at {lock['fork_revision']}")
            return 0
        if arguments.verify_package is not None:
            verify_package(arguments.verify_package.resolve(), lock, source_info)
            print(f"Sileo package verified: {arguments.verify_package}")
            return 0

        BUILD_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="sileo-source-", dir=BUILD_ROOT) as temporary_directory:
            source_root = Path(temporary_directory) / "source"
            export_pinned_source(lock, source_root)
            apply_ios_destination_build_adapter(source_root)
            vendored_resolved = SOURCE_ROOT / RESOLVED_PATH
            exported_resolved = source_root / RESOLVED_PATH
            compare_resolved_pins(vendored_resolved, exported_resolved)

            package = build_package(lock, source_root)
            compare_resolved_pins(vendored_resolved, exported_resolved)
            staged_executable = BUILD_TMP / "stage/Applications/Sileo.app/Sileo"
            try:
                staged_executable_bytes = staged_executable.read_bytes()
            except OSError as error:
                raise fail(f"Sileo iOS build output is missing: {staged_executable}: {error}") from error
            verify_ios_executable(staged_executable_bytes, "built Sileo executable")
            source_info = verify_source(lock)
            verify_package(package, lock, source_info)
            destination = arguments.destination.absolute()
            atomic_copy_verified(package, destination, lock, source_info)
        print(f"Built and installed verified Sileo package at {arguments.destination}")
        return 0
    except BuildError as error:
        print(f"build_vendored_sileo: error: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"build_vendored_sileo: error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
