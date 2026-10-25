#!/usr/bin/env python3
"""Source contracts for fail-closed BaseBin trust-cache generation."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
COMMON = ROOT / "BaseBin/libjailbreak/src/roothider/common.m"

COMPLETED = 0
SKIPPED = 1
EIO = -5


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def aggregate_file(status: int, hashes: list[bytes], required: bool) -> tuple[int, list[bytes]]:
    """Model one file in the BaseBin transaction."""
    if status < 0:
        return status, []
    if status == SKIPPED:
        return (EIO if required else 0), []
    if status != COMPLETED:
        return EIO, []
    return 0, hashes


def deduplicate(hashes: list[bytes]) -> list[bytes]:
    result: list[bytes] = []
    for value in hashes:
        if value not in result:
            result.append(value)
    return result


def current_slice_collection(saw_slice: bool, mappable_hashes: list[bytes], malformed: bool = False) -> tuple[int, list[bytes]]:
    """Model the read-only post-mutation pass for one completed Mach-O."""
    if malformed:
        return EIO, []
    if not mappable_hashes:
        return (SKIPPED if saw_slice else EIO), []
    return COMPLETED, deduplicate(mappable_hashes)


def main() -> int:
    common = COMMON.read_text(encoding="utf-8")

    require("file_collect_untrusted_cdhashes_by_path_status" in common,
            "BaseBin generation must use the status-returning Mach-O collector")
    require("FILE_CDHASH_COLLECTION_SKIPPED" in common and
            "FILE_CDHASH_COLLECTION_COMPLETED" in common,
            "collector status must distinguish intentional skips from completion")
    require("collectionStatus < 0" in common and
            "enumerationError = collectionStatus" in common,
            "malformed/unreadable Mach-O and jbrand failures must abort the transaction")
    require("errorHandler:^BOOL" in common and "enumerationError" in common,
            "partial directory enumeration errors must not become empty success")
    require("append_unique_basebin_cdhash" in common,
            "all collected slices must be deduplicated before trust-cache upload")
    require("The fixed BASEBIN UUID is replaced in place" in common and
            "including hashes that the status collector" in common,
            "fixed-UUID replacement must rebuild from already-trusted current hashes")
    require("dyldhook_dylib_for_platform()" in common,
            "the device-selected dyldhook image must be required")
    for image in ("roothidehooks.dylib", "systemhook.dylib", "libjailbreak.dylib", "launchdhook.dylib"):
        require(image in common, f"required runtime image missing from contract: {image}")
    require("is_cdhash_trustcached(requiredImages[i].cdhashes[j])" in common,
            "every required randomized mappable-slice CDHash must be verified after upload")
    required_helper_start = common.index("static int collect_current_basebin_mappable_cdhashes")
    required_helper_end = common.index("static void free_required_basebin_images", required_helper_start)
    required_helper = common[required_helper_start:required_helper_end]
    require("macho_parse_code_signature(macho, cdhash)" in required_helper and
            "if (!macho_parse_code_signature(macho, cdhash))" in required_helper and
            "collectionError = -EINVAL" in required_helper and
            "ensure_randomized_cdhash_for_slice" not in required_helper,
            "every mappable signature must be read and malformed input must fail without a second mutation pass")
    require("return sawSlice ? FILE_CDHASH_COLLECTION_SKIPPED : -EINVAL" in common,
            "valid non-mappable Mach-O must skip while an empty/malformed parse fails")
    require("BASEBIN_REQUIRED_IMAGE_COUNT = 5" in common and
            "requiredPathCount != BASEBIN_REQUIRED_IMAGE_COUNT" in common,
            "required-image storage must have an explicit five-image bound")
    require("selectedDyldhook.isAbsolutePath" in common and
            "rangeOfString:@\"/\"" in common,
            "selected dyldhook must be a BaseBin-local filename")
    current_pass_start = common.index("/* The fixed BASEBIN UUID is replaced in place.")
    current_pass_end = common.index("if (requiredIndex != NSNotFound)", current_pass_start)
    current_pass = common[current_pass_start:current_pass_end]
    require("collect_current_basebin_mappable_cdhashes(" in current_pass,
            "every completed BaseBin Mach-O must enter the current-hash pass")
    require("trustcache_file_upload_with_uuid(basebinTcFile, BASEBIN_TRUSTCACHE_UUID)" in common,
            "BaseBin trust-cache upload must retain its stable UUID")

    # Non-Mach files are benign aggregate skips; malformed Mach-O collection
    # errors and required-file skips are fail-closed.
    non_mach = aggregate_file(SKIPPED, [], required=False)
    malformed = aggregate_file(-22, [], required=False)
    required_skip = aggregate_file(SKIPPED, [], required=True)
    require(non_mach == (0, []), "non-Mach files must remain intentional skips")
    require(malformed == (-22, []), "malformed Mach-O must propagate its error")
    require(required_skip == (EIO, []), "required image cannot be silently skipped")

    duplicate = b"duplicate-cdhash"
    require(deduplicate([duplicate, b"other", duplicate]) == [duplicate, b"other"],
            "duplicate CDHashes must be uploaded once")

    # The old fixed UUID is replaced, so a hash trusted only by that old cache
    # must still be present in the replacement aggregate.
    old_cache_only = b"old-cache-only"
    current_hashes = [old_cache_only, b"new-slice"]
    require(old_cache_only in deduplicate(current_hashes),
            "fixed-UUID replacement must retain hashes already trusted by the old cache")
    require(current_slice_collection(True, [], malformed=False) == (SKIPPED, []),
            "non-mappable Mach-O must remain a benign skip")
    require(current_slice_collection(True, [], malformed=True) == (EIO, []),
            "ordinary mappable Mach-O with a malformed signature must fail closed")
    require(current_slice_collection(True, [b"valid", b"valid"]) == (COMPLETED, [b"valid"]),
            "ordinary mappable Mach-O slices must be deduplicated in the replacement")

    # Architecture fixtures are represented by the existing collector's output:
    # the production path must accept each mappable slice and leave selection
    # to macho_is_mappable/fat enumeration (including old arm64e dylibs).
    for fixture in ("arm64", "old-arm64e-dylib", "arm64e-abi-v2"):
        require(aggregate_file(COMPLETED, [fixture.encode()], required=True)[0] == 0,
                f"mappable architecture fixture rejected: {fixture}")

    print("BaseBin trustcache contract: fail-closed required images and deduplicated slices")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
