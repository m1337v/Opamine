#!/usr/bin/env python3
"""Host/source-level characterization of trustcache upload geometry.

The production uploader depends on iOS kernel primitives, so compiling or
mocking the whole uploader on a host would produce misleading coverage. This
lane instead executes the pure size/offset model and statically checks that
the production source uses the model's bounded payload write in the
same-size replacement branch.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "BaseBin/libjailbreak/src/trustcache.c"

FILE_HEADER_SIZE = 24  # packed version (4) + UUID (16) + length (4)
ENTRY_SIZE = 22  # packed 20-byte cdhash + hash type + flags
MAX_ALLOCATION = 0x4000
UINT32_MAX = (1 << 32) - 1
SIZE_MAX = (1 << 64) - 1


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def source_text() -> str:
    require(SOURCE.is_file(), f"missing production source: {SOURCE}")
    return SOURCE.read_text(encoding="utf-8")


@dataclass(frozen=True)
class Geometry:
    """Checked equivalent of the uploader's allocation-size arithmetic."""

    head_size: int
    entry_count: int

    @property
    def file_size(self) -> int:
        return FILE_HEADER_SIZE + self.entry_count * ENTRY_SIZE

    @property
    def allocation_size(self) -> int:
        return self.head_size + self.file_size

    @property
    def payload_write_size(self) -> int:
        return self.allocation_size - self.head_size


def checked_geometry(head_size: int, entry_count: int) -> Geometry | None:
    """Return valid uint32-count/uint64-size geometry, or None on overflow."""

    if head_size < 0 or entry_count < 0 or entry_count > UINT32_MAX:
        return None
    file_size = FILE_HEADER_SIZE + entry_count * ENTRY_SIZE
    allocation_size = head_size + file_size
    if file_size > SIZE_MAX or allocation_size > SIZE_MAX:
        return None
    return Geometry(head_size, entry_count)


def file_geometry_valid(actual_size: int, claimed_count: int) -> bool:
    """Model trustcache_file_build_from_path's exact file-size check."""

    expected = checked_geometry(0, claimed_count)
    return (expected is not None and actual_size >= FILE_HEADER_SIZE and
            actual_size == expected.file_size)


def classify_replacement(head_size: int, previous_count: int,
                         replacement_count: int) -> str:
    """Model the branch selected after both allocation sizes are computed."""

    previous = checked_geometry(head_size, previous_count)
    replacement = checked_geometry(head_size, replacement_count)
    if previous is None or replacement is None:
        return "malformed-or-overflow"
    if replacement.allocation_size > MAX_ALLOCATION:
        return "rejected-over-limit"
    if previous.allocation_size == replacement.allocation_size:
        return "same-size"
    if replacement_count > previous_count:
        return "grow"
    return "shrink"


def check_source_contract(text: str) -> None:
    """Pin the one production write whose bound this lane characterizes."""

    same_size = re.search(
        r"if\s*\(previousTcSize\s*==\s*tcSize\)\s*\{(?P<body>.*?)\n\s*\}",
        text,
        flags=re.DOTALL,
    )
    require(same_size is not None, "same-size replacement branch is missing")
    # The branch now contains nested snapshot/restore checks, so inspect its
    # full source span through the distinct-size replacement comment instead
    # of stopping at the first nested closing brace.
    branch_start = same_size.start()
    branch_end = text.index("/* Publish a complete replacement", branch_start)
    body = text[branch_start:branch_end]
    require(
        re.search(
            r"kwritebuf\s*\(\s*existingTcFile\s*,\s*tc\s*,\s*payloadSize\s*\)",
            body,
        ) is not None and
        re.search(
            r"kwritebuf\s*\(\s*existingTcFile\s*,\s*previousPayload\s*,\s*payloadSize\s*\)",
            body,
        ) is not None and
        "size_t payloadSize = (size_t)(tcSize - ksizeof(trustcache));" in text,
        "same-size replacement and restore must write only the trustcache file payload",
    )
    require(
        re.search(
            r"kwritebuf\s*\(\s*tcFileKaddr\s*,\s*tc\s*,\s*"
            r"tcSize\s*-\s*ksizeof\s*\(\s*trustcache\s*\)\s*\)",
            text,
        ) is not None,
        "new allocation path must retain its payload-sized write",
    )
    require(
        "s.st_size < (off_t)sizeof(trustcache_file_v1)" in text,
        "file loader must reject inputs shorter than its packed header",
    )
    require(
        "trustcache_payload_size(file->length, &expectedSize)" in text and
        "expectedSize != payloadSize" in text,
        "file loader must reject claimed-count/file-size mismatches",
    )


def run_checks() -> list[str]:
    text = source_text()
    check_source_contract(text)

    # The packed file has a valid zero-entry boundary and a one-entry boundary.
    for head_size in (0x10, 0x28):
        zero = checked_geometry(head_size, 0)
        one = checked_geometry(head_size, 1)
        require(zero is not None and one is not None, "boundary geometry overflowed")
        require(zero.file_size == FILE_HEADER_SIZE, "zero-entry file size changed")
        require(one.file_size == FILE_HEADER_SIZE + ENTRY_SIZE,
                "one-entry file size changed")
        require(zero.payload_write_size == FILE_HEADER_SIZE,
                "zero-entry payload write includes the kernel head")
        require(one.payload_write_size == FILE_HEADER_SIZE + ENTRY_SIZE,
                "one-entry payload write includes the kernel head")

    # Same-size replacement is the only in-place path; differing counts must
    # take the remove/free/new-allocation path.
    require(classify_replacement(0x10, 1, 1) == "same-size",
            "equal one-entry files did not select same-size replacement")
    require(classify_replacement(0x28, 0, 0) == "same-size",
            "equal zero-entry files did not select same-size replacement")
    require(classify_replacement(0x10, 1, 2) == "grow",
            "larger replacement did not select grow path")
    require(classify_replacement(0x28, 2, 1) == "shrink",
            "smaller replacement did not select shrink path")

    # The uploader's 0x4000 cap is reached at this count for both supported
    # head layouts; one more entry must be rejected before kernel writes.
    for head_size in (0x10, 0x28):
        last_count = (MAX_ALLOCATION - head_size - FILE_HEADER_SIZE) // ENTRY_SIZE
        at_limit = checked_geometry(head_size, last_count)
        over_limit = checked_geometry(head_size, last_count + 1)
        require(at_limit is not None and at_limit.allocation_size <= MAX_ALLOCATION,
                "last in-limit entry count is not accepted")
        require(over_limit is not None and over_limit.allocation_size > MAX_ALLOCATION,
                "first over-limit entry count is not rejected")
        require(classify_replacement(head_size, 0, last_count + 1) ==
                "rejected-over-limit", "over-limit replacement was not rejected")

    # Malformed/overflow-shaped inputs are characterized without allocating
    # their claimed payload. A short file or mismatched claimed count is
    # rejected by the exact-size relation; UINT32_MAX remains representable
    # on arm64 but is safely over the uploader's cap.
    require(not file_geometry_valid(FILE_HEADER_SIZE - 1, 0),
            "short file was accepted as a zero-entry file")
    require(not file_geometry_valid(FILE_HEADER_SIZE, 1),
            "missing one-entry payload was accepted")
    require(not file_geometry_valid(FILE_HEADER_SIZE + ENTRY_SIZE - 1, 1),
            "truncated one-entry payload was accepted")
    require(file_geometry_valid(FILE_HEADER_SIZE, 0),
            "zero-entry file was rejected")
    require(file_geometry_valid(FILE_HEADER_SIZE + ENTRY_SIZE, 1),
            "one-entry file was rejected")
    max_count_size = FILE_HEADER_SIZE + UINT32_MAX * ENTRY_SIZE
    require(file_geometry_valid(max_count_size, UINT32_MAX),
            "maximum uint32 count did not preserve exact-size arithmetic")
    require(not file_geometry_valid(max_count_size - 1, UINT32_MAX),
            "maximum-count truncated payload was accepted")
    require(checked_geometry(0x10, UINT32_MAX) is not None,
            "maximum count unexpectedly overflowed uint64 geometry")
    require(classify_replacement(0x10, 0, UINT32_MAX) == "rejected-over-limit",
            "maximum count did not fail closed at the allocation cap")
    require(checked_geometry(0x10, UINT32_MAX + 1) is None,
            "count wider than uint32 was accepted")
    require(checked_geometry(SIZE_MAX, 0) is None,
            "head-size addition overflow was not rejected")
    require(classify_replacement(0x10, 0, UINT32_MAX + 1) ==
            "malformed-or-overflow", "wider-than-uint32 count was not malformed")

    return [
        "source contract: same-size replacement/restore use payloadSize = tcSize - ksizeof(trustcache)",
        "geometry: zero/one entry, same-size, grow/shrink boundaries",
        "geometry: 0x4000 allocation cap and malformed/uint32 overflow-shaped inputs",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = parser.parse_args()
    try:
        checks = run_checks()
    except (AssertionError, OSError, UnicodeError) as error:
        if args.json:
            print(json.dumps({"status": "failed", "error": str(error)}))
        else:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"status": "passed", "checks": checks}, indent=2))
    else:
        for check in checks:
            print(f"PASS {check}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
