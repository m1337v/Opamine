#!/usr/bin/env python3
"""Contracts for RootHide-aware filesystem trustcache collection status."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "BaseBin/libjailbreak/src"

COMPLETED = 0
SKIPPED = 1
EIO = -5


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def modeled_transaction(collection_status: int, hashes: list[bytes]) -> tuple[int, list[bytes]]:
    """Model the only allowed status transition at the filesystem boundary."""
    if collection_status < 0:
        return collection_status, []
    if collection_status == SKIPPED:
        return 0, []
    return 0, hashes


def main() -> int:
    signatures_h = (SRC / "signatures.h").read_text(encoding="utf-8")
    signatures = (SRC / "signatures.c").read_text(encoding="utf-8")
    trustcache_fs = (SRC / "trustcache_fs.c").read_text(encoding="utf-8")

    require("FILE_CDHASH_COLLECTION_COMPLETED = 0" in signatures_h and
            "FILE_CDHASH_COLLECTION_SKIPPED = 1" in signatures_h and
            "int file_collect_untrusted_cdhashes_by_path_status(" in signatures_h,
            "collector status API must be additive and expose completed/skip/error semantics")
    require("void file_collect_untrusted_cdhashes_by_path(" in signatures_h,
            "legacy void collector API must remain available for existing callers")
    require("if (!root_hide_allows_trust_path(filepath)) return FILE_CDHASH_COLLECTION_SKIPPED;" in signatures,
            "RootHide policy exclusions must remain an intentional skip")
    require("file_cdhash_input_kind" in signatures and
            "return FILE_CDHASH_COLLECTION_SKIPPED;" in signatures and
            "return -EIO;" in signatures,
            "non-Mach input and short-read/I/O failure must not collapse together")
    require("int jbrandError = ensure_randomized_cdhash_for_slice" in signatures and
            "return collectionError;" in signatures,
            "jbrand mutation failure must propagate to the status API")
    require("file_collect_untrusted_cdhashes_by_path_status(path, &hashes, &hashCount)" in trustcache_fs and
            "if (collectionStatus < 0)" in trustcache_fs and
            "if (collectionStatus == FILE_CDHASH_COLLECTION_SKIPPED) return 0;" in trustcache_fs,
            "filesystem collection may forgive skips but must propagate real collector errors")
    require("result = -errno;" in trustcache_fs and "break;" in trustcache_fs,
            "directory traversal must fail its transaction on lstat I/O errors")
    require("errno = 0;" in trustcache_fs and "entry = readdir(directory);" in trustcache_fs and
            "if (closedir(directory) != 0 && result == 0) result = -errno;" in trustcache_fs,
            "readdir and close failures must not become an empty successful directory scan")

    collected_hash = b"x" * 20
    require(modeled_transaction(COMPLETED, [collected_hash]) == (0, [collected_hash]),
            "completed collection must preserve hashes for the add transaction")
    require(modeled_transaction(SKIPPED, []) == (0, []),
            "policy/non-Mach skip must remain benign")
    require(modeled_transaction(EIO, [collected_hash]) == (EIO, []),
            "I/O/jbrand collection failure must abort before a trustcache add")

    print("trustcache filesystem status contract: completed/skip/error propagation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
