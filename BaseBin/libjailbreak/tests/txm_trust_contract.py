#!/usr/bin/env python3
"""Host/source contracts for the transactional TXM, trustcache, and signing port.

These assertions deliberately do not emulate kernel primitives.  They pin the
ordering and fail-closed boundaries which a host build cannot execute safely.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "BaseBin/libjailbreak/src"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def between(text: str, start: str, end: str) -> str:
    start_at = text.index(start)
    end_at = text.index(end, start_at + len(start))
    return text[start_at:end_at]


def main() -> int:
    signatures_h = (SRC / "signatures.h").read_text(encoding="utf-8")
    signatures = (SRC / "signatures.c").read_text(encoding="utf-8")
    trustcache = (SRC / "trustcache.c").read_text(encoding="utf-8")
    trustcache_fs = (SRC / "trustcache_fs.c").read_text(encoding="utf-8")
    txm = (SRC / "txm.c").read_text(encoding="utf-8")

    # siginfo crosses RootHide's existing launchdhook Mach boundary; its old
    # FILE/PROC numeric values must never move when ALLOCATION is introduced.
    enum = between(signatures_h, "typedef enum", "} signature_source_t;")
    require(enum.index("SIGNATURE_SOURCE_FILE") < enum.index("SIGNATURE_SOURCE_PROC") <
            enum.index("SIGNATURE_SOURCE_ALLOCATION"),
            "signature source ABI no longer preserves FILE/PROC before ALLOCATION")
    require("const struct siginfo *siginfo" in signatures_h,
            "siginfo resolver must keep the public input const")

    file_hashes = between(signatures, "static int file_collect_untrusted_cdhashes_status(",
                          "void file_collect_untrusted_cdhashes(")
    require("const char *pathForBlock = filepath;" in file_hashes,
            "Objective-C block must capture an immutable path pointer")
    require(file_hashes.index("ensure_randomized_cdhash_for_slice") <
            file_hashes.index("is_cdhash_trustcached(cdhash)"),
            "RootHide jbrand randomization must precede trust-cache lookup")
    require("root_hide_allows_trust_path" in file_hashes and
            "Cryptexes" in signatures and "hasTrollstoreLiteMarker" in signatures,
            "RootHide path/allowlist policy was dropped from file collection")

    signing = signatures[signatures.index("int trust_signatures("):]
    require("if (txmSignaturesRequired && !jbinfo_sptm_runtime_ready()) return -ENOTSUP;" in signing,
            "partial SPTM/TXM startup must reject signing")
    require("result = -EPERM;" in signing and
            "curSigInfo->source != SIGNATURE_SOURCE_ALLOCATION" in signing,
            "file/proc signatures must not be mutated in place")
    require(signing.index("fd_attach_signature") < signing.index("jb_trustcache_add_cdhashes"),
            "rewritten signatures must attach before their cdhash is globally trusted")

    require("if (__builtin_available(iOS 26.0, *)) return -ENOTSUP;" in txm,
            "iOS 26+ TXM allocation must remain disabled without hookd/provider")
    require(txm.index("if (__builtin_available(iOS 26.0, *)) return -ENOTSUP;") <
            txm.index("vm_protect("),
            "iOS 26+ must not reach direct vm_protect")
    require("!keyBacking || keyBacking < koffsetof(TXMCodeRegion, startAddr)" in txm and
            "uint64_t key = keyBacking - koffsetof(TXMCodeRegion, startAddr);" in txm,
            "TXM RB lookup key must validate translation before subtraction")

    list_insert = between(trustcache, "static int trustcache_list_insert_transactional(",
                          "int trustcache_list_insert(")
    require("if (jbinfo_sptm_runtime_ready())" in list_insert and
            "lastTC" in list_insert and
            "trustcache_write64_verified(lastNextAddr, tcToInsert)" in list_insert,
            "TXM trustcache insertion must append instead of rewriting its root")
    add_entries = between(trustcache, "int jb_trustcache_add_entries(",
                          "int jb_trustcache_add_cdhashes(")
    require("qsort(pending" in add_entries and "is_cdhash_trustcached" in add_entries and
            "jb_trustcache_rollback" in add_entries,
            "JB trustcache append must dedupe and restore earlier pages on failure")
    upload = trustcache[trustcache.index("int trustcache_file_upload("):]
    require("trustcache_kernel_file_equals" in upload and
            "if (previousTcSize == tcSize)" in upload,
            "file upload must verify same-size idempotency before replacement")
    require(upload.index("trustcache_allocate_and_insert(tc, tcSize, &replacementTcKaddr)") <
            upload.index("trustcache_list_remove_transactional(existingTcKaddr, &oldRemoved)"),
            "replacement trustcache must publish before old UUID retirement")
    require("bool oldRemoved = false;" in upload and "bool replacementRemoved = false;" in upload and
            "trustcache_list_remove_transactional(replacementTcKaddr, &replacementRemoved)" in upload,
            "failed old-cache retirement needs transactional replacement rollback")

    require("file_collect_untrusted_cdhashes_by_path" in trustcache_fs and
            "lstat(" in trustcache_fs and "TRUSTCACHE_FS_MAX_DEPTH" in trustcache_fs and
            "Symlinks and all other node types are intentionally not followed" in trustcache_fs,
            "filesystem trustcache collection must retain path policy and not traverse symlinks")

    print("signature contract: RootHide ABI, jbrand ordering, attach-before-trust transaction")
    print("TXM contract: append-only list and iOS 26+ hookd/provider fail-closed gate")
    print("trustcache contract: duplicate suppression, verified replacement, rollback")
    print("filesystem contract: RootHide-aware collection with bounded no-symlink traversal")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
