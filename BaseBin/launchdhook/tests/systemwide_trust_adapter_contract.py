#!/usr/bin/env python3
"""Host/source contract for the RootHide-aware Dopamine 3 trust adapter.

The real transaction needs an iOS kernel, TXM and F_ADDSIGS, so this test pins
the caller's policy and ownership/order guarantees rather than pretending to
exercise those device-only primitives on macOS.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "BaseBin/launchdhook/src/jbserver/jbdomain_systemwide.c"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def section(text: str, start: str, end: str) -> str:
    start_at = text.index(start)
    end_at = text.index(end, start_at + len(start))
    return text[start_at:end_at]


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8")
    all_slices = section(
        source,
        "static int systemwide_prepare_root_hide_file_signatures(",
        "/* A Mach siginfo has FILE/PROC storage owned by its sender.",
    )
    exact_slice = section(
        source,
        "static int systemwide_prepare_root_hide_siginfo(",
        "int systemwide_trust_file(",
    )
    handler = section(source, "int systemwide_trust_file(", "int systemwide_trust_file_by_path(")

    # RootHide policy must gate the transaction itself, not merely an auxiliary
    # filesystem helper.  That prevents Cryptex/removable apps from entering a
    # raw Dopamine 3 signature path.
    require("systemwide_root_hide_allows_trust_path(filepath)" in handler,
            "RootHide path/allowlist gate is missing at the systemwide boundary")
    require("/private/preboot/Cryptexes/" in source and "hasTrollstoreLiteMarker" in source,
            "Cryptex or TrollStore Lite policy disappeared")

    # Incomplete SPTM metadata must be rejected before any irreversible jbrand
    # rewrite.  trust_signatures keeps the same backstop, but this caller makes
    # the ordering explicit.
    capability = "jbinfo_has_sptm_metadata() && !jbinfo_sptm_runtime_ready()"
    require(capability in handler and "return -ENOTSUP;" in handler,
            "incomplete SPTM/TXM startup is not fail-closed")
    require(handler.index(capability) < handler.index("systemwide_prepare_root_hide_siginfo"),
            "jbrand preparation can run before the SPTM/TXM capability gate")

    # The no-siginfo path retains RootHide's all-mappable-slices behavior and
    # accepts a signature only after comparing its post-rewrite final cdhash.
    require("file_collect_signatures(fd, &initial, &initialCount);" in all_slices,
            "RootHide all-slice collection no longer starts from local signatures")
    require(all_slices.index("ensure_randomized_cdhash_for_slice") <
            all_slices.index("is_cdhash_trustcached(randomizedCdhash)"),
            "jbrand randomization must precede final-hash duplicate suppression")
    require(".fileStart = initial[i].signature.fs_file_start" in all_slices and
            "systemwide_collect_updated_signatures" in all_slices,
            "all-slice path does not bind final hashes to their source slice")

    # A cross-process siginfo remains FILE/PROC-only.  The local refreshed
    # allocation is deliberately selected by both offset and final hash before
    # TXM is allowed to rewrite/attach it.
    require("SIGNATURE_SOURCE_FILE && siginfo->source != SIGNATURE_SOURCE_PROC" in exact_slice,
            "cross-process siginfo source validation is missing")
    require(exact_slice.index("is_cdhash_trustcached(initialCdhash)") <
            exact_slice.index("ensure_randomized_cdhash_for_slice"),
            "exact siginfo duplicate behavior no longer matches deployed RootHide")
    require("systemwide_collect_updated_signatures(fd, &candidate, 1" in exact_slice,
            "exact siginfo path does not convert to a local transaction input")

    refreshed = section(
        source,
        "static int systemwide_collect_updated_signatures(",
        "/* Preserve RootHide's no-siginfo flow:",
    )
    require("collected[i].signature.fs_file_start != candidates[j].fileStart" in refreshed and
            "memcmp(cdhash, candidates[j].cdhash, sizeof(cdhash_t))" in refreshed,
            "refreshed signature selection is not offset-and-cdhash exact")
    require("Ownership moves into selected[j]." in refreshed and
            "systemwide_free_local_signatures(collected, collectedCount);" in refreshed,
            "allocation ownership is not released after signature selection")

    # The adapter delegates publishing to the transaction.  It must return its
    # error and must not retain the old direct trustcache add that could publish
    # a hash before a needed F_ADDSIGS succeeds.
    require("result = trust_signatures(pid, fd, sigInfos, sigInfoCount);" in handler,
            "Dopamine 3 transactional signer is not called")
    require("jb_trustcache_add_cdhashes" not in handler,
            "launchdhook directly publishes hashes outside the transaction")
    require(handler.index("trust_signatures(pid, fd, sigInfos, sigInfoCount)") <
            handler.index("systemwide_free_local_signatures(sigInfos, sigInfoCount);"),
            "transaction input is released before the signer runs")
    require("return result;" in handler,
            "transaction/preparation errors are not propagated to the caller")

    print("systemwide trust adapter contract: RootHide jbrand/policy + D3 transaction: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
