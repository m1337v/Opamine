#!/usr/bin/env python3
"""Source contracts for the selective Dopamine 3 libjailbreak port.

This deliberately requires no iOS device or kernel primitive.  It pins the
named-XPC ABI fields and the fail-closed boundaries that prevent an old XPF
one-image startup from accidentally using SPTM/TXM offsets.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "BaseBin/libjailbreak/src"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def ordered(text: str, *needles: str) -> None:
    offsets = [text.index(needle) for needle in needles]
    require(offsets == sorted(offsets), f"ABI fields reordered: {needles}")


def main() -> int:
    info = (SRC / "info.h").read_text(encoding="utf-8")
    info_c = (SRC / "info.c").read_text(encoding="utf-8")
    primitives = (SRC / "primitives_external.h").read_text(encoding="utf-8")
    translation = (SRC / "translation.c").read_text(encoding="utf-8")
    phys_pte = (SRC / "physrw_pte.c").read_text(encoding="utf-8")
    util = (SRC / "util.c").read_text(encoding="utf-8")
    main_c = (SRC / "main.c").read_text(encoding="utf-8")
    inline_svc = (SRC / "inline_svc.c").read_text(encoding="utf-8")

    ordered(info, "uint64_t staticBase;", "uint64_t staticSptmBase;",
            "uint64_t staticTxmBase;", "uint64_t base;")
    ordered(info, "uint64_t sptmBase;", "uint64_t sptmSlide;",
            "uint64_t txmBase;", "uint64_t txmSlide;")
    ordered(info, "char *appIdentifier;", "uint64_t jbrand;",
            "uint64_t palera1n;", "bool dyld_patch_enabled;")
    for field in ("SPTMArgs", "libsptm_papt_ranges", "libsptm_frame_table",
                  "txm_developer_mode_storage", "txm_trustcache_root"):
        require(f"kernelSymbol.{field}" in info,
                f"missing serialized SPTM/TXM symbol: {field}")
    require("jbinfo_sptm_runtime_ready" in info,
            "missing explicit SPTM/TXM capability gate")
    require("staticSptmBase) != 0" in info and "staticTxmBase) != 0" in info,
            "SPTM/TXM static image bases are not mandatory")
    require("disabling SPTM/TXM paths" in info_c,
            "boot initialization does not fail closed on missing image bases")
    require("unsupported kernel version format" in info_c and "unsupported XNU version" in info_c,
            "unparseable kernel versions do not fail closed")
    require("darwinMajor < 21 || darwinMajor > 27" in info_c,
            "unknown Darwin releases can receive stale hardcoded offsets")
    require("typedef void (^kernel_map_accessor)(void *ptr);" in primitives,
            "mapped primitive callback ABI missing")
    require("physaccess_mapped" in primitives,
            "mapped physical primitive vtable entry missing")
    require("jbinfo_sptm_runtime_ready()" in translation and "papt_table_n > 4096" in translation,
            "SPTM translation metadata is not bounded and gated")
    require("size == 0" in phys_pte and "access would cross page boundary" not in phys_pte,
            "PTE mapped access must reject zero and cross-page requests")
    require("sptm_capability_incomplete" in util and "return -ENOTSUP" in util,
            "page-table allocation does not fail closed for incomplete SPTM startup")
    require("if (initResult != 0) return initResult;" in main_c,
            "primitive handoff failure can be ignored by the client")
    require("libjailbreak_kalloc_pt_init" in main_c,
            "legacy RootHide kalloc_pt compatibility was retired before callers migrated")
    require("wait4_inline" in inline_svc and "getpid_svc_inline" in inline_svc,
            "Dopamine inline service primitives are missing")
    print("abi contract: named SPTM/TXM fields, RootHide identity order, primitive vtable")
    print("capability contract: incomplete XPF SPTM/TXM startup fails closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
