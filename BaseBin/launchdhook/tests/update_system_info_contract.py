#!/usr/bin/env python3
"""Fail-closed source contract for launchdhook's dynamic XPF refresh."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "BaseBin/launchdhook/src/update.m"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8")
    start = source.index("void jbupdate_update_system_info(void)")
    update = source[start:]

    symbols = (
        "xpf_start_with_kernel_path",
        "xpf_get_error",
        "xpf_set_is_supported",
        "xpf_stop",
        "xpf_construct_offset_dictionary",
    )
    for symbol in symbols:
        require(symbol in update, f"missing dynamic XPF symbol: {symbol}")
    guard = "if (!xpf_start_with_kernel_path || !xpf_get_error || !xpf_set_is_supported || !xpf_stop || !xpf_construct_offset_dictionary)"
    require(guard in update and update.index(guard) < update.index("int r = xpf_start_with_kernel_path"),
            "XPF entry points must be verified before invocation")
    require("libxpf is missing a required patchfinding symbol." in update,
            "missing XPF symbol does not terminate fail-closed")

    require('"kernelConstant.staticBase"' in update and
            '"kernelConstant.staticSptmBase"' in update and
            '"kernelConstant.staticTxmBase"' in update,
            "serialized static image bases are not preserved")
    require("xpc_get_type(systemInfoXdict) != XPC_TYPE_DICTIONARY" in update and
            "serialized launchd system information is invalid." in update and
            "if (!staticBase)" in update and
            "existing static kernel image base is unavailable." in update,
            "missing serialized launchd state must stop the refresh")
    require(update.index("xpc_get_type(systemInfoXdict) != XPC_TYPE_DICTIONARY") <
            update.index("xpc_dictionary_get_uint64(systemInfoXdict"),
            "serialized state is read before its XPC dictionary type is validated")
    require("if ((staticSptmBase && !sptmPath) || (staticTxmBase && !txmPath))" in update and
            "required SPTM/TXM preboot image is unavailable." in update,
            "a required SPTM/TXM image may be silently dropped")

    require("roothide_xpf_construct_offset_dictionary_wrapper(sets)" in update,
            "RootHide's offset-dictionary wrapper was bypassed")
    require("xpc_get_type(newSystemInfoXdict) != XPC_TYPE_DICTIONARY" in update,
            "XPF output must be type-checked before it is merged")
    require("RootHide namecache offsets are unavailable." in update and
            "validated RootHide AMFI developer-mode offsets are unavailable." in update,
            "RootHide-specific XPF requirements are not validated")
    merge = update.index("xpc_dictionary_apply(newSystemInfoXdict")
    new_type_check = update.index("xpc_get_type(newSystemInfoXdict) != XPC_TYPE_DICTIONARY")
    preserve = update.index('xpc_dictionary_set_uint64(systemInfoXdict, "kernelConstant.staticBase", staticBase)')
    rebuild = update.index("jbinfo_initialize_dynamic_offsets(systemInfoXdict)")
    require(new_type_check < merge < preserve < rebuild,
            "XPF output must be type-checked, merged, then restore static bases before rebuilding")

    print("update system-info contract: dynamic XPF and static SPTM/TXM state fail closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
