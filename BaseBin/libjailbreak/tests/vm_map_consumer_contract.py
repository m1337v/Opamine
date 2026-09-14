#!/usr/bin/env python3
"""Keep external vm_map users aligned with libjailbreak's flattened ABI."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CONSUMERS = (
    ROOT / "Application/Dopamine/Exploits/kfd/kfd.m",
    ROOT / "BaseBin/launchdhook/src/jbserver/jbdomain_systemwide.c",
)
REMOVED_EXPRESSIONS = (
    "koffsetof(vm_map_links",
    "koffsetof(vm_map_header, links)",
    "koffsetof(vm_map_entry, links)",
)
REQUIRED_FIELDS = {
    CONSUMERS[0]: (
        "koffsetof(vm_map_header, first)",
        "koffsetof(vm_map_header, last)",
        "koffsetof(vm_map_header, min_offset)",
        "koffsetof(vm_map_header, max_offset)",
    ),
    CONSUMERS[1]: (
        "koffsetof(vm_map_header, first)",
        "koffsetof(vm_map_entry, start)",
        "koffsetof(vm_map_entry, end)",
        "koffsetof(vm_map_entry, next)",
    ),
}


def main() -> None:
    for consumer in CONSUMERS:
        source = consumer.read_text(encoding="utf-8")
        for expression in REMOVED_EXPRESSIONS:
            assert expression not in source, f"{consumer}: stale {expression}"
        for field in REQUIRED_FIELDS[consumer]:
            assert field in source, f"{consumer}: missing flattened {field}"
    launchd_source = CONSUMERS[1].read_text(encoding="utf-8")
    assert "childNentries = kread32(childHeader + koffsetof(vm_map_header, nentries))" in launchd_source, (
        "launchdhook must bound the child traversal with the child map header"
    )
    print("vm_map external consumer ABI contract: PASS")


if __name__ == "__main__":
    main()
