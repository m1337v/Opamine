#!/usr/bin/env python3
"""Fault model for trustcache remove/replace link transactions.

The iOS implementation uses kernel primitives, so this host test models the
same ordering: repair the successor's reverse link first, then commit the
forward/root unlink.  A failed final write must restore both snapshots before
the replacement rollback is allowed to free anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "BaseBin/libjailbreak/src/trustcache.c"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


@dataclass
class Node:
    next: int | None = None
    prev: int | None = None


class FaultyList:
    """One-shot write faults; failed writes have no side effect like kwrite64."""

    def __init__(self, order: list[int], fail_at: int | set[int] | None = None):
        self.nodes = {key: Node() for key in order}
        self.root = order[0] if order else None
        for before, after in zip(order, order[1:]):
            self.nodes[before].next = after
            self.nodes[after].prev = before
        self.fail_at = set() if fail_at is None else ({fail_at} if isinstance(fail_at, int) else fail_at)
        self.write_count = 0

    def write(self, owner: int | None, field: str, value: int | None) -> bool:
        self.write_count += 1
        if self.write_count in self.fail_at:
            return False
        if owner is None:
            self.root = value
        else:
            setattr(self.nodes[owner], field, value)
        return True

    def reachable(self) -> list[int]:
        result: list[int] = []
        current = self.root
        while current is not None:
            require(current not in result, "forward list looped")
            result.append(current)
            current = self.nodes[current].next
        return result

    def valid(self) -> bool:
        chain = self.reachable()
        return all(self.nodes[key].prev == (chain[index - 1] if index else None)
                   for index, key in enumerate(chain))

    def remove_transactional(self, target: int) -> bool:
        chain = self.reachable()
        if target not in chain:
            return False
        index = chain.index(target)
        previous = chain[index - 1] if index else None
        successor = self.nodes[target].next
        reverse_before = self.nodes[successor].prev if successor is not None else None

        # Successor reverse link first: forward reachability still includes
        # target if this write fails.
        if successor is not None and not self.write(successor, "prev", previous):
            self.write(successor, "prev", reverse_before)
            return False

        forward_before = target
        forward_owner = previous
        if not self.write(forward_owner, "next", successor):
            # Restore the forward owner/root before the reverse pointer.
            self.write(forward_owner, "next", forward_before)
            if successor is not None:
                self.write(successor, "prev", reverse_before)
            return False
        return True

    def insert_pre_sptm(self, candidate: int) -> tuple[bool, bool]:
        """Model the production safe-to-free distinction for root insertion."""

        require(candidate not in self.nodes, "candidate already exists")
        self.nodes[candidate] = Node()
        old_root = self.root
        old_root_prev = self.nodes[old_root].prev if old_root is not None else None

        # Old root's reverse field is external to the candidate; it must be
        # restored before a failed candidate allocation may be released.
        if old_root is not None and not self.write(old_root, "prev", candidate):
            restored = self.write(old_root, "prev", old_root_prev)
            return False, restored
        if not self.write(candidate, "next", old_root):
            restored = old_root is None or self.write(old_root, "prev", old_root_prev)
            return False, restored
        if not self.write(None, "root", candidate):
            restored = old_root is None or self.write(old_root, "prev", old_root_prev)
            return False, restored
        return True, False


def assert_replace_fault(fail_at: int | None) -> None:
    """Model old->replacement transition and its rollback when old survives."""

    old, replacement = 1, 2
    state = FaultyList([old, replacement], fail_at)
    old_removed = state.remove_transactional(old)
    if old_removed:
        require(state.reachable() == [replacement] and state.valid(),
                f"success left an invalid replacement list (fault={fail_at})")
        return

    # Old remains reachable, so replacement rollback must run. A one-shot
    # fault has already fired; the retry removes only the unlinked candidate.
    replacement_removed = state.remove_transactional(replacement)
    require(replacement_removed, f"replacement rollback did not finish (fault={fail_at})")
    require(state.reachable() == [old] and state.valid(),
            f"rollback did not leave exactly old live (fault={fail_at})")


def assert_middle_remove_fault(fail_at: int) -> None:
    anchor, old, successor = 10, 11, 12
    state = FaultyList([anchor, old, successor], fail_at)
    require(not state.remove_transactional(old),
            f"middle removal unexpectedly succeeded with write {fail_at} fault")
    require(state.reachable() == [anchor, old, successor] and state.valid(),
            f"middle removal did not restore both snapshots (fault={fail_at})")


def same_size_replace(original: bytes, replacement: bytes, *, partial_write: bool,
                      restore_succeeds: bool) -> tuple[bool, bytes]:
    """Model snapshot/verify/restore for the only in-place payload path."""

    snapshot = bytes(original)
    live = bytearray(snapshot)
    if partial_write:
        live[:len(live) // 2] = replacement[:len(live) // 2]
    else:
        live[:] = replacement
    if bytes(live) == replacement:
        return True, bytes(live)
    if restore_succeeds:
        live[:] = snapshot
    else:
        # A second primitive fault can leave damage, but the operation remains
        # an error; it must never report a successful UUID replacement.
        live[len(live) // 2:] = snapshot[len(live) // 2:]
    return False, bytes(live)


def check_source_contract() -> None:
    text = SOURCE.read_text(encoding="utf-8")
    start = text.index("static int trustcache_list_remove_transactional(")
    end = text.index("int trustcache_list_remove(", start)
    remove = text[start:end]
    require(remove.index("reverseBefore") < remove.index("trustcache_write64_verified(reverseAddr") <
            remove.index("trustcache_write64_verified(forwardAddr"),
            "remove must snapshot and update reverse before forward/root")
    rollback = remove[remove.index("int forwardRollback"):]
    require(rollback.index("trustcache_restore64(forwardAddr, forwardBefore)") <
            rollback.index("trustcache_restore64(reverseAddr, reverseBefore)"),
            "remove rollback must restore forward/root before reverse metadata")
    upload = text[text.index("int trustcache_file_upload("):]
    require("bool oldRemoved = false;" in upload and
            "trustcache_list_remove_transactional(existingTcKaddr, &oldRemoved)" in upload,
            "replacement must consume transactional removal state")
    require("for (unsigned attempt = 0; attempt < 2 && !replacementRemoved; attempt++)" in upload and
            "if (replacementRemoved)" in upload and "kfree(replacementTcKaddr, tcSize)" in upload,
            "replacement cleanup must retry and free only after proven unlink")
    insert = text[text.index("static int trustcache_list_insert_transactional("):
                  text.index("int trustcache_list_insert(")]
    require("bool *safeToFreeOut" in insert and
            "trustcache_restore64(previousPrevAddr, previousPrev)" in insert and
            "if (!listTransactionStarted || (safeToFree && !linked)) (void)kfree(tcKaddr, tcSize);" in text,
            "insert failure must retain a candidate with an un-restored external prevptr")
    grow = text[text.index("uint64_t _jb_trustcache_grow("):
                text.index("struct jb_trustcache_mutation", text.index("uint64_t _jb_trustcache_grow("))]
    require("trustcache_list_insert_transactional(jbTcKern, &linked, &safeToFree)" in grow and
            "if (safeToFree && !linked) (void)kfree(jbTcKern, JB_TRUSTCACHE_SIZE);" in grow,
            "JB trustcache grow must obey the same safe-to-free insert contract")
    same_size = upload[upload.index("if (previousTcSize == tcSize)"):]
    require("trustcache_file_v1 *previousPayload = malloc(payloadSize);" in same_size and
            "kreadbuf(existingTcFile, previousPayload, payloadSize)" in same_size and
            "kwritebuf(existingTcFile, previousPayload, payloadSize)" in same_size and
            "bool restored = trustcache_kernel_file_equals(existingTcFile, previousPayload, payloadSize);" in same_size,
            "same-size replacement must snapshot and verify rollback payload")


def main() -> int:
    check_source_contract()
    # Root removal has two writes: successor.prev and root.  Exercise a fault
    # after each write, then the replacement rollback path.
    for fault in (1, 2):
        assert_replace_fault(fault)
    assert_replace_fault(None)

    # Middle removal has successor.prev and predecessor.next writes. Each
    # one-shot failure restores the exact original forward/reverse topology.
    for fault in (1, 2):
        assert_middle_remove_fault(fault)

    # A replacement rollback itself is a single predecessor.next write in the
    # old->replacement shape.  Its first fault preserves both nodes; retrying
    # then leaves exactly old linked, so neither path frees a live node.
    state = FaultyList([1, 2], fail_at=1)
    require(not state.remove_transactional(2), "rollback fault unexpectedly removed replacement")
    require(state.reachable() == [1, 2] and state.valid(), "rollback fault corrupted live list")
    require(state.remove_transactional(2), "rollback retry did not remove replacement")
    require(state.reachable() == [1] and state.valid(), "rollback retry did not preserve old cache")

    # Pre-SPTM insertion mutates old-root.prev before publishing the root. For
    # every one-shot write fault, its recovery proves the candidate detached
    # and safe to free. If the restore itself faults, the candidate is retained
    # because old.prev still points at it even though it is not forward-linked.
    for fault in (1, 2, 3):
        state = FaultyList([1], fail_at=fault)
        linked, safe_to_free = state.insert_pre_sptm(2)
        require(not linked and safe_to_free, f"one-shot insert fault not safely detached ({fault})")
        require(state.reachable() == [1] and state.valid(), f"one-shot insert recovery invalid ({fault})")
    state = FaultyList([1], fail_at={3, 4})
    linked, safe_to_free = state.insert_pre_sptm(2)
    require(not linked and not safe_to_free, "failed reverse restore incorrectly permits free")
    require(state.reachable() == [1] and state.nodes[1].prev == 2,
            "persistent reverse-restore model did not retain the dangling candidate")

    original, replacement = b"old-trustcache-payloadA", b"new-trustcache-payloadB"
    require(len(original) == len(replacement), "model payloads must use same-size branch")
    success, live = same_size_replace(original, replacement, partial_write=False, restore_succeeds=True)
    require(success and live == replacement, "verified full same-size replacement was rejected")
    success, live = same_size_replace(original, replacement, partial_write=True, restore_succeeds=True)
    require(not success and live == original, "partial same-size write did not restore snapshot")
    success, live = same_size_replace(original, replacement, partial_write=True, restore_succeeds=False)
    require(not success and live != replacement,
            "unverified rollback must not be reported as a successful replacement")

    print("transaction model: root/middle write faults restore forward and reverse snapshots")
    print("replacement model: one-shot primary or rollback fault leaves exactly one selected cache")
    print("insert model: candidate is retained when external reverse-link restore cannot be proven")
    print("payload model: same-size partial write restores snapshot or returns unverified EIO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
