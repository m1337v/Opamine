#!/usr/bin/env python3
"""Host characterization lane for the current rhinject systemhook.

This deliberately does not compile the iOS production sources.  The source
files depend on Darwin/Mach-O/Objective-C/RootHide APIs, and pretending a host
build proves those paths would produce false confidence.  Instead this runner
executes small deterministic models of contracts that the implementation must
eventually satisfy, and statically records where the current implementation
does or does not satisfy them.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable


ROOT = Path(__file__).resolve().parents[3]
TESTS = Path(__file__).resolve().parent
HIDER = ROOT / "BaseBin/systemhook/src/hidden_dylib_hider.c"
HIDER_IDENTITY = ROOT / "BaseBin/systemhook/src/hider_identity.c"
HIDER_IDENTITY_HEADER = ROOT / "BaseBin/systemhook/src/hider_identity.h"
HIDER_CALLER_POLICY = ROOT / "BaseBin/systemhook/src/hider_caller_policy.c"
HIDER_CALLER_POLICY_HEADER = ROOT / "BaseBin/systemhook/src/hider_caller_policy.h"
HIDER_INTERNAL = ROOT / "BaseBin/systemhook/src/hider_internal.h"
COMMON = ROOT / "BaseBin/systemhook/src/common.c"
MAIN = ROOT / "BaseBin/systemhook/src/main.c"
ROOTHIDER_COMMON = ROOT / "BaseBin/systemhook/src/roothider_common.c"
ROOTHIDER_MAIN = ROOT / "BaseBin/systemhook/src/roothider_main.c"
LAUNCHD = ROOT / "BaseBin/launchdhook/src/roothider.m"
LITEHOOK = ROOT / "BaseBin/_external/modules/litehook/src/litehook.c"
RHI_REBIND = ROOT / "BaseBin/systemhook/src/rhi_rebind.c"
RHI_REBIND_HEADER = ROOT / "BaseBin/systemhook/src/rhi_rebind.h"
HIDER_HOOK_SESSION = ROOT / "BaseBin/systemhook/src/hider_hook_session.c"
OWNERSHIP = TESTS / "ownership.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def production_text(path: Path) -> str:
    require(path.is_file(), f"missing production owner: {path}")
    return path.read_text(encoding="utf-8")


def symbol_exists(text: str, symbol: str) -> bool:
    # This catches definitions and call sites without making the matrix depend
    # on a particular C declaration style or attributes.
    return re.search(rf"\b{re.escape(symbol)}\s*\(", text) is not None


def split_components(value: str | None) -> list[str]:
    """Model hider_component_list_contains' delimiter contract."""

    if not value:
        return []
    return [token for token in re.split(r"[:;, \t\n]+", value) if token]


@dataclass(frozen=True)
class ProfileState:
    objc_runtime: bool = True
    objc_copy_class_list: bool = True
    url_schemes: bool = True
    environment: bool = True
    filesystem: bool = True
    directory: bool = True


def profile_state(profile: str | None, disabled: str | None) -> ProfileState:
    """Portable model of the current profile/disabled-token policy."""

    state = {
        "objc_runtime": True,
        "objc_copy_class_list": True,
        "url_schemes": True,
        "environment": True,
        "filesystem": True,
        "directory": True,
    }

    if profile in ("core", "minimal"):
        for key in state:
            state[key] = False
    elif profile == "lite":
        state["objc_copy_class_list"] = False
        state["url_schemes"] = False

    for token in split_components(disabled):
        if token == "all-strict":
            for key in state:
                state[key] = False
        elif token == "objc-runtime":
            state["objc_runtime"] = False
            state["objc_copy_class_list"] = False
        elif token in ("objc-copy-class-list", "copy-class-list"):
            state["objc_copy_class_list"] = False
        elif token in ("url-schemes", "can-open-url"):
            state["url_schemes"] = False
        elif token in ("environment", "getenv"):
            state["environment"] = False
        elif token in ("filesystem", "fs"):
            state["filesystem"] = False
            state["directory"] = False
        elif token in ("directory", "dir"):
            state["directory"] = False

    return ProfileState(**state)


MH_EXECUTE = 2
MH_DYLIB = 6


@dataclass(frozen=True)
class ImageFixture:
    index: int
    filetype: int
    name: str


def select_executable(images: Iterable[ImageFixture]) -> ImageFixture | None:
    """Model the safe MH_EXECUTE-only lookup used by the identity layer."""

    image_list = list(images)
    for image in image_list:
        if image.filetype == MH_EXECUTE:
            return image
    return None


class HookState(str, Enum):
    NOT_ATTEMPTED = "not_attempted"
    PREPARED = "prepared"
    ACTIVE = "active"
    FAILED = "failed"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


@dataclass
class HookFixture:
    name: str
    state: HookState = HookState.NOT_ATTEMPTED
    replacement: str = ""


@dataclass
class SelectedReadinessModel:
    """Small publication model for the selected-tweak dlopen gate."""

    transaction_published: bool = False
    installed: bool = False
    state: HookState = HookState.NOT_ATTEMPTED
    live_state: HookState = HookState.NOT_ATTEMPTED
    dlopen_active: bool = False

    def ready(self) -> bool:
        if not (self.transaction_published and self.installed and self.state is HookState.ACTIVE):
            return False
        if self.live_state is not HookState.ACTIVE or not self.dlopen_active:
            # Readiness invalidation is one-way: a stale physical replacement
            # must never become advertised again in this process.
            self.state = HookState.FAILED
            self.installed = False
            return False
        return True


def remap_result(hook: HookFixture, strict_enabled: bool = True) -> str | None:
    """Model truthful remapping: only a verified ACTIVE hook is advertised."""

    if not strict_enabled or hook.state is not HookState.ACTIVE:
        return None
    return hook.replacement


def session_ready(required: bool, hooks: Iterable[HookFixture]) -> bool:
    """Model required all-or-nothing core versus independent strict sessions."""

    hook_list = list(hooks)
    if not hook_list:
        return False
    return all(hook.state is HookState.ACTIVE for hook in hook_list) if required else \
        hook_list[0].state is HookState.ACTIVE


class DlsymDouble:
    """Model external dlsym remaps, denied results, and one-shot TLS errors."""

    def __init__(self) -> None:
        self.default = {
            "known": "default-known",
            "shared": "default-shared",
            "hidden": "hidden-private",
        }
        self.next = {"shared": "next-shared"}
        self.handles = {"handle-a": {"known": "handle-a-known"}}
        self._state = threading.local()

    def _set_error(self, message: str | None) -> None:
        self._state.error = message

    def _get_error(self) -> str | None:
        return getattr(self._state, "error", None)

    def lookup(
        self,
        handle: str,
        name: str | None,
        remaps: dict[str, str] | None = None,
    ) -> str | None:
        # h_dlsym drops only its own pending denial before delegating. The
        # original lookup establishes stock success/failure state first.
        self._set_error(None)
        if name is None:
            self._set_error("stock invalid symbol")
            return None
        if handle == "RTLD_DEFAULT":
            result = self.default.get(name)
        elif handle == "RTLD_NEXT":
            result = self.next.get(name)
        else:
            result = self.handles.get(handle, {}).get(name)
        if result is None:
            self._set_error(f"symbol not found: {name}")
        if remaps and name in remaps:
            # A policy-remapped success must consume an original lookup error.
            self._set_error(None)
            return remaps[name]
        if result == "hidden-private":
            self._set_error(f"symbol not found: {name}")
            return None
        return result

    def dlerror(self) -> str | None:
        result = self._get_error()
        self._set_error(None)
        return result


@dataclass
class RelativeImageDouble:
    """One catalog identity in the caller-relative dlsym model."""

    name: str
    identity: int
    hidden: bool
    symbols: dict[str, str | None]
    main: bool = False
    two_level: bool = False


class CallerRelativeDlsymDouble:
    """Model RTLD_SELF/NEXT with exact catalog identities and short pins.

    This is deliberately stricter than a simple name-to-address lookup: a pin
    failure cannot skip a preceding provider, a generation/address-reuse race
    restarts the whole walk, and an image that exports a legitimate NULL stays
    distinguishable from one with no symbol.
    """

    RETRIES = 3

    def __init__(self) -> None:
        self.images = [
            RelativeImageDouble("main", 1, False, {"main": "main-symbol"}, main=True),
            RelativeImageDouble("caller", 2, False, {"self": "caller-symbol", "nil": None}),
            RelativeImageDouble("hidden", 3, True, {"shared": "hidden-symbol"}),
            RelativeImageDouble("public", 4, False, {
                "shared": "public-symbol",
                "next": "next-symbol",
                "reexport": "hidden-owned-symbol",
            }),
        ]
        self.hidden_owned_addresses = {"hidden-owned-symbol"}
        self.generation = 1
        self.opens: list[tuple[str, bool]] = []
        self.closes: list[str] = []
        self.fallback_calls = 0
        self.pin_fail_identity: int | None = None
        self.mutate_once = False
        self._mutated = False
        self._error: str | None = None

    def dlerror(self) -> str | None:
        result = self._error
        self._error = None
        return result

    def _pin(self, image: RelativeImageDouble) -> bool:
        self.opens.append((image.name, image.main))
        return image.identity != self.pin_fail_identity

    def _close(self, image: RelativeImageDouble) -> None:
        self.closes.append(image.name)

    def _replace_at_same_address(self) -> None:
        # The header/name slot is deliberately retained while the identity
        # changes: this models dlclose/reload address reuse.
        self.images[2] = RelativeImageDouble(
            "hidden", 30, True, {"shared": "replacement-hidden"}
        )
        self.generation += 1

    def _fallback(self, symbol: str, external: bool) -> str | None:
        self.fallback_calls += 1
        # Model a wrapper-frame native fallback that happened to find a hidden
        # provider. External post-filtering must still deny it.
        if symbol == "fallback-hidden":
            if external:
                self._error = f"symbol not found: {symbol}"
                return None
            return "hidden-fallback-symbol"
        self._error = f"symbol not found: {symbol}"
        return None

    def relative(
        self,
        kind: str,
        caller_name: str,
        symbol: str,
        *,
        external: bool,
        remaps: dict[str, str] | None = None,
    ) -> str | None:
        self._error = None
        if external and remaps and symbol in remaps:
            return remaps[symbol]

        for _attempt in range(self.RETRIES):
            generation = self.generation
            snapshot = list(self.images)
            try:
                caller_index = next(i for i, image in enumerate(snapshot) if image.name == caller_name)
            except StopIteration:
                return self._fallback(symbol, external)
            # The catalog's linear order is only a sound model for a verified
            # flat caller. A two-level image follows its own dependency/static
            # linker graph and must retain the explicit native fallback gap.
            if snapshot[caller_index].two_level:
                return self._fallback(symbol, external)
            start = caller_index if kind == "SELF" else caller_index + 1
            retry = False
            for image in snapshot[start:]:
                if not self._pin(image):
                    # A failed pin means the real first provider is unknown;
                    # continuing to a later image would change RTLD semantics.
                    return self._fallback(symbol, external)
                if self.mutate_once and not self._mutated:
                    self._mutated = True
                    self._replace_at_same_address()
                if generation != self.generation or image not in self.images:
                    self._close(image)
                    retry = True
                    break
                found = symbol in image.symbols
                result = image.symbols.get(symbol)
                self._close(image)
                if found:
                    if external and (image.hidden or result in self.hidden_owned_addresses):
                        self._error = f"symbol not found: {symbol}"
                        return None
                    return result
            if not retry and generation == self.generation:
                self._error = f"symbol not found: {symbol}"
                return None
        return self._fallback(symbol, external)


class SysctlDouble:
    """Model stock two-pass sysctlbyname behavior for a hidden string."""

    ENOMEM = 12
    ENOENT = 2

    def __init__(self) -> None:
        self.values = {"kern.bootargs": b"\x00"}

    def query(self, name: str, capacity: int | None) -> tuple[int, bytes, int]:
        value = self.values.get(name)
        if value is None:
            return (self.ENOENT, b"", 0)
        required = len(value)
        if capacity is None:
            return (0, b"", required)
        if capacity < required:
            return (self.ENOMEM, b"", required)
        return (0, value, required)


class Procargs2Double:
    """Deterministic contract model for the private PROCARGS2 materializer.

    This models only the wrapper decisions (never the Darwin-private byte
    layout, which is covered by the sanitizer fixture and remains device-gated).
    It captures current XNU's distinct PROCARGS2 short-buffer contract: reserve
    an argc word, reject a caller buffer no larger than that word, and otherwise
    return success with the historical page-window zero tail. That operation is
    applied only to the filtered private payload; failed materialization never
    returns raw bytes to its caller.
    """

    ENOMEM = 12
    EIO = 5
    EINVAL = 22
    WORD_BYTES = 4
    ARG_MAX = 262144
    PAGE_SIZE = 16

    def __init__(self, visible: bytes =
                 b"\x02\x00\x00\x00argv\x00PATH=/usr/bin\x00HOME=/var/mobile\x00\x00") -> None:
        self.visible = visible
        padding = (-len(visible)) % self.WORD_BYTES
        # The environment-policy primitive remains byte-exact; the sysctl
        # wrapper alone creates this validated public word-aligned view.
        self.materialized = visible + b"\x00" * padding

    @classmethod
    def legacy_short_payload(cls, payload: bytes, capacity: int, *, page_size: int | None = None) -> bytes:
        """XNU sysctl_procargsx smallbuffer window, over filtered bytes."""

        page = page_size or cls.PAGE_SIZE
        rounded_capacity = (capacity + page - 1) & ~(page - 1)
        rounded_payload = (len(payload) + page - 1) & ~(page - 1)
        zero_offset = max(len(payload) + capacity - min(rounded_capacity, rounded_payload), 0)
        private = bytearray(payload)
        private[zero_offset:] = b"\x00" * (len(payload) - zero_offset)
        return bytes(private[len(payload) - capacity:])

    def query(
        self,
        capacity: int | None,
        *,
        self_pid: bool = True,
        readonly: bool = True,
        internal: bool = False,
        malformed: bool = False,
        allocation_failed: bool = False,
        grow_once: bool = False,
    ) -> tuple[str | int, bytes, int]:
        if not self_pid or not readonly or internal:
            return ("native", b"raw-marker\x00", len(b"raw-marker\x00"))
        if malformed:
            return (self.EIO, b"", 0)
        if allocation_failed:
            return (self.ENOMEM, b"", 0)
        # A bounded private retry does not change which filtered payload is
        # returned to the public caller.
        if grow_once:
            _ = b"transiently-longer-private-payload"
        if capacity is None:
            return (0, b"", len(self.materialized))
        if capacity <= self.WORD_BYTES or capacity - self.WORD_BYTES > self.ARG_MAX:
            # XNU returns before calculate_size, so oldlen remains the input.
            return (self.EINVAL, b"", capacity)
        payload = self.visible[self.WORD_BYTES:]
        payload_capacity = capacity - self.WORD_BYTES
        if payload_capacity >= len(payload):
            return (0, self.visible, len(self.visible))
        return (0, self.visible[:self.WORD_BYTES] +
                self.legacy_short_payload(payload, payload_capacity), capacity)


def clear_self_traced(rows: list[tuple[int, int]], self_pid: int, traced: int) -> list[tuple[int, int]]:
    """Model mutation of only complete self KERN_PROC rows."""

    return [(pid, flags & ~traced if pid == self_pid else flags) for pid, flags in rows]


def compact_objc_storage(values: list[tuple[str, bool]], *, class_list: bool) -> tuple[list[str | None], int]:
    """Model stable in-place compaction and sanitization of original-owned storage."""

    total = len(values)
    storage: list[str | None] = [value for value, _ in values]
    if class_list:
        # objc_copyClassList documents a nil terminator after its count.
        storage.append(None)
    kept = 0
    for value, hidden in values:
        if not hidden:
            storage[kept] = value
            kept += 1
    # ClassList clears through its documented terminator; ImageNames clears
    # every count-owned tail element without inventing a terminator contract.
    clear_end = total + 1 if class_list else total
    for index in range(kept, clear_end):
        storage[index] = None
    return storage, kept


def compact_objc_view(values: list[tuple[str, bool]], out_count_requested: bool) -> tuple[list[str], int | None]:
    """The runtime-owned class pointer array is compacted in place; no allocation path."""

    storage, kept = compact_objc_storage(values, class_list=True)
    return [value for value in storage[:kept] if value is not None], kept if out_count_requested else None


def getfsstat_route(buf_present: bool, bufsize: int) -> str:
    """Model the wrapper's XNU boundary routing before it filters entries."""

    if bufsize < 0:
        return "native-invalid"
    if buf_present and bufsize == 0:
        return "native-zero-capacity"
    if not buf_present:
        return "filtered-count"
    return "filtered-buffer"


class DirectoryDouble:
    """Model fresh fd-path classification with no retained DIR ownership."""

    def __init__(self) -> None:
        self.paths: dict[str, str] = {}

    def open(self, token: str, path: str) -> None:
        self.paths[token] = path

    def rename_or_rebind(self, token: str, path: str) -> None:
        require(token in self.paths, "directory token must be open")
        self.paths[token] = path

    def classify(self, token: str, errno: int, available: bool = True) -> tuple[str | None, int]:
        """Return the current resolved path without letting resolution alter errno."""

        saved_errno = errno
        if not available or token not in self.paths:
            return None, saved_errno
        return self.paths[token], saved_errno

    def close(self, token: str) -> None:
        self.paths.pop(token, None)


class TrackingState(str, Enum):
    FILTERED = "filtered"
    DEGRADING = "degrading"
    NATIVE = "native"


class CallbackState(str, Enum):
    REPLAYING = "replaying"
    ACTIVE = "active"
    NATIVE = "native"


@dataclass
class CatalogImageDouble:
    path: str
    header: int
    identity: int
    hidden: bool = False
    active: bool = True
    added: int = 0
    removed: int = 0


@dataclass
class CatalogEventDouble:
    kind: str
    image: CatalogImageDouble
    sequence: int


@dataclass
class DyldRegistrationDouble:
    callback: Callable[[CatalogImageDouble], None]
    hidden_reader: bool
    state: CallbackState = CallbackState.REPLAYING
    boundary: int = 0
    marker: int = 0


class CallbackCatalogDouble:
    """Portable WP4 contract model.  It intentionally makes all callback
    delivery observable so the checks below catch lock/replay ordering bugs."""

    def __init__(self) -> None:
        self.state = TrackingState.FILTERED
        self.images: list[CatalogImageDouble] = []
        self.events: list[CatalogEventDouble] = []
        self.registrations: list[DyldRegistrationDouble] = []
        self.sequence = 0
        self.identity = 0
        self.locked = False
        self.callback_under_lock = False
        self.force_allocation_failure = False

    def _degrade(self) -> None:
        if self.state is TrackingState.FILTERED:
            self.state = TrackingState.DEGRADING
            for registration in self.registrations:
                registration.state = CallbackState.NATIVE
            self.state = TrackingState.NATIVE

    def add(self, path: str, header: int, hidden: bool = False) -> CatalogImageDouble:
        if self.force_allocation_failure:
            self._degrade()
            raise MemoryError("deterministic catalog allocation failure")
        self.identity += 1
        self.sequence += 1
        image = CatalogImageDouble(path, header, self.identity, hidden, True, self.sequence)
        self.images.append(image)
        event = CatalogEventDouble("add", image, self.sequence)
        self.events.append(event)
        if self.state is TrackingState.FILTERED:
            self._dispatch_live(event)
        return image

    def remove(self, image: CatalogImageDouble) -> None:
        self.sequence += 1
        image.active = False
        image.removed = self.sequence
        event = CatalogEventDouble("remove", image, self.sequence)
        self.events.append(event)
        if self.state is TrackingState.FILTERED:
            self._dispatch_live(event)

    def _visible(self, registration: DyldRegistrationDouble, image: CatalogImageDouble) -> bool:
        return registration.hidden_reader or not image.hidden

    def _deliver(self, registration: DyldRegistrationDouble, image: CatalogImageDouble) -> None:
        require(not self.locked, "callback must never run under catalog/registry lock")
        self.callback_under_lock = self.callback_under_lock or self.locked
        if self._visible(registration, image):
            registration.callback(image)

    def _dispatch_live(self, event: CatalogEventDouble) -> None:
        for registration in self.registrations:
            if registration.state is CallbackState.ACTIVE:
                if event.kind == "remove":
                    # The C implementation has a synchronous dyld callback
                    # window for a remove. This model only needs ordering.
                    self._deliver(registration, event.image)
                elif event.image.active:
                    self._deliver(registration, event.image)
                else:
                    self._degrade()

    def register_add(self, callback: Callable[[CatalogImageDouble], None], hidden_reader: bool = False) -> DyldRegistrationDouble:
        registration = DyldRegistrationDouble(callback, hidden_reader)
        self.locked = True
        if self.state is not TrackingState.FILTERED or self.force_allocation_failure:
            self.locked = False
            self._degrade()
            registration.state = CallbackState.NATIVE
            return registration
        registration.boundary = self.sequence
        registration.marker = self.sequence
        self.registrations.append(registration)
        self.locked = False

        # Historical catalog, then only post-registration adds. An add that
        # was unloaded before delivery is a fail-stop handoff, never stale use.
        for image in self.images:
            if image.added <= registration.boundary and (not image.removed or image.removed > registration.boundary):
                if not image.active:
                    self._degrade()
                    return registration
                self._deliver(registration, image)
        registration.state = CallbackState.ACTIVE
        for event in list(self.events):
            if event.sequence <= registration.marker:
                continue
            if event.kind == "remove" or not event.image.active:
                self._degrade()
                return registration
            self._deliver(registration, event.image)
        return registration

    def snapshot(self) -> tuple[int, list[tuple[str, int, int]]]:
        # Return owned tuples rather than catalog references.
        return self.sequence, [(str(image.path), image.header, image.identity)
                               for image in self.images if image.active]


class PermanentRelayDouble:
    """Model the one-way permanent-bootstrap-relay fallback.

    A source event selects exactly one route.  FILTERED uses catalog delivery;
    PASSTHROUGH uses the already-installed native relay and sends the exact
    live event to already ACTIVE linked registrations.  New registrations use
    the original API after the route flips, so there is no second registration
    of a retained callback.  A replaying registration cannot safely receive a
    remove after the source callback returns; the model records that ambiguity
    as a fail-stop rather than inventing a stale delivery.
    """

    def __init__(self) -> None:
        self.state = TrackingState.FILTERED
        self.route = "filtered"
        self.linked: list[tuple[str, CallbackState, Callable[[str, int], None]]] = []
        self.native_registrations: list[str] = []
        self.delivery_failed = False
        self.ready = True
        self.events: list[tuple[str, int]] = []
        self.caller_policy_events: list[tuple[str, int]] = []
        self.timeline: list[tuple[str, str, int]] = []

    def link(self, kind: str, callback: Callable[[str, int], None],
             state: CallbackState = CallbackState.ACTIVE) -> None:
        require(self.route == "filtered", "only filtered registrations are retained by the relay")
        self.linked.append((kind, state, callback))

    def register_after_transition(self, kind: str) -> None:
        require(self.route == "passthrough", "native registration is only for a new post-transition client")
        self.native_registrations.append(kind)

    def degrade(self) -> None:
        if self.state is TrackingState.FILTERED:
            self.state = TrackingState.DEGRADING
        self.route = "passthrough"
        self.state = TrackingState.NATIVE

    def source_event(self, kind: str, header: int, transition: bool = False) -> None:
        if kind in ("add", "remove"):
            self.caller_policy_events.append((kind, header))
            self.timeline.append(("caller-policy", kind, header))
        if not self.ready:
            return
        if transition:
            self.degrade()
        if self.route == "filtered":
            self.events.append((f"filtered:{kind}", header))
            self.timeline.append(("filtered", kind, header))
            return
        # This represents the source callback itself: no lock, queue, pin,
        # allocation, or original registration surrounds the callback.
        self.events.append((f"raw:{kind}", header))
        self.timeline.append(("raw", kind, header))
        for registration_kind, state, callback in self.linked:
            if registration_kind != kind:
                continue
            if state is not CallbackState.ACTIVE:
                self.delivery_failed = True
                self.ready = False
                self.degrade()
                continue
            callback(kind, header)

    def fail_stop_after_partial_filtered_delivery(self, kind: str, header: int) -> None:
        """Model a route flip discovered after an earlier filtered callback.

        Re-driving the event raw would duplicate that earlier callback, so the
        hider relinquishes readiness and no later event is advertised as part
        of a coherent callback stream.
        """
        require(self.route == "filtered", "partial delivery starts in filtered mode")
        for registration_kind, state, callback in self.linked:
            if registration_kind == kind and state is CallbackState.ACTIVE:
                callback(kind, header)
                break
        self.events.append((f"filtered:{kind}", header))
        self.delivery_failed = True
        self.ready = False
        self.degrade()

    def child_after_fork(self) -> None:
        # The parent had fenced publication with its catalog lock.  The child
        # must not rely on an inherited filtered catalog or worker.
        self.state = TrackingState.NATIVE
        self.route = "passthrough"


@dataclass
class PinnedImageDouble:
    identity: int
    generation: int
    active: bool = True


class CallbackPinDouble:
    """Model a callback-local RTLD_NOLOAD lifetime pin.

    Handles are deliberately not cached. The post-acquisition
    identity/generation check is observable.  A failed bookkeeping probe
    consumes only its own loader error while TLS virtualization retains the
    callback caller's pre-existing one.
    """

    def __init__(self) -> None:
        self.generation = 1
        self.opens = 0
        self.closes = 0
        self.loader_error: str | None = "caller pending error"
        self.bookkeeping_failures_consumed = 0
        self._handles: set[int] = set()

    def acquire(
        self,
        image: PinnedImageDouble,
        after_open: Callable[[], None] | None = None,
        fail_no_load: bool = False,
    ) -> int | None:
        expected_identity = image.identity
        expected_generation = self.generation
        if not image.active:
            return None
        if fail_no_load:
            # The real helper snapshots the pending caller error into fixed
            # TLS, then consumes this internal RTLD_NOLOAD failure.
            self.bookkeeping_failures_consumed += 1
            return None
        self.opens += 1
        handle = self.opens
        self._handles.add(handle)
        if after_open:
            after_open()
        if (not image.active or image.identity != expected_identity or
                self.generation != expected_generation):
            self.release(handle)
            return None
        return handle

    def release(self, handle: int) -> None:
        require(handle in self._handles, "only a currently acquired pin may be released")
        self.closes += 1
        self._handles.remove(handle)

    @property
    def retained_handles(self) -> int:
        return len(self._handles)


class CallerCapabilityDouble:
    """Model exact-range trust and generation-invalidated return-address cache."""

    def __init__(self, range_capacity: int = 8) -> None:
        self.generation = 1
        self.range_capacity = range_capacity
        self.ranges: dict[str, tuple[tuple[int, int], ...]] = {}
        self.cache: dict[int, tuple[int, bool]] = {}
        self.internal_depth = 0

    def _invalidate(self) -> None:
        self.generation += 1
        self.cache.clear()

    def image_added(self) -> None:
        self._invalidate()

    def image_removed(self, name: str) -> None:
        self.ranges.pop(name, None)
        self._invalidate()

    def authorize_exact(self, requested: str, loaded: dict[str, tuple[tuple[int, int], ...]]) -> bool:
        image_ranges = loaded.get(requested)
        if image_ranges is None:
            return False
        other_count = sum(len(ranges) for name, ranges in self.ranges.items() if name != requested)
        if not image_ranges or len(image_ranges) > self.range_capacity - other_count:
            return False
        self.ranges[requested] = image_ranges
        self._invalidate()
        return True

    def enter_internal(self) -> None:
        self.internal_depth += 1

    def leave_internal(self) -> None:
        if self.internal_depth:
            self.internal_depth -= 1

    def can_read_hidden(self, address: int) -> bool:
        if self.internal_depth:
            return True
        cached = self.cache.get(address)
        if cached and cached[0] == self.generation:
            return cached[1]
        allowed = any(
            start <= address < end
            for image_ranges in self.ranges.values()
            for start, end in image_ranges
        )
        self.cache[address] = (self.generation, allowed)
        return allowed


IDENTITY_ENV_KEYS = {"XPC_SERVICE_NAME", "CFBundleIdentifier", "BUNDLE_IDENTIFIER"}


def normalized_bundle_candidate(value: str | None) -> str | None:
    """Portable model of the launchd identity grammar, not a bundle validator."""

    if not value:
        return None
    candidate = value.strip()
    if not candidate or "/" in candidate or "=" in candidate:
        return None
    candidate = candidate.split("[", 1)[0].strip()
    return candidate if candidate and "." in candidate else None


def bundle_candidate_from_spawn_value(value: str) -> str | None:
    if value.startswith("UIKitApplication:"):
        return normalized_bundle_candidate(value[len("UIKitApplication:"):])
    if "=" in value:
        key, candidate = value.split("=", 1)
        if key not in IDENTITY_ENV_KEYS:
            return None
        if candidate.startswith("UIKitApplication:"):
            candidate = candidate[len("UIKitApplication:"):]
        return normalized_bundle_candidate(candidate)
    return normalized_bundle_candidate(value)


def unique_identity(values: Iterable[str]) -> str | None:
    candidates = {candidate for value in values if (candidate := bundle_candidate_from_spawn_value(value))}
    return next(iter(candidates)) if len(candidates) == 1 else None


@dataclass(frozen=True)
class DependencyFixture:
    name: str
    hard: bool


def dependency_load_plan(selected: set[str], graph: dict[str, list[DependencyFixture]]) -> list[str] | None:
    """Model hard-only local dependency validation and postorder planning."""

    visiting: set[str] = set()
    visited: set[str] = set()
    plan: list[str] = []

    def visit(name: str) -> bool:
        if name in visited:
            return True
        if name in visiting:
            return False
        visiting.add(name)
        for dependency in graph.get(name, []):
            if not dependency.hard or dependency.name not in graph:
                continue
            if dependency.name not in selected or not visit(dependency.name):
                return False
        visiting.remove(name)
        visited.add(name)
        plan.append(name)
        return True

    return plan if all(visit(name) for name in selected) else None


def select_slice_for_arch(slices: list[tuple[str, str]], arch: str) -> tuple[str, str] | None:
    """Model selecting the executing arm64/arm64e slice, never first parseable."""

    for candidate in slices:
        if candidate[0] == arch:
            return candidate
    return None


def run_checks(artifact: Path | None = None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    known_gaps: list[dict[str, str]] = []

    def check(name: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except AssertionError as exc:
            checks.append({"name": name, "status": "fail", "detail": str(exc)})
        else:
            checks.append({"name": name, "status": "pass"})

    hider = production_text(HIDER)
    identity = production_text(HIDER_IDENTITY)
    identity_header = production_text(HIDER_IDENTITY_HEADER)
    caller_policy = production_text(HIDER_CALLER_POLICY)
    caller_policy_header = production_text(HIDER_CALLER_POLICY_HEADER)
    hider_internal = production_text(HIDER_INTERNAL)
    common = production_text(COMMON)
    main = production_text(MAIN)
    roothider_common = production_text(ROOTHIDER_COMMON)
    roothider_main = production_text(ROOTHIDER_MAIN)
    launchd = production_text(LAUNCHD)
    litehook = production_text(LITEHOOK)
    rhi_rebind = production_text(RHI_REBIND)
    rhi_rebind_header = production_text(RHI_REBIND_HEADER)
    hider_hook_session = production_text(HIDER_HOOK_SESSION)

    def check_launchd_identity_fixture() -> None:
        require(bundle_candidate_from_spawn_value("UIKitApplication:com.example.App[0x123]") == "com.example.App", "UIKitApplication label must preserve its app identifier")
        require(bundle_candidate_from_spawn_value("com.example.service") == "com.example.service", "exact dotted service label must remain valid")
        require(bundle_candidate_from_spawn_value("com.example.App[launchd]") == "com.example.App", "bracketed exact label must normalize")
        require(bundle_candidate_from_spawn_value("XPC_SERVICE_NAME=com.example.service") == "com.example.service", "recognized KEY=value must contribute only its value")
        require(bundle_candidate_from_spawn_value("UNRELATED_DOTTED_VALUE=api.example.com") is None, "unrelated dotted environment value must not become identity")
        require(bundle_candidate_from_spawn_value("com.example.App=bad") is None, "structural direct label must be rejected")
        require(unique_identity(["UNRELATED=api.example.com", "com.example.A", "com.example.B"]) is None, "conflicting heuristic identities must remain ambiguous")

    check("launchd_bundle_identity_fixture", check_launchd_identity_fixture)

    def check_launchd_identity_source_contract() -> None:
        require("RootHideIsIdentityEnvironmentKey" in launchd, "recognized identity-key gate missing")
        require('[trimmedCandidate containsString:@"="]' in launchd, "direct candidate must reject structured '=' input")
        require('key not' not in launchd, "Objective-C source must not use a non-native key-membership expression")
        require("XPC_SERVICE_NAME" in launchd, "XPC service identity label missing")
        require("RootHideBundleIdentifierSourceAmbiguousHeuristic" in launchd, "ambiguous identity state missing")

    check("launchd_bundle_identity_source_contract", check_launchd_identity_source_contract)

    def check_dependency_fixture() -> None:
        graph = {
            "A": [DependencyFixture("B", True), DependencyFixture("Optional", False)],
            "B": [],
            "Optional": [],
        }
        plan = dependency_load_plan({"A", "B"}, graph)
        require(plan is not None and plan.index("B") < plan.index("A"), "hard local dependency must load first")
        require(dependency_load_plan({"A"}, graph) is None, "missing selected hard local dependency must reject")
        require(dependency_load_plan({"Optional"}, {"Optional": [DependencyFixture("A", False)], "A": []}) == ["Optional"], "weak local edge must not impose order or selection")
        require(dependency_load_plan({"A", "B"}, {"A": [DependencyFixture("B", True)], "B": [DependencyFixture("A", True)]}) is None, "hard local dependency cycle must reject")
        slices = [("arm64", "slice0"), ("arm64e", "slice1")]
        require(select_slice_for_arch(slices, "arm64e") == ("arm64e", "slice1"), "arm64e must not use first arm64 slice")
        require(select_slice_for_arch(slices, "arm64") == ("arm64", "slice0"), "arm64 must select its matching slice")
        require(select_slice_for_arch(slices, "arm64e") != select_slice_for_arch(slices, "arm64"), "architecture selections must remain distinct")

    check("selected_tweak_dependency_and_arch_fixture", check_dependency_fixture)

    def check_dependency_source_contract() -> None:
        for symbol in ("HiddenTweakDependency", "hidden_tweak_slice_matches_executing_arch", "CPU_SUBTYPE_ARM64E", "sizeofcmds", "sliceSize"):
            require(symbol in roothider_main, f"dependency parser hardening missing {symbol}")
        require("dependency->hard" in roothider_main, "only hard local dependencies may drive graph rejection")
        require("LC_LOAD_WEAK_DYLIB" in roothider_main and "LC_LAZY_LOAD_DYLIB" in roothider_main, "weak/lazy edge handling missing")
        require("roothide_hidden_tweak_note_loader_result" in main, "TweakLoader result must feed selected-tweak transaction state")
        require("skip TweakLoader after failed selected-tweak prepare" in main, "TweakLoader must be gated on successful prepare")
        require("bool roothide_hidden_tweak_prepare_for_loader" in roothider_main, "prepare API must return an explicit result")

    check("selected_tweak_dependency_source_contract", check_dependency_source_contract)

    def check_environment_handoff_source_contract() -> None:
        require("bool envbuf_setenv" in production_text(ROOT / "BaseBin/systemhook/src/envbuf.c"), "envbuf_setenv must report mutation success")
        require("bool envbuf_unsetenv" in production_text(ROOT / "BaseBin/systemhook/src/envbuf.c"), "envbuf_unsetenv must report mutation success")
        require("candidateEnvc" in launchd and "mutationsSucceeded" in launchd, "hidden launchd handoff must be transactional")
        require("ROOTHIDE_HIDDEN_TWEAK_LIST" in launchd and "ROOTHIDE_HIDER_PROFILE" in launchd, "required handoff fields missing")
        require("errno = ENOMEM" in common, "systemhook child handoff must fail instead of passing a NULL environment")
        require("retain_effective_hider_profile_for_child" in hider, "xpcproxy must retain the effective hider profile after consuming its environment")
        require("hidden_dylib_hider_envbuf_apply(envc)" in roothider_main, "xpcproxy child bridge must propagate profile and disabled-hook policy")
        require("int mutationErrorReturn" in common, "shared spawn/exec mutation failures must preserve each API's return ABI")
        require("jetsamMultiplier, ENOMEM" in common, "posix_spawn mutation failure must return its errno value")
        require("trust_binary, 0, -1" in common, "execve mutation failure must return -1 with errno set")

        # Every bridge value is retained before the only physical environment
        # compaction and before the hider can publish import hooks.
        consume_hidden = main.find("gHiddenInjection = consume_hidden_injection_env()")
        consume_selected = main.find("roothide_hidden_tweak_consume_environment()", consume_hidden)
        consume_profile = main.find("hidden_dylib_hider_consume_environment_profile()", consume_selected)
        scrub = main.find("scrub_hidden_process_environment()", consume_profile)
        publish = main.find("hidden_dylib_hider_init()", scrub)
        require(min(consume_hidden, consume_selected, consume_profile, scrub, publish) >= 0,
                "hidden startup seams must all be present")
        require(consume_hidden < consume_selected < consume_profile < scrub < publish,
                "bridge consumption must precede physical scrub and hook publication")
        require("_NSGetEnviron" in main and "count + 1U" in main and
                "rhi_hider_env_scrub_vector" in main,
                "physical environment scrub must use an exact terminated vector")
        require("roothide_hidden_tweak_consume_environment" in roothider_main and
                "gHiddenTweakEnvironmentConsumed" in roothider_main,
                "selected-tweak bridge consumption must be idempotent")
        require("hidden_dylib_hider_consume_environment_profile" in hider and
                "g_hider_profile_consumed" in hider,
                "hider profile bridge consumption must be idempotent")

    check("environment_handoff_source_contract", check_environment_handoff_source_contract)

    def check_environment_view_matrix_fixture() -> None:
        markers = ("DYLD_INSERT_LIBRARIES", "ROOTHIDE_HIDER_PROFILE", "_SafeMode")
        public = ("PATH", "HOME")
        for marker in markers:
            require(marker.startswith(("DYLD_", "ROOTHIDE_", "_")), "marker fixture drift")
        require(all(not value.startswith(("DYLD_", "ROOTHIDE_", "_SafeMode")) for value in public),
                "PATH and unrelated environment variables must stay visible")
        procargs = Procargs2Double()
        result, data, needed = procargs.query(None)
        require(result == 0 and data == b"" and needed == len(procargs.materialized),
                "filtered PROCARGS2 size query must report the word-aligned filtered view")
        result, data, needed = procargs.query(Procargs2Double.WORD_BYTES)
        require(result == Procargs2Double.EINVAL and data == b"" and
                needed == Procargs2Double.WORD_BYTES,
                "PROCARGS2 must reject buffers no larger than its argc word")
        result, data, needed = procargs.query(Procargs2Double.WORD_BYTES + Procargs2Double.ARG_MAX + 1)
        require(result == Procargs2Double.EINVAL and data == b"" and
                needed == Procargs2Double.WORD_BYTES + Procargs2Double.ARG_MAX + 1,
                "PROCARGS2 must preserve XNU's oversized-buffer EINVAL boundary")
        short_capacity = len(procargs.visible) - 1
        result, data, needed = procargs.query(short_capacity)
        expected_short = procargs.visible[:Procargs2Double.WORD_BYTES] + \
            Procargs2Double.legacy_short_payload(
                procargs.visible[Procargs2Double.WORD_BYTES:],
                short_capacity - Procargs2Double.WORD_BYTES)
        require(result == 0 and needed == short_capacity and data == expected_short and
                b"raw-marker" not in data,
                "short PROCARGS2 must use the filtered private page-window zero-tail contract")
        # XNU's zero boundary is relative to a rounded backing range, not the
        # payload start. Cover equal rounded windows and a cross-page window.
        equal_window = b"abcdefghijklmnopqrst"
        require(Procargs2Double.legacy_short_payload(equal_window, 17) ==
                equal_window[3:5] + b"\x00" * 15,
                "same rounded PROCARGS2 window must translate its zero boundary from backing storage")
        cross_page = b"abcdefghijklmnopqrst"
        require(Procargs2Double.legacy_short_payload(cross_page, 15) ==
                cross_page[5:19] + b"\x00",
                "cross-page PROCARGS2 window must retain only the pre-zero tail prefix")
        result, data, needed = procargs.query(len(procargs.materialized), grow_once=True)
        require(result == 0 and data == procargs.visible and needed == len(procargs.visible),
                "a sufficient PROCARGS2 fetch must report its unrounded filtered consumed length")
        odd = Procargs2Double(b"\x01\x00\x00\x00/x\x00ODD=1\x00\x00")
        require(len(odd.visible) % Procargs2Double.WORD_BYTES != 0,
                "odd PROCARGS2 fixture must exercise sysctl-only alignment")
        result, data, needed = odd.query(None)
        require(result == 0 and needed == len(odd.materialized) and
                odd.materialized.startswith(odd.visible) and
                odd.materialized[len(odd.visible):] == b"\x00" * (len(odd.materialized) - len(odd.visible)),
                "odd filtered PROCARGS2 size query must include explicit zero word padding")
        result, data, needed = odd.query(len(odd.materialized))
        require(result == 0 and data == odd.visible and needed == len(odd.visible),
                "odd filtered PROCARGS2 fetch must keep XNU's unrounded consumed length")
        require(procargs.query(None, malformed=True)[0] == Procargs2Double.EIO,
                "malformed PROCARGS2 must fail closed")
        require(procargs.query(None, allocation_failed=True)[0] == Procargs2Double.ENOMEM,
                "allocation failure must fail closed")
        for kwargs in ({"self_pid": False}, {"readonly": False}, {"internal": True}):
            require(procargs.query(None, **kwargs)[0] == "native",
                    "other-PID, writes, and internal callers must remain native")

    check("environment_procargs2_view_matrix_fixture", check_environment_view_matrix_fixture)

    def check_profile_model() -> None:
        require(profile_state(None, None) == ProfileState(), "empty profile must keep all strict hooks enabled")
        require(profile_state("core", None) == ProfileState(False, False, False, False, False, False), "core must disable every strict hook")
        require(profile_state("minimal", None) == ProfileState(False, False, False, False, False, False), "minimal must disable every strict hook")
        lite = profile_state("lite", None)
        require(not lite.objc_copy_class_list and not lite.url_schemes, "lite disables class-list and URL hooks")
        require(lite.objc_runtime and lite.environment and lite.filesystem and lite.directory, "lite keeps the remaining strict hooks")
        aliases = profile_state(None, "copy-class-list,can-open-url:getenv;fs dir")
        require(not aliases.objc_copy_class_list and not aliases.url_schemes, "disabled aliases must be tokenized")
        require(not aliases.environment and not aliases.filesystem and not aliases.directory, "filesystem aliases disable directory too")
        require(profile_state(None, "prefix-getenvx").environment, "tokens must not match by substring")
        require(profile_state("lite", "all-strict").__eq__(ProfileState(False, False, False, False, False, False)), "all-strict must override lite")

    check("profile_and_disabled_token_model", check_profile_model)

    def check_profile_source_contract() -> None:
        require('getenv("ROOTHIDE_HIDER_PROFILE")' in hider, "profile environment variable missing")
        require('getenv("ROOTHIDE_HIDER_DISABLED_HOOKS")' in hider, "disabled-hook environment variable missing")
        for token in (
            "all-strict", "objc-runtime", "objc-copy-class-list", "copy-class-list",
            "url-schemes", "can-open-url", "environment", "getenv", "filesystem",
            "fs", "directory", "dir",
        ):
            require(f'"{token}"' in hider, f"production parser token missing: {token}")
        require('unsetenv("ROOTHIDE_HIDER_PROFILE")' in hider, "profile must be consumed")
        require('unsetenv("ROOTHIDE_HIDER_DISABLED_HOOKS")' in hider, "disabled-hook list must be consumed")

    check("profile_production_static_contract", check_profile_source_contract)

    def check_executable_fixture() -> None:
        images = [
            ImageFixture(0, MH_DYLIB, "/usr/lib/systemhook.dylib"),
            ImageFixture(1, MH_EXECUTE, "/Applications/Test.app/Test"),
            ImageFixture(2, MH_DYLIB, "/usr/lib/libobjc.A.dylib"),
        ]
        selected = select_executable(images)
        require(selected is not None and selected.index == 1, "must select MH_EXECUTE rather than image zero")
        require(select_executable([ImageFixture(0, MH_DYLIB, "only.dylib")]) is None, "an arbitrary dylib must never become the executable fallback")
        require(select_executable([]) is None, "empty image list must be handled")

    check("true_executable_selection_fixture", check_executable_fixture)

    def check_identity_source_contract() -> None:
        require("MH_EXECUTE" in identity, "identity layer must recognize the executable Mach-O filetype")
        require("rhi_hider_identity_image_text_range" in identity, "identity layer must validate __TEXT ranges")
        require("rhi_hider_identity_executable_ranges" in identity, "identity layer must enumerate every executable segment")
        require("LC_SEGMENT_64" in identity and "SEG_TEXT" in identity, "identity range must be derived from validated __TEXT")
        require("VM_PROT_EXECUTE" in identity, "executable ranges must use segment execute protections")
        require("__builtin_add_overflow" in identity, "identity layer must reject malformed load-command arithmetic")
        require("ptrauth_strip" in identity, "arm64e Mach-O data pointers must be canonicalized before arithmetic")
        require("rhi_hider_identity_copy_path" in identity, "identity path must be process-lifetime owned")
        require("fallback_header" not in identity and "used_fallback" not in identity, "identity layer must not fall back to an arbitrary image")
        require("rhi_hider_identity_executable_path" in hider, "hider must consume stable executable identity")
        require("rhi_hider_identity_executable_header" in hider, "dladdr rewrite must use stable executable header")
        require("_dyld_get_image_name(0)" not in hider, "hider must not assume image zero is executable")
        require("orig_dyld_get_image_header(0)" not in hider, "dladdr rewrite must not use image-zero header")

    check("true_executable_identity_production_contract", check_identity_source_contract)

    def check_caller_capability_fixture() -> None:
        policy = CallerCapabilityDouble()
        loaded = {
            "/private/preboot/.jbroot-abc/usr/lib/A.dylib": ((0x1000, 0x1200), (0x1800, 0x2000)),
            "/private/preboot/.jbroot-abc/usr/lib/B.dylib": ((0x3000, 0x4000),),
        }
        require(not policy.can_read_hidden(0x1100), "unknown caller must default external")
        require(policy.authorize_exact("/private/preboot/.jbroot-abc/usr/lib/A.dylib", loaded), "exact loaded selected tweak must authorize")
        require(policy.can_read_hidden(0x1100) and policy.can_read_hidden(0x1900), "every validated executable segment must receive the selected tweak capability")
        require(not policy.can_read_hidden(0x1300), "non-executable address gaps must remain external")
        require(not policy.can_read_hidden(0x3100), "unselected .jbroot image must remain external")
        require(not policy.authorize_exact("A.dylib", loaded), "basename must not grant capability")
        policy.image_removed("/private/preboot/.jbroot-abc/usr/lib/A.dylib")
        require(not policy.can_read_hidden(0x1100), "unload must invalidate cached trust before address reuse")
        policy.enter_internal()
        policy.enter_internal()
        require(policy.can_read_hidden(0xDEAD), "nested internal scope grants same-thread access")
        policy.leave_internal()
        require(policy.can_read_hidden(0xDEAD), "inner scope leave must preserve outer capability")
        policy.leave_internal()
        require(not policy.can_read_hidden(0xDEAD), "final scope leave must restore external default")
        limited = CallerCapabilityDouble(range_capacity=1)
        require(not limited.authorize_exact("/private/preboot/.jbroot-abc/usr/lib/A.dylib", loaded), "range-capacity exhaustion must fail closed without a partial capability")
        require(not limited.can_read_hidden(0x1100), "failed range authorization must not leave stale trust")

    check("caller_capability_generation_fixture", check_caller_capability_fixture)

    def check_caller_capability_source_contract() -> None:
        require("rhi_hider_caller_can_read_hidden" in caller_policy, "caller policy entry point missing")
        require("rhi_hider_caller_authorize_loaded_image_path" in caller_policy, "selected-tweak authorization seam missing")
        require("rhi_hider_caller_image_removed" in caller_policy, "unload invalidation missing")
        require("rhi_hider_caller_internal_read_enter" in caller_policy, "internal read scope missing")
        require("g_generation" in caller_policy and "rhi_hider_caller_advance_generation_locked" in caller_policy, "return-address cache must be generation aware")
        require("rhi_hider_identity_executable_ranges" in caller_policy, "authorization must register all validated executable ranges")
        require("RHI_HIDER_CALLER_AUTH_RANGE_CAPACITY" in caller_policy, "range capacity must be an explicit authorization result")
        require("ptrauth_key_return_address" in caller_policy and "ptrauth_key_function_pointer" in caller_policy, "arm64e return/function pointers must be canonicalized before range comparison")
        require("RHI_HIDER_INTERNAL" in caller_policy_header, "caller capability surface must be hidden from injected code")
        require("RHI_HIDER_INTERNAL" in identity_header and "RHI_HIDER_INTERNAL" in hider_internal, "hider implementation seams must be hidden")
        require("dyld_image_path_containing_address(ra)" not in hider, "caller capability must not use path classification")
        require("g_caller_cache" not in hider, "legacy path-based caller cache must be removed")
        require("rhi_hider_caller_authorize_loaded_image_path(path, &authorization)" in roothider_main, "only verified selected loads may authorize ranges")
        require("rhi_hider_caller_authorization_result_name(authorization)" in roothider_main, "authorization failure must be propagated and diagnosable")
        require("rhi_hider_caller_internal_read_enter" not in roothider_main, "TLS capability must not be broadened across dlopen")

    check("caller_capability_production_contract", check_caller_capability_source_contract)

    if artifact is not None:
        def check_private_hider_export_surface() -> None:
            require(artifact.is_file(), f"missing systemhook artifact: {artifact}")
            completed = subprocess.run(
                ["xcrun", "dyld_info", "-exports", str(artifact)],
                check=False,
                capture_output=True,
                text=True,
            )
            require(completed.returncode == 0, f"could not inspect exports: {completed.stderr.strip()}")
            for symbol in (
                "rhi_hider_caller_authorize_loaded_image_path",
                "rhi_hider_caller_internal_read_enter",
                "rhi_hider_caller_internal_read_leave",
                "rhi_hider_caller_register_own_function",
                "rhi_hider_identity_executable_path",
                "hidden_dylib_hider_init",
                "hidden_dylib_hider_catalog_snapshot",
                "hidden_dylib_hider_catalog_generation_is_current",
                "rhi_rebind_transaction_prepare_global",
                "rhi_hider_hook_session_start",
            ):
                require(symbol not in completed.stdout, f"private hider symbol exported: {symbol}")

        check("private_hider_export_surface", check_private_hider_export_surface)

    def check_hook_state_fixture() -> None:
        active = HookFixture("getenv", HookState.ACTIVE, "h_getenv")
        require(remap_result(active) == "h_getenv", "active hook must be advertised")
        for state in (HookState.NOT_ATTEMPTED, HookState.PREPARED, HookState.FAILED, HookState.PARTIAL, HookState.UNKNOWN):
            require(remap_result(HookFixture("getenv", state, "h_getenv")) is None, f"{state.value} hook must not be advertised")
        require(remap_result(active, strict_enabled=False) is None, "strict remap must remain hidden before strict phase")

    check("hook_state_and_remap_truth_fixture", check_hook_state_fixture)

    def check_selected_readiness_contract() -> None:
        model = SelectedReadinessModel(
            transaction_published=False,
            installed=True,
            state=HookState.ACTIVE,
            live_state=HookState.ACTIVE,
            dlopen_active=True,
        )
        require(not model.ready(), "selected readiness must fail closed before transaction publication")

        model.transaction_published = True
        require(model.ready(), "published active selected transaction must be ready")

        model.live_state = HookState.PARTIAL
        require(not model.ready(), "late transaction degradation must invalidate selected readiness")
        require(model.state is HookState.FAILED and not model.installed,
                "selected readiness invalidation must be one-way")
        model.live_state = HookState.ACTIVE
        model.dlopen_active = True
        require(not model.ready(), "invalidated selected readiness must not reactivate")

    check("selected_tweak_readiness_publication_fixture", check_selected_readiness_contract)

    def check_selected_readiness_source_contract() -> None:
        require("#include <stdatomic.h>" in roothider_main,
                "selected readiness owner must use C11 atomics")
        for token in (
            "atomic_bool dlopen_fallback_hook_installed",
            "static atomic_bool gHiddenTweakHooksInstalled",
            "static atomic_int gHiddenTweakHookState",
            "_Atomic(rhi_rebind_transaction_t *) gHiddenTweakFallbackTransaction",
            "atomic_compare_exchange_strong_explicit(&gHiddenTweakHookState",
            "atomic_store_explicit(&gHiddenTweakFallbackTransaction, transaction, memory_order_release)",
            "atomic_store_explicit(&gHiddenTweakHooksInstalled, true, memory_order_release)",
            "atomic_store_explicit(&gHiddenTweakHookState, RHI_HOOK_ACTIVE, memory_order_release)",
        ):
            require(token in roothider_main, f"selected readiness atomic contract missing: {token}")
        require("extern atomic_bool dlopen_fallback_hook_installed" in hider,
                "hider advertisement must declare the fallback flag atomically")
        require("atomic_load_explicit(&dlopen_fallback_hook_installed, memory_order_acquire)" in hider,
                "hider advertisement must acquire the fallback publication")
        require(
            re.search(
                r"atomic_load_explicit\(\s*&gHiddenTweakFallbackTransaction\s*,\s*memory_order_acquire\s*\)",
                roothider_main,
            ),
            "selected readiness must acquire its published transaction pointer",
        )
        require(
            re.search(
                r"atomic_load_explicit\(\s*&dlopen_fallback_hook_installed\s*,\s*memory_order_acquire\s*\)",
                roothider_main,
            ),
            "selected readiness must acquire its fallback advertisement flag",
        )
        pointer_publish = roothider_main.find(
            "atomic_store_explicit(&gHiddenTweakFallbackTransaction, transaction, memory_order_release)")
        installed_publish = roothider_main.find(
            "atomic_store_explicit(&dlopen_fallback_hook_installed, true, memory_order_release)")
        require(pointer_publish >= 0 and installed_publish > pointer_publish,
                "selected fallback flag must publish only after its transaction pointer")
        require("rhi_rebind_transaction_hook_is_active(transaction, \"dlopen\")" in roothider_main,
                "selected readiness must query the live transaction hook state")

    check("selected_tweak_readiness_atomic_source_contract", check_selected_readiness_source_contract)

    def check_remap_source_contract() -> None:
        require("hidden_dylib_hider_dlsym_remap" in hider, "remap entry point missing")
        for symbol in ("_dyld_image_count", "dlsym", "dladdr", "getenv", "opendir", "sysctlbyname"):
            require(f'"{symbol}"' in hider, f"remap table missing {symbol}")
        require(
            "g_strict_hooks_enabled" in hider
            or "g_strict_state" in hider
            or "hider_strict_hooks_ready" in hider,
            "strict phase state missing",
        )

    check("hook_remap_production_static_contract", check_remap_source_contract)

    def check_result_aware_rebind_contract() -> None:
        require("RHI_REBIND_NONE" in rhi_rebind_header and "RHI_REBIND_COMPLETE" in rhi_rebind_header, "transaction must distinguish no mutation from complete mutation")
        require("RHI_REBIND_PARTIAL" in rhi_rebind_header and "RHI_REBIND_UNKNOWN" in rhi_rebind_header, "post-write failure states missing")
        for state in ("RHI_HOOK_NOT_ATTEMPTED", "RHI_HOOK_PREPARED", "RHI_HOOK_ACTIVE", "RHI_HOOK_FAILED", "RHI_HOOK_PARTIAL", "RHI_HOOK_UNKNOWN"):
            require(state in rhi_rebind_header, f"per-hook state missing {state}")
        require("rhi_transaction_image_snapshot_stable" in rhi_rebind and "rhi_commit_slots" in rhi_rebind, "all current slots must be prepared and revalidated before commit")
        require("__atomic_store_n" in rhi_rebind and "__ATOMIC_RELEASE" in rhi_rebind, "slot writes must use release atomics")
        require("rhi_pac_sign_key" in rhi_rebind and "rhi_slot_schema_matches" in rhi_rebind and "__auth_got" in rhi_rebind, "authenticated GOT slots need exact file-schema signing and raw PAC validation")
        require("mach_vm_region_recurse" in rhi_rebind and "original_protection" in rhi_rebind and "mach_vm_protect" in rhi_rebind, "writer must record and restore actual page protections")
        require("LC_DYLD_CHAINED_FIXUPS" in rhi_rebind and "rhi_scan_chained_image" in rhi_rebind and "rhi_walk_chained_image" in rhi_rebind and "rhi_open_file_view" in rhi_rebind, "chained imports must use validated original-file words rather than live resolved slots")
        require("rhi_chained_imports_validate" in rhi_rebind and "rhi_decode_chain_pointer" in rhi_rebind and "rhi_select_file_slice" in rhi_rebind, "chained imports must validate names, fat-slice CPU identity, addends and PAC schema before planning")
        require("rhi_legacy_import_metadata_init" in rhi_rebind and "rhi_legacy_slot_hook_index" in rhi_rebind, "legacy candidate discovery must use indirect-symbol metadata, not pointer aliases")
        require("RHI_IMPORT_MALFORMED" in rhi_rebind and "rhi_import_name_matches_spec" in rhi_rebind and "predecessor != rhi_strip_function" in rhi_rebind, "metadata-selected slots must reject malformed indirect tables and prove canonical predecessors")
        require("rhi_rebind_transaction_activate_global" in rhi_rebind, "new image handling must stay on the same result-aware transaction")
        require("g_native_register_add_image" in rhi_rebind and "g_native_register_remove_image" in rhi_rebind, "dyld lifecycle registration must use captured native entry points")
        require("rhi_global_image_removed" in rhi_rebind and "image.header = NULL" in rhi_rebind and "g_lifecycle_generation" in rhi_rebind, "dlclose must invalidate stale identity and generation before address reuse")
        require("g_writer_lock" in rhi_rebind and "info.is_submap" in rhi_rebind and "_Alignof(uintptr_t)" in rhi_rebind and "rhi_transaction_image_snapshot_stable(transaction)" in rhi_rebind, "writer must serialize, identity-revalidate and validate whole leaf pages before atomic writes")
        require("if (start == end) return RHI_REBIND_COMPLETE" in rhi_rebind and "slot_count == 0" not in rhi_rebind[rhi_rebind.find("rhi_rebind_transaction_all_hooks_prepared"):], "zero current sites must be a valid monitored session, not a fabricated failed hook")
        require("litehook_rebind_symbol(" not in hider, "hider must not call LiteHook's result-less rebind API")
        require("litehook_rebind_symbol(" not in roothider_main, "selected loader fallback must not call LiteHook's result-less rebind API")
        require("rhi_hider_hook_session_hook_is_active" in hider and "rhi_hider_hook_session_start" in hider_hook_session, "dlsym advertisement must consult verified per-hook session state")
        require("roothide_hidden_tweak_hooks_ready" in roothider_main and "roothide_hidden_tweak_hooks_ready" in main, "selected tweak progress must be gated on a verified dyld hook transaction")
        require(
            "rhi_rebind_transaction_hook_is_active(gHiddenTweakFallbackTransaction, \"dlopen\")" in roothider_main
            or "rhi_rebind_transaction_hook_is_active(transaction, \"dlopen\")" in roothider_main,
            "selected readiness must query the live fallback transaction rather than a cached ACTIVE bit",
        )
        require("hider_strict_hook_is_ready" in hider and "hider_strict_hooks_ready" in hider, "strict replacements must forward once their own session or core view loses verification")
        require("unverified; refusing transaction before mutation" in roothider_main, "private dyld vtable must refuse absent ABI proof")

        raw_vtable_call = main.find("dyld_hook_routine(*gDyldPtr")
        hidden_guard = main.rfind("if (!gHiddenInjection)", 0, raw_vtable_call)
        require(raw_vtable_call >= 0 and hidden_guard >= 0, "raw gDyld mutation must remain guarded to non-hidden legacy mode")

        active = HookFixture("one", HookState.ACTIVE, "h_one")
        missing = HookFixture("two", HookState.NOT_ATTEMPTED, "h_two")
        require(session_ready(True, [active]), "required session with all verified hooks must be ready")
        require(not session_ready(True, [active, missing]), "required multi-hook session must reject missing hook slots before READY")
        require(not session_ready(True, [HookFixture("one", HookState.PARTIAL, "h_one")]), "required partial transaction must never become ready")
        require(session_ready(False, [active]), "one-hook optional strict session may be ready independently")
        require("rhi_rebind_transaction_all_hooks_prepared" in hider_hook_session and "rhi_rebind_transaction_all_hooks_active" in hider_hook_session, "required session must demand every hook at prepare and ready time")

    check("result_aware_rebind_production_contract", check_result_aware_rebind_contract)

    def check_dlsym_fixture() -> None:
        dlsym = DlsymDouble()
        require(dlsym.lookup("handle-a", "known") == "handle-a-known", "explicit handle lookup failed")
        require(dlsym.lookup("RTLD_DEFAULT", "known") == "default-known", "RTLD_DEFAULT lookup failed")
        require(dlsym.lookup("RTLD_NEXT", "shared") == "next-shared", "RTLD_NEXT lookup failed")
        require(dlsym.lookup("RTLD_DEFAULT", "missing") is None, "missing symbol must return NULL")
        require(dlsym.dlerror() == "symbol not found: missing", "missing symbol must set dlerror")
        require(dlsym.dlerror() is None, "dlerror must consume the pending error")
        require(
            dlsym.lookup("handle-a", "remapped", {"remapped": "h_remapped"}) == "h_remapped",
            "active policy remap must succeed independent of the original handle lookup",
        )
        require(dlsym.dlerror() is None, "remapped success must clear the failed original lookup error")
        require(dlsym.lookup("RTLD_DEFAULT", "hidden") is None, "hidden resolved result must be denied")
        require(dlsym.dlerror() == "symbol not found: hidden", "denied result must use dlsym-shaped error")
        require(dlsym.dlerror() is None, "denied result error must be one-shot")
        require(dlsym.lookup("RTLD_DEFAULT", None) is None, "NULL symbol must delegate safely")
        require(dlsym.dlerror() == "stock invalid symbol", "NULL symbol must not manufacture a hidden-result error")

        worker_result: list[str | None] = []

        def denied_in_worker() -> None:
            require(dlsym.lookup("RTLD_DEFAULT", "hidden") is None, "worker hidden result must be denied")
            worker_result.append(dlsym.dlerror())
            worker_result.append(dlsym.dlerror())

        worker = threading.Thread(target=denied_in_worker)
        worker.start()
        worker.join()
        require(worker_result == ["symbol not found: hidden", None], "denied error must stay thread-local and one-shot")
        require(dlsym.dlerror() is None, "worker denial must not poison caller thread")

    check("dlsym_handle_next_dlerror_fixture", check_dlsym_fixture)

    def check_dlsym_caller_relative_fixture() -> None:
        dlsym = CallerRelativeDlsymDouble()

        # SELF begins at the caller. NEXT begins strictly after it in the
        # complete load order, which includes otherwise-hidden images.
        require(
            dlsym.relative("SELF", "caller", "self", external=True) == "caller-symbol",
            "RTLD_SELF must begin with the true caller image",
        )
        require(
            dlsym.relative("NEXT", "caller", "next", external=True) == "next-symbol",
            "RTLD_NEXT must exclude every image at or before the caller",
        )
        require(
            dlsym.opens[:3] == [("caller", False), ("hidden", False), ("public", False)],
            "SELF/NEXT must use saved-original per-image pins in catalog order",
        )
        require(dlsym.closes == [name for name, _main in dlsym.opens],
                "every successfully acquired caller-relative pin must be closed")

        # Main must use NULL (represented by main=True), non-main images use
        # no-load pins. No image is silently skipped when its pin fails.
        main = CallerRelativeDlsymDouble()
        require(main.relative("SELF", "main", "main", external=True) == "main-symbol",
                "main executable provider lookup failed")
        require(main.opens == [("main", True)] and main.closes == ["main"],
                "main must use a NULL-style pin and release it")

        # Linear catalog order is restricted to a verified flat namespace.
        # A two-level caller must make no internal pins and use the explicit
        # native fallback, whose wrapper-relative semantics remain a gap.
        two_level = CallerRelativeDlsymDouble()
        two_level.images[1].two_level = True
        require(two_level.relative("NEXT", "caller", "fallback-hidden", external=True) is None,
                "two-level caller must retain native fallback availability")
        require(two_level.fallback_calls == 1 and not two_level.opens and not two_level.closes,
                "two-level caller must not use the flat catalog resolver")
        require(two_level.dlerror() == "symbol not found: fallback-hidden",
                "two-level fallback must preserve external hidden-result filtering")

        failed_pin = CallerRelativeDlsymDouble()
        failed_pin.pin_fail_identity = 3
        require(failed_pin.relative("NEXT", "caller", "shared", external=True) is None,
                "a pin failure must fall back, never skip the first possible provider")
        require(failed_pin.fallback_calls == 1 and failed_pin.opens == [("hidden", False)],
                "pin failure must not open or select a later provider")

        # The first provider may be hidden. External code is denied there even
        # if a later public image exports the same symbol; privileged code sees
        # the real first result. NULL-valued exports are still successful.
        external = CallerRelativeDlsymDouble()
        require(external.relative("NEXT", "caller", "shared", external=True) is None,
                "the first hidden provider must deny an external caller")
        require(external.dlerror() == "symbol not found: shared" and external.dlerror() is None,
                "relative hidden denial must be one-shot")
        internal = CallerRelativeDlsymDouble()
        require(internal.relative("NEXT", "caller", "shared", external=False) == "hidden-symbol",
                "trusted callers must receive the true hidden first provider")
        reexport = CallerRelativeDlsymDouble()
        require(reexport.relative("NEXT", "hidden", "reexport", external=True) is None,
                "public re-export of a hidden-owned address must still be denied")
        require(reexport.dlerror() == "symbol not found: reexport",
                "hidden actual-owner denial must provide a synthetic error")
        nullable = CallerRelativeDlsymDouble()
        require(nullable.relative("SELF", "caller", "nil", external=True) is None,
                "NULL-valued export must preserve its NULL value")
        require(nullable.dlerror() is None,
                "NULL-valued export must be distinct from a missing symbol")

        # Identity/generation revalidation restarts rather than reading a
        # stale snapshot record when an address is reused during the probe.
        raced = CallerRelativeDlsymDouble()
        raced.mutate_once = True
        require(raced.relative("NEXT", "caller", "shared", external=True) is None,
                "address-reuse retry must still deny the replacement hidden provider")
        require(raced.generation == 2 and raced.opens.count(("hidden", False)) == 2,
                "generation change must rebuild and probe only the replacement identity")
        require(raced.closes == [name for name, _main in raced.opens],
                "retry must close its pre-race pin")

        # An external hook remap has policy precedence and must not create any
        # internal loader handles. A native fallback still filters a hidden
        # provider, while trusted callers retain the fallback truth.
        remapped = CallerRelativeDlsymDouble()
        require(
            remapped.relative("NEXT", "caller", "shared", external=True,
                              remaps={"shared": "h_shared"}) == "h_shared",
            "external remap must win before caller-relative resolution",
        )
        require(not remapped.opens and not remapped.closes,
                "remap precedence must not open catalog images")
        fallback = CallerRelativeDlsymDouble()
        require(fallback.relative("NEXT", "gone", "fallback-hidden", external=True) is None,
                "external native fallback must post-filter hidden result")
        require(fallback.dlerror() == "symbol not found: fallback-hidden",
                "fallback filtering must provide a synthetic dlsym error")
        trusted_fallback = CallerRelativeDlsymDouble()
        require(trusted_fallback.relative("NEXT", "gone", "fallback-hidden", external=False) ==
                "hidden-fallback-symbol", "trusted fallback must retain unfiltered result")

    check("dlsym_caller_relative_fixture", check_dlsym_caller_relative_fixture)

    def check_dlsym_source_contract() -> None:
        require("orig_dlsym(handle, symbol)" in hider, "h_dlsym must preserve the original lookup path")
        require("hidden_dylib_hider_dlsym_remap" in main or "hidden_dylib_hider_dlsym_remap" in hider, "remap must have a caller")
        require("static char *h_dlerror(void)" in hider and "orig_dlerror" in hider, "synthetic dlsym denials require a hooked dlerror")
        require("_Thread_local" in hider and "g_dlsym_error_pending" in hider, "dlsym denial state must be thread-local")
        require('"symbol not found: %s"' in hider, "denied result must use dlsym-shaped error text")
        require("if (!symbol)" in hider, "NULL symbols must remain on the original dlsym path")
        require("(void)orig_dlerror()" in hider, "remapped success must consume stale original error state")
        require('{ "dlerror", (void *)dlerror, (void *)h_dlerror }' in hider, "dlerror must be part of the core transaction")
        require('{ "dlerror",                               (void *)h_dlerror' in hider, "dlsym(dlerror) must agree with the GOT hook")
        for token in (
            "RHI_DLSYM_RELATIVE_LOOKUP_ATTEMPTS", "RTLD_SELF", "RTLD_NEXT", "RTLD_FIRST",
            "hider_dlsym_resolve_caller_relative", "hider_dlsym_find_caller_catalog_index",
            "hider_dlsym_caller_is_verified_flat", "rhi_hider_identity_image_text_range", "MH_TWOLEVEL",
            "HIDER_DLSYM_RELATIVE_UNAVAILABLE_CALLER_NAMESPACE",
            "HIDER_DLSYM_RELATIVE_UNAVAILABLE_RETRY_LIMIT",
            "hider_catalog_snapshot_image_is_current", "catalog_find_active_locked",
            "paths_match", "hider_dlsym_result_address_is_hidden", "orig_dladdr(address, &owner_info)",
            "hidden_dylib_hider_catalog_snapshot", "hidden_dylib_hider_catalog_generation_is_current",
            "orig_dlopen(image->main_executable ? NULL : image->path, mode)",
            "RTLD_NOLOAD", "orig_dlclose", "HIDER_DLSYM_PROBE_FOUND",
            "HIDER_DLSYM_RELATIVE_UNAVAILABLE", "hidden_provider",
        ):
            require(token in hider, f"caller-relative dlsym contract missing: {token}")
        require("image->hidden = record->hidden" in hider and "bool                      hidden;" in hider_internal,
                "relative snapshot must retain hidden state across its owned copy")
        relative_body_start = hider.find("static hider_dlsym_relative_result_t hider_dlsym_resolve_caller_relative")
        relative_body_end = hider.find("static void *hider_dlsym_fallback_with_external_filter", relative_body_start)
        relative_body = hider[relative_body_start:relative_body_end]
        require(relative_body_start >= 0 and "for (uint32_t attempt = 0; attempt < RHI_DLSYM_RELATIVE_LOOKUP_ATTEMPTS" in relative_body,
                "relative resolver must use bounded generation retries")
        require("Never skip a provider whose pin failed" in relative_body and
                "hider_dlsym_fallback_with_external_filter" in hider,
                "pin failures must fall back without skipping a provider")
        hdlerror_body_start = hider.find("__attribute__((noinline))\nstatic char *h_dlerror(void) {")
        hdlerror_body_end = hider.find("#pragma mark - ObjC runtime hooks", hdlerror_body_start)
        hdlerror_body = hider[hdlerror_body_start:hdlerror_body_end]
        require(hdlerror_body.find("g_dlsym_error_pending") < hdlerror_body.find("caller_is_hidden"),
                "synthetic relative errors must be served for either caller class")

    check("dlsym_production_static_contract", check_dlsym_source_contract)

    known_gaps.append({
        "id": "dlsym-caller-relative-handle-semantics",
        "severity": "medium",
        "source": "BaseBin/systemhook/src/hidden_dylib_hider.c",
        "detail": "The catalog resolver is intentionally limited to callers verified as flat namespace (MH_TWOLEVEL clear). Two-level, unprovable, pin-failure, and retry-limit cases use native fallback from h_dlsym's wrapper frame, so RTLD_SELF/RTLD_NEXT provider selection may remain wrapper-relative; external results are still post-filtered.",
    })

    def check_sysctl_fixture() -> None:
        sysctl = SysctlDouble()
        result, data, needed = sysctl.query("kern.bootargs", None)
        require(result == 0 and data == b"" and needed == 1, "size query must return required hidden value size")
        result, data, needed = sysctl.query("kern.bootargs", 0)
        require(result == SysctlDouble.ENOMEM and data == b"" and needed == 1, "short buffer must preserve ENOMEM and required size")
        result, data, needed = sysctl.query("kern.bootargs", 1)
        require(result == 0 and data == b"\x00" and needed == 1, "one-byte hidden bootargs result must succeed")
        result, _, _ = sysctl.query("kern.unknown", None)
        require(result == SysctlDouble.ENOENT, "unknown sysctl must remain an error")

        # Named and resolved numeric routes must share one synthetic result.
        numeric = SysctlDouble()
        for capacity in (None, 0, 1, 4):
            require(sysctl.query("kern.bootargs", capacity) == numeric.query("kern.bootargs", capacity),
                    "named and numeric bootargs paths must have identical two-pass semantics")

        traced = 0x800
        rows = [(101, traced | 0x1), (202, traced | 0x2), (303, 0x4)]
        filtered_rows = clear_self_traced(rows, 202, traced)
        require(filtered_rows == [(101, traced | 0x1), (202, 0x2), (303, 0x4)],
                "KERN_PROC mutation must clear P_TRACED only in the self row")

    check("sysctlbyname_two_pass_fixture", check_sysctl_fixture)

    def check_sysctl_source_contract() -> None:
        require("h_sysctlbyname" in hider, "h_sysctlbyname missing")
        require('"kern.bootargs"' in hider, "bootargs policy missing")
        require("orig_sysctlbyname" in hider, "original sysctlbyname path missing")
        require("oldlenp" in hider, "sysctlbyname length parameter missing")
        require("hider_sysctl_synthesize_empty_bootargs" in hider,
                "named and numeric bootargs must use one synthetic helper")
        require("const size_t required = 1U" in hider,
                "bootargs size probe must publish only the synthetic one-byte result")
        require("errno = ENOMEM" in hider, "undersized bootargs buffers must preserve ENOMEM semantics")
        require("sysctlnametomib(\"kern.bootargs\"" in hider and "g_bootargs_mib_resolved" in hider,
                "numeric bootargs policy must resolve, not guess, the current MIB")
        require("hider_sysctl_filtered_self_procargs2" in hider and
                "rhi_hider_procargs2_filter_inplace" in hider,
                "self PROCARGS2 must materialize and filter privately")
        require("const size_t caller_capacity = *oldlenp" in hider and
                "caller_capacity <= sizeof(int)" in hider and
                "caller_capacity - sizeof(int) > ARG_MAX" in hider,
                "PROCARGS2 must preserve the current XNU argc-word and ARG_MAX boundaries")
        require("getpagesize()" in hider and "rounded_capacity" in hider and
                "rounded_payload_length" in hider and "rounded_overlap" in hider and
                "memset(payload + zero_offset, 0, payload_length - zero_offset)" in hider,
                "short PROCARGS2 must reproduce the filtered private legacy zero-tail window")
        require("const size_t filtered_fetch_length" in hider and
                "const size_t filtered_size_length" in hider and
                "filtered_size_length > raw_length" in hider and
                "memset((uint8_t *)raw + filtered_length, 0," in hider,
                "PROCARGS2 must word-round only the size query within private capacity and zero padding")
        require("if (!oldp) {\n\t\t\t*oldlenp = filtered_size_length;" in hider and
                "const size_t payload_length = filtered_fetch_length - sizeof(int);" in hider,
                "PROCARGS2 must keep aligned sizing separate from unrounded fetch/short semantics")
        require("memcpy(oldp, raw, sizeof(int))" in hider and
                "memcpy((uint8_t *)oldp + sizeof(int), copy_data, copy_length)" in hider,
                "PROCARGS2 must copy argc and data only from its filtered private result")
        require("kp[i].kp_proc.p_pid == getpid()" in hider,
                "P_TRACED normalization must be self-only")
        require("!hider_sysctl_is_read_only(newp, newlen)" in hider,
                "sysctl writes must remain native")

    check("sysctlbyname_production_static_contract", check_sysctl_source_contract)

    def check_getfsstat_boundary_fixture() -> None:
        require(getfsstat_route(False, 0) == "filtered-count",
                "the canonical NULL/zero count query needs a filtered count")
        require(getfsstat_route(False, 4096) == "filtered-count",
                "NULL count queries remain filtered regardless of nonnegative size")
        require(getfsstat_route(True, 0) == "native-zero-capacity",
                "non-NULL zero-capacity getfsstat must retain native success semantics")
        require(getfsstat_route(True, -1) == "native-invalid" and
                getfsstat_route(False, -1) == "native-invalid",
                "negative getfsstat sizes must retain native EINVAL behavior")
        require(getfsstat_route(True, 4096) == "filtered-buffer",
                "only a real caller buffer receives in-place mount filtering")

    check("getfsstat_boundary_matrix_fixture", check_getfsstat_boundary_fixture)

    def check_getfsstat_source_contract() -> None:
        start = hider.index("static int h_getfsstat(struct statfs *buf, int bufsize, int mode) {")
        body = hider[start:hider.index("static int h_statfs", start)]
        require("bufsize < 0 || (buf != NULL && bufsize == 0)" in body and
                "return orig_getfsstat(buf, bufsize, mode);" in body,
                "negative and non-NULL zero-size getfsstat calls must remain native")
        require("if (!buf)" in body and "malloc(tmpsize)" in body,
                "only NULL-buffer count queries may materialize a filtered count")

    check("getfsstat_boundary_source_contract", check_getfsstat_source_contract)

    def check_directory_fixture() -> None:
        directory = DirectoryDouble()
        directory.open("dir-1", "/allowed/dir")
        path, errno_after = directory.classify("dir-1", errno=11)
        require(path == "/allowed/dir" and errno_after == 11, "fresh path resolution must preserve errno")
        directory.rename_or_rebind("dir-1", "/restricted/dir")
        path, errno_after = directory.classify("dir-1", errno=35)
        require(path == "/restricted/dir" and errno_after == 35, "classification must resolve current descriptor path")
        path, errno_after = directory.classify("dir-1", errno=6, available=False)
        require(path is None and errno_after == 6, "unavailable path resolution must fail open without changing errno")
        directory.close("dir-1")
        path, errno_after = directory.classify("dir-1", errno=22)
        require(path is None and errno_after == 22, "close must not leave retained directory classification")
        directory.open("dir-1", "/new/allowed")
        path, _ = directory.classify("dir-1", errno=0)
        require(path == "/new/allowed", "reused directory token must resolve only its current path")

        # F_GETPATH failure still applies universal image-basename filtering;
        # unrelated entries keep stock enumeration behavior.
        hidden_basename = "systemhook-ABC.dylib"
        visible_basename = "MobileSubstrateBackup.dylib"
        require(hidden_basename.startswith("systemhook-"), "hidden fallback fixture drift")
        require(not visible_basename.startswith("systemhook-"), "basename fallback must avoid broad substring rules")

    check("directory_pointer_reuse_fresh_path_fixture", check_directory_fixture)

    def check_directory_source_contract() -> None:
        for symbol in ("h_opendir", "h_readdir", "h_closedir", "rhi_hider_directory_entry_hidden"):
            require(symbol in hider, f"directory symbol missing: {symbol}")
        require("dirfd(dirp)" in hider and "fcntl(fd, F_GETPATH, parent_path)" in hider, "readdir must classify each live DIR descriptor via F_GETPATH")
        require("const int saved_errno = errno" in hider and "errno = saved_errno" in hider, "directory path resolution must preserve errno")
        require("rhi_hider_image_path_hidden(entry->d_name)" in hider,
                "F_GETPATH failure must retain universal hidden-basename filtering")
        require("rhi_hider_filesystem_path_hidden(path)" in hider and "errno = ENOENT" in hider,
                "opendir must deny externally requested hidden directories")
        for obsolete in ("register_dir_filter", "lookup_dir_filter", "unregister_dir_filter", "g_dir_filters", "g_dir_filter_lock"):
            require(obsolete not in hider, f"obsolete DIR state must be removed: {obsolete}")

    check("directory_production_static_contract", check_directory_source_contract)

    opendir_match = re.search(r"\nstatic DIR \*h_opendir\(const char \*path\) \{", hider)
    closedir_match = re.search(r"\nstatic int h_closedir\(DIR \*dirp\) \{", hider)
    require(opendir_match is not None and closedir_match is not None, "directory hook definitions missing")
    opendir_start = opendir_match.start()
    opendir_body = hider[opendir_start:hider.index("static struct dirent *h_readdir", opendir_start)]
    closedir_start = closedir_match.start()
    closedir_body = hider[closedir_start:hider.index("static int h_sysctlbyname", closedir_start)]
    require("F_GETPATH" not in opendir_body, "opendir must not capture a directory category")
    require("g_dir_filter" not in closedir_body and "unregister_dir_filter" not in closedir_body, "closedir must remain ownership-neutral")

    def check_path_and_objc_view_fixture() -> None:
        # Name similarity is not ownership: only the hidden-owning-image bit
        # changes an external ObjC enumeration view.
        source = [
            ("NSSubstituteWebResource", False),
            ("Shadow", False),
            ("InjectedClass", True),
        ]
        names, count = compact_objc_view(source, True)
        require(names == ["NSSubstituteWebResource", "Shadow"] and count == 2,
                "ObjC compaction must preserve legitimate same-named classes")
        names_without_count, count_without_count = compact_objc_view(source, False)
        require(names_without_count == names and count_without_count is None,
                "nullable ObjC outCount must not disable external filtering")
        class_storage, class_kept = compact_objc_storage(source, class_list=True)
        require(class_storage[:class_kept] == names and
                class_storage[class_kept:] == [None] * (len(source) + 1 - class_kept),
                "objc_copyClassList must clear hidden tail pointers through its nil terminator")
        image_storage, image_kept = compact_objc_storage(source, class_list=False)
        require(image_storage[:image_kept] == names and
                image_storage[image_kept:] == [None] * (len(source) - image_kept),
                "objc_copyImageNames must clear every hidden tail pointer")

    check("path_and_objc_view_fixture", check_path_and_objc_view_fixture)

    def check_path_and_objc_source_contract() -> None:
        require('#include "hider_path_policy.h"' in hider and
                '#include "hider_environment_policy.h"' in hider,
                "hider must consume the centralized policy modules")
        for obsolete in ("image_path_should_hide", "fs_path_should_hide", "class_name_should_hide_from_app"):
            require(obsolete not in hider, f"duplicate/overfit policy must be removed: {obsolete}")
        require("rhi_hider_image_path_hidden" in hider and "rhi_hider_filesystem_path_hidden" in hider,
                "image and filesystem probes must use centralized path policy")
        class_start = hider.index("static Class *h_objc_copyClassList(unsigned int *outCount) {")
        image_start = hider.index("static const char * _Nonnull *h_objc_copyImageNames(unsigned int *outCount) {")
        class_body = hider[class_start:image_start]
        image_body = hider[image_start:hider.index("// NOTE: objc_getClass", image_start)]
        for body in (class_body, image_body):
            require("&total" in body and "malloc(" not in body and "free(result)" not in body,
                    "ObjC copy APIs must compact their original-owned arrays in place")
            require("if (outCount)" in body, "ObjC nullable outCount must be handled explicitly")
        require("for (unsigned int i = kept; i <= total; i++)" in class_body and
                "result[i] = NULL" in class_body,
                "objc_copyClassList must clear its compacted tail through the documented terminator")
        require("for (unsigned int i = kept; i < total; i++)" in image_body and
                "mutable_result[i] = NULL" in image_body,
                "objc_copyImageNames must clear its compacted count-owned tail")
        require("orig_class_getImageName" in hider and "rhi_hider_image_path_hidden(image)" in hider,
                "class visibility must use owning image identity")
        require("rhi_hider_env_name_hidden(name)" in hider,
                "getenv must share direct-environment and PROCARGS2 marker policy")

    check("path_and_objc_production_static_contract", check_path_and_objc_source_contract)

    def check_csops_visibility_matrix() -> None:
        CS_VALID, CS_HARD, CS_KILL, CS_DEBUGGED, CS_GET_TASK_ALLOW = 1, 2, 4, 8, 16

        def normalize(flags: int, *, hidden_process: bool, self_query: bool,
                      external: bool, fully_debugged: bool) -> int:
            flags |= CS_VALID
            flags &= ~CS_DEBUGGED
            if fully_debugged and not external:
                flags |= CS_DEBUGGED
            if hidden_process and self_query:
                flags |= CS_VALID | CS_HARD | CS_KILL
                flags &= ~CS_GET_TASK_ALLOW
                if external:
                    flags &= ~CS_DEBUGGED
            return flags

        initial = CS_DEBUGGED | CS_GET_TASK_ALLOW
        external = normalize(initial, hidden_process=True, self_query=True,
                             external=True, fully_debugged=True)
        internal = normalize(initial, hidden_process=True, self_query=True,
                             external=False, fully_debugged=True)
        non_hidden = normalize(initial, hidden_process=False, self_query=True,
                               external=False, fully_debugged=True)
        require(external & (CS_VALID | CS_HARD | CS_KILL) == (CS_VALID | CS_HARD | CS_KILL) and
                not external & (CS_DEBUGGED | CS_GET_TASK_ALLOW),
                "external hidden csops view must be stock-like even when globally debugged")
        require(internal & CS_DEBUGGED and not internal & CS_GET_TASK_ALLOW,
                "authorized hidden caller preserves debug truth but not task-allow")
        require(non_hidden & CS_DEBUGGED and non_hidden & CS_GET_TASK_ALLOW,
                "non-hidden csops behavior must retain legacy normalization")

    check("csops_visibility_matrix_fixture", check_csops_visibility_matrix)

    def check_csops_source_contract() -> None:
        for hook in ("csops_hook", "csops_audittoken_hook"):
            start = main.index(f"int {hook}")
            body = main[start:main.index("\n}", start) + 2]
            require("__builtin_extract_return_addr(__builtin_return_address(0))" in body,
                    f"{hook} must classify the true caller at wrapper entry")
            require("external_hidden_view" in body and "normalize_csops_status_flags" in body,
                    f"{hook} must apply caller-aware shared normalization")
        normalize_start = main.index("static void normalize_csops_status_flags")
        normalize_body = main[normalize_start:main.index("\n}\n\nint csops_hook", normalize_start)]
        require("CS_GET_TASK_ALLOW" in normalize_body and "CS_HARD" in normalize_body and
                "CS_KILL" in normalize_body and "external_hidden_view" in normalize_body,
                "shared csops normalizer must encode the hidden external capability matrix")

    check("csops_production_static_contract", check_csops_source_contract)

    def check_callback_registration_replay_fixture() -> None:
        catalog = CallbackCatalogDouble()
        first = catalog.add("/app/Main", 0x1000)
        second = catalog.add("/app/Framework", 0x2000)
        delivered: list[int] = []

        def callback(image: CatalogImageDouble) -> None:
            delivered.append(image.header)
            if image is first:
                catalog.add("/app/PostRegistration", 0x3000)

        registration = catalog.register_add(callback)
        require(registration.state is CallbackState.ACTIVE, "registration must publish only after replay")
        require(delivered == [first.header, second.header, 0x3000],
                "historical images must precede queued post-registration additions")
        require(not catalog.callback_under_lock, "replay callback must run out of lock")

    check("callback_registration_replay_order_fixture", check_callback_registration_replay_fixture)

    def check_catalog_remove_reuse_fixture() -> None:
        catalog = CallbackCatalogDouble()
        old = catalog.add("/app/Old", 0x4000)
        catalog.remove(old)
        replacement = catalog.add("/app/NewAtSameAddress", 0x4000)
        delivered: list[tuple[int, int]] = []
        catalog.register_add(lambda image: delivered.append((image.header, image.identity)))
        require(delivered == [(0x4000, replacement.identity)],
                "address reuse must create a new catalog identity and never replay the removed image")
        require(old.identity != replacement.identity and not old.active and replacement.active,
                "removed catalog identities must persist inertly")

    check("callback_catalog_remove_address_reuse_fixture", check_catalog_remove_reuse_fixture)

    def check_recursive_unload_fixture() -> None:
        catalog = CallbackCatalogDouble()
        anchor = catalog.add("/app/Anchor", 0x5000)
        delivered: list[int] = []

        def callback(image: CatalogImageDouble) -> None:
            delivered.append(image.header)
            if image is anchor:
                temporary = catalog.add("/app/Temporary", 0x6000)
                catalog.remove(temporary)

        registration = catalog.register_add(callback)
        require(catalog.state is TrackingState.NATIVE and registration.state is CallbackState.NATIVE,
                "queued add/remove during replay must fail-stop to native delivery")
        require(0x6000 not in delivered, "an unloaded header must never be dispatched from replay")

    check("callback_recursive_load_unload_failstop_fixture", check_recursive_unload_fixture)

    def check_callback_allocation_failure_fixture() -> None:
        catalog = CallbackCatalogDouble()
        catalog.add("/app/Main", 0x7000)
        delivered: list[int] = []
        catalog.force_allocation_failure = True
        registration = catalog.register_add(lambda image: delivered.append(image.header))
        require(catalog.state is TrackingState.NATIVE and registration.state is CallbackState.NATIVE,
                "registration allocation failure must transition FILTERED -> DEGRADING -> NATIVE")
        require(not delivered, "failed filtered registration must not silently publish a partial replay")

    check("callback_allocation_failure_degradation_fixture", check_callback_allocation_failure_fixture)

    def check_catalog_snapshot_ownership_fixture() -> None:
        catalog = CallbackCatalogDouble()
        image = catalog.add("/app/OwnedPath", 0x8000)
        generation, snapshot = catalog.snapshot()
        image.path = "/mutated/source"
        require(snapshot == [("/app/OwnedPath", 0x8000, image.identity)],
                "consumer snapshot must own path/header identity outside catalog lock")
        require(generation == catalog.sequence, "catalog snapshot must expose a recheckable generation")

    check("callback_catalog_snapshot_ownership_fixture", check_catalog_snapshot_ownership_fixture)

    def check_objc_timing_lane_fixture() -> None:
        # The model has no implicit ObjC event in add(); only the runtime relay
        # is permitted to produce that lane's deliveries.
        catalog = CallbackCatalogDouble()
        catalog.add("/app/Main", 0x9000)
        objc_events: list[int] = []
        dyld_events: list[int] = []
        catalog.register_add(lambda image: dyld_events.append(image.header))
        require(objc_events == [] and dyld_events == [0x9000],
                "dyld replay must not synthesize ObjC runtime callbacks")

    check("objc_runtime_timing_lane_separation_fixture", check_objc_timing_lane_fixture)

    def check_callback_lifetime_pin_fixture() -> None:
        pins = CallbackPinDouble()
        image = PinnedImageDouble(identity=41, generation=1)
        handle = pins.acquire(image)
        require(handle is not None, "active catalog identity must acquire a short-lived callback pin")
        pins.release(handle)
        require(pins.opens == pins.closes and pins.retained_handles == 0,
                "every delivery pin must be released; handles cannot be retained in the catalog")
        require(pins.loader_error == "caller pending error",
                "successful pin bookkeeping must preserve the caller's pending dlerror state")

        failed = pins.acquire(image, fail_no_load=True)
        require(failed is None and pins.bookkeeping_failures_consumed == 1 and
                pins.loader_error == "caller pending error",
                "failed RTLD_NOLOAD must consume its own error while TLS preserves the caller error")

        reused = PinnedImageDouble(identity=42, generation=1)
        rejected = pins.acquire(reused, after_open=lambda: (
            setattr(reused, "identity", 43), setattr(pins, "generation", 2)))
        require(rejected is None and pins.opens == pins.closes and pins.retained_handles == 0,
                "post-open identity/generation change must release and reject a stale callback header")

    check("callback_lifetime_pin_revalidate_release_fixture", check_callback_lifetime_pin_fixture)

    def check_permanent_relay_transition_fixture() -> None:
        relay = PermanentRelayDouble()
        delivered: list[tuple[str, int]] = []
        relay.link("remove", lambda kind, header: delivered.append((kind, header)))
        relay.source_event("remove", 0xABCD, transition=True)
        require(relay.route == "passthrough" and relay.state is TrackingState.NATIVE,
                "degradation must flip the public delivery route exactly once")
        require(relay.events == [("raw:remove", 0xABCD)] and delivered == [("remove", 0xABCD)],
                "the transition-causing remove must be delivered once, raw, before its source relay returns")
        relay.source_event("remove", 0xABCE)
        require(delivered == [("remove", 0xABCD), ("remove", 0xABCE)],
                "already-linked callbacks stay permanently multiplexed in raw source order")
        relay.register_after_transition("remove")
        require(relay.native_registrations == ["remove"] and len(relay.linked) == 1,
                "only a new post-transition registration uses the original API")

    check("permanent_relay_transition_remove_fixture", check_permanent_relay_transition_fixture)

    def check_passthrough_caller_policy_fixture() -> None:
        relay = PermanentRelayDouble()
        relay.degrade()
        relay.source_event("add", 0xADE0)
        relay.source_event("remove", 0xADE0)
        require(relay.caller_policy_events == [("add", 0xADE0), ("remove", 0xADE0)],
                "pass-through add/remove must still invalidate caller-policy image ranges")
        require(relay.timeline == [
                    ("caller-policy", "add", 0xADE0), ("raw", "add", 0xADE0),
                    ("caller-policy", "remove", 0xADE0), ("raw", "remove", 0xADE0),
                ],
                "caller-policy invalidation must precede raw pass-through delivery")

    check("permanent_relay_passthrough_caller_policy_fixture", check_passthrough_caller_policy_fixture)

    def check_passthrough_objc_lane_fixture() -> None:
        relay = PermanentRelayDouble()
        delivered: list[tuple[str, int]] = []
        relay.link("objc", lambda kind, header: delivered.append((kind, header)))
        relay.source_event("objc", 0xBEEF, transition=True)
        require(delivered == [("objc", 0xBEEF)] and relay.events == [("raw:objc", 0xBEEF)],
                "ObjC fallback delivery remains on its own native relay lane, not dyld add timing")

    check("permanent_relay_objc_lane_fixture", check_passthrough_objc_lane_fixture)

    def check_replay_ambiguity_failstop_fixture() -> None:
        relay = PermanentRelayDouble()
        relay.link("remove", lambda _kind, _header: None, CallbackState.REPLAYING)
        relay.source_event("remove", 0xC001, transition=True)
        require(relay.delivery_failed and relay.events == [("raw:remove", 0xC001)],
                "a replaying registration must not receive a deferred/stale remove after fallback")

    check("permanent_relay_replay_remove_failstop_fixture", check_replay_ambiguity_failstop_fixture)

    def check_mid_dispatch_route_flip_failstop_fixture() -> None:
        relay = PermanentRelayDouble()
        delivered: list[tuple[str, int]] = []
        relay.link("remove", lambda kind, header: delivered.append((kind, header)))
        relay.link("remove", lambda kind, header: delivered.append((kind, header)))
        relay.fail_stop_after_partial_filtered_delivery("remove", 0xC010)
        require(relay.delivery_failed and not relay.ready and relay.route == "passthrough" and
                delivered == [("remove", 0xC010)],
                "a route flip after partial filtered delivery must fail readiness, not raw-replay duplicates")
        relay.source_event("remove", 0xC011)
        require(delivered == [("remove", 0xC010)],
                "terminal callback ambiguity must not advertise a later coherent stream")

    check("permanent_relay_mid_dispatch_failstop_fixture", check_mid_dispatch_route_flip_failstop_fixture)

    def check_atfork_passthrough_fixture() -> None:
        child = PermanentRelayDouble()
        child.link("remove", lambda _kind, _header: None)
        child.child_after_fork()
        child.source_event("remove", 0xC002)
        require(child.state is TrackingState.NATIVE and child.route == "passthrough" and
                child.events == [("raw:remove", 0xC002)],
                "fork child must use its inherited permanent relay without a worker or filtered catalog")

    check("atfork_passthrough_no_hang_fixture", check_atfork_passthrough_fixture)

    def check_task_snapshot_coherence_contract() -> None:
        require("RHI_TASK_SNAPSHOT_GENERATION_LIMIT" not in hider, "snapshot generations must not have a detector-controlled fixed cap")
        require("RHI_TASK_SNAPSHOT_COPY_ATTEMPTS" in hider, "snapshot copy must use bounded stability retries")
        require("hider_image_record" in hider and "record->path" in hider,
                "published task snapshot must derive paths from process-lifetime catalog ownership")
        require("task_snapshot_source_is_current" in hider, "snapshot source must be revalidated around copies")
        require("TASK_SNAPSHOT_FATAL" in hider, "snapshot result must distinguish fatal publication failure")
        require("HIDER_TRACKING_DEGRADING" in hider and "hider_degrade_to_native" in hider,
                "fatal snapshot publication failure must hand every linked view to native APIs")

    check("task_snapshot_coherence_production_contract", check_task_snapshot_coherence_contract)

    def check_callback_catalog_source_contract() -> None:
        for token in (
            "hider_image_record", "HIDER_CALLBACK_REPLAYING", "HIDER_CALLBACK_ACTIVE",
            "HIDER_CALLBACK_NATIVE", "HIDER_TRACKING_FILTERED", "HIDER_TRACKING_DEGRADING",
            "HIDER_TRACKING_NATIVE", "catalog_append_event_locked", "hider_degrade_to_native",
            "HIDER_DELIVERY_FILTERED", "HIDER_DELIVERY_PASSTHROUGH",
            "hider_dispatch_passthrough_dyld_event", "hider_dispatch_passthrough_objc_event",
            "callback_invoking", "recursive_event",
            "on_objc_image_loaded", "orig_objc_addLoadImageFunc(on_objc_image_loaded)",
            "hidden_dylib_hider_catalog_snapshot", "hidden_dylib_hider_catalog_generation_is_current",
        ):
            require(token in hider, f"stable callback/catalog contract missing: {token}")
        require("g_add_cbs" not in hider and "g_objc_addload_cbs" not in hider,
                "snapshot callback arrays must be removed")
        for obsolete in ("g_all", "g_visible", "arr_add", "g_image_tracking_degraded"):
            require(re.search(rf"\b{obsolete}\b", hider) is None,
                    f"obsolete pre-catalog state must be fully migrated: {obsolete}")
        require("hider_dispatch_objc_event" not in hider[hider.find("static void on_image_added"):hider.find("static void on_image_removed")],
                "dyld add callback must not synthesize ObjC callbacks")
        require("rhi_hider_catalog_snapshot_t" in hider_internal and
                "RHI_HIDER_INTERNAL bool hidden_dylib_hider_catalog_snapshot" in hider_internal,
                "caller-relative resolver seam must expose a hidden stable snapshot API")
        require("header/slide are opaque" in hider_internal and "identities only" in hider_internal and
                "must never be dereferenced" in hider_internal and "hidden_dylib_hider.c" in hider_internal,
                "snapshot consumers must treat header/slide as opaque; any resolver pinning stays local")

        # Event nodes must be pre-owned by the process-lifetime image record.
        for token in ("hider_image_event_t       add_event", "hider_image_event_t       remove_event",
                      "hider_objc_event_t        objc_event"):
            require(token in hider, f"catalog record must embed pre-owned event node: {token}")

        def body(start: str, end: str) -> str:
            begin = hider.find(start)
            finish = hider.find(end, begin)
            require(begin >= 0 and finish > begin, f"unable to isolate source body {start}")
            return hider[begin:finish]

        added_body = body("static void on_image_added", "static void on_image_removed")
        removed_body = body("static void on_image_removed", "static void on_objc_image_loaded")
        objc_body = body("static void on_objc_image_loaded(const struct mach_header *mh) {",
                         "#pragma mark - Hooked dyld Functions")
        require("calloc(" not in added_body and "calloc(" not in removed_body and "calloc(" not in objc_body,
                "native lifecycle relays may not allocate per event")
        require("catalog_create_event" not in hider,
                "event allocation helper must not survive the pre-owned node design")

        for token in ("orig_dlopen", "orig_dlclose", "RTLD_NOLOAD", "hider_callback_pin_acquire",
                      "hider_callback_pin_release",
                      "record->identity == identity", "g_image_generation == generation"):
            require(token in hider, f"out-of-lane callback lifetime proof missing: {token}")
        pin_body = body("static void hider_callback_pin_release", "static bool hider_call_dyld_callback")
        require("hider_loader_error_preserve_for_internal_call" in pin_body and
                "hider_loader_error_consume_internal_failure" in pin_body and
                "g_loader_error_pending" in hider and "RHI_LOADER_ERROR_CAPACITY" in hider,
                "callback pins must virtualize a pre-existing dlerror and consume only their own failure")
        dlerror_body = body("__attribute__((noinline))\nstatic char *h_dlerror(void) {",
                            "#pragma mark - ObjC runtime hooks")
        require(dlerror_body.find("g_loader_error_pending") < dlerror_body.find("caller_is_hidden"),
                "virtualized callback errors must be delivered before caller-policy forwarding")
        raw_dyld_body = body("static bool hider_dispatch_passthrough_dyld_event(hider_dyld_callback_kind_t kind,\n\t                                                const struct mach_header *mh,\n\t                                                intptr_t slide) {",
                             "static bool hider_dispatch_dyld_event_to_registration")
        raw_objc_body = body("static bool hider_dispatch_passthrough_objc_event(const struct mach_header *mh) {",
                             "static bool hider_dispatch_objc_event_to_registration")
        for raw_body in (raw_dyld_body, raw_objc_body):
            for forbidden in ("os_unfair_lock_lock", "calloc(", "hider_callback_pin_",
                              "orig_dyld_register_func", "orig_objc_addLoadImageFunc"):
                require(forbidden not in raw_body,
                        f"raw source-relay pass-through must not lock/allocate/pin/register: {forbidden}")
            require(raw_body.find("g_callback_delivery_failed") < raw_body.find("dyld_image_path_containing_address"),
                    "a terminal callback ambiguity must suppress later raw callback delivery")
        require("hider_migrate_callbacks_to_native" not in hider and
                "hider_native_migration_worker" not in hider and
                "hider_native_relay_try_enter" not in hider,
                "retained callbacks must not use worker/gated post-hoc native registration")
        require("orig_objc_addLoadImageFunc" not in objc_body,
                "ObjC relay must never synchronously register callbacks")
        require("header_identities == 1" in objc_body and "runtime_uuid_valid" in objc_body and
                "runtime_path" in objc_body,
                "ObjC relay must reject delayed/reused header identities")
        for relay_body, kind in ((added_body, "HIDER_DYLD_CALLBACK_ADD"),
                                 (removed_body, "HIDER_DYLD_CALLBACK_REMOVE")):
            require("HIDER_DELIVERY_PASSTHROUGH" in relay_body and
                    "hider_dispatch_passthrough_dyld_event" in relay_body and kind in relay_body,
                    "each dyld relay must synchronously forward a pass-through event")
        for relay_body, caller_update in ((added_body, "rhi_hider_caller_image_added"),
                                          (removed_body, "rhi_hider_caller_image_removed")):
            policy_index = relay_body.find(caller_update)
            route_index = relay_body.find("HIDER_DELIVERY_PASSTHROUGH")
            raw_index = relay_body.find("hider_dispatch_passthrough_dyld_event")
            require(0 <= policy_index < route_index < raw_index,
                    "caller-policy image invalidation must precede every pass-through fast return")
        require("HIDER_DELIVERY_PASSTHROUGH" in objc_body and
                "hider_dispatch_passthrough_objc_event" in objc_body,
                "ObjC relay must synchronously forward its own pass-through event")
        require(added_body.count("hider_dispatch_passthrough_dyld_event") >= 2 and
                removed_body.count("hider_dispatch_passthrough_dyld_event") >= 2 and
                objc_body.count("hider_dispatch_passthrough_objc_event") >= 2,
                "a transition-causing source event and every later event must both use raw relay delivery")
        fail_stop_body = body("static void hider_callback_fail_stop", "typedef struct {")
        require("g_callback_delivery_failed" in fail_stop_body and
                "HIDER_STATE_FAILED" in fail_stop_body and
                "hider_degrade_to_native" in fail_stop_body,
                "partial source dispatch must make readiness terminally false before public fallback")
        for relay_body, dispatch in ((added_body, "hider_dispatch_dyld_event(&record->add_event)"),
                                     (removed_body, "hider_dispatch_dyld_event(&record->remove_event)"),
                                     (objc_body, "hider_dispatch_objc_event(&record->objc_event)")):
            dispatch_index = relay_body.find(dispatch)
            require(dispatch_index >= 0 and
                    "hider_callback_fail_stop" in relay_body[dispatch_index:],
                    "a route flip after partial filtered dispatch must fail-stop, never raw-replay all callbacks")
        atfork_body = body("static void hider_catalog_atfork_prepare", "static void hider_degrade_to_native")
        require("pthread_atfork" in hider and "hider_catalog_atfork_child" in atfork_body and
                "HIDER_TRACKING_NATIVE" in atfork_body and
                "HIDER_DELIVERY_PASSTHROUGH" in atfork_body and
                "pthread_create" not in atfork_body,
                "atfork child must abandon filtering and use the inherited permanent relay without a worker")

        init_atfork = hider.find("pthread_atfork(hider_catalog_atfork_prepare")
        init_replay = hider.find("orig_dyld_register_func_for_add_image(on_image_added)")
        require(init_atfork >= 0 and init_atfork < init_replay,
                "atfork catalog fence and saved originals must exist before initial dyld catalog replay")

    check("callback_catalog_production_static_contract", check_callback_catalog_source_contract)

    def check_mode_inventory() -> None:
        matrix = json.loads(OWNERSHIP.read_text(encoding="utf-8"))
        require(matrix.get("schema") == "rhinject.systemhook.ownership.v1", "unexpected ownership schema")
        names = [mode["name"] for mode in matrix["modes"]]
        require(names == ["stock", "blacklist", "whitelist", "hiddenwhitelist", "blacklistallowlist"], "all five injection modes must be listed in stable order")
        for mode in names:
            require(f'"{mode}"' in common, f"mode string missing from common.c: {mode}")
        require("ROOTHIDE_HIDDEN_INJECTION" in main and "ROOTHIDE_ENABLE_HIDDEN_TWEAKS" in main, "hidden handoff envs missing from main.c")
        require("ROOTHIDE_HIDER_PROFILE" in launchd and "ROOTHIDE_HIDER_DISABLED_HOOKS" in launchd, "launchd hider controls missing")

    check("injection_mode_ownership_inventory", check_mode_inventory)

    def check_owner_symbols() -> None:
        matrix = json.loads(OWNERSHIP.read_text(encoding="utf-8"))
        texts = {
            "BaseBin/systemhook/src/common.c": common,
            "BaseBin/systemhook/src/hider_identity.c": identity,
            "BaseBin/systemhook/src/hider_caller_policy.c": caller_policy,
            "BaseBin/systemhook/src/main.c": main,
            "BaseBin/systemhook/src/hidden_dylib_hider.c": hider,
            "BaseBin/systemhook/src/roothider_common.c": roothider_common,
            "BaseBin/systemhook/src/roothider_main.c": roothider_main,
            "BaseBin/launchdhook/src/roothider.m": launchd,
        }
        for owner in matrix["owners"]:
            require(owner["owner"] in texts, f"owner path not loaded: {owner['owner']}")
            text = texts[owner["owner"]]
            for symbol in owner["symbols"]:
                require(symbol_exists(text, symbol), f"{owner['id']} missing symbol {symbol}")

    check("ownership_matrix_symbol_paths", check_owner_symbols)

    return {
        "schema": "rhinject.systemhook.characterization.v1",
        "repository_root": str(ROOT),
        "tests": checks,
        "known_gaps": known_gaps,
        "summary": {
            "passed": sum(test["status"] == "pass" for test in checks),
            "failed": sum(test["status"] == "fail" for test in checks),
            "known_gaps": len(known_gaps),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit only the machine-readable report")
    parser.add_argument("--artifact", type=Path, help="built systemhook dylib for private-export verification")
    args = parser.parse_args()
    report = run_checks(args.artifact)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("rhinject systemhook characterization")
        for test in report["tests"]:
            suffix = f": {test['detail']}" if test.get("detail") else ""
            print(f"  {test['status'].upper():4} {test['name']}{suffix}")
        print(f"summary: {report['summary']}")
        if report["known_gaps"]:
            print("known production gaps:")
            for gap in report["known_gaps"]:
                print(f"  - [{gap['severity']}] {gap['id']}: {gap['detail']}")
    return 1 if report["summary"]["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
