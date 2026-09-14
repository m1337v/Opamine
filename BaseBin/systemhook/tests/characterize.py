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

    check("environment_handoff_source_contract", check_environment_handoff_source_contract)

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

    check("dlsym_production_static_contract", check_dlsym_source_contract)

    known_gaps.append({
        "id": "dlsym-caller-relative-handle-semantics",
        "severity": "medium",
        "source": "BaseBin/systemhook/src/hidden_dylib_hider.c",
        "detail": "RTLD_NEXT/RTLD_SELF are delegated through the h_dlsym frame; caller-relative lookup has not been implemented or device-validated.",
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

    check("sysctlbyname_two_pass_fixture", check_sysctl_fixture)

    def check_sysctl_source_contract() -> None:
        require("h_sysctlbyname" in hider, "h_sysctlbyname missing")
        require('"kern.bootargs"' in hider, "bootargs policy missing")
        require("orig_sysctlbyname" in hider, "original sysctlbyname path missing")
        require("oldlenp" in hider, "sysctlbyname length parameter missing")
        require("const size_t required = 1" in hider, "bootargs size probe must publish only the synthetic one-byte result")
        require("errno = ENOMEM" in hider, "undersized bootargs buffers must preserve ENOMEM semantics")

    check("sysctlbyname_production_static_contract", check_sysctl_source_contract)

    sysctl_match = re.search(r"\nstatic int h_sysctlbyname\([^\n]+\n(?:[^\n]*\n){0,3}", hider)
    require(sysctl_match is not None, "h_sysctlbyname definition missing")
    sysctl_body = hider[sysctl_match.start():sysctl_match.start() + 1600]
    if "!oldp" in sysctl_body and "const size_t required = 1" not in sysctl_body:
        known_gaps.append({
            "id": "sysctlbyname-size-query",
            "severity": "medium",
            "source": "BaseBin/systemhook/src/hidden_dylib_hider.c",
            "detail": "kern.bootargs rewriting is guarded by oldp, so a NULL size query is delegated without a hidden one-byte contract.",
        })

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

    check("directory_pointer_reuse_fresh_path_fixture", check_directory_fixture)

    def check_directory_source_contract() -> None:
        for symbol in ("h_opendir", "h_readdir", "h_closedir", "dir_filter_kind_for_dir"):
            require(symbol in hider, f"directory symbol missing: {symbol}")
        require("dirfd(dirp)" in hider and "fcntl(fd, F_GETPATH, path)" in hider, "readdir must classify each live DIR descriptor via F_GETPATH")
        require("const int saved_errno = errno" in hider and "errno = saved_errno" in hider, "directory path resolution must preserve errno")
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
    require("dir_filter_kind_for_dir" not in opendir_body, "opendir must not capture a directory category")
    require("g_dir_filter" not in closedir_body and "unregister_dir_filter" not in closedir_body, "closedir must remain ownership-neutral")

    def check_task_snapshot_coherence_contract() -> None:
        require("RHI_TASK_SNAPSHOT_GENERATION_LIMIT" not in hider, "snapshot generations must not have a detector-controlled fixed cap")
        require("RHI_TASK_SNAPSHOT_COPY_ATTEMPTS" in hider, "snapshot copy must use bounded stability retries")
        require("copy_dyld_image_path" in hider and "image_paths" in hider, "published task snapshot must own its image paths")
        require("task_snapshot_source_is_current" in hider, "snapshot source must be revalidated around copies")
        require("TASK_SNAPSHOT_FATAL" in hider, "snapshot result must distinguish fatal publication failure")
        require("g_image_tracking_degraded = true" in hider, "fatal snapshot publication failure must degrade all linked views")

    check("task_snapshot_coherence_production_contract", check_task_snapshot_coherence_contract)

    if "g_add_cbs[g_add_cb_n++]" in hider and "for (uint32_t i = 0; i < n; i++)\n\t\tfunc(image_snapshot" in hider:
        known_gaps.append({
            "id": "dyld-callback-registration-replay-order",
            "severity": "medium",
            "source": "BaseBin/systemhook/src/hidden_dylib_hider.c",
            "detail": "A newly registered add-image callback is visible before its out-of-lock replay completes; WP4 must queue post-registration events until replay order is established.",
        })

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
