#!/usr/bin/env python3
"""Static contracts for post-launchd first-load failure containment."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
HEADER = ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.h"
JAILBREAKER = ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m"
MAIN_VIEW = ROOT / "Application/Dopamine/UI/DOMainViewController.m"
LOG_VIEW = ROOT / "Application/Dopamine/UI/Log/DOLogCrashViewController.m"
LOG_HEADER = ROOT / "Application/Dopamine/UI/Log/DOLogCrashViewController.h"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def section(text: str, start: str, end: str) -> str:
    start_index = text.index(start)
    end_index = text.index(end, start_index)
    return text[start_index:end_index]


def main() -> None:
    header = HEADER.read_text(encoding="utf-8")
    jailbreaker = JAILBREAKER.read_text(encoding="utf-8")
    main_view = MAIN_VIEW.read_text(encoding="utf-8")
    log_view = LOG_VIEW.read_text(encoding="utf-8")
    log_header = LOG_HEADER.read_text(encoding="utf-8")

    for phase in (
        "DOJailbreakActivationPhasePreInjection",
        "DOJailbreakActivationPhaseLaunchdFirstLoad",
        "DOJailbreakActivationPhaseFinalized",
        "DOJailbreakActivationPhaseUserspaceRebooting",
    ):
        require(phase in header, f"activation phase missing: {phase}")
    for contract in (
        "DOJailbreakerErrorRequiresFullRebootKey",
        "DOJailbreakerErrorActivationPhaseKey",
        "@property (nonatomic, readonly) DOJailbreakActivationPhase activationPhase;",
    ):
        require(contract in header, f"late-failure public contract missing: {contract}")

    inject_method = section(jailbreaker, "- (NSError *)injectLaunchdHook", "\n/*")
    run = section(jailbreaker, "- (void)runWithError:", "- (void)finalize")
    inject = run.index("*errOut = [self injectLaunchdHook];")
    inject_failure = run[inject:run.index("// After the launchd hook", inject)]
    require(
        "[self errorRequiringFullRebootIfNeeded:*errOut]" in inject_failure,
        "an injectLaunchdHook error must be marked reboot-required",
    )
    require(
        "self.activationPhase = DOJailbreakActivationPhasePreInjection;" in run,
        "every jailbreak attempt must start in pre-injection state",
    )
    phase_transition = inject_method.index(
        "self.activationPhase = DOJailbreakActivationPhaseLaunchdFirstLoad;"
    )
    injector_spawn = inject_method.index("exec_cmd_nowait")
    require(
        phase_transition < injector_spawn,
        "launchd-first-load phase must be entered before the injector is spawned",
    )
    for contract in (
        "DOBoomerangInfo",
        "(__bridge_retained void *)info",
        "CFBridgingRelease(context)",
        "info = nil;",
        "dispatch_semaphore_wait(boomerangDone, injectionDeadline)",
        "mach_port_destroy(mach_task_self(), info.serverPort)",
        "exec_cmd_nowait(&injectorPid",
        "waitpid(pid, &status, WNOHANG)",
        "kill(pid, SIGKILL)",
    ):
        require(contract in jailbreaker, f"bounded launchd-injection contract missing: {contract}")
    require("xpc_release(" not in jailbreaker,
            "ARC build must not manually release the boomerang XPC reply")
    post_handoff = inject_method[inject_method.index("info = nil;"):]
    require(
        "info.serverPort" not in post_handoff and "info->" not in post_handoff,
        "caller must not dereference boomerang state after starting its receiver",
    )
    require(
        "dispatch_time_t injectionDeadline" in inject_method,
        "injector and boomerang acknowledgement must share one 45-second deadline",
    )
    for late_failure in (
        "int ret = basebin_generate(false);",
        "ret = ensure_dyld_trustcache(JBROOT_PATH(\"/basebin/.fakelib/dyld\"));",
        "*errOut = [self finalizeBootstrapIfNeeded];",
    ):
        failure_index = run.index(late_failure)
        return_index = run.index("return;", failure_index)
        require(
            "[self errorRequiringFullRebootIfNeeded:*errOut]" in run[failure_index:return_index],
            f"post-launchd failure must be marked reboot-required: {late_failure}",
        )
    require(
        "Do not clean up, retry, or launch a BaseBin helper after the first" in run,
        "a post-injection failure must preserve the elevated recovery path",
    )
    finalize = section(jailbreaker, "- (void)finalize", "- (IOSurfaceRef)")
    require(
        "self.activationPhase = DOJailbreakActivationPhaseUserspaceRebooting;" in finalize,
        "userspace reboot transition must be recorded",
    )

    require(
        "DOJailbreakerErrorRequiresFullRebootKey" in main_view,
        "main UI must consume the reboot-required error contract",
    )
    require(
        "initWithTitle:error.localizedDescription rebootRequired:rebootRequired" in main_view,
        "post-launchd failures must open the recovery log screen",
    )
    require("exec_cmd_trusted" not in main_view, "main recovery UI must not spawn a BaseBin reboot helper")
    require(
        "[[DOEnvironmentManager sharedManager] reboot];" in main_view,
        "generic reboot path must use the direct app reboot mechanism",
    )

    require(
        "- (id)initWithTitle:(NSString*)title rebootRequired:(BOOL)rebootRequired;" in log_header,
        "log view needs an explicit reboot-required mode",
    )
    for contract in (
        "shareLogRecordFromView",
        "A full device reboot is required before Dopamine can be opened again.",
        "[[DOEnvironmentManager sharedManager] reboot];",
        "if (self.rebootRequired && !self.recoveryAcknowledged)",
        "I Understand",
    ):
        require(contract in log_view, f"recovery UI contract missing: {contract}")
    require("exec_cmd_trusted" not in log_view, "recovery reboot must not spawn a BaseBin helper")
    require("rebootUserspace" not in log_view, "recovery must require a full device reboot")

    print("late first-load recovery and bounded launchd-injection contracts: PASS")


if __name__ == "__main__":
    main()
