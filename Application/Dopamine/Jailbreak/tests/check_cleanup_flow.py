#!/usr/bin/env python3
"""Contracts for the 3.x jailbreak lifecycle cleanup and recovery boundary."""

from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "DOJailbreaker.m"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def between(text: str, start: str, end: str) -> str:
    offset = text.index(start)
    return text[offset:text.index(end, offset)]


def returning_segment(text: str, anchor: str) -> str:
    offset = text.index(anchor)
    end = text.index("return;", offset) + len("return;")
    return text[offset:end]


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    run = between(source, "- (void)runWithError:", "- (void)finalize")

    for anchor in (
        "*errOut = [self doExploitation];",
        "*errOut = [self buildPhysRWPrimitive];",
    ):
        require(
            "[self cleanUpExploits];" in returning_segment(run, anchor),
            f"pre-elevation failure must clean active exploits: {anchor}",
        )

    for anchor in (
        "*errOut = [self showNonDefaultSystemApps];",
        "*errOut = [self ensureDevModeEnabled];",
        "*errOut = [[DOEnvironmentManager sharedManager] ensureJailbreakRootExists];",
        "*errOut = [[DOEnvironmentManager sharedManager] updateBootLogo];",
        "*errOut = [self loadBasebinTrustcache];",
    ):
        require(
            "[self cleanUpPostExploitation];" in returning_segment(run, anchor),
            f"reversible pre-injection failure must restore app credentials: {anchor}",
        )

    prepare = returning_segment(run, "*errOut = [[DOEnvironmentManager sharedManager] prepareBootstrap];")
    require(
        "if (*errOut) return;" in prepare,
        "the upstream prepareBootstrap direct-return boundary changed unexpectedly",
    )

    inject = returning_segment(run, "*errOut = [self injectLaunchdHook];")
    require(
        "[self errorRequiringFullRebootIfNeeded:*errOut]" in inject,
        "launchd injection failures must enter reboot-required recovery",
    )
    require(
        "if (self.activationPhase < DOJailbreakActivationPhaseLaunchdFirstLoad)" in inject,
        "cleanup after injection must be limited to failures before the irreversible boundary",
    )

    for anchor in (
        "int ret = basebin_generate(false);",
        'ret = ensure_dyld_trustcache(JBROOT_PATH("/basebin/.fakelib/dyld"));',
        "*errOut = [self finalizeBootstrapIfNeeded];",
        "*errOut = [self cleanUpPostExploitation];",
    ):
        require(
            "[self errorRequiringFullRebootIfNeeded:*errOut]" in returning_segment(run, anchor),
            f"late RootHide failure must retain direct reboot recovery: {anchor}",
        )

    require(
        "setBasebinDependency(tweaksEnabled);" in run
        and "syncRootHideInjectionSettingsNeedsUnsandbox:NO" in run,
        "RootHide dependency and per-app injection settings must survive finalization",
    )
    print("jailbreak cleanup/recovery boundary: PASS")


if __name__ == "__main__":
    main()
