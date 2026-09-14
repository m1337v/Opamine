#!/usr/bin/env python3
"""Static contract checks for DOJailbreaker's cleanup boundaries."""

from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "DOJailbreaker.m"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def slice_between(text: str, start: str, end: str) -> str:
    start_offset = text.index(start)
    end_offset = text.index(end, start_offset)
    return text[start_offset:end_offset]


def require_cleanup_after(body: str, anchor: str, cleanup: str) -> None:
    anchor_offset = body.index(anchor)
    next_return = body.index("return;", anchor_offset)
    segment = body[anchor_offset:next_return]
    require(cleanup in segment, f"{anchor} must run {cleanup} before returning")


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    cleanup = slice_between(
        source,
        "- (NSError *)cleanUpPostExploitation",
        "- (void)runWithError:",
    )
    run = slice_between(source, "- (void)runWithError:", "- (void)finalize")

    require("@available(iOS 17.0, *)" in cleanup, "credential restoration must remain iOS 17+")
    for field in ("svuid", "ruid", "uid", "rgid", "svgid", "groups"):
        require(
            f"koffsetof(ucred, {field}), 501" in cleanup,
            f"cleanup must restore {field} to mobile",
        )

    require_cleanup_after(run, "*errOut = [self doExploitation];", "[self cleanUpExploits];")
    require_cleanup_after(run, "*errOut = [self buildPhysRWPrimitive];", "[self cleanUpExploits];")

    elevation = run.index("*errOut = [self elevatePrivileges];")
    first_post_elevation = run.index("*errOut = [self showNonDefaultSystemApps];", elevation)
    require(
        "if (*errOut) return;" in run[elevation:first_post_elevation],
        "failed privilege elevation must retain the upstream direct-return boundary",
    )

    post_exploitation_anchors = (
        "*errOut = [self showNonDefaultSystemApps];",
        "*errOut = [self ensureDevModeEnabled];",
        "*errOut = [[DOEnvironmentManager sharedManager] ensureJailbreakRootExists];",
        "*errOut = [[DOEnvironmentManager sharedManager] prepareBootstrap];",
        "*errOut = [[DOEnvironmentManager sharedManager] updateBootLogo];",
        "*errOut = [self loadBasebinTrustcache];",
        "*errOut = [self injectLaunchdHook];",
        'NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Creating fakelib failed',
        'NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to upload dyld trustcache',
        "*errOut = [self finalizeBootstrapIfNeeded];",
    )
    for anchor in post_exploitation_anchors:
        require_cleanup_after(run, anchor, "[self cleanUpPostExploitation];")

    remove_branch = slice_between(
        run,
        "if (removeJailbreakEnabled)",
        "*errOut = [[DOEnvironmentManager sharedManager] prepareBootstrap];",
    )
    require(
        "[self cleanUpPostExploitation];" in remove_branch,
        "remove-jailbreak exit must restore post-exploitation credentials",
    )

    final_cleanup = run.rfind("*errOut = [self cleanUpPostExploitation];")
    require(final_cleanup > run.index("*errOut = [self finalizeBootstrapIfNeeded];"),
            "successful RootHide flow must end with post-exploitation cleanup")

    # Guard against accidentally replacing the fork's RootHide stage wholesale.
    for invariant in (
        'setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin:/rootfs/',
        "basebin_generate(false)",
        'ensure_dyld_trustcache(JBROOT_PATH("/basebin/.fakelib/dyld"))',
        "exec_set_patch(true)",
    ):
        require(invariant in run, f"RootHide invariant disappeared: {invariant}")

    print("DOJailbreaker cleanup flow: PASS")


if __name__ == "__main__":
    main()
