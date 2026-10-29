#!/usr/bin/env python3
"""Application-side lifecycle/update guards for the RootHide 3.x merge.

BaseBin internals moved to the separate libroothider implementation and are
tested by its owner. This keeps the app contracts at that boundary explicit.
"""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[4]
ENVIRONMENT = ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m"
ENVIRONMENT_HEADER = ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.h"
ROOT_HIDE_ENVIRONMENT_HEADER = ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager+RootHide.h"
ROOT_HIDE_BOOTSTRAPPER_HEADER = ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper+RootHide.h"
JAILBREAKER = ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m"
BOOTSTRAPPER = ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m"
UI_MANAGER = ROOT / "Application/Dopamine/UI/DOUIManager.m"
UPDATE_VIEW = ROOT / "Application/Dopamine/UI/Update/DOUpdateViewController.m"
VERSION = ROOT / "BaseBin/_external/basebin/.version"
ROOTHIDE_VERSION = ROOT / "BaseBin/_external/basebin/.version-roothide"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def section(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def without_block_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


def main() -> None:
    environment = ENVIRONMENT.read_text(encoding="utf-8")
    environment_header = ENVIRONMENT_HEADER.read_text(encoding="utf-8")
    root_hide_environment_header = ROOT_HIDE_ENVIRONMENT_HEADER.read_text(encoding="utf-8")
    root_hide_bootstrapper_header = ROOT_HIDE_BOOTSTRAPPER_HEADER.read_text(encoding="utf-8")
    jailbreaker = JAILBREAKER.read_text(encoding="utf-8")
    bootstrapper = BOOTSTRAPPER.read_text(encoding="utf-8")
    ui_manager = UI_MANAGER.read_text(encoding="utf-8")
    update_view = UPDATE_VIEW.read_text(encoding="utf-8")

    require(VERSION.read_text(encoding="utf-8").strip() == "3.0.12", "unexpected 3.x basebin version")
    require(ROOTHIDE_VERSION.read_text(encoding="utf-8").strip() == "29+opamine1", "RootHide fork revision lost")
    require('JBROOT_PATH(@"/basebin/.version-roothide")' in environment,
            "app must read the RootHide revision from the active randomized root")

    for declaration in (
        "- (NSString *)activePrebootPath;",
        "- (NSString *)accessibleSPTMPath;",
        "- (NSString *)accessibleTXMPath;",
        "- (BOOL)isSPTM;",
        "- (NSString *)jailbrokenBasebinMD5;",
        "- (NSString *)launchedBasebinMD5;",
        "- (NSString *)jailbrokenBuildID;",
        "- (NSString *)launchedBuildID;",
    ):
        require(declaration in environment_header, f"required app lifecycle API missing: {declaration}")

    require('#pragma clang diagnostic error "-Wincomplete-implementation"' in environment,
            "environment manager must fail its local compile if a primary selector loses its implementation")
    for declaration in (
        "@interface DOEnvironmentManager (roothide)",
        "- (void)locateJailbreakRoot;",
        "- (NSError *)ensureJailbreakRootExists;",
    ):
        require(declaration in root_hide_environment_header,
                f"RootHide root-lifecycle category declaration missing: {declaration}")
    active_bootstrapper = without_block_comments(bootstrapper)
    root_lifecycle_category = section(active_bootstrapper, "@implementation DOEnvironmentManager(roothide)", "\n@end")
    for implementation_contract in (
        "- (void)locateJailbreakRoot",
        "find_jbroot(NO) ?: find_jbroot(YES)",
        "- (NSError *)ensureJailbreakRootExists",
    ):
        require(implementation_contract in root_lifecycle_category,
                f"RootHide root-lifecycle implementation is inactive or missing: {implementation_contract}")
    for declaration in (
        "@interface DOBootstrapper (roothide)",
        "- (void)prepareBootstrapWithCompletion:(void (^)(NSError *))completion;",
        "- (NSError *)finalizeBootstrap;",
        "- (NSError *)deleteBootstrap;",
    ):
        require(declaration in root_hide_bootstrapper_header,
                f"RootHide bootstrap category declaration missing: {declaration}")
    root_bootstrapper_category = section(active_bootstrapper, "@implementation DOBootstrapper(roothide)", "\n@end")
    for implementation_contract in (
        "- (void)prepareBootstrapWithCompletion:(void (^)(NSError *))completion",
        "- (NSError *)finalizeBootstrap",
        "- (NSError *)deleteBootstrap",
        "RootHideFindOwnedJailbreakRoot",
    ):
        require(implementation_contract in root_bootstrapper_category,
                f"RootHide bootstrap transaction implementation is inactive or missing: {implementation_contract}")

    for accessor, expected_path in (
        ("jailbrokenBasebinMD5", 'JBROOT_PATH(@"/basebin/.basebin_md5")'),
        ("launchedBasebinMD5", 'stringByAppendingPathComponent:@"basebin.md5"'),
        ("jailbrokenBuildID", 'JBROOT_PATH(@"/basebin/.build_id")'),
        ("launchedBuildID", 'stringByAppendingPathComponent:@"basebin-build-id.txt"'),
    ):
        body = section(environment, f"- (NSString *){accessor}", "\n- (")
        require(expected_path in body, f"{accessor} must read its designated identity artifact")
        if accessor.startswith("jailbroken"):
            require("[self runAsRoot:" in body and "[self runUnsandboxed:" in body,
                    f"{accessor} must read live basebin identity with elevated access")

    for accessor, image in (("accessibleSPTMPath", "SecurePageTableMonitor"),
                            ("accessibleTXMPath", "TrustedExecutionMonitor")):
        body = section(environment, f"- (NSString *){accessor}", "\n- (")
        require("[self activePrebootPath]" in body and image in body,
                f"{accessor} must use the active preboot image")
        require("[self isInstalledThroughTrollStore] || getuid() == 0" in body,
                f"{accessor} must keep its privileged fallback gated")
        require("return nil;" in body, f"{accessor} must fail closed")

    gather = section(jailbreaker, "- (NSError *)gatherSystemInformation", "- (NSError *)doExploitation")
    for invariant in (
        "accessibleSPTMPath",
        "accessibleTXMPath",
        "xpf_start_with_kernel_path",
        "kernelConstant.staticBase",
        "kernelConstant.staticSptmBase",
        "kernelConstant.staticTxmBase",
    ):
        require(invariant in gather, f"XPF lifecycle data contract missing: {invariant}")

    require('spawnJbctlAsRootWithArgs:@[@"reboot_userspace"]' in environment,
            "userspace reboot must cross the synchronized root-helper boundary")
    require("jbclient_platform_stage_jailbreak_update" in environment and "[self rebootUserspace]" in environment,
            "environment updates must stage before rebooting userspace")

    root_helper = section(environment, "- (BOOL)installedBasebinSupportsRootHelperWaitProtocol", "\n- (int)runTrollStoreAction")
    for invariant in (
        "DORootHelperWaitProtocolMinimumBasebinVersion",
        "DOBasebinSupportsRootHelperWaitProtocol",
        "installedBasebinSupportsRootHelperWaitProtocol",
        "resumeSuspendedRootHelperProcess",
        "SIZE_MAX / sizeof(char *)",
        "calloc(argumentSlots, sizeof(*argBuf))",
        "if (!argBuf)",
        "if (![arg isKindOfClass:NSString.class])",
        "if (pipe(waitPipe) != 0)",
        "posix_spawn_file_actions_adddup2",
        "posix_spawn_file_actions_addclose",
        "POSIX_SPAWN_START_SUSPENDED",
        "while (write(waitPipe[1], &signal, sizeof(signal)) == -1 && errno == EINTR)",
        "cmd_wait_for_exit(pid)",
    ):
        require(invariant in environment if invariant.startswith(("DORootHelper", "DOBasebin")) else root_helper,
                f"root-helper failure/lifetime guard missing: {invariant}")
    require("strcmp(" not in root_helper, "root-helper capability selection must use numeric version comparison")
    require(root_helper.index("[self runAsRoot:") < root_helper.index("while (write(waitPipe[1]"),
            "--waitfor completion must occur after dropping elevated credentials")

    update_guard = section(ui_manager, "- (BOOL)environmentUpdateAvailable", "- (bool)launchedReleaseNeedsManualUpdate")
    for invariant in (
        "jailbrokenBasebinMD5",
        "launchedBasebinMD5",
        "jailbrokenBuildID",
        "launchedBuildID",
        "jailbrokenVersionRootHide",
    ):
        require(invariant in update_guard, f"environment identity/update guard missing: {invariant}")
    require(update_guard.index("jailbrokenBasebinMD5") < update_guard.index("jailbrokenVersionRootHide"),
            "MD5 identity comparison must precede semantic RootHide fallback")
    require(update_guard.index("jailbrokenBuildID") < update_guard.index("jailbrokenVersionRootHide"),
            "build-ID comparison must precede semantic RootHide fallback")
    require("DOIsThreeComponentNumericVersion(jailbrokenBaseVersion)" in update_guard,
            "RootHide revision fallback must validate its base version")
    require('stringWithFormat:@"%@-%@", jailbrokenBaseVersion, jailbrokenRootHideRevision' in update_guard,
            "RootHide revision must be joined to the installed base version before comparison")
    require("return YES;" in update_guard[update_guard.index("jailbrokenBaseVersion"):],
            "unprovable identity/version metadata must not silently suppress an environment update")
    require("componentsSeparatedByString:@\"-\"" not in section(ui_manager, "- (NSString*)getLaunchedReleaseTag", "- (NSArray*)availablePackageManagers"),
            "launched release tag must retain its complete RootHide revision")

    releases = section(ui_manager, "- (NSArray *)getLatestReleases", "- (BOOL)environmentUpdateAvailable")
    for invariant in (
        "https://api.github.com/repos/m1337v/Opamine/releases",
        "[parsedReleases isKindOfClass:NSArray.class]",
        "[candidate isKindOfClass:NSDictionary.class]",
        "[candidate[@\"tag_name\"] isKindOfClass:NSString.class]",
        "releases = @[];",
    ):
        require(invariant in releases, f"fork update feed safety contract missing: {invariant}")
    require("roothide/Dopamine" not in releases and "opa334/Dopamine" not in update_view,
            "fork UI must not direct in-app updates to an upstream installer")
    require("https://github.com/m1337v/Opamine/releases" in update_view,
            "manual update fallback must target the Opamine fork")

    for root_transaction_anchor in (
        "RootHideFindOwnedJailbreakRoot",
        "RootHideRepairPairedRootLinks",
        "RootHideCollectNestedRootLinks",
        "RootHideReplaceExpectedSymlink",
        "rewrittenNestedLinks.reverseObjectEnumerator",
    ):
        require(root_transaction_anchor in bootstrapper,
                f"owned paired-root recovery transaction missing: {root_transaction_anchor}")

    print("application lifecycle/update boundary: PASS")


if __name__ == "__main__":
    main()
