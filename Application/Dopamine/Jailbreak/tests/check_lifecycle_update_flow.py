#!/usr/bin/env python3
"""Static contracts for RootHide lifecycle/update compatibility changes."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
ENVIRONMENT = ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m"
ENVIRONMENT_HEADER = ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.h"
JAILBREAKER = ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m"
JAILBREAKER_HEADER = ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.h"
BOOTSTRAPPER = ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m"
JBCTL = ROOT / "BaseBin/jbctl/src/main.m"
UPDATE = ROOT / "BaseBin/launchdhook/src/update.m"
LAUNCHD_ROOTHIDER = ROOT / "BaseBin/launchdhook/src/roothider.m"
ROOTHIDER_COMMON_HEADER = ROOT / "BaseBin/libjailbreak/src/roothider/common.h"
ROOTHIDER_COMMON = ROOT / "BaseBin/libjailbreak/src/roothider/common.m"
VERSION = ROOT / "BaseBin/_external/basebin/.version"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def section(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    finish = text.index(end, begin)
    return text[begin:finish]


def main() -> None:
    environment = ENVIRONMENT.read_text(encoding="utf-8")
    environment_header = ENVIRONMENT_HEADER.read_text(encoding="utf-8")
    jailbreaker = JAILBREAKER.read_text(encoding="utf-8")
    jailbreaker_header = JAILBREAKER_HEADER.read_text(encoding="utf-8")
    bootstrapper = BOOTSTRAPPER.read_text(encoding="utf-8")
    jbctl = JBCTL.read_text(encoding="utf-8")
    update = UPDATE.read_text(encoding="utf-8")
    launchd_roothider = LAUNCHD_ROOTHIDER.read_text(encoding="utf-8")
    roothider_common_header = ROOTHIDER_COMMON_HEADER.read_text(encoding="utf-8")
    roothider_common = ROOTHIDER_COMMON.read_text(encoding="utf-8")

    require(VERSION.read_text(encoding="utf-8").strip() == "3.0.9.1",
            "basebin version must sort above official Dopamine 3.0.9")
    require('DORootHelperWaitProtocolMinimumBasebinVersion = @"2.4.9.29"' in environment,
            "app protocol gate must match the shipped basebin revision")

    helper = section(environment, "- (int)spawnJbctlAsRootWithArgs:", "- (int)runTrollStoreAction:")
    for invariant in (
        "SIZE_MAX / sizeof(char *)",
        "size_t argumentSlots = (size_t)args.count + 4;",
        'strdup("--waitfor")',
        'posix_spawn_file_actions_adddup2(&actions, waitPipe[0], 3)',
        'posix_spawn_file_actions_addclose(&actions, waitPipe[1])',
        'return cmd_wait_for_exit(pid);',
    ):
        require(invariant in helper, f"root helper lost required invariant: {invariant}")

    respring = section(environment, "- (void)respring", "- (void)rebootUserspace")
    require('exec_cmd_suspended(&pid, JBROOT_PATH("/usr/bin/sbreload"), NULL)' in respring,
            "pre-protocol basebin must keep the direct sbreload compatibility path")
    require(respring.index('[self runAsRoot:^{') < respring.index('[self resumeSuspendedRootHelperProcess:pid]'),
            "legacy sbreload must resume only after leaving runAsRoot")
    require('[self spawnJbctlAsRootWithArgs:@[@"respring"]];' in respring,
            "new basebin must route respring through the synchronized helper")

    for invariant in (
        "strtol(argv[argc - 1], &end, 10)",
        "bytesRead = read((int)parsedFD, &signal, sizeof(signal));",
        "*commandArgc -= 2;",
        'else if (!strcmp(cmd, "respring"))',
    ):
        require(invariant in jbctl, f"jbctl synchronization contract missing: {invariant}")

    require('strcmp(prevVersion, "3.0") < 0 && strcmp(newVersion, "3.0") >= 0' in update,
            "2.x-to-3.x jbupdate must reboot before incompatible finalizers")

    recovery = section(bootstrapper, 'BOOL recovered = NO;', 'if (!recovered) {')
    for invariant in (
        'JBROOT_PATH(@"/basebin/gen/dyld.old")',
        'activePrebootPath',
        'moveItemAtPath:corruptedFilePath toPath:orphanedPath',
        'removeItemAtPath:basebinPath error:&error',
    ):
        require(invariant in recovery, f"dyld.old recovery contract missing: {invariant}")
    require('/var/jb/basebin' not in recovery,
            "dyld.old recovery must resolve through JBROOT, not /var/jb")

    for declaration in (
        "- (NSString *)activePrebootPath;",
        "- (NSString *)accessibleSPTMPath;",
        "- (NSString *)accessibleTXMPath;",
    ):
        require(declaration in environment_header,
                f"SPTM/TXM path contract is not publicly available: {declaration}")

    sptm = section(environment, "- (NSString *)accessibleSPTMPath", "- (NSString *)accessibleTXMPath")
    txm = section(environment, "- (NSString *)accessibleTXMPath", "- (BOOL)isPACBypassRequired")
    expected_paths = {
        "SPTM": (
            sptm,
            "sptm.img4",
            "Documents/sptm.img4",
            "Documents/sptm.im4p",
            "usr/standalone/firmware/FUD/Ap,SecurePageTableMonitor.img4",
            "txm.img4",
            "TrustedExecutionMonitor",
        ),
        "TXM": (
            txm,
            "txm.img4",
            "Documents/txm.img4",
            "Documents/txm.im4p",
            "usr/standalone/firmware/FUD/Ap,TrustedExecutionMonitor.img4",
            "sptm.img4",
            "SecurePageTableMonitor",
        ),
    }
    for image_name, (accessor, app_path, docs_path, im4p_path, preboot_path, other_app_path, other_preboot_name) in expected_paths.items():
        for expected_path in (app_path, docs_path, im4p_path, preboot_path):
            require(expected_path in accessor,
                    f"{image_name} lookup lost required path: {expected_path}")
        require(other_app_path not in accessor and other_preboot_name not in accessor,
                f"{image_name} lookup must not substitute the other privileged image")
        require("[self activePrebootPath]" in accessor,
                f"{image_name} privileged lookup must use RootHide's active preboot path")
        require("[self isInstalledThroughTrollStore] || getuid() == 0" in accessor,
                f"{image_name} preboot lookup must stay privilege-gated")
        require("return nil;" in accessor,
                f"{image_name} lookup must fail closed when every candidate is missing")
        require(accessor.index(app_path) < accessor.index(docs_path) < accessor.index(im4p_path) < accessor.index(preboot_path) < accessor.rindex("return nil;"),
                f"{image_name} lookup must prefer app and Documents fallbacks before active preboot")

    print("SPTM/TXM image path flow: PASS")

    is_sptm = section(environment, "- (BOOL)isSPTM", "- (NSString *)versionSupportString")
    for invariant in (
        "IODeviceTree:/chosen/memory-map",
        "CFSTR(\"SPTM\")",
        "CFSTR(\"TXM\")",
        "IOObjectRelease(memoryMap)",
        "CFRelease(keys)",
        "return NO;",
    ):
        require(invariant in is_sptm,
                f"SPTM detection lost its fail-closed I/O registry contract: {invariant}")
    require("- (BOOL)isSPTM;" in environment_header,
            "SPTM detection must be declared for the app hard stop")

    gather = section(jailbreaker, "- (NSError *)gatherSystemInformation", "- (NSError *)doExploitation")
    for invariant in (
        "[environmentManager accessibleSPTMPath]",
        "[environmentManager accessibleTXMPath]",
        "xpf_start_with_kernel_path(kernelPath.fileSystemRepresentation,",
        "sptmPath ? sptmPath.fileSystemRepresentation : NULL",
        "txmPath ? txmPath.fileSystemRepresentation : NULL",
        "\"IOSurface\"",
        'xpf_set_is_supported("perfkrw")',
        'xpf_set_is_supported("namecache")',
        'xpf_set_is_supported("amfi_oids")',
        "DOJailbreakerAppendXPFSet",
        "kernelConstant.staticBase",
        "kernelConstant.staticSptmBase",
        "kernelConstant.staticTxmBase",
    ):
        require(invariant in gather, f"app XPF contract missing: {invariant}")
    require("environmentManager.isSPTM && (!sptmPath || !txmPath)" in gather,
            "SPTM app path must stop before XPF when either required image is absent")
    require(gather.index("environmentManager.isSPTM && (!sptmPath || !txmPath)") <
            gather.index("xpf_start_with_kernel_path(kernelPath.fileSystemRepresentation,"),
            "SPTM image hard stop must run before XPF")
    require(gather.index("kernelConstant.staticBase") < gather.index("jbinfo_initialize_dynamic_offsets"),
            "app static image bases must be recorded before jbinfo initialization")
    require("requiresAMFIOIDs" in gather and
            "kernelSymbol.launch_env_logging" in gather and
            "kernelSymbol.developer_mode_status" in gather,
            "iOS 16+ app path must fail closed when AMFI metrics are absent")

    update_system_info = section(update, "void jbupdate_update_system_info", "// Before primitives are retrieved")
    for invariant in (
        "int (*xpf_start_with_kernel_path)(const char *kernelPath, const char *optSptmPath, const char *optTxmPath)",
        "xpf_start_with_kernel_path(kernelPath, sptmPath, txmPath)",
        "prebootUUIDPath(\"/usr/standalone/firmware/FUD/Ap,SecurePageTableMonitor.img4\")",
        "prebootUUIDPath(\"/usr/standalone/firmware/FUD/Ap,TrustedExecutionMonitor.img4\")",
        "\"IOSurface\"",
        'xpf_set_is_supported("perfkrw")',
        'xpf_set_is_supported("namecache")',
        'xpf_set_is_supported("amfi_oids")',
        "jbupdate_append_xpf_set",
        "kernelConstant.staticBase",
        "kernelConstant.staticSptmBase",
        "kernelConstant.staticTxmBase",
    ):
        require(invariant in update_system_info, f"launchdhook XPF contract missing: {invariant}")
    require("(staticSptmBase && !sptmPath) || (staticTxmBase && !txmPath)" in update_system_info,
            "launchdhook must stop before XPF when a prior SPTM/TXM state loses its matching image")
    require(update_system_info.index("staticSptmBase =") <
            update_system_info.index("xpf_start_with_kernel_path(kernelPath, sptmPath, txmPath)"),
            "launchdhook must read serialized SPTM/TXM state before rerunning XPF")
    require(update_system_info.index("xpc_dictionary_set_uint64(systemInfoXdict, \"kernelConstant.staticBase\"") <
            update_system_info.index("jbinfo_initialize_dynamic_offsets(systemInfoXdict)"),
            "launchdhook static image bases must be restored before jbinfo initialization")
    require("requiresAMFIOIDs" in update_system_info and
            "validated RootHide AMFI developer-mode metrics are missing" in update_system_info,
            "iOS 16+ launchdhook update must fail closed when AMFI metrics are absent")

    hide_developer_mode = section(roothider_common, "int hideDeveloperMode(void)", "int randomizeAndLoadBasebinTrustcache")
    for invariant in (
        "developerModeStatusNameField <= oidNameOffset",
        "launchEnvLoggingNameField <= oidNameOffset",
        "oid_record_is_sane",
        "oid_record_has_expected_name",
        "oid_parent_contains",
        "oid_rollback_records",
        "goto rollback;",
        "rollback:",
        "JBLogError(\"hideDeveloperMode failed",
    ):
        require(invariant in hide_developer_mode,
                f"hideDeveloperMode lost fail-closed invariant: {invariant}")
    require(hide_developer_mode.index("oid_parent_contains") < hide_developer_mode.index("oid_remove(oidParent"),
            "hideDeveloperMode must validate both records before the first mutation")
    for invariant in (
        "kwritebuf(developerModeStatusAddress, developerModeStatusSnapshot",
        "kwritebuf(launchEnvLoggingAddress, launchEnvLoggingSnapshot",
        "oid_parent_remove_all",
        "oid_parent_occurrence_count(developerParent, developer_mode_status_oidp",
        "oid_parent_occurrence_count",
        "kRootHideMaximumSysctlOIDEntries",
    ):
        require(invariant in roothider_common,
                f"hideDeveloperMode rollback is not bounded and restorative: {invariant}")
    rollback_records = section(roothider_common, "static int oid_rollback_records", "static bool oid_record_has_expected_name")
    require(rollback_records.index("oid_parent_remove_all(oid_parent, (struct sysctl_oid *)developerModeStatusAddress)") <
            rollback_records.index("kwritebuf(developerModeStatusAddress, developerModeStatusSnapshot"),
            "rollback must unlink every developer-mode occurrence before restoring its snapshot")
    require(rollback_records.index("oid_parent_remove_all(oid_parent, (struct sysctl_oid *)launchEnvLoggingAddress)") <
            rollback_records.index("kwritebuf(launchEnvLoggingAddress, launchEnvLoggingSnapshot"),
            "rollback must unlink every launch-env occurrence before restoring its snapshot")
    require(rollback_records.index("kwritebuf(launchEnvLoggingAddress, launchEnvLoggingSnapshot") <
            rollback_records.index("oid_insert(oid_parent, (struct sysctl_oid *)developerModeStatusAddress)"),
            "rollback must restore both original records before sorted reinsertion")
    integrity_verification = section(roothider_common,
                                     "static int oid_parent_verify_integrity",
                                     "int hideDeveloperMode(void)")
    for invariant in (
        "oid_parent_verify_no_cycle(parentAddress)",
        "kRootHideMaximumSysctlOIDEntries",
        "oid_parent_read_verified_node",
        "currentOID.oid_number < previousNumber",
        "developerCount == 1 && launchCount == 1",
        "++developerCount > 1",
        "++launchCount > 1",
    ):
        require(invariant in integrity_verification,
                f"post-insert AMFI OID integrity verification missing: {invariant}")
    require("kwrite" not in integrity_verification,
            "post-insert AMFI OID integrity verification must be read-only")
    require(hide_developer_mode.index("oid_insert(oidParent, (struct sysctl_oid*)launch_env_logging_oidp)") <
            hide_developer_mode.index("oid_parent_verify_integrity(oidParent, developer_mode_status_oidp, launch_env_logging_oidp)") <
            hide_developer_mode.index("return 0;"),
            "post-insert AMFI OID verification must run after both inserts and before success")
    require(hide_developer_mode.index("oid_parent_verify_integrity(oidParent, developer_mode_status_oidp, launch_env_logging_oidp)") <
            hide_developer_mode.index("if (result != 0) goto rollback;", hide_developer_mode.index("oid_parent_verify_integrity")),
            "post-insert AMFI OID verification failures must roll back to the pre-mutation snapshot")
    require("int hideDeveloperMode(void);" in roothider_common_header,
            "hideDeveloperMode must expose an error result")
    require("int hideDeveloperModeResult = hideDeveloperMode();" in launchd_roothider and
            "launchd_panic(\"hideDeveloperMode failed: %d\", hideDeveloperModeResult);" in launchd_roothider,
            "launchdhook must treat failed developer-mode hiding as fatal")

    print("XPF/AMFI safety flow: PASS")

    contiguous_mapping = section(jailbreaker, "- (IOSurfaceRef)allocatePurpleGfxMemWithSize", "@end")
    for invariant in (
        '#import "clock_alarm.h"',
        "#import <IOSurface/IOSurfaceRef.h>",
        "kDOContiguousMappingMaximumAttempts = 512",
        "kDOContiguousMappingMaximumNanoseconds",
        "mach_continuous_time() - startTime >= deadlineTicks",
        "for (NSUInteger attempt = 0; attempt < kDOContiguousMappingMaximumAttempts; attempt++)",
        '[kernelExploit hasRequirement:@\"contiguousMapping\"]',
        "IOSurfaceCreateMachPort(surface)",
        "clock_alarm_preserve_port(surfacePort, 20)",
        "mach_port_mod_refs(mach_task_self(), surfacePort, MACH_PORT_RIGHT_SEND, -1)",
        "CFRelease(surface)",
        "xpc_connection_cancel(client)",
        "XPC overlay releases ool, reply,",
        "mach_port_deallocate(mach_task_self(), service)",
    ):
        require(invariant in jailbreaker,
                f"contiguous-mapping workaround lost required contract: {invariant}")
    require("- (BOOL)contiguousMappingWorkaroundNeeded;" in jailbreaker_header and
            "- (NSError * _Nullable)applyContiguousMappingWorkaround;" in jailbreaker_header,
            "contiguous-mapping public contract must expose the predicate and fail-closed result")
    apply_workaround = section(jailbreaker,
                               "- (NSError * _Nullable)applyContiguousMappingWorkaround",
                               "@end")
    require("do {" not in apply_workaround and "while (![self surfaceIsContiguous" not in apply_workaround,
            "contiguous-mapping acquisition must not retain upstream's unbounded retry loop")
    require(apply_workaround.index("clock_alarm_preserve_port(surfacePort, 20)") <
            apply_workaround.rindex("return nil;"),
            "contiguous-mapping workaround may only return success after port preservation")
    require("Unable to obtain a contiguous PurpleGfxMem mapping within the safe retry window." in apply_workaround,
            "contiguous-mapping acquisition must fail closed when the bounded window expires")

    print("Contiguous mapping workaround flow: PASS")

    print("RootHide lifecycle/update flow: PASS")


if __name__ == "__main__":
    main()
