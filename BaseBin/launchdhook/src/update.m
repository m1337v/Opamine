#include <stdlib.h>
#include <libjailbreak/util.h>
#include <libjailbreak/trustcache.h>
#include <libjailbreak/kcall_arm64.h>
#include <libjailbreak/signatures.h>
#include <libjailbreak/basebin_gen.h>
#include <xpc/xpc.h>
#include <dlfcn.h>
#include <CommonCrypto/CommonDigest.h>

#import <Foundation/Foundation.h>

//void abort_with_reason(uint32_t reason_namespace, uint64_t reason_code, const char *reason_string, uint64_t reason_flags);
#define abort_with_reason(reason_namespace,reason_code,reason_string,reason_flags)  launchd_panic("%s",reason_string)

static NSString *basebin_tar_md5(NSString *path)
{
	NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
	if (data.length == 0) {
		return nil;
	}

	unsigned char digest[CC_MD5_DIGEST_LENGTH] = {0};
	CC_MD5(data.bytes, (CC_LONG)data.length, digest);

	NSMutableString *hash = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
	for (NSUInteger i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
		[hash appendFormat:@"%02x", digest[i]];
	}
	return hash;
}

static bool jbupdate_append_xpf_set(const char *sets[], size_t capacity, size_t *setCount, const char *set)
{
	if (!sets || !setCount || !set || capacity < 2 || *setCount >= capacity - 1) {
		return false;
	}

	sets[(*setCount)++] = set;
	sets[*setCount] = NULL;
	return true;
}

int jbupdate_basebin(const char *basebinTarPath)
{
	@autoreleasepool {
		int r = 0;
		if (access(basebinTarPath, F_OK) != 0) return 1;

		NSString *prevVersion = [NSString stringWithContentsOfFile:JBROOT_PATH(@"/basebin/.version") encoding:NSUTF8StringEncoding error:nil] ?: @"2.0";
		NSString *basebinMD5 = basebin_tar_md5(@(basebinTarPath));

		// Extract basebin tar
		NSString *tmpExtractionPath = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
		r = libarchive_unarchive(basebinTarPath, tmpExtractionPath.fileSystemRepresentation);
		if (r != 0) {
			[[NSFileManager defaultManager] removeItemAtPath:tmpExtractionPath error:nil];
			return 2;
		}
		NSString *tmpBasebinPath = [tmpExtractionPath stringByAppendingPathComponent:@"basebin"];

		// Update basebin trustcache
		NSString *trustcachePath = [tmpBasebinPath stringByAppendingPathComponent:@"basebin.tc"];
		if (![[NSFileManager defaultManager] fileExistsAtPath:trustcachePath]) return 3;
/*
		trustcache_file_v1 *basebinTcFile = NULL;
		if (trustcache_file_build_from_path(trustcachePath.fileSystemRepresentation, &basebinTcFile) != 0) {
			[[NSFileManager defaultManager] removeItemAtPath:tmpExtractionPath error:nil];
			return 4;
		}
		r = trustcache_file_upload_with_uuid(basebinTcFile, BASEBIN_TRUSTCACHE_UUID);
		free(basebinTcFile);
*/
/********************************* roothide specfic ********************/
		r = randomizeAndLoadBasebinTrustcache(tmpBasebinPath.fileSystemRepresentation);
/********************************* roothide specfic ********************/

		if (r != 0) {
			[[NSFileManager defaultManager] removeItemAtPath:tmpExtractionPath error:nil];
			return 5;
		}
		else {
			[[NSFileManager defaultManager] removeItemAtPath:trustcachePath error:nil];
		}

		// Replace basebin content
		NSArray *newBasebinContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:tmpBasebinPath error:nil];
		for (NSString *basebinItem in newBasebinContents) {
			NSString *newBasebinPath = [tmpBasebinPath stringByAppendingPathComponent:basebinItem];
			NSString *oldBasebinPath = [JBROOT_PATH(@"/basebin") stringByAppendingPathComponent:basebinItem];
			if ([[NSFileManager defaultManager] fileExistsAtPath:oldBasebinPath]) {
				[[NSFileManager defaultManager] removeItemAtPath:oldBasebinPath error:nil];
			}
			[[NSFileManager defaultManager] copyItemAtPath:newBasebinPath toPath:oldBasebinPath error:nil];
		}
		if (basebinMD5.length > 0) {
			[basebinMD5 writeToFile:JBROOT_PATH(@"/basebin/.basebin_md5") atomically:YES encoding:NSUTF8StringEncoding error:nil];
		}
		[[NSFileManager defaultManager] removeItemAtPath:tmpExtractionPath error:nil];

		// Patch basebin plists
		NSURL *basebinDaemonsURL = [NSURL fileURLWithPath:JBROOT_PATH(@"/basebin/LaunchDaemons")];
		for (NSURL *basebinDaemonURL in [[NSFileManager defaultManager] contentsOfDirectoryAtURL:basebinDaemonsURL includingPropertiesForKeys:nil options:0 error:nil]) {
			NSString *plistPath = basebinDaemonURL.path;
			NSMutableDictionary *plistDict = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
			if (plistDict) {
				bool madeChanges = NO;
				NSMutableArray *programArguments = ((NSArray *)plistDict[@"ProgramArguments"]).mutableCopy;
				for (NSString *argument in [programArguments reverseObjectEnumerator]) {
					if ([argument containsString:@"@JBROOT@"]) {
						programArguments[[programArguments indexOfObject:argument]] = [argument stringByReplacingOccurrencesOfString:@"@JBROOT@" withString:JBROOT_PATH(@"/")];
						madeChanges = YES;
					}
				}
				if (madeChanges) {
					plistDict[@"ProgramArguments"] = programArguments.copy;
					[plistDict writeToFile:plistPath atomically:NO];
				}
			}
		}

		NSString *newVersion = [NSString stringWithContentsOfFile:JBROOT_PATH(@"/basebin/.version") encoding:NSUTF8StringEncoding error:nil];
		if (!newVersion) return 6;

		setenv("JBUPDATE_PREV_VERSION", prevVersion.UTF8String, 1);
		setenv("JBUPDATE_NEW_VERSION", newVersion.UTF8String, 1);
		return 0;
	}
}

void jbupdate_update_system_info(void)
{
	@autoreleasepool {
		// Load XPF
		void *xpfHandle = dlopen("@loader_path/libxpf.dylib", RTLD_NOW);
		if (!xpfHandle) {
			char msg[4000];
			snprintf(msg, 4000, "Dopamine: dlopening libxpf failed: (%s), cannot continue.", dlerror());
			abort_with_reason(7, 1, msg, 0);
			return;
		}
		int (*xpf_start_with_kernel_path)(const char *kernelPath, const char *optSptmPath, const char *optTxmPath) = dlsym(xpfHandle, "xpf_start_with_kernel_path");
		const char *(*xpf_get_error)(void) = dlsym(xpfHandle, "xpf_get_error");
		bool (*xpf_set_is_supported)(const char *name) = dlsym(xpfHandle, "xpf_set_is_supported");
		void (*xpf_stop)(void) = dlsym(xpfHandle, "xpf_stop");
		xpc_object_t (*xpf_construct_offset_dictionary)(const char *sets[]) = dlsym(xpfHandle, "xpf_construct_offset_dictionary");
		if (!xpf_start_with_kernel_path || !xpf_get_error || !xpf_set_is_supported || !xpf_stop || !xpf_construct_offset_dictionary) {
			dlclose(xpfHandle);
			abort_with_reason(7, 1, "Dopamine: libxpf is missing a required patchfinding symbol.", 0);
			return;
		}

		// Read these before invoking XPF. Their presence means the prior launchd
		// state was built with the SPTM/TXM path and must not be downgraded.
		xpc_object_t systemInfoXdict = jbinfo_get_serialized();
		uint64_t staticBase = systemInfoXdict ? xpc_dictionary_get_uint64(systemInfoXdict, "kernelConstant.staticBase") : 0;
		uint64_t staticSptmBase = systemInfoXdict ? xpc_dictionary_get_uint64(systemInfoXdict, "kernelConstant.staticSptmBase") : 0;
		uint64_t staticTxmBase = systemInfoXdict ? xpc_dictionary_get_uint64(systemInfoXdict, "kernelConstant.staticTxmBase") : 0;
		if (!systemInfoXdict || !staticBase) {
			dlclose(xpfHandle);
			abort_with_reason(7, 1, "Dopamine: existing static kernel image base is unavailable.", 0);
			return;
		}

		const char *kernelPath = prebootUUIDPath("/System/Library/Caches/com.apple.kernelcaches/kernelcache");
		const char *sptmPath = prebootUUIDPath("/usr/standalone/firmware/FUD/Ap,SecurePageTableMonitor.img4");
		if (access(sptmPath, F_OK) != 0) sptmPath = NULL;
		const char *txmPath = prebootUUIDPath("/usr/standalone/firmware/FUD/Ap,TrustedExecutionMonitor.img4");
		if (access(txmPath, F_OK) != 0) txmPath = NULL;
		if ((staticSptmBase && !sptmPath) || (staticTxmBase && !txmPath)) {
			dlclose(xpfHandle);
			abort_with_reason(7, 1, "Dopamine: required SPTM/TXM preboot image is unavailable.", 0);
			return;
		}
		xpc_object_t newSystemInfoXdict = NULL;
		const char *error = NULL;
		char xpfError[4000] = { 0 };

		// Rerun patchfinder
		int r = xpf_start_with_kernel_path(kernelPath, sptmPath, txmPath);
		if (r == 0) {
			const char *sets[16] = { 0 };
			size_t setCount = 0;
			const char *requiredSets[] = {
				"translation",
				"trustcache",
				"sandbox",
				"physmap",
				"struct",
				"physrw",
				"IOSurface",
				NULL,
			};

			for (const char **set = requiredSets; *set; set++) {
				if (!jbupdate_append_xpf_set(sets, sizeof(sets) / sizeof(*sets), &setCount, *set)) {
					error = "Dopamine: XPF set list overflow while preparing required offsets.";
					break;
				}
			}
			if (!error && xpf_set_is_supported("devmode") &&
				!jbupdate_append_xpf_set(sets, sizeof(sets) / sizeof(*sets), &setCount, "devmode")) {
				error = "Dopamine: XPF set list overflow while preparing developer-mode offsets.";
			}
			if (!error && xpf_set_is_supported("badRecovery") &&
				!jbupdate_append_xpf_set(sets, sizeof(sets) / sizeof(*sets), &setCount, "badRecovery")) {
				error = "Dopamine: XPF set list overflow while preparing recovery offsets.";
			}
			if (!error && xpf_set_is_supported("arm64kcall") &&
				!jbupdate_append_xpf_set(sets, sizeof(sets) / sizeof(*sets), &setCount, "arm64kcall")) {
				error = "Dopamine: XPF set list overflow while preparing kcall offsets.";
			}
			if (!error && xpf_set_is_supported("perfkrw") &&
				!jbupdate_append_xpf_set(sets, sizeof(sets) / sizeof(*sets), &setCount, "perfkrw")) {
				error = "Dopamine: XPF set list overflow while preparing perfkrw offsets.";
			}

			// RootHide requires this validated pair for its namecache implementation.
			if (!error && (!xpf_set_is_supported("namecache") ||
				!jbupdate_append_xpf_set(sets, sizeof(sets) / sizeof(*sets), &setCount, "namecache"))) {
				error = "Dopamine: RootHide namecache offsets are unavailable.";
			}

			bool requiresAMFIOIDs = false;
			if (__builtin_available(iOS 16.0, *)) {
				requiresAMFIOIDs = true;
			}
			if (!error && requiresAMFIOIDs && (!xpf_set_is_supported("amfi_oids") ||
				!jbupdate_append_xpf_set(sets, sizeof(sets) / sizeof(*sets), &setCount, "amfi_oids"))) {
				// launchd's first-load path must not call hideDeveloperMode with
				// unvalidated or missing AMFI record offsets.
				error = "Dopamine: validated RootHide AMFI developer-mode offsets are unavailable.";
			}

			if (!error) {
				newSystemInfoXdict = xpf_construct_offset_dictionary(sets);
			}
			if (!error && !newSystemInfoXdict) {
				snprintf(xpfError, sizeof(xpfError), "%s", xpf_get_error() ?: "unknown XPF error");
				error = xpfError;
			}
			if (!error && requiresAMFIOIDs &&
				(!xpc_dictionary_get_uint64(newSystemInfoXdict, "kernelSymbol.launch_env_logging") ||
				 !xpc_dictionary_get_uint64(newSystemInfoXdict, "kernelSymbol.developer_mode_status"))) {
				error = "Dopamine: validated RootHide AMFI developer-mode metrics are missing.";
			}
			xpf_stop();
		}
		else {
			snprintf(xpfError, sizeof(xpfError), "%s", xpf_get_error() ?: "unknown XPF error");
			error = xpfError;
			xpf_stop();
		}

		dlclose(xpfHandle);
		if (error) {
			char msg[4000];
			snprintf(msg, 4000, "Dopamine: Updating system info via XPF failed with error: (%s), cannot continue.", error);
			abort_with_reason(7, 1, msg, 0);
			return;
		}

		if (!newSystemInfoXdict) {
			error = "Dopamine: XPF did not return a system information dictionary.";
		}

		// Keep the original image bases from the serialized launchd state. XPF is
		// dynamically loaded here, unlike the app path where gXPF is available.
		if (!error) {
			xpc_dictionary_apply(newSystemInfoXdict, ^_Bool(const char *key, xpc_object_t xobj) {
				xpc_dictionary_set_value(systemInfoXdict, key, xobj);
				return true;
			});
			xpc_dictionary_set_uint64(systemInfoXdict, "kernelConstant.staticBase", staticBase);
			xpc_dictionary_set_uint64(systemInfoXdict, "kernelConstant.staticSptmBase", staticSptmBase);
			xpc_dictionary_set_uint64(systemInfoXdict, "kernelConstant.staticTxmBase", staticTxmBase);
		}

		if (error) {
			char msg[4000];
			snprintf(msg, 4000, "Dopamine: Updating system info via XPF failed with error: (%s), cannot continue.", error);
			abort_with_reason(7, 1, msg, 0);
			return;
		}

		// Rebuild gSystemInfo
		jbinfo_initialize_dynamic_offsets(systemInfoXdict);
		jbinfo_initialize_hardcoded_offsets();
	}
}

// Before primitives are retrieved
void jbupdate_finalize_stage1(const char *prevVersion, const char *newVersion)
{
	// Currently unused, reserved for the future
}

// After primitives are retrieved
void jbupdate_finalize_stage2(const char *prevVersion, const char *newVersion)
{
	jbupdate_update_system_info();

	if (strcmp(prevVersion, "2.4") < 0 && strcmp(newVersion, "2.4") >= 0) {
		// On Dopamine <= 2.3, dyld used to be a file on the fakelib mount
		// Due to that, the fakelib mount cannot be unmounted, or else the system will panic
		// Additionally it cannot be modified because bind mounts are weird and won't update correctly
		// In >= 2.4 dyld is a symlink to elsewhere, which allows it to be updated and the bind mount to be unmounted
		// But if we're coming from <= 2.3, we have no option other than to reboot the device
		reboot(0);
	}

	if (strcmp(prevVersion, "3.0") < 0 && strcmp(newVersion, "3.0") >= 0) {
		// An in-place 2.x -> 3.x update is unsafe after the PPLRW user mapping
		// change. Reboot before any remaining update finalizers use the new basebin.
		reboot(0);
	}

	// Legacy, this file is no longer used
	if (!access(JBROOT_PATH("/basebin/.idownloadd_enabled"), F_OK)) {
		remove(JBROOT_PATH("/basebin/.idownloadd_enabled"));
	}

	if (strcmp(prevVersion, "2.1") < 0 && strcmp(newVersion, "2.1") >= 0) {
		// Default value for this pref is true
		// Set it during jbupdate if prev version is <2.1 and new version is >=2.1
		gSystemInfo.jailbreakSettings.markAppsAsDebugged = true;

#ifndef __arm64e__
		// Initialize kcall only after we have the offsets required for it
		arm64_kcall_init();
#endif
	}

	// Update patched dyld
	int r = basebin_generate(YES);
	if (r != 0) {
		char msg[4000];
		snprintf(msg, 4000, "Dopamine: Updating patched dyld failed with error %d, cannot continue.", r);
		abort_with_reason(7, 1, msg, 0);
	}

	// Update dyld trustcache
	cdhash_t *cdhashes = NULL;
	uint32_t cdhashesCount = 0;
	file_collect_untrusted_cdhashes_by_path(JBROOT_PATH("/basebin/.fakelib/dyld"), &cdhashes, &cdhashesCount);

	if (cdhashesCount > 1) {
		char msg[4000];
		snprintf(msg, 4000, "Dopamine: Updating patched dyld failed due to unexpected amount of cdhashes (%d), cannot continue.", cdhashesCount);
		abort_with_reason(7, 1, msg, 0);
	}
	else if (cdhashesCount == 1) {
		trustcache_file_v1 *dyldTCFile = NULL;
		r = trustcache_file_build_from_cdhashes(cdhashes, cdhashesCount, &dyldTCFile);
		free(cdhashes);
		if (r != 0) {
			char msg[4000];
			snprintf(msg, 4000, "Dopamine: Building dyld trustcache failed with error %d, cannot continue.", r);
			abort_with_reason(7, 1, msg, 0);
		}

		r = trustcache_file_upload_with_uuid(dyldTCFile, DYLD_TRUSTCACHE_UUID);
		if (r != 0) {
			char msg[4000];
			snprintf(msg, 4000, "Dopamine: Updating dyld trustcache failed with error %d, cannot continue.", r);
			abort_with_reason(7, 1, msg, 0);
		}

		free(dyldTCFile);
	}

	JBFixMobilePermissions();
}
