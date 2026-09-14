#include "jbserver_global.h"
#include "jbsettings.h"
#include <libjailbreak/info.h>
#include <sandbox.h>
#include <libproc.h>
#include <sys/proc_info.h>

#include <libjailbreak/signatures.h>
#include <libjailbreak/trustcache.h>
#include <libjailbreak/kernel.h>
#include <libjailbreak/util.h>
#include <libjailbreak/primitives.h>
#include <libjailbreak/codesign.h>

#include <errno.h>
#include <signal.h>
#include <libjailbreak/roothider.h>

/*
bool gSystemwideDomainEnabled = true;
void systemwide_domain_set_enabled(bool enabled)
{
	gSystemwideDomainEnabled = enabled;
}
*/

extern bool string_has_prefix(const char *str, const char* prefix);
extern bool string_has_suffix(const char* str, const char* suffix);

char *combine_strings(char separator, char **components, int count)
{
	if (count <= 0) return NULL;

	bool isFirst = true;

	size_t outLength = 1;
	for (int i = 0; i < count; i++) {
		if (components[i]) {
			outLength += !isFirst + strlen(components[i]);
			if (isFirst) isFirst = false;
		}
	}

	isFirst = true;
	char *outString = malloc(outLength * sizeof(char));
	*outString = 0;

	for (int i = 0; i < count; i++) {
		if (components[i]) {
			if (isFirst) {
				strlcpy(outString, components[i], outLength);
				isFirst = false;
			}
			else {
				char separatorString[2] = { separator, 0 };
				strlcat(outString, (char *)separatorString, outLength);
				strlcat(outString, components[i], outLength);
			}
		}
	}

	return outString;
}

/*
bool systemwide_domain_allowed(audit_token_t clientToken)
{
	if (!gSystemwideDomainEnabled) {
		// While the jailbreak is hidden, we need to disable the systemwide domain
		pid_t pid = audit_token_to_pid(clientToken);
		char procPath[4*MAXPATHLEN];
		if (proc_pidpath(pid, procPath, sizeof(procPath)) <= 0) {
			return false;
		}

		if (string_has_suffix(procPath, "/Dopamine.app/Dopamine")) {
			// We still want it to be accessible by Dopamine itself though
			// Unfortunately, there is not really a better check here since
			// - Dopamine can be sideloaded, so no control over entitlements
			// - App identifier could be changed by whoever installed it aswell
			return true;
		}

		return false;
	}
	return true;
}
*/

static int systemwide_get_jbroot(char **rootPathOut)
{
	*rootPathOut = strdup(jbinfo(rootPath));
	return 0;
}

static int systemwide_get_boot_uuid(char **bootUUIDOut)
{
	const char *launchdUUID = getenv("LAUNCHD_UUID");
	*bootUUIDOut = launchdUUID ? strdup(launchdUUID) : NULL;
	return 0;
}

/*
 * The signature transaction comes from Dopamine 3, but these checks and the
 * jbrand rewrite are RootHide policy.  Keep them at the launchdhook boundary:
 * trust_signatures deliberately knows nothing about a randomized root or the
 * removable-app allowlist.
 */
static bool systemwide_root_hide_allows_trust_path(const char *path)
{
	if (!path || path[0] == '\0') return false;
	if (string_has_prefix(path, "/private/preboot/Cryptexes/")) {
		JBLogDebug("Skipping Cryptexes file: %s", path);
		return false;
	}
	if (isRemovableBundlePath(path) && !hasTrollstoreLiteMarker(path)) {
		JBLogDebug("Ignoring adhoc-signed removable app: %s", path);
		return false;
	}
	return true;
}

static void systemwide_free_local_signatures(struct siginfo *sigInfos, uint32_t sigInfoCount)
{
	if (!sigInfos) return;
	for (uint32_t i = 0; i < sigInfoCount; i++) {
		if (sigInfos[i].source == SIGNATURE_SOURCE_ALLOCATION) {
			free(sigInfos[i].signature.fs_blob_start);
		}
	}
	free(sigInfos);
}

static bool systemwide_siginfo_cdhash(const struct siginfo *siginfo, int pid, int fd, cdhash_t cdhashOut)
{
	CS_SuperBlob *superblob = siginfo_resolve_superblob(siginfo, pid, fd);
	if (!superblob) return false;
	bool result = code_signature_calculate_adhoc_cdhash(superblob, cdhashOut);
	free(superblob);
	return result;
}

struct systemwide_root_hide_signature_candidate {
	uint64_t fileStart;
	cdhash_t cdhash;
};

/*
 * Re-read signatures after RootHide has changed a slice's first section and
 * CodeDirectory page hash.  Passing these local copies to trust_signatures is
 * essential on SPTM devices: it may need to rewrite the CodeDirectory and
 * F_ADDSIGS cannot safely mutate a FILE/PROC siginfo supplied by another
 * process.  Matching both offset and final cdhash prevents an unrelated fat
 * slice from entering the transaction.
 */
static int systemwide_collect_updated_signatures(
	int fd,
	const struct systemwide_root_hide_signature_candidate *candidates,
	uint32_t candidateCount,
	struct siginfo **sigInfosOut,
	uint32_t *sigInfoCountOut)
{
	if (!sigInfosOut || !sigInfoCountOut || !candidates || candidateCount == 0) return -EINVAL;
	*sigInfosOut = NULL;
	*sigInfoCountOut = 0;
	if ((size_t)candidateCount > SIZE_MAX / sizeof(struct siginfo)) return -EOVERFLOW;

	struct siginfo *collected = NULL;
	uint32_t collectedCount = 0;
	file_collect_signatures(fd, &collected, &collectedCount);
	if (!collected || collectedCount == 0) {
		systemwide_free_local_signatures(collected, collectedCount);
		return -EIO;
	}

	struct siginfo *selected = calloc(candidateCount, sizeof(*selected));
	bool *matched = calloc(candidateCount, sizeof(*matched));
	if (!selected || !matched) {
		free(selected);
		free(matched);
		systemwide_free_local_signatures(collected, collectedCount);
		return -ENOMEM;
	}

	for (uint32_t i = 0; i < collectedCount; i++) {
		if (collected[i].source != SIGNATURE_SOURCE_ALLOCATION) continue;
		for (uint32_t j = 0; j < candidateCount; j++) {
			if (matched[j] || collected[i].signature.fs_file_start != candidates[j].fileStart) continue;
			cdhash_t cdhash;
			if (!systemwide_siginfo_cdhash(&collected[i], 1, fd, cdhash) ||
				memcmp(cdhash, candidates[j].cdhash, sizeof(cdhash_t)) != 0) {
				continue;
			}
			selected[j] = collected[i];
			/* Ownership moves into selected[j]. */
			collected[i].signature.fs_blob_start = NULL;
			collected[i].signature.fs_blob_size = 0;
			matched[j] = true;
			break;
		}
	}

	int result = 0;
	for (uint32_t i = 0; i < candidateCount; i++) {
		if (!matched[i]) {
			result = -EIO;
			break;
		}
	}
	free(matched);
	systemwide_free_local_signatures(collected, collectedCount);
	if (result != 0) {
		systemwide_free_local_signatures(selected, candidateCount);
		return result;
	}

	*sigInfosOut = selected;
	*sigInfoCountOut = candidateCount;
	return 0;
}

/* Preserve RootHide's no-siginfo flow: every mappable adhoc slice is jbrand
 * randomized before its final cdhash is checked, then only those exact slices
 * enter the Dopamine 3 signature transaction. */
static int systemwide_prepare_root_hide_file_signatures(
	int fd,
	const char *path,
	struct siginfo **sigInfosOut,
	uint32_t *sigInfoCountOut)
{
	if (!path || !sigInfosOut || !sigInfoCountOut) return -EINVAL;
	*sigInfosOut = NULL;
	*sigInfoCountOut = 0;

	struct siginfo *initial = NULL;
	uint32_t initialCount = 0;
	file_collect_signatures(fd, &initial, &initialCount);
	if (initialCount == 0) {
		systemwide_free_local_signatures(initial, initialCount);
		return 0;
	}
	if (!initial || (size_t)initialCount > SIZE_MAX / sizeof(struct systemwide_root_hide_signature_candidate)) {
		systemwide_free_local_signatures(initial, initialCount);
		return -EIO;
	}

	struct systemwide_root_hide_signature_candidate *candidates = calloc(initialCount, sizeof(*candidates));
	if (!candidates) {
		systemwide_free_local_signatures(initial, initialCount);
		return -ENOMEM;
	}

	uint32_t candidateCount = 0;
	int result = 0;
	for (uint32_t i = 0; i < initialCount; i++) {
		cdhash_t initialCdhash;
		if (!systemwide_siginfo_cdhash(&initial[i], 1, fd, initialCdhash)) continue;

		cdhash_t randomizedCdhash;
		if (ensure_randomized_cdhash_for_slice(path, initial[i].signature.fs_file_start, randomizedCdhash) != 0) {
			JBLogError("Failed to ensure randomized cdhash for %s", path);
			result = -EIO;
			break;
		}
		if (is_cdhash_trustcached(randomizedCdhash)) continue;

		candidates[candidateCount].fileStart = initial[i].signature.fs_file_start;
		memcpy(candidates[candidateCount].cdhash, randomizedCdhash, sizeof(cdhash_t));
		candidateCount++;
	}
	systemwide_free_local_signatures(initial, initialCount);
	if (result == 0 && candidateCount > 0) {
		result = systemwide_collect_updated_signatures(fd, candidates, candidateCount, sigInfosOut, sigInfoCountOut);
	}
	free(candidates);
	return result;
}

/* A Mach siginfo has FILE/PROC storage owned by its sender.  Keep the old
 * exact-slice policy, but turn the post-jbrand file signature into a local
 * allocation so TXM fixes can attach it transactionally. */
static int systemwide_prepare_root_hide_siginfo(
	int pid,
	int fd,
	const char *path,
	const struct siginfo *siginfo,
	struct siginfo **sigInfosOut,
	uint32_t *sigInfoCountOut)
{
	if (!path || !siginfo || !sigInfosOut || !sigInfoCountOut) return -EINVAL;
	*sigInfosOut = NULL;
	*sigInfoCountOut = 0;
	if (siginfo->source != SIGNATURE_SOURCE_FILE && siginfo->source != SIGNATURE_SOURCE_PROC) return -EPERM;

	cdhash_t initialCdhash;
	if (!systemwide_siginfo_cdhash(siginfo, pid, fd, initialCdhash)) return 0;
	/* This is intentionally before jbrand randomization to preserve the old
	 * siginfo path's per-slice duplicate behaviour. */
	if (is_cdhash_trustcached(initialCdhash)) return 0;

	struct systemwide_root_hide_signature_candidate candidate = {
		.fileStart = siginfo->signature.fs_file_start,
	};
	if (ensure_randomized_cdhash_for_slice(path, candidate.fileStart, candidate.cdhash) != 0) {
		JBLogError("Failed to ensure randomized cdhash for %s", path);
		return -EIO;
	}
	if (is_cdhash_trustcached(candidate.cdhash)) return 0;
	return systemwide_collect_updated_signatures(fd, &candidate, 1, sigInfosOut, sigInfoCountOut);
}

int systemwide_trust_file(audit_token_t *processToken, int rfd, struct siginfo *siginfo, size_t siginfoSize)
{
	if (siginfo && siginfoSize != sizeof(struct siginfo)) return -EINVAL;

	pid_t pid = -1;
	int fd = -1;
	if (!processToken) {
		pid = 1;
		fd = dup(rfd);
	}
	else {
		pid = audit_token_to_pid(*processToken);
		struct vnode_fdinfowithpath vnodeInfo;
		int ok = proc_pidfdinfo(pid, rfd, PROC_PIDFDVNODEPATHINFO, &vnodeInfo, sizeof(vnodeInfo));
		if (ok > 0) {
			fd = open(vnodeInfo.pvip.vip_path, O_RDONLY);
		}
	}

	if (fd < 0) return errno ? -errno : -EIO;

	struct statfs fsb;
	int fsr = fstatfs(fd, &fsb);
	if (fsr == 0) {
		// Anything on the rootfs or fakelib mount point can be ignored as it's guaranteed to already be in trustcache
		if (!strcmp(fsb.f_mntonname, "/") /*|| !strcmp(fsb.f_mntonname, "/usr/lib")*/) {
			close(fd);
			return 0;
		}
	}

	char filepath[PATH_MAX] = {0};
	if (fcntl(fd, F_GETPATH, filepath) != 0) {
		int result = errno ? -errno : -EIO;
		JBLogError("Failed to get file path for fd %d", fd);
		close(fd);
		return result;
	}
	if (!systemwide_root_hide_allows_trust_path(filepath)) {
		close(fd);
		return 0;
	}

	/* Never jbrand-mutate a file before discovering that the required SPTM/TXM
	 * metadata was omitted by an old basebin/XPF startup. */
	if (jbinfo_has_sptm_metadata() && !jbinfo_sptm_runtime_ready()) {
		JBLogError("Refusing signature transaction with incomplete SPTM/TXM metadata");
		close(fd);
		return -ENOTSUP;
	}

	struct siginfo *sigInfos = NULL;
	uint32_t sigInfoCount = 0;
	int result = siginfo
		? systemwide_prepare_root_hide_siginfo(pid, fd, filepath, siginfo, &sigInfos, &sigInfoCount)
		: systemwide_prepare_root_hide_file_signatures(fd, filepath, &sigInfos, &sigInfoCount);
	if (result == 0 && sigInfoCount > 0) {
		/* trust_signatures attaches any TXM-rewritten local signatures before
		 * publishing its final cdhashes, and deduplicates both the transaction
		 * and the existing RootHide trust cache. */
		result = trust_signatures(pid, fd, sigInfos, sigInfoCount);
	}
	systemwide_free_local_signatures(sigInfos, sigInfoCount);
	close(fd);
	return result;
}

int systemwide_trust_file_by_path(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	int r = systemwide_trust_file(NULL, fd, NULL, 0);
	close(fd);
	return r;
}

int systemwide_process_checkin(audit_token_t *processToken, char **rootPathOut, char **bootUUIDOut, char **sandboxExtensionsOut, bool *fullyDebuggedOut)
{
	// Fetch process info
	pid_t pid = audit_token_to_pid(*processToken);
	char procPath[4*MAXPATHLEN];
	if (proc_pidpath(pid, procPath, sizeof(procPath)) <= 0) {
		return -1;
	}

	// Find proc in kernelspace
	uint64_t proc = proc_find(pid);
	if (!proc) {
		return -1;
	}

	// Get jbroot and boot uuid
	systemwide_get_jbroot(rootPathOut);
	systemwide_get_boot_uuid(bootUUIDOut);

/*
	// Generate sandbox extensions for the requesting process
	char *sandboxExtensionsArr[] = {
		// Make /var/jb readable and executable
		sandbox_extension_issue_file_to_process("com.apple.app-sandbox.read", JBROOT_PATH(""), 0, *processToken),
		sandbox_extension_issue_file_to_process("com.apple.sandbox.executable", JBROOT_PATH(""), 0, *processToken),

		// Make /var/jb/var/mobile writable
		sandbox_extension_issue_file_to_process("com.apple.app-sandbox.read-write", JBROOT_PATH("/var/mobile"), 0, *processToken),
	};
	int sandboxExtensionsCount = sizeof(sandboxExtensionsArr) / sizeof(char *);
	*sandboxExtensionsOut = combine_strings('|', sandboxExtensionsArr, sandboxExtensionsCount);
	for (int i = 0; i < sandboxExtensionsCount; i++) {
		if (sandboxExtensionsArr[i]) {
			free(sandboxExtensionsArr[i]);
		}
	}

	bool fullyDebugged = false;
	if (string_has_prefix(procPath, "/private/var/containers/Bundle/Application") || string_has_prefix(procPath, JBROOT_PATH("/Applications"))) {
*/

/************************************ roothide specific ************************************************/
	uint32_t csflags = 0;
    csops(pid, CS_OPS_STATUS, &csflags, sizeof(csflags));
	bool isPlatformProcess = (csflags & CS_PLATFORM_BINARY) != 0;

	// Generate sandbox extensions for the requesting process
	*sandboxExtensionsOut = generate_sandbox_extensions(processToken, pid, procPath, isPlatformProcess);
	if(!(*sandboxExtensionsOut)) {
		JBLogError("Failed to generate sandbox extensions for process %d", pid);
	}

	bool fullyDebugged = false;
	if (isRemovableBundlePath(procPath) || isSubPathOf(procPath, JBROOT_PATH("/Applications"))) {
/*************************************** roothide specific *********************************/
		
		// This is an app, enable CS_DEBUGGED based on user preference
		if (jbsetting(markAppsAsDebugged)) {
			fullyDebugged = true;
		}
	}
	*fullyDebuggedOut = fullyDebugged;

	// Allow invalid pages
	cs_allow_invalid(proc, fullyDebugged);

	// Fix setuid
	struct stat sb;
	if (stat(procPath, &sb) == 0) {
		if (S_ISREG(sb.st_mode) && (sb.st_mode & (S_ISUID | S_ISGID))) {
			uint64_t ucred = proc_ucred(proc);
			if ((sb.st_mode & (S_ISUID))) {
				kwrite32(proc + koffsetof(proc, svuid), sb.st_uid);
				kwrite32(ucred + koffsetof(ucred, svuid), sb.st_uid);
				kwrite32(ucred + koffsetof(ucred, uid), sb.st_uid);
			}
			if ((sb.st_mode & (S_ISGID))) {
				kwrite32(proc + koffsetof(proc, svgid), sb.st_gid);
				kwrite32(ucred + koffsetof(ucred, svgid), sb.st_gid);
				kwrite32(ucred + koffsetof(ucred, groups), sb.st_gid);
			}
			uint32_t flag = kread32(proc + koffsetof(proc, flag));
			if ((flag & P_SUGID) != 0) {
				flag &= ~P_SUGID;
				kwrite32(proc + koffsetof(proc, flag), flag);
			}
		}
	}

	if (__builtin_available(iOS 16.0, *)) {
		// In iOS 16+ there is a super annoying security feature called Protobox
		// Amongst other things, it allows for a process to have a syscall mask
		// If a process calls a syscall it's not allowed to call, it immediately crashes
		// Because for tweaks and hooking this is unacceptable, we update these masks to be 1 for all syscalls on all processes
		// That will at least get rid of the syscall mask part of Protobox
		proc_allow_all_syscalls(proc);

		// Some processes also have a filter for mach messages, fortunately there is one allowed message id that can be used for the check-in
		// Then we remove the filter to make other message ids accessible afterwards aswell
		proc_remove_msg_filter(proc);
	}

	// For whatever reason after SpringBoard has restarted, AutoFill and other stuff stops working
	// The fix is to always also restart the kbd daemon alongside SpringBoard
	// Seems to be something sandbox related where kbd doesn't have the right extensions until restarted
	if (strcmp(procPath, "/System/Library/CoreServices/SpringBoard.app/SpringBoard") == 0) {
		static bool springboardStartedBefore = false;
		if (!springboardStartedBefore) {
			// Ignore the first SpringBoard launch after userspace reboot
			// This fix only matters when SpringBoard gets restarted during runtime
			springboardStartedBefore = true;
		}
		else {
			dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
				killall("/System/Library/TextInput/kbd", SIGKILL);
			});
		}
	}
	// For the Dopamine app itself we want to give it a saved uid/gid of 0, unsandbox it and give it CS_PLATFORM_BINARY
	// This is so that the buttons inside it can work when jailbroken, even if the app was not installed by TrollStore
	else if (isRemovableBundlePath(procPath) && string_has_suffix(procPath, "/Dopamine")) {
		// svuid = 0, svgid = 0
		uint64_t ucred = proc_ucred(proc);
		kwrite32(proc + koffsetof(proc, svuid), 0);
		kwrite32(ucred + koffsetof(ucred, svuid), 0);
		kwrite32(proc + koffsetof(proc, svgid), 0);
		kwrite32(ucred + koffsetof(ucred, svgid), 0);

		// platformize
		proc_csflags_set(proc, CS_PLATFORM_BINARY);

/********************* roothide specific ********************/
		proc_csflags_set(proc, CS_INSTALLER);
/*************************************************************/
	}

#ifdef __arm64e__
	// On arm64e every image has a trust level associated with it
	// "In trust cache" trust levels have higher runtime enforcements, this can be a problem for some tools as Dopamine trustcaches everything that's adhoc signed
	// So we add the ability for a binary to get a different trust level using the "jb.pmap_cs_custom_trust" entitlement
	// This is for binaries that rely on weaker PMAP_CS checks (e.g. Lua trampolines need it)
	xpc_object_t customTrustObj = xpc_copy_entitlement_for_token("jb.pmap_cs.custom_trust", processToken);
	if (customTrustObj) {
		if (xpc_get_type(customTrustObj) == XPC_TYPE_STRING) {
			const char *customTrustStr = xpc_string_get_string_ptr(customTrustObj);
			uint32_t customTrust = pmap_cs_trust_string_to_int(customTrustStr);
			if (customTrust >= 2) {
				uint64_t mainCodeDir = proc_find_main_binary_code_dir(proc);
				if (mainCodeDir) {
					kwrite32(mainCodeDir + koffsetof(pmap_cs_code_directory, trust), customTrust);
				}
			}
		}
	}
#endif

	proc_rele(proc);
	return 0;
}

int systemwide_fork_fix(audit_token_t *parentToken, uint64_t childPid)
{
	int retval = 3;
	uint64_t parentPid  = audit_token_to_pid(*parentToken);
	uint64_t parentProc = proc_find(parentPid);
	uint64_t childProc  = proc_find(childPid);

	if (childProc && parentProc) {
		retval = 2;
		// Safety check to ensure we are actually coming from fork
		if (kread_ptr(childProc + koffsetof(proc, pptr)) == parentProc) {
			cs_allow_invalid(childProc, false);

			uint64_t childTask  = proc_task(childProc);
			uint64_t childVmMap = kread_ptr(childTask + koffsetof(task, map));

			uint64_t parentTask  = proc_task(parentProc);
			uint64_t parentVmMap = kread_ptr(parentTask + koffsetof(task, map));

			uint64_t parentHeader   = parentVmMap + koffsetof(vm_map, hdr);
			uint32_t parentNentries = kread32(parentHeader + koffsetof(vm_map_header, nentries));
			uint64_t parentEntry    = kread_ptr(parentHeader + koffsetof(vm_map_header, first));

			uint64_t childHeader   = childVmMap + koffsetof(vm_map, hdr);
			uint32_t childNentries = kread32(childHeader + koffsetof(vm_map_header, nentries));
			uint64_t childEntry    = kread_ptr(childHeader + koffsetof(vm_map_header, first));

			uint64_t childFirstEntry = childEntry, parentFirstEntry = parentEntry;
			uint32_t childIdx = 0, parentIdx = 0;
			do {
				uint64_t childStart  = kread_ptr(childEntry  + koffsetof(vm_map_entry, start));
				uint64_t childEnd    = kread_ptr(childEntry  + koffsetof(vm_map_entry, end));
				uint64_t parentStart = kread_ptr(parentEntry + koffsetof(vm_map_entry, start));
				uint64_t parentEnd   = kread_ptr(parentEntry + koffsetof(vm_map_entry, end));

				if (parentStart < childStart) {
					parentEntry = kread_ptr(parentEntry + koffsetof(vm_map_entry, next));
					parentIdx++;
				}
				else if (parentStart > childStart) {
					childEntry = kread_ptr(childEntry + koffsetof(vm_map_entry, next));
					childIdx++;
				}
				else {
					uint64_t parentFlags = kread64(parentEntry + koffsetof(vm_map_entry, flags));
					uint64_t childFlags  = kread64(childEntry  + koffsetof(vm_map_entry, flags));

					uint8_t parentProt = VM_FLAGS_GET_PROT(parentFlags), parentMaxProt = VM_FLAGS_GET_MAXPROT(parentFlags);
					uint8_t childProt  = VM_FLAGS_GET_PROT(childFlags),  childMaxProt  = VM_FLAGS_GET_MAXPROT(childFlags);

					if (parentProt != childProt || parentMaxProt != childMaxProt) {
						VM_FLAGS_SET_PROT(childFlags, parentProt);
						VM_FLAGS_SET_MAXPROT(childFlags, parentMaxProt);
						kwrite64(childEntry + koffsetof(vm_map_entry, flags), childFlags);
					}

					parentEntry = kread_ptr(parentEntry + koffsetof(vm_map_entry, next));
					parentIdx++;
					childEntry  = kread_ptr(childEntry  + koffsetof(vm_map_entry, next));
					childIdx++;
				}
			} while (parentEntry != 0 && childEntry != 0 && parentEntry != parentFirstEntry && childEntry != childFirstEntry && parentIdx < parentNentries && childIdx < childNentries);
			retval = 0;
		}
	}
	if (childProc)  proc_rele(childProc);
	if (parentProc) proc_rele(parentProc);

	return retval;
}

static int systemwide_cs_revalidate(audit_token_t *callerToken)
{
	uint64_t callerPid = audit_token_to_pid(*callerToken);
	if (callerPid > 0) {
		uint64_t callerProc = proc_find(callerPid);
		if (callerProc) {
			proc_csflags_set(callerProc, CS_VALID);
			return 0;
		}
	}
	return -1;
}

struct jbserver_domain gSystemwideDomain = {
	.permissionHandler = roothide_domain_allowed,
	.actions = {
		// JBS_SYSTEMWIDE_GET_JBROOT
		{
			.handler = systemwide_get_jbroot,
			.args = (jbserver_arg[]){
				{ .name = "root-path", .type = JBS_TYPE_STRING, .out = true },
				{ 0 },
			},
		},
		// JBS_SYSTEMWIDE_GET_BOOT_UUID
		{
			.handler = systemwide_get_boot_uuid,
			.args = (jbserver_arg[]){
				{ .name = "boot-uuid", .type = JBS_TYPE_STRING, .out = true },
				{ 0 },
			},
		},
		// JBS_SYSTEMWIDE_TRUST_FILE
		{
			.handler = systemwide_trust_file,
			.args = (jbserver_arg[]){
				{ .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
				{ .name = "fd", .type = JBS_TYPE_UINT64, .out = false },
				{ .name = "siginfo", .type = JBS_TYPE_DATA, .out = false },
				{ 0 },
			},
		},
		// JBS_SYSTEMWIDE_PROCESS_CHECKIN
		{
			.handler = systemwide_process_checkin,
			.args = (jbserver_arg[]) {
				{ .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
				{ .name = "root-path", .type = JBS_TYPE_STRING, .out = true },
				{ .name = "boot-uuid", .type = JBS_TYPE_STRING, .out = true },
				{ .name = "sandbox-extensions", .type = JBS_TYPE_STRING, .out = true },
				{ .name = "fully-debugged", .type = JBS_TYPE_BOOL, .out = true },
				{ 0 },
			},
		},
		// JBS_SYSTEMWIDE_FORK_FIX
		{
			.handler = systemwide_fork_fix,
			.args = (jbserver_arg[]) {
				{ .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
				{ .name = "child-pid", .type = JBS_TYPE_UINT64, .out = false },
				{ 0 },
			},
		},
		// JBS_SYSTEMWIDE_CS_REVALIDATE
		{
			.handler = systemwide_cs_revalidate,
			.args = (jbserver_arg[]) {
				{ .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
				{ 0 },
			},
		},
		// JBS_SYSTEMWIDE_JBSETTINGS_GET
		{
			.handler = jbsettings_get,
			.args = (jbserver_arg[]){
				{ .name = "key", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "value", .type = JBS_TYPE_XPC_GENERIC, .out = true },
			},
		},
		{ 0 },
	},
};
