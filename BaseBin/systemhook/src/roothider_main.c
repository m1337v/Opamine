#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach/machine.h>
#include <libkern/OSByteOrder.h>
#include <stdatomic.h>

#include <litehook.h>

#include "rhi_rebind.h"

#include "common.h"
#include "envbuf.h"
#include "hider_caller_policy.h"
#include "hider_internal.h"
#include "sandbox.h"
#include "roothider.h"

const char* HOOK_DYLIB_PATH = NULL;

bool dyld_patch_fallback_enabled = false;
/*
 * This flag is read by hidden_dylib_hider.c from dlsym paths that may run
 * concurrently with selected-tweak initialization or a late-image failure.
 * Keep the advertisement publication atomic and release it only after the
 * transaction pointer and predecessor have been published.
 */
atomic_bool dlopen_fallback_hook_installed = false;
static bool gHiddenTweakAllowMode = true;
static size_t gHiddenTweakNameCount = 0;
static char **gHiddenTweakNames = NULL;
static atomic_bool gHiddenTweakHooksInstalled = false;
static atomic_int gHiddenTweakHookState = RHI_HOOK_NOT_ATTEMPTED;
static _Atomic(rhi_rebind_transaction_t *) gHiddenTweakFallbackTransaction = NULL;
static char *gHiddenTweakModeString = NULL;
static char *gHiddenTweakListString = NULL;
static bool gHiddenTweakEnvironmentConsumed = false;

typedef struct {
	char *path;
	void *handle;
} HiddenTweakLoadedLibrary;

static HiddenTweakLoadState gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_NOT_ATTEMPTED;
static bool gHiddenTweakAnyDlopenSucceeded = false;
static HiddenTweakLoadedLibrary *gHiddenTweakLoadedLibraries = NULL;
static size_t gHiddenTweakLoadedLibraryCount = 0;
static size_t *gHiddenTweakLoadPlan = NULL;
static size_t gHiddenTweakLoadPlanCount = 0;


typedef struct {
	char *name;
	bool hard;
} HiddenTweakDependency;

typedef struct {
	char *path;
	char *name;
	size_t dependencyCount;
	HiddenTweakDependency *dependencies;
	HiddenTweakLoadState state;
	bool nameAmbiguous;
	bool dependencyMetadataValid;
} HiddenTweakBinary;

static HiddenTweakBinary *gHiddenTweakBinaries = NULL;
static size_t gHiddenTweakBinaryCount = 0;

static bool hidden_tweak_binary_should_load(const HiddenTweakBinary *binary);

static const char *hidden_tweak_load_state_name(HiddenTweakLoadState state)
{
	switch (state) {
		case HIDDEN_TWEAK_LOAD_NOT_ATTEMPTED: return "not-attempted";
		case HIDDEN_TWEAK_LOAD_PREPARED: return "prepared";
		case HIDDEN_TWEAK_LOAD_ACTIVE: return "active";
		case HIDDEN_TWEAK_LOAD_FAILED: return "failed";
		case HIDDEN_TWEAK_LOAD_PARTIAL: return "partial";
		case HIDDEN_TWEAK_LOAD_UNKNOWN: return "unknown";
	}
	return "invalid";
}

static void clear_hidden_tweak_binaries(void)
{
	if (!gHiddenTweakBinaries) {
		gHiddenTweakBinaryCount = 0;
		return;
	}

	for (size_t i = 0; i < gHiddenTweakBinaryCount; i++) {
		free(gHiddenTweakBinaries[i].path);
		free(gHiddenTweakBinaries[i].name);
		for (size_t j = 0; j < gHiddenTweakBinaries[i].dependencyCount; j++) {
			free(gHiddenTweakBinaries[i].dependencies[j].name);
		}
		free(gHiddenTweakBinaries[i].dependencies);
	}
	free(gHiddenTweakBinaries);
	gHiddenTweakBinaries = NULL;
	gHiddenTweakBinaryCount = 0;
	free(gHiddenTweakLoadPlan);
	gHiddenTweakLoadPlan = NULL;
	gHiddenTweakLoadPlanCount = 0;
}

static void clear_hidden_tweak_filter(void)
{
	free(gHiddenTweakModeString);
	gHiddenTweakModeString = NULL;
	free(gHiddenTweakListString);
	gHiddenTweakListString = NULL;
	clear_hidden_tweak_binaries();
	for (size_t i = 0; i < gHiddenTweakLoadedLibraryCount; i++) {
		free(gHiddenTweakLoadedLibraries[i].path);
	}
	free(gHiddenTweakLoadedLibraries);
	gHiddenTweakLoadedLibraries = NULL;
	gHiddenTweakLoadedLibraryCount = 0;
	gHiddenTweakAnyDlopenSucceeded = false;
	gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_NOT_ATTEMPTED;

	if (!gHiddenTweakNames) {
		gHiddenTweakNameCount = 0;
		return;
	}

	for (size_t i = 0; i < gHiddenTweakNameCount; i++) {
		free(gHiddenTweakNames[i]);
	}
	free(gHiddenTweakNames);
	gHiddenTweakNames = NULL;
	gHiddenTweakNameCount = 0;
}

static bool hidden_tweak_filter_contains_name(const char *tweakName);

static bool hidden_tweak_filter_add_name(const char *tweakName)
{
	if (!tweakName || tweakName[0] == '\0' || hidden_tweak_filter_contains_name(tweakName)) {
		return false;
	}

	if (gHiddenTweakNameCount == SIZE_MAX / sizeof(char *)) {
		return false;
	}
	char *nameCopy = strdup(tweakName);
	if (!nameCopy) {
		return false;
	}
	char **newNames = realloc(gHiddenTweakNames, sizeof(char *) * (gHiddenTweakNameCount + 1));
	if (!newNames) {
		free(nameCopy);
		return false;
	}

	gHiddenTweakNames = newNames;
	gHiddenTweakNames[gHiddenTweakNameCount++] = nameCopy;
	return true;
}

static bool hidden_tweak_dependency_name_from_load_path(const char *loadPath, char outName[PATH_MAX])
{
	if (!loadPath || !outName) {
		return false;
	}

	const char *baseName = strrchr(loadPath, '/');
	baseName = baseName ? baseName + 1 : loadPath;
	if (baseName[0] == '\0') {
		return false;
	}

	strlcpy(outName, baseName, PATH_MAX);
	char *extension = strrchr(outName, '.');
	if (extension && !strcmp(extension, ".dylib")) {
		*extension = '\0';
	}

	return outName[0] != '\0';
}

static HiddenTweakDependency *hidden_tweak_dependency_for_name(HiddenTweakDependency dependencies[], size_t dependencyCount, const char *name)
{
	if (!dependencies || !name) {
		return NULL;
	}
	for (size_t i = 0; i < dependencyCount; i++) {
		if (!strcmp(dependencies[i].name, name)) {
			return &dependencies[i];
		}
	}
	return NULL;
}

static bool hidden_tweak_dependency_add_name(HiddenTweakDependency **dependencies, size_t *dependencyCount, const char *name, bool hard)
{
	if (!dependencies || !dependencyCount || !name || name[0] == '\0') {
		return false;
	}

	HiddenTweakDependency *existingDependency = hidden_tweak_dependency_for_name(*dependencies, *dependencyCount, name);
	if (existingDependency) {
		// If different load commands mention the same library, retain the
		// stronger constraint. A hard edge must never be weakened by a later
		// LC_LOAD_WEAK_DYLIB command.
		existingDependency->hard |= hard;
		return true;
	}

	if (*dependencyCount == SIZE_MAX / sizeof(HiddenTweakDependency)) {
		return false;
	}
	char *nameCopy = strdup(name);
	if (!nameCopy) {
		return false;
	}
	HiddenTweakDependency *newDependencies = realloc(*dependencies, sizeof(HiddenTweakDependency) * (*dependencyCount + 1));
	if (!newDependencies) {
		free(nameCopy);
		return false;
	}

	*dependencies = newDependencies;
	(*dependencies)[*dependencyCount] = (HiddenTweakDependency){
		.name = nameCopy,
		.hard = hard,
	};
	(*dependencyCount)++;
	return true;
}

static bool hidden_tweak_file_size(FILE *file, uint64_t *sizeOut)
{
	if (!file || !sizeOut) {
		return false;
	}
	if (fseeko(file, 0, SEEK_END) != 0) {
		return false;
	}
	off_t end = ftello(file);
	if (end < 0) {
		return false;
	}
	*sizeOut = (uint64_t)end;
	return true;
}

static bool hidden_tweak_read_at_offset(FILE *file, uint64_t fileSize, uint64_t offset, void *buffer, size_t size)
{
	if (!file || !buffer || size == 0 || offset > fileSize || size > fileSize - offset || offset > INT64_MAX) {
		return false;
	}
	if (fseeko(file, (off_t)offset, SEEK_SET) != 0) {
		return false;
	}
	return fread(buffer, 1, size, file) == size;
}

static bool hidden_tweak_slice_matches_executing_arch(cpu_type_t cputype, cpu_subtype_t cpusubtype)
{
	if (cputype != CPU_TYPE_ARM64) {
		return false;
	}
	uint32_t subtype = ((uint32_t)cpusubtype) & ~CPU_SUBTYPE_MASK;
#if defined(__arm64e__)
	return subtype == CPU_SUBTYPE_ARM64E;
#else
	return subtype == CPU_SUBTYPE_ARM64_ALL;
#endif
}

static bool hidden_tweak_collect_dependencies_for_slice(FILE *file, uint64_t fileSize, uint64_t sliceOffset, uint64_t sliceSize, HiddenTweakDependency **dependencies, size_t *dependencyCount)
{
	if (!file || !dependencies || !dependencyCount || sliceOffset > fileSize || sliceSize > fileSize - sliceOffset || sliceSize < sizeof(struct mach_header)) {
		return false;
	}

	struct mach_header header = {0};
	if (!hidden_tweak_read_at_offset(file, fileSize, sliceOffset, &header, sizeof(header))) {
		return false;
	}

	uint32_t magic = header.magic;
	bool is64 = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
	bool shouldSwap = (magic == MH_CIGAM || magic == MH_CIGAM_64);
	if (!(magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64)) {
		return false;
	}

	uint32_t ncmds = shouldSwap ? OSSwapInt32(header.ncmds) : header.ncmds;
	uint32_t sizeofcmds = shouldSwap ? OSSwapInt32(header.sizeofcmds) : header.sizeofcmds;
	cpu_type_t cputype = shouldSwap ? (cpu_type_t)OSSwapInt32((uint32_t)header.cputype) : header.cputype;
	cpu_subtype_t cpusubtype = shouldSwap ? (cpu_subtype_t)OSSwapInt32((uint32_t)header.cpusubtype) : header.cpusubtype;
	if (!hidden_tweak_slice_matches_executing_arch(cputype, cpusubtype)) {
		return false;
	}

	size_t headerSize = is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
	if (headerSize > sliceSize || sizeofcmds > sliceSize - headerSize || ncmds > sizeofcmds / sizeof(struct load_command)) {
		return false;
	}
	uint64_t cursor = sliceOffset + headerSize;
	uint64_t commandsEnd = cursor + sizeofcmds;
	for (uint32_t i = 0; i < ncmds; i++) {
		struct load_command loadCommand = {0};
		if (cursor > commandsEnd || sizeof(loadCommand) > commandsEnd - cursor || !hidden_tweak_read_at_offset(file, fileSize, cursor, &loadCommand, sizeof(loadCommand))) {
			return false;
		}

		uint32_t command = shouldSwap ? OSSwapInt32(loadCommand.cmd) : loadCommand.cmd;
		uint32_t commandSize = shouldSwap ? OSSwapInt32(loadCommand.cmdsize) : loadCommand.cmdsize;
		if (commandSize < sizeof(struct load_command) || commandSize > commandsEnd - cursor) {
			return false;
		}

		if (command == LC_LOAD_DYLIB || command == LC_LOAD_WEAK_DYLIB || command == LC_REEXPORT_DYLIB || command == LC_LOAD_UPWARD_DYLIB || command == LC_LAZY_LOAD_DYLIB) {
			struct dylib_command dylibCommand = {0};
			if (commandSize < sizeof(dylibCommand) || !hidden_tweak_read_at_offset(file, fileSize, cursor, &dylibCommand, sizeof(dylibCommand))) {
				return false;
			}
			uint32_t nameOffset = shouldSwap ? OSSwapInt32(dylibCommand.dylib.name.offset) : dylibCommand.dylib.name.offset;
			if (nameOffset < sizeof(struct dylib_command) || nameOffset >= commandSize) {
				return false;
			}
			size_t nameLength = commandSize - nameOffset;
			char *nameBuffer = calloc(1, nameLength + 1);
			if (!nameBuffer || !hidden_tweak_read_at_offset(file, fileSize, cursor + nameOffset, nameBuffer, nameLength)) {
				free(nameBuffer);
				return false;
			}
			char dependencyName[PATH_MAX] = {0};
			bool hard = command != LC_LOAD_WEAK_DYLIB && command != LC_LAZY_LOAD_DYLIB;
			if (hidden_tweak_dependency_name_from_load_path(nameBuffer, dependencyName)
				&& !hidden_tweak_dependency_add_name(dependencies, dependencyCount, dependencyName, hard)) {
				free(nameBuffer);
				return false;
			}
			free(nameBuffer);
		}
		cursor += commandSize;
	}

	return true;
}

static bool hidden_tweak_collect_dependencies_for_binary(const char *path, HiddenTweakDependency **dependencies, size_t *dependencyCount)
{
	if (!path || !dependencies || !dependencyCount) {
		return false;
	}

	FILE *file = fopen(path, "rb");
	if (!file) {
		return false;
	}

	uint64_t fileSize = 0;
	uint32_t magic = 0;
	if (!hidden_tweak_file_size(file, &fileSize) || !hidden_tweak_read_at_offset(file, fileSize, 0, &magic, sizeof(magic))) {
		fclose(file);
		return false;
	}
	bool collected = false;

	if (magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
		bool shouldSwap = (magic == FAT_CIGAM || magic == FAT_CIGAM_64);
		bool is64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
		if (is64) {
			struct fat_header fatHeader = {0};
			if (hidden_tweak_read_at_offset(file, fileSize, 0, &fatHeader, sizeof(fatHeader))) {
				uint32_t nfatArch = shouldSwap ? OSSwapBigToHostInt32(fatHeader.nfat_arch) : fatHeader.nfat_arch;
				if (nfatArch > (fileSize - sizeof(fatHeader)) / sizeof(struct fat_arch_64)) {
					fclose(file);
					return false;
				}
				for (uint32_t i = 0; i < nfatArch; i++) {
					struct fat_arch_64 fatArch = {0};
					uint64_t archOffset = sizeof(struct fat_header) + (sizeof(struct fat_arch_64) * i);
					if (!hidden_tweak_read_at_offset(file, fileSize, archOffset, &fatArch, sizeof(fatArch))) {
						fclose(file);
						return false;
					}
					uint64_t sliceOffset = shouldSwap ? OSSwapBigToHostInt64(fatArch.offset) : fatArch.offset;
					uint64_t sliceSize = shouldSwap ? OSSwapBigToHostInt64(fatArch.size) : fatArch.size;
					cpu_type_t cputype = shouldSwap ? (cpu_type_t)OSSwapBigToHostInt32((uint32_t)fatArch.cputype) : fatArch.cputype;
					cpu_subtype_t cpusubtype = shouldSwap ? (cpu_subtype_t)OSSwapBigToHostInt32((uint32_t)fatArch.cpusubtype) : fatArch.cpusubtype;
					if (!hidden_tweak_slice_matches_executing_arch(cputype, cpusubtype)) {
						continue;
					}
					if (hidden_tweak_collect_dependencies_for_slice(file, fileSize, sliceOffset, sliceSize, dependencies, dependencyCount)) {
						collected = true;
						break;
					}
				}
			}
		}
		else {
			struct fat_header fatHeader = {0};
			if (hidden_tweak_read_at_offset(file, fileSize, 0, &fatHeader, sizeof(fatHeader))) {
				uint32_t nfatArch = shouldSwap ? OSSwapBigToHostInt32(fatHeader.nfat_arch) : fatHeader.nfat_arch;
				if (nfatArch > (fileSize - sizeof(fatHeader)) / sizeof(struct fat_arch)) {
					fclose(file);
					return false;
				}
				for (uint32_t i = 0; i < nfatArch; i++) {
					struct fat_arch fatArch = {0};
					uint64_t archOffset = sizeof(struct fat_header) + (sizeof(struct fat_arch) * i);
					if (!hidden_tweak_read_at_offset(file, fileSize, archOffset, &fatArch, sizeof(fatArch))) {
						fclose(file);
						return false;
					}
					uint32_t sliceOffset = shouldSwap ? OSSwapBigToHostInt32(fatArch.offset) : fatArch.offset;
					uint32_t sliceSize = shouldSwap ? OSSwapBigToHostInt32(fatArch.size) : fatArch.size;
					cpu_type_t cputype = shouldSwap ? (cpu_type_t)OSSwapBigToHostInt32((uint32_t)fatArch.cputype) : fatArch.cputype;
					cpu_subtype_t cpusubtype = shouldSwap ? (cpu_subtype_t)OSSwapBigToHostInt32((uint32_t)fatArch.cpusubtype) : fatArch.cpusubtype;
					if (!hidden_tweak_slice_matches_executing_arch(cputype, cpusubtype)) {
						continue;
					}
					if (hidden_tweak_collect_dependencies_for_slice(file, fileSize, sliceOffset, sliceSize, dependencies, dependencyCount)) {
						collected = true;
						break;
					}
				}
			}
		}
	}
	else {
		collected = hidden_tweak_collect_dependencies_for_slice(file, fileSize, 0, fileSize, dependencies, dependencyCount);
	}

	fclose(file);
	return collected;
}

static void hidden_tweak_index_register_binary(const char *path)
{
	if (!path || path[0] == '\0') {
		return;
	}

	char pathCopy[PATH_MAX];
	strlcpy(pathCopy, path, sizeof(pathCopy));
	char *baseName = basename(pathCopy);
	if (!baseName || baseName[0] == '\0') {
		return;
	}

	char tweakName[PATH_MAX];
	strlcpy(tweakName, baseName, sizeof(tweakName));
	char *extension = strrchr(tweakName, '.');
	if (!extension || strcmp(extension, ".dylib") != 0) {
		return;
	}
	*extension = '\0';

	for (size_t i = 0; i < gHiddenTweakBinaryCount; i++) {
		if (!strcmp(gHiddenTweakBinaries[i].name, tweakName)) {
			gHiddenTweakBinaries[i].nameAmbiguous = true;
			root_hide_hidden_whitelist_log("hidden binary index duplicate name=%s path=%s existing=%s", tweakName, path, gHiddenTweakBinaries[i].path ?: "(null)");
			return;
		}
	}

	if (gHiddenTweakBinaryCount == SIZE_MAX / sizeof(HiddenTweakBinary)) {
		return;
	}
	char *pathCopyForBinary = strdup(path);
	char *nameCopyForBinary = strdup(tweakName);
	if (!pathCopyForBinary || !nameCopyForBinary) {
		free(pathCopyForBinary);
		free(nameCopyForBinary);
		return;
	}
	HiddenTweakBinary *newBinaries = realloc(gHiddenTweakBinaries, sizeof(HiddenTweakBinary) * (gHiddenTweakBinaryCount + 1));
	if (!newBinaries) {
		free(pathCopyForBinary);
		free(nameCopyForBinary);
		return;
	}
	gHiddenTweakBinaries = newBinaries;

	HiddenTweakBinary *binary = &gHiddenTweakBinaries[gHiddenTweakBinaryCount++];
	memset(binary, 0, sizeof(*binary));
	binary->path = pathCopyForBinary;
	binary->name = nameCopyForBinary;
	binary->dependencyMetadataValid = hidden_tweak_collect_dependencies_for_binary(path, &binary->dependencies, &binary->dependencyCount);
}

static void hidden_tweak_build_binary_index(void)
{
	clear_hidden_tweak_binaries();

	const char *directories[] = {
		JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries"),
		JBROOT_PATH("/usr/lib/TweakInject"),
	};

	for (size_t i = 0; i < sizeof(directories) / sizeof(directories[0]); i++) {
		const char *directoryPath = directories[i];
		if (!directoryPath || directoryPath[0] == '\0') {
			continue;
		}

		DIR *directory = opendir(directoryPath);
		if (!directory) {
			continue;
		}

		struct dirent *entry = NULL;
		while ((entry = readdir(directory)) != NULL) {
			if (entry->d_name[0] == '.') {
				continue;
			}
			const char *extension = strrchr(entry->d_name, '.');
			if (!extension || strcmp(extension, ".dylib") != 0) {
				continue;
			}

			char fullPath[PATH_MAX];
			int pathLength = snprintf(fullPath, sizeof(fullPath), "%s/%s", directoryPath, entry->d_name);
			if (pathLength < 0 || (size_t)pathLength >= sizeof(fullPath)) {
				root_hide_hidden_whitelist_log("hidden binary index path too long directory=%s entry=%s", directoryPath, entry->d_name);
				continue;
			}
			hidden_tweak_index_register_binary(fullPath);
		}
		closedir(directory);
	}
}

static HiddenTweakBinary *hidden_tweak_binary_for_name(const char *name)
{
	if (!name || name[0] == '\0') {
		return NULL;
	}

	for (size_t i = 0; i < gHiddenTweakBinaryCount; i++) {
		if (!strcmp(gHiddenTweakBinaries[i].name, name)) {
			return &gHiddenTweakBinaries[i];
		}
	}
	return NULL;
}

static bool hidden_tweak_loaded_library_contains_path(const char *path)
{
	if (!path) {
		return false;
	}
	for (size_t i = 0; i < gHiddenTweakLoadedLibraryCount; i++) {
		if (!strcmp(gHiddenTweakLoadedLibraries[i].path, path)) {
			return true;
		}
	}
	return false;
}

static bool hidden_tweak_store_loaded_library(const char *path, void *handle)
{
	if (!path || !handle) {
		return false;
	}
	if (hidden_tweak_loaded_library_contains_path(path)) {
		return true;
	}
	if (gHiddenTweakLoadedLibraryCount == SIZE_MAX / sizeof(HiddenTweakLoadedLibrary)) {
		return false;
	}
	char *pathCopy = strdup(path);
	if (!pathCopy) {
		return false;
	}

	HiddenTweakLoadedLibrary *newLibraries = realloc(gHiddenTweakLoadedLibraries, sizeof(HiddenTweakLoadedLibrary) * (gHiddenTweakLoadedLibraryCount + 1));
	if (!newLibraries) {
		free(pathCopy);
		return false;
	}

	gHiddenTweakLoadedLibraries = newLibraries;
	gHiddenTweakLoadedLibraries[gHiddenTweakLoadedLibraryCount++] = (HiddenTweakLoadedLibrary){
		.path = pathCopy,
		.handle = handle,
	};
	return true;
}

static bool hidden_tweak_preflight_support_library(const char *libraryPath)
{
	if (!libraryPath || libraryPath[0] == '\0') {
		return false;
	}

	if (access(libraryPath, R_OK) != 0) {
		root_hide_hidden_whitelist_log("support library preflight failed path=%s", libraryPath);
		return false;
	}
	return true;
}

static bool hidden_tweak_load_support_library(const char *libraryPath)
{
	if (!hidden_tweak_preflight_support_library(libraryPath)) {
		return false;
	}
	if (hidden_tweak_loaded_library_contains_path(libraryPath)) {
		return true;
	}

	jbclient_trust_library_recurse(libraryPath, NULL);
	root_hide_hidden_whitelist_log("support library dlopen attempt path=%s", libraryPath);
	void *handle = dlopen(libraryPath, RTLD_NOW | RTLD_GLOBAL);
	if (!handle) {
		root_hide_hidden_whitelist_log("support library dlopen failed path=%s error=%s", libraryPath, dlerror() ?: "(null)");
		gHiddenTweakLoadState = gHiddenTweakAnyDlopenSucceeded ? HIDDEN_TWEAK_LOAD_PARTIAL : HIDDEN_TWEAK_LOAD_FAILED;
		return false;
	}

	gHiddenTweakAnyDlopenSucceeded = true;
	if (!hidden_tweak_store_loaded_library(libraryPath, handle)) {
		// dlopen has already run constructors.  We deliberately retain the handle
		// and stop rather than retrying an untracked mutation.
		gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_PARTIAL;
		root_hide_hidden_whitelist_log("support library handle record failed path=%s", libraryPath);
		return false;
	}

	root_hide_hidden_whitelist_log("support library dlopen success path=%s handle=%p", libraryPath, handle);
	return true;
}

static bool hidden_tweak_selected_binary_depends_on_name(const char *dependencyName)
{
	if (!dependencyName || dependencyName[0] == '\0') {
		return false;
	}

	for (size_t i = 0; i < gHiddenTweakBinaryCount; i++) {
		HiddenTweakBinary *binary = &gHiddenTweakBinaries[i];
		if (binary->state != HIDDEN_TWEAK_LOAD_PREPARED && binary->state != HIDDEN_TWEAK_LOAD_ACTIVE) {
			continue;
		}

		for (size_t j = 0; j < binary->dependencyCount; j++) {
			if (binary->dependencies[j].hard && !strcmp(binary->dependencies[j].name, dependencyName)) {
				return true;
			}
		}
	}

	return false;
}

static bool hidden_tweak_selected_binary_has_patch_companion(void)
{
	for (size_t i = 0; i < gHiddenTweakBinaryCount; i++) {
		HiddenTweakBinary *binary = &gHiddenTweakBinaries[i];
		if ((binary->state != HIDDEN_TWEAK_LOAD_PREPARED && binary->state != HIDDEN_TWEAK_LOAD_ACTIVE) || !binary->path) {
			continue;
		}

		char patcherPath[PATH_MAX];
		snprintf(patcherPath, sizeof(patcherPath), "%s.roothidepatch", binary->path);
		if (lstat(patcherPath, &(struct stat){0}) == 0) {
			return true;
		}
	}

	return false;
}

static bool hidden_tweak_append_support_library(const char **libraries, size_t *libraryCount, size_t libraryCapacity, const char *libraryPath)
{
	if (!libraries || !libraryCount || !libraryPath || libraryPath[0] == '\0') {
		return false;
	}
	for (size_t i = 0; i < *libraryCount; i++) {
		if (!strcmp(libraries[i], libraryPath)) {
			return true;
		}
	}
	if (*libraryCount >= libraryCapacity) {
		return false;
	}
	libraries[(*libraryCount)++] = libraryPath;
	return true;
}

static bool hidden_tweak_load_runtime_support_libraries(bool minimalRuntime)
{
	const char *supportLibraries[5] = {0};
	size_t supportLibraryCount = 0;

	if (!minimalRuntime) {
		if (!hidden_tweak_append_support_library(supportLibraries, &supportLibraryCount, sizeof(supportLibraries) / sizeof(*supportLibraries), JBROOT_PATH("/usr/lib/libroothide.dylib"))
			|| !hidden_tweak_append_support_library(supportLibraries, &supportLibraryCount, sizeof(supportLibraries) / sizeof(*supportLibraries), JBROOT_PATH("/usr/lib/libellekit.dylib"))) {
			gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_FAILED;
			return false;
		}
	}
	else {
		// Lower-footprint runtime for Blacklist + Allowlist: keep ElleKit for
		// broad hook compatibility, then add only declared compatibility layers.
		if (!hidden_tweak_append_support_library(supportLibraries, &supportLibraryCount, sizeof(supportLibraries) / sizeof(*supportLibraries), JBROOT_PATH("/usr/lib/libellekit.dylib"))) {
			gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_FAILED;
			return false;
		}
		if (hidden_tweak_selected_binary_depends_on_name("libroothide")) {
			hidden_tweak_append_support_library(supportLibraries, &supportLibraryCount, sizeof(supportLibraries) / sizeof(*supportLibraries), JBROOT_PATH("/usr/lib/libroothide.dylib"));
		}
		if (hidden_tweak_selected_binary_depends_on_name("libroot")) {
			hidden_tweak_append_support_library(supportLibraries, &supportLibraryCount, sizeof(supportLibraries) / sizeof(*supportLibraries), JBROOT_PATH("/usr/lib/libroot.dylib"));
		}
		if (hidden_tweak_selected_binary_depends_on_name("libsandy")) {
			hidden_tweak_append_support_library(supportLibraries, &supportLibraryCount, sizeof(supportLibraries) / sizeof(*supportLibraries), JBROOT_PATH("/usr/lib/libsandy.dylib"));
		}
		if (hidden_tweak_selected_binary_has_patch_companion()) {
			hidden_tweak_append_support_library(supportLibraries, &supportLibraryCount, sizeof(supportLibraries) / sizeof(*supportLibraries), JBROOT_PATH("/usr/lib/roothidepatch.dylib"));
		}
	}

	// Validate the complete support set before the first support-library dlopen.
	for (size_t i = 0; i < supportLibraryCount; i++) {
		if (!hidden_tweak_preflight_support_library(supportLibraries[i])) {
			gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_FAILED;
			return false;
		}
	}
	for (size_t i = 0; i < supportLibraryCount; i++) {
		if (!hidden_tweak_load_support_library(supportLibraries[i])) {
			return false;
		}
	}
	return true;
}

static void hidden_tweak_expand_with_companions(void)
{
	if (gHiddenTweakNameCount == 0) {
		return;
	}

	hidden_tweak_build_binary_index();
	if (gHiddenTweakBinaryCount == 0) {
		return;
	}

	bool changed = false;
	do {
		changed = false;
		for (size_t i = 0; i < gHiddenTweakBinaryCount; i++) {
			HiddenTweakBinary *binary = &gHiddenTweakBinaries[i];
			bool binaryAllowed = hidden_tweak_filter_contains_name(binary->name);
			bool dependencyAllowed = false;

			for (size_t j = 0; j < binary->dependencyCount; j++) {
				const char *dependencyName = binary->dependencies[j].name;
				if (!hidden_tweak_binary_for_name(dependencyName)) {
					continue;
				}

				if (binaryAllowed) {
					changed |= hidden_tweak_filter_add_name(dependencyName);
				}
				if (hidden_tweak_filter_contains_name(dependencyName)) {
					dependencyAllowed = true;
				}
			}

			if (dependencyAllowed) {
				changed |= hidden_tweak_filter_add_name(binary->name);
			}
		}
	} while (changed);
}

void roothide_hidden_tweak_consume_environment(void)
{
	if (gHiddenTweakEnvironmentConsumed) {
		return;
	}
	gHiddenTweakEnvironmentConsumed = true;
	clear_hidden_tweak_filter();
	gHiddenTweakAllowMode = true;

	const char *mode = getenv("ROOTHIDE_HIDDEN_TWEAK_MODE");
	if (mode && !strcmp(mode, "deny")) {
		gHiddenTweakAllowMode = false;
	}
	if (mode && mode[0] != '\0') {
		gHiddenTweakModeString = strdup(mode);
		if (!gHiddenTweakModeString) {
			root_hide_hidden_whitelist_log("hidden filter failed to copy mode");
			unsetenv("ROOTHIDE_HIDDEN_TWEAK_MODE");
			unsetenv("ROOTHIDE_HIDDEN_TWEAK_LIST");
			return;
		}
	}

	const char *list = getenv("ROOTHIDE_HIDDEN_TWEAK_LIST");
	if (!list || list[0] == '\0') {
		root_hide_hidden_whitelist_log("hidden filter not configured");
		unsetenv("ROOTHIDE_HIDDEN_TWEAK_MODE");
		unsetenv("ROOTHIDE_HIDDEN_TWEAK_LIST");
		return;
	}
	gHiddenTweakListString = strdup(list);
	if (!gHiddenTweakListString) {
		root_hide_hidden_whitelist_log("hidden filter failed to copy list");
		clear_hidden_tweak_filter();
		unsetenv("ROOTHIDE_HIDDEN_TWEAK_MODE");
		unsetenv("ROOTHIDE_HIDDEN_TWEAK_LIST");
		return;
	}

	char *listCopy = strdup(list);
	if (!listCopy) {
		root_hide_hidden_whitelist_log("hidden filter failed to allocate parser");
		clear_hidden_tweak_filter();
		unsetenv("ROOTHIDE_HIDDEN_TWEAK_MODE");
		unsetenv("ROOTHIDE_HIDDEN_TWEAK_LIST");
		return;
	}
	char *cursor = listCopy;
	char *token = NULL;
	while ((token = strsep(&cursor, ":")) != NULL) {
		if (token[0] == '\0') {
			continue;
		}
		if (!hidden_tweak_filter_contains_name(token) && !hidden_tweak_filter_add_name(token)) {
			root_hide_hidden_whitelist_log("hidden filter failed to retain selected tweak=%s", token);
			free(listCopy);
			clear_hidden_tweak_filter();
			unsetenv("ROOTHIDE_HIDDEN_TWEAK_MODE");
			unsetenv("ROOTHIDE_HIDDEN_TWEAK_LIST");
			return;
		}
	}
	free(listCopy);
	// Keep the hidden tweak list explicit for now. The UI shows all tweak dylibs,
	// so automatic companion expansion would make app-side testing ambiguous.
	// hidden_tweak_expand_with_companions();
	root_hide_hidden_whitelist_log("hidden filter mode=%s list=%s count=%zu", gHiddenTweakAllowMode ? "allow" : "deny", gHiddenTweakListString ?: "(null)", gHiddenTweakNameCount);

	unsetenv("ROOTHIDE_HIDDEN_TWEAK_MODE");
	unsetenv("ROOTHIDE_HIDDEN_TWEAK_LIST");
}

bool roothide_hidden_tweak_env_is_configured(void)
{
	return gHiddenTweakListString && gHiddenTweakListString[0] != '\0';
}

bool roothide_hidden_tweak_envbuf_apply(char ***envc)
{
	if (!envc || !*envc || !roothide_hidden_tweak_env_is_configured()) {
		return false;
	}

	return envbuf_setenv(envc, "ROOTHIDE_HIDDEN_INJECTION", "1")
		&& envbuf_setenv(envc, "ROOTHIDE_ENABLE_HIDDEN_TWEAKS", "1")
		&& envbuf_setenv(envc, "ROOTHIDE_HIDDEN_TWEAK_MODE", gHiddenTweakModeString ? gHiddenTweakModeString : "allow")
		&& envbuf_setenv(envc, "ROOTHIDE_HIDDEN_TWEAK_LIST", gHiddenTweakListString)
		&& hidden_dylib_hider_envbuf_apply(envc);
}

static bool hidden_tweak_filter_contains_name(const char *tweakName)
{
	if (!tweakName || tweakName[0] == '\0') {
		return false;
	}

	for (size_t i = 0; i < gHiddenTweakNameCount; i++) {
		if (!strcmp(gHiddenTweakNames[i], tweakName)) {
			return true;
		}
	}
	return false;
}

static bool hidden_tweak_filter_applies_to_path(const char *path)
{
	if (!path || gHiddenTweakNameCount == 0) {
		return false;
	}

	if (!string_has_suffix(path, ".dylib")) {
		return false;
	}

	const char *substrateDir = JBROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/");
	const char *tweakInjectDir = JBROOT_PATH("/usr/lib/TweakInject/");
	if ((substrateDir && string_has_prefix(path, substrateDir))
		|| (tweakInjectDir && string_has_prefix(path, tweakInjectDir))
		|| strstr(path, "/Library/MobileSubstrate/DynamicLibraries/")
		|| strstr(path, "/usr/lib/TweakInject/")) {
		return true;
	}

	return false;
}

bool hidden_tweak_filter_should_block_path(const char *path)
{
	if (!hidden_tweak_filter_applies_to_path(path)) {
		return false;
	}

	char pathBuffer[PATH_MAX];
	strlcpy(pathBuffer, path, sizeof(pathBuffer));
	char *baseName = basename(pathBuffer);
	if (!baseName) {
		return false;
	}

	char tweakName[PATH_MAX];
	strlcpy(tweakName, baseName, sizeof(tweakName));
	char *extension = strrchr(tweakName, '.');
	if (extension) {
		*extension = '\0';
	}

	bool listed = hidden_tweak_filter_contains_name(tweakName);
	return gHiddenTweakAllowMode ? !listed : listed;
}

static bool hidden_tweak_binary_should_load(const HiddenTweakBinary *binary)
{
	if (!binary || !binary->path || binary->path[0] == '\0') {
		return false;
	}

	return !hidden_tweak_filter_should_block_path(binary->path);
}

static bool hidden_tweak_binary_index_for_name(const char *name, size_t *indexOut)
{
	if (!name || !indexOut) {
		return false;
	}
	for (size_t i = 0; i < gHiddenTweakBinaryCount; i++) {
		if (!strcmp(gHiddenTweakBinaries[i].name, name)) {
			*indexOut = i;
			return true;
		}
	}
	return false;
}

static bool hidden_tweak_binary_preflight(const HiddenTweakBinary *binary)
{
	struct stat st = {0};
	if (!binary || !binary->path || binary->path[0] == '\0' || binary->nameAmbiguous || !binary->dependencyMetadataValid) {
		return false;
	}
	if (stat(binary->path, &st) != 0 || !S_ISREG(st.st_mode) || access(binary->path, R_OK) != 0) {
		root_hide_hidden_whitelist_log("selected tweak preflight failed binary=%s path=%s", binary->name ?: "(null)", binary->path ?: "(null)");
		return false;
	}
	return true;
}

static bool hidden_tweak_plan_append(size_t binaryIndex)
{
	if (!gHiddenTweakLoadPlan || gHiddenTweakLoadPlanCount >= gHiddenTweakBinaryCount) {
		return false;
	}
	gHiddenTweakLoadPlan[gHiddenTweakLoadPlanCount++] = binaryIndex;
	return true;
}

static bool hidden_tweak_preflight_visit(size_t binaryIndex, const bool *selected, uint8_t *visitStates)
{
	if (!selected || !visitStates || binaryIndex >= gHiddenTweakBinaryCount) {
		return false;
	}
	if (visitStates[binaryIndex] == 2) {
		return true;
	}
	if (visitStates[binaryIndex] == 1) {
		root_hide_hidden_whitelist_log("selected tweak dependency cycle binary=%s", gHiddenTweakBinaries[binaryIndex].name ?: "(null)");
		return false;
	}

	visitStates[binaryIndex] = 1;
	HiddenTweakBinary *binary = &gHiddenTweakBinaries[binaryIndex];
	for (size_t i = 0; i < binary->dependencyCount; i++) {
		HiddenTweakDependency *dependency = &binary->dependencies[i];
		if (!dependency->hard) {
			// Weak/lazy local edges may be absent and must not create ordering or
			// cycle constraints for the selected-tweak transaction.
			continue;
		}
		const char *dependencyName = dependency->name;
		size_t dependencyIndex = 0;
		if (!hidden_tweak_binary_index_for_name(dependencyName, &dependencyIndex)) {
			// Dependencies outside the selected tweak directories are resolved by
			// dyld.  A selected/local dependency must be explicit and preflighted.
			continue;
		}
		if (!selected[dependencyIndex]) {
			root_hide_hidden_whitelist_log("selected tweak unresolved local dependency binary=%s dependency=%s", binary->name ?: "(null)", dependencyName ?: "(null)");
			return false;
		}
		if (!hidden_tweak_preflight_visit(dependencyIndex, selected, visitStates)) {
			return false;
		}
	}
	visitStates[binaryIndex] = 2;
	return hidden_tweak_plan_append(binaryIndex);
}

static bool hidden_tweak_preflight_selected_binaries(void)
{
	if (gHiddenTweakLoadState != HIDDEN_TWEAK_LOAD_NOT_ATTEMPTED) {
		return gHiddenTweakLoadState == HIDDEN_TWEAK_LOAD_PREPARED;
	}
	if (gHiddenTweakNameCount == 0) {
		root_hide_hidden_whitelist_log("selected tweak preflight skipped count=0");
		gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_FAILED;
		return false;
	}

	hidden_tweak_build_binary_index();
	if (gHiddenTweakBinaryCount == 0) {
		root_hide_hidden_whitelist_log("selected tweak preflight failed indexed=0 list=%s", gHiddenTweakListString ?: "(null)");
		gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_FAILED;
		return false;
	}

	bool *selected = calloc(gHiddenTweakBinaryCount, sizeof(*selected));
	uint8_t *visitStates = calloc(gHiddenTweakBinaryCount, sizeof(*visitStates));
	gHiddenTweakLoadPlan = calloc(gHiddenTweakBinaryCount, sizeof(*gHiddenTweakLoadPlan));
	if (!selected || !visitStates || !gHiddenTweakLoadPlan) {
		free(selected);
		free(visitStates);
		free(gHiddenTweakLoadPlan);
		gHiddenTweakLoadPlan = NULL;
		root_hide_hidden_whitelist_log("selected tweak preflight allocation failed indexed=%zu", gHiddenTweakBinaryCount);
		gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_FAILED;
		return false;
	}

	if (gHiddenTweakAllowMode) {
		for (size_t i = 0; i < gHiddenTweakNameCount; i++) {
			size_t binaryIndex = 0;
			if (!hidden_tweak_binary_index_for_name(gHiddenTweakNames[i], &binaryIndex)) {
				root_hide_hidden_whitelist_log("selected tweak preflight unresolved configured tweak=%s", gHiddenTweakNames[i]);
				goto fail;
			}
			selected[binaryIndex] = true;
		}
	}
	else {
		for (size_t i = 0; i < gHiddenTweakBinaryCount; i++) {
			selected[i] = hidden_tweak_binary_should_load(&gHiddenTweakBinaries[i]);
		}
	}

	for (size_t i = 0; i < gHiddenTweakBinaryCount; i++) {
		if (!selected[i]) {
			continue;
		}
		if (!hidden_tweak_binary_preflight(&gHiddenTweakBinaries[i])) {
			root_hide_hidden_whitelist_log("selected tweak preflight rejected binary=%s", gHiddenTweakBinaries[i].name ?: "(null)");
			goto fail;
		}
	}
	for (size_t i = 0; i < gHiddenTweakBinaryCount; i++) {
		if (selected[i] && !hidden_tweak_preflight_visit(i, selected, visitStates)) {
			goto fail;
		}
	}
	if (gHiddenTweakLoadPlanCount == 0) {
		root_hide_hidden_whitelist_log("selected tweak preflight selected no loadable binaries");
		goto fail;
	}
	for (size_t i = 0; i < gHiddenTweakLoadPlanCount; i++) {
		gHiddenTweakBinaries[gHiddenTweakLoadPlan[i]].state = HIDDEN_TWEAK_LOAD_PREPARED;
	}
	free(selected);
	free(visitStates);
	gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_PREPARED;
	root_hide_hidden_whitelist_log("selected tweak preflight prepared selected=%zu indexed=%zu", gHiddenTweakLoadPlanCount, gHiddenTweakBinaryCount);
	return true;

fail:
	free(selected);
	free(visitStates);
	free(gHiddenTweakLoadPlan);
	gHiddenTweakLoadPlan = NULL;
	gHiddenTweakLoadPlanCount = 0;
	gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_FAILED;
	return false;
}

static bool hidden_tweak_prepare_runtime(bool minimalRuntime)
{
	if (!roothide_hidden_tweak_hooks_ready()) {
		root_hide_hidden_whitelist_log("selected tweak prepare blocked: dyld transaction is no longer verified");
		return false;
	}
	if (!hidden_tweak_preflight_selected_binaries()) {
		root_hide_hidden_whitelist_log("selected tweak prepare blocked state=%s", hidden_tweak_load_state_name(gHiddenTweakLoadState));
		return false;
	}

	for (size_t i = 0; i < gHiddenTweakLoadPlanCount; i++) {
		HiddenTweakBinary *binary = &gHiddenTweakBinaries[gHiddenTweakLoadPlan[i]];
		root_hide_hidden_whitelist_log("prepare trust binary=%s path=%s", binary->name, binary->path);
		jbclient_trust_library_recurse(binary->path, NULL);
	}
	if (!hidden_tweak_load_runtime_support_libraries(minimalRuntime)) {
		root_hide_hidden_whitelist_log("selected tweak support prepare failed state=%s", hidden_tweak_load_state_name(gHiddenTweakLoadState));
		return false;
	}
	return true;
}

HiddenTweakLoadState roothide_hidden_tweak_load_state(void)
{
	return gHiddenTweakLoadState;
}

bool roothide_hidden_tweak_prepare_for_loader(void)
{
	return hidden_tweak_prepare_runtime(false);
}

bool roothide_hidden_tweak_prepare_minimal_runtime(void)
{
	return hidden_tweak_prepare_runtime(true);
}

void roothide_hidden_tweak_note_loader_result(bool succeeded)
{
	if (gHiddenTweakLoadState != HIDDEN_TWEAK_LOAD_PREPARED) {
		return;
	}
	if (!succeeded) {
		// Runtime support has already been dlopen'ed before TweakLoader is
		// attempted. Its constructors may have mutated process state, so failure
		// cannot truthfully be reported as a clean preflight refusal.
		gHiddenTweakLoadState = gHiddenTweakAnyDlopenSucceeded ? HIDDEN_TWEAK_LOAD_PARTIAL : HIDDEN_TWEAK_LOAD_FAILED;
		root_hide_hidden_whitelist_log("TweakLoader transaction failed state=%s", hidden_tweak_load_state_name(gHiddenTweakLoadState));
	}
}

static bool hidden_tweak_verified_loaded_image_seam(const char *path)
{
	/*
	 * dlopen succeeded and the handle was recorded, so this is the narrow point
	 * at which selected-tweak code may receive the full hidden view.  The policy
	 * accepts only an exact, validated dyld image path; aliases, basenames, and
	 * failed/partial loads remain filtered.
	 */
	rhi_hider_caller_authorization_result_t authorization = RHI_HIDER_CALLER_AUTH_INVALID_PATH;
	if (!rhi_hider_caller_authorize_loaded_image_path(path, &authorization)) {
		root_hide_hidden_whitelist_log("selected tweak capability withheld path=%s reason=%s",
			path ?: "(null)", rhi_hider_caller_authorization_result_name(authorization));
		return false;
	}
	return true;
}

bool roothide_hidden_tweak_load_selected(void)
{
	if (!roothide_hidden_tweak_hooks_ready()) {
		gHiddenTweakLoadState = gHiddenTweakAnyDlopenSucceeded ?
			HIDDEN_TWEAK_LOAD_PARTIAL : HIDDEN_TWEAK_LOAD_FAILED;
		root_hide_hidden_whitelist_log("selected tweak load blocked: dyld transaction is no longer verified state=%s",
			hidden_tweak_load_state_name(gHiddenTweakLoadState));
		return false;
	}
	if (gHiddenTweakLoadState == HIDDEN_TWEAK_LOAD_NOT_ATTEMPTED) {
		// Keep this public entry point safe for future callers: it may not load
		// selected tweaks until both the binaries and runtime support set passed
		// the same preflight used by the normal systemhook path.
		if (!hidden_tweak_prepare_runtime(false)) {
			return false;
		}
	}
	if (gHiddenTweakLoadState != HIDDEN_TWEAK_LOAD_PREPARED) {
		root_hide_hidden_whitelist_log("selected tweak load not retried state=%s", hidden_tweak_load_state_name(gHiddenTweakLoadState));
		return false;
	}

	root_hide_hidden_whitelist_log("selected tweak load begin planned=%zu indexed=%zu mode=%s list=%s",
		gHiddenTweakLoadPlanCount,
		gHiddenTweakBinaryCount,
		gHiddenTweakAllowMode ? "allow" : "deny",
		gHiddenTweakListString ?: "(null)");

	for (size_t i = 0; i < gHiddenTweakLoadPlanCount; i++) {
		if (!roothide_hidden_tweak_hooks_ready()) {
			gHiddenTweakLoadState = gHiddenTweakAnyDlopenSucceeded ?
				HIDDEN_TWEAK_LOAD_PARTIAL : HIDDEN_TWEAK_LOAD_FAILED;
			root_hide_hidden_whitelist_log("selected tweak load stopped: dyld transaction invalidated state=%s",
				hidden_tweak_load_state_name(gHiddenTweakLoadState));
			return false;
		}
		HiddenTweakBinary *binary = &gHiddenTweakBinaries[gHiddenTweakLoadPlan[i]];
		if (binary->state != HIDDEN_TWEAK_LOAD_PREPARED) {
			gHiddenTweakLoadState = gHiddenTweakAnyDlopenSucceeded ? HIDDEN_TWEAK_LOAD_PARTIAL : HIDDEN_TWEAK_LOAD_UNKNOWN;
			root_hide_hidden_whitelist_log("selected tweak load invalid planned state binary=%s state=%s", binary->name ?: "(null)", hidden_tweak_load_state_name(binary->state));
			return false;
		}

		if (hidden_tweak_loaded_library_contains_path(binary->path)) {
			if (!hidden_tweak_verified_loaded_image_seam(binary->path)) {
				binary->state = HIDDEN_TWEAK_LOAD_UNKNOWN;
				gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_PARTIAL;
				root_hide_hidden_whitelist_log("selected tweak existing image lacks capability binary=%s path=%s",
					binary->name, binary->path);
				return false;
			}
			binary->state = HIDDEN_TWEAK_LOAD_ACTIVE;
			root_hide_hidden_whitelist_log("selected tweak already loaded binary=%s path=%s", binary->name, binary->path);
			continue;
		}

		jbclient_trust_library_recurse(binary->path, NULL);
		root_hide_hidden_whitelist_log("selected tweak dlopen attempt binary=%s path=%s", binary->name, binary->path);
		void *handle = dlopen(binary->path, RTLD_NOW | RTLD_GLOBAL);
		if (!handle) {
			binary->state = HIDDEN_TWEAK_LOAD_FAILED;
			gHiddenTweakLoadState = gHiddenTweakAnyDlopenSucceeded ? HIDDEN_TWEAK_LOAD_PARTIAL : HIDDEN_TWEAK_LOAD_FAILED;
			root_hide_hidden_whitelist_log("selected tweak dlopen failed binary=%s path=%s error=%s state=%s",
				binary->name,
				binary->path,
				dlerror() ?: "(null)",
				hidden_tweak_load_state_name(gHiddenTweakLoadState));
			return false;
		}

		gHiddenTweakAnyDlopenSucceeded = true;
		if (!roothide_hidden_tweak_hooks_ready()) {
			binary->state = HIDDEN_TWEAK_LOAD_UNKNOWN;
			gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_PARTIAL;
			root_hide_hidden_whitelist_log("selected tweak dlopen invalidated dyld transaction binary=%s",
				binary->name);
			return false;
		}
		if (!hidden_tweak_store_loaded_library(binary->path, handle)) {
			binary->state = HIDDEN_TWEAK_LOAD_UNKNOWN;
			gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_PARTIAL;
			root_hide_hidden_whitelist_log("selected tweak handle record failed binary=%s path=%s", binary->name, binary->path);
			return false;
		}
		if (!hidden_tweak_verified_loaded_image_seam(binary->path)) {
			binary->state = HIDDEN_TWEAK_LOAD_UNKNOWN;
			gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_PARTIAL;
			root_hide_hidden_whitelist_log("selected tweak load stopped without capability binary=%s path=%s",
				binary->name, binary->path);
			return false;
		}
		binary->state = HIDDEN_TWEAK_LOAD_ACTIVE;
		root_hide_hidden_whitelist_log("selected tweak dlopen success binary=%s path=%s handle=%p", binary->name, binary->path, handle);
	}

	gHiddenTweakLoadState = HIDDEN_TWEAK_LOAD_ACTIVE;
	root_hide_hidden_whitelist_log("selected tweak load end loadedLibraries=%zu state=%s", gHiddenTweakLoadedLibraryCount, hidden_tweak_load_state_name(gHiddenTweakLoadState));
	return true;
}

//export for PatchLoader
__attribute__((visibility("default"))) int PLRequiredJIT() {
	return 0;
}

static uid_t _CFGetSVUID(bool *successful) {
    uid_t uid = -1;
    struct kinfo_proc kinfo;
    u_int miblen = 4;
    size_t  len;
    int mib[miblen];
    int ret;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    len = sizeof(struct kinfo_proc);
    ret = sysctl(mib, miblen, &kinfo, &len, NULL, 0);
    if (ret != 0) {
        uid = -1;
        *successful = false;
    } else {
        uid = kinfo.kp_eproc.e_pcred.p_svuid;
        *successful = true;
    }
    return uid;
}

bool _CFCanChangeEUIDs(void) {
    static bool canChangeEUIDs;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        uid_t euid = geteuid();
        uid_t uid = getuid();
        bool gotSVUID = false;
        uid_t svuid = _CFGetSVUID(&gotSVUID);
        canChangeEUIDs = (uid == 0 || uid != euid || svuid != euid || !gotSVUID);
    });
    return canChangeEUIDs;
}

void loadPathHook()
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
		void* roothidehooks = dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
		ASSERT(roothidehooks != NULL);
		void (*pathhook)() = dlsym(roothidehooks, "pathhook");
		ASSERT(pathhook != NULL);
		pathhook();
	});
}

void redirect_env_paths(const char* rootdir)
{
    //for now libSystem should be initlized, container should be set.

    char* homedir = NULL;

/* 
there is a bug in NSHomeDirectory,
if a containerized root process changes its uid/gid, 
NSHomeDirectory may return a home directory that it cannot access. (exclude NSTemporaryDirectory)
We just keep this bug:
*/
    if(!issetugid()) // issetugid() should always be false at this time. (but how about persona-mgmt? idk)
    {
        homedir = getenv("CFFIXED_USER_HOME");
        if(homedir)
        {
#define CONTAINER_PATH_PREFIX   "/private/var/mobile/Containers/Data/" // +/Application,PluginKitPlugin,InternalDaemon
            if(strncmp(homedir, CONTAINER_PATH_PREFIX, sizeof(CONTAINER_PATH_PREFIX)-1) == 0)
            {
                return; //containerized
            }
            else
            {
                homedir = NULL; //from parent, drop it
            }
        }
    }

    if(!homedir) {
        struct passwd* pwd = getpwuid(geteuid());
        if(pwd && pwd->pw_dir) {
            homedir = pwd->pw_dir;
        }
    }

    // if(!homedir) {
    //     //CFCopyHomeDirectoryURL does, but not for NSHomeDirectory
    //     homedir = getenv("HOME");
    // }

    if(!homedir) {
        homedir = "/var/empty";
    }

	if(homedir[0] == '/') {
		char newhome[PATH_MAX*2]={0};
		strlcpy(newhome, rootdir, sizeof(newhome));
		strlcat(newhome, homedir, sizeof(newhome));
		setenv("CFFIXED_USER_HOME", newhome, 1);
	}
}

void redirect_paths(const char* rootdir)
{
    do {
        
        char executablePath[PATH_MAX]={0};
        uint32_t bufsize=sizeof(executablePath);
        if(_NSGetExecutablePath(executablePath, &bufsize) != 0)
            break;
        
        char realexepath[PATH_MAX]={0};
        if(!realpath(executablePath, realexepath))
            break;
            
        char realjbroot[PATH_MAX+1]={0};
        if(!realpath(rootdir, realjbroot))
            break;
        
        if(realjbroot[0] && realjbroot[strlen(realjbroot)-1] != '/')
            strlcat(realjbroot, "/", sizeof(realjbroot));
        
        if(strncmp(realexepath, realjbroot, strlen(realjbroot)) != 0)
            break;

        //for jailbroken binaries
        redirect_env_paths(rootdir);
		
		if(_CFCanChangeEUIDs()) {
			loadPathHook();
		}
    
        pid_t ppid = __getppid();
        ASSERT(ppid > 0);
        if(ppid != 1)
            break;
        
        char pwd[PATH_MAX];
        if(getcwd(pwd, sizeof(pwd)) == NULL)
            break;
        if(strcmp(pwd, "/") != 0)
            break;
    
        ASSERT(chdir(rootdir)==0);
        
    } while(0);
}


kSpawnConfig spawn_config_for_executable(const char* path, char *const argv[restrict]);
void string_enumerate_components(const char *string, const char *separator, void (^enumBlock)(const char *pathString, bool *stop));

void trust_insert_libraries(char** envc)
{
	const char* DYLD_INSERT_LIBRARIES = envbuf_getenv((const char * const *)envc, "DYLD_INSERT_LIBRARIES");
	if(!DYLD_INSERT_LIBRARIES) return;

	string_enumerate_components(DYLD_INSERT_LIBRARIES, ":", ^(const char *path, bool *stop) {
		if (strcmp(path, HOOK_DYLIB_PATH) != 0) {
			jbclient_trust_library_recurse(path, NULL);
		}
	});
}

int __no_need_to_trust_now__(const char* path)
{
	return 0;
}

#define NBINPREFS       4
#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t * __restrict, int * __restrict) __API_AVAILABLE(macos(10.8), ios(6.0));

int roothide_systemhook___posix_spawn_prehook(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict], void *orig, int (*trust_binary)(const char *path), int (*set_process_debugged)(uint64_t pid, bool fullyDebugged), double jetsamMultiplier)
{
	if(!path) { //Don't crash here due to bad posix_spawn call
		return __posix_spawn_orig(pidp, path, desc, argv, envp);
	}

	if(!desc || !desc->attrp) {
		posix_spawnattr_t attr=NULL;
		posix_spawnattr_init(&attr);
		int ret = posix_spawn(pidp, path, (desc && desc->file_actions) ? &desc->file_actions : NULL, &attr, argv, envp);
		posix_spawnattr_destroy(&attr);
		return ret;
	}

	if(!jbclient_dyld_patch_enabled())
	{
		trust_binary = __no_need_to_trust_now__;
	}

	char **envc = NULL;
	const char *const *effectiveEnvp = (const char *const *)envp;
	if (roothide_hidden_tweak_env_is_configured()) {
		envc = envbuf_mutcopy((const char **)envp);
		if (!envc || !roothide_hidden_tweak_envbuf_apply(&envc)) {
			envbuf_free(envc);
			errno = ENOMEM;
			return ENOMEM;
		}
		effectiveEnvp = (const char *const *)envc;
	}

	int ret = posix_spawn_hook_shared(pidp, path, desc, argv, (char *const *)effectiveEnvp, orig, trust_binary, set_process_debugged, jetsamMultiplier);
	if (envc) {
		envbuf_free(envc);
	}
	return ret;
}

int roothide_systemhook___posix_spawn_posthook(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
	posix_spawnattr_t attrp = &desc->attrp;

	kSpawnConfig spawnConfig = 0;
	if(!jbclient_dyld_patch_enabled())
	{
		spawnConfig = spawn_config_for_executable(path, argv);

		if (spawnConfig & kSpawnConfigTrust) {
			size_t outCount = 0;
			bool preferredArchsSet = false;
			cpu_type_t preferredTypes[NBINPREFS] = {0};
			cpu_subtype_t preferredSubtypes[NBINPREFS] = {0};
			if (posix_spawnattr_getarchpref_np(attrp, 4, preferredTypes, preferredSubtypes, &outCount) == 0) {
				for (size_t i = 0; i < outCount; i++) {
					if (preferredTypes[i] != 0 || preferredSubtypes[i] != UINT32_MAX) {
						preferredArchsSet = true;
						break;
					}
				}
			}

			xpc_object_t preferredArchsArray = NULL;
			if (preferredArchsSet) {
				preferredArchsArray = xpc_array_create_empty();
				for (size_t i = 0; i < outCount; i++) {
					xpc_object_t curArch = xpc_dictionary_create_empty();
					xpc_dictionary_set_uint64(curArch, "type", preferredTypes[i]);
					xpc_dictionary_set_uint64(curArch, "subtype", preferredSubtypes[i]);
					xpc_array_set_value(preferredArchsArray, XPC_ARRAY_APPEND, curArch);
					xpc_release(curArch);
				}
			}

			// Upload binary to trustcache if needed
			jbclient_trust_executable_recurse(path, preferredArchsArray);

			if (preferredArchsArray) {
				xpc_release(preferredArchsArray);
			}
		}
	}

	short flags = 0;
	posix_spawnattr_getflags(attrp, &flags);

	int proctype = 0;
	posix_spawnattr_getprocesstype_np(attrp, &proctype);

	bool should_suspend = (proctype != POSIX_SPAWN_PROC_TYPE_DRIVER);
	bool should_resume = should_suspend && (flags & POSIX_SPAWN_START_SUSPENDED)==0;
	bool patch_exec = should_suspend && (flags & POSIX_SPAWN_SETEXEC) != 0;

	if (should_suspend) {
		posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
	}

	if (patch_exec) {
		if (jbdSpawnExecStart(path, should_resume) != 0) { // jdb fault?
			//restore flags
			posix_spawnattr_setflags(attrp, flags);
			return 201;
		}
	}

	// on some devices dyldhook may fail due to vm_protect(VM_PROT_READ|VM_PROT_WRITE), 2, (os/kern) protection failure in dsc::__DATA_CONST:__const, 
	// so we need to disable dyld-in-cache here. (or we can use VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY)
	char **envc = envbuf_mutcopy((const char **)envp);
	bool ownsEnvc = envc != NULL;
	if (!envc) {
		if (envbuf_getenv((const char **)envp, "DYLD_INSERT_LIBRARIES")) {
			posix_spawnattr_setflags(attrp, flags);
			return ENOMEM;
		}
		envc = (char **)envp;
	}
	if(envbuf_getenv((const char **)envc, "DYLD_INSERT_LIBRARIES") && !envbuf_setenv(&envc, "DYLD_IN_CACHE", "0")) {
		if (ownsEnvc) envbuf_free(envc);
		posix_spawnattr_setflags(attrp, flags);
		return ENOMEM;
	}

	if(!jbclient_dyld_patch_enabled())
	{
		if (spawnConfig & kSpawnConfigTrust) {
			trust_insert_libraries(envc);
		}
	}

	pid_t pidval = 0;
	if (!pidp) pidp = &pidval;
	int ret = __posix_spawn_orig(pidp, path, desc, argv, envc);
	pid_t pid = *pidp;
	
	if (ownsEnvc) envbuf_free(envc);

	// maybe caller will use it again? restore flags
	posix_spawnattr_setflags(attrp, flags);

	if (patch_exec) { //exec failed?
		jbdSpawnExecCancel(path);
	} else if (ret == 0 && pid > 0) {
		if (should_suspend) {
			if(jbdSpawnPatchChild(pid, should_resume) != 0) { // jdb fault? kill
				//just kill it instead of letting it hang forever, and the requester decides what to do later
				kill(pid, SIGQUIT); //core dump
				kill(pid, SIGKILL);
				return 202;
			}
		}
	}

	return ret;
}

int roothide_systemhook___execve_prehook(const char *path, char *const argv[], char *const envp[], void *orig, int (*trust_binary)(const char *path))
{
	//try POSIX_SPAWN_SETEXEC first
	posix_spawnattr_t attr = NULL;
	posix_spawnattr_init(&attr);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
	int ret = posix_spawn(NULL, path, NULL, &attr, argv, envp);
	posix_spawnattr_destroy(&attr);

	//posix_spawn with POSIX_SPAWN_SETEXEC failed
	assert(ret != 0);

	/* some processes are only allowed to call execve but not posix_spawn,
	 e.g: "configd" on ios15, we need to trace it so that we can patch the subprocess before it runs. */
	if(ret==EPERM && access(path, X_OK)==0 && sandbox_check(getpid(), "process-fork", SANDBOX_CHECK_NO_REPORT, NULL) == 0)
	{
		trust_binary = __no_need_to_trust_now__;
		char **envc = NULL;
		const char *const *effectiveEnvp = (const char *const *)envp;
		if (roothide_hidden_tweak_env_is_configured()) {
			envc = envbuf_mutcopy((const char **)envp);
			if (!envc || !roothide_hidden_tweak_envbuf_apply(&envc)) {
				envbuf_free(envc);
				errno = ENOMEM;
				return -1;
			}
			effectiveEnvp = (const char *const *)envc;
		}
		int hookRet = execve_hook_shared(path, argv, (char *const *)effectiveEnvp, orig, trust_binary);
		if (envc) {
			envbuf_free(envc);
		}
		return hookRet;
	}

	// posix_spawn will return errno and restore errno if it fails
	// so we need to set errno by ourself
	errno = ret; 
	return -1;
}

int roothide_systemhook___execve_posthook(const char *path, char *const argv[], char *const envp[])
{
	/* the posix_spawn call above should already trust the executable
	(also its libraries) and the inserted libraries, so we can skip them below */

	bool traced = false;

	if(jbdExecTraceStart(path, &traced) != 0) { // jdb fault?
		errno = 203;
		return -1;
	}

	//wait for SIGSTOP
	while(!traced) usleep(10*1000);

	char **envc = envbuf_mutcopy((const char **)envp);
	bool ownsEnvc = envc != NULL;
	if (!envc) {
		if (envbuf_getenv((const char **)envp, "DYLD_INSERT_LIBRARIES")) {
			errno = ENOMEM;
			return -1;
		}
		envc = (char **)envp;
	}
	if(envbuf_getenv((const char **)envc, "DYLD_INSERT_LIBRARIES") && !envbuf_setenv(&envc, "DYLD_IN_CACHE", "0")) {
		if (ownsEnvc) envbuf_free(envc);
		errno = ENOMEM;
		return -1;
	}
	
	int ret = __execve_orig(path, argv, envc);
	int olderr = errno;
	
	if (ownsEnvc) envbuf_free(envc);

	// exec* should never return if successful

	bool detached = false;

	if(jbdExecTraceCancel(path, &detached) != 0) {
		//broken process
		exit(99);
	}

	//wait for detach
	while(!detached) usleep(10*1000);

	errno = olderr;
	return ret;
}

void* (*dyld_dlopen_orig)(void *dyld, const char* path, int mode);
void* dyld_dlopen_hook(void *dyld, const char* path, int mode)
{
	bool shouldBlock = path && hidden_tweak_filter_should_block_path(path);
	if (path && (shouldBlock || hidden_tweak_filter_applies_to_path(path) || strstr(path, "/usr/lib/TweakLoader.dylib"))) {
		root_hide_hidden_whitelist_log("dlopen mode=%d %s path=%s", mode, shouldBlock ? "block" : "allow", path);
	}
	if (shouldBlock) {
		return NULL;
	}
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library_recurse(path, __builtin_return_address(0));
	}
    __attribute__((musttail)) return dyld_dlopen_orig(dyld, path, mode);
}

void* (*dyld_dlopen_from_orig)(void *dyld, const char* path, int mode, void* addressInCaller);
void* dyld_dlopen_from_hook(void *dyld, const char* path, int mode, void* addressInCaller)
{
	bool shouldBlock = path && hidden_tweak_filter_should_block_path(path);
	if (path && (shouldBlock || hidden_tweak_filter_applies_to_path(path) || strstr(path, "/usr/lib/TweakLoader.dylib"))) {
		root_hide_hidden_whitelist_log("dlopen_from mode=%d %s path=%s", mode, shouldBlock ? "block" : "allow", path);
	}
	if (shouldBlock) {
		return NULL;
	}
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library_recurse(path, addressInCaller);
	}
	__attribute__((musttail)) return dyld_dlopen_from_orig(dyld, path, mode, addressInCaller);
}

void* (*dyld_dlopen_audited_orig)(void *dyld, const char* path, int mode);
void* dyld_dlopen_audited_hook(void *dyld, const char* path, int mode)
{
	bool shouldBlock = path && hidden_tweak_filter_should_block_path(path);
	if (path && (shouldBlock || hidden_tweak_filter_applies_to_path(path) || strstr(path, "/usr/lib/TweakLoader.dylib"))) {
		root_hide_hidden_whitelist_log("dlopen_audited mode=%d %s path=%s", mode, shouldBlock ? "block" : "allow", path);
	}
	if (shouldBlock) {
		return NULL;
	}
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library_recurse(path, __builtin_return_address(0));
	}
	__attribute__((musttail)) return dyld_dlopen_audited_orig(dyld, path, mode);
}

bool (*dyld_dlopen_preflight_orig)(void *dyld, const char *path);
bool dyld_dlopen_preflight_hook(void *dyld, const char* path)
{
	bool shouldBlock = path && hidden_tweak_filter_should_block_path(path);
	if (path && (shouldBlock || hidden_tweak_filter_applies_to_path(path) || strstr(path, "/usr/lib/TweakLoader.dylib"))) {
		root_hide_hidden_whitelist_log("dlopen_preflight %s path=%s", shouldBlock ? "block" : "allow", path);
	}
	if (shouldBlock) {
		return false;
	}
	if (path) {
		jbclient_trust_library_recurse(path, __builtin_return_address(0));
	}
	__attribute__((musttail)) return dyld_dlopen_preflight_orig(dyld, path);
}

/*
 * The dyld4 gDyld vtable is private ABI.  The historical code blindly wrote
 * four hard-coded indexes and then called that success.  We have no supported
 * way to prove the table span and PAC discriminator layout for every dyld
 * revision from this process, so it is deliberately treated as an
 * unsupported transaction rather than risking a partially-written vtable.
 * The result-aware import-slot fallback below remains available when it can
 * prepare and verify every target slot.
 */
static rhi_rebind_result_t prepare_dyld_vtable_transaction(void ***gDyldPtr)
{
	if (gDyldPtr) {
		root_hide_hidden_whitelist_log("dyld4 vtable layout unverified; refusing transaction before mutation");
	}
	return RHI_REBIND_NONE;
}

// iOS 15 / dyld3 fallback: GOT-rebound dlopen hook with standard C signature.
// litehook_rebind_symbol replaces the GOT entry for dlopen in all loaded images,
// so the original dlopen address stays valid through the DSC.
/* Captured before the first replacement write; atomic so a replacement that
 * becomes reachable during commit cannot race this publication. */
static _Atomic(void *(*)(const char *, int)) dlopen_fallback_orig = NULL;
void *dlopen_fallback_hook(const char *path, int mode)
{
	/* A late image can invalidate this physical GOT replacement. Forward via
	 * the published predecessor instead of retaining a stale success bit. */
	if (!roothide_hidden_tweak_hooks_ready()) {
		void *(*predecessor)(const char *, int) =
			atomic_load_explicit(&dlopen_fallback_orig, memory_order_acquire);
		return predecessor ? predecessor(path, mode) : NULL;
	}
	bool shouldBlock = path && hidden_tweak_filter_should_block_path(path);
	if (path && (shouldBlock || hidden_tweak_filter_applies_to_path(path) || strstr(path, "/usr/lib/TweakLoader.dylib"))) {
		root_hide_hidden_whitelist_log("dlopen mode=%d %s path=%s", mode, shouldBlock ? "block" : "allow", path);
	}
	if (shouldBlock) {
		return NULL;
	}
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library_recurse(path, __builtin_return_address(0));
	}
	void *(*predecessor)(const char *, int) =
		atomic_load_explicit(&dlopen_fallback_orig, memory_order_acquire);
	return predecessor ? predecessor(path, mode) : NULL;
}

void init_dyldhooks()
{
	if (atomic_load_explicit(&gHiddenTweakHooksInstalled, memory_order_acquire) &&
	    roothide_hidden_tweak_hooks_ready()) {
		return;
	}
	rhi_hook_state_t current_state = (rhi_hook_state_t)
		atomic_load_explicit(&gHiddenTweakHookState, memory_order_acquire);
	if (current_state != RHI_HOOK_NOT_ATTEMPTED) {
		return;
	}
	/* Claim initialization exactly once.  This is intentionally lock-free:
	 * init can be reached through a dyld/dlopen path where a mutex would
	 * recurse.  PREPARED is the in-progress and no-retry publication state. */
	int expected_state = RHI_HOOK_NOT_ATTEMPTED;
	if (!atomic_compare_exchange_strong_explicit(&gHiddenTweakHookState,
	                                             &expected_state,
	                                             RHI_HOOK_PREPARED,
	                                             memory_order_acq_rel,
	                                             memory_order_acquire)) {
		return;
	}

	// First attempt the private dyld4 route only if it can be transactionally proven.
	void ***gDyldPtr = litehook_find_dsc_symbol("/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");
	rhi_rebind_result_t vtable_result = prepare_dyld_vtable_transaction(gDyldPtr);
	if (vtable_result == RHI_REBIND_COMPLETE) {
		/* No current implementation reaches this branch without ABI proof.  A
		 * vtable result has no published transaction/session for the readiness
		 * API, so never advertise it as a successful selected hook. */
		atomic_store_explicit(&dlopen_fallback_hook_installed, false, memory_order_release);
		atomic_store_explicit(&gHiddenTweakHooksInstalled, false, memory_order_release);
		atomic_store_explicit(&gHiddenTweakHookState, RHI_HOOK_FAILED, memory_order_release);
		return;
	}
	if (vtable_result == RHI_REBIND_PARTIAL || vtable_result == RHI_REBIND_UNKNOWN) {
		rhi_hook_state_t state = vtable_result == RHI_REBIND_PARTIAL ?
			RHI_HOOK_PARTIAL : RHI_HOOK_UNKNOWN;
		atomic_store_explicit(&gHiddenTweakHookState, state, memory_order_release);
		root_hide_hidden_whitelist_log("dyld vtable transaction %s; no fallback after mutation",
			vtable_result == RHI_REBIND_PARTIAL ? "partial" : "unknown");
		return;
	}

	/* iOS 15/dyld3 compatible path: verified global GOT transaction for dlopen. */
	rhi_rebind_transaction_t *transaction = rhi_rebind_transaction_create();
	if (!transaction) {
		atomic_store_explicit(&gHiddenTweakHookState, RHI_HOOK_FAILED, memory_order_release);
		return;
	}
	const rhi_rebind_spec_t fallback_spec = {
		"dlopen", (void *)dlopen, (void *)dlopen_fallback_hook,
	};
	if (!rhi_rebind_transaction_prepare_global(transaction,
	                                           &fallback_spec, 1)) {
		rhi_hook_state_t state = rhi_rebind_transaction_state(transaction);
		atomic_store_explicit(&gHiddenTweakHookState, state, memory_order_release);
		root_hide_hidden_whitelist_log("dyld dlopen fallback prepare %s",
			rhi_hook_state_name(state));
		return;
	}
	/* Publish the captured predecessor before a replacement becomes reachable. */
	void *(*predecessor)(const char *, int) = (void *(*)(const char *, int))
		rhi_rebind_transaction_original(transaction, 0);
	if (!predecessor) {
		atomic_store_explicit(&gHiddenTweakHookState, RHI_HOOK_FAILED, memory_order_release);
		return;
	}
	atomic_store_explicit(&dlopen_fallback_orig, predecessor, memory_order_release);
	rhi_rebind_result_t fallback_result =
		rhi_rebind_transaction_commit(transaction);
	if (fallback_result != RHI_REBIND_COMPLETE ||
	    !rhi_rebind_transaction_activate_global(transaction)) {
		rhi_hook_state_t state = rhi_rebind_transaction_state(transaction);
		atomic_store_explicit(&gHiddenTweakHookState, state, memory_order_release);
		root_hide_hidden_whitelist_log("dyld dlopen fallback %s",
			rhi_hook_state_name(state));
		return;
	}
	/* The transaction is process-lifetime after activation. Publish it before
	 * the readiness and dlsym advertisement flags, so no reader can observe a
	 * true flag with a missing/partially initialized transaction. */
	atomic_store_explicit(&gHiddenTweakFallbackTransaction, transaction, memory_order_release);
	atomic_store_explicit(&dlopen_fallback_hook_installed, true, memory_order_release);
	atomic_store_explicit(&gHiddenTweakHookState, RHI_HOOK_ACTIVE, memory_order_release);
	/* This is the single publication point. Its release pairs with the first
	 * acquire in readiness, making the pointer, predecessor, state and dlsym
	 * advertisement visible as one completed installation. */
	atomic_store_explicit(&gHiddenTweakHooksInstalled, true, memory_order_release);
}

bool roothide_hidden_tweak_hooks_ready(void)
{
	const bool installed = atomic_load_explicit(&gHiddenTweakHooksInstalled, memory_order_acquire);
	/* False includes both the ordinary pre-publication window and a terminal
	 * invalidation. Do not mutate other fields merely because a reader raced the
	 * initializer before its final release store. */
	if (!installed) return false;
	const bool fallback_advertised = atomic_load_explicit(
		&dlopen_fallback_hook_installed, memory_order_acquire);
	const rhi_hook_state_t published_state = (rhi_hook_state_t)
		atomic_load_explicit(&gHiddenTweakHookState, memory_order_acquire);
	/* Load the pointer only after the release-published state/flag.  A missing
	 * pointer is always a fail-closed result; the pointer is never destroyed
	 * after publication, so this acquire also keeps the transaction readable. */
	rhi_rebind_transaction_t *transaction = atomic_load_explicit(
		&gHiddenTweakFallbackTransaction, memory_order_acquire);
	if (!fallback_advertised || published_state != RHI_HOOK_ACTIVE || !transaction) {
		/* Once the final installed flag was acquired, an incomplete tuple is a
		 * real one-way invalidation rather than an initialization race. */
		atomic_store_explicit(&gHiddenTweakHookState, RHI_HOOK_FAILED, memory_order_release);
		atomic_store_explicit(&gHiddenTweakHooksInstalled, false, memory_order_release);
		atomic_store_explicit(&dlopen_fallback_hook_installed, false, memory_order_release);
		return false;
	}
	const rhi_hook_state_t live_state =
		rhi_rebind_transaction_state(transaction);
	if (live_state != RHI_HOOK_ACTIVE ||
	    !rhi_rebind_transaction_hook_is_active(transaction, "dlopen")) {
		/* A physical GOT replacement may remain after a failed late-image
		 * transaction.  This one-way gate is used by both the wrapper and the
		 * selected-loader progress path, so stale state is never advertised. */
		rhi_hook_state_t invalidated_state = live_state == RHI_HOOK_ACTIVE ?
			RHI_HOOK_FAILED : live_state;
		atomic_store_explicit(&gHiddenTweakHookState, invalidated_state, memory_order_release);
		atomic_store_explicit(&gHiddenTweakHooksInstalled, false, memory_order_release);
		atomic_store_explicit(&dlopen_fallback_hook_installed, false, memory_order_release);
		return false;
	}
	return true;
}

extern struct mach_header __dso_handle;
extern const char* dyld_image_path_containing_address(const void* addr);

extern int parse_dyldhook_jbinfo(char **jbRootPathOut, char **bootUUIDOut, char **sandboxExtensionsOut, bool *fullyDebuggedOut);

void roothide_init()
{
	if(getenv("DYLD_INSERT_LIBRARIES")) {
		const char* DYLD_IN_CACHE = getenv("DYLD_IN_CACHE");
		if(DYLD_IN_CACHE && strcmp(DYLD_IN_CACHE, "0") == 0) {
			unsetenv("DYLD_IN_CACHE");
		}
	}

	const char *hookDylibPath = dyld_image_path_containing_address(&__dso_handle);
	if (hookDylibPath) {
		char *hookDylibPathCopy = strdup(hookDylibPath);
		if (hookDylibPathCopy) {
			free((void *)HOOK_DYLIB_PATH);
			HOOK_DYLIB_PATH = hookDylibPathCopy;
		}
	}

	if(parse_dyldhook_jbinfo(NULL, NULL, NULL, NULL) != 0)
	{
		dyld_patch_fallback_enabled = true;
	}
}

void roothide_init_with_checkin(const char* rootdir)
{
	roothide_hidden_tweak_consume_environment();

	if (dyld_patch_fallback_enabled || gHiddenTweakNameCount > 0)
	{
		init_dyldhooks();
	}

	redirect_paths(rootdir);

	dlopen(JBROOT_PATH("/usr/lib/roothideinit.dylib"), RTLD_NOW);
}

void roothide_init_with_executable(const char* executable)
{
	if (__builtin_available(iOS 16.0, *))
	{
		if(!isRemovableBundlePath(executable)) {
			litehook_hook_function(__sysctl, __sysctl_hook);
			litehook_hook_function(__sysctlbyname, __sysctlbyname_hook);
		}
	}

#ifndef __arm64e__
	if(strcmp(executable, "/System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd")==0
	|| strcmp(executable, "/System/Library/Frameworks/CryptoTokenKit.framework/ctkd")==0
	|| strcmp(executable, "/usr/libexec/securityd")==0
	|| strcmp(executable, "/usr/libexec/keybagd")==0) {
		if(jbclient_palehide_present())
		{
			void* roothidehooks = dlopen(JBROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
			ASSERT(roothidehooks != NULL);
			void (*palera1n)() = dlsym(roothidehooks, "palera1n");
			palera1n();
		}
	}
#endif

	if(isRemovableBundlePath(executable) && string_has_suffix(executable, "/Dopamine")) {
		loadPathHook(); //requre jit
	}

	dlopen(JBROOT_PATH("/usr/lib/roothidepatch.dylib"), RTLD_NOW); //require jit
}
