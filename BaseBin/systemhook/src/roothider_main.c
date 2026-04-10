#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <dirent.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <libkern/OSByteOrder.h>

#include <litehook.h>

#include "common.h"
#include "envbuf.h"
#include "sandbox.h"
#include "roothider.h"

const char* HOOK_DYLIB_PATH = NULL;

bool dyld_patch_fallback_enabled = false;
bool dlopen_fallback_hook_installed = false;
static bool gHiddenTweakAllowMode = true;
static size_t gHiddenTweakNameCount = 0;
static char **gHiddenTweakNames = NULL;
static bool gHiddenTweakHooksInstalled = false;
static char *gHiddenTweakModeString = NULL;
static char *gHiddenTweakListString = NULL;
static void **gHiddenTweakLoadedHandles = NULL;
static size_t gHiddenTweakLoadedHandleCount = 0;

typedef struct {
	char *path;
	char *name;
	size_t dependencyCount;
	char **dependencies;
} HiddenTweakBinary;

static HiddenTweakBinary *gHiddenTweakBinaries = NULL;
static size_t gHiddenTweakBinaryCount = 0;

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
			free(gHiddenTweakBinaries[i].dependencies[j]);
		}
		free(gHiddenTweakBinaries[i].dependencies);
	}
	free(gHiddenTweakBinaries);
	gHiddenTweakBinaries = NULL;
	gHiddenTweakBinaryCount = 0;
}

static void clear_hidden_tweak_filter(void)
{
	free(gHiddenTweakModeString);
	gHiddenTweakModeString = NULL;
	free(gHiddenTweakListString);
	gHiddenTweakListString = NULL;
	clear_hidden_tweak_binaries();
	free(gHiddenTweakLoadedHandles);
	gHiddenTweakLoadedHandles = NULL;
	gHiddenTweakLoadedHandleCount = 0;

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

	char **newNames = realloc(gHiddenTweakNames, sizeof(char *) * (gHiddenTweakNameCount + 1));
	if (!newNames) {
		return false;
	}

	gHiddenTweakNames = newNames;
	gHiddenTweakNames[gHiddenTweakNameCount++] = strdup(tweakName);
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

static bool hidden_tweak_dependency_add_name(char ***dependencies, size_t *dependencyCount, const char *name)
{
	if (!dependencies || !dependencyCount || !name || name[0] == '\0') {
		return false;
	}

	for (size_t i = 0; i < *dependencyCount; i++) {
		if (!strcmp((*dependencies)[i], name)) {
			return false;
		}
	}

	char **newDependencies = realloc(*dependencies, sizeof(char *) * (*dependencyCount + 1));
	if (!newDependencies) {
		return false;
	}

	*dependencies = newDependencies;
	(*dependencies)[(*dependencyCount)++] = strdup(name);
	return true;
}

static bool hidden_tweak_read_at_offset(FILE *file, uint64_t offset, void *buffer, size_t size)
{
	if (!file || !buffer || size == 0) {
		return false;
	}
	if (fseeko(file, (off_t)offset, SEEK_SET) != 0) {
		return false;
	}
	return fread(buffer, 1, size, file) == size;
}

static bool hidden_tweak_collect_dependencies_for_slice(FILE *file, uint64_t sliceOffset, char ***dependencies, size_t *dependencyCount)
{
	struct mach_header_64 header64 = {0};
	if (!hidden_tweak_read_at_offset(file, sliceOffset, &header64, sizeof(header64))) {
		return false;
	}

	uint32_t magic = header64.magic;
	bool is64 = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
	bool shouldSwap = (magic == MH_CIGAM || magic == MH_CIGAM_64);
	if (!(magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64)) {
		return false;
	}

	uint32_t ncmds = shouldSwap ? OSSwapInt32(header64.ncmds) : header64.ncmds;
	uint64_t cursor = sliceOffset + (is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
	for (uint32_t i = 0; i < ncmds; i++) {
		struct load_command loadCommand = {0};
		if (!hidden_tweak_read_at_offset(file, cursor, &loadCommand, sizeof(loadCommand))) {
			return false;
		}

		uint32_t command = shouldSwap ? OSSwapInt32(loadCommand.cmd) : loadCommand.cmd;
		uint32_t commandSize = shouldSwap ? OSSwapInt32(loadCommand.cmdsize) : loadCommand.cmdsize;
		if (commandSize < sizeof(struct load_command)) {
			return false;
		}

		if (command == LC_LOAD_DYLIB || command == LC_LOAD_WEAK_DYLIB || command == LC_REEXPORT_DYLIB || command == LC_LOAD_UPWARD_DYLIB || command == LC_LAZY_LOAD_DYLIB) {
			struct dylib_command dylibCommand = {0};
			if (commandSize >= sizeof(dylibCommand) && hidden_tweak_read_at_offset(file, cursor, &dylibCommand, sizeof(dylibCommand))) {
				uint32_t nameOffset = shouldSwap ? OSSwapInt32(dylibCommand.dylib.name.offset) : dylibCommand.dylib.name.offset;
				if (nameOffset >= sizeof(struct dylib_command) && nameOffset < commandSize) {
					size_t nameLength = commandSize - nameOffset;
					char *nameBuffer = calloc(1, nameLength + 1);
					if (nameBuffer && hidden_tweak_read_at_offset(file, cursor + nameOffset, nameBuffer, nameLength)) {
						char dependencyName[PATH_MAX] = {0};
						if (hidden_tweak_dependency_name_from_load_path(nameBuffer, dependencyName)) {
							hidden_tweak_dependency_add_name(dependencies, dependencyCount, dependencyName);
						}
					}
					free(nameBuffer);
				}
			}
		}

		cursor += commandSize;
	}

	return true;
}

static void hidden_tweak_collect_dependencies_for_binary(const char *path, char ***dependencies, size_t *dependencyCount)
{
	if (!path || !dependencies || !dependencyCount) {
		return;
	}

	FILE *file = fopen(path, "rb");
	if (!file) {
		return;
	}

	uint32_t magic = 0;
	if (!hidden_tweak_read_at_offset(file, 0, &magic, sizeof(magic))) {
		fclose(file);
		return;
	}

	if (magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
		bool shouldSwap = (magic == FAT_MAGIC || magic == FAT_MAGIC_64);
		bool is64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
		if (is64) {
			struct fat_header fatHeader = {0};
			if (hidden_tweak_read_at_offset(file, 0, &fatHeader, sizeof(fatHeader))) {
				uint32_t nfatArch = shouldSwap ? OSSwapBigToHostInt32(fatHeader.nfat_arch) : fatHeader.nfat_arch;
				for (uint32_t i = 0; i < nfatArch; i++) {
					struct fat_arch_64 fatArch = {0};
					uint64_t archOffset = sizeof(struct fat_header) + (sizeof(struct fat_arch_64) * i);
					if (!hidden_tweak_read_at_offset(file, archOffset, &fatArch, sizeof(fatArch))) {
						break;
					}
					uint64_t sliceOffset = shouldSwap ? OSSwapBigToHostInt64(fatArch.offset) : fatArch.offset;
					if (hidden_tweak_collect_dependencies_for_slice(file, sliceOffset, dependencies, dependencyCount)) {
						break;
					}
				}
			}
		}
		else {
			struct fat_header fatHeader = {0};
			if (hidden_tweak_read_at_offset(file, 0, &fatHeader, sizeof(fatHeader))) {
				uint32_t nfatArch = shouldSwap ? OSSwapBigToHostInt32(fatHeader.nfat_arch) : fatHeader.nfat_arch;
				for (uint32_t i = 0; i < nfatArch; i++) {
					struct fat_arch fatArch = {0};
					uint64_t archOffset = sizeof(struct fat_header) + (sizeof(struct fat_arch) * i);
					if (!hidden_tweak_read_at_offset(file, archOffset, &fatArch, sizeof(fatArch))) {
						break;
					}
					uint32_t sliceOffset = shouldSwap ? OSSwapBigToHostInt32(fatArch.offset) : fatArch.offset;
					if (hidden_tweak_collect_dependencies_for_slice(file, sliceOffset, dependencies, dependencyCount)) {
						break;
					}
				}
			}
		}
	}
	else {
		hidden_tweak_collect_dependencies_for_slice(file, 0, dependencies, dependencyCount);
	}

	fclose(file);
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
			return;
		}
	}

	HiddenTweakBinary *newBinaries = realloc(gHiddenTweakBinaries, sizeof(HiddenTweakBinary) * (gHiddenTweakBinaryCount + 1));
	if (!newBinaries) {
		return;
	}
	gHiddenTweakBinaries = newBinaries;

	HiddenTweakBinary *binary = &gHiddenTweakBinaries[gHiddenTweakBinaryCount++];
	memset(binary, 0, sizeof(*binary));
	binary->path = strdup(path);
	binary->name = strdup(tweakName);
	hidden_tweak_collect_dependencies_for_binary(path, &binary->dependencies, &binary->dependencyCount);
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
			snprintf(fullPath, sizeof(fullPath), "%s/%s", directoryPath, entry->d_name);
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

static void hidden_tweak_store_loaded_handle(void *handle)
{
	if (!handle) {
		return;
	}

	void **newHandles = realloc(gHiddenTweakLoadedHandles, sizeof(void *) * (gHiddenTweakLoadedHandleCount + 1));
	if (!newHandles) {
		return;
	}

	gHiddenTweakLoadedHandles = newHandles;
	gHiddenTweakLoadedHandles[gHiddenTweakLoadedHandleCount++] = handle;
}

static void hidden_tweak_load_runtime_support_libraries(void)
{
	const char *supportLibraries[] = {
		JBROOT_PATH("/usr/lib/libroothide.dylib"),
		JBROOT_PATH("/usr/lib/libellekit.dylib"),
	};

	for (size_t i = 0; i < sizeof(supportLibraries) / sizeof(*supportLibraries); i++) {
		const char *libraryPath = supportLibraries[i];
		if (!libraryPath || libraryPath[0] == '\0') {
			continue;
		}

		if (access(libraryPath, F_OK) != 0) {
			root_hide_hidden_whitelist_log("support library missing path=%s", libraryPath);
			continue;
		}

		jbclient_trust_library_recurse(libraryPath, NULL);
		root_hide_hidden_whitelist_log("support library dlopen attempt path=%s", libraryPath);
		void *handle = dlopen(libraryPath, RTLD_NOW | RTLD_GLOBAL);
		if (handle) {
			hidden_tweak_store_loaded_handle(handle);
			root_hide_hidden_whitelist_log("support library dlopen success path=%s handle=%p", libraryPath, handle);
		}
		else {
			root_hide_hidden_whitelist_log("support library dlopen failed path=%s error=%s", libraryPath, dlerror() ?: "(null)");
		}
	}
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
				const char *dependencyName = binary->dependencies[j];
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

static void load_hidden_tweak_filter_from_environment(void)
{
	clear_hidden_tweak_filter();
	gHiddenTweakAllowMode = true;

	const char *mode = getenv("ROOTHIDE_HIDDEN_TWEAK_MODE");
	if (mode && !strcmp(mode, "deny")) {
		gHiddenTweakAllowMode = false;
	}
	if (mode && mode[0] != '\0') {
		gHiddenTweakModeString = strdup(mode);
	}

	const char *list = getenv("ROOTHIDE_HIDDEN_TWEAK_LIST");
	if (!list || list[0] == '\0') {
		root_hide_hidden_whitelist_log("hidden filter not configured");
		unsetenv("ROOTHIDE_HIDDEN_TWEAK_MODE");
		unsetenv("ROOTHIDE_HIDDEN_TWEAK_LIST");
		return;
	}
	gHiddenTweakListString = strdup(list);

	char *listCopy = strdup(list);
	char *cursor = listCopy;
	char *token = NULL;
	while ((token = strsep(&cursor, ":")) != NULL) {
		if (token[0] == '\0') {
			continue;
		}
		hidden_tweak_filter_add_name(token);
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

void roothide_hidden_tweak_envbuf_apply(char ***envc)
{
	if (!envc || !roothide_hidden_tweak_env_is_configured()) {
		return;
	}

	envbuf_setenv(envc, "ROOTHIDE_HIDDEN_INJECTION", "1");
	envbuf_setenv(envc, "ROOTHIDE_ENABLE_HIDDEN_TWEAKS", "1");
	envbuf_setenv(envc, "ROOTHIDE_HIDDEN_TWEAK_MODE", gHiddenTweakModeString ? gHiddenTweakModeString : "allow");
	envbuf_setenv(envc, "ROOTHIDE_HIDDEN_TWEAK_LIST", gHiddenTweakListString);
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

static void hidden_tweak_build_binary_index_if_needed(void)
{
	if (gHiddenTweakBinaryCount == 0) {
		hidden_tweak_build_binary_index();
	}
}

void roothide_hidden_tweak_prepare_for_loader(void)
{
	if (gHiddenTweakNameCount == 0) {
		root_hide_hidden_whitelist_log("prepare selected tweaks skipped count=0");
		return;
	}

	hidden_tweak_build_binary_index_if_needed();
	root_hide_hidden_whitelist_log("prepare selected tweaks count=%zu indexed=%zu", gHiddenTweakNameCount, gHiddenTweakBinaryCount);
	hidden_tweak_load_runtime_support_libraries();
	for (size_t i = 0; i < gHiddenTweakBinaryCount; i++) {
		HiddenTweakBinary *binary = &gHiddenTweakBinaries[i];
		if (!hidden_tweak_binary_should_load(binary)) {
			root_hide_hidden_whitelist_log("prepare skip blocked binary=%s path=%s", binary->name ?: "(null)", binary->path ?: "(null)");
			continue;
		}

		root_hide_hidden_whitelist_log("prepare trust binary=%s path=%s", binary->name ?: "(null)", binary->path ?: "(null)");
		jbclient_trust_library_recurse(binary->path, NULL);
	}
}

static bool hidden_tweak_binary_dependencies_are_ready(const HiddenTweakBinary *binary, bool *loadedStates)
{
	if (!binary || !loadedStates) {
		return false;
	}

	for (size_t dependencyIndex = 0; dependencyIndex < binary->dependencyCount; dependencyIndex++) {
		const char *dependencyName = binary->dependencies[dependencyIndex];
		if (!dependencyName || dependencyName[0] == '\0') {
			continue;
		}

		for (size_t binaryIndex = 0; binaryIndex < gHiddenTweakBinaryCount; binaryIndex++) {
			HiddenTweakBinary *dependencyBinary = &gHiddenTweakBinaries[binaryIndex];
			if (strcmp(dependencyBinary->name, dependencyName) != 0) {
				continue;
			}

			if (!hidden_tweak_binary_should_load(dependencyBinary)) {
				break;
			}

			if (!loadedStates[binaryIndex]) {
				return false;
			}

			break;
		}
	}

	return true;
}

void roothide_hidden_tweak_load_selected(void)
{
	if (gHiddenTweakNameCount == 0) {
		root_hide_hidden_whitelist_log("selected tweak load skipped count=0");
		return;
	}

	hidden_tweak_build_binary_index_if_needed();
	if (gHiddenTweakBinaryCount == 0) {
		root_hide_hidden_whitelist_log("selected tweak load skipped indexed=0 list=%s", gHiddenTweakListString ?: "(null)");
		return;
	}

	root_hide_hidden_whitelist_log("selected tweak load begin count=%zu indexed=%zu mode=%s list=%s",
		gHiddenTweakNameCount,
		gHiddenTweakBinaryCount,
		gHiddenTweakAllowMode ? "allow" : "deny",
		gHiddenTweakListString ?: "(null)");

	bool *loadedStates = calloc(gHiddenTweakBinaryCount, sizeof(bool));
	if (!loadedStates) {
		root_hide_hidden_whitelist_log("selected tweak load failed alloc loadedStates");
		return;
	}

	bool progress = false;
	do {
		progress = false;
		for (size_t i = 0; i < gHiddenTweakBinaryCount; i++) {
			HiddenTweakBinary *binary = &gHiddenTweakBinaries[i];
			if (loadedStates[i] || !hidden_tweak_binary_should_load(binary)) {
				continue;
			}

			if (!hidden_tweak_binary_dependencies_are_ready(binary, loadedStates)) {
				root_hide_hidden_whitelist_log("selected tweak wait dependencies binary=%s path=%s", binary->name ?: "(null)", binary->path ?: "(null)");
				continue;
			}

			jbclient_trust_library_recurse(binary->path, NULL);
			root_hide_hidden_whitelist_log("selected tweak dlopen attempt binary=%s path=%s", binary->name ?: "(null)", binary->path ?: "(null)");
			void *handle = dlopen(binary->path, RTLD_NOW | RTLD_GLOBAL);
			if (handle) {
				hidden_tweak_store_loaded_handle(handle);
				loadedStates[i] = true;
				progress = true;
				root_hide_hidden_whitelist_log("selected tweak dlopen success binary=%s path=%s handle=%p", binary->name ?: "(null)", binary->path ?: "(null)", handle);
			}
			else {
				root_hide_hidden_whitelist_log("selected tweak dlopen failed binary=%s path=%s error=%s",
					binary->name ?: "(null)",
					binary->path ?: "(null)",
					dlerror() ?: "(null)");
			}
		}
	} while (progress);

	for (size_t i = 0; i < gHiddenTweakBinaryCount; i++) {
		HiddenTweakBinary *binary = &gHiddenTweakBinaries[i];
		if (loadedStates[i] || !hidden_tweak_binary_should_load(binary)) {
			continue;
		}

		jbclient_trust_library_recurse(binary->path, NULL);
		root_hide_hidden_whitelist_log("selected tweak fallback dlopen attempt binary=%s path=%s", binary->name ?: "(null)", binary->path ?: "(null)");
		void *handle = dlopen(binary->path, RTLD_NOW | RTLD_GLOBAL);
		if (handle) {
			hidden_tweak_store_loaded_handle(handle);
			root_hide_hidden_whitelist_log("selected tweak fallback dlopen success binary=%s path=%s handle=%p", binary->name ?: "(null)", binary->path ?: "(null)", handle);
		}
		else {
			root_hide_hidden_whitelist_log("selected tweak fallback dlopen failed binary=%s path=%s error=%s",
				binary->name ?: "(null)",
				binary->path ?: "(null)",
				dlerror() ?: "(null)");
		}
	}

	root_hide_hidden_whitelist_log("selected tweak load end loadedHandles=%zu", gHiddenTweakLoadedHandleCount);
	free(loadedStates);
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
	const char* DYLD_INSERT_LIBRARIES = envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES");
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
		roothide_hidden_tweak_envbuf_apply(&envc);
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
	if(envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES")) {
		envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");
	}

	if(!jbclient_dyld_patch_enabled())
	{
		if (spawnConfig & kSpawnConfigTrust) {
			trust_insert_libraries(envc);
		}
	}

	int pid = 0;
	int ret = __posix_spawn_orig(&pid, path, desc, argv, envc);
	if (pidp) *pidp = pid;

	envbuf_free(envc);

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
			roothide_hidden_tweak_envbuf_apply(&envc);
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
	if(envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES")) {
		envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");
	}
	
	int ret = __execve_orig(path, argv, envc);
	int olderr = errno;
	
	envbuf_free(envc);

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

int hook_dyld_routine(void **dyld, int idx, void *hook, void **orig, uint16_t pacSalt)
{
	if (!dyld) return -1;

	uint64_t dyldPacDiversifier = ((uint64_t)dyld & ~(0xFFFFull << 48)) | (0x63FAull << 48);
	void **dyldFuncPtrs = ptrauth_auth_data(*dyld, ptrauth_key_process_independent_data, dyldPacDiversifier);
	if (!dyldFuncPtrs) return -1;

	if (vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *), false, VM_PROT_READ | VM_PROT_WRITE) == 0) {
		uint64_t location = (uint64_t)&dyldFuncPtrs[idx];
		uint64_t pacDiversifier = (location & ~(0xFFFFull << 48)) | ((uint64_t)pacSalt << 48);

		*orig = ptrauth_auth_and_resign(dyldFuncPtrs[idx], ptrauth_key_process_independent_code, pacDiversifier, ptrauth_key_function_pointer, 0);
		dyldFuncPtrs[idx] = ptrauth_auth_and_resign(hook, ptrauth_key_function_pointer, 0, ptrauth_key_process_independent_code, pacDiversifier);
		vm_protect(mach_task_self_, (mach_vm_address_t)&dyldFuncPtrs[idx], sizeof(void *), false, VM_PROT_READ);
		return 0;
	}

	return -1;
}

// iOS 15 / dyld3 fallback: GOT-rebound dlopen hook with standard C signature.
// litehook_rebind_symbol replaces the GOT entry for dlopen in all loaded images,
// so the original dlopen address stays valid through the DSC.
void *(*dlopen_fallback_orig)(const char *, int) = NULL;
void *dlopen_fallback_hook(const char *path, int mode)
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
	return dlopen_fallback_orig(path, mode);
}

void init_dyldhooks()
{
	if (gHiddenTweakHooksInstalled) {
		return;
	}

	// Apply dyld hooks — try dyld4 vtable first (iOS 16+), fall back to GOT rebinding (iOS 15)
	void ***gDyldPtr = litehook_find_dsc_symbol("/usr/lib/system/libdyld.dylib", "__ZN5dyld45gDyldE");
	if (gDyldPtr) {
		hook_dyld_routine(*gDyldPtr, 14, (void *)&dyld_dlopen_hook, (void **)&dyld_dlopen_orig, 0xBF31);
		hook_dyld_routine(*gDyldPtr, 18, (void *)&dyld_dlopen_preflight_hook, (void **)&dyld_dlopen_preflight_orig, 0xB1B6);
		hook_dyld_routine(*gDyldPtr, 97, (void *)&dyld_dlopen_from_hook, (void **)&dyld_dlopen_from_orig, 0xD48C);
		hook_dyld_routine(*gDyldPtr, 98, (void *)&dyld_dlopen_audited_hook, (void **)&dyld_dlopen_audited_orig, 0xD2A5);
		dlopen_fallback_hook_installed = false;
		gHiddenTweakHooksInstalled = true;
	} else {
		// iOS 15 / dyld3 fallback: rebind dlopen in GOT of all loaded images.
		// Save the real dlopen pointer before rebinding.
		dlopen_fallback_orig = dlopen;
		litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, dlopen, dlopen_fallback_hook,
		                       NULL);
		dlopen_fallback_hook_installed = true;
		gHiddenTweakHooksInstalled = true;
	}
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

	HOOK_DYLIB_PATH = strdup(dyld_image_path_containing_address(&__dso_handle));

	if(parse_dyldhook_jbinfo(NULL, NULL, NULL, NULL) != 0)
	{
		dyld_patch_fallback_enabled = true;
	}
}

void roothide_init_with_checkin(const char* rootdir)
{
	load_hidden_tweak_filter_from_environment();

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

	if(string_has_suffix(executable, "/Dopamine.app/Dopamine")) {
		loadPathHook(); //requre jit
	}

	dlopen(JBROOT_PATH("/usr/lib/roothidepatch.dylib"), RTLD_NOW); //require jit
}
