#include "trustcache_fs.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "signatures.h"
#include "trustcache.h"

#define TRUSTCACHE_FS_MAX_FILES 8192U
#define TRUSTCACHE_FS_MAX_DEPTH 64U

struct trustcache_fs_collection {
	cdhash_t *hashes;
	uint32_t count;
	uint32_t filesSeen;
};

static int trustcache_fs_append_unique(struct trustcache_fs_collection *collection, const cdhash_t hash)
{
	for (uint32_t i = 0; i < collection->count; i++) {
		if (memcmp(collection->hashes[i], hash, sizeof(cdhash_t)) == 0) return 0;
	}
	if (collection->count == TRUSTCACHE_FS_MAX_FILES ||
	    (size_t)(collection->count + 1) > SIZE_MAX / sizeof(cdhash_t)) return -E2BIG;
	cdhash_t *grown = realloc(collection->hashes, (size_t)(collection->count + 1) * sizeof(cdhash_t));
	if (!grown) return -ENOMEM;
	collection->hashes = grown;
	memcpy(collection->hashes[collection->count++], hash, sizeof(cdhash_t));
	return 0;
}

static int trustcache_fs_collect_file(const char *path, struct trustcache_fs_collection *collection)
{
	if (++collection->filesSeen > TRUSTCACHE_FS_MAX_FILES) return -E2BIG;
	cdhash_t *hashes = NULL;
	uint32_t hashCount = 0;
	int collectionStatus = file_collect_untrusted_cdhashes_by_path_status(path, &hashes, &hashCount);
	if (collectionStatus < 0) {
		free(hashes);
		return collectionStatus;
	}
	/* RootHide policy and non-Mach files are intentional exclusions. */
	if (collectionStatus == FILE_CDHASH_COLLECTION_SKIPPED) return 0;
	for (uint32_t i = 0; i < hashCount; i++) {
		int result = trustcache_fs_append_unique(collection, hashes[i]);
		if (result != 0) {
			free(hashes);
			return result;
		}
	}
	free(hashes);
	return 0;
}

static int trustcache_fs_collect_directory(const char *directoryPath, bool recursive, unsigned depth,
	                                           struct trustcache_fs_collection *collection)
{
	if (depth > TRUSTCACHE_FS_MAX_DEPTH) return -ELOOP;
	DIR *directory = opendir(directoryPath);
	if (!directory) return -errno;

	int result = 0;
	struct dirent *entry = NULL;
	for (;;) {
		errno = 0;
		entry = readdir(directory);
		if (!entry) {
			if (errno != 0) result = -errno;
			break;
		}
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
		size_t parentLength = strlen(directoryPath);
		size_t nameLength = strlen(entry->d_name);
		if (parentLength > SIZE_MAX - nameLength - 2) {
			result = -ENAMETOOLONG;
			break;
		}
		char *path = malloc(parentLength + nameLength + 2);
		if (!path) {
			result = -ENOMEM;
			break;
		}
		int written = snprintf(path, parentLength + nameLength + 2, "%s/%s", directoryPath, entry->d_name);
		if (written < 0 || (size_t)written != parentLength + nameLength + 1) {
			free(path);
			result = -ENAMETOOLONG;
			break;
		}

		struct stat st = {};
		if (lstat(path, &st) != 0) {
			result = -errno;
			free(path);
			break;
		}
		if (S_ISDIR(st.st_mode) && recursive) {
			result = trustcache_fs_collect_directory(path, true, depth + 1, collection);
		}
		else if (S_ISREG(st.st_mode)) {
			result = trustcache_fs_collect_file(path, collection);
		}
		/* Symlinks and all other node types are intentionally not followed. */
		free(path);
		if (result != 0) break;
	}
	if (closedir(directory) != 0 && result == 0) result = -errno;
	return result;
}

int jb_trustcache_add_file(const char *filePath)
{
	if (!filePath) return -EINVAL;
	struct stat st = {};
	if (lstat(filePath, &st) != 0) return -errno;
	if (!S_ISREG(st.st_mode)) return -EINVAL;

	struct trustcache_fs_collection collection = {};
	int result = trustcache_fs_collect_file(filePath, &collection);
	if (result == 0 && collection.count > 0) result = jb_trustcache_add_cdhashes(collection.hashes, collection.count);
	free(collection.hashes);
	return result;
}

int jb_trustcache_add_directory(const char *directoryPath, bool recursive)
{
	if (!directoryPath) return -EINVAL;
	struct trustcache_fs_collection collection = {};
	int result = trustcache_fs_collect_directory(directoryPath, recursive, 0, &collection);
	if (result == 0 && collection.count > 0) result = jb_trustcache_add_cdhashes(collection.hashes, collection.count);
	free(collection.hashes);
	return result;
}
