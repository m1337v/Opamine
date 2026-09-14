#include "hider_path_policy.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef bool (*path_predicate_t)(const char *path);

typedef struct {
	const char *path;
	bool expected;
} path_case_t;

typedef struct {
	const char *parent;
	const char *name;
	bool expected;
} directory_case_t;

static int g_failures = 0;

static void expect_path(const char *label, path_predicate_t predicate, const path_case_t *test_case)
{
	bool actual = predicate(test_case->path);
	if (actual != test_case->expected) {
		fprintf(stderr, "FAIL %s(%s): got %d, expected %d\n", label, test_case->path,
		        actual, test_case->expected);
		g_failures++;
	}
}

static void expect_directory(const directory_case_t *test_case)
{
	bool actual = rhi_hider_directory_entry_hidden(test_case->parent, test_case->name);
	if (actual != test_case->expected) {
		fprintf(stderr, "FAIL directory(%s, %s): got %d, expected %d\n", test_case->parent,
		        test_case->name, actual, test_case->expected);
		g_failures++;
	}
}

static void expect_directory_point_equivalence(const char *parent, const char *name)
{
	char point[1024];
	int written = snprintf(point, sizeof(point), "%s%s%s", parent,
	                       parent[strlen(parent) - 1] == '/' ? "" : "/", name);
	if (written < 0 || (size_t)written >= sizeof(point)) {
		fprintf(stderr, "FAIL fixture path overflow for %s / %s\n", parent, name);
		g_failures++;
		return;
	}
	bool directory = rhi_hider_directory_entry_hidden(parent, name);
	bool point_result = rhi_hider_filesystem_path_hidden(point);
	if (directory != point_result) {
		fprintf(stderr, "FAIL directory/point mismatch: %s => %d, (%s, %s) => %d\n", point,
		        point_result, parent, name, directory);
		g_failures++;
	}
}

int main(void)
{
	static const path_case_t image_cases[] = {
		{ "/usr/lib/systemhook.dylib", true },
		{ "/usr/lib/systemhook-9D1722053A2B61DD.dylib", true },
		{ "/private/preboot/.jbroot-abc/usr/lib/TweakLoader.dylib", true },
		{ "/tmp/TweakLoader.dylib", true },
		{ "/tmp/MobileSubstrate.dylib", true },
		{ "/tmp/MobileSubstrateBackup.dylib", false },
		{ "/tmp/my-systemhook-notes", false },
		{ "/usr/lib/libobjc.A.dylib", false },
		{ NULL, false },
	};
	for (size_t index = 0; image_cases[index].path; index++) {
		expect_path("image", rhi_hider_image_path_hidden, &image_cases[index]);
	}

	static const path_case_t filesystem_cases[] = {
		{ "/Applications/Cydia.app", true },
		{ "/Applications/Cydia.app/", true },
		{ "/Applications/Cydia.app/Contents/MacOS/Cydia", false },
		{ "/Library/MobileSubstrate", true },
		{ "/Library/MobileSubstrate///", true },
		{ "/usr/lib/libjailbreak.dylib", true },
		{ "/var/lib/dpkg/", true },
		{ "/private/preboot", false },
		{ "/private/preboot/", false },
		{ "/private/preboot/active", false },
		{ "/private/preboot/.installed_palera1n", true },
		{ "/private/preboot/jb", true },
		{ "/private/preboot/jb/usr/lib/libfoo.dylib", true },
		{ "/private/preboot/procursus/usr/bin/apt", true },
		{ "/private/preboot/active/dopamine-123/usr/lib/libfoo.dylib", true },
		{ "/private/preboot/ACTIVE/jb-root", true },
		{ "/private/preboot/active/not-dopamine-123", false },
		{ "/private/preboot/active/procursus-backup", false },
		{ "/private/preboot/active/nested/dopamine-123", false },
		{ "/tmp/MobileSubstrateBackup.dylib", false },
		{ "/tmp/my-systemhook-notes", false },
		{ "/tmp/systemhook-notes", true },
		{ "/tmp/systemhookish-notes", false },
		{ NULL, false },
	};
	for (size_t index = 0; filesystem_cases[index].path; index++) {
		expect_path("filesystem", rhi_hider_filesystem_path_hidden, &filesystem_cases[index]);
	}

	/* Every image artifact remains hidden through the filesystem view too. */
	for (size_t index = 0; image_cases[index].path; index++) {
		if (image_cases[index].expected &&
		    !rhi_hider_filesystem_path_hidden(image_cases[index].path)) {
			fprintf(stderr, "FAIL image/filesystem mismatch for %s\n", image_cases[index].path);
			g_failures++;
		}
	}

	static const directory_case_t directory_cases[] = {
		{ "/usr/lib", "systemhook.dylib", true },
		{ "/usr/lib", "systemhook-abc.dylib", true },
		{ "/usr/lib", "my-systemhook-notes", false },
		{ "/tmp", "MobileSubstrateBackup.dylib", false },
		{ "/tmp/.jbroot-abc", "ordinary", true },
		{ "/Applications", "Cydia.app", true },
		{ "/Applications/", "Cydia.app", true },
		{ "/private/preboot", "active", false },
		{ "/private/preboot", "jb", true },
		{ "/private/preboot", "procursus", true },
		{ "/private/preboot", ".installed_palera1n", true },
		{ "/private/preboot/active", "dopamine-123", true },
		{ "/private/preboot/active/", "dopamine-123", true },
		{ "/private/preboot/active", "jb-root", true },
		{ "/private/preboot/active", "procursus", true },
		{ "/private/preboot/active", "procursus-backup", false },
		{ "/private/preboot/active", "ordinary", false },
		{ "/tmp", ".", false },
		{ "/tmp", "../escape", false },
		{ NULL, NULL, false },
	};
	for (size_t index = 0; directory_cases[index].parent; index++) {
		expect_directory(&directory_cases[index]);
		expect_directory_point_equivalence(directory_cases[index].parent,
		                                  directory_cases[index].name);
	}

	if (g_failures != 0) {
		return 1;
	}
	puts("hider_path_policy_host: PASS");
	return 0;
}
